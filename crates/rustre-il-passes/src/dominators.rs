//! Dominator-tree and loop-nesting infrastructure for [`LlilFunction`]s.
//!
//! This module provides the foundational CFG analyses that SSA construction
//! ([`crate::ssa`]) and the SSA-based optimizations ([`crate::gvn2`]) are
//! built on:
//!
//! - [`Cfg`]: an index-based control-flow graph (blocks are `usize` indices
//!   into [`LlilFunction::blocks`]) with successor/predecessor lists.
//! - [`DomTree`]: immediate dominators via the Cooper–Harvey–Kennedy
//!   iterative algorithm, plus dominance frontiers.
//! - [`LoopNest`]: natural loops from back edges, with nesting parents.

use std::collections::HashMap;

use rustre_core::address::Address;
use rustre_il_llil::{LlilExpr, LlilFunction, LlilInstruction};

// ─────────────────────────────────────────────────────────────────────
// Cfg
// ─────────────────────────────────────────────────────────────────────

/// Index-based control-flow graph over a function's basic blocks.
#[derive(Debug, Clone)]
pub struct Cfg {
    /// Successor block indices for each block.
    pub succs: Vec<Vec<usize>>,
    /// Predecessor block indices for each block.
    pub preds: Vec<Vec<usize>>,
    /// Index of the entry block.
    pub entry: usize,
    /// Number of blocks.
    pub len: usize,
}

impl Cfg {
    /// Builds the CFG for `func`.
    ///
    /// Successors are derived from block terminators (`CondJump`,
    /// `JumpDest`/`Jump` with constant target, `JumpTo`, `ConditionalJump`);
    /// non-terminated blocks and `Call`-terminated blocks fall through to
    /// the next block in layout order. The builder-populated
    /// [`rustre_il_llil::LlilBasicBlock::successors`] list is used as a
    /// fallback when nothing else yields successors.
    #[must_use]
    pub fn build(func: &LlilFunction) -> Self {
        let n = func.blocks.len();
        let addr_to_idx: HashMap<Address, usize> = func
            .blocks
            .iter()
            .enumerate()
            .map(|(i, b)| (b.start, i))
            .collect();
        let entry = addr_to_idx.get(&func.entry).copied().unwrap_or(0);

        let mut succs: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (i, block) in func.blocks.iter().enumerate() {
            let mut out: Vec<usize> = Vec::new();
            let mut fall_through = true;
            if let Some(term) = block.terminator() {
                fall_through = false;
                match &term.instr {
                    LlilInstruction::CondJump {
                        true_dest,
                        false_dest,
                        ..
                    } => {
                        if let Some(&t) = addr_to_idx.get(true_dest) {
                            out.push(t);
                        }
                        if let Some(&f) = addr_to_idx.get(false_dest) {
                            out.push(f);
                        }
                    }
                    LlilInstruction::ConditionalJump {
                        true_target,
                        false_target,
                        ..
                    } => {
                        if let Some(&t) = addr_to_idx.get(true_target) {
                            out.push(t);
                        }
                        if let Some(&f) = addr_to_idx.get(false_target) {
                            out.push(f);
                        }
                    }
                    LlilInstruction::JumpDest { dest } | LlilInstruction::Jump(dest) => {
                        if let LlilExpr::Const { value, .. } = dest
                            && let Some(&t) = addr_to_idx.get(&Address::new(*value))
                        {
                            out.push(t);
                        }
                    }
                    LlilInstruction::JumpTo { targets, .. } => {
                        for t in targets {
                            if let Some(&ti) = addr_to_idx.get(t) {
                                out.push(ti);
                            }
                        }
                    }
                    // Calls return: fall through to the next block.
                    LlilInstruction::Call(_)
                    | LlilInstruction::CallDest { .. }
                    | LlilInstruction::CondCall { .. } => fall_through = true,
                    _ => {}
                }
            }
            if out.is_empty() && fall_through {
                // Prefer explicit builder successors, else layout order.
                for a in &block.successors {
                    if let Some(&s) = addr_to_idx.get(a) {
                        out.push(s);
                    }
                }
                if out.is_empty() && i + 1 < n {
                    out.push(i + 1);
                }
            }
            out.dedup();
            succs[i] = out;
        }

        let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (i, ss) in succs.iter().enumerate() {
            for &s in ss {
                preds[s].push(i);
            }
        }
        Self {
            succs,
            preds,
            entry,
            len: n,
        }
    }

    /// Reverse postorder over blocks reachable from the entry.
    #[must_use]
    pub fn reverse_postorder(&self) -> Vec<usize> {
        let mut visited = vec![false; self.len];
        let mut post: Vec<usize> = Vec::with_capacity(self.len);
        // Iterative DFS with explicit stack of (node, next-child-index).
        if self.len == 0 {
            return post;
        }
        let mut stack: Vec<(usize, usize)> = vec![(self.entry, 0)];
        visited[self.entry] = true;
        while let Some(&mut (node, ref mut child)) = stack.last_mut() {
            if *child < self.succs[node].len() {
                let s = self.succs[node][*child];
                *child += 1;
                if !visited[s] {
                    visited[s] = true;
                    stack.push((s, 0));
                }
            } else {
                post.push(node);
                stack.pop();
            }
        }
        post.reverse();
        post
    }
}

// ─────────────────────────────────────────────────────────────────────
// DomTree
// ─────────────────────────────────────────────────────────────────────

/// Dominator tree (Cooper–Harvey–Kennedy) plus dominance frontiers.
#[derive(Debug, Clone)]
pub struct DomTree {
    /// Immediate dominator of each block (`None` for the entry and
    /// unreachable blocks).
    pub idom: Vec<Option<usize>>,
    /// Dominator-tree children of each block.
    pub children: Vec<Vec<usize>>,
    /// Reverse postorder of reachable blocks.
    pub rpo: Vec<usize>,
    /// Dominance frontier of each block.
    pub frontiers: Vec<Vec<usize>>,
    /// Entry block index.
    pub entry: usize,
}

impl DomTree {
    /// Computes the dominator tree and dominance frontiers for `cfg`.
    #[must_use]
    pub fn build(cfg: &Cfg) -> Self {
        let n = cfg.len;
        let rpo = cfg.reverse_postorder();
        let mut rpo_num = vec![usize::MAX; n];
        for (i, &b) in rpo.iter().enumerate() {
            rpo_num[b] = i;
        }

        let mut idom: Vec<Option<usize>> = vec![None; n];
        if n == 0 {
            return Self {
                idom,
                children: Vec::new(),
                rpo,
                frontiers: Vec::new(),
                entry: 0,
            };
        }
        idom[cfg.entry] = Some(cfg.entry);

        let intersect = |idom: &[Option<usize>], rpo_num: &[usize], mut a: usize, mut b: usize| {
            while a != b {
                while rpo_num[a] > rpo_num[b] {
                    a = idom[a].expect("processed node has idom");
                }
                while rpo_num[b] > rpo_num[a] {
                    b = idom[b].expect("processed node has idom");
                }
            }
            a
        };

        let mut changed = true;
        while changed {
            changed = false;
            for &b in &rpo {
                if b == cfg.entry {
                    continue;
                }
                let mut new_idom: Option<usize> = None;
                for &p in &cfg.preds[b] {
                    if idom[p].is_none() {
                        continue; // unreachable or not yet processed
                    }
                    new_idom = Some(match new_idom {
                        None => p,
                        Some(cur) => intersect(&idom, &rpo_num, p, cur),
                    });
                }
                if new_idom.is_some() && idom[b] != new_idom {
                    idom[b] = new_idom;
                    changed = true;
                }
            }
        }
        // Entry's idom is conventionally itself internally; expose None.
        let mut exposed = idom.clone();
        exposed[cfg.entry] = None;

        let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (b, &d) in exposed.iter().enumerate() {
            if let Some(d) = d {
                children[d].push(b);
            }
        }

        // Dominance frontiers (Cooper et al.).
        let mut frontiers: Vec<Vec<usize>> = vec![Vec::new(); n];
        for b in 0..n {
            if cfg.preds[b].len() >= 2 {
                for &p in &cfg.preds[b] {
                    if idom[p].is_none() {
                        continue;
                    }
                    let mut runner = p;
                    let b_idom = exposed[b];
                    while Some(runner) != b_idom {
                        if !frontiers[runner].contains(&b) {
                            frontiers[runner].push(b);
                        }
                        match exposed[runner] {
                            Some(next) => runner = next,
                            None => break,
                        }
                    }
                }
            }
        }

        Self {
            idom: exposed,
            children,
            rpo,
            frontiers,
            entry: cfg.entry,
        }
    }

    /// Returns `true` if `a` dominates `b` (reflexive).
    #[must_use]
    pub fn dominates(&self, a: usize, b: usize) -> bool {
        let mut cur = b;
        loop {
            if cur == a {
                return true;
            }
            match self.idom[cur] {
                Some(next) => cur = next,
                None => return false,
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// LoopNest
// ─────────────────────────────────────────────────────────────────────

/// A single natural loop.
#[derive(Debug, Clone)]
pub struct NaturalLoop {
    /// Loop header block.
    pub header: usize,
    /// All blocks in the loop body (including the header).
    pub body: Vec<usize>,
    /// Back-edge sources (latches).
    pub latches: Vec<usize>,
    /// Index into [`LoopNest::loops`] of the innermost enclosing loop, if any.
    pub parent: Option<usize>,
    /// Nesting depth (outermost = 1).
    pub depth: usize,
}

/// Loop nesting forest built from natural loops.
#[derive(Debug, Clone)]
pub struct LoopNest {
    /// All discovered loops. Loops with the same header are merged.
    pub loops: Vec<NaturalLoop>,
    /// For each block, the innermost loop containing it (index into `loops`).
    pub innermost: Vec<Option<usize>>,
}

impl LoopNest {
    /// Discovers natural loops in `cfg` using `dom` to identify back edges
    /// (`src -> header` where `header` dominates `src`).
    #[must_use]
    pub fn build(cfg: &Cfg, dom: &DomTree) -> Self {
        let n = cfg.len;
        let mut by_header: HashMap<usize, (Vec<usize>, Vec<usize>)> = HashMap::new(); // header -> (body, latches)
        for src in 0..n {
            for &dst in &cfg.succs[src] {
                let reachable = src == cfg.entry || dom.idom[src].is_some();
                if reachable && dom.dominates(dst, src) {
                    // Back edge src -> dst; body = dst + reverse reachable from src w/o dst.
                    let entry = by_header.entry(dst).or_default();
                    entry.1.push(src);
                    let mut in_body = vec![false; n];
                    in_body[dst] = true;
                    let mut stack = vec![src];
                    while let Some(b) = stack.pop() {
                        if in_body[b] {
                            continue;
                        }
                        in_body[b] = true;
                        for &p in &cfg.preds[b] {
                            stack.push(p);
                        }
                    }
                    for (b, &inb) in in_body.iter().enumerate() {
                        if inb && !entry.0.contains(&b) {
                            entry.0.push(b);
                        }
                    }
                }
            }
        }

        let mut loops: Vec<NaturalLoop> = by_header
            .into_iter()
            .map(|(header, (mut body, latches))| {
                body.sort_unstable();
                NaturalLoop {
                    header,
                    body,
                    latches,
                    parent: None,
                    depth: 1,
                }
            })
            .collect();
        // Deterministic order: by header index.
        loops.sort_by_key(|l| l.header);

        // Parent = smallest strictly-larger loop containing this header.
        let sizes: Vec<usize> = loops.iter().map(|l| l.body.len()).collect();
        for i in 0..loops.len() {
            let mut best: Option<usize> = None;
            for j in 0..loops.len() {
                if i == j {
                    continue;
                }
                let contains =
                    loops[j].body.contains(&loops[i].header) && sizes[j] > sizes[i];
                if contains && best.is_none_or(|b| sizes[j] < sizes[b]) {
                    best = Some(j);
                }
            }
            loops[i].parent = best;
        }
        // Depths.
        for i in 0..loops.len() {
            let mut d = 1;
            let mut p = loops[i].parent;
            while let Some(j) = p {
                d += 1;
                p = loops[j].parent;
            }
            loops[i].depth = d;
        }

        // Innermost loop per block.
        let mut innermost: Vec<Option<usize>> = vec![None; n];
        for (li, l) in loops.iter().enumerate() {
            for &b in &l.body {
                match innermost[b] {
                    None => innermost[b] = Some(li),
                    Some(cur) => {
                        if l.body.len() < loops[cur].body.len() {
                            innermost[b] = Some(li);
                        }
                    }
                }
            }
        }

        Self { loops, innermost }
    }

    /// Returns the nesting depth of `block` (0 = not in any loop).
    #[must_use]
    pub fn depth_of(&self, block: usize) -> usize {
        self.innermost[block].map_or(0, |li| self.loops[li].depth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_il_llil::{LlilAnnotatedInstr, LlilBasicBlock, Size, llil_const};

    fn block(id: u32, start: u64, instrs: Vec<LlilInstruction>) -> LlilBasicBlock {
        LlilBasicBlock {
            start: Address::new(start),
            end: Address::new(start),
            instrs: instrs
                .into_iter()
                .map(|instr| LlilAnnotatedInstr {
                    address: Address::new(start),
                    size: 1,
                    instr,
                    length: 1,
                })
                .collect(),
            id,
            successors: Vec::new(),
        }
    }

    fn jmp(target: u64) -> LlilInstruction {
        LlilInstruction::JumpDest {
            dest: llil_const(target, Size::QWord),
        }
    }

    fn condjmp(t: u64, f: u64) -> LlilInstruction {
        LlilInstruction::CondJump {
            cond: llil_const(1, Size::Byte),
            true_dest: Address::new(t),
            false_dest: Address::new(f),
        }
    }

    /// Diamond: 0 -> 1,2 -> 3.
    fn diamond() -> LlilFunction {
        let mut f = LlilFunction::new(Address::new(0x100));
        f.blocks = vec![
            block(0, 0x100, vec![condjmp(0x200, 0x300)]),
            block(1, 0x200, vec![jmp(0x400)]),
            block(2, 0x300, vec![jmp(0x400)]),
            block(3, 0x400, vec![LlilInstruction::Ret]),
        ];
        f
    }

    /// Loop: 0 -> 1 (header) -> 2 (body) -> 1; 1 -> 3 (exit).
    fn simple_loop() -> LlilFunction {
        let mut f = LlilFunction::new(Address::new(0x100));
        f.blocks = vec![
            block(0, 0x100, vec![jmp(0x200)]),
            block(1, 0x200, vec![condjmp(0x300, 0x400)]),
            block(2, 0x300, vec![jmp(0x200)]),
            block(3, 0x400, vec![LlilInstruction::Ret]),
        ];
        f
    }

    #[test]
    fn cfg_diamond_edges() {
        let f = diamond();
        let cfg = Cfg::build(&f);
        assert_eq!(cfg.succs[0], vec![1, 2]);
        assert_eq!(cfg.succs[1], vec![3]);
        assert_eq!(cfg.succs[2], vec![3]);
        assert!(cfg.succs[3].is_empty());
        assert_eq!(cfg.preds[3], vec![1, 2]);
        assert_eq!(cfg.entry, 0);
    }

    #[test]
    fn cfg_fall_through() {
        let mut f = LlilFunction::new(Address::new(0x100));
        f.blocks = vec![
            block(0, 0x100, vec![LlilInstruction::Nop]),
            block(1, 0x101, vec![LlilInstruction::Ret]),
        ];
        let cfg = Cfg::build(&f);
        assert_eq!(cfg.succs[0], vec![1]);
    }

    #[test]
    fn idom_diamond() {
        let f = diamond();
        let cfg = Cfg::build(&f);
        let dom = DomTree::build(&cfg);
        assert_eq!(dom.idom[0], None);
        assert_eq!(dom.idom[1], Some(0));
        assert_eq!(dom.idom[2], Some(0));
        assert_eq!(dom.idom[3], Some(0)); // join point dominated by branch, not arms
        assert!(dom.dominates(0, 3));
        assert!(!dom.dominates(1, 3));
    }

    #[test]
    fn frontiers_diamond() {
        let f = diamond();
        let cfg = Cfg::build(&f);
        let dom = DomTree::build(&cfg);
        assert_eq!(dom.frontiers[1], vec![3]);
        assert_eq!(dom.frontiers[2], vec![3]);
        assert!(dom.frontiers[0].is_empty());
        assert!(dom.frontiers[3].is_empty());
    }

    #[test]
    fn loop_detection() {
        let f = simple_loop();
        let cfg = Cfg::build(&f);
        let dom = DomTree::build(&cfg);
        let nest = LoopNest::build(&cfg, &dom);
        assert_eq!(nest.loops.len(), 1);
        let l = &nest.loops[0];
        assert_eq!(l.header, 1);
        assert_eq!(l.body, vec![1, 2]);
        assert_eq!(l.latches, vec![2]);
        assert_eq!(l.depth, 1);
        assert_eq!(nest.depth_of(2), 1);
        assert_eq!(nest.depth_of(0), 0);
        assert_eq!(nest.depth_of(3), 0);
    }

    #[test]
    fn nested_loops() {
        // 0 -> 1(outer hdr) -> 2(inner hdr) -> 3 -> 2 ; 2 -> 4 -> 1 ; 1 -> 5.
        let mut f = LlilFunction::new(Address::new(0x0));
        f.blocks = vec![
            block(0, 0x0, vec![jmp(0x1)]),
            block(1, 0x1, vec![condjmp(0x2, 0x5)]),
            block(2, 0x2, vec![condjmp(0x3, 0x4)]),
            block(3, 0x3, vec![jmp(0x2)]),
            block(4, 0x4, vec![jmp(0x1)]),
            block(5, 0x5, vec![LlilInstruction::Ret]),
        ];
        let cfg = Cfg::build(&f);
        let dom = DomTree::build(&cfg);
        let nest = LoopNest::build(&cfg, &dom);
        assert_eq!(nest.loops.len(), 2);
        let outer = nest.loops.iter().position(|l| l.header == 1).unwrap();
        let inner = nest.loops.iter().position(|l| l.header == 2).unwrap();
        assert_eq!(nest.loops[inner].parent, Some(outer));
        assert_eq!(nest.loops[outer].parent, None);
        assert_eq!(nest.loops[inner].depth, 2);
        assert_eq!(nest.depth_of(3), 2);
        assert_eq!(nest.depth_of(4), 1);
    }

    #[test]
    fn unreachable_block_ignored() {
        let mut f = diamond();
        f.blocks.push(block(4, 0x900, vec![LlilInstruction::Ret]));
        let cfg = Cfg::build(&f);
        let dom = DomTree::build(&cfg);
        assert_eq!(dom.idom[4], None);
        assert!(!dom.rpo.contains(&4));
    }
}
