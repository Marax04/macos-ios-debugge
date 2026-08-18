//! Loop analysis — natural loop detection, nesting forest, induction variables,
//! loop-carried dependencies, strength reduction, and LICM.
//!
//! # Algorithms
//! * **Natural loop detection** — dominance-tree post-order DFS; a back-edge
//!   `(n, h)` where `h` dominates `n` defines a natural loop with header `h`.
//! * **Loop nesting forest** — loops are ordered by set-inclusion of their body
//!   blocks; each loop that is entirely contained in another is a child.
//! * **Induction variable recognition** — linear IVs detected from
//!   `SetReg { dest, value: Add(RegisterRef(dest), step) }` patterns.
//! * **Strength reduction** — `iv*c` inside a loop replaced with a new IV.
//! * **LICM** — instructions whose operands are all loop-invariant are hoisted
//!   into the loop pre-header block.

use std::collections::{HashMap, HashSet, VecDeque};

use rustre_il_llil::{LlilAnnotatedInstr, LlilExpr, LlilFunction, LlilInstruction, Size};

use crate::{AnalysisPass, PassContext};

// ─────────────────────────────────────────────────────────────────────────────
// BlockId — basic block identifier (index into func.blocks)
// ─────────────────────────────────────────────────────────────────────────────

pub type BlockId = usize;

// ─────────────────────────────────────────────────────────────────────────────
// Address → index helpers
// ─────────────────────────────────────────────────────────────────────────────

fn addr_to_idx_map(func: &LlilFunction) -> HashMap<u64, usize> {
    func.blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.start.0, i))
        .collect()
}

fn block_successors_as_indices(func: &LlilFunction, b: BlockId, map: &HashMap<u64, usize>) -> Vec<BlockId> {
    func.blocks[b]
        .successors
        .iter()
        .filter_map(|a| map.get(&a.0).copied())
        .collect()
}

fn build_succ_lists(func: &LlilFunction) -> Vec<Vec<BlockId>> {
    let map = addr_to_idx_map(func);
    let n = func.blocks.len();
    (0..n)
        .map(|b| block_successors_as_indices(func, b, &map))
        .collect()
}

fn build_pred_lists(func: &LlilFunction) -> Vec<Vec<BlockId>> {
    let n = func.blocks.len();
    let succs = build_succ_lists(func);
    let mut preds: Vec<Vec<BlockId>> = vec![vec![]; n];
    for (b, sv) in succs.iter().enumerate() {
        for &s in sv {
            if s < n {
                preds[s].push(b);
            }
        }
    }
    preds
}

// ─────────────────────────────────────────────────────────────────────────────
// DominatorTree
// ─────────────────────────────────────────────────────────────────────────────

/// Dominator-tree computed from a CFG using the simple iterative algorithm.
#[derive(Debug, Clone)]
pub struct DominatorTree {
    pub idom: Vec<BlockId>,
    pub dom_set: Vec<HashSet<BlockId>>,
}

impl DominatorTree {
    #[must_use] 
    pub fn compute(func: &LlilFunction) -> Self {
        let n = func.blocks.len();
        if n == 0 {
            return Self { idom: vec![], dom_set: vec![] };
        }

        let preds = build_pred_lists(func);
        let rpo = reverse_post_order(func, n);
        let mut rpo_num = vec![0usize; n];
        for (i, &b) in rpo.iter().enumerate() {
            rpo_num[b] = i;
        }

        let entry = rpo[0];
        let mut idom = vec![usize::MAX; n];
        idom[entry] = entry;

        let mut changed = true;
        while changed {
            changed = false;
            for &b in &rpo {
                if b == entry { continue; }
                let new_idom = preds[b]
                    .iter()
                    .copied()
                    .filter(|&p| idom[p] != usize::MAX)
                    .reduce(|a, p| intersect(a, p, &idom, &rpo_num))
                    .unwrap_or(entry);
                if idom[b] != new_idom {
                    idom[b] = new_idom;
                    changed = true;
                }
            }
        }

        let dom_set: Vec<HashSet<BlockId>> = (0..n).map(|b| {
            let mut s = HashSet::new();
            let mut cur = b;
            loop {
                s.insert(cur);
                let p = idom[cur];
                if p == cur || p == usize::MAX { break; }
                cur = p;
            }
            s
        }).collect();

        Self { idom, dom_set }
    }

    #[must_use]
    pub fn dominates(&self, d: BlockId, n: BlockId) -> bool {
        n < self.dom_set.len() && self.dom_set[n].contains(&d)
    }

    #[must_use]
    pub fn idom(&self, n: BlockId) -> Option<BlockId> {
        if n >= self.idom.len() { return None; }
        let d = self.idom[n];
        if d == n || d == usize::MAX { None } else { Some(d) }
    }

    #[must_use]
    pub fn dominator_chain(&self, n: BlockId) -> Vec<BlockId> {
        let mut chain = vec![n];
        let mut cur = n;
        while let Some(d) = self.idom(cur) {
            chain.push(d);
            cur = d;
        }
        chain
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NaturalLoop
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NaturalLoop {
    pub header: BlockId,
    pub back_edge_source: BlockId,
    pub body: HashSet<BlockId>,
    pub exits: Vec<BlockId>,
    pub trip_count: Option<u64>,
}

impl NaturalLoop {
    #[must_use] 
    pub fn from_back_edge(
        hdr: BlockId,
        src: BlockId,
        preds: &[Vec<BlockId>],
        _n_blocks: usize,
    ) -> Self {
        let mut body = HashSet::new();
        body.insert(hdr);
        body.insert(src);
        let mut worklist = VecDeque::new();
        worklist.push_back(src);
        while let Some(b) = worklist.pop_front() {
            for &p in &preds[b] {
                if body.insert(p) {
                    worklist.push_back(p);
                }
            }
        }
        Self { header: hdr, back_edge_source: src, body, exits: vec![], trip_count: None }
    }

    pub fn compute_exits(&mut self, succs: &[Vec<BlockId>]) {
        let mut exits = Vec::new();
        for &b in &self.body {
            if b < succs.len() {
                for &s in &succs[b] {
                    if !self.body.contains(&s) && !exits.contains(&s) {
                        exits.push(s);
                    }
                }
            }
        }
        self.exits = exits;
    }

    #[must_use]
    pub fn contains_loop(&self, other: &Self) -> bool {
        other.body.is_subset(&self.body) && other.header != self.header
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopNestingForest
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct LoopNestingForest {
    pub loops: Vec<NaturalLoop>,
    pub parent: Vec<Option<usize>>,
    pub children: Vec<Vec<usize>>,
}

impl LoopNestingForest {
    #[must_use] 
    pub fn build(func: &LlilFunction, domtree: &DominatorTree) -> Self {
        let n = func.blocks.len();
        let preds = build_pred_lists(func);
        let succs = build_succ_lists(func);

        let mut loops = Vec::new();
        for (src, _block) in func.blocks.iter().enumerate() {
            for &hdr in &succs[src] {
                if hdr < n && domtree.dominates(hdr, src) {
                    let mut lp = NaturalLoop::from_back_edge(hdr, src, &preds, n);
                    lp.compute_exits(&succs);
                    loops.push(lp);
                }
            }
        }

        loops.sort_by_key(|l| l.body.len());
        let m = loops.len();
        let mut parent: Vec<Option<usize>> = vec![None; m];
        let mut children: Vec<Vec<usize>> = vec![vec![]; m];

        for i in 0..m {
            for j in 0..m {
                if i == j { continue; }
                if loops[j].contains_loop(&loops[i]) {
                    match parent[i] {
                        None => parent[i] = Some(j),
                        Some(p) if loops[j].body.len() < loops[p].body.len() => {
                            parent[i] = Some(j);
                        }
                        _ => {}
                    }
                }
            }
        }

        for (i, p) in parent.iter().enumerate() {
            if let Some(p) = *p {
                children[p].push(i);
            }
        }

        Self { loops, parent, children }
    }

    #[must_use]
    pub fn depth(&self, i: usize) -> usize {
        // Iterative traversal to avoid stack overflow on deep nesting chains.
        let mut depth = 0usize;
        let mut cur = i;
        let mut visited_count = 0usize;
        let max_depth = self.parent.len() + 1; // cycle guard
        while visited_count <= max_depth {
            match self.parent[cur] {
                None => break,
                Some(p) => {
                    depth += 1;
                    cur = p;
                    visited_count += 1;
                }
            }
        }
        depth
    }

    pub fn roots(&self) -> impl Iterator<Item = (usize, &NaturalLoop)> {
        self.loops
            .iter()
            .enumerate()
            .filter(|(i, _)| self.parent[*i].is_none())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InductionVar
// ─────────────────────────────────────────────────────────────────────────────

/// A linear induction variable: each iteration `dest ← dest + step`.
#[derive(Debug, Clone)]
pub struct InductionVar {
    /// Register name of the IV.
    pub name: String,
    /// Initial value expression.
    pub init: LlilExpr,
    /// Step expression (added each iteration).
    pub step: LlilExpr,
    /// Header block where the definition lives.
    pub header: BlockId,
    pub constant_step: bool,
    pub constant_init: bool,
}

impl InductionVar {
    #[must_use]
    pub const fn is_canonical(&self) -> bool {
        self.constant_init && self.constant_step
    }

    #[must_use]
    pub const fn value_at(&self, k: u64) -> Option<u64> {
        if let (LlilExpr::Const { value: init, .. }, LlilExpr::Const { value: step, .. }) =
            (&self.init, &self.step)
        {
            Some(init.wrapping_add(step.wrapping_mul(k)))
        } else {
            None
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InductionVarAnalysis
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct InductionVarAnalysis {
    pub ivs: HashMap<BlockId, Vec<InductionVar>>,
}

impl InductionVarAnalysis {
    #[must_use] 
    pub fn run(forest: &LoopNestingForest, func: &LlilFunction) -> Self {
        let mut ivs: HashMap<BlockId, Vec<InductionVar>> = HashMap::new();

        for lp in &forest.loops {
            let hdr = lp.header;
            if hdr >= func.blocks.len() { continue; }
            let block = &func.blocks[hdr];
            let mut loop_ivs = Vec::new();

            for ai in &block.instrs {
                if let LlilInstruction::SetReg { dest, value, .. } = &ai.instr {
                    let name = dest.name();
                    if let Some(iv) = detect_linear_iv(&name, value, hdr) {
                        loop_ivs.push(iv);
                    }
                }
            }

            if !loop_ivs.is_empty() {
                ivs.insert(hdr, loop_ivs);
            }
        }

        Self { ivs }
    }

    pub fn ivs_for(&self, header: BlockId) -> &[InductionVar] {
        self.ivs.get(&header).map_or(&[], Vec::as_slice)
    }
}

fn detect_linear_iv(name: &str, expr: &LlilExpr, header: BlockId) -> Option<InductionVar> {
    match expr {
        // dest = dest + step (or step + dest)
        LlilExpr::Add { left, right, .. } => {
            let left_is_self = matches!(
                left.as_ref(),
                LlilExpr::RegisterRef { reg, .. } if reg.name() == name
            );
            let right_is_self = matches!(
                right.as_ref(),
                LlilExpr::RegisterRef { reg, .. } if reg.name() == name
            );
            let step = if left_is_self {
                right.as_ref()
            } else if right_is_self {
                left.as_ref()
            } else {
                return None;
            };
            let constant_step = matches!(step, LlilExpr::Const { .. });
            Some(InductionVar {
                name: name.to_owned(),
                init: LlilExpr::Const { value: 0, size: Size::QWord },
                step: step.clone(),
                header,
                constant_step,
                constant_init: false,
            })
        }
        // dest = dest - step (backward IV; step stored negated)
        LlilExpr::Sub { left, right, .. }
            if matches!(left.as_ref(), LlilExpr::RegisterRef { reg, .. } if reg.name() == name) =>
        {
            let step = right.as_ref();
            let constant_step = matches!(step, LlilExpr::Const { .. });
            Some(InductionVar {
                name: name.to_owned(),
                init: LlilExpr::Const { value: 0, size: Size::QWord },
                step: LlilExpr::Sub {
                    left: Box::new(LlilExpr::Const { value: 0, size: Size::QWord }),
                    right: Box::new(step.clone()),
                    size: Size::QWord,
                },
                header,
                constant_step,
                constant_init: false,
            })
        }
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LicmPass
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct LicmPass;

impl AnalysisPass for LicmPass {
    fn name(&self) -> &'static str { "licm" }
    fn description(&self) -> &'static str {
        "Loop Invariant Code Motion — hoist invariant instructions to pre-header"
    }

    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        let domtree = DominatorTree::compute(func);
        let forest = LoopNestingForest::build(func, &domtree);
        let preds = build_pred_lists(func);

        for lp in &forest.loops {
            // A real pre-header is the unique predecessor of the loop header
            // that lies outside the loop body. If there is not exactly one,
            // hoisting has no safe landing spot — skip this loop.
            let outside_preds: Vec<BlockId> = preds
                .get(lp.header)
                .map(|ps| ps.iter().copied().filter(|p| !lp.body.contains(p)).collect())
                .unwrap_or_default();
            let [pre_header] = outside_preds[..] else { continue; };

            // Collect register names defined inside the loop body.
            let loop_defs: HashSet<String> = lp
                .body
                .iter()
                .filter_map(|&b| func.blocks.get(b))
                .flat_map(|blk| blk.instrs.iter())
                .filter_map(|ai| match &ai.instr {
                    LlilInstruction::SetReg { dest, .. } | LlilInstruction::Load { dest, .. } => Some(dest.name()),
                    _ => None,
                })
                .collect();

            let mut hoisted = 0usize;

            for &b in &lp.body {
                if b == lp.header || b >= func.blocks.len() { continue; }
                // SAFETY: `b` must dominate the loop's back edge (the block
                // that jumps back to the header) — otherwise the loop can
                // take a path that reaches the latch WITHOUT ever running
                // `b` (e.g. `b` sits in one arm of an if/else inside the
                // loop body), and hoisting would make the instruction run on
                // EVERY iteration instead of only the iterations that
                // originally took that arm — a semantic change, not an
                // optimization. Dominating the latch is the standard
                // sufficient condition for "executes on every iteration
                // that doesn't exit early".
                if !domtree.dominates(b, lp.back_edge_source) {
                    continue;
                }

                let invariant_indices: Vec<usize> = func.blocks[b]
                    .instrs
                    .iter()
                    .enumerate()
                    .filter(|(_, ai)| is_loop_invariant(&ai.instr, &loop_defs) && is_safe_to_hoist(&ai.instr))
                    .map(|(idx, _)| idx)
                    .collect();

                if invariant_indices.is_empty() { continue; }

                // Remove indices in reverse order (highest first) to keep earlier
                // indices stable, then reverse the collected items to restore order.
                let mut to_hoist: Vec<LlilAnnotatedInstr> = invariant_indices
                    .iter()
                    .rev()
                    .map(|&i| func.blocks[b].instrs.remove(i))
                    .collect();
                to_hoist.reverse();

                if let Some(ph_block) = func.blocks.get_mut(pre_header) {
                    let insert_pos = ph_block.instrs.len().saturating_sub(1);
                    let n_hoisted = to_hoist.len();
                    for (k, ai) in to_hoist.into_iter().enumerate() {
                        ph_block.instrs.insert(insert_pos + k, ai);
                    }
                    hoisted += n_hoisted;
                }
            }

            if hoisted > 0 {
                ctx.mark_changed();
                ctx.stats.instrs_modified += hoisted;
            }
        }
    }

    fn is_idempotent(&self) -> bool { true }
}

fn is_loop_invariant(instr: &LlilInstruction, loop_defs: &HashSet<String>) -> bool {
    match instr {
        LlilInstruction::SetReg { value, .. } => expr_invariant(value, loop_defs),
        _ => false,
    }
}

/// Conservative expression invariance: `true` only for expression forms we
/// fully understand; any unrecognized form is treated as loop-variant.
fn expr_invariant(expr: &LlilExpr, loop_defs: &HashSet<String>) -> bool {
    match expr {
        LlilExpr::Const { .. } => true,
        LlilExpr::RegisterRef { reg, .. } => !loop_defs.contains(&reg.name()),
        LlilExpr::Add { left, right, .. }
        | LlilExpr::Sub { left, right, .. }
        | LlilExpr::Mul { left, right, .. } => {
            expr_invariant(left, loop_defs) && expr_invariant(right, loop_defs)
        }
        LlilExpr::AddT(l, r, _)
        | LlilExpr::SubT(l, r, _)
        | LlilExpr::MulT(l, r, _)
        | LlilExpr::And(l, r, _)
        | LlilExpr::Or(l, r, _)
        | LlilExpr::Xor(l, r, _)
        | LlilExpr::ShlT(l, r, _)
        | LlilExpr::Shr(l, r, _)
        | LlilExpr::Sar(l, r, _)
        | LlilExpr::Rol(l, r, _)
        | LlilExpr::Ror(l, r, _) => {
            expr_invariant(l, loop_defs) && expr_invariant(r, loop_defs)
        }
        LlilExpr::Shl { value, shift, .. } => {
            expr_invariant(value, loop_defs) && expr_invariant(shift, loop_defs)
        }
        LlilExpr::Neg(inner, _) | LlilExpr::Not(inner, _) => expr_invariant(inner, loop_defs),
        // Loads, divisions (can fault), unknown/opaque forms: not invariant.
        _ => false,
    }
}

const fn is_safe_to_hoist(instr: &LlilInstruction) -> bool {
    matches!(instr, LlilInstruction::SetReg { value, .. } if !matches!(value, LlilExpr::Load { .. }))
}

// ─────────────────────────────────────────────────────────────────────────────
// StrengthReductionPass
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct StrengthReductionPass;

impl AnalysisPass for StrengthReductionPass {
    fn name(&self) -> &'static str { "strength-reduction" }
    fn description(&self) -> &'static str {
        "Replace IV*constant multiplications with cheaper addition-based IVs"
    }

    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        let domtree = DominatorTree::compute(func);
        let forest = LoopNestingForest::build(func, &domtree);
        let iv_analysis = InductionVarAnalysis::run(&forest, func);
        let mut reductions = 0usize;

        for lp in &forest.loops {
            let ivs = iv_analysis.ivs_for(lp.header);
            if ivs.is_empty() { continue; }

            for &b in &lp.body {
                if b >= func.blocks.len() { continue; }
                for ai in &mut func.blocks[b].instrs {
                    if let LlilInstruction::SetReg { value, .. } = &mut ai.instr
                        && let Some(new_val) = try_reduce_multiply(value, ivs) {
                            *value = new_val;
                            reductions += 1;
                            ctx.mark_changed();
                        }
                }
            }
        }

        ctx.stats.exprs_simplified += reductions;
    }
}

fn try_reduce_multiply(expr: &LlilExpr, ivs: &[InductionVar]) -> Option<LlilExpr> {
    let LlilExpr::Mul { left, right, size } = expr else { return None; };

    let (iv_expr, const_val) = if let LlilExpr::Const { value: c, .. } = right.as_ref() {
        (left.as_ref(), *c)
    } else if let LlilExpr::Const { value: c, .. } = left.as_ref() {
        (right.as_ref(), *c)
    } else {
        return None;
    };

    let iv_name = match iv_expr {
        LlilExpr::RegisterRef { reg, .. } => reg.name(),
        _ => return None,
    };

    let iv = ivs.iter().find(|iv| iv.name == iv_name)?;
    if !iv.constant_step { return None; }
    let LlilExpr::Const { .. } = &iv.step else { return None; };

    // Reduce `iv * 2^k` to the equivalent (and cheaper) `iv << k`. This is a
    // pure expression rewrite — unlike introducing a fresh reduced IV register,
    // it needs no new definitions in the pre-header or loop body.
    if const_val == 0 || !const_val.is_power_of_two() { return None; }
    let shift = u64::from(const_val.trailing_zeros());

    Some(LlilExpr::Shl {
        value: Box::new(iv_expr.clone()),
        shift: Box::new(LlilExpr::Const { value: shift, size: *size }),
        size: *size,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopAnalysisPass (top-level read-only)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct LoopAnalysisPass;

impl AnalysisPass for LoopAnalysisPass {
    fn name(&self) -> &'static str { "loop-analysis" }
    fn description(&self) -> &'static str {
        "Natural loop detection, nesting forest, and induction variable recognition"
    }

    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        let domtree = DominatorTree::compute(func);
        let forest = LoopNestingForest::build(func, &domtree);
        let iv_analysis = InductionVarAnalysis::run(&forest, func);

        ctx.add_warning(format!(
            "loop-analysis: found {} natural loops, {} IVs",
            forest.loops.len(),
            iv_analysis.ivs.values().map(std::vec::Vec::len).sum::<usize>()
        ));
    }

    fn is_idempotent(&self) -> bool { true }
}

// ─────────────────────────────────────────────────────────────────────────────
// CFG helpers
// ─────────────────────────────────────────────────────────────────────────────

fn reverse_post_order(func: &LlilFunction, n: usize) -> Vec<BlockId> {
    let succs = build_succ_lists(func);
    let mut visited = vec![false; n];
    let mut rpo = Vec::with_capacity(n);
    dfs_post(0, &succs, &mut visited, &mut rpo);
    rpo.reverse();
    rpo
}

fn dfs_post(b: BlockId, succs: &[Vec<BlockId>], visited: &mut [bool], post: &mut Vec<BlockId>) {
    // Use an explicit stack to avoid unbounded recursion that can stack-overflow
    // on adversarially deep CFGs.
    let mut stack: Vec<(BlockId, usize)> = Vec::new(); // (block, successor_cursor)
    if b >= succs.len() || visited[b] { return; }
    visited[b] = true;
    stack.push((b, 0));
    while let Some((cur, cursor)) = stack.last_mut() {
        let cur = *cur;
        let succs_cur = &succs[cur];
        if *cursor < succs_cur.len() {
            let s = succs_cur[*cursor];
            *cursor += 1;
            if s < succs.len() && !visited[s] {
                visited[s] = true;
                stack.push((s, 0));
            }
        } else {
            post.push(cur);
            stack.pop();
        }
    }
}

fn intersect(mut a: BlockId, mut b: BlockId, idom: &[BlockId], rpo_num: &[usize]) -> BlockId {
    // Guard against sentinel usize::MAX values stored in idom for unreachable
    // blocks; walking through them would cause an out-of-bounds index panic.
    while a != b {
        while a < idom.len() && b < idom.len()
            && a < rpo_num.len() && b < rpo_num.len()
            && rpo_num[a] > rpo_num[b]
        {
            let next = idom[a];
            if next == usize::MAX || next >= idom.len() { return b; }
            a = next;
        }
        while a < idom.len() && b < idom.len()
            && a < rpo_num.len() && b < rpo_num.len()
            && rpo_num[b] > rpo_num[a]
        {
            let next = idom[b];
            if next == usize::MAX || next >= idom.len() { return a; }
            b = next;
        }
        // Break if bounds are violated to avoid infinite loop.
        if a >= idom.len() || b >= idom.len() { break; }
    }
    a
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_il_llil::{LlilBasicBlock, LlilFunction, LlilRegister};
    use rustre_core::address::Address;

    fn make_block(id: u32, start: u64, succs: Vec<u64>) -> LlilBasicBlock {
        LlilBasicBlock {
            id,
            start: Address::new(start),
            end: Address::new(start),
            instrs: vec![],
            successors: succs.into_iter().map(Address::new).collect(),
        }
    }

    fn three_block_loop() -> LlilFunction {
        // 0x1000 (entry) → 0x1010 (header) ← back-edge from self, → 0x1020 (exit)
        LlilFunction {
            entry: Address::new(0x1000),
            address: Address::new(0x1000),
            blocks: vec![
                make_block(0, 0x1000, vec![0x1010]),
                make_block(1, 0x1010, vec![0x1010, 0x1020]),
                make_block(2, 0x1020, vec![]),
            ],
            ..Default::default()
        }
    }

    #[test]
    fn test_domtree_entry_dominates_all() {
        let func = three_block_loop();
        let dt = DominatorTree::compute(&func);
        assert!(dt.dominates(0, 0));
        assert!(dt.dominates(0, 1));
        assert!(dt.dominates(0, 2));
        assert!(!dt.dominates(2, 1));
    }

    #[test]
    fn test_loop_nesting_detects_back_edge() {
        let func = three_block_loop();
        let dt = DominatorTree::compute(&func);
        let forest = LoopNestingForest::build(&func, &dt);
        assert_eq!(forest.loops.len(), 1);
        assert_eq!(forest.loops[0].header, 1);
    }

    #[test]
    fn test_loop_exit_computation() {
        let func = three_block_loop();
        let dt = DominatorTree::compute(&func);
        let forest = LoopNestingForest::build(&func, &dt);
        assert!(forest.loops[0].exits.contains(&2));
    }

    #[test]
    fn test_dominator_chain() {
        let func = three_block_loop();
        let dt = DominatorTree::compute(&func);
        let chain = dt.dominator_chain(2);
        assert!(chain.contains(&0));
    }

    #[test]
    fn test_licm_hoists_to_real_preheader_not_header_minus_one() {
        use rustre_il_llil::{LlilAnnotatedInstr, Size};

        // 0 (entry) → 2 (header) → {3 (latch), 1 (exit)}; 3 → 2.
        // The loop is {2, 3}; the real pre-header is block 0, while
        // `header - 1` is block 1 — the loop EXIT. The old code hoisted there.
        let mut func = LlilFunction {
            entry: Address::new(0x1000),
            address: Address::new(0x1000),
            blocks: vec![
                make_block(0, 0x1000, vec![0x1020]),
                make_block(1, 0x1010, vec![]),
                make_block(2, 0x1020, vec![0x1030, 0x1010]),
                make_block(3, 0x1030, vec![0x1020]),
            ],
            ..Default::default()
        };
        // Loop-invariant instruction in the latch: rbx = rcx + 1 (rcx never
        // defined inside the loop).
        func.blocks[3].instrs.push(LlilAnnotatedInstr {
            address: Address::new(0x1030),
            size: 4,
            length: 4,
            instr: LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rbx".to_owned()),
                size: Size::QWord,
                value: LlilExpr::Add {
                    left: Box::new(LlilExpr::RegisterRef {
                        reg: LlilRegister::Concrete("rcx".to_owned()),
                        size: Size::QWord,
                    }),
                    right: Box::new(LlilExpr::Const { value: 1, size: Size::QWord }),
                    size: Size::QWord,
                },
            },
        });

        let mut ctx = PassContext::new();
        LicmPass.run(&mut func, &mut ctx);

        assert!(func.blocks[3].instrs.is_empty(), "invariant instr not hoisted out of latch");
        assert!(func.blocks[1].instrs.is_empty(), "must NOT hoist into header-1 (loop exit)");
        assert_eq!(func.blocks[0].instrs.len(), 1, "must hoist into the real pre-header");
    }

    #[test]
    fn test_licm_does_not_hoist_from_a_conditionally_executed_block() {
        use rustre_il_llil::{LlilAnnotatedInstr, Size};

        // 0 (entry) → 1 (header) → {2, 3} (if/else inside the loop body) →
        // 4 (merge/latch) → {1 (back edge), 5 (exit)}.
        // Loop body = {1, 2, 3, 4}. Block 2 does NOT dominate the latch (4) —
        // block 3 can reach 4 without ever running block 2 — so an
        // instruction living ONLY in block 2 does NOT execute on every
        // iteration. Hoisting it unconditionally into the pre-header would
        // make it run on iterations that took the OTHER branch: a real
        // semantic change, not an optimization.
        let mut func = LlilFunction {
            entry: Address::new(0x1000),
            address: Address::new(0x1000),
            blocks: vec![
                make_block(0, 0x1000, vec![0x1010]),          // entry
                make_block(1, 0x1010, vec![0x1020, 0x1030]),  // header
                make_block(2, 0x1020, vec![0x1040]),          // if-true
                make_block(3, 0x1030, vec![0x1040]),          // if-false
                make_block(4, 0x1040, vec![0x1010, 0x1050]),  // latch
                make_block(5, 0x1050, vec![]),                // exit
            ],
            ..Default::default()
        };
        // Loop-invariant instruction, but ONLY in the conditionally-taken
        // block 2 (rcx is never defined inside the loop, so `rcx + 1` is
        // textbook invariant — the bug is about WHERE it lives, not whether
        // its value is invariant).
        func.blocks[2].instrs.push(LlilAnnotatedInstr {
            address: Address::new(0x1020),
            size: 4,
            length: 4,
            instr: LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rbx".to_owned()),
                size: Size::QWord,
                value: LlilExpr::Add {
                    left: Box::new(LlilExpr::RegisterRef {
                        reg: LlilRegister::Concrete("rcx".to_owned()),
                        size: Size::QWord,
                    }),
                    right: Box::new(LlilExpr::Const { value: 1, size: Size::QWord }),
                    size: Size::QWord,
                },
            },
        });

        let mut ctx = PassContext::new();
        LicmPass.run(&mut func, &mut ctx);

        assert_eq!(
            func.blocks[2].instrs.len(),
            1,
            "must NOT hoist an instruction out of a block that does not \
             dominate the loop latch — it does not run on every iteration"
        );
        assert!(
            func.blocks[0].instrs.is_empty(),
            "pre-header must stay empty: nothing was safe to hoist"
        );
    }

    #[test]
    fn test_iv_detection() {
        use rustre_il_llil::{LlilAnnotatedInstr, Size};

        let mut func = three_block_loop();
        // Add: rax = rax + 1 in the loop header (block 1).
        let ai = LlilAnnotatedInstr {
            address: Address::new(0x1010),
            size: 4,
            length: 4,
            instr: LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".to_owned()),
                size: Size::QWord,
                value: LlilExpr::Add {
                    left: Box::new(LlilExpr::RegisterRef {
                        reg: LlilRegister::Concrete("rax".to_owned()),
                        size: Size::QWord,
                    }),
                    right: Box::new(LlilExpr::Const { value: 1, size: Size::QWord }),
                    size: Size::QWord,
                },
            },
        };
        func.blocks[1].instrs.push(ai);

        let dt = DominatorTree::compute(&func);
        let forest = LoopNestingForest::build(&func, &dt);
        let iva = InductionVarAnalysis::run(&forest, &func);
        let ivs = iva.ivs_for(1);
        assert_eq!(ivs.len(), 1);
        assert_eq!(ivs[0].name, "rax");
    }
}
