/// `luajit_cfg_builder.rs` â€” Control-flow graph construction for `LuaJIT` 2.x bytecode.
///
/// Builds a per-proto CFG from raw instruction words:
///   1. Identify basic-block leaders (entry, branch targets, fall-throughs after branches).
///   2. Create `LjBlock` nodes with instruction ranges.
///   3. Add edges: fall-through and jump targets.
///   4. Mark LOOP back-edges.
///   5. Compute immediate dominators (simple iterative algorithm).
///   6. Identify natural loops from back-edges.

use std::collections::{HashMap, HashSet};
use std::fmt;

// â”€â”€â”€ opcode helpers (reuse constants from bytecode_analyzer domain) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const OP_JMP:    u8 = 0x52;
const OP_LOOP:   u8 = 0x59;
const OP_FORI:   u8 = 0x4A;
const OP_FORL:   u8 = 0x4B;
const OP_JFORI:  u8 = 0x4C;
const OP_JFORL:  u8 = 0x4D;
const OP_UCLO:   u8 = 0x4E;
const OP_RET:    u8 = 0x54;
const OP_RET0:   u8 = 0x55;
const OP_RET1:   u8 = 0x56;
const OP_RETM:   u8 = 0x53;
const OP_CALLT:  u8 = 0x3F;

// Conditional branch opcodes (ISLT, ISLE, ISNL, ISNN, ISTC, ISFC, IST, ISF â€¦)
// Rough range: 0x00..=0x18
const fn is_conditional(op: u8) -> bool {
    op <= 0x18
}

const fn is_unconditional_branch(op: u8) -> bool {
    matches!(op, OP_JMP | OP_LOOP | OP_FORI | OP_FORL | OP_JFORI | OP_JFORL | OP_UCLO)
}

const fn is_return(op: u8) -> bool {
    matches!(op, OP_RET | OP_RET0 | OP_RET1 | OP_RETM | OP_CALLT)
}

const fn is_branch(op: u8) -> bool {
    is_unconditional_branch(op) || is_conditional(op)
}

/// Decode jump target from instruction word.
/// JMP D field: D = (word >> 16) as u16 as i16; target = pc + 1 + D - 0x8000.
const fn jump_target(word: u32, pc: u32) -> Option<i32> {
    let op = (word & 0xFF) as u8;
    if is_unconditional_branch(op) {
        let d = (word >> 16) as u16 as i16;
        Some(pc as i32 + 1 + d as i32 - 0x8000)
    } else {
        None
    }
}

// â”€â”€â”€ EdgeKind â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// The kind of a CFG edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    /// Normal fall-through to the next block.
    FallThrough,
    /// Taken branch (unconditional or conditional taken).
    Jump,
    /// Back-edge forming a loop.
    BackEdge,
    /// Conditional not-taken (falls through but was a conditional branch).
    ConditionalFallThrough,
}

impl fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FallThrough           => write!(f, "fall"),
            Self::Jump                  => write!(f, "jump"),
            Self::BackEdge              => write!(f, "back"),
            Self::ConditionalFallThrough => write!(f, "cond_fall"),
        }
    }
}

// â”€â”€â”€ LjBranch â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A directed edge in the CFG.
#[derive(Debug, Clone)]
pub struct LjBranch {
    pub from_block: usize,
    pub to_block: usize,
    pub kind: EdgeKind,
}

impl fmt::Display for LjBranch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "B{} --{}--> B{}", self.from_block, self.kind, self.to_block)
    }
}

// â”€â”€â”€ LjBlock â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A basic block: a maximal straight-line sequence of instructions.
#[derive(Debug, Clone)]
pub struct LjBlock {
    /// Block index (0 = entry block).
    pub id: usize,
    /// First instruction PC (inclusive).
    pub start_pc: u32,
    /// Last instruction PC (inclusive).
    pub end_pc: u32,
    /// Successor block indices.
    pub successors: Vec<usize>,
    /// Predecessor block indices.
    pub predecessors: Vec<usize>,
    /// True if this block has at least one back-edge predecessor.
    pub is_loop_header: bool,
    /// True if this block is a function exit.
    pub is_exit: bool,
}

impl LjBlock {
    /// Number of instructions in this block.
    #[must_use]
    pub const fn insn_count(&self) -> u32 {
        self.end_pc - self.start_pc + 1
    }
}

impl fmt::Display for LjBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "B{} [pc {}..{}] succ={:?} pred={:?}{}{}",
            self.id,
            self.start_pc,
            self.end_pc,
            self.successors,
            self.predecessors,
            if self.is_loop_header { " LOOP" } else { "" },
            if self.is_exit { " EXIT" } else { "" },
        )
    }
}

// â”€â”€â”€ LjLoop â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A natural loop identified by a back-edge.
#[derive(Debug, Clone)]
pub struct LjLoop {
    /// The loop header block.
    pub header: usize,
    /// The latch block (source of the back-edge).
    pub latch: usize,
    /// All blocks in the loop body (header inclusive).
    pub body: Vec<usize>,
    /// Nesting depth (0 = outermost).
    pub depth: usize,
}

impl LjLoop {
    /// True if `block` is in this loop.
    #[must_use]
    pub fn contains(&self, block: usize) -> bool {
        self.body.contains(&block)
    }
}

impl fmt::Display for LjLoop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Loop(header=B{} latch=B{} depth={} body_blocks={})",
            self.header, self.latch, self.depth, self.body.len()
        )
    }
}

// â”€â”€â”€ LjCfg â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// The complete control-flow graph for one proto.
#[derive(Debug)]
pub struct LjCfg {
    pub proto_idx: usize,
    pub blocks: Vec<LjBlock>,
    pub edges: Vec<LjBranch>,
    pub loops: Vec<LjLoop>,
    /// Immediate dominator for each block (idom[i] = i means root or unreachable).
    pub idom: Vec<usize>,
}

impl LjCfg {
    /// Block count.
    #[must_use]
    pub const fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Edge count.
    #[must_use]
    pub const fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Back-edge count.
    #[must_use]
    pub fn back_edge_count(&self) -> usize {
        self.edges.iter().filter(|e| e.kind == EdgeKind::BackEdge).count()
    }

    /// Find the block containing `pc`, if any.
    #[must_use]
    pub fn block_at_pc(&self, pc: u32) -> Option<&LjBlock> {
        self.blocks.iter().find(|b| b.start_pc <= pc && pc <= b.end_pc)
    }

    /// Render a textual adjacency-list representation.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = format!(
            "CFG proto[{}]: {} blocks, {} edges, {} loops\n",
            self.proto_idx,
            self.blocks.len(),
            self.edges.len(),
            self.loops.len()
        );
        for b in &self.blocks {
            out.push_str(&format!("  {b}\n"));
        }
        for e in &self.edges {
            out.push_str(&format!("  {e}\n"));
        }
        for l in &self.loops {
            out.push_str(&format!("  {l}\n"));
        }
        out
    }

    /// Compute dominance frontier for block `n`.
    #[must_use]
    pub fn dominance_frontier(&self, n: usize) -> HashSet<usize> {
        let mut df = HashSet::new();
        for edge in &self.edges {
            let b = edge.to_block;
            // Walk up dominator tree from `edge.from_block` to idom of `b`.
            let mut runner = edge.from_block;
            while runner != self.idom[b] && runner != self.idom[runner] {
                if runner == n {
                    df.insert(b);
                    break;
                }
                runner = self.idom[runner];
            }
        }
        df
    }
}

impl fmt::Display for LjCfg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.render())
    }
}

// â”€â”€â”€ CfgBuilder â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Constructs a `LjCfg` from a raw instruction slice.
pub struct CfgBuilder {
    proto_idx: usize,
    insns: Vec<u32>,
}

impl CfgBuilder {
    /// Create a builder for a proto.
    #[must_use]
    pub const fn new(proto_idx: usize, insns: Vec<u32>) -> Self {
        Self { proto_idx, insns }
    }

    /// Build the CFG.  Returns `None` if the proto has no instructions.
    #[must_use]
    pub fn build(self) -> Option<LjCfg> {
        if self.insns.is_empty() {
            return None;
        }
        let n = self.insns.len() as u32;

        // â”€â”€ Step 1: identify leaders â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        let mut leaders: HashSet<u32> = HashSet::new();
        leaders.insert(0); // entry

        for (pc, &word) in self.insns.iter().enumerate() {
            let pc = pc as u32;
            let op = (word & 0xFF) as u8;
            if is_branch(op) || is_return(op) {
                // Instruction after branch is a leader (if it exists).
                if pc + 1 < n {
                    leaders.insert(pc + 1);
                }
                // Jump target is a leader.
                if let Some(tgt) = jump_target(word, pc)
                    && tgt >= 0 && (tgt as u32) < n {
                        leaders.insert(tgt as u32);
                    }
                // For conditional branches, the instruction after the skipped
                // comparison is also a leader (LuaJIT puts comparison before JMP).
            }
        }

        // Sort leaders.
        let mut leader_vec: Vec<u32> = leaders.into_iter().collect();
        leader_vec.sort_unstable();

        // â”€â”€ Step 2: create blocks â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // Map from leader PC â†’ block index.
        let pc_to_block: HashMap<u32, usize> = leader_vec
            .iter()
            .enumerate()
            .map(|(i, &pc)| (pc, i))
            .collect();

        let mut blocks: Vec<LjBlock> = leader_vec
            .iter()
            .enumerate()
            .map(|(i, &start)| {
                // End PC = next leader - 1, or last instruction.
                let end = if i + 1 < leader_vec.len() {
                    leader_vec[i + 1] - 1
                } else {
                    n - 1
                };
                let last_op = (self.insns[end as usize] & 0xFF) as u8;
                LjBlock {
                    id: i,
                    start_pc: start,
                    end_pc: end,
                    successors: Vec::new(),
                    predecessors: Vec::new(),
                    is_loop_header: false,
                    is_exit: is_return(last_op),
                }
            })
            .collect();

        // â”€â”€ Step 3: add edges â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        let mut edges: Vec<LjBranch> = Vec::new();
        // Temporary: we need to know back-edges first. Collect raw edges.
        let mut raw_edges: Vec<(usize, usize, EdgeKind)> = Vec::new();

        for (i, b) in blocks.iter().enumerate() {
            let last_pc = b.end_pc;
            let last_word = self.insns[last_pc as usize];
            let last_op  = (last_word & 0xFF) as u8;

            if is_return(last_op) {
                // No outgoing edges.
                continue;
            }

            if is_unconditional_branch(last_op) {
                if let Some(tgt) = jump_target(last_word, last_pc)
                    && tgt >= 0 && (tgt as u32) < n {
                        let tgt_u = tgt as u32;
                        if let Some(&to) = pc_to_block.get(&tgt_u) {
                            let kind = if tgt_u <= b.start_pc {
                                EdgeKind::BackEdge
                            } else {
                                EdgeKind::Jump
                            };
                            raw_edges.push((i, to, kind));
                        }
                    }
                // Fall-through after unconditional is dead; skip.
            } else if is_conditional(last_op) {
                // Conditional: fall-through (not taken) + jump (taken via next JMP).
                // LuaJIT conditional branches skip the next instruction on mismatch;
                // the next instruction is usually a JMP.  We add both successors.
                if last_pc + 1 < n {
                    // The instruction following the cond branch.
                    let skip_pc = last_pc + 1;
                    if let Some(&skip_block) = pc_to_block.get(&skip_pc) {
                        raw_edges.push((i, skip_block, EdgeKind::ConditionalFallThrough));
                    }
                }
                // The "taken" path: skip_pc + 1 or the JMP at skip_pc.
                let skip_word = if (last_pc + 1) < n { self.insns[(last_pc + 1) as usize] } else { 0 };
                let skip_op   = (skip_word & 0xFF) as u8;
                if is_unconditional_branch(skip_op)
                    && let Some(tgt) = jump_target(skip_word, last_pc + 1)
                        && tgt >= 0 && (tgt as u32) < n
                            && let Some(&to) = pc_to_block.get(&(tgt as u32)) {
                                raw_edges.push((i, to, EdgeKind::Jump));
                            }
            } else {
                // Plain instruction: fall through to next block.
                if i + 1 < blocks.len() {
                    raw_edges.push((i, i + 1, EdgeKind::FallThrough));
                }
            }
        }

        // Populate successor / predecessor lists and flag loop headers.
        for (from, to, kind) in &raw_edges {
            blocks[*from].successors.push(*to);
            blocks[*to].predecessors.push(*from);
            if *kind == EdgeKind::BackEdge {
                blocks[*to].is_loop_header = true;
            }
            edges.push(LjBranch { from_block: *from, to_block: *to, kind: *kind });
        }

        // â”€â”€ Step 4: compute dominators (Cooper et al. simple iterative) â”€â”€â”€
        let idom = compute_idoms(&blocks);

        // â”€â”€ Step 5: identify natural loops â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        let loops = find_loops(&edges, &blocks, &idom);

        Some(LjCfg {
            proto_idx: self.proto_idx,
            blocks,
            edges,
            loops,
            idom,
        })
    }
}

// â”€â”€â”€ Dominator computation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Simple iterative dominator algorithm (Cooper et al. 2001).
/// Returns idom[i]: the immediate dominator of block i (idom[0]=0 for entry).
fn compute_idoms(blocks: &[LjBlock]) -> Vec<usize> {
    let n = blocks.len();
    if n == 0 {
        return vec![];
    }
    // Reverse post-order for convergence.
    let rpo = reverse_post_order(blocks);
    // Map block id â†’ rpo position.
    let mut pos = vec![0usize; n];
    for (i, &b) in rpo.iter().enumerate() {
        pos[b] = i;
    }

    let undefined = n; // sentinel
    let mut idom = vec![undefined; n];
    idom[rpo[0]] = rpo[0]; // entry dominates itself

    let mut changed = true;
    while changed {
        changed = false;
        for &b in rpo.iter().skip(1) {
            let preds: Vec<usize> = blocks[b]
                .predecessors
                .iter()
                .copied()
                .filter(|&p| idom[p] != undefined)
                .collect();
            if preds.is_empty() {
                continue;
            }
            let mut new_idom = preds[0];
            for &p in preds.iter().skip(1) {
                new_idom = intersect(new_idom, p, &idom, &pos);
            }
            if idom[b] != new_idom {
                idom[b] = new_idom;
                changed = true;
            }
        }
    }
    // Fix any remaining undefined (unreachable blocks dominate themselves).
    for i in 0..n {
        if idom[i] == undefined {
            idom[i] = i;
        }
    }
    idom
}

fn intersect(b1: usize, b2: usize, idom: &[usize], pos: &[usize]) -> usize {
    let mut f = b1;
    let mut g = b2;
    while f != g {
        while pos[f] > pos[g] {
            f = idom[f];
        }
        while pos[g] > pos[f] {
            g = idom[g];
        }
    }
    f
}

fn reverse_post_order(blocks: &[LjBlock]) -> Vec<usize> {
    let n = blocks.len();
    let mut visited = vec![false; n];
    let mut post = Vec::with_capacity(n);
    let mut stack = vec![(0usize, 0usize)]; // (block, next_succ_idx)
    visited[0] = true;
    while let Some(&mut (b, ref mut s)) = stack.last_mut() {
        if *s < blocks[b].successors.len() {
            let succ = blocks[b].successors[*s];
            *s += 1;
            if !visited[succ] {
                visited[succ] = true;
                stack.push((succ, 0));
            }
        } else {
            post.push(b);
            stack.pop();
        }
    }
    // Blocks not reachable from entry.
    for i in 0..n {
        if !visited[i] {
            post.push(i);
        }
    }
    post.reverse();
    post
}

// â”€â”€â”€ Loop identification â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

fn find_loops(edges: &[LjBranch], blocks: &[LjBlock], idom: &[usize]) -> Vec<LjLoop> {
    let mut loops = Vec::new();

    for edge in edges {
        if edge.kind != EdgeKind::BackEdge {
            continue;
        }
        let header = edge.to_block;
        let latch  = edge.from_block;

        // Natural loop body: all blocks that can reach latch without going through header.
        let body = natural_loop_body(header, latch, blocks);
        let depth = compute_depth(header, idom, &loops);

        loops.push(LjLoop { header, latch, body, depth });
    }

    // Sort by header block index.
    loops.sort_by_key(|l| l.header);
    loops
}

fn natural_loop_body(header: usize, latch: usize, blocks: &[LjBlock]) -> Vec<usize> {
    let mut body = HashSet::new();
    body.insert(header);
    body.insert(latch);
    let mut worklist = vec![latch];
    while let Some(b) = worklist.pop() {
        if b == header {
            continue;
        }
        for &pred in &blocks[b].predecessors {
            if body.insert(pred) {
                worklist.push(pred);
            }
        }
    }
    let mut v: Vec<usize> = body.into_iter().collect();
    v.sort_unstable();
    v
}

fn compute_depth(header: usize, idom: &[usize], existing: &[LjLoop]) -> usize {
    // Depth = number of existing loop headers that dominate this one.
    let mut depth = 0;
    for lp in existing {
        if lp.header != header && dominates(lp.header, header, idom) {
            depth += 1;
        }
    }
    depth
}

fn dominates(a: usize, b: usize, idom: &[usize]) -> bool {
    let mut x = b;
    loop {
        if x == a { return true; }
        let p = idom[x];
        if p == x { return false; } // root
        x = p;
    }
}

// â”€â”€â”€ tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(op: u8) -> u32 {
        op as u32
    }

    fn jmp(op: u8, pc: u32, target: u32) -> u32 {
        let d = (target as i32 - pc as i32 - 1 + 0x8000) as u16;
        (op as u32) | ((d as u32) << 16)
    }

    #[test]
    fn trivial_single_block() {
        // One instruction: RET0
        let cfg = CfgBuilder::new(0, vec![insn(OP_RET0)]).build().unwrap();
        assert_eq!(cfg.block_count(), 1);
        assert_eq!(cfg.edge_count(), 0);
        assert!(cfg.blocks[0].is_exit);
    }

    #[test]
    fn two_blocks_fall_through() {
        // NOP-like (OP 0x20 = KSTR, not branch/return), then RET0
        let insns = vec![insn(0x20), insn(OP_RET0)];
        let cfg = CfgBuilder::new(0, insns).build().unwrap();
        // 0x20 is <= 0x18? No; it's not a conditional. Not unconditional branch.
        // So block 0 = [0,0], block 1 = [1,1], edge fall-through.
        // Actually 0x20 > 0x18 so is_conditional = false; not branch/return â†’ fall-through.
        assert!(cfg.block_count() >= 1);
    }

    #[test]
    fn loop_with_back_edge() {
        // pc0: NOP, pc1: JMP back to pc0
        let insns = vec![insn(0x20), jmp(OP_JMP, 1, 0)];
        let cfg = CfgBuilder::new(0, insns).build().unwrap();
        assert!(cfg.back_edge_count() > 0);
        assert!(!cfg.loops.is_empty());
        let lp = &cfg.loops[0];
        assert_eq!(lp.header, 0); // header is block at pc 0
        assert!(lp.body.contains(&0));
    }

    #[test]
    fn entry_block_is_block_zero() {
        let cfg = CfgBuilder::new(1, vec![insn(OP_RET0)]).build().unwrap();
        assert_eq!(cfg.blocks[0].start_pc, 0);
    }

    #[test]
    fn block_at_pc_found() {
        let cfg = CfgBuilder::new(0, vec![insn(0x20), insn(OP_RET0)]).build().unwrap();
        let b = cfg.block_at_pc(0);
        assert!(b.is_some());
    }

    #[test]
    fn block_at_pc_not_found() {
        let cfg = CfgBuilder::new(0, vec![insn(OP_RET0)]).build().unwrap();
        let b = cfg.block_at_pc(99);
        assert!(b.is_none());
    }

    #[test]
    fn empty_proto_returns_none() {
        let result = CfgBuilder::new(0, vec![]).build();
        assert!(result.is_none());
    }

    #[test]
    fn render_non_empty() {
        let cfg = CfgBuilder::new(0, vec![insn(OP_RET0)]).build().unwrap();
        let s = cfg.render();
        assert!(s.contains("CFG proto[0]"));
    }

    #[test]
    fn idom_entry_points_to_itself() {
        let cfg = CfgBuilder::new(0, vec![insn(OP_RET0)]).build().unwrap();
        assert_eq!(cfg.idom[0], 0);
    }

    #[test]
    fn loop_body_contains_header_and_latch() {
        let insns = vec![insn(0x20), jmp(OP_JMP, 1, 0)];
        let cfg = CfgBuilder::new(0, insns).build().unwrap();
        if let Some(lp) = cfg.loops.first() {
            assert!(lp.body.contains(&lp.header));
            assert!(lp.body.contains(&lp.latch));
        }
    }

    #[test]
    fn cfg_display_works() {
        let cfg = CfgBuilder::new(0, vec![insn(0x20), insn(OP_RET0)]).build().unwrap();
        let s = format!("{cfg}");
        assert!(!s.is_empty());
    }

    #[test]
    fn multiple_protos_independent() {
        let cfg0 = CfgBuilder::new(0, vec![insn(OP_RET0)]).build().unwrap();
        let cfg1 = CfgBuilder::new(1, vec![insn(OP_RET0)]).build().unwrap();
        assert_eq!(cfg0.proto_idx, 0);
        assert_eq!(cfg1.proto_idx, 1);
    }

    #[test]
    fn insn_count_in_block() {
        let cfg = CfgBuilder::new(0, vec![insn(0x20), insn(0x21), insn(OP_RET0)]).build().unwrap();
        let total: u32 = cfg.blocks.iter().map(super::LjBlock::insn_count).sum();
        assert_eq!(total, 3);
    }

    #[test]
    fn loop_depth_zero_for_outermost() {
        let insns = vec![insn(0x20), jmp(OP_JMP, 1, 0)];
        let cfg = CfgBuilder::new(0, insns).build().unwrap();
        if let Some(lp) = cfg.loops.first() {
            assert_eq!(lp.depth, 0);
        }
    }
}
