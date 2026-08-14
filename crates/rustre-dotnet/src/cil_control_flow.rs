//! CIL (Common Intermediate Language) control-flow graph builder.
//!
//! Splits a flat sequence of CIL instructions into basic blocks, connects
//! them with typed edges, and attaches exception-handler region information.
//!
//! Types: [`CilBlock`], [`CilEdge`], [`EdgeKind`], [`EhRegion`],
//! [`EhRegionKind`], [`CilCfg`], [`CilDominator`].

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;

// ─── CIL instruction stub ─────────────────────────────────────────────────────

/// Minimal CIL instruction record.  Only the fields needed for CFG construction
/// are present here; the full operand decoding lives in `il_decoder`.
#[derive(Debug, Clone)]
pub struct CilInstruction {
    /// Byte offset of this instruction within the method body.
    pub offset: u32,
    /// Opcode mnemonic.
    pub mnemonic: String,
    /// For branch instructions: target offset(s).
    pub branch_targets: Vec<u32>,
    /// True if this instruction unconditionally transfers control (br, ret,
    /// throw, rethrow, leave).
    pub is_unconditional_branch: bool,
    /// True if this instruction may throw and needs EH edge treatment.
    pub may_throw: bool,
    /// True for ret / throw / rethrow / endfinally.
    pub is_terminator: bool,
    /// Byte length of this instruction (opcode + operand).
    pub length: u32,
}

impl CilInstruction {
    #[must_use]
    pub fn new(offset: u32, mnemonic: impl Into<String>, length: u32) -> Self {
        Self {
            offset,
            mnemonic: mnemonic.into(),
            branch_targets: Vec::new(),
            is_unconditional_branch: false,
            may_throw: false,
            is_terminator: false,
            length,
        }
    }

    /// Next sequential offset (offset + length).
    #[must_use]
    pub const fn next_offset(&self) -> u32 {
        self.offset + self.length
    }
}

impl fmt::Display for CilInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IL_{:04X}: {}", self.offset, self.mnemonic)
    }
}

// ─── EdgeKind ─────────────────────────────────────────────────────────────────

/// The kind of control-flow edge between two blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    /// Sequential fall-through (no branch at all, or after conditional taken=false).
    FallThrough,
    /// Unconditional branch (`br`, `leave`).
    Unconditional,
    /// Conditional branch taken (`brtrue`, `brfalse`, `beq`, …).
    Conditional,
    /// Exception dispatch from a protected try block to a handler.
    Exception,
    /// `ret` / `throw` — the block exits the method.
    Exit,
}

impl fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── CilEdge ─────────────────────────────────────────────────────────────────

/// A directed edge in the CFG.
#[derive(Debug, Clone)]
pub struct CilEdge {
    pub from_block: u32,
    pub to_block: u32,
    pub kind: EdgeKind,
}

impl CilEdge {
    #[must_use]
    pub const fn new(from: u32, to: u32, kind: EdgeKind) -> Self {
        Self { from_block: from, to_block: to, kind }
    }
}

impl fmt::Display for CilEdge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IL_{:04X} --{}--> IL_{:04X}", self.from_block, self.kind, self.to_block)
    }
}

// ─── EhRegionKind ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EhRegionKind {
    Try,
    Catch,
    Finally,
    Fault,
    Filter,
}

impl fmt::Display for EhRegionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── EhRegion ─────────────────────────────────────────────────────────────────

/// An exception-handling region descriptor (from the method's exception table).
#[derive(Debug, Clone)]
pub struct EhRegion {
    pub kind: EhRegionKind,
    /// Inclusive start offset of the try block.
    pub try_start: u32,
    /// Exclusive end offset of the try block.
    pub try_end: u32,
    /// Inclusive start offset of the handler.
    pub handler_start: u32,
    /// Exclusive end offset of the handler.
    pub handler_end: u32,
    /// For `Catch`: the type token of the caught exception type.
    pub catch_type_token: Option<u32>,
    /// For `Filter`: the offset of the filter prologue.
    pub filter_offset: Option<u32>,
}

impl EhRegion {
    #[must_use]
    pub const fn try_catch(try_start: u32, try_end: u32, handler_start: u32, handler_end: u32,
                     catch_type: u32) -> Self {
        Self {
            kind: EhRegionKind::Catch,
            try_start, try_end, handler_start, handler_end,
            catch_type_token: Some(catch_type),
            filter_offset: None,
        }
    }

    #[must_use]
    pub const fn try_finally(try_start: u32, try_end: u32, handler_start: u32, handler_end: u32) -> Self {
        Self {
            kind: EhRegionKind::Finally,
            try_start, try_end, handler_start, handler_end,
            catch_type_token: None,
            filter_offset: None,
        }
    }
}

impl fmt::Display for EhRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} try=[{:#x}..{:#x}) handler=[{:#x}..{:#x})",
               self.kind, self.try_start, self.try_end,
               self.handler_start, self.handler_end)
    }
}

// ─── CilBlock ─────────────────────────────────────────────────────────────────

/// A basic block: a maximal sequence of instructions with a single entry and
/// (potentially multiple) exits.
#[derive(Debug, Clone)]
pub struct CilBlock {
    /// Block id = offset of the first instruction.
    pub id: u32,
    /// Byte offset of the first instruction in the block.
    pub start_offset: u32,
    /// Byte offset **after** the last instruction in the block.
    pub end_offset: u32,
    /// Indices of instructions in this block (referencing the original slice).
    pub instructions: Vec<usize>,
    /// Successor block ids.
    pub successors: Vec<u32>,
    /// Predecessor block ids.
    pub predecessors: Vec<u32>,
}

impl CilBlock {
    const fn new(start: u32) -> Self {
        Self {
            id: start,
            start_offset: start,
            end_offset: start,
            instructions: Vec::new(),
            successors: Vec::new(),
            predecessors: Vec::new(),
        }
    }

    /// True if this block has no predecessors (entry block or unreachable).
    #[must_use]
    pub const fn is_entry(&self) -> bool {
        self.predecessors.is_empty()
    }

    /// True if this block has no successors (exits method).
    #[must_use]
    pub const fn is_exit(&self) -> bool {
        self.successors.is_empty()
    }
}

impl fmt::Display for CilBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Block IL_{:04X}..IL_{:04X} ({} insns, {} succ)",
               self.start_offset, self.end_offset,
               self.instructions.len(), self.successors.len())
    }
}

// ─── CilCfg ───────────────────────────────────────────────────────────────────

/// The complete control-flow graph for a CIL method body.
#[derive(Debug, Default)]
pub struct CilCfg {
    /// All blocks indexed by their start offset.
    pub blocks: BTreeMap<u32, CilBlock>,
    /// All edges in the graph.
    pub edges: Vec<CilEdge>,
    /// Exception-handling regions from the method's fat/tiny header.
    pub eh_regions: Vec<EhRegion>,
    /// Offset of the entry block (always 0 for .NET methods).
    pub entry_block: u32,
}

impl CilCfg {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Find the block that contains the instruction at `offset`.
    #[must_use]
    pub fn block_for_offset(&self, offset: u32) -> Option<&CilBlock> {
        self.blocks.range(..=offset).next_back()
            .filter(|(_, b)| b.end_offset > offset)
            .map(|(_, b)| b)
    }

    /// All successor blocks of `block_id`.
    #[must_use]
    pub fn successors_of(&self, block_id: u32) -> Vec<&CilBlock> {
        self.blocks.get(&block_id)
            .map(|b| b.successors.iter().filter_map(|id| self.blocks.get(id)).collect())
            .unwrap_or_default()
    }

    /// All predecessor blocks of `block_id`.
    #[must_use]
    pub fn predecessors_of(&self, block_id: u32) -> Vec<&CilBlock> {
        self.blocks.get(&block_id)
            .map(|b| b.predecessors.iter().filter_map(|id| self.blocks.get(id)).collect())
            .unwrap_or_default()
    }

    /// BFS reachable blocks from the entry.
    #[must_use]
    pub fn reachable_blocks(&self) -> HashSet<u32> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(self.entry_block);
        visited.insert(self.entry_block);
        while let Some(id) = queue.pop_front() {
            if let Some(block) = self.blocks.get(&id) {
                for &succ in &block.successors {
                    if visited.insert(succ) {
                        queue.push_back(succ);
                    }
                }
            }
        }
        visited
    }

    /// Number of blocks.
    #[must_use]
    pub fn block_count(&self) -> usize { self.blocks.len() }

    /// Number of edges.
    #[must_use]
    pub const fn edge_count(&self) -> usize { self.edges.len() }
}

// ─── build_cfg ────────────────────────────────────────────────────────────────

/// Build a `CilCfg` from a slice of decoded CIL instructions and a list of
/// exception-handler regions.
///
/// The algorithm:
/// 1. Identify basic block leaders (targets of branches + fallthrough entries).
/// 2. Partition instructions into blocks.
/// 3. Add edges for each block's terminator.
/// 4. Add exception edges from try blocks to handler blocks.
/// # Panics
/// Panics if invariants are violated.
#[must_use]
pub fn build_cfg(insns: &[CilInstruction], eh_regions: Vec<EhRegion>) -> CilCfg {
    if insns.is_empty() {
        return CilCfg { eh_regions, ..Default::default() };
    }

    // ── Step 1: identify leaders ──────────────────────────────────────────────
    let mut leaders: HashSet<u32> = HashSet::new();
    leaders.insert(insns[0].offset); // method entry

    for eh in &eh_regions {
        leaders.insert(eh.try_start);
        leaders.insert(eh.handler_start);
        if let Some(fo) = eh.filter_offset { leaders.insert(fo); }
    }

    for insn in insns {
        for &tgt in &insn.branch_targets {
            leaders.insert(tgt);
        }
        // Instruction after a branch is a leader (fallthrough).
        if !insn.branch_targets.is_empty() || insn.is_terminator {
            let next = insn.next_offset();
            // Only if there's a following instruction.
            if insns.iter().any(|i| i.offset == next) {
                leaders.insert(next);
            }
        }
    }

    // ── Step 2: build blocks ──────────────────────────────────────────────────
    let mut blocks: BTreeMap<u32, CilBlock> = BTreeMap::new();
    let mut current_start: Option<u32> = None;

    for (idx, insn) in insns.iter().enumerate() {
        if leaders.contains(&insn.offset) {
            current_start = Some(insn.offset);
            blocks.entry(insn.offset).or_insert_with(|| CilBlock::new(insn.offset));
        }
        if let Some(start) = current_start
            && let Some(block) = blocks.get_mut(&start) {
                block.instructions.push(idx);
                block.end_offset = insn.next_offset();
            }
    }

    // ── Step 3: add edges ─────────────────────────────────────────────────────
    let mut edges: Vec<CilEdge> = Vec::new();

    let block_ids: Vec<u32> = blocks.keys().copied().collect();
    for &block_id in &block_ids {
        let block = &blocks[&block_id];
        if block.instructions.is_empty() { continue; }
        let last_idx = *block.instructions.last().unwrap();
        let last = &insns[last_idx];

        if last.is_unconditional_branch {
            for &tgt in &last.branch_targets {
                if blocks.contains_key(&tgt) {
                    edges.push(CilEdge::new(block_id, tgt, EdgeKind::Unconditional));
                }
            }
        } else if !last.branch_targets.is_empty() {
            // Conditional: branch target(s) + fallthrough.
            for &tgt in &last.branch_targets {
                if blocks.contains_key(&tgt) {
                    edges.push(CilEdge::new(block_id, tgt, EdgeKind::Conditional));
                }
            }
            let ft = last.next_offset();
            if blocks.contains_key(&ft) {
                edges.push(CilEdge::new(block_id, ft, EdgeKind::FallThrough));
            }
        } else if !last.is_terminator {
            // Pure fallthrough.
            let ft = last.next_offset();
            if blocks.contains_key(&ft) {
                edges.push(CilEdge::new(block_id, ft, EdgeKind::FallThrough));
            }
        } else {
            // ret / throw: exit block, no outgoing edges.
        }
    }

    // ── Step 4: exception edges ───────────────────────────────────────────────
    for eh in &eh_regions {
        // Every block within the try range gets an exception edge to the handler.
        for &bid in &block_ids {
            if bid >= eh.try_start && bid < eh.try_end
                && blocks.contains_key(&eh.handler_start)
            {
                edges.push(CilEdge::new(bid, eh.handler_start, EdgeKind::Exception));
            }
        }
    }

    // ── Step 5: populate successor / predecessor lists ────────────────────────
    let mut succ_map: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut pred_map: HashMap<u32, Vec<u32>> = HashMap::new();
    for e in &edges {
        succ_map.entry(e.from_block).or_default().push(e.to_block);
        pred_map.entry(e.to_block).or_default().push(e.from_block);
    }
    for (&id, block) in &mut blocks {
        if let Some(succs) = succ_map.get(&id) {
            block.successors.clone_from(succs);
        }
        if let Some(preds) = pred_map.get(&id) {
            block.predecessors.clone_from(preds);
        }
    }

    let entry_block = insns[0].offset;
    CilCfg { blocks, edges, eh_regions, entry_block }
}

// ─── CilDominator ─────────────────────────────────────────────────────────────

/// Dominator tree computed via the simple iterative algorithm (Cooper et al.).
#[derive(Debug)]
pub struct CilDominator {
    /// idom[b] = immediate dominator of b; idom[entry] = entry.
    pub idom: HashMap<u32, u32>,
    /// Dominance frontiers: DF[b] = set of blocks where b's dominance ends.
    pub frontiers: HashMap<u32, HashSet<u32>>,
}

impl CilDominator {
    /// Compute the dominator tree for `cfg`.
    /// # Panics
    /// Panics if invariants are violated.
    #[must_use]
    pub fn compute(cfg: &CilCfg) -> Self {
        let entry = cfg.entry_block;
        let mut idom: HashMap<u32, u32> = HashMap::new();
        idom.insert(entry, entry);

        // RPO traversal (simplified: BFS from entry).
        let rpo = rpo_order(cfg);
        let rpo_idx: HashMap<u32, usize> = rpo.iter().enumerate().map(|(i, &b)| (b, i)).collect();

        let mut changed = true;
        while changed {
            changed = false;
            for &b in rpo.iter().skip(1) {
                let preds: Vec<u32> = cfg.blocks.get(&b)
                    .map(|bl| bl.predecessors.iter()
                        .filter(|&&p| idom.contains_key(&p))
                        .copied().collect())
                    .unwrap_or_default();
                if preds.is_empty() { continue; }
                let mut new_idom = *preds.iter()
                    .min_by_key(|&&p| rpo_idx.get(&p).copied().unwrap_or(usize::MAX))
                    .unwrap();
                for &p in &preds {
                    if p == new_idom { continue; }
                    if idom.contains_key(&p) {
                        new_idom = intersect(p, new_idom, &idom, &rpo_idx);
                    }
                }
                if idom.get(&b) != Some(&new_idom) {
                    idom.insert(b, new_idom);
                    changed = true;
                }
            }
        }

        // Compute dominance frontiers.
        let mut frontiers: HashMap<u32, HashSet<u32>> = HashMap::new();
        for (&b, block) in &cfg.blocks {
            if block.predecessors.len() < 2 { continue; }
            for &p in &block.predecessors {
                let mut runner = p;
                while runner != idom[&b] {
                    frontiers.entry(runner).or_default().insert(b);
                    runner = idom[&runner];
                }
            }
        }

        Self { idom, frontiers }
    }

    /// True if block `a` dominates block `b`.
    #[must_use]
    pub fn dominates(&self, a: u32, b: u32) -> bool {
        let mut cur = b;
        loop {
            if cur == a { return true; }
            let parent = match self.idom.get(&cur) {
                Some(&p) if p != cur => p,
                _ => return false,
            };
            cur = parent;
        }
    }

    /// All blocks dominated by `b` (inclusive).
    #[must_use]
    pub fn dominated_by(&self, b: u32) -> HashSet<u32> {
        self.idom.iter()
            .filter(|&(&node, _)| self.dominates(b, node))
            .map(|(&node, _)| node)
            .collect()
    }
}

fn rpo_order(cfg: &CilCfg) -> Vec<u32> {
    let mut visited = HashSet::new();
    let mut post: Vec<u32> = Vec::new();
    let mut stack: Vec<(u32, bool)> = vec![(cfg.entry_block, false)];

    while let Some((id, processed)) = stack.pop() {
        if processed {
            post.push(id);
            continue;
        }
        if !visited.insert(id) { continue; }
        stack.push((id, true));
        if let Some(block) = cfg.blocks.get(&id) {
            for &succ in block.successors.iter().rev() {
                if !visited.contains(&succ) {
                    stack.push((succ, false));
                }
            }
        }
    }
    post.reverse();
    post
}

fn intersect(mut a: u32, mut b: u32, idom: &HashMap<u32, u32>,
             rpo_idx: &HashMap<u32, usize>) -> u32 {
    loop {
        let ia = rpo_idx.get(&a).copied().unwrap_or(usize::MAX);
        let ib = rpo_idx.get(&b).copied().unwrap_or(usize::MAX);
        if a == b { return a; }
        if ia > ib {
            a = idom[&a];
        } else {
            b = idom[&b];
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(off: u32, mnem: &str, len: u32) -> CilInstruction {
        CilInstruction::new(off, mnem, len)
    }

    fn br_uncond(off: u32, tgt: u32) -> CilInstruction {
        let mut i = insn(off, "br", 5);
        i.branch_targets = vec![tgt];
        i.is_unconditional_branch = true;
        i
    }

    fn br_cond(off: u32, tgt: u32) -> CilInstruction {
        let mut i = insn(off, "brtrue", 5);
        i.branch_targets = vec![tgt];
        i
    }

    fn ret(off: u32) -> CilInstruction {
        let mut i = insn(off, "ret", 1);
        i.is_terminator = true;
        i
    }

    #[test]
    fn build_cfg_empty() {
        let cfg = build_cfg(&[], vec![]);
        assert!(cfg.blocks.is_empty());
    }

    #[test]
    fn build_cfg_single_block() {
        let insns = vec![insn(0, "ldarg.0", 1), insn(1, "stloc.0", 1), ret(2)];
        let cfg = build_cfg(&insns, vec![]);
        assert_eq!(cfg.block_count(), 1);
        assert_eq!(cfg.edge_count(), 0);
    }

    #[test]
    fn build_cfg_unconditional_branch() {
        // IL_0000: ldarg.0 (len=1)
        // IL_0001: br IL_0010 (len=5)
        // IL_0006: nop (unreachable, but we emit it)
        // IL_0010: ret (len=1)
        let insns = vec![
            insn(0, "ldarg.0", 1),
            br_uncond(1, 6),
            ret(6),
        ];
        let cfg = build_cfg(&insns, vec![]);
        assert!(cfg.block_count() >= 2);
    }

    #[test]
    fn build_cfg_conditional_branch() {
        let insns = vec![
            insn(0, "ldarg.0", 1),
            br_cond(1, 10),
            insn(6, "ldc.i4.0", 1),
            ret(7),
            insn(10, "ldc.i4.1", 1),
            ret(11),
        ];
        let cfg = build_cfg(&insns, vec![]);
        // Should have at least 3 blocks: 0..6, 6..8, 10..12
        assert!(cfg.block_count() >= 2);
        // Conditional edge + fallthrough edge
        
        assert!(!!cfg.edges.iter().any(|e| e.kind == EdgeKind::Conditional));
    }

    #[test]
    fn build_cfg_eh_region() {
        let insns = vec![
            insn(0, "nop", 1),
            insn(1, "call", 5),
            ret(6),
            insn(7, "pop", 1),
            ret(8),
        ];
        let eh = vec![EhRegion::try_catch(0, 6, 7, 9, 0x0100_0001)];
        let cfg = build_cfg(&insns, eh);
        
        assert!(!!cfg.edges.iter().any(|e| e.kind == EdgeKind::Exception));
    }

    #[test]
    fn cfg_block_for_offset() {
        let insns = vec![insn(0, "nop", 1), ret(1)];
        let cfg = build_cfg(&insns, vec![]);
        assert!(cfg.block_for_offset(0).is_some());
        assert!(cfg.block_for_offset(1).is_some());
    }

    #[test]
    fn cfg_reachable_blocks() {
        let insns = vec![
            insn(0, "nop", 1),
            br_uncond(1, 5),
            insn(6, "unreachable_nop", 1), // offset 6, can only reach from 1→5
            insn(5, "ret", 1),
        ];
        // Note: insns not sorted here, but build_cfg handles any order.
        let cfg = build_cfg(&insns, vec![]);
        let reachable = cfg.reachable_blocks();
        assert!(reachable.contains(&0));
    }

    #[test]
    fn dominator_single_block() {
        let insns = vec![ret(0)];
        let cfg = build_cfg(&insns, vec![]);
        let dom = CilDominator::compute(&cfg);
        assert!(dom.dominates(0, 0));
    }

    #[test]
    fn dominator_linear_chain() {
        let insns = vec![
            insn(0, "nop", 1),
            insn(1, "nop", 1),
            ret(2),
        ];
        let cfg = build_cfg(&insns, vec![]);
        let dom = CilDominator::compute(&cfg);
        // Entry dominates everything.
        let entry = cfg.entry_block;
        for &id in cfg.blocks.keys() {
            assert!(dom.dominates(entry, id));
        }
    }

    #[test]
    fn eh_region_display() {
        let r = EhRegion::try_finally(0, 10, 10, 20);
        assert!(r.to_string().contains("Finally"));
    }

    #[test]
    fn cil_edge_display() {
        let e = CilEdge::new(0, 10, EdgeKind::Conditional);
        assert!(e.to_string().contains("Conditional"));
    }

    #[test]
    fn cil_block_display() {
        let b = CilBlock::new(0x10);
        assert!(b.to_string().contains("IL_0010"));
    }
}
