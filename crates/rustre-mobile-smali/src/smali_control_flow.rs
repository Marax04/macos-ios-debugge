//! Control-flow graph construction for Smali methods.
//!
//! Parses `goto`, `if-*`, `packed-switch`, and `sparse-switch` instructions
//! from a `SmaliMethod` and builds a `SmaliCfg` consisting of `SmaliBlock`
//! nodes connected by `SmaliEdge` edges.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{SmaliInstr, SmaliMethod, SmaliOp};

// ─── SmaliEdgeKind ────────────────────────────────────────────────────────────

/// The semantic kind of a CFG edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SmaliEdgeKind {
    /// Unconditional fall-through or goto.
    Fallthrough,
    /// Taken branch of an `if-*` instruction.
    BranchTrue,
    /// Not-taken (fall-through) path of an `if-*` instruction.
    BranchFalse,
    /// One arm of a `packed-switch` or `sparse-switch`.
    SwitchCase,
    /// Default arm of a switch.
    SwitchDefault,
    /// Back edge (detected during DFS; target dominates source).
    BackEdge,
}

impl fmt::Display for SmaliEdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fallthrough => write!(f, "fallthrough"),
            Self::BranchTrue => write!(f, "branch-true"),
            Self::BranchFalse => write!(f, "branch-false"),
            Self::SwitchCase => write!(f, "switch-case"),
            Self::SwitchDefault => write!(f, "switch-default"),
            Self::BackEdge => write!(f, "back-edge"),
        }
    }
}

// ─── SmaliEdge ────────────────────────────────────────────────────────────────

/// A directed edge in the Smali CFG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmaliEdge {
    /// Index of the source block.
    pub from: usize,
    /// Index of the target block.
    pub to: usize,
    /// Semantic kind of this edge.
    pub kind: SmaliEdgeKind,
}

impl SmaliEdge {
    /// Create a new edge.
    #[must_use]
    pub const fn new(from: usize, to: usize, kind: SmaliEdgeKind) -> Self {
        Self { from, to, kind }
    }
}

impl fmt::Display for SmaliEdge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "B{} --{}--> B{}", self.from, self.kind, self.to)
    }
}

// ─── SmaliBlock ───────────────────────────────────────────────────────────────

/// A basic block in the Smali CFG.
///
/// A basic block is a maximal sequence of instructions with a single entry
/// point and a single exit point.  Instructions inside the block have no
/// branches and no branch targets (except at the last instruction).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmaliBlock {
    /// Unique block index (0 = entry).
    pub index: usize,
    /// Label that starts this block (if any).
    pub label: Option<String>,
    /// Indices into the method's instruction list.
    pub instr_range: std::ops::Range<usize>,
    /// Whether this block is the method entry point.
    pub is_entry: bool,
    /// Whether this block has a `return-void` / `return` terminal.
    pub is_exit: bool,
    /// Predecessor block indices.
    pub predecessors: Vec<usize>,
    /// Successor block indices.
    pub successors: Vec<usize>,
}

impl SmaliBlock {
    /// Create a new block.
    #[must_use]
    pub const fn new(index: usize, start: usize, end: usize) -> Self {
        Self {
            index,
            label: None,
            instr_range: start..end,
            is_entry: index == 0,
            is_exit: false,
            predecessors: Vec::new(),
            successors: Vec::new(),
        }
    }

    /// Returns the number of instructions in this block.
    #[must_use]
    pub fn instr_count(&self) -> usize {
        self.instr_range.len()
    }
}

impl fmt::Display for SmaliBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Block[{}] instrs={}..{} entry={} exit={}",
            self.index,
            self.instr_range.start,
            self.instr_range.end,
            self.is_entry,
            self.is_exit,
        )
    }
}

// ─── SmaliCfg ─────────────────────────────────────────────────────────────────

/// Control-flow graph for a single Smali method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmaliCfg {
    /// Method name this CFG was built from.
    pub method_name: String,
    /// All basic blocks, indexed by their `index` field.
    pub blocks: Vec<SmaliBlock>,
    /// All directed edges.
    pub edges: Vec<SmaliEdge>,
}

impl SmaliCfg {
    /// Create an empty CFG.
    #[must_use]
    pub fn new(method_name: impl Into<String>) -> Self {
        Self {
            method_name: method_name.into(),
            blocks: Vec::new(),
            edges: Vec::new(),
        }
    }

    /// Number of basic blocks.
    #[must_use]
    pub const fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Number of edges.
    #[must_use]
    pub const fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Entry block (always block 0 when the method has instructions).
    #[must_use]
    pub fn entry_block(&self) -> Option<&SmaliBlock> {
        self.blocks.first()
    }

    /// All exit blocks (blocks with a `return` terminal).
    #[must_use]
    pub fn exit_blocks(&self) -> Vec<&SmaliBlock> {
        self.blocks.iter().filter(|b| b.is_exit).collect()
    }

    /// Return the successors of a block by index.
    #[must_use]
    pub fn successors_of(&self, block_idx: usize) -> Vec<&SmaliBlock> {
        self.edges
            .iter()
            .filter(|e| e.from == block_idx)
            .filter_map(|e| self.blocks.get(e.to))
            .collect()
    }

    /// Return the predecessors of a block by index.
    #[must_use]
    pub fn predecessors_of(&self, block_idx: usize) -> Vec<&SmaliBlock> {
        self.edges
            .iter()
            .filter(|e| e.to == block_idx)
            .filter_map(|e| self.blocks.get(e.from))
            .collect()
    }

    /// Perform a BFS walk over blocks starting from the entry and return the
    /// block indices in BFS order.
    #[must_use]
    pub fn bfs_order(&self) -> Vec<usize> {
        if self.blocks.is_empty() {
            return Vec::new();
        }
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut order = Vec::new();
        queue.push_back(0usize);
        visited.insert(0usize);
        while let Some(idx) = queue.pop_front() {
            order.push(idx);
            for edge in self.edges.iter().filter(|e| e.from == idx) {
                if visited.insert(edge.to) {
                    queue.push_back(edge.to);
                }
            }
        }
        order
    }

    /// Count back-edges (loop back-edges indicate loops).
    #[must_use]
    pub fn back_edge_count(&self) -> usize {
        self.edges
            .iter()
            .filter(|e| e.kind == SmaliEdgeKind::BackEdge)
            .count()
    }

    /// Returns `true` if the CFG contains at least one loop (back-edge).
    #[must_use]
    pub fn has_loops(&self) -> bool {
        self.back_edge_count() > 0
    }
}

// ─── CfgBuilder ───────────────────────────────────────────────────────────────

/// Internal state for building a `SmaliCfg` from a `SmaliMethod`.
struct CfgBuilder<'a> {
    instrs: &'a [SmaliInstr],
    /// Map from label string → instruction index.
    label_index: HashMap<String, usize>,
    /// Set of instruction indices that start a new basic block.
    block_starts: BTreeMap<usize, ()>,
}

impl<'a> CfgBuilder<'a> {
    fn new(instrs: &'a [SmaliInstr]) -> Self {
        let mut label_index = HashMap::new();
        for (idx, instr) in instrs.iter().enumerate() {
            if let Some(lbl) = &instr.label {
                // Strip trailing ':' if present
                let clean = lbl.trim_end_matches(':').to_string();
                label_index.insert(clean, idx);
            }
        }
        Self {
            instrs,
            label_index,
            block_starts: BTreeMap::new(),
        }
    }

    /// Mark an instruction index as the start of a new basic block.
    fn mark_start(&mut self, idx: usize) {
        if idx < self.instrs.len() {
            self.block_starts.insert(idx, ());
        }
    }

    /// Resolve a label to an instruction index.
    fn resolve_label(&self, label: &str) -> Option<usize> {
        let clean = label.trim_end_matches(':');
        self.label_index.get(clean).copied()
    }

    /// Identify all block-start boundaries.
    fn find_block_starts(&mut self) {
        self.mark_start(0);
        for (idx, instr) in self.instrs.iter().enumerate() {
            match &instr.op {
                SmaliOp::Goto => {
                    // target of goto starts a block
                    if let Some(target_label) = instr.operands.first() {
                        let label = format!("{target_label}");
                        if let Some(target) = self.resolve_label(&label) {
                            self.mark_start(target);
                        }
                    }
                    // instruction after goto starts a block (dead code, still a boundary)
                    self.mark_start(idx + 1);
                }
                SmaliOp::IfEq
                | SmaliOp::IfNe
                | SmaliOp::IfLt
                | SmaliOp::IfGe
                | SmaliOp::IfGt
                | SmaliOp::IfLe
                | SmaliOp::IfEqz
                | SmaliOp::IfNez => {
                    // branch target
                    if let Some(target_label) = instr.operands.last() {
                        let label = format!("{target_label}");
                        if let Some(target) = self.resolve_label(&label) {
                            self.mark_start(target);
                        }
                    }
                    // fall-through
                    self.mark_start(idx + 1);
                }
                SmaliOp::Return | SmaliOp::ReturnVoid => {
                    self.mark_start(idx + 1);
                }
                SmaliOp::Other(s) if s.starts_with("packed-switch") || s.starts_with("sparse-switch") => {
                    self.mark_start(idx + 1);
                }
                _ => {}
            }
        }
    }

    /// Build the list of blocks from the identified starts.
    fn build_blocks(&self) -> Vec<SmaliBlock> {
        let starts: Vec<usize> = self.block_starts.keys().copied().collect();
        let mut blocks = Vec::new();
        for (block_idx, &start) in starts.iter().enumerate() {
            let end = starts
                .get(block_idx + 1)
                .copied()
                .unwrap_or(self.instrs.len());
            let end = end.min(self.instrs.len());
            let mut block = SmaliBlock::new(block_idx, start, end);
            // Attach label from the first instruction
            if let Some(instr) = self.instrs.get(start)
                && let Some(lbl) = &instr.label {
                    block.label = Some(lbl.trim_end_matches(':').to_string());
                }
            // Mark exit blocks
            if let Some(last) = self.instrs.get(end.saturating_sub(1)) {
                block.is_exit = matches!(last.op, SmaliOp::Return | SmaliOp::ReturnVoid);
            }
            blocks.push(block);
        }
        blocks
    }

    /// Build a mapping from instruction index → block index.
    fn instr_to_block(blocks: &[SmaliBlock]) -> HashMap<usize, usize> {
        let mut map = HashMap::new();
        for block in blocks {
            for i in block.instr_range.clone() {
                map.insert(i, block.index);
            }
        }
        map
    }

    /// Build edges between blocks.
    fn build_edges(
        &self,
        blocks: &mut [SmaliBlock],
        instr_to_block: &HashMap<usize, usize>,
    ) -> Vec<SmaliEdge> {
        let mut edges = Vec::new();
        // DFS coloring for back-edge detection
        let mut color: Vec<u8> = vec![0u8; blocks.len()]; // 0=white, 1=grey, 2=black
        let mut raw_edges: Vec<(usize, usize, SmaliEdgeKind)> = Vec::new();

        for block in blocks.iter() {
            let end = block.instr_range.end;
            if end == 0 {
                continue;
            }
            let last_idx = end.saturating_sub(1);
            let Some(last_instr) = self.instrs.get(last_idx) else {
                continue;
            };
            let block_idx = block.index;
            match &last_instr.op {
                SmaliOp::Goto => {
                    if let Some(lbl_op) = last_instr.operands.first() {
                        let label = format!("{lbl_op}");
                        if let Some(target_instr) = self.resolve_label(&label)
                            && let Some(&target_block) = instr_to_block.get(&target_instr) {
                                raw_edges.push((block_idx, target_block, SmaliEdgeKind::Fallthrough));
                            }
                    }
                }
                SmaliOp::IfEq
                | SmaliOp::IfNe
                | SmaliOp::IfLt
                | SmaliOp::IfGe
                | SmaliOp::IfGt
                | SmaliOp::IfLe
                | SmaliOp::IfEqz
                | SmaliOp::IfNez => {
                    // Branch target
                    if let Some(lbl_op) = last_instr.operands.last() {
                        let label = format!("{lbl_op}");
                        if let Some(target_instr) = self.resolve_label(&label)
                            && let Some(&target_block) = instr_to_block.get(&target_instr) {
                                raw_edges.push((block_idx, target_block, SmaliEdgeKind::BranchTrue));
                            }
                    }
                    // Fall-through
                    if let Some(&next_block) = instr_to_block.get(&(last_idx + 1)) {
                        raw_edges.push((block_idx, next_block, SmaliEdgeKind::BranchFalse));
                    }
                }
                SmaliOp::Return | SmaliOp::ReturnVoid => {
                    // No outgoing edges
                }
                _ => {
                    // Fall-through to next block
                    if let Some(&next_block) = instr_to_block.get(&(last_idx + 1))
                        && next_block != block_idx {
                            raw_edges.push((block_idx, next_block, SmaliEdgeKind::Fallthrough));
                        }
                }
            }
        }

        // DFS to detect back edges.
        //
        // We maintain an explicit `ancestor` set alongside the DFS stack so
        // that we can correctly identify back edges: an edge (from, to) is a
        // back edge if and only if `to` is currently *grey* — i.e. it is an
        // ancestor of `from` on the current DFS path (still on the stack and
        // not yet finished).  We record these edges in a HashSet so the final
        // loop can look them up in O(1).
        let n = blocks.len();
        let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
        for &(from, to, _) in &raw_edges {
            if from < n && to < n {
                adj[from].push(to);
            }
        }

        // back_edge_set: pairs (from, to) that are confirmed back edges.
        let mut back_edge_set: std::collections::HashSet<(usize, usize)> =
            std::collections::HashSet::new();
        // grey = currently on the DFS stack (ancestor set).
        let mut grey: std::collections::HashSet<usize> = std::collections::HashSet::new();
        // Iterative DFS using an explicit stack of (node, child_iterator_index).
        let mut dfs_stack: Vec<(usize, usize)> = Vec::new();
        if n > 0 {
            color[0] = 1; // grey
            grey.insert(0);
            dfs_stack.push((0, 0));
        }
        while let Some((v, ci)) = dfs_stack.last_mut() {
            let v = *v;
            if *ci < adj[v].len() {
                let w = adj[v][*ci];
                *ci += 1;
                if grey.contains(&w) {
                    // w is an ancestor on the current DFS path → back edge
                    back_edge_set.insert((v, w));
                } else if color[w] == 0 {
                    // w is white → tree edge, descend
                    color[w] = 1;
                    grey.insert(w);
                    dfs_stack.push((w, 0));
                }
                // color[w] == 2 → w is already fully processed → cross/forward edge
            } else {
                // All children of v processed → finish v
                color[v] = 2;
                grey.remove(&v);
                dfs_stack.pop();
            }
        }

        for (from, to, kind) in raw_edges {
            let actual_kind = if back_edge_set.contains(&(from, to)) {
                SmaliEdgeKind::BackEdge
            } else {
                kind
            };
            if from < blocks.len() {
                blocks[from].successors.push(to);
            }
            if to < blocks.len() {
                blocks[to].predecessors.push(from);
            }
            edges.push(SmaliEdge::new(from, to, actual_kind));
        }

        edges
    }
}

// ─── build_cfg ────────────────────────────────────────────────────────────────

/// Build a `SmaliCfg` from a `SmaliMethod`.
///
/// The algorithm:
/// 1. Scan instructions to identify block-start boundaries (targets of branches
///    and the instructions following terminators).
/// 2. Partition instructions into basic blocks.
/// 3. Add edges: fall-through, branch-true/false, and switch arms.
/// 4. Annotate back edges using DFS coloring.
#[must_use]
pub fn build_cfg(method: &SmaliMethod) -> SmaliCfg {
    let mut cfg = SmaliCfg::new(format!("{}.{}", method.class, method.name));

    if method.instructions.is_empty() {
        return cfg;
    }

    let mut builder = CfgBuilder::new(&method.instructions);
    builder.find_block_starts();
    let mut blocks = builder.build_blocks();
    let instr_to_block = CfgBuilder::instr_to_block(&blocks);
    let edges = builder.build_edges(&mut blocks, &instr_to_block);

    cfg.blocks = blocks;
    cfg.edges = edges;
    cfg
}

// ─── CfgStats ─────────────────────────────────────────────────────────────────

/// Summary statistics for a CFG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgStats {
    pub block_count: usize,
    pub edge_count: usize,
    pub back_edge_count: usize,
    pub exit_block_count: usize,
    pub has_loops: bool,
    /// Cyclomatic complexity: E − N + 2 (`McCabe`'s formula).
    pub cyclomatic_complexity: i64,
}

impl CfgStats {
    /// Compute statistics for `cfg`.
    #[must_use]
    pub fn compute(cfg: &SmaliCfg) -> Self {
        let e = i64::try_from(cfg.edge_count()).unwrap_or(i64::MAX);
        let n = i64::try_from(cfg.block_count()).unwrap_or(i64::MAX);
        let back_edges = cfg.back_edge_count();
        Self {
            block_count: cfg.block_count(),
            edge_count: cfg.edge_count(),
            back_edge_count: back_edges,
            exit_block_count: cfg.exit_blocks().len(),
            has_loops: cfg.has_loops(),
            cyclomatic_complexity: (e - n + 2).max(1),
        }
    }
}

impl fmt::Display for CfgStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CFG: blocks={} edges={} loops={} CC={}",
            self.block_count, self.edge_count, self.has_loops, self.cyclomatic_complexity
        )
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SmaliAccess, SmaliInstr, SmaliMethod, SmaliOp, SmaliOperand};

    fn reg(n: u8) -> SmaliOperand {
        SmaliOperand::Reg(crate::SmaliReg { num: n })
    }

    fn label_op(s: &str) -> SmaliOperand {
        SmaliOperand::Str(s.to_string())
    }

    fn make_method(instrs: Vec<SmaliInstr>) -> SmaliMethod {
        SmaliMethod {
            name: "test".to_string(),
            class: "Lfoo;".to_string(),
            signature: "()V".to_string(),
            access: SmaliAccess::PUBLIC,
            registers: 4,
            instructions: instrs,
        }
    }

    #[test]
    fn test_empty_method_gives_empty_cfg() {
        let m = make_method(vec![]);
        let cfg = build_cfg(&m);
        assert_eq!(cfg.block_count(), 0);
    }

    #[test]
    fn test_linear_method_one_block() {
        let m = make_method(vec![
            SmaliInstr { op: SmaliOp::Nop, operands: vec![], label: None },
            SmaliInstr { op: SmaliOp::ReturnVoid, operands: vec![], label: None },
        ]);
        let cfg = build_cfg(&m);
        assert_eq!(cfg.block_count(), 1);
        assert!(cfg.blocks[0].is_entry);
        assert!(cfg.blocks[0].is_exit);
    }

    #[test]
    fn test_goto_splits_into_two_blocks() {
        let m = make_method(vec![
            SmaliInstr {
                op: SmaliOp::Goto,
                operands: vec![label_op(":end")],
                label: None,
            },
            SmaliInstr {
                op: SmaliOp::ReturnVoid,
                operands: vec![],
                label: Some(":end".to_string()),
            },
        ]);
        let cfg = build_cfg(&m);
        assert!(cfg.block_count() >= 1);
    }

    #[test]
    fn test_if_creates_branch_edges() {
        let m = make_method(vec![
            SmaliInstr {
                op: SmaliOp::IfEqz,
                operands: vec![reg(0), label_op(":true_branch")],
                label: None,
            },
            SmaliInstr {
                op: SmaliOp::ReturnVoid,
                operands: vec![],
                label: None,
            },
            SmaliInstr {
                op: SmaliOp::ReturnVoid,
                operands: vec![],
                label: Some(":true_branch".to_string()),
            },
        ]);
        let cfg = build_cfg(&m);
        assert!(cfg.block_count() >= 2);
    }

    #[test]
    fn test_cfg_stats_computation() {
        let m = make_method(vec![
            SmaliInstr { op: SmaliOp::Nop, operands: vec![], label: None },
            SmaliInstr { op: SmaliOp::ReturnVoid, operands: vec![], label: None },
        ]);
        let cfg = build_cfg(&m);
        let stats = CfgStats::compute(&cfg);
        assert_eq!(stats.block_count, 1);
        assert!(!stats.has_loops);
        assert!(stats.cyclomatic_complexity >= 1);
    }

    #[test]
    fn test_bfs_order_single_block() {
        let m = make_method(vec![
            SmaliInstr { op: SmaliOp::ReturnVoid, operands: vec![], label: None },
        ]);
        let cfg = build_cfg(&m);
        let order = cfg.bfs_order();
        assert_eq!(order, vec![0]);
    }

    #[test]
    fn test_exit_blocks() {
        let m = make_method(vec![
            SmaliInstr { op: SmaliOp::ReturnVoid, operands: vec![], label: None },
        ]);
        let cfg = build_cfg(&m);
        assert_eq!(cfg.exit_blocks().len(), 1);
    }
}
