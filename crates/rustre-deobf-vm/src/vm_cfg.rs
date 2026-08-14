//! Virtual Control-Flow Graph (CFG) Reconstruction
//!
//! Reconstructs a control-flow graph operating at the virtual-instruction level:
//! - [`VirtualBlock`] — a maximal straight-line sequence of virtual instructions
//! - [`VirtualEdge`] — a directed edge between two virtual blocks
//! - [`VirtualCfg`] — the complete reconstructed virtual CFG
//! - [`VmCfgBuilder`] — builds a [`VirtualCfg`] from an instruction trace
//! - Loop detection and irreducibility handling

#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::isa_reconstruction::{VirtualInstruction, VirtualOpCategory};

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from virtual CFG construction.
#[derive(Debug, Error)]
pub enum VmCfgError {
    #[error("instruction stream is empty; cannot build a CFG")]
    EmptyInstructionStream,

    #[error("virtual block {id} referenced but not in the CFG")]
    UnknownBlock { id: u64 },

    #[error("CFG contains more than {limit} blocks; possible infinite loop in builder")]
    BlockLimitExceeded { limit: usize },

    #[error("loop detection failed: CFG is acyclic but loop-detect pass found a back-edge")]
    Inconsistency,
}

// ─────────────────────────────────────────────────────────────────────────────
// EdgeKind
// ─────────────────────────────────────────────────────────────────────────────

/// Kinds of CFG edges at the virtual-instruction level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VirtualEdgeKind {
    /// Unconditional fall-through or direct jump.
    Unconditional,
    /// True branch of a conditional (condition was true/taken).
    ConditionalTrue,
    /// False branch of a conditional (condition was false/not-taken).
    ConditionalFalse,
    /// Back-edge (target dominates source → loop).
    BackEdge,
    /// Exception / unwind edge.
    Exception,
    /// VM subroutine call.
    Call,
    /// VM subroutine return.
    Return,
}

impl VirtualEdgeKind {
    /// Returns `true` if this edge might be a loop back-edge.
    #[must_use]
    pub fn is_back_edge(self) -> bool {
        self == Self::BackEdge
    }

    /// Returns `true` if the edge is a branch (not fall-through).
    #[must_use]
    pub const fn is_branch(self) -> bool {
        !matches!(self, Self::Unconditional)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VirtualEdge
// ─────────────────────────────────────────────────────────────────────────────

/// A directed edge between two virtual basic blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualEdge {
    /// Source block ID (= the block's entry VIP).
    pub from: u64,
    /// Destination block ID (= the block's entry VIP).
    pub to: u64,
    /// Kind of this edge.
    pub kind: VirtualEdgeKind,
    /// Optional probability annotation [0.0, 1.0] (from profiling or heuristics).
    pub probability: Option<f32>,
    /// The VIP offset of the terminator instruction that produced this edge.
    pub terminator_vip: u64,
}

impl VirtualEdge {
    /// Create a new edge with no probability annotation.
    #[must_use]
    pub const fn new(from: u64, to: u64, kind: VirtualEdgeKind, terminator_vip: u64) -> Self {
        Self {
            from,
            to,
            kind,
            probability: None,
            terminator_vip,
        }
    }

    /// Create an unconditional edge.
    #[must_use]
    pub const fn unconditional(from: u64, to: u64, terminator_vip: u64) -> Self {
        Self::new(from, to, VirtualEdgeKind::Unconditional, terminator_vip)
    }

    /// Mark this edge as a back-edge.
    pub const fn mark_back_edge(&mut self) {
        self.kind = VirtualEdgeKind::BackEdge;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VirtualBlock
// ─────────────────────────────────────────────────────────────────────────────

/// A single virtual basic block: a maximal sequence of virtual instructions
/// with exactly one entry point and one exit (terminator).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualBlock {
    /// Unique block ID: the VIP of the first instruction.
    pub id: u64,
    /// Ordered virtual instructions in this block.
    pub instructions: Vec<VirtualInstruction>,
    /// IDs of predecessor blocks.
    pub predecessors: Vec<u64>,
    /// IDs of successor blocks.
    pub successors: Vec<u64>,
    /// Whether this block is a loop header.
    pub is_loop_header: bool,
    /// Whether this block is the CFG entry.
    pub is_entry: bool,
    /// Whether this block is a VM-exit block (returns to native code).
    pub is_vm_exit: bool,
    /// Dominator block ID (the immediate dominator in the dominator tree).
    pub idom: Option<u64>,
    /// Loop nesting depth (0 = top-level, >0 = inside N loops).
    pub loop_depth: u32,
    /// Block index in the reverse-post-order traversal.
    pub rpo_index: Option<usize>,
}

impl VirtualBlock {
    /// Create a new empty block.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self {
            id,
            instructions: Vec::new(),
            predecessors: Vec::new(),
            successors: Vec::new(),
            is_loop_header: false,
            is_entry: false,
            is_vm_exit: false,
            idom: None,
            loop_depth: 0,
            rpo_index: None,
        }
    }

    /// Add an instruction to this block.
    pub fn push_insn(&mut self, insn: VirtualInstruction) {
        if matches!(insn.category, VirtualOpCategory::Halt) {
            self.is_vm_exit = true;
        }
        self.instructions.push(insn);
    }

    /// Returns the terminator instruction (last in the block), if any.
    #[must_use]
    pub fn terminator(&self) -> Option<&VirtualInstruction> {
        self.instructions
            .last()
            .filter(|i: &&VirtualInstruction| i.is_terminator())
    }

    /// Number of instructions in the block.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Returns `true` if the block has no instructions.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// In-degree: number of predecessors.
    #[must_use]
    pub const fn in_degree(&self) -> usize {
        self.predecessors.len()
    }

    /// Out-degree: number of successors.
    #[must_use]
    pub const fn out_degree(&self) -> usize {
        self.successors.len()
    }

    /// Returns `true` if this block ends with an unconditional branch.
    #[must_use]
    pub fn is_unconditional_exit(&self) -> bool {
        self.terminator()
            .is_some_and(|t| t.category == VirtualOpCategory::Jump)
    }

    /// Returns `true` if this block is a conditional branch.
    #[must_use]
    pub fn is_conditional_exit(&self) -> bool {
        self.terminator()
            .is_some_and(|t| t.category == VirtualOpCategory::CondBranch)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Information about a natural loop in the virtual CFG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmLoop {
    /// The loop header block ID.
    pub header: u64,
    /// All block IDs that are part of this loop body (including header).
    pub body: HashSet<u64>,
    /// The back-edge that defines this loop (from → header).
    pub back_edge_source: u64,
    /// Estimated iteration count (from profiling data, or 0 if unknown).
    pub estimated_iterations: u32,
    /// Whether this loop is irreducible (has multiple entries).
    pub is_irreducible: bool,
    /// Nesting depth of this loop (1 = outermost).
    pub nesting_depth: u32,
}

impl VmLoop {
    /// Create a new loop.
    #[must_use]
    pub fn new(header: u64, back_edge_source: u64) -> Self {
        let mut body = HashSet::new();
        body.insert(header);
        Self {
            header,
            body,
            back_edge_source,
            estimated_iterations: 0,
            is_irreducible: false,
            nesting_depth: 1,
        }
    }

    /// Returns the number of blocks in the loop body.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.body.len()
    }

    /// Returns `true` if the given block is inside this loop.
    #[must_use]
    pub fn contains(&self, block_id: u64) -> bool {
        self.body.contains(&block_id)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VirtualCfg
// ─────────────────────────────────────────────────────────────────────────────

/// The complete reconstructed virtual CFG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualCfg {
    /// Blocks indexed by their entry VIP.
    pub blocks: BTreeMap<u64, VirtualBlock>,
    /// All edges in the CFG.
    pub edges: Vec<VirtualEdge>,
    /// Entry block ID.
    pub entry: u64,
    /// Detected natural loops.
    pub loops: Vec<VmLoop>,
    /// Reverse-post-order traversal of block IDs.
    pub rpo: Vec<u64>,
    /// Whether the CFG is reducible (all loops are natural loops).
    pub is_reducible: bool,
    /// Total virtual instruction count across all blocks.
    pub total_instructions: usize,
}

impl VirtualCfg {
    /// Create a new empty CFG with the given entry VIP.
    #[must_use]
    pub const fn new(entry: u64) -> Self {
        Self {
            blocks: BTreeMap::new(),
            edges: Vec::new(),
            entry,
            loops: Vec::new(),
            rpo: Vec::new(),
            is_reducible: true,
            total_instructions: 0,
        }
    }

    /// Insert a block into the CFG.
    pub fn add_block(&mut self, block: VirtualBlock) {
        self.total_instructions += block.len();
        self.blocks.insert(block.id, block);
    }

    /// Retrieve a block by ID.
    #[must_use]
    pub fn get_block(&self, id: u64) -> Option<&VirtualBlock> {
        self.blocks.get(&id)
    }

    /// Retrieve a mutable block by ID.
    pub fn get_block_mut(&mut self, id: u64) -> Option<&mut VirtualBlock> {
        self.blocks.get_mut(&id)
    }

    /// Number of blocks in the CFG.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Number of edges in the CFG.
    #[must_use]
    pub const fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Add an edge (and update predecessor/successor lists).
    pub fn add_edge(&mut self, edge: VirtualEdge) {
        let from = edge.from;
        let to = edge.to;
        self.edges.push(edge);
        if let Some(b) = self.blocks.get_mut(&from)
            && !b.successors.contains(&to) {
                b.successors.push(to);
            }
        if let Some(b) = self.blocks.get_mut(&to)
            && !b.predecessors.contains(&from) {
                b.predecessors.push(from);
            }
    }

    /// Return the entry block.
    #[must_use]
    pub fn entry_block(&self) -> Option<&VirtualBlock> {
        self.blocks.get(&self.entry)
    }

    /// All blocks reachable from the entry via BFS.
    #[must_use]
    pub fn reachable_blocks(&self) -> Vec<u64> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(self.entry);
        let mut order = Vec::new();
        while let Some(id) = queue.pop_front() {
            if !visited.insert(id) {
                continue;
            }
            order.push(id);
            if let Some(block) = self.get_block(id) {
                for &succ in &block.successors {
                    queue.push_back(succ);
                }
            }
        }
        order
    }

    /// Compute the reverse-post-order traversal and store in `self.rpo`.
    pub fn compute_rpo(&mut self) {
        let mut visited = HashSet::new();
        let mut post_order = Vec::new();
        self.dfs_postorder(self.entry, &mut visited, &mut post_order);
        post_order.reverse();
        for (idx, &id) in post_order.iter().enumerate() {
            if let Some(block) = self.blocks.get_mut(&id) {
                block.rpo_index = Some(idx);
            }
        }
        self.rpo = post_order;
    }

    fn dfs_postorder(&self, id: u64, visited: &mut HashSet<u64>, post: &mut Vec<u64>) {
        if !visited.insert(id) {
            return;
        }
        if let Some(block) = self.get_block(id) {
            for &succ in &block.successors {
                self.dfs_postorder(succ, visited, post);
            }
        }
        post.push(id);
    }

    /// Identify back-edges and mark them.
    pub fn mark_back_edges(&mut self) {
        let mut visited = HashSet::new();
        let mut stack_set = HashSet::new();
        let mut back_edge_pairs: Vec<(u64, u64)> = Vec::new();
        self.dfs_back_edges(
            self.entry,
            &mut visited,
            &mut stack_set,
            &mut back_edge_pairs,
        );
        for (from, to) in back_edge_pairs {
            for edge in &mut self.edges {
                if edge.from == from && edge.to == to {
                    edge.mark_back_edge();
                }
            }
            if let Some(block) = self.blocks.get_mut(&to) {
                block.is_loop_header = true;
            }
        }
    }

    fn dfs_back_edges(
        &self,
        id: u64,
        visited: &mut HashSet<u64>,
        stack: &mut HashSet<u64>,
        back_edges: &mut Vec<(u64, u64)>,
    ) {
        if !visited.insert(id) {
            return;
        }
        stack.insert(id);
        if let Some(block) = self.get_block(id) {
            for &succ in &block.successors {
                if stack.contains(&succ) {
                    back_edges.push((id, succ));
                } else {
                    self.dfs_back_edges(succ, visited, stack, back_edges);
                }
            }
        }
        stack.remove(&id);
    }

    /// Detect natural loops from back-edges and store in `self.loops`.
    pub fn detect_loops(&mut self) {
        self.mark_back_edges();
        let back_edges: Vec<(u64, u64)> = self
            .edges
            .iter()
            .filter(|e| e.kind == VirtualEdgeKind::BackEdge)
            .map(|e| (e.from, e.to))
            .collect();

        for (back_src, header) in back_edges {
            let body = self.find_loop_body(header, back_src);
            let mut lp = VmLoop::new(header, back_src);
            lp.body = body;
            // Annotate loop depth on blocks.
            for &bid in &lp.body {
                if let Some(block) = self.blocks.get_mut(&bid) {
                    block.loop_depth += 1;
                }
            }
            lp.nesting_depth = self.blocks.get(&header).map_or(1, |b| b.loop_depth);
            self.loops.push(lp);
        }
    }

    /// Find the loop body (all blocks that can reach `back_src` without going
    /// through `header`).
    fn find_loop_body(&self, header: u64, back_src: u64) -> HashSet<u64> {
        let mut body = HashSet::new();
        body.insert(header);
        let mut work = vec![back_src];
        while let Some(id) = work.pop() {
            if body.insert(id)
                && let Some(block) = self.get_block(id) {
                    for &pred in &block.predecessors {
                        if !body.contains(&pred) {
                            work.push(pred);
                        }
                    }
                }
        }
        body
    }

    /// Check whether the CFG is reducible (no irreducible loops).
    ///
    /// Uses Tarjan's irreducibility check: a loop is irreducible if it has
    /// more than one entry point.
    pub fn check_reducibility(&mut self) {
        // Collect (loop_index, is_irreducible) by examining block predecessors
        // without holding a mutable borrow on self.loops at the same time.
        let loop_count = self.loops.len();
        let mut irreducible_flags = vec![false; loop_count];
        for (loop_idx, lp) in self.loops.iter().enumerate() {
            let header = lp.header;
            let body = &lp.body;
            // A natural loop is irreducible if any non-header body block has a
            // predecessor outside the body.
            let has_non_header_entry = body.iter().any(|&bid| {
                if bid == header {
                    return false;
                }
                self.blocks.get(&bid).is_some_and(|block| block.predecessors.iter().any(|&pred| !body.contains(&pred)))
            });
            irreducible_flags[loop_idx] = has_non_header_entry;
        }
        for (loop_idx, &is_irreducible) in irreducible_flags.iter().enumerate() {
            if is_irreducible {
                self.loops[loop_idx].is_irreducible = true;
                self.is_reducible = false;
            }
        }
    }

    /// Compute dominators for all blocks in RPO order.
    ///
    /// Returns a map: `block_id` → immediate dominator `block_id`.
    pub fn compute_dominators(&mut self) -> HashMap<u64, u64> {
        if self.rpo.is_empty() {
            self.compute_rpo();
        }
        let rpo = std::mem::take(&mut self.rpo);
        let rpo_index: HashMap<u64, usize> =
            rpo.iter().enumerate().map(|(i, &id)| (id, i)).collect();

        // Initialize idom with the entry dominating itself.
        let mut idom: HashMap<u64, u64> = HashMap::new();
        idom.insert(self.entry, self.entry);

        let mut changed = true;
        while changed {
            changed = false;
            for &id in &rpo {
                if id == self.entry {
                    continue;
                }
                let preds: Vec<u64> = self
                    .blocks
                    .get(&id)
                    .map(|b| b.predecessors.clone())
                    .unwrap_or_default();
                let processed_preds: Vec<u64> = preds
                    .iter()
                    .copied()
                    .filter(|p| idom.contains_key(p))
                    .collect();
                if processed_preds.is_empty() {
                    continue;
                }

                let new_idom = processed_preds
                    .iter()
                    .copied()
                    .reduce(|a, b| Self::intersect(a, b, &idom, &rpo_index))
                    .unwrap_or(self.entry);

                let entry = idom.entry(id).or_insert(new_idom);
                if *entry != new_idom {
                    *entry = new_idom;
                    changed = true;
                }
            }
        }

        // Annotate idom on blocks.
        for (&id, &dom) in &idom {
            if let Some(block) = self.blocks.get_mut(&id) {
                block.idom = if dom == id { None } else { Some(dom) };
            }
        }

        self.rpo = rpo;
        idom
    }

    fn intersect(
        mut a: u64,
        mut b: u64,
        idom: &HashMap<u64, u64>,
        rpo_index: &HashMap<u64, usize>,
    ) -> u64 {
        while a != b {
            while rpo_index.get(&a).copied().unwrap_or(usize::MAX)
                > rpo_index.get(&b).copied().unwrap_or(usize::MAX)
            {
                a = idom.get(&a).copied().unwrap_or(a);
            }
            while rpo_index.get(&b).copied().unwrap_or(usize::MAX)
                > rpo_index.get(&a).copied().unwrap_or(usize::MAX)
            {
                b = idom.get(&b).copied().unwrap_or(b);
            }
        }
        a
    }

    /// Export the CFG to DOT format for Graphviz.
    #[must_use]
    pub fn to_dot(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::from("digraph vm_cfg {\n  node [shape=box fontname=\"monospace\"];\n");
        for block in self.blocks.values() {
            let label = format!(
                "VB_{:x}\\n{} insns\\ndepth={}{}{}",
                block.id,
                block.len(),
                block.loop_depth,
                if block.is_loop_header {
                    "\\n[LOOP HEADER]"
                } else {
                    ""
                },
                if block.is_vm_exit { "\\n[VM EXIT]" } else { "" },
            );
            let color = if block.is_entry {
                "lightblue"
            } else if block.is_vm_exit {
                "lightcoral"
            } else if block.is_loop_header {
                "lightyellow"
            } else {
                "white"
            };
            writeln!(s, "  VB_{:x} [label=\"{}\" fillcolor={} style=filled];", block.id, label, color).unwrap();
        }
        for edge in &self.edges {
            let style = match edge.kind {
                VirtualEdgeKind::BackEdge => "style=dashed color=red",
                VirtualEdgeKind::ConditionalTrue => "color=green",
                VirtualEdgeKind::ConditionalFalse => "color=orange",
                VirtualEdgeKind::Call => "style=dotted color=blue",
                VirtualEdgeKind::Return => "style=dotted color=purple",
                _ => "",
            };
            writeln!(s, "  VB_{:x} -> VB_{:x} [{}];", edge.from, edge.to, style).unwrap();
        }
        s.push_str("}\n");
        s
    }

    /// Return a human-readable summary of the CFG.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "VirtualCFG: {} blocks, {} edges, {} loops, {} insns, reducible={}",
            self.block_count(),
            self.edge_count(),
            self.loops.len(),
            self.total_instructions,
            self.is_reducible,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmCfgBuilder
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for [`VmCfgBuilder`].
#[derive(Debug, Clone)]
pub struct CfgBuilderConfig {
    /// Maximum number of basic blocks allowed.
    pub max_blocks: usize,
    /// Whether to run loop detection after building.
    pub detect_loops: bool,
    /// Whether to compute dominators after building.
    pub compute_dominators: bool,
}

impl Default for CfgBuilderConfig {
    fn default() -> Self {
        Self {
            max_blocks: 65536,
            detect_loops: true,
            compute_dominators: true,
        }
    }
}

/// Builds a [`VirtualCfg`] from a flat sequence of decoded [`VirtualInstruction`]s.
///
/// The algorithm:
/// 1. Split the instruction stream at every terminator instruction (JMP, JCC, CALL, RET, HALT).
/// 2. Register each segment as a [`VirtualBlock`].
/// 3. Wire edges based on branch targets from operands.
/// 4. Optionally run loop detection and dominator computation.
#[derive(Debug, Clone, Default)]
pub struct VmCfgBuilder {
    pub config: CfgBuilderConfig,
}

impl VmCfgBuilder {
    /// Create a builder with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with custom configuration.
    #[must_use]
    pub const fn with_config(config: CfgBuilderConfig) -> Self {
        Self { config }
    }

    /// Build a [`VirtualCfg`] from the given instruction stream.
    ///
    /// # Errors
    ///
    /// Returns [`VmCfgError`] if the instruction stream is empty or the block
    /// limit is exceeded.
    pub fn build(&self, instructions: &[VirtualInstruction]) -> Result<VirtualCfg, VmCfgError> {
        if instructions.is_empty() {
            return Err(VmCfgError::EmptyInstructionStream);
        }

        let entry_vip = instructions[0].vip;
        let mut cfg = VirtualCfg::new(entry_vip);

        // Step 1: identify block boundaries (leader VIPs).
        let mut leaders: HashSet<u64> = HashSet::new();
        leaders.insert(entry_vip);

        for (i, insn) in instructions.iter().enumerate() {
            if VirtualInstruction::is_terminator(insn) {
                // The instruction after a terminator starts a new block.
                if let Some(next) = instructions.get(i + 1) {
                    leaders.insert(next.vip);
                }
                // Branch targets are also leaders.
                for target in extract_branch_targets(insn) {
                    leaders.insert(target);
                }
            }
        }

        // Step 2: partition instructions into blocks.
        let mut block_map: BTreeMap<u64, Vec<VirtualInstruction>> = BTreeMap::new();
        let mut current_leader = entry_vip;
        for insn in instructions {
            if leaders.contains(&insn.vip) {
                current_leader = insn.vip;
            }
            block_map
                .entry(current_leader)
                .or_default()
                .push(insn.clone());
        }

        if block_map.len() > self.config.max_blocks {
            return Err(VmCfgError::BlockLimitExceeded {
                limit: self.config.max_blocks,
            });
        }

        // Step 3: build VirtualBlock structs.
        let block_ids: Vec<u64> = block_map.keys().copied().collect();
        for (idx, &id) in block_ids.iter().enumerate() {
            let insns = block_map.remove(&id).unwrap_or_default();
            let mut block = VirtualBlock::new(id);
            block.is_entry = id == entry_vip;
            // Check if this block ends with a VM-exit category.
            if let Some(last) = insns.last()
                && last.category == VirtualOpCategory::Halt {
                    block.is_vm_exit = true;
                }
            for insn in insns {
                block.push_insn(insn);
            }
            // Next block in linear order (fall-through target).
            if let Some(&next_id) = block_ids.get(idx + 1)
                && !block.is_unconditional_exit() && !block.is_vm_exit {
                    block.successors.push(next_id);
                }
            cfg.add_block(block);
        }

        // Step 4: wire branch edges.
        let term_edges: Vec<(u64, u64, VirtualEdgeKind)> = cfg
            .blocks
            .values()
            .flat_map(|block| {
                let mut edges = Vec::new();
                if let Some(term) = block.terminator() {
                    let targets = extract_branch_targets(term);
                    for target in targets {
                        if cfg.blocks.contains_key(&target) {
                            let kind = match term.category {
                                VirtualOpCategory::CondBranch => VirtualEdgeKind::ConditionalTrue,
                                VirtualOpCategory::Call => VirtualEdgeKind::Call,
                                VirtualOpCategory::Return => VirtualEdgeKind::Return,
                                _ => VirtualEdgeKind::Unconditional,
                            };
                            edges.push((block.id, target, kind));
                        }
                    }
                }
                edges
            })
            .collect();

        for (from, to, kind) in term_edges {
            let term_vip = cfg
                .get_block(from)
                .and_then(|b| b.terminator())
                .map_or(from, |t| t.vip);
            cfg.add_edge(VirtualEdge::new(from, to, kind, term_vip));
        }

        // Step 5: compute RPO and optionally detect loops and dominators.
        cfg.compute_rpo();
        if self.config.detect_loops {
            cfg.detect_loops();
            cfg.check_reducibility();
        }
        if self.config.compute_dominators {
            cfg.compute_dominators();
        }

        Ok(cfg)
    }
}

/// Extract branch target VIPs from a virtual instruction's operands.
fn extract_branch_targets(insn: &VirtualInstruction) -> Vec<u64> {
    use crate::isa_reconstruction::VirtualOperand;
    let mut targets = Vec::new();
    for op in &insn.operands {
        match op {
            VirtualOperand::BranchOffset(delta) => {
                let target = insn.vip.cast_signed().wrapping_add(i64::from(*delta)).cast_unsigned();
                targets.push(target);
            }
            VirtualOperand::MemoryAddr(addr) => {
                targets.push(*addr);
            }
            VirtualOperand::Immediate(v) if *v > 0 => {
                targets.push(v.cast_unsigned());
            }
            _ => {}
        }
    }
    targets
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa_reconstruction::{VirtualInstruction, VirtualOpCategory, VirtualOperand};

    fn nop_insn(vip: u64) -> VirtualInstruction {
        VirtualInstruction::new(0x00, VirtualOpCategory::Nop, vec![], vip, 1, 0, "NOP")
    }

    fn jmp_insn(vip: u64, target: u64) -> VirtualInstruction {
        let delta = i32::try_from(target.cast_signed() - vip.cast_signed()).unwrap_or(i32::MAX);
        VirtualInstruction::new(
            0x30,
            VirtualOpCategory::Jump,
            vec![VirtualOperand::BranchOffset(delta)],
            vip,
            1,
            0,
            "JMP",
        )
    }

    fn jcc_insn(vip: u64, target: u64) -> VirtualInstruction {
        let delta = i32::try_from(target.cast_signed() - vip.cast_signed()).unwrap_or(i32::MAX);
        VirtualInstruction::new(
            0x31,
            VirtualOpCategory::CondBranch,
            vec![VirtualOperand::BranchOffset(delta)],
            vip,
            1,
            0,
            "JCC",
        )
    }

    fn halt_insn(vip: u64) -> VirtualInstruction {
        VirtualInstruction::new(0xFF, VirtualOpCategory::Halt, vec![], vip, 1, 0, "HALT")
    }

    #[test]
    fn test_virtual_edge_constructors() {
        let e = VirtualEdge::unconditional(0x100, 0x200, 0x100);
        assert_eq!(e.from, 0x100);
        assert_eq!(e.to, 0x200);
        assert_eq!(e.kind, VirtualEdgeKind::Unconditional);
        assert!(!e.kind.is_back_edge());
    }

    #[test]
    fn test_virtual_block_new() {
        let block = VirtualBlock::new(0x1000);
        assert_eq!(block.id, 0x1000);
        assert!(block.is_empty());
        assert_eq!(block.in_degree(), 0);
        assert_eq!(block.out_degree(), 0);
    }

    #[test]
    fn test_virtual_block_push_insn_terminator() {
        let mut block = VirtualBlock::new(0x100);
        block.push_insn(nop_insn(0x100));
        block.push_insn(halt_insn(0x101));
        assert_eq!(block.len(), 2);
        let term = block.terminator().unwrap();
        assert_eq!(term.category, VirtualOpCategory::Halt);
        assert!(block.is_vm_exit);
    }

    #[test]
    fn test_virtual_cfg_add_block_edge() {
        let mut cfg = VirtualCfg::new(0x100);
        let mut b1 = VirtualBlock::new(0x100);
        b1.is_entry = true;
        let b2 = VirtualBlock::new(0x200);
        cfg.add_block(b1);
        cfg.add_block(b2);
        cfg.add_edge(VirtualEdge::unconditional(0x100, 0x200, 0x100));
        assert_eq!(cfg.block_count(), 2);
        assert_eq!(cfg.edge_count(), 1);
        assert_eq!(cfg.get_block(0x100).unwrap().out_degree(), 1);
        assert_eq!(cfg.get_block(0x200).unwrap().in_degree(), 1);
    }

    #[test]
    fn test_cfg_builder_single_block() {
        let insns = vec![nop_insn(0x00), nop_insn(0x01), halt_insn(0x02)];
        let builder = VmCfgBuilder::new();
        let cfg = builder.build(&insns).unwrap();
        assert_eq!(cfg.block_count(), 1);
        assert!(cfg.rpo.len() == 1);
    }

    #[test]
    fn test_cfg_builder_two_blocks_jmp() {
        let insns = vec![
            nop_insn(0x00),
            jmp_insn(0x01, 0x10), // jumps to 0x10
            nop_insn(0x10),
            halt_insn(0x11),
        ];
        let builder = VmCfgBuilder::new();
        let cfg = builder.build(&insns).unwrap();
        // Two blocks: [0x00, 0x01] and [0x10, 0x11]
        assert_eq!(cfg.block_count(), 2);
        assert_eq!(cfg.edge_count(), 1);
    }

    #[test]
    fn test_cfg_builder_empty_errors() {
        let builder = VmCfgBuilder::new();
        assert!(builder.build(&[]).is_err());
    }

    #[test]
    fn test_cfg_builder_loop_detection() {
        // 0x00 → 0x01 (NOP), 0x01 JCC to 0x00, fall-through to 0x10
        let insns = vec![
            nop_insn(0x00),
            jcc_insn(0x01, 0x00), // back-edge to 0x00
            halt_insn(0x10),
        ];
        let builder = VmCfgBuilder::new();
        let cfg = builder.build(&insns).unwrap();
        // Loop should be detected.
        assert!(!cfg.loops.is_empty(), "Expected at least one loop");
    }

    #[test]
    fn test_vm_cfg_summary() {
        let insns = vec![nop_insn(0), halt_insn(1)];
        let builder = VmCfgBuilder::new();
        let cfg = builder.build(&insns).unwrap();
        let summary = cfg.summary();
        assert!(summary.contains("VirtualCFG"));
        assert!(summary.contains("blocks"));
    }

    #[test]
    fn test_vm_cfg_to_dot() {
        let insns = vec![nop_insn(0), halt_insn(1)];
        let builder = VmCfgBuilder::new();
        let cfg = builder.build(&insns).unwrap();
        let dot = cfg.to_dot();
        assert!(dot.contains("digraph vm_cfg"));
    }

    #[test]
    fn test_vm_cfg_reachable_blocks() {
        let insns = vec![
            nop_insn(0x00),
            jmp_insn(0x01, 0x10),
            nop_insn(0x10),
            halt_insn(0x11),
        ];
        let builder = VmCfgBuilder::new();
        let cfg = builder.build(&insns).unwrap();
        let reachable = cfg.reachable_blocks();
        assert_eq!(reachable.len(), 2);
    }

    #[test]
    fn test_vm_loop_contains() {
        let mut lp = VmLoop::new(0x100, 0x200);
        lp.body.insert(0x150);
        assert!(lp.contains(0x100));
        assert!(lp.contains(0x150));
        assert!(!lp.contains(0x300));
        assert_eq!(lp.block_count(), 2);
    }

    #[test]
    fn test_virtual_edge_mark_back_edge() {
        let mut e = VirtualEdge::unconditional(0x200, 0x100, 0x200);
        e.mark_back_edge();
        assert_eq!(e.kind, VirtualEdgeKind::BackEdge);
        assert!(e.kind.is_back_edge());
    }

    #[test]
    fn test_block_is_conditional_exit() {
        let mut block = VirtualBlock::new(0x100);
        block.push_insn(jcc_insn(0x100, 0x200));
        assert!(block.is_conditional_exit());
        assert!(!block.is_unconditional_exit());
    }

    #[test]
    fn test_block_rpo_index_set_after_compute() {
        let insns = vec![nop_insn(0), halt_insn(1)];
        let builder = VmCfgBuilder::new();
        let cfg = builder.build(&insns).unwrap();
        let entry_block = cfg.entry_block().unwrap();
        assert!(entry_block.rpo_index.is_some());
    }
}
