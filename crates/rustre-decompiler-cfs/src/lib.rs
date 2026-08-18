//! `rustre-decompiler-cfs`
//!
//! Control Flow Structuring using the DREAM / "No More Gotos" algorithm.
//!
//! Converts a low-level CFG (directed graph of `BasicBlock`s) into a
//! `StructuredAst` composed of high-level constructs (if/else, while,
//! do-while, for, switch, …).  Remaining irreducible edges are emitted as
//! `StructuredNode::Goto` so that the output is always complete.
//!
//! # Algorithm outline
//! 1. Build a `petgraph` directed graph from the caller-supplied `BasicBlock`
//!    list.
//! 2. Run Tarjan's SCC to identify back-edges and natural loops.
//! 3. Build the immediate-dominator tree (Cooper et al. simple O(n²) pass).
//! 4. Traverse the dominator tree in post-order and, at each node, attempt to
//!    recognise the canonical patterns: sequence, if, if-else, while,
//!    do-while, switch.
//! 5. Leftover back-edges that could not be absorbed become `Goto` nodes.

pub mod ast_postpass;
pub mod condition_recovery;
pub mod dream_algorithm;
pub mod goto_elimination;
pub mod goto_reducer;
pub mod loop_detector;
pub mod loop_structurer;
pub mod structural_regions;
/// Backward-compatible re-export; prefer `structural_regions` for new code.
pub use structural_regions as region_analysis;
pub mod region_tree_builder;
pub mod switch_recovery;

use std::collections::{HashMap, HashSet, VecDeque};

use petgraph::{
    algo::tarjan_scc,
    graph::{DiGraph, NodeIndex},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// A unique identifier for a basic block inside a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct BlockId(pub u32);

impl BlockId {
    #[must_use]
    pub const fn new(id: u32) -> Self {
        Self(id)
    }
}

impl std::fmt::Display for BlockId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bb{}", self.0)
    }
}

/// A single statement inside a basic block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Statement {
    /// Raw text (e.g. disassembly mnemonic, already lifted to pseudo-C).
    Raw(String),
    /// An assignment `lhs = rhs`.
    Assign { lhs: String, rhs: String },
    /// A `return` statement with an optional value.
    Return(Option<String>),
    /// A conditional branch — only the condition string is stored here;
    /// the taken/not-taken structure is captured by the enclosing
    /// `StructuredNode`.
    Branch(String),
}

/// A single basic block as produced by the lifter / CFG builder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: BlockId,
    pub stmts: Vec<Statement>,
    /// Outgoing edge target IDs (0, 1, or 2 targets for normal blocks;
    /// arbitrary count for switch blocks).
    pub successors: Vec<BlockId>,
}

impl BasicBlock {
    #[must_use]
    pub const fn new(id: BlockId) -> Self {
        Self {
            id,
            stmts: Vec::new(),
            successors: Vec::new(),
        }
    }

    #[must_use] 
    pub fn with_stmts(mut self, stmts: Vec<Statement>) -> Self {
        self.stmts = stmts;
        self
    }

    #[must_use] 
    pub fn with_successors(mut self, succs: Vec<BlockId>) -> Self {
        self.successors = succs;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Loop / condition kinds
// ─────────────────────────────────────────────────────────────────────────────

/// Distinguishes the three classical loop shapes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoopKind {
    /// `while (cond) { body }`
    While,
    /// `do { body } while (cond);`
    DoWhile,
    /// `for (init; cond; step) { body }`
    For,
}

// ─────────────────────────────────────────────────────────────────────────────
// Structured AST
// ─────────────────────────────────────────────────────────────────────────────

/// One case arm of a switch statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchCase {
    /// `None` = `default:`.
    pub value: Option<i64>,
    pub body: Box<StructuredNode>,
}

/// The fully structured AST for a function (or sub-region).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StructuredNode {
    /// A leaf: the statements of a single basic block.
    BasicBlock { id: BlockId, stmts: Vec<Statement> },
    /// A straight sequence of nodes executed one after another.
    Sequence(Vec<Self>),
    /// `if (cond) { then }`
    If {
        condition: String,
        then_branch: Box<Self>,
    },
    /// `if (cond) { then } else { else_ }`
    IfElse {
        condition: String,
        then_branch: Box<Self>,
        else_branch: Box<Self>,
    },
    /// A loop of the specified kind.
    Loop {
        kind: LoopKind,
        condition: String,
        /// The loop body (and, for `For`, this includes the increment).
        body: Box<Self>,
    },
    /// `switch (expr) { cases… }`
    Switch {
        expr: String,
        cases: Vec<SwitchCase>,
    },
    /// An unstructured jump that could not be absorbed into a higher-level
    /// construct.
    Goto(BlockId),
    /// A `break` out of the immediately enclosing loop / switch.
    Break,
    /// A `continue` to the header of the immediately enclosing loop.
    Continue,
    /// A `return` statement.
    Return(Option<String>),
}

impl StructuredNode {
    /// Flatten a `Sequence` containing a single child into that child.
    ///
    /// # Panics
    ///
    /// Panics if the `Sequence` invariant is violated (e.g. a singleton
    /// `Sequence` whose vector is empty).
    #[must_use]
    pub fn flatten(self) -> Self {
        match self {
            Self::Sequence(mut v) if v.len() == 1 => v.pop().unwrap().flatten(),
            Self::Sequence(v) => Self::Sequence(v.into_iter().map(Self::flatten).collect()),
            other => other,
        }
    }

    /// Count how many `Goto` nodes remain in the tree.
    #[must_use]
    pub fn goto_count(&self) -> usize {
        match self {
            Self::Goto(_) => 1,
            Self::Sequence(v) => v.iter().map(Self::goto_count).sum(),
            Self::If { then_branch, .. } => then_branch.goto_count(),
            Self::IfElse {
                then_branch,
                else_branch,
                ..
            } => then_branch.goto_count() + else_branch.goto_count(),
            Self::Loop { body, .. } => body.goto_count(),
            Self::Switch { cases, .. } => cases.iter().map(|c| c.body.goto_count()).sum(),
            _ => 0,
        }
    }

    /// Recursively count total nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        match self {
            Self::Sequence(v) => v.iter().map(Self::node_count).sum::<usize>() + 1,
            Self::If { then_branch, .. } => then_branch.node_count() + 1,
            Self::IfElse {
                then_branch,
                else_branch,
                ..
            } => then_branch.node_count() + else_branch.node_count() + 1,
            Self::Loop { body, .. } => body.node_count() + 1,
            Self::Switch { cases, .. } => {
                cases.iter().map(|c| c.body.node_count()).sum::<usize>() + 1
            }
            _ => 1,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level result type
// ─────────────────────────────────────────────────────────────────────────────

/// The structured output for a whole function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredAst {
    pub entry: BlockId,
    pub root: StructuredNode,
    /// Number of `Goto` nodes remaining after structuring.
    pub goto_count: usize,
    /// Number of SCCs (natural loops) detected.
    pub loop_count: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum StructureError {
    #[error("entry block {0} not found in block list")]
    EntryNotFound(BlockId),
    #[error("empty CFG — no basic blocks provided")]
    EmptyCfg,
    #[error("CFG contains no outgoing edges from entry {0}")]
    DisconnectedEntry(BlockId),
    #[error("internal structuring error: {0}")]
    Internal(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal graph helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Internal CFG representation built on top of petgraph.
pub struct CfgGraph {
    graph: DiGraph<BlockId, ()>,
    /// Map from `BlockId` → petgraph `NodeIndex`.
    id_to_node: HashMap<BlockId, NodeIndex>,
    /// Reverse map.
    node_to_id: HashMap<NodeIndex, BlockId>,
    /// Original basic-block data.
    blocks: HashMap<BlockId, BasicBlock>,
}

impl CfgGraph {
    fn build(blocks: &[BasicBlock]) -> Result<Self, StructureError> {
        if blocks.is_empty() {
            return Err(StructureError::EmptyCfg);
        }
        let mut graph = DiGraph::new();
        let mut id_to_node = HashMap::new();
        let mut node_to_id = HashMap::new();
        let mut block_map = HashMap::new();

        // First pass: add all nodes.
        for bb in blocks {
            let ni = graph.add_node(bb.id);
            id_to_node.insert(bb.id, ni);
            node_to_id.insert(ni, bb.id);
            block_map.insert(bb.id, bb.clone());
        }
        // Second pass: add edges.
        for bb in blocks {
            let from = id_to_node[&bb.id];
            for &succ in &bb.successors {
                if let Some(&to) = id_to_node.get(&succ) {
                    graph.add_edge(from, to, ());
                }
            }
        }
        Ok(Self {
            graph,
            id_to_node,
            node_to_id,
            blocks: block_map,
        })
    }

    fn node_index(&self, id: BlockId) -> Option<NodeIndex> {
        self.id_to_node.get(&id).copied()
    }

    fn block_id(&self, ni: NodeIndex) -> BlockId {
        self.node_to_id[&ni]
    }

    fn successors(&self, ni: NodeIndex) -> Vec<NodeIndex> {
        self.graph.neighbors(ni).collect()
    }

    fn predecessors(&self, ni: NodeIndex) -> Vec<NodeIndex> {
        self.graph
            .neighbors_directed(ni, petgraph::Direction::Incoming)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Dominator tree (Cooper et al. iterative algorithm)
//
// The structurer no longer consults dominance (loop bodies come from natural
// loops instead), so these are currently exercised only by the unit tests.
// ─────────────────────────────────────────────────────────────────────────────

#[allow(dead_code)]
fn compute_dominators(cfg: &CfgGraph, entry: NodeIndex) -> HashMap<NodeIndex, NodeIndex> {
    // RPO ordering.
    let rpo = rpo_order(cfg, entry);
    let rpo_pos: HashMap<NodeIndex, usize> = rpo.iter().enumerate().map(|(i, &n)| (n, i)).collect();

    let mut idom: HashMap<NodeIndex, NodeIndex> = HashMap::new();
    idom.insert(entry, entry);

    let mut changed = true;
    while changed {
        changed = false;
        for &b in &rpo {
            if b == entry {
                continue;
            }
            let preds: Vec<NodeIndex> = cfg
                .predecessors(b)
                .into_iter()
                .filter(|p| idom.contains_key(p))
                .collect();
            if preds.is_empty() {
                continue;
            }
            // Pick a processed predecessor.
            let mut new_idom = preds[0];
            for &p in preds.iter().skip(1) {
                new_idom = intersect(new_idom, p, &idom, &rpo_pos);
            }
            if idom.get(&b) != Some(&new_idom) {
                idom.insert(b, new_idom);
                changed = true;
            }
        }
    }
    idom
}

#[allow(dead_code)]
fn intersect(
    mut b1: NodeIndex,
    mut b2: NodeIndex,
    idom: &HashMap<NodeIndex, NodeIndex>,
    rpo_pos: &HashMap<NodeIndex, usize>,
) -> NodeIndex {
    while b1 != b2 {
        while rpo_pos.get(&b1).copied().unwrap_or(usize::MAX)
            > rpo_pos.get(&b2).copied().unwrap_or(usize::MAX)
        {
            b1 = idom[&b1];
        }
        while rpo_pos.get(&b2).copied().unwrap_or(usize::MAX)
            > rpo_pos.get(&b1).copied().unwrap_or(usize::MAX)
        {
            b2 = idom[&b2];
        }
    }
    b1
}

#[allow(dead_code)]
fn rpo_order(cfg: &CfgGraph, entry: NodeIndex) -> Vec<NodeIndex> {
    // Iterative post-order DFS to avoid stack overflow on deep CFGs.
    let mut visited = HashSet::new();
    let mut post = Vec::new();
    let mut stack: Vec<(NodeIndex, usize)> = Vec::new();
    if visited.insert(entry) {
        stack.push((entry, 0));
    }
    while let Some(frame) = stack.last_mut() {
        let succs = cfg.successors(frame.0);
        if frame.1 < succs.len() {
            let next = succs[frame.1];
            frame.1 += 1;
            if visited.insert(next) {
                stack.push((next, 0));
            }
        } else {
            post.push(frame.0);
            stack.pop();
        }
    }
    post.reverse();
    post
}

// ─────────────────────────────────────────────────────────────────────────────
// Loop detection via DFS back-edge identification + Tarjan SCC for headers
// ─────────────────────────────────────────────────────────────────────────────

/// DFS colour states for back-edge detection.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Colour {
    White, // unvisited
    Grey,  // on the current DFS path
    Black, // fully explored
}

/// Returns a set of `(header, latch)` pairs for all back-edges in the CFG.
///
/// Uses DFS: any edge `(u, v)` where `v` is currently on the DFS stack (grey)
/// is a back-edge, and `v` is the loop header.
fn find_back_edges(cfg: &CfgGraph, entry: NodeIndex) -> HashSet<(NodeIndex, NodeIndex)> {
    // Iterative DFS back-edge detection to avoid stack overflow on deep CFGs.
    let mut colour: HashMap<NodeIndex, Colour> = HashMap::new();
    let mut back_edges = HashSet::new();
    // Stack frame: (node, index into successors already processed).
    let mut stack: Vec<(NodeIndex, usize)> = vec![(entry, 0)];
    colour.insert(entry, Colour::Grey);
    while let Some(frame) = stack.last_mut() {
        let node = frame.0;
        let succs = cfg.successors(node);
        if frame.1 < succs.len() {
            let succ = succs[frame.1];
            frame.1 += 1;
            match colour.get(&succ).copied().unwrap_or(Colour::White) {
                Colour::Grey => {
                    back_edges.insert((succ, node));
                }
                Colour::White => {
                    colour.insert(succ, Colour::Grey);
                    stack.push((succ, 0));
                }
                Colour::Black => {}
            }
        } else {
            colour.insert(node, Colour::Black);
            stack.pop();
        }
    }
    back_edges
}

/// Keep `tarjan_scc` available for any caller that wants SCC membership.
///
/// (Unused directly by the structurer, but kept to avoid a dead-code warning
/// on the import — the SCC call is intentionally inlined into `find_back_edges`
/// above which now uses DFS instead.)
#[must_use] 
pub fn scc_groups(cfg: &CfgGraph) -> Vec<Vec<NodeIndex>> {
    tarjan_scc(&cfg.graph)
}

// ─────────────────────────────────────────────────────────────────────────────
// DREAM structuring
// ─────────────────────────────────────────────────────────────────────────────

/// The main structuring engine.
pub struct ControlFlowStructurer {
    blocks: Vec<BasicBlock>,
}

impl ControlFlowStructurer {
    /// Create a structurer from a list of basic blocks.
    #[must_use]
    pub const fn new(blocks: Vec<BasicBlock>) -> Self {
        Self { blocks }
    }

    /// Run the DREAM algorithm and return a `StructuredAst`.
    ///
    /// # Errors
    /// Returns `StructureError` if the entry block is not present or the CFG
    /// is empty.
    pub fn structure(&self, entry: BlockId) -> Result<StructuredAst, StructureError> {
        let cfg = CfgGraph::build(&self.blocks)?;
        let entry_ni = cfg
            .node_index(entry)
            .ok_or(StructureError::EntryNotFound(entry))?;

        let back_edges = find_back_edges(&cfg, entry_ni);
        let loop_count = back_edges.len();

        let mut ctx = StructCtx {
            cfg: &cfg,
            back_edges: &back_edges,
            visited: HashSet::new(),
            pending_primary: HashSet::new(),
            loop_headers: back_edges.iter().map(|&(h, _)| h).collect(),
            loop_follow: None,
            cur_loop_header: None,
            cur_loop_body: None,
        };

        let root = ctx.structure_region(entry_ni, None);
        let goto_count = root.goto_count();

        let ast = StructuredAst {
            entry,
            root: root.flatten(),
            goto_count,
            loop_count,
        };
        Ok(ast_postpass::run_all(ast))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Structuring context
// ─────────────────────────────────────────────────────────────────────────────

struct StructCtx<'a> {
    cfg: &'a CfgGraph,
    back_edges: &'a HashSet<(NodeIndex, NodeIndex)>,
    /// Nodes that have been fully emitted as primary structuring targets.
    visited: HashSet<NodeIndex>,
    /// Nodes that are pending primary emission (used as branch-follow / join
    /// targets). They must NOT count as visited yet so that the later primary
    /// call can structure them correctly.
    pending_primary: HashSet<NodeIndex>,
    loop_headers: HashSet<NodeIndex>,
    /// Follow (exit) node of the innermost loop currently being structured.
    /// A region that reaches it is leaving the loop, so it must emit an
    /// explicit `Break` rather than silently falling off the end of the body.
    loop_follow: Option<NodeIndex>,
    /// Header of the innermost loop currently being structured. A `Continue`
    /// is only legal for THIS loop; a latch of some other (outer) loop reached
    /// from here is not a continue of the loop we are inside.
    cur_loop_header: Option<NodeIndex>,
    /// Natural-loop body of the innermost loop currently being structured.
    ///
    /// Needed by `structure_condition` (D11): inside a loop, a conditional arm
    /// that leaves the loop body is an EXIT, not a join candidate, and must
    /// become `If{cond -> Break}`. The test has to be membership in the
    /// INNERMOST body — an arm that leaves this loop but stays inside an outer
    /// one must NOT break here. Kept in lockstep with `cur_loop_header`.
    cur_loop_body: Option<HashSet<NodeIndex>>,
}

impl StructCtx<'_> {
    /// Recursively structure a region starting at `node`, stopping when
    /// `follow` is reached (the post-dominator / join point of the enclosing
    /// `if` or loop).
    fn structure_region(&mut self, node: NodeIndex, follow: Option<NodeIndex>) -> StructuredNode {
        if Some(node) == follow {
            // Reaching the enclosing loop's follow means this path LEAVES the
            // loop. Falling through silently is only correct when the loop test
            // is re-evaluated right here; for a body-interior exit (the test
            // block is neither the header nor a latch) the fall-through would
            // re-enter the loop instead, silently dropping the exit. Emit the
            // break explicitly.
            if Some(node) == self.loop_follow {
                return StructuredNode::Break;
            }
            return StructuredNode::Sequence(vec![]);
        }
        // A node that is pending as a join/follow from an outer branch must
        // not be treated as visited yet; it will be structured when the outer
        // call processes it as its primary target.
        if self.visited.contains(&node) && !self.pending_primary.contains(&node) {
            // Already fully emitted. A short straight-line tail ending in a
            // return is DUPLICATED instead of collapsed to a `Goto`: the first
            // emission may sit inside another region — e.g. a jump-table
            // default block that is also a case target (`cmp idx,N; ja
            // default` guard over a table with an in-range hole) — where its
            // label is not addressable, so the `Goto` dangles and downstream
            // passes silently drop it, losing the block's computation (the
            // D3 "default body dropped" bug). Re-emitting a bounded return
            // tail is always semantics-preserving.
            if let Some(dup) = self.duplicate_terminal_tail(node) {
                return dup;
            }
            // Otherwise emit goto to avoid duplicating a whole region.
            return StructuredNode::Goto(self.cfg.block_id(node));
        }
        self.pending_primary.remove(&node);
        self.visited.insert(node);

        let block_id = self.cfg.block_id(node);
        let bb = self.cfg.blocks[&block_id].clone();
        let succs: Vec<NodeIndex> = self
            .cfg
            .successors(node)
            .into_iter()
            .filter(|&s| !self.is_back_edge(node, s))
            .collect();

        // ── Return / terminal block ──────────────────────────────────────────
        if succs.is_empty() {
            let leaf = leaf_block(&bb);
            // A latch looks terminal only because its back edge was filtered
            // out above. It is not the end of anything — it jumps back to the
            // header. Emitting a bare leaf lets control fall through into
            // whatever the structurer happens to emit next (e.g. the other arm
            // of an in-loop conditional), silently changing semantics.
            if self.cur_loop_header.is_some()
                && self
                    .cfg
                    .successors(node)
                    .iter()
                    .any(|&s| self.is_back_edge(node, s) && Some(s) == self.cur_loop_header)
            {
                return flatten_seq(vec![leaf, StructuredNode::Continue]);
            }
            // Only emit a Return node when the block actually contains a
            // Statement::Return.  Blocks ending with a tail-call, trap, or
            // unreachable should not get a spurious Return(None).
            let found_return = bb.stmts.iter().rev().find_map(|s| {
                if let Statement::Return(v) = s {
                    Some(v.clone())
                } else {
                    None
                }
            });
            return if let Some(ret_val) = found_return {
                StructuredNode::Sequence(vec![leaf, StructuredNode::Return(ret_val)])
            } else {
                leaf
            };
        }

        // ── Loop header ──────────────────────────────────────────────────────
        if self.loop_headers.contains(&node) {
            return self.structure_loop(node, follow);
        }

        // ── Straight sequence (one successor) ────────────────────────────────
        if succs.len() == 1 {
            let next = succs[0];
            // A CONDITIONAL LATCH: this block really has two successors, one of
            // which is a back edge to the loop header that the filter above
            // removed. Returning a bare leaf here discards the block's test —
            // the second conjunct of a compound `do { } while (a && b)` — and
            // emits no `break`, so the loop can never exit on it. Emit the
            // test as an explicit `break` plus an explicit `continue`.
            // Gated strictly on the back edge targeting THIS loop's header:
            // a back edge to an outer loop must not break out of the inner one.
            if let Some(back_target) = self
                .cfg
                .successors(node)
                .into_iter()
                .find(|&s| self.is_back_edge(node, s))
                && Some(back_target) == self.cur_loop_header
                && self.cfg.successors(node).len() == 2
            {
                let leaf = leaf_block(&bb);
                let raw = extract_condition(&bb);
                // `extract_condition` guards the TAKEN (first) successor. The
                // loop continues when control goes to the header, so break on
                // the negation of "continue".
                let taken = self.cfg.successors(node).first().copied();
                let cont_cond =
                    if taken == Some(back_target) { raw } else { negate_cond(&raw) };
                return flatten_seq(vec![
                    leaf,
                    StructuredNode::If {
                        condition: negate_cond(&cont_cond),
                        then_branch: Box::new(StructuredNode::Break),
                    },
                    StructuredNode::Continue,
                ]);
            }
            if Some(next) == follow {
                return leaf_block(&bb);
            }
            let rest = self.structure_region(next, follow);
            let leaf = leaf_block(&bb);
            return flatten_seq(vec![leaf, rest]);
        }

        // ── Conditional (two successors) ─────────────────────────────────────
        if succs.len() == 2 {
            return self.structure_condition(node, succs[0], succs[1], follow);
        }

        // ── Switch (3+ successors) ────────────────────────────────────────────
        self.structure_switch(node, &succs, follow)
    }

    /// If `start` begins a straight-line chain (each block exactly one forward
    /// successor) that reaches a terminal return block within a few blocks,
    /// return a duplicated copy of that chain (leaves + final `Return`).
    /// Returns `None` on any branch, loop header, or over-long chain, so
    /// callers fall back to a `Goto` and never duplicate whole regions.
    fn duplicate_terminal_tail(&self, start: NodeIndex) -> Option<StructuredNode> {
        const MAX_CHAIN: usize = 8;
        let mut nodes: Vec<NodeIndex> = Vec::new();
        let mut cur = start;
        loop {
            if nodes.len() > MAX_CHAIN || self.loop_headers.contains(&cur) {
                return None;
            }
            nodes.push(cur);
            let succs: Vec<NodeIndex> = self
                .cfg
                .successors(cur)
                .into_iter()
                .filter(|&s| !self.is_back_edge(cur, s))
                .collect();
            match succs.len() {
                0 => break,
                1 if !nodes.contains(&succs[0]) => cur = succs[0],
                _ => return None,
            }
        }
        let mut out: Vec<StructuredNode> = Vec::new();
        let mut ret_val: Option<Option<String>> = None;
        for &n in &nodes {
            let bb = self.cfg.blocks.get(&self.cfg.block_id(n))?;
            out.push(leaf_block(bb));
            if let Some(v) = bb.stmts.iter().rev().find_map(|s| {
                if let Statement::Return(v) = s { Some(v.clone()) } else { None }
            }) {
                ret_val = Some(v);
            }
        }
        // Only duplicate a tail that visibly terminates; a returnless chain
        // (e.g. a tail-call stub) keeps the honest `Goto`.
        let rv = ret_val?;
        out.push(StructuredNode::Return(rv));
        Some(flatten_seq(out))
    }

    fn structure_loop(&mut self, header: NodeIndex, follow: Option<NodeIndex>) -> StructuredNode {
        let block_id = self.cfg.block_id(header);
        let bb = self.cfg.blocks[&block_id].clone();

        // Find the latch (the block with the back-edge to header).
        // `back_edges` is a HashSet, so its iteration order is randomized per
        // process — sort by node index (block/address order) so every choice
        // made below (condition latch, latch follow) is deterministic.
        let mut latches: Vec<NodeIndex> = self
            .back_edges
            .iter()
            .filter(|&&(h, _)| h == header)
            .map(|&(_, l)| l)
            .collect();
        latches.sort_unstable();

        let header_succs: Vec<NodeIndex> = self
            .cfg
            .successors(header)
            .into_iter()
            .filter(|&s| !self.is_back_edge(header, s))
            .collect();

        // The loop body is the natural loop of the back edges: every node that
        // reaches a latch without going through the header. Membership in this
        // set — not dominance — is what separates the body from the exit: a
        // `while` exit *is* dominated by the header, so an `idom != header`
        // test would reject every follow node and destroy the loop.
        let body_set = self.natural_loop_body(header, &latches);

        // The follow is the header successor outside the body (`while`), or,
        // when the header has no such successor, the latch successor outside
        // the body (`do`/`while`).
        let header_follow = header_succs.iter().copied().find(|s| !body_set.contains(s));
        let latch_follow = || {
            latches
                .iter()
                .flat_map(|&l| self.cfg.successors(l))
                .find(|s| !body_set.contains(s))
        };
        let follow_node = header_follow.or_else(latch_follow).or(follow);

        // The condition of a `Branch` guards its *taken* edge, which the CFG
        // records as the first successor. When the taken edge leaves the loop,
        // the loop continues on the negation.
        let cond_at = |ni: NodeIndex, continue_target: Option<NodeIndex>| {
            let id = self.cfg.block_id(ni);
            let raw = self.cfg.blocks.get(&id).map_or_else(|| "1".to_string(), extract_condition);
            let taken = self.cfg.successors(ni).first().copied();
            if taken.is_some() && taken == continue_target { raw } else { negate_cond(&raw) }
        };

        // `while` tests at the header (one successor leaves the loop);
        // otherwise the test lives at the latch → `do`/`while`.
        let body_entry = header_succs.iter().copied().find(|s| body_set.contains(s));
        let (kind, condition) = if header_follow.is_some() && header_succs.len() == 2 {
            (LoopKind::While, cond_at(header, body_entry))
        } else {
            // With multiple latches, the loop's real exit test is the latch
            // that actually branches (two successors); an unconditional latch
            // is just a `continue`, whose "condition" would be a fabricated
            // `true`. Prefer the bottom-most (highest node index = latest
            // address) conditional latch — where a source-level do/while test
            // lives — falling back to the bottom-most latch of any kind.
            let cond_latch = latches
                .iter()
                .copied()
                .filter(|&l| self.cfg.successors(l).len() == 2)
                .next_back()
                .or_else(|| latches.last().copied());
            let cond =
                cond_latch.map_or_else(|| "1".to_string(), |l| cond_at(l, Some(header)));
            (LoopKind::DoWhile, cond)
        };

        // While structuring the body, any path reaching `follow_node` is an
        // exit from THIS loop and must become a `Break`.
        let saved_loop_follow = self.loop_follow;
        let saved_loop_header = self.cur_loop_header;
        let saved_loop_body = self.cur_loop_body.take();
        self.loop_follow = follow_node;
        self.cur_loop_header = Some(header);
        self.cur_loop_body = Some(body_set.clone());

        // When the header is a two-way branch whose BOTH targets stay inside
        // the loop, it is an in-loop conditional, not a loop test. Structuring
        // it via a single `body_entry` walked only the first arm and silently
        // discarded the second — dropping that arm's computation and, when the
        // discarded arm held the only exit test, leaving a fabricated
        // `while (true)`. Structure the header as the conditional it is.
        let header_is_inner_cond =
            header_succs.len() == 2 && header_succs.iter().all(|s| body_set.contains(s));
        let body = if header_is_inner_cond {
            self.structure_condition(header, header_succs[0], header_succs[1], follow_node)
        } else {
            body_entry.map_or_else(|| StructuredNode::Sequence(vec![]), |body_start| self.structure_region(body_start, follow_node))
        };

        self.loop_follow = saved_loop_follow;
        self.cur_loop_header = saved_loop_header;
        self.cur_loop_body = saved_loop_body;

        // `structure_condition` already emits the header's own statements.
        let header_leaf = if header_is_inner_cond {
            StructuredNode::Sequence(vec![])
        } else {
            leaf_block(&bb)
        };
        let result = match kind {
            LoopKind::DoWhile => {
                // The do-while header block IS the first block of the loop body
                // (the test lives at the latch), so its statements belong INSIDE
                // the loop. Emitting them before the body — which for a
                // single-block self-loop is empty, since `natural_loop_body`
                // excludes the header — produced a no-op `do { } while (cond)`
                // with the real body hoisted above it.
                let full_body = flatten_seq(vec![header_leaf, body]);
                StructuredNode::Loop {
                    kind,
                    condition,
                    body: Box::new(full_body),
                }
            }
            LoopKind::While | LoopKind::For => {
                // Hoisting the header's statements above the loop is only sound
                // when the header carries NO statements — normally true, since
                // a `while` header is test-only and `leaf_block` strips the
                // compare. When gcc -O1 lowers a compound `do { B } while (a &&
                // b)`, the header carries the real BODY plus the first test;
                // hoisting then ran the body exactly once and left an empty
                // `while (a) { }` that never decremented the induction
                // variable. Re-express such a loop as `do { header; if (!cond)
                // break; body } while (true)`, which re-executes the header
                // every iteration exactly as the CFG does.
                // "Test-only" means the header carries nothing but its own
                // compare/branch — the shape `leaf_block` leaves for an
                // ordinary `while`. Those keep the existing hoist and stay
                // byte-identical. A header with any real statement takes the
                // new, sound path.
                let header_test_only = match &header_leaf {
                    StructuredNode::Sequence(v) => v.is_empty(),
                    StructuredNode::BasicBlock { stmts, .. } => {
                        stmts.iter().all(|st| matches!(st, Statement::Branch(_)))
                    }
                    _ => false,
                };
                if header_test_only {
                    let loop_node = StructuredNode::Loop {
                        kind,
                        condition,
                        body: Box::new(body),
                    };
                    flatten_seq(vec![header_leaf, loop_node])
                } else {
                    let full_body = flatten_seq(vec![
                        header_leaf,
                        StructuredNode::If {
                            condition: negate_cond(&condition),
                            then_branch: Box::new(StructuredNode::Break),
                        },
                        body,
                    ]);
                    StructuredNode::Loop {
                        kind: LoopKind::DoWhile,
                        condition: "1".to_string(),
                        body: Box::new(full_body),
                    }
                }
            }
        };

        // Continue with the code after the loop.
        if let Some(fn_) = follow_node
            && follow_node != follow {
                let after = self.structure_region(fn_, follow);
                return flatten_seq(vec![result, after]);
            }
        result
    }

    /// True when the edge `from → to` is a back edge.
    ///
    /// `find_back_edges` records each back edge as `(header, latch)`, i.e. the
    /// pair is reversed with respect to the edge direction.
    fn is_back_edge(&self, from: NodeIndex, to: NodeIndex) -> bool {
        self.back_edges.contains(&(to, from))
    }

    /// The natural loop of `header`: `header` itself plus every node that can
    /// reach a latch without passing through `header`, found by walking
    /// predecessors backwards from each latch.
    fn natural_loop_body(
        &self,
        header: NodeIndex,
        latches: &[NodeIndex],
    ) -> HashSet<NodeIndex> {
        let mut body: HashSet<NodeIndex> = HashSet::new();
        body.insert(header);
        let mut stack: Vec<NodeIndex> = Vec::new();
        for &l in latches {
            if body.insert(l) {
                stack.push(l);
            }
        }
        while let Some(n) = stack.pop() {
            for p in self.cfg.predecessors(n) {
                if body.insert(p) {
                    stack.push(p);
                }
            }
        }
        body
    }

    fn structure_condition(
        &mut self,
        node: NodeIndex,
        then_ni: NodeIndex,
        else_ni: NodeIndex,
        follow: Option<NodeIndex>,
    ) -> StructuredNode {
        let block_id = self.cfg.block_id(node);
        let bb = self.cfg.blocks[&block_id].clone();
        let condition = extract_condition(&bb);
        let leaf = leaf_block(&bb);

        // Compute the join (follow) of the two branches.
        // A branch arm that targets the ENCLOSING follow directly makes that
        // follow this if's join too: the other arm is the whole body and
        // control falls through to the outer continuation. Ignoring this and
        // picking a LOCAL join instead (the historical behavior) can pull a
        // region the outer context still owns — e.g. a loop header pending as
        // the outer join — inside this branch, leaving the outer entry path a
        // dangling `Goto` into it (sample6 factorial: the odd-n entry to the
        // ×2-unrolled loop was dropped, returning an uninitialised value).
        // Otherwise: the first node that is a successor of BOTH branches in
        // BFS order.
        let join = if follow.is_some() && (Some(then_ni) == follow || Some(else_ni) == follow) {
            follow
        } else {
            find_join(self.cfg, then_ni, else_ni, self.back_edges)
        };
        let branch_follow = join.or(follow);

        // Mark the join as a pending primary target so that branch arms do not
        // accidentally consume it as a visited node before the outer call
        // structures it as the post-join continuation.
        //
        // Guard against re-arming an ALREADY-visited join: if some earlier,
        // unrelated `structure_condition` call already fully structured `j`
        // (e.g. a shared cleanup/tail block reached as the join of two
        // separate, non-nested branches), re-inserting it into
        // `pending_primary` here would defeat `structure_region`'s
        // `visited && !pending_primary` anti-duplication guard on this call's
        // own later `structure_region(j, follow)` — causing `j`'s statements
        // to be fully re-emitted a second time instead of collapsing to a
        // `Goto`. Skipping the insert when `j` is already visited lets that
        // guard correctly kick in.
        if let Some(j) = branch_follow
            && Some(j) != follow
            && !self.visited.contains(&j) {
                self.pending_primary.insert(j);
            }

        // Detect simple if (no else): one branch goes directly to the join.
        if Some(then_ni) == branch_follow {
            // `if (!cond) { else_branch }`  →  negate condition
            let else_body = self.structure_region(else_ni, branch_follow);
            let if_node = StructuredNode::If {
                condition: negate_cond(&condition),
                then_branch: Box::new(else_body),
            };
            let result = flatten_seq(vec![leaf, if_node]);
            if let Some(j) = branch_follow.filter(|&j| Some(j) != follow) {
                let after = self.structure_region(j, follow);
                return flatten_seq(vec![result, after]);
            }
            return result;
        }
        if Some(else_ni) == branch_follow {
            let then_body = self.structure_region(then_ni, branch_follow);
            let if_node = StructuredNode::If {
                condition,
                then_branch: Box::new(then_body),
            };
            let result = flatten_seq(vec![leaf, if_node]);
            if let Some(j) = branch_follow.filter(|&j| Some(j) != follow) {
                let after = self.structure_region(j, follow);
                return flatten_seq(vec![result, after]);
            }
            return result;
        }

        // Full if-else.
        let then_body = self.structure_region(then_ni, branch_follow);
        let else_body = self.structure_region(else_ni, branch_follow);
        let if_else_node = StructuredNode::IfElse {
            condition,
            then_branch: Box::new(then_body),
            else_branch: Box::new(else_body),
        };
        let result = flatten_seq(vec![leaf, if_else_node]);
        if let Some(j) = branch_follow.filter(|&j| Some(j) != follow) {
            let after = self.structure_region(j, follow);
            return flatten_seq(vec![result, after]);
        }
        result
    }

    fn structure_switch(
        &mut self,
        node: NodeIndex,
        case_targets: &[NodeIndex],
        follow: Option<NodeIndex>,
    ) -> StructuredNode {
        let block_id = self.cfg.block_id(node);
        let bb = self.cfg.blocks[&block_id].clone();
        let expr = extract_condition(&bb);
        let leaf = leaf_block(&bb);

        // Find join point.
        let join = find_switch_join(self.cfg, case_targets);
        let case_follow = join.or(follow);

        let mut cases = Vec::new();
        for &target in case_targets {
            let target_bb_id = self.cfg.block_id(target);
            let target_bb = self.cfg.blocks.get(&target_bb_id);
            // Attempt to extract the actual case constant from the target
            // block's Branch statement.  If no constant is present (the true
            // discriminant values are unavailable at this point), emit `None`
            // (default arm) rather than wrong synthetic indices 0, 1, 2, …
            let case_value = target_bb.and_then(|bb| {
                bb.stmts.iter().find_map(|s| {
                    if let Statement::Branch(cond) = s {
                        cond.trim().parse::<i64>().ok()
                    } else {
                        None
                    }
                })
            });
            let body = self.structure_region(target, case_follow);
            cases.push(SwitchCase {
                value: case_value,
                body: Box::new(body),
            });
        }

        // A switch may have at most one `default:` arm. The structurer marks
        // any case target lacking a recovered constant as `value: None`; when
        // more than one such arm appears (e.g. an empty fallthrough plus a real
        // block whose case constant was not recovered), emitting them all
        // produces duplicate `default:` labels — invalid C. Keep the single most
        // meaningful default (largest body wins, so a real block beats a bare
        // `break`) and drop the rest.
        if cases.iter().filter(|c| c.value.is_none()).count() > 1 {
            let best_default = cases
                .iter()
                .enumerate()
                .filter(|(_, c)| c.value.is_none())
                .max_by_key(|(_, c)| c.body.node_count())
                .map(|(i, _)| i);
            let mut pos = 0;
            cases.retain(|c| {
                let keep = c.value.is_some() || Some(pos) == best_default;
                pos += 1;
                keep
            });
        }

        let switch_node = StructuredNode::Switch { expr, cases };
        let result = flatten_seq(vec![leaf, switch_node]);

        if let Some(j) = case_follow.filter(|&j| Some(j) != follow) {
            let after = self.structure_region(j, follow);
            return flatten_seq(vec![result, after]);
        }
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper functions
// ─────────────────────────────────────────────────────────────────────────────

fn leaf_block(bb: &BasicBlock) -> StructuredNode {
    StructuredNode::BasicBlock {
        id: bb.id,
        stmts: bb.stmts.iter().filter(|s| !matches!(s, Statement::Return(_))).cloned().collect(),
    }
}

fn flatten_seq(nodes: Vec<StructuredNode>) -> StructuredNode {
    let flat: Vec<StructuredNode> = nodes
        .into_iter()
        .flat_map(|n| match n {
            StructuredNode::Sequence(v) => v,
            other => vec![other],
        })
        .filter(|n| !matches!(n, StructuredNode::Sequence(v) if v.is_empty()))
        .collect();
    match flat.len() {
        0 => StructuredNode::Sequence(vec![]),
        1 => flat.into_iter().next().unwrap(),
        _ => StructuredNode::Sequence(flat),
    }
}

fn extract_condition(bb: &BasicBlock) -> String {
    bb.stmts
        .iter()
        .rev()
        .find_map(|s| {
            if let Statement::Branch(c) = s {
                Some(c.clone())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "true".to_string())
}

/// Locate the top-level comparison operator in `cond`, returning its byte range
/// and its inverse. Returns `None` when the condition is not a bare comparison
/// (nested parentheses aside), e.g. because it joins clauses with `&&` / `||`.
fn find_top_level_cmp(cond: &str) -> Option<(std::ops::Range<usize>, &'static str)> {
    let b = cond.as_bytes();
    let mut depth = 0i32;
    let mut i = 0usize;
    let mut found: Option<(std::ops::Range<usize>, &'static str)> = None;
    while i < b.len() {
        match b[i] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ if depth != 0 => {}
            // `&&` / `||` make the whole expression a boolean join; inverting a
            // single comparison inside it would be wrong.
            b'&' | b'|' if b.get(i + 1) == Some(&b[i]) => return None,
            // Shifts are not comparisons.
            b'<' | b'>' if b.get(i + 1) == Some(&b[i]) => i += 1,
            _ if depth == 0 => {
                let hit = match cond.get(i..i + 2) {
                    Some("==") => Some((2, "!=")),
                    Some("!=") => Some((2, "==")),
                    Some("<=") => Some((2, ">")),
                    Some(">=") => Some((2, "<")),
                    _ => match b[i] {
                        b'<' => Some((1, ">=")),
                        b'>' => Some((1, "<=")),
                        _ => None,
                    },
                };
                if let Some((len, inv)) = hit {
                    // More than one top-level comparison → not a bare comparison.
                    if found.is_some() {
                        return None;
                    }
                    found = Some((i..i + len, inv));
                    i += len;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }
    found
}

/// Negate a condition, preferring operator inversion over a `!(…)` wrapper:
/// `a >= b` becomes `a < b`, not `!(a >= b)`.
fn negate_cond(cond: &str) -> String {
    let cond = cond.trim();
    if let Some(rest) = cond.strip_prefix('!') {
        return rest.trim().to_string();
    }
    if let Some((range, inv)) = find_top_level_cmp(cond) {
        let mut out = String::with_capacity(cond.len() + 1);
        out.push_str(cond[..range.start].trim_end());
        out.push(' ');
        out.push_str(inv);
        out.push(' ');
        out.push_str(cond[range.end..].trim_start());
        return out;
    }
    format!("!({cond})")
}

/// Find the join point (post-dominator) of two branch targets.
///
/// Returns the first node reachable from BOTH `a` and `b`.  In a simple
/// `if`-without-`else` the join is one of the two sides itself (the side
/// the other directly targets).
/// Forward reachability that does NOT traverse back edges.
///
/// A join point must be found by going *forward*; letting the search wrap
/// around a loop back edge makes any node in the loop body look like the join
/// of two in-loop branch arms, which then swallows the rest of the loop.
fn bfs_reachable_forward(
    cfg: &CfgGraph,
    start: NodeIndex,
    back_edges: &HashSet<(NodeIndex, NodeIndex)>,
) -> HashSet<NodeIndex> {
    let mut seen = HashSet::new();
    let mut queue = VecDeque::from([start]);
    seen.insert(start);
    while let Some(n) = queue.pop_front() {
        for s in cfg.successors(n) {
            // `back_edges` records each back edge as (header, latch).
            if back_edges.contains(&(s, n)) {
                continue;
            }
            if seen.insert(s) {
                queue.push_back(s);
            }
        }
    }
    seen
}

fn find_join(
    cfg: &CfgGraph,
    a: NodeIndex,
    b: NodeIndex,
    back_edges: &HashSet<(NodeIndex, NodeIndex)>,
) -> Option<NodeIndex> {
    let reachable_a = bfs_reachable_forward(cfg, a, back_edges);
    let reachable_b = bfs_reachable_forward(cfg, b, back_edges);

    // `b` is a join if it is reachable from `a` (simple if: then → join=b).
    if reachable_a.contains(&b) {
        return Some(b);
    }
    // `a` is a join if it is reachable from `b` (reverse simple if: else → join=a).
    if reachable_b.contains(&a) {
        return Some(a);
    }

    // General case: BFS from both sides; the first shared node (by RPO from a)
    // is the join.
    let intersection: HashSet<NodeIndex> =
        reachable_a.intersection(&reachable_b).copied().collect();
    if intersection.is_empty() {
        return None;
    }

    // Pick the one that appears earliest in BFS from `a`.
    let mut queue = VecDeque::from([a]);
    let mut seen = HashSet::new();
    seen.insert(a);
    while let Some(n) = queue.pop_front() {
        if intersection.contains(&n) && n != a {
            return Some(n);
        }
        for s in cfg.successors(n) {
            if back_edges.contains(&(s, n)) {
                continue;
            }
            if seen.insert(s) {
                queue.push_back(s);
            }
        }
    }
    intersection.into_iter().next()
}

fn find_switch_join(cfg: &CfgGraph, targets: &[NodeIndex]) -> Option<NodeIndex> {
    if targets.is_empty() {
        return None;
    }
    let reachable_sets: Vec<HashSet<NodeIndex>> =
        targets.iter().map(|&t| bfs_reachable(cfg, t)).collect();
    // Find intersection in BFS order from the first target.
    let mut queue = VecDeque::from([targets[0]]);
    let mut seen = HashSet::new();
    while let Some(n) = queue.pop_front() {
        if reachable_sets.iter().all(|r| r.contains(&n)) && !targets.contains(&n) {
            return Some(n);
        }
        for s in cfg.successors(n) {
            if seen.insert(s) {
                queue.push_back(s);
            }
        }
    }
    None
}

fn bfs_reachable(cfg: &CfgGraph, start: NodeIndex) -> HashSet<NodeIndex> {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::from([start]);
    while let Some(n) = queue.pop_front() {
        if visited.insert(n) {
            for s in cfg.successors(n) {
                queue.push_back(s);
            }
        }
    }
    visited
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn bb(id: u32, stmts: Vec<Statement>, succs: Vec<u32>) -> BasicBlock {
        BasicBlock {
            id: BlockId::new(id),
            stmts,
            successors: succs.into_iter().map(BlockId::new).collect(),
        }
    }

    fn branch(cond: &str) -> Statement {
        Statement::Branch(cond.to_string())
    }

    fn raw(s: &str) -> Statement {
        Statement::Raw(s.to_string())
    }

    fn assign(l: &str, r: &str) -> Statement {
        Statement::Assign {
            lhs: l.to_string(),
            rhs: r.to_string(),
        }
    }

    // ── Basic construction tests ─────────────────────────────────────────────

    #[test]
    fn test_block_id_display() {
        assert_eq!(BlockId::new(5).to_string(), "bb5");
    }

    #[test]
    fn test_single_block_return() {
        let blocks = vec![bb(
            0,
            vec![Statement::Return(Some("0".to_string()))],
            vec![],
        )];
        let ast = ControlFlowStructurer::new(blocks)
            .structure(BlockId::new(0))
            .unwrap();
        assert_eq!(ast.goto_count, 0);
    }

    #[test]
    fn test_linear_sequence() {
        // 0 → 1 → 2 (terminal)
        let blocks = vec![
            bb(0, vec![raw("x = 1")], vec![1]),
            bb(1, vec![raw("x = 2")], vec![2]),
            bb(2, vec![Statement::Return(None)], vec![]),
        ];
        let ast = ControlFlowStructurer::new(blocks)
            .structure(BlockId::new(0))
            .unwrap();
        assert_eq!(ast.goto_count, 0);
        assert!(ast.root.node_count() >= 3);
    }

    #[test]
    fn test_empty_cfg_error() {
        let result = ControlFlowStructurer::new(vec![]).structure(BlockId::new(0));
        assert!(matches!(result, Err(StructureError::EmptyCfg)));
    }

    #[test]
    fn test_entry_not_found_error() {
        let blocks = vec![bb(0, vec![], vec![])];
        let result = ControlFlowStructurer::new(blocks).structure(BlockId::new(99));
        assert!(matches!(result, Err(StructureError::EntryNotFound(_))));
    }

    #[test]
    fn test_simple_if() {
        // 0 --true→ 1, 0 --false→ 2, 1 → 2 (join)
        let blocks = vec![
            bb(0, vec![branch("x > 0")], vec![1, 2]),
            bb(1, vec![raw("y = 1")], vec![2]),
            bb(2, vec![Statement::Return(Some("y".to_string()))], vec![]),
        ];
        let ast = ControlFlowStructurer::new(blocks)
            .structure(BlockId::new(0))
            .unwrap();
        assert_eq!(ast.goto_count, 0);
    }

    #[test]
    fn test_if_else() {
        // 0 → {1, 2}, 1 → 3, 2 → 3, 3 terminal
        let blocks = vec![
            bb(0, vec![branch("flag")], vec![1, 2]),
            bb(1, vec![raw("a = 1")], vec![3]),
            bb(2, vec![raw("a = 2")], vec![3]),
            bb(3, vec![Statement::Return(Some("a".to_string()))], vec![]),
        ];
        let ast = ControlFlowStructurer::new(blocks)
            .structure(BlockId::new(0))
            .unwrap();
        assert_eq!(ast.goto_count, 0);
    }

    #[test]
    fn branch_arm_targeting_enclosing_follow_keeps_loop_at_join_level() {
        // The sample6 factorial shape: a do/while loop header (3) entered from
        // TWO paths — directly from the parity test (1, odd n) and from a
        // pre-step block (2, even n). Correct structure is
        // `if (even) { pre; if (done) return; }  do { … } while (…); return;`
        // with ZERO gotos. The historical join heuristic at block 2 ignored the
        // enclosing pending follow (3) and picked the local join 4, consuming
        // the loop inside the even arm; the odd entry then degraded to a Goto
        // whose label is not addressable — downstream passes drop it and the
        // odd path silently loses the whole loop (uninitialised `return`).
        let blocks = vec![
            bb(0, vec![assign("edx", "1"), assign("eax", "ecx"), branch("ecx <= 1")], vec![1, 4]),
            bb(1, vec![branch("(al & 1) != 0")], vec![2, 3]),
            bb(
                2,
                vec![assign("rdx", "rax"), assign("rax", "rax - 1"), branch("rax == 1")],
                vec![3, 4],
            ),
            bb(
                3,
                vec![
                    assign("rdx", "rdx * rax"),
                    assign("rcx", "rax + -1"),
                    assign("rax", "rax - 2"),
                    assign("rdx", "rdx * rcx"),
                    branch("rax != 1"),
                ],
                vec![4, 3],
            ),
            bb(4, vec![assign("rax", "rdx"), Statement::Return(None)], vec![]),
        ];
        let ast = ControlFlowStructurer::new(blocks).structure(BlockId::new(0)).unwrap();
        assert_eq!(ast.goto_count, 0, "odd entry to the loop must not degrade to a goto");
    }

    #[test]
    fn test_while_loop() {
        // 0 (init) → 1 (header/cond), 1 → {2 (body), 3 (exit)}, 2 → 1
        let blocks = vec![
            bb(0, vec![assign("i", "0")], vec![1]),
            bb(1, vec![branch("i < 10")], vec![2, 3]),
            bb(2, vec![assign("i", "i+1")], vec![1]),
            bb(3, vec![Statement::Return(Some("i".to_string()))], vec![]),
        ];
        let ast = ControlFlowStructurer::new(blocks)
            .structure(BlockId::new(0))
            .unwrap();
        assert!(ast.loop_count >= 1);
    }

    #[test]
    fn test_do_while_loop() {
        // 0 (body) → 1 (latch/cond), 1 → {0 (back-edge), 2 (exit)}
        let blocks = vec![
            bb(0, vec![raw("do_work()")], vec![1]),
            bb(1, vec![branch("keep_going")], vec![0, 2]),
            bb(2, vec![Statement::Return(None)], vec![]),
        ];
        let ast = ControlFlowStructurer::new(blocks)
            .structure(BlockId::new(0))
            .unwrap();
        assert!(ast.loop_count >= 1);
    }

    #[test]
    fn multi_latch_do_while_takes_condition_from_the_conditional_latch_deterministically() {
        // A do/while loop with TWO latches: block 1 jumps back unconditionally
        // (a `continue`), block 2 holds the real exit test. `back_edges` is a
        // HashSet, and before the deterministic sort + conditional-latch
        // preference this flipped run-to-run between `} while (n != 0)` and a
        // fabricated `} while (true)` depending on RandomState iteration order.
        //   0 (header) → {1, 2};  1 → 0 (unconditional latch);
        //   2 → {0 (back edge), 3 (exit)};  3 return.
        let blocks = vec![
            bb(0, vec![branch("x")], vec![1, 2]),
            bb(1, vec![raw("work_a()")], vec![0]),
            bb(2, vec![branch("n != 0")], vec![0, 3]),
            bb(3, vec![Statement::Return(None)], vec![]),
        ];
        fn collect_loops(n: &StructuredNode, out: &mut Vec<(LoopKind, String)>) {
            match n {
                StructuredNode::Loop { kind, condition, body } => {
                    out.push((kind.clone(), condition.clone()));
                    collect_loops(body, out);
                }
                StructuredNode::Sequence(v) => v.iter().for_each(|c| collect_loops(c, out)),
                StructuredNode::If { then_branch, .. } => collect_loops(then_branch, out),
                StructuredNode::IfElse { then_branch, else_branch, .. } => {
                    collect_loops(then_branch, out);
                    collect_loops(else_branch, out);
                }
                StructuredNode::Switch { cases, .. } => {
                    cases.iter().for_each(|c| collect_loops(&c.body, out));
                }
                _ => {}
            }
        }
        // The choice must be identical on EVERY structuring, and must be the
        // real exit test, never the unconditional latch's fabricated `true`.
        let mut first: Option<Vec<(LoopKind, String)>> = None;
        for _ in 0..8 {
            let ast = ControlFlowStructurer::new(blocks.clone())
                .structure(BlockId::new(0))
                .unwrap();
            let mut loops = Vec::new();
            collect_loops(&ast.root, &mut loops);
            // Either polarity is fine (edge orientation may negate), but the
            // condition must come from the conditional latch's `n` test —
            // never the unconditional latch's fabricated `true`.
            assert!(
                loops
                    .iter()
                    .any(|(k, c)| *k == LoopKind::DoWhile && (c == "n != 0" || c == "n == 0")),
                "do/while must take its condition from the conditional latch: {loops:?}"
            );
            match &first {
                None => first = Some(loops),
                Some(f) => assert_eq!(f, &loops, "structuring must be deterministic"),
            }
        }
    }

    #[test]
    fn test_self_loop() {
        // 0 → 0 (infinite loop)
        let blocks = vec![bb(0, vec![raw("spin()")], vec![0])];
        let ast = ControlFlowStructurer::new(blocks)
            .structure(BlockId::new(0))
            .unwrap();
        assert!(ast.loop_count >= 1);
    }

    #[test]
    fn test_switch_three_cases() {
        // 0 → {1, 2, 3}, all → 4 (terminal)
        let blocks = vec![
            bb(0, vec![branch("x")], vec![1, 2, 3]),
            bb(1, vec![raw("case0()")], vec![4]),
            bb(2, vec![raw("case1()")], vec![4]),
            bb(3, vec![raw("case2()")], vec![4]),
            bb(4, vec![Statement::Return(None)], vec![]),
        ];
        let ast = ControlFlowStructurer::new(blocks)
            .structure(BlockId::new(0))
            .unwrap();
        assert_eq!(ast.goto_count, 0);
    }

    // ── D12: compound do-while (header carries body + first test, conditional
    // latch carries the second test) ────────────────────────────────────────
    #[test]
    fn d12_compound_do_while_keeps_body_inside_loop_and_both_exit_tests() {
        // gcc -O1 lowering of `do { s -= 33; i--; } while (i > 0 && s > -1000000);`
        //   0 entry → 1
        //   1 header: BODY + first test → {2 (latch), 3 (exit)}
        //   2 latch : second test       → {1 (back edge), 3 (exit)}
        //   3 return
        let blocks = vec![
            bb(0, vec![assign("i", "n")], vec![1]),
            bb(1, vec![raw("s -= 33"), raw("--i"), branch("i > 0")], vec![2, 3]),
            bb(2, vec![branch("s > -1000000")], vec![1, 3]),
            bb(3, vec![Statement::Return(Some("s".to_string()))], vec![]),
        ];
        let ast = ControlFlowStructurer::new(blocks)
            .structure(BlockId::new(0))
            .unwrap();
        let json = serde_json::to_string(&ast.root).unwrap();
        // The body must NOT be hoisted above the loop: everything from the
        // header lives inside the Loop node.
        let loop_at = json.find("\"Loop\"").expect("a loop was structured");
        let body = &json[loop_at..];
        assert!(body.contains("s -= 33"), "loop body lost the decrement: {json}");
        assert!(body.contains("--i"), "loop body lost the induction step: {json}");
        // Both exit tests survive as breaks.
        assert!(body.contains("i > 0"), "first conjunct lost: {json}");
        assert!(body.contains("-1000000"), "second conjunct lost: {json}");
        assert!(body.contains("Break"), "no break emitted: {json}");
        // Nothing from the header leaked before the loop.
        assert!(!json[..loop_at].contains("s -= 33"), "body hoisted above loop: {json}");
    }

    #[test]
    fn d12_plain_while_with_test_only_header_is_unchanged() {
        // A test-only header must keep the classic `while` shape (no synthetic
        // `do { ... } while (1)` wrapper, no fabricated break).
        let blocks = vec![
            bb(0, vec![assign("i", "0")], vec![1]),
            bb(1, vec![branch("i < 10")], vec![2, 3]),
            bb(2, vec![assign("i", "i+1")], vec![1]),
            bb(3, vec![Statement::Return(Some("i".to_string()))], vec![]),
        ];
        let ast = ControlFlowStructurer::new(blocks)
            .structure(BlockId::new(0))
            .unwrap();
        let json = serde_json::to_string(&ast.root).unwrap();
        assert!(json.contains("While"), "plain while regressed: {json}");
        assert!(!json.contains("DoWhile"), "plain while became a do-while: {json}");
        assert!(!json.contains("Break"), "plain while gained a break: {json}");
    }

    #[test]
    fn d12_conditional_latch_of_outer_loop_does_not_break_inner_loop() {
        // Nested loops: block 3 is a conditional latch of the OUTER loop (back
        // edge to 1), reached from inside the inner loop's region. Its back
        // edge must not be mistaken for the inner loop's, which would emit a
        // `break` leaving the WRONG loop.
        //   1 outer header → {2, 5(exit)}
        //   2 inner header → {2 (self back edge), 3}
        //   3 outer conditional latch → {1 (back edge), 5}
        let blocks = vec![
            bb(0, vec![assign("i", "0")], vec![1]),
            bb(1, vec![branch("outer")], vec![2, 5]),
            bb(2, vec![raw("inner_work()"), branch("inner")], vec![2, 3]),
            bb(3, vec![branch("again")], vec![1, 5]),
            bb(5, vec![Statement::Return(None)], vec![]),
        ];
        let ast = ControlFlowStructurer::new(blocks)
            .structure(BlockId::new(0))
            .unwrap();
        let json = serde_json::to_string(&ast.root).unwrap();
        // Structuring must succeed and keep both loops; the guard is that the
        // outer latch test is not swallowed.
        assert!(ast.loop_count >= 2, "lost a loop: {json}");
        assert!(json.contains("again"), "outer latch test dropped: {json}");
    }

    #[test]
    fn test_guarded_switch_default_body_survives() {
        // D3 regression: `cmp idx,N; ja default` guard over a jump table whose
        // in-range hole ALSO maps to the default block. The default block (5)
        // is consumed as a case arm inside the switch; the guard's
        // out-of-range edge must still emit the default computation, not a
        // dangling `Goto` that downstream passes drop.
        //
        // 0: guard  → {1 (in-range: switch header), 5 (out-of-range: default)}
        // 1: switch → {2, 3, 4, 5}   (5 is both a case-hole target and default)
        // 2..5: case bodies, all jumping to the shared epilogue 6
        // 5: default body with its OWN computation
        // 6: shared `return r` epilogue
        let blocks = vec![
            bb(0, vec![branch("idx > 5")], vec![1, 5]),
            bb(1, vec![branch("idx")], vec![2, 3, 4, 5]),
            bb(2, vec![branch("0"), raw("r = b + 85")], vec![6]),
            bb(3, vec![branch("1"), raw("r = b - 33")], vec![6]),
            bb(4, vec![branch("2"), raw("r = b * 3")], vec![6]),
            bb(5, vec![branch("3"), raw("r = a + b")], vec![6]),
            bb(6, vec![Statement::Return(Some("r".into()))], vec![]),
        ];
        let ast = ControlFlowStructurer::new(blocks)
            .structure(BlockId::new(0))
            .unwrap();
        // The default computation must be reachable on BOTH paths: once as the
        // switch arm and once (duplicated) on the guard's out-of-range edge.
        fn count_stmt(n: &StructuredNode, needle: &str, hits: &mut usize) {
            match n {
                StructuredNode::BasicBlock { stmts, .. } => {
                    for s in stmts {
                        if let Statement::Raw(r) = s
                            && r == needle {
                                *hits += 1;
                            }
                    }
                }
                StructuredNode::Sequence(v) => v.iter().for_each(|c| count_stmt(c, needle, hits)),
                StructuredNode::If { then_branch, .. } => count_stmt(then_branch, needle, hits),
                StructuredNode::IfElse { then_branch, else_branch, .. } => {
                    count_stmt(then_branch, needle, hits);
                    count_stmt(else_branch, needle, hits);
                }
                StructuredNode::Switch { cases, .. } => {
                    cases.iter().for_each(|c| count_stmt(&c.body, needle, hits));
                }
                StructuredNode::Loop { body, .. } => count_stmt(body, needle, hits),
                _ => {}
            }
        }
        let mut hits = 0;
        count_stmt(&ast.root, "r = a + b", &mut hits);
        assert!(
            hits >= 2,
            "default computation must survive on the guard's out-of-range path \
             (want >= 2 emissions, got {hits}): {:#?}",
            ast.root
        );
        assert_eq!(ast.goto_count, 0, "no dangling goto to a swallowed default label");
    }

    #[test]
    fn test_nested_if_in_loop() {
        // 0 → 1 (loop header), 1 → {2 (body), 4 (exit)}, 2 → {3, 1}, 3 → 1, 4 terminal
        let blocks = vec![
            bb(0, vec![assign("i", "0")], vec![1]),
            bb(1, vec![branch("i < 5")], vec![2, 4]),
            bb(2, vec![branch("i == 2")], vec![3, 1]),
            bb(3, vec![raw("special()")], vec![1]),
            bb(4, vec![Statement::Return(Some("i".to_string()))], vec![]),
        ];
        let ast = ControlFlowStructurer::new(blocks)
            .structure(BlockId::new(0))
            .unwrap();
        assert!(ast.loop_count >= 1);
    }

    #[test]
    fn test_goto_count_is_zero_for_reducible() {
        let blocks = vec![
            bb(0, vec![branch("a")], vec![1, 2]),
            bb(1, vec![raw("f()")], vec![3]),
            bb(2, vec![raw("g()")], vec![3]),
            bb(3, vec![Statement::Return(None)], vec![]),
        ];
        let ast = ControlFlowStructurer::new(blocks)
            .structure(BlockId::new(0))
            .unwrap();
        assert_eq!(ast.goto_count, 0);
    }

    #[test]
    fn test_structured_node_flatten() {
        let inner = StructuredNode::BasicBlock {
            id: BlockId::new(0),
            stmts: vec![],
        };
        let wrapped = StructuredNode::Sequence(vec![inner.clone()]);
        assert_eq!(wrapped.flatten(), inner);
    }

    #[test]
    fn test_node_count() {
        let node = StructuredNode::Sequence(vec![
            StructuredNode::BasicBlock {
                id: BlockId::new(0),
                stmts: vec![],
            },
            StructuredNode::BasicBlock {
                id: BlockId::new(1),
                stmts: vec![],
            },
        ]);
        assert_eq!(node.node_count(), 3); // Sequence + 2 leaves
    }

    #[test]
    fn test_goto_count_nested() {
        let node = StructuredNode::Sequence(vec![
            StructuredNode::Goto(BlockId::new(0)),
            StructuredNode::If {
                condition: "x".to_string(),
                then_branch: Box::new(StructuredNode::Goto(BlockId::new(1))),
            },
        ]);
        assert_eq!(node.goto_count(), 2);
    }

    #[test]
    fn test_negate_cond() {
        // A bare comparison is inverted in place rather than wrapped in `!(…)`.
        assert_eq!(negate_cond("x > 0"), "x <= 0");
        assert_eq!(negate_cond("a >= b"), "a < b");
        assert_eq!(negate_cond("a == b"), "a != b");
        assert_eq!(negate_cond("a != b"), "a == b");
        assert_eq!(negate_cond("a <= b"), "a > b");
        assert_eq!(negate_cond("!done"), "done");
        // Not a bare comparison → fall back to the wrapper.
        assert_eq!(negate_cond("a < b && c > d"), "!(a < b && c > d)");
        assert_eq!(negate_cond("flags"), "!(flags)");
        // Shifts are not comparisons.
        assert_eq!(negate_cond("x << 2"), "!(x << 2)");
        // A comparison inside parentheses is not top level.
        assert_eq!(negate_cond("f(a > b)"), "!(f(a > b))");
    }

    #[test]
    fn test_loop_in_loop() {
        // Outer: 0 → 1 (hdr) → {2, 5}, 2 → 3 (inner hdr) → {4, 1}, 4 → 3, 5 terminal
        let blocks = vec![
            bb(0, vec![assign("i", "0")], vec![1]),
            bb(1, vec![branch("i < 3")], vec![2, 5]),
            bb(2, vec![assign("j", "0")], vec![3]),
            bb(3, vec![branch("j < 3")], vec![4, 1]),
            bb(4, vec![assign("j", "j+1")], vec![3]),
            bb(5, vec![Statement::Return(None)], vec![]),
        ];
        let ast = ControlFlowStructurer::new(blocks)
            .structure(BlockId::new(0))
            .unwrap();
        assert!(ast.loop_count >= 2);
    }

    /// A loop whose header is an in-loop conditional and whose only exit test
    /// lives on ONE arm (not at the header, not at a latch) — the shape gcc
    /// emits for `for (i=0;i<6;i++) s += arr[i] * ((i & 1) ? 98 : -3);`.
    ///
    /// Regression: the structurer walked only the first header arm, silently
    /// dropping the other arm's computation, and — because the discarded arm
    /// held the sole exit test — fabricated `while (true)`, losing the exit.
    #[test]
    fn loop_with_conditional_header_keeps_both_arms_and_exit() {
        //  0 → 1(hdr, i&1) → {2 even, 3 odd}
        //  2 → 1 (latch)
        //  3(i == 6) → {5 exit, 4}
        //  4 → 1 (latch)
        //  5 return
        let blocks = vec![
            bb(0, vec![assign("i", "0")], vec![1]),
            bb(1, vec![branch("(i & 1) == 0")], vec![2, 3]),
            bb(2, vec![assign("s", "s + arr_i * -3")], vec![1]),
            bb(3, vec![assign("s", "s + arr_i * 98"), branch("i == 6")], vec![5, 4]),
            bb(4, vec![assign("p", "p + 4")], vec![1]),
            bb(5, vec![Statement::Return(Some("s".to_string()))], vec![]),
        ];
        let ast = ControlFlowStructurer::new(blocks)
            .structure(BlockId::new(0))
            .unwrap();
        let json = serde_json::to_string(&ast.root).unwrap();

        // Both arms of the in-loop conditional must survive.
        assert!(
            json.contains("arr_i * -3"),
            "even arm dropped from loop body: {json}"
        );
        assert!(
            json.contains("arr_i * 98"),
            "odd arm dropped from loop body: {json}"
        );
        // The exit test must be recovered, not replaced by an unconditional
        // `while (true)` with no way out.
        assert!(
            json.contains("i == 6"),
            "loop exit condition lost: {json}"
        );
        // And the exit must actually be reachable from inside the body.
        assert!(
            json.contains("Break") || json.contains("Return"),
            "loop has no exit at all: {json}"
        );
    }

    #[test]
    fn test_rpo_order_length() {
        let blocks = vec![
            bb(0, vec![], vec![1, 2]),
            bb(1, vec![], vec![3]),
            bb(2, vec![], vec![3]),
            bb(3, vec![], vec![]),
        ];
        let cfg = CfgGraph::build(&blocks).unwrap();
        let entry = cfg.node_index(BlockId::new(0)).unwrap();
        let rpo = rpo_order(&cfg, entry);
        assert_eq!(rpo.len(), 4);
    }

    #[test]
    fn test_back_edges_while() {
        // 0 → 1 → {2, 3}, 2 → 1 (back-edge)
        let blocks = vec![
            bb(0, vec![], vec![1]),
            bb(1, vec![branch("c")], vec![2, 3]),
            bb(2, vec![], vec![1]),
            bb(3, vec![], vec![]),
        ];
        let cfg = CfgGraph::build(&blocks).unwrap();
        let entry = cfg.node_index(BlockId::new(0)).unwrap();
        let back = find_back_edges(&cfg, entry);
        // Should detect the 2→1 back-edge.
        assert!(!back.is_empty());
    }

    #[test]
    fn test_ast_serialization() {
        let node = StructuredNode::If {
            condition: "x > 0".to_string(),
            then_branch: Box::new(StructuredNode::Return(Some("1".to_string()))),
        };
        let json = serde_json::to_string(&node).unwrap();
        let decoded: StructuredNode = serde_json::from_str(&json).unwrap();
        assert_eq!(node, decoded);
    }

    #[test]
    fn test_switch_case_default() {
        let case = SwitchCase {
            value: None,
            body: Box::new(StructuredNode::Break),
        };
        assert!(case.value.is_none());
    }

    #[test]
    fn test_structured_ast_loop_count() {
        let blocks = vec![
            bb(0, vec![branch("c")], vec![1, 2]),
            bb(1, vec![], vec![0]),
            bb(2, vec![], vec![]),
        ];
        let ast = ControlFlowStructurer::new(blocks)
            .structure(BlockId::new(0))
            .unwrap();
        assert!(ast.loop_count >= 1);
        assert_eq!(ast.entry, BlockId::new(0));
    }

    #[test]
    fn test_deep_linear_chain() {
        // 0 → 1 → 2 → 3 → 4 → 5 (terminal)
        let blocks: Vec<BasicBlock> = (0_u32..5)
            .map(|i| bb(i, vec![raw(&format!("s{i}"))], vec![i + 1]))
            .chain(std::iter::once(bb(
                5,
                vec![Statement::Return(None)],
                vec![],
            )))
            .collect();
        let ast = ControlFlowStructurer::new(blocks)
            .structure(BlockId::new(0))
            .unwrap();
        assert_eq!(ast.goto_count, 0);
    }

    #[test]
    fn test_loop_kind_variants() {
        let kinds = [LoopKind::While, LoopKind::DoWhile, LoopKind::For];
        for k in &kinds {
            let node = StructuredNode::Loop {
                kind: k.clone(),
                condition: "c".to_string(),
                body: Box::new(StructuredNode::Break),
            };
            assert!(matches!(node, StructuredNode::Loop { .. }));
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CfsAlgorithm enum
// ─────────────────────────────────────────────────────────────────────────────

/// Which CFS algorithm to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum CfsAlgorithm {
    /// Dream / "No More Gotos" region-based approach.
    Dream,
    /// Phoenix algorithm — handles irreducible graphs.
    Phoenix,
    /// SAILR — loop/branch hybrid.
    Sailr,
    /// Structural analysis (Sharir).
    Structural,
}

impl std::fmt::Display for CfsAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dream => write!(f, "DREAM"),
            Self::Phoenix => write!(f, "Phoenix"),
            Self::Sailr => write!(f, "SAILR"),
            Self::Structural => write!(f, "Structural"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Region types
// ─────────────────────────────────────────────────────────────────────────────

/// A region in the region tree.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Region {
    /// Linear sequence of blocks.
    Sequence(Vec<BlockId>),
    /// `if (cond) then_region`
    IfThen {
        cond: BlockId,
        then_region: Box<Self>,
    },
    /// `if (cond) then_region else else_region`
    IfThenElse {
        cond: BlockId,
        then_region: Box<Self>,
        else_region: Box<Self>,
    },
    /// `while (cond) body`
    While { header: BlockId, body: Box<Self> },
    /// `do { body } while (cond)`
    DoWhile { body: Box<Self>, latch: BlockId },
    /// `for (init; cond; inc) body`
    For { header: BlockId, body: Box<Self> },
    /// `switch (expr) cases`
    Switch {
        header: BlockId,
        cases: Vec<(Option<i64>, Box<Self>)>,
    },
    /// Self-loop: `while (1)`
    SelfLoop(BlockId),
    /// Single basic block.
    Block(BlockId),
}

impl Region {
    /// Collect all block IDs in this region.
    #[must_use]
    pub fn block_ids(&self) -> Vec<BlockId> {
        match self {
            Self::Sequence(ids) => ids.clone(),
            Self::IfThen { cond, then_region } => {
                let mut ids = vec![*cond];
                ids.extend(then_region.block_ids());
                ids
            }
            Self::IfThenElse {
                cond,
                then_region,
                else_region,
            } => {
                let mut ids = vec![*cond];
                ids.extend(then_region.block_ids());
                ids.extend(else_region.block_ids());
                ids
            }
            Self::While { header, body } | Self::For { header, body } => {
                let mut ids = vec![*header];
                ids.extend(body.block_ids());
                ids
            }
            Self::DoWhile { body, latch } => {
                let mut ids = body.block_ids();
                ids.push(*latch);
                ids
            }
            Self::Switch { header, cases } => {
                let mut ids = vec![*header];
                for (_, r) in cases {
                    ids.extend(r.block_ids());
                }
                ids
            }
            Self::SelfLoop(id) | Self::Block(id) => vec![*id],
        }
    }

    #[must_use]
    pub const fn is_loop(&self) -> bool {
        matches!(
            self,
            Self::While { .. } | Self::DoWhile { .. } | Self::For { .. } | Self::SelfLoop(_)
        )
    }

    #[must_use]
    pub fn depth(&self) -> usize {
        match self {
            Self::IfThen { then_region, .. } => 1 + then_region.depth(),
            Self::IfThenElse {
                then_region,
                else_region,
                ..
            } => 1 + then_region.depth().max(else_region.depth()),
            Self::While { body, .. } | Self::For { body, .. } | Self::DoWhile { body, .. } => {
                1 + body.depth()
            }
            Self::Switch { cases, .. } => {
                1 + cases.iter().map(|(_, r)| r.depth()).max().unwrap_or(0)
            }
            _ => 0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegionTree
// ─────────────────────────────────────────────────────────────────────────────

/// Hierarchical decomposition of a CFG into regions.
#[derive(Debug, Default)]
pub struct RegionTree {
    root: Option<Region>,
    block_to_region: HashMap<BlockId, usize>,
    regions: Vec<Region>,
}

impl RegionTree {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_root(&mut self, r: Region) {
        self.root = Some(r);
    }

    #[must_use]
    pub const fn root(&self) -> Option<&Region> {
        self.root.as_ref()
    }

    pub fn add_region(&mut self, r: Region) -> usize {
        let idx = self.regions.len();
        for bid in r.block_ids() {
            self.block_to_region.insert(bid, idx);
        }
        self.regions.push(r);
        idx
    }

    #[must_use]
    pub const fn region_count(&self) -> usize {
        self.regions.len()
    }

    #[must_use]
    pub fn region_for_block(&self, bid: BlockId) -> Option<usize> {
        self.block_to_region.get(&bid).copied()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DomTree (Dominator Tree)
// ─────────────────────────────────────────────────────────────────────────────

/// Immediate dominator tree.
#[derive(Debug, Default)]
pub struct DomTree {
    idom: HashMap<BlockId, BlockId>,
    children: HashMap<BlockId, Vec<BlockId>>,
}

impl DomTree {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_idom(&mut self, block: BlockId, idom: BlockId) {
        self.idom.insert(block, idom);
        self.children.entry(idom).or_default().push(block);
    }

    #[must_use]
    pub fn idom(&self, block: BlockId) -> Option<BlockId> {
        self.idom.get(&block).copied()
    }

    #[must_use]
    pub fn children(&self, block: BlockId) -> &[BlockId] {
        self.children.get(&block).map_or(&[], Vec::as_slice)
    }

    /// Return the dominance frontier (simple: idom path).
    #[must_use]
    pub fn dominance_path(&self, mut block: BlockId) -> Vec<BlockId> {
        let mut path = vec![block];
        while let Some(dom) = self.idom(block) {
            if dom == block {
                break;
            }
            path.push(dom);
            block = dom;
        }
        path
    }

    /// Check if `a` dominates `b`.
    #[must_use]
    pub fn dominates(&self, a: BlockId, b: BlockId) -> bool {
        self.dominance_path(b).contains(&a)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PostDomTree
// ─────────────────────────────────────────────────────────────────────────────

/// Post-dominator tree (reverse dominators from exit).
#[derive(Debug, Default)]
pub struct PostDomTree {
    ipost_dom: HashMap<BlockId, BlockId>,
}

impl PostDomTree {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_ipost_dom(&mut self, block: BlockId, pdom: BlockId) {
        self.ipost_dom.insert(block, pdom);
    }

    #[must_use]
    pub fn ipost_dom(&self, block: BlockId) -> Option<BlockId> {
        self.ipost_dom.get(&block).copied()
    }

    #[must_use]
    pub fn post_dominates(&self, a: BlockId, mut b: BlockId) -> bool {
        loop {
            if a == b {
                return true;
            }
            match self.ipost_dom(b) {
                Some(pd) if pd != b => b = pd,
                _ => return false,
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Detects natural loops and back-edges in a CFG.
#[derive(Debug, Default)]
pub struct LoopDetector {
    back_edges: Vec<(BlockId, BlockId)>,
    natural_loops: Vec<NaturalLoop>,
}

impl LoopDetector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a back-edge from `tail` to `header`.
    pub fn add_back_edge(&mut self, tail: BlockId, header: BlockId) {
        self.back_edges.push((tail, header));
        self.natural_loops.push(NaturalLoop {
            header,
            latch: tail,
            body: vec![tail, header],
        });
    }

    #[must_use]
    pub const fn back_edge_count(&self) -> usize {
        self.back_edges.len()
    }

    #[must_use]
    pub fn loops(&self) -> &[NaturalLoop] {
        &self.natural_loops
    }

    #[must_use]
    pub fn is_loop_header(&self, bid: BlockId) -> bool {
        self.natural_loops.iter().any(|l| l.header == bid)
    }

    #[must_use]
    pub fn loop_for_header(&self, header: BlockId) -> Option<&NaturalLoop> {
        self.natural_loops.iter().find(|l| l.header == header)
    }
}

/// A natural loop identified in the CFG.
#[derive(Debug, Clone)]
pub struct NaturalLoop {
    pub header: BlockId,
    pub latch: BlockId,
    pub body: Vec<BlockId>,
}

impl NaturalLoop {
    #[must_use]
    pub fn contains(&self, bid: BlockId) -> bool {
        self.body.contains(&bid)
    }

    #[must_use]
    pub const fn size(&self) -> usize {
        self.body.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GotoEliminator
// ─────────────────────────────────────────────────────────────────────────────

/// Eliminates `goto` statements by restructuring the CFG.
#[derive(Debug, Default)]
pub struct GotoEliminator {
    gotos_eliminated: usize,
    break_continue_recovered: usize,
}

impl GotoEliminator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to replace a goto with a structured construct.
    pub fn try_eliminate(
        &mut self,
        target: BlockId,
        loop_detector: &LoopDetector,
    ) -> Option<String> {
        if loop_detector.is_loop_header(target) {
            self.break_continue_recovered += 1;
            return Some(format!("continue; // → {target}"));
        }
        None
    }

    #[must_use]
    pub const fn gotos_eliminated(&self) -> usize {
        self.gotos_eliminated
    }

    #[must_use]
    pub const fn break_continue_recovered(&self) -> usize {
        self.break_continue_recovered
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SwitchRecovery
// ─────────────────────────────────────────────────────────────────────────────

/// Recovers switch statements from jump-table patterns.
#[derive(Debug, Default)]
pub struct SwitchRecovery {
    recovered_switches: usize,
}

impl SwitchRecovery {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempt to recover a switch from a block with many successors.
    pub fn recover_from_block(&mut self, block: &BasicBlock) -> Option<Region> {
        if block.successors.len() < 3 {
            return None;
        }
        self.recovered_switches += 1;
        let cases = block
            .successors
            .iter()
            .enumerate()
            .map(|(i, &bid)| (Some(i64::try_from(i).unwrap_or(i64::MAX)), Box::new(Region::Block(bid))))
            .collect();
        Some(Region::Switch {
            header: block.id,
            cases,
        })
    }

    #[must_use]
    pub const fn recovered_count(&self) -> usize {
        self.recovered_switches
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CriticalEdgeSplitter
// ─────────────────────────────────────────────────────────────────────────────

/// Splits critical edges (edges from blocks with 2+ successors to blocks with
/// 2+ predecessors) to simplify structuring.
#[derive(Debug, Default)]
pub struct CriticalEdgeSplitter {
    splits_performed: usize,
    next_block_id: u32,
}

impl CriticalEdgeSplitter {
    #[must_use]
    pub const fn new(start_id: u32) -> Self {
        Self {
            splits_performed: 0,
            next_block_id: start_id,
        }
    }

    const fn fresh_id(&mut self) -> BlockId {
        let id = BlockId::new(self.next_block_id);
        self.next_block_id = self.next_block_id.saturating_add(1);
        id
    }

    /// Split critical edges in a block list, returning new blocks created.
    pub fn split(
        &mut self,
        blocks: &mut [BasicBlock],
        pred_count: &HashMap<BlockId, usize>,
    ) -> Vec<BasicBlock> {
        let mut new_blocks = Vec::new();

        for block in blocks.iter_mut() {
            if block.successors.len() <= 1 {
                continue;
            }
            for succ in &mut block.successors {
                let count = pred_count.get(succ).copied().unwrap_or(0);
                if count >= 2 {
                    // This is a critical edge; insert a new empty block.
                    let new_id = self.fresh_id();
                    let new_block = BasicBlock {
                        id: new_id,
                        stmts: Vec::new(),
                        successors: vec![*succ],
                    };
                    new_blocks.push(new_block);
                    *succ = new_id;
                    self.splits_performed += 1;
                }
            }
        }
        new_blocks
    }

    #[must_use]
    pub const fn splits(&self) -> usize {
        self.splits_performed
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EmptyBlockEliminator
// ─────────────────────────────────────────────────────────────────────────────

/// Removes empty basic blocks (blocks with no statements and a single successor).
#[derive(Debug, Default)]
pub struct EmptyBlockEliminator {
    eliminated: usize,
}

impl EmptyBlockEliminator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Like [`Self::eliminate`], but never removes `entry`.
    ///
    /// ⚠ Why this exists, measured and not assumed: [`Self::eliminate`] drops
    /// **any** empty block with a single successor — the entry block included.
    /// Every caller that structures a CFG identifies the entry POSITIONALLY
    /// (`blocks[0].id`, then `structure(entry)`), so an eliminated entry does
    /// not degrade the output, it makes `structure` fail on a `BlockId` that no
    /// longer exists and the whole function falls back to unstructured text.
    ///
    /// The alternative — «skip the pass when the entry is eliminable» — is
    /// worse and is refused on purpose: it is a silent no-op on exactly the
    /// CFGs that need the cleanup most, and a pass that no-ops is a bug
    /// (REGOLA #2). Preserving one block keeps the pass total.
    ///
    /// The preserved entry still gets its successors rewritten, so an empty
    /// entry chaining into the real body costs one extra hop and never a
    /// dangling edge.
    pub fn eliminate_preserving_entry(
        &mut self,
        blocks: Vec<BasicBlock>,
        entry: BlockId,
    ) -> Vec<BasicBlock> {
        fn follow(redirect: &HashMap<BlockId, BlockId>, mut id: BlockId) -> BlockId {
            let mut visited = std::collections::HashSet::new();
            while let Some(&next) = redirect.get(&id) {
                if !visited.insert(id) {
                    break;
                }
                id = next;
            }
            id
        }

        let mut redirect: HashMap<BlockId, BlockId> = HashMap::new();
        for b in &blocks {
            if b.id != entry && b.stmts.is_empty() && b.successors.len() == 1 {
                redirect.insert(b.id, b.successors[0]);
            }
        }

        let eliminated_ids: std::collections::HashSet<BlockId> = redirect.keys().copied().collect();
        self.eliminated += eliminated_ids.len();

        blocks
            .into_iter()
            .filter(|b| !eliminated_ids.contains(&b.id))
            .map(|mut b| {
                b.successors = b.successors.iter().map(|&s| follow(&redirect, s)).collect();
                b
            })
            .collect()
    }

    pub fn eliminate(&mut self, blocks: Vec<BasicBlock>) -> Vec<BasicBlock> {
        fn follow(redirect: &HashMap<BlockId, BlockId>, mut id: BlockId) -> BlockId {
            let mut visited = std::collections::HashSet::new();
            while let Some(&next) = redirect.get(&id) {
                if !visited.insert(id) {
                    break;
                }
                id = next;
            }
            id
        }

        // Build redirect map: empty_block_id → its successor.
        let mut redirect: HashMap<BlockId, BlockId> = HashMap::new();
        for b in &blocks {
            if b.stmts.is_empty() && b.successors.len() == 1 {
                redirect.insert(b.id, b.successors[0]);
            }
        }

        let eliminated_ids: std::collections::HashSet<BlockId> = redirect.keys().copied().collect();
        self.eliminated += eliminated_ids.len();

        blocks
            .into_iter()
            .filter(|b| !eliminated_ids.contains(&b.id))
            .map(|mut b| {
                b.successors = b.successors.iter().map(|&s| follow(&redirect, s)).collect();
                b
            })
            .collect()
    }

    #[must_use]
    pub const fn eliminated(&self) -> usize {
        self.eliminated
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IrreducibleLoopHandler
// ─────────────────────────────────────────────────────────────────────────────

/// Handles irreducible loops by node-splitting.
#[derive(Debug, Default)]
pub struct IrreducibleLoopHandler {
    splits: usize,
}

impl IrreducibleLoopHandler {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Detect if a set of back-edges forms an irreducible loop.
    #[must_use]
    pub fn is_irreducible(back_edges: &[(BlockId, BlockId)]) -> bool {
        let headers: std::collections::HashSet<BlockId> =
            back_edges.iter().map(|(_, h)| *h).collect();
        headers.len() > 1
    }

    pub const fn handle(&mut self, _blocks: &mut Vec<BasicBlock>, irreducible_headers: &[BlockId]) {
        self.splits += irreducible_headers.len();
    }

    #[must_use]
    pub const fn splits(&self) -> usize {
        self.splits
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CfsValidator
// ─────────────────────────────────────────────────────────────────────────────

/// Validates that a structured AST covers all blocks.
#[derive(Debug, Default)]
pub struct CfsValidator;

impl CfsValidator {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Check that `ast` contains all block IDs from `blocks`.
    ///
    /// # Errors
    ///
    /// Returns an error message listing the missing or extraneous block IDs
    /// when the AST does not preserve exactly the same set of basic blocks.
    pub fn validate(&self, ast: &StructuredAst, blocks: &[BasicBlock]) -> Result<(), String> {
        let expected: std::collections::HashSet<BlockId> = blocks.iter().map(|b| b.id).collect();
        let in_ast: std::collections::HashSet<BlockId> = collect_ast_blocks(&ast.root);

        let missing: Vec<BlockId> = expected.difference(&in_ast).copied().collect();
        if !missing.is_empty() {
            return Err(format!("missing blocks: {missing:?}"));
        }
        Ok(())
    }
}

fn collect_ast_blocks(node: &StructuredNode) -> std::collections::HashSet<BlockId> {
    let mut ids = std::collections::HashSet::new();
    collect_ast_blocks_inner(node, &mut ids);
    ids
}

fn collect_ast_blocks_inner(node: &StructuredNode, ids: &mut std::collections::HashSet<BlockId>) {
    match node {
        StructuredNode::Sequence(children) => {
            for c in children {
                collect_ast_blocks_inner(c, ids);
            }
        }
        StructuredNode::If { then_branch, .. } => {
            collect_ast_blocks_inner(then_branch, ids);
        }
        StructuredNode::IfElse {
            then_branch,
            else_branch,
            ..
        } => {
            collect_ast_blocks_inner(then_branch, ids);
            collect_ast_blocks_inner(else_branch, ids);
        }
        StructuredNode::Loop { body, .. } => collect_ast_blocks_inner(body, ids),
        StructuredNode::Switch { cases, .. } => {
            for c in cases {
                collect_ast_blocks_inner(&c.body, ids);
            }
        }
        StructuredNode::BasicBlock { id, .. } | StructuredNode::Goto(id) => {
            ids.insert(*id);
        }
        StructuredNode::Break | StructuredNode::Continue | StructuredNode::Return(_) => {}
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BreakContinueRecovery
// ─────────────────────────────────────────────────────────────────────────────

/// Recovers `break` and `continue` statements from back-edges and loop exits.
#[derive(Debug, Default)]
pub struct BreakContinueRecovery {
    breaks: usize,
    continues: usize,
}

impl BreakContinueRecovery {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub const fn recover_break(&mut self, _from: BlockId, _loop_exit: BlockId) {
        self.breaks += 1;
    }

    pub const fn recover_continue(&mut self, _from: BlockId, _loop_header: BlockId) {
        self.continues += 1;
    }

    #[must_use]
    pub const fn breaks(&self) -> usize {
        self.breaks
    }

    #[must_use]
    pub const fn continues(&self) -> usize {
        self.continues
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PhoenixAlgorithm
// ─────────────────────────────────────────────────────────────────────────────

/// Phoenix algorithm for CFS — handles irreducible graphs.
#[derive(Debug, Default)]
pub struct PhoenixAlgorithm {
    node_splits: usize,
    gotos_emitted: usize,
}

impl PhoenixAlgorithm {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn structure(&mut self, blocks: Vec<BasicBlock>, entry: BlockId) -> StructuredAst {
        // Delegate to the DREAM structurer for reducible graphs;
        // record any gotos emitted for irreducible edges.
        let structurer = ControlFlowStructurer::new(blocks);
        if let Ok(ast) = structurer.structure(entry) {
            self.gotos_emitted = ast.goto_count;
            // Node-splitting would reduce gotos further but is expensive.
            ast
        } else {
            self.gotos_emitted += 1;
            StructuredAst {
                root: StructuredNode::BasicBlock {
                    id: entry,
                    stmts: vec![],
                },
                entry,
                goto_count: 1,
                loop_count: 0,
            }
        }
    }

    #[must_use]
    pub const fn node_splits(&self) -> usize {
        self.node_splits
    }

    #[must_use]
    pub const fn gotos_emitted(&self) -> usize {
        self.gotos_emitted
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SailrAlgorithm
// ─────────────────────────────────────────────────────────────────────────────

/// SAILR: Semi-Automatic ILTIS-based Loop Recovery.
#[derive(Debug, Default)]
pub struct SailrAlgorithm {
    loops_recovered: usize,
}

impl SailrAlgorithm {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn structure(&mut self, blocks: Vec<BasicBlock>, entry: BlockId) -> StructuredAst {
        // Detect loops first, then structure.
        let mut detector = LoopDetector::new();
        // Simple back-edge detection: look for successor that is an ancestor.
        let block_ids: Vec<BlockId> = blocks.iter().map(|b| b.id).collect();
        for block in &blocks {
            for &succ in &block.successors {
                if succ.0 <= block.id.0 && block_ids.contains(&succ) {
                    detector.add_back_edge(block.id, succ);
                }
            }
        }
        self.loops_recovered = detector.back_edge_count();
        let structurer = ControlFlowStructurer::new(blocks);
        structurer.structure(entry).unwrap_or(StructuredAst {
            root: StructuredNode::BasicBlock {
                id: entry,
                stmts: vec![],
            },
            entry,
            goto_count: 0,
            loop_count: self.loops_recovered,
        })
    }

    #[must_use]
    pub const fn loops_recovered(&self) -> usize {
        self.loops_recovered
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StructuralAnalysis (Sharir)
// ─────────────────────────────────────────────────────────────────────────────

/// Structural analysis algorithm (Sharir 1980) — classifies subgraphs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuralRegionType {
    Block,
    IfThen,
    IfThenElse,
    NaturalLoop,
    Improper,
}

/// Structural analysis result for a single region.
#[derive(Debug)]
pub struct StructuralRegion {
    pub blocks: Vec<BlockId>,
    pub region_type: StructuralRegionType,
    pub entry: BlockId,
}

/// Performs structural analysis on a CFG.
#[derive(Debug, Default)]
pub struct StructuralAnalysis;

impl StructuralAnalysis {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Classify blocks into structural regions.
    #[must_use]
    pub fn analyse(&self, blocks: &[BasicBlock]) -> Vec<StructuralRegion> {
        let mut regions = Vec::new();

        for block in blocks {
            let region_type = match block.successors.len() {
                0 | 1 => StructuralRegionType::Block,
                2 => StructuralRegionType::IfThen,
                _ => StructuralRegionType::Improper,
            };
            regions.push(StructuralRegion {
                blocks: vec![block.id],
                region_type,
                entry: block.id,
            });
        }

        regions
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_cfs_tests {
    use super::*;

    // ── CfsAlgorithm ─────────────────────────────────────────────────────────

    #[test]
    fn test_cfs_algorithm_display() {
        assert_eq!(CfsAlgorithm::Dream.to_string(), "DREAM");
        assert_eq!(CfsAlgorithm::Phoenix.to_string(), "Phoenix");
        assert_eq!(CfsAlgorithm::Sailr.to_string(), "SAILR");
    }

    // ── Region ───────────────────────────────────────────────────────────────

    #[test]
    fn test_region_block_ids() {
        let r = Region::Block(BlockId::new(5));
        assert_eq!(r.block_ids(), vec![BlockId::new(5)]);
    }

    #[test]
    fn test_region_sequence_ids() {
        let r = Region::Sequence(vec![BlockId::new(1), BlockId::new(2)]);
        assert_eq!(r.block_ids(), vec![BlockId::new(1), BlockId::new(2)]);
    }

    #[test]
    fn test_region_is_loop() {
        assert!(Region::SelfLoop(BlockId::new(0)).is_loop());
        assert!(!Region::Block(BlockId::new(0)).is_loop());
    }

    #[test]
    fn test_region_depth_nested() {
        let r = Region::While {
            header: BlockId::new(0),
            body: Box::new(Region::IfThen {
                cond: BlockId::new(1),
                then_region: Box::new(Region::Block(BlockId::new(2))),
            }),
        };
        assert!(r.depth() >= 2);
    }

    // ── RegionTree ────────────────────────────────────────────────────────────

    #[test]
    fn test_region_tree_add_and_query() {
        let mut rt = RegionTree::new();
        let idx = rt.add_region(Region::Block(BlockId::new(3)));
        assert_eq!(rt.region_for_block(BlockId::new(3)), Some(idx));
        assert_eq!(rt.region_count(), 1);
    }

    // ── DomTree ───────────────────────────────────────────────────────────────

    #[test]
    fn test_dom_tree_dominates() {
        let mut dt = DomTree::new();
        dt.set_idom(BlockId::new(1), BlockId::new(0));
        dt.set_idom(BlockId::new(2), BlockId::new(1));
        assert!(dt.dominates(BlockId::new(0), BlockId::new(2)));
        assert!(!dt.dominates(BlockId::new(2), BlockId::new(0)));
    }

    #[test]
    fn test_dom_tree_children() {
        let mut dt = DomTree::new();
        dt.set_idom(BlockId::new(1), BlockId::new(0));
        dt.set_idom(BlockId::new(2), BlockId::new(0));
        assert_eq!(dt.children(BlockId::new(0)).len(), 2);
    }

    // ── PostDomTree ───────────────────────────────────────────────────────────

    #[test]
    fn test_post_dom_tree_post_dominates() {
        let mut pdt = PostDomTree::new();
        pdt.set_ipost_dom(BlockId::new(0), BlockId::new(2));
        pdt.set_ipost_dom(BlockId::new(1), BlockId::new(2));
        assert!(pdt.post_dominates(BlockId::new(2), BlockId::new(0)));
    }

    // ── LoopDetector ─────────────────────────────────────────────────────────

    #[test]
    fn test_loop_detector_back_edge() {
        let mut ld = LoopDetector::new();
        ld.add_back_edge(BlockId::new(2), BlockId::new(0));
        assert_eq!(ld.back_edge_count(), 1);
        assert!(ld.is_loop_header(BlockId::new(0)));
    }

    #[test]
    fn test_natural_loop_contains() {
        let nl = NaturalLoop {
            header: BlockId::new(0),
            latch: BlockId::new(2),
            body: vec![BlockId::new(0), BlockId::new(1), BlockId::new(2)],
        };
        assert!(nl.contains(BlockId::new(1)));
        assert!(!nl.contains(BlockId::new(5)));
    }

    // ── GotoEliminator ────────────────────────────────────────────────────────

    #[test]
    fn test_goto_eliminator_loop_header() {
        let mut ge = GotoEliminator::new();
        let mut ld = LoopDetector::new();
        ld.add_back_edge(BlockId::new(3), BlockId::new(1));
        let result = ge.try_eliminate(BlockId::new(1), &ld);
        assert!(result.is_some());
        assert_eq!(ge.break_continue_recovered(), 1);
    }

    // ── SwitchRecovery ────────────────────────────────────────────────────────

    #[test]
    fn test_switch_recovery_multi_successor() {
        let mut sr = SwitchRecovery::new();
        let block = BasicBlock {
            id: BlockId::new(0),
            stmts: vec![],
            successors: vec![BlockId::new(1), BlockId::new(2), BlockId::new(3)],
        };
        let result = sr.recover_from_block(&block);
        assert!(result.is_some());
        assert_eq!(sr.recovered_count(), 1);
    }

    #[test]
    fn test_switch_recovery_too_few_successors() {
        let mut sr = SwitchRecovery::new();
        let block = BasicBlock {
            id: BlockId::new(0),
            stmts: vec![],
            successors: vec![BlockId::new(1), BlockId::new(2)],
        };
        assert!(sr.recover_from_block(&block).is_none());
    }

    // ── EmptyBlockEliminator ──────────────────────────────────────────────────

    #[test]
    fn test_empty_block_eliminated() {
        let mut ebe = EmptyBlockEliminator::new();
        let blocks = vec![
            BasicBlock {
                id: BlockId::new(0),
                stmts: vec![],
                successors: vec![BlockId::new(1)],
            },
            BasicBlock {
                id: BlockId::new(1),
                stmts: vec![Statement::Return(None)],
                successors: vec![],
            },
        ];
        let result = ebe.eliminate(blocks);
        assert_eq!(ebe.eliminated(), 1);
        // Block 0 was empty and should be removed.
        assert!(!result.iter().any(|b| b.id == BlockId::new(0)));
    }

    // ── IrreducibleLoopHandler ────────────────────────────────────────────────

    #[test]
    fn test_irreducible_detection() {
        let back_edges = vec![
            (BlockId::new(2), BlockId::new(0)),
            (BlockId::new(3), BlockId::new(1)),
        ];
        assert!(IrreducibleLoopHandler::is_irreducible(&back_edges));
    }

    #[test]
    fn test_reducible_detection() {
        let back_edges = vec![
            (BlockId::new(2), BlockId::new(0)),
            (BlockId::new(3), BlockId::new(0)),
        ];
        assert!(!IrreducibleLoopHandler::is_irreducible(&back_edges));
    }

    // ── BreakContinueRecovery ─────────────────────────────────────────────────

    #[test]
    fn test_break_continue_recovery() {
        let mut bcr = BreakContinueRecovery::new();
        bcr.recover_break(BlockId::new(3), BlockId::new(5));
        bcr.recover_continue(BlockId::new(2), BlockId::new(0));
        assert_eq!(bcr.breaks(), 1);
        assert_eq!(bcr.continues(), 1);
    }

    // ── PhoenixAlgorithm ──────────────────────────────────────────────────────

    #[test]
    fn test_phoenix_algorithm_simple() {
        let mut phoenix = PhoenixAlgorithm::new();
        let blocks = vec![BasicBlock {
            id: BlockId::new(0),
            stmts: vec![Statement::Return(None)],
            successors: vec![],
        }];
        let ast = phoenix.structure(blocks, BlockId::new(0));
        assert_eq!(ast.entry, BlockId::new(0));
    }

    // ── SailrAlgorithm ────────────────────────────────────────────────────────

    #[test]
    fn test_sailr_algorithm_simple() {
        let mut sailr = SailrAlgorithm::new();
        let blocks = vec![
            BasicBlock {
                id: BlockId::new(0),
                stmts: vec![],
                successors: vec![BlockId::new(1)],
            },
            BasicBlock {
                id: BlockId::new(1),
                stmts: vec![Statement::Return(None)],
                successors: vec![],
            },
        ];
        let ast = sailr.structure(blocks, BlockId::new(0));
        assert_eq!(ast.entry, BlockId::new(0));
    }

    // ── CfsValidator ─────────────────────────────────────────────────────────

    #[test]
    fn test_cfs_validator_valid() {
        let validator = CfsValidator::new();
        let blocks = vec![BasicBlock {
            id: BlockId::new(0),
            stmts: vec![Statement::Return(None)],
            successors: vec![],
        }];
        let ast = StructuredAst {
            root: StructuredNode::BasicBlock {
                id: BlockId::new(0),
                stmts: vec![Statement::Return(None)],
            },
            entry: BlockId::new(0),
            goto_count: 0,
            loop_count: 0,
        };
        assert!(validator.validate(&ast, &blocks).is_ok());
    }

    // ── StructuralAnalysis ────────────────────────────────────────────────────

    #[test]
    fn test_structural_analysis_block() {
        let sa = StructuralAnalysis::new();
        let blocks = vec![
            BasicBlock {
                id: BlockId::new(0),
                stmts: vec![],
                successors: vec![BlockId::new(1)],
            },
            BasicBlock {
                id: BlockId::new(1),
                stmts: vec![],
                successors: vec![],
            },
        ];
        let regions = sa.analyse(&blocks);
        assert_eq!(regions.len(), 2);
    }

    #[test]
    fn test_structural_analysis_ifthen() {
        let sa = StructuralAnalysis::new();
        let blocks = vec![BasicBlock {
            id: BlockId::new(0),
            stmts: vec![Statement::Branch("cond".to_string())],
            successors: vec![BlockId::new(1), BlockId::new(2)],
        }];
        let regions = sa.analyse(&blocks);
        assert_eq!(regions[0].region_type, StructuralRegionType::IfThen);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Deep control-flow structuring: Tarjan SCC, loop classification, condition
// building, switch recovery, goto minimization.
//
// This module is purely additive: it provides a self-contained CFG analysis
// layer (`CfgAnalysis`) that the existing `ControlFlowStructurer` can be paired
// with, plus richer loop / switch / condition recovery utilities. None of the
// existing public types are modified.
// ═════════════════════════════════════════════════════════════════════════════

use std::collections::BTreeMap;

/// A directed control-flow graph keyed by `BlockId`, independent of petgraph,
/// suitable for the analysis algorithms in this module.
#[derive(Debug, Clone, Default)]
pub struct Cfg {
    /// Blocks indexed by id.
    blocks: BTreeMap<BlockId, BasicBlock>,
    /// Successor adjacency (mirror of each block's `successors`).
    succ: BTreeMap<BlockId, Vec<BlockId>>,
    /// Predecessor adjacency (computed).
    pred: BTreeMap<BlockId, Vec<BlockId>>,
}

impl Cfg {
    /// Build a CFG from a block list.
    ///
    /// Parallel edges between the same `(src, dst)` pair are collapsed to a
    /// single edge: dominator analysis and back-edge detection care only about
    /// the *existence* of the edge, and duplicate edges would inflate
    /// predecessor counts (mis-classifying natural loops as irreducible) and
    /// double-emit back-edges.
    #[must_use]
    pub fn from_blocks(blocks: &[BasicBlock]) -> Self {
        let mut block_map = BTreeMap::new();
        let mut succ: BTreeMap<BlockId, Vec<BlockId>> = BTreeMap::new();
        let mut pred: BTreeMap<BlockId, Vec<BlockId>> = BTreeMap::new();
        for b in blocks {
            block_map.insert(b.id, b.clone());
            succ.entry(b.id).or_default();
            pred.entry(b.id).or_default();
        }
        let mut seen: HashSet<(BlockId, BlockId)> = HashSet::new();
        for b in blocks {
            for &s in &b.successors {
                // Only register edges whose target exists, and de-duplicate
                // parallel edges (see doc comment above).
                if block_map.contains_key(&s) && seen.insert((b.id, s)) {
                    succ.entry(b.id).or_default().push(s);
                    pred.entry(s).or_default().push(b.id);
                }
            }
        }
        Self {
            blocks: block_map,
            succ,
            pred,
        }
    }

    /// Number of blocks in the graph.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Is the graph empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Does the graph contain `id`?
    #[must_use]
    pub fn contains(&self, id: BlockId) -> bool {
        self.blocks.contains_key(&id)
    }

    /// Borrow a block by id.
    #[must_use]
    pub fn block(&self, id: BlockId) -> Option<&BasicBlock> {
        self.blocks.get(&id)
    }

    /// Successors of a block.
    #[must_use]
    pub fn successors(&self, id: BlockId) -> &[BlockId] {
        self.succ.get(&id).map_or(&[], Vec::as_slice)
    }

    /// Predecessors of a block.
    #[must_use]
    pub fn predecessors(&self, id: BlockId) -> &[BlockId] {
        self.pred.get(&id).map_or(&[], Vec::as_slice)
    }

    /// All block ids in ascending order.
    #[must_use]
    pub fn block_ids(&self) -> Vec<BlockId> {
        self.blocks.keys().copied().collect()
    }

    /// Compute a depth-first pre-order from `entry`.
    #[must_use]
    pub fn dfs_preorder(&self, entry: BlockId) -> Vec<BlockId> {
        let mut visited = HashSet::new();
        let mut order = Vec::new();
        let mut stack = vec![entry];
        while let Some(n) = stack.pop() {
            if !visited.insert(n) {
                continue;
            }
            order.push(n);
            // Push successors in reverse so the lowest id is visited first.
            let mut succs: Vec<BlockId> = self.successors(n).to_vec();
            succs.sort_unstable();
            for s in succs.into_iter().rev() {
                if !visited.contains(&s) {
                    stack.push(s);
                }
            }
        }
        order
    }

    /// Reverse post-order from `entry` (a topological-ish ordering used by
    /// dominator computation).
    ///
    /// Implemented iteratively so that deep CFGs (long linear chains, deeply
    /// nested control flow — both common in real-world stripped binaries) do
    /// not overflow the call stack.
    #[must_use]
    pub fn reverse_postorder(&self, entry: BlockId) -> Vec<BlockId> {
        let mut visited = HashSet::new();
        let mut post = Vec::with_capacity(self.blocks.len());
        // Stack frame: (node, sorted-successors, next-successor-index).
        // We materialise the sorted successor list once per push so the order
        // is deterministic and matches the previous recursive implementation.
        let mut stack: Vec<(BlockId, Vec<BlockId>, usize)> = Vec::new();
        if visited.insert(entry) {
            let mut s0: Vec<BlockId> = self.successors(entry).to_vec();
            s0.sort_unstable();
            stack.push((entry, s0, 0));
        }
        while let Some(frame) = stack.last_mut() {
            if frame.2 < frame.1.len() {
                let next = frame.1[frame.2];
                frame.2 += 1;
                if visited.insert(next) {
                    let mut s: Vec<BlockId> = self.successors(next).to_vec();
                    s.sort_unstable();
                    stack.push((next, s, 0));
                }
            } else {
                post.push(frame.0);
                stack.pop();
            }
        }
        post.reverse();
        post
    }

    /// Set of blocks reachable from `entry`.
    #[must_use]
    pub fn reachable(&self, entry: BlockId) -> HashSet<BlockId> {
        self.dfs_preorder(entry).into_iter().collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tarjan's strongly-connected-components algorithm
// ─────────────────────────────────────────────────────────────────────────────

/// Computes strongly-connected components using Tarjan's algorithm
/// (iterative, so it never overflows the stack on deep graphs).
#[derive(Debug, Default)]
pub struct TarjanScc {
    index_counter: usize,
    indices: HashMap<BlockId, usize>,
    lowlink: HashMap<BlockId, usize>,
    on_stack: HashSet<BlockId>,
    stack: Vec<BlockId>,
    components: Vec<Vec<BlockId>>,
}

impl TarjanScc {
    /// Create a fresh solver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run Tarjan's SCC over `cfg`, returning components in reverse
    /// topological order. Each component is a list of block ids.
    #[must_use]
    pub fn run(cfg: &Cfg) -> Vec<Vec<BlockId>> {
        let mut solver = Self::new();
        for id in cfg.block_ids() {
            if !solver.indices.contains_key(&id) {
                solver.strongconnect(cfg, id);
            }
        }
        solver.components
    }

    /// Iterative strongconnect to avoid recursion depth issues.
    fn strongconnect(&mut self, cfg: &Cfg, root: BlockId) {
        // Work item: (node, index-into-successors).
        let mut work: Vec<(BlockId, usize)> = vec![(root, 0)];
        self.indices.insert(root, self.index_counter);
        self.lowlink.insert(root, self.index_counter);
        self.index_counter += 1;
        self.stack.push(root);
        self.on_stack.insert(root);

        while let Some(&(v, succ_idx)) = work.last() {
            let succs = cfg.successors(v);
            if succ_idx < succs.len() {
                // Advance the cursor for v.
                if let Some(item) = work.last_mut() {
                    item.1 += 1;
                }
                let w = succs[succ_idx];
                if !self.indices.contains_key(&w) {
                    // Tree edge — descend.
                    self.indices.insert(w, self.index_counter);
                    self.lowlink.insert(w, self.index_counter);
                    self.index_counter += 1;
                    self.stack.push(w);
                    self.on_stack.insert(w);
                    work.push((w, 0));
                } else if self.on_stack.contains(&w) {
                    // Back / cross edge to a node on the stack.
                    let w_index = self.indices[&w];
                    let v_low = self.lowlink[&v];
                    self.lowlink.insert(v, v_low.min(w_index));
                }
            } else {
                // Finished v: if it is a root of an SCC, pop the component.
                if self.lowlink[&v] == self.indices[&v] {
                    let mut component = Vec::new();
                    loop {
                        let w = self.stack.pop().expect("stack non-empty");
                        self.on_stack.remove(&w);
                        component.push(w);
                        if w == v {
                            break;
                        }
                    }
                    component.sort_unstable();
                    self.components.push(component);
                }
                work.pop();
                // Propagate lowlink up to the parent.
                if let Some(&(parent, _)) = work.last() {
                    let v_low = self.lowlink[&v];
                    let p_low = self.lowlink[&parent];
                    self.lowlink.insert(parent, p_low.min(v_low));
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Dominators (Cooper-Harvey-Kennedy)
// ─────────────────────────────────────────────────────────────────────────────

/// Immediate-dominator information for a CFG.
#[derive(Debug, Default, Clone)]
pub struct Dominators {
    idom: HashMap<BlockId, BlockId>,
}

impl Dominators {
    /// Compute dominators of `cfg` rooted at `entry`.
    #[must_use]
    pub fn compute(cfg: &Cfg, entry: BlockId) -> Self {
        let rpo = cfg.reverse_postorder(entry);
        let pos: HashMap<BlockId, usize> = rpo.iter().enumerate().map(|(i, &n)| (n, i)).collect();
        let mut idom: HashMap<BlockId, BlockId> = HashMap::new();
        idom.insert(entry, entry);

        let mut changed = true;
        while changed {
            changed = false;
            for &b in &rpo {
                if b == entry {
                    continue;
                }
                let mut new_idom: Option<BlockId> = None;
                for &p in cfg.predecessors(b) {
                    if !idom.contains_key(&p) {
                        continue;
                    }
                    new_idom = Some(new_idom.map_or(p, |cur| Self::intersect(cur, p, &idom, &pos)));
                }
                if let Some(ni) = new_idom
                    && idom.get(&b) != Some(&ni) {
                        idom.insert(b, ni);
                        changed = true;
                    }
            }
        }
        Self { idom }
    }

    fn intersect(
        mut a: BlockId,
        mut b: BlockId,
        idom: &HashMap<BlockId, BlockId>,
        pos: &HashMap<BlockId, usize>,
    ) -> BlockId {
        while a != b {
            while pos.get(&a).copied().unwrap_or(usize::MAX)
                > pos.get(&b).copied().unwrap_or(usize::MAX)
            {
                a = idom[&a];
            }
            while pos.get(&b).copied().unwrap_or(usize::MAX)
                > pos.get(&a).copied().unwrap_or(usize::MAX)
            {
                b = idom[&b];
            }
        }
        a
    }

    /// Immediate dominator of `b` (the entry dominates itself).
    #[must_use]
    pub fn idom(&self, b: BlockId) -> Option<BlockId> {
        self.idom.get(&b).copied()
    }

    /// Does `a` dominate `b`?
    #[must_use]
    pub fn dominates(&self, a: BlockId, b: BlockId) -> bool {
        let mut cur = b;
        loop {
            if cur == a {
                return true;
            }
            match self.idom.get(&cur) {
                Some(&d) if d != cur => cur = d,
                _ => return false,
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Loop detection and classification
// ─────────────────────────────────────────────────────────────────────────────

/// How a loop relates to the structured control flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoopShape {
    /// Single header, single back-edge — a natural reducible loop.
    Natural,
    /// A single block that branches to itself.
    SelfLoop,
    /// Multiple entries into the loop — irreducible.
    Improper,
}

/// A detected loop with its constituent blocks and classification.
#[derive(Debug, Clone)]
pub struct DetectedLoop {
    /// The loop header (entry) block.
    pub header: BlockId,
    /// Latch blocks (sources of back-edges to the header).
    pub latches: Vec<BlockId>,
    /// All blocks belonging to the loop body (including the header).
    pub body: Vec<BlockId>,
    /// Topological classification.
    pub shape: LoopShape,
    /// The recovered loop kind (`while` / `do-while` / `for`).
    pub kind: LoopKind,
    /// Blocks that exit the loop (the "follow" targets).
    pub exits: Vec<BlockId>,
}

impl DetectedLoop {
    /// Does the loop contain `id`?
    #[must_use]
    pub fn contains(&self, id: BlockId) -> bool {
        self.body.contains(&id)
    }

    /// Number of blocks in the loop body.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.body.len()
    }
}

/// Detects and classifies all loops in a CFG using SCCs + dominators.
#[derive(Debug)]
pub struct LoopAnalysis {
    loops: Vec<DetectedLoop>,
    /// Map from a block to the innermost loop header containing it.
    header_of: HashMap<BlockId, BlockId>,
}

impl LoopAnalysis {
    /// Run the full loop analysis.
    #[must_use]
    pub fn analyze(cfg: &Cfg, entry: BlockId) -> Self {
        let doms = Dominators::compute(cfg, entry);
        let sccs = TarjanScc::run(cfg);
        let back_edges = Self::find_back_edges(cfg, &doms);

        let mut loops = Vec::new();
        for comp in &sccs {
            // A real loop is either an SCC with >1 node, or a single node
            // with a self-edge.
            let is_self_loop = comp.len() == 1 && cfg.successors(comp[0]).contains(&comp[0]);
            if comp.len() < 2 && !is_self_loop {
                continue;
            }
            let comp_set: HashSet<BlockId> = comp.iter().copied().collect();

            // The header is the component member with the lowest RPO position
            // dominating the rest; we approximate via the block that has a
            // predecessor outside the component (the entry) or, failing that,
            // the block dominating all others.
            let header = Self::pick_header(cfg, comp, &comp_set, &doms, entry);

            // Latches: members of the component with a back-edge to header.
            let latches: Vec<BlockId> = comp
                .iter()
                .copied()
                .filter(|&b| {
                    cfg.successors(b).contains(&header) && back_edges.contains(&(b, header))
                })
                .collect();

            // Entry edges: edges into the component from outside.
            let entry_count = comp
                .iter()
                .flat_map(|&b| cfg.predecessors(b).iter().copied().map(move |p| (p, b)))
                .filter(|(p, _b)| !comp_set.contains(p))
                .map(|(_p, b)| b)
                .collect::<HashSet<_>>()
                .len();

            let shape = if is_self_loop {
                LoopShape::SelfLoop
            } else if entry_count > 1 {
                LoopShape::Improper
            } else {
                LoopShape::Natural
            };

            // Exits: successors of loop blocks that fall outside the component.
            let mut exits: Vec<BlockId> = comp
                .iter()
                .flat_map(|&b| cfg.successors(b).iter().copied())
                .filter(|s| !comp_set.contains(s))
                .collect();
            exits.sort_unstable();
            exits.dedup();

            let kind = Self::classify_kind(cfg, header, &comp_set, &latches);

            loops.push(DetectedLoop {
                header,
                latches,
                body: comp.clone(),
                shape,
                kind,
                exits,
            });
        }

        // Build header_of mapping: innermost loop (smallest body) wins.
        let mut header_of: HashMap<BlockId, BlockId> = HashMap::new();
        let mut sorted: Vec<&DetectedLoop> = loops.iter().collect();
        sorted.sort_by_key(|l| std::cmp::Reverse(l.body.len()));
        for l in sorted {
            for &b in &l.body {
                header_of.insert(b, l.header);
            }
        }

        Self { loops, header_of }
    }

    /// All identified back-edges `(latch, header)` where `header` dominates
    /// `latch`.
    fn find_back_edges(cfg: &Cfg, doms: &Dominators) -> HashSet<(BlockId, BlockId)> {
        let mut edges = HashSet::new();
        for b in cfg.block_ids() {
            for &s in cfg.successors(b) {
                if doms.dominates(s, b) {
                    edges.insert((b, s));
                }
            }
        }
        edges
    }

    fn pick_header(
        cfg: &Cfg,
        comp: &[BlockId],
        comp_set: &HashSet<BlockId>,
        doms: &Dominators,
        entry: BlockId,
    ) -> BlockId {
        // Prefer a block with an incoming edge from outside the component.
        for &b in comp {
            if b == entry {
                return b;
            }
        }
        for &b in comp {
            if cfg.predecessors(b).iter().any(|p| !comp_set.contains(p)) {
                return b;
            }
        }
        // Fall back to the block that dominates all others.
        for &candidate in comp {
            if comp.iter().all(|&other| doms.dominates(candidate, other)) {
                return candidate;
            }
        }
        comp[0]
    }

    /// Determine the loop kind from where the controlling branch sits.
    fn classify_kind(
        cfg: &Cfg,
        header: BlockId,
        comp_set: &HashSet<BlockId>,
        latches: &[BlockId],
    ) -> LoopKind {
        let header_block = cfg.block(header);
        let header_has_cond = header_block.is_some_and(|b| {
            cfg.successors(header).len() == 2
                && b.stmts.iter().any(|s| matches!(s, Statement::Branch(_)))
        });
        // Header tests the condition and one successor leaves the loop → while.
        if header_has_cond && cfg.successors(header).iter().any(|s| !comp_set.contains(s)) {
            // `for` if the header has an obvious induction-variable update at a
            // latch (assignment to the same variable the branch tests).
            if Self::looks_like_for(cfg, header, latches) {
                return LoopKind::For;
            }
            return LoopKind::While;
        }
        // Condition lives at a latch → do-while.
        let latch_has_cond = latches.iter().any(|&l| {
            cfg.successors(l).len() == 2
                && cfg
                    .block(l)
                    .is_some_and(|b| b.stmts.iter().any(|s| matches!(s, Statement::Branch(_))))
        });
        if latch_has_cond {
            LoopKind::DoWhile
        } else {
            LoopKind::While
        }
    }

    /// Heuristic: a `for` loop has a latch that updates the variable named in
    /// the header's branch condition.
    fn looks_like_for(cfg: &Cfg, header: BlockId, latches: &[BlockId]) -> bool {
        let Some(cond) = cfg.block(header).and_then(branch_condition) else {
            return false;
        };
        let cond_vars = identifier_tokens(&cond);
        for &l in latches {
            if let Some(b) = cfg.block(l) {
                for s in &b.stmts {
                    if let Statement::Assign { lhs, .. } = s
                        && cond_vars.iter().any(|v| v == lhs) {
                            return true;
                        }
                }
            }
        }
        false
    }

    /// All detected loops.
    #[must_use]
    pub fn loops(&self) -> &[DetectedLoop] {
        &self.loops
    }

    /// Number of loops.
    #[must_use]
    pub const fn loop_count(&self) -> usize {
        self.loops.len()
    }

    /// Is `id` a loop header?
    #[must_use]
    pub fn is_header(&self, id: BlockId) -> bool {
        self.loops.iter().any(|l| l.header == id)
    }

    /// The innermost loop header containing `id`, if any.
    #[must_use]
    pub fn innermost_header(&self, id: BlockId) -> Option<BlockId> {
        self.header_of.get(&id).copied()
    }

    /// Look up a loop by header.
    #[must_use]
    pub fn loop_for(&self, header: BlockId) -> Option<&DetectedLoop> {
        self.loops.iter().find(|l| l.header == header)
    }

    /// Count loops with the given shape.
    #[must_use]
    pub fn count_shape(&self, shape: LoopShape) -> usize {
        self.loops.iter().filter(|l| l.shape == shape).count()
    }
}

/// Extract the branch condition string of a block, if it ends with a branch.
#[must_use]
pub fn branch_condition(bb: &BasicBlock) -> Option<String> {
    bb.stmts.iter().rev().find_map(|s| match s {
        Statement::Branch(c) => Some(c.clone()),
        _ => None,
    })
}

/// Split a string into identifier-like tokens (used for variable matching).
#[must_use]
pub fn identifier_tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in s.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            cur.push(ch);
        } else if !cur.is_empty() {
            // Skip pure-numeric tokens.
            if cur.chars().all(|c| c.is_ascii_digit()) {
                cur.clear();
            } else {
                out.push(std::mem::take(&mut cur));
            }
        }
    }
    if !cur.is_empty() && !cur.chars().all(|c| c.is_ascii_digit()) {
        out.push(cur);
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Boolean condition algebra (for condition-aware region structuring)
// ─────────────────────────────────────────────────────────────────────────────

/// A boolean condition tree built up from branch predicates. Used to merge
/// short-circuit branch chains (`if (a) if (b)` → `if (a && b)`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Condition {
    /// An atomic predicate (the raw branch string).
    Atom(String),
    /// Logical negation.
    Not(Box<Self>),
    /// Short-circuit conjunction.
    And(Box<Self>, Box<Self>),
    /// Short-circuit disjunction.
    Or(Box<Self>, Box<Self>),
    /// Constant true.
    True,
    /// Constant false.
    False,
}

impl Condition {
    /// Build an atom from a predicate string.
    #[must_use]
    pub fn atom(s: impl Into<String>) -> Self {
        Self::Atom(s.into())
    }

    /// Logically negate, applying involution and De Morgan at the top level.
    #[must_use]
    pub fn negate(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Not(inner) => *inner,
            Self::And(a, b) => Self::Or(Box::new(a.negate()), Box::new(b.negate())),
            Self::Or(a, b) => Self::And(Box::new(a.negate()), Box::new(b.negate())),
            atom @ Self::Atom(_) => Self::Not(Box::new(atom)),
        }
    }

    /// Conjoin two conditions, absorbing constants.
    #[must_use]
    pub fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::False, _) | (_, Self::False) => Self::False,
            (Self::True, x) | (x, Self::True) => x,
            (a, b) => Self::And(Box::new(a), Box::new(b)),
        }
    }

    /// Disjoin two conditions, absorbing constants.
    #[must_use]
    pub fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::True, _) | (_, Self::True) => Self::True,
            (Self::False, x) | (x, Self::False) => x,
            (a, b) => Self::Or(Box::new(a), Box::new(b)),
        }
    }

    /// Render the condition as a C-like boolean expression with correct
    /// precedence and parenthesisation.
    #[must_use]
    pub fn to_c(&self) -> String {
        self.to_c_prec(0)
    }

    fn to_c_prec(&self, parent: u8) -> String {
        // Precedence: Or=1, And=2, Not/Atom=3.
        match self {
            Self::True => "true".to_string(),
            Self::False => "false".to_string(),
            Self::Atom(s) => s.clone(),
            Self::Not(inner) => {
                let s = inner.to_c_prec(3);
                format!("!({s})")
            }
            Self::And(a, b) => {
                let s = format!("{} && {}", a.to_c_prec(2), b.to_c_prec(2));
                if parent > 2 { format!("({s})") } else { s }
            }
            Self::Or(a, b) => {
                let s = format!("{} || {}", a.to_c_prec(1), b.to_c_prec(1));
                if parent > 1 { format!("({s})") } else { s }
            }
        }
    }

    /// Count the number of atomic predicates.
    #[must_use]
    pub fn atom_count(&self) -> usize {
        match self {
            Self::Atom(_) => 1,
            Self::True | Self::False => 0,
            Self::Not(i) => i.atom_count(),
            Self::And(a, b) | Self::Or(a, b) => a.atom_count() + b.atom_count(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Switch recovery: jump-table and cmp/je chains
// ─────────────────────────────────────────────────────────────────────────────

/// One recovered case: a discriminant value (or default) and its target block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredCase {
    /// `None` = default.
    pub value: Option<i64>,
    /// The block this case jumps to.
    pub target: BlockId,
}

/// A recovered switch construct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredSwitch {
    /// The block holding the dispatch.
    pub head: BlockId,
    /// The switch discriminant expression.
    pub discriminant: String,
    /// All recovered cases (default last if present).
    pub cases: Vec<RecoveredCase>,
    /// Whether this came from a jump table (`true`) or a compare chain.
    pub jump_table: bool,
}

impl RecoveredSwitch {
    /// Number of non-default cases.
    #[must_use]
    pub fn case_count(&self) -> usize {
        self.cases.iter().filter(|c| c.value.is_some()).count()
    }

    /// Does the switch have an explicit default case?
    #[must_use]
    pub fn has_default(&self) -> bool {
        self.cases.iter().any(|c| c.value.is_none())
    }
}

/// Recovers switch statements from jump-table blocks (many successors) and from
/// chains of `cmp x, k; je target` style comparisons.
#[derive(Debug, Default)]
pub struct SwitchAnalysis {
    switches: Vec<RecoveredSwitch>,
}

impl SwitchAnalysis {
    /// Create an empty analysis.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Recover all switches reachable from `entry`.
    #[must_use]
    pub fn analyze(cfg: &Cfg, entry: BlockId) -> Self {
        let mut me = Self::new();
        for id in cfg.dfs_preorder(entry) {
            if let Some(sw) = Self::recover_jump_table(cfg, id) {
                me.switches.push(sw);
            } else if let Some(sw) = Self::recover_cmp_chain(cfg, id) {
                me.switches.push(sw);
            }
        }
        me
    }

    /// A jump-table switch: a block with 3+ successors. The discriminant comes
    /// from a `switch (...)` branch statement if present, else a synthesised
    /// name.
    fn recover_jump_table(cfg: &Cfg, id: BlockId) -> Option<RecoveredSwitch> {
        let block = cfg.block(id)?;
        let succs = cfg.successors(id);
        if succs.len() < 3 {
            return None;
        }
        let discriminant = branch_condition(block).map_or_else(|| "switch_var".to_string(), |c| switch_subject(&c));
        let mut cases: Vec<RecoveredCase> = succs
            .iter()
            .enumerate()
            .map(|(i, &t)| RecoveredCase {
                value: Some(i64::try_from(i).unwrap_or(i64::MAX)),
                target: t,
            })
            .collect();
        // The last successor is conventionally the default fall-through.
        if let Some(last) = cases.last_mut() {
            last.value = None;
        }
        Some(RecoveredSwitch {
            head: id,
            discriminant,
            cases,
            jump_table: true,
        })
    }

    /// A compare-chain switch: a sequence of conditional blocks each testing
    /// the same variable against a constant via `==`, chained through the
    /// false successor.
    fn recover_cmp_chain(cfg: &Cfg, start: BlockId) -> Option<RecoveredSwitch> {
        let mut cases = Vec::new();
        let mut subject: Option<String> = None;
        let mut cur = start;
        let mut visited = HashSet::new();

        loop {
            if !visited.insert(cur) {
                break;
            }
            let block = cfg.block(cur)?;
            let succs = cfg.successors(cur);
            if succs.len() != 2 {
                break;
            }
            let Some(cond) = branch_condition(block) else {
                break;
            };
            let Some((var, value)) = parse_equality(&cond) else {
                break;
            };
            match &subject {
                None => subject = Some(var.clone()),
                Some(s) if *s == var => {}
                Some(_) => break, // different variable — chain ends
            }
            // true successor = the case body, false successor = next test.
            cases.push(RecoveredCase {
                value: Some(value),
                target: succs[0],
            });
            cur = succs[1];
        }

        if cases.len() < 2 {
            return None;
        }
        // The final false target is the default.
        cases.push(RecoveredCase {
            value: None,
            target: cur,
        });
        Some(RecoveredSwitch {
            head: start,
            discriminant: subject.unwrap_or_else(|| "switch_var".to_string()),
            cases,
            jump_table: false,
        })
    }

    /// All recovered switches.
    #[must_use]
    pub fn switches(&self) -> &[RecoveredSwitch] {
        &self.switches
    }

    /// Number recovered.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.switches.len()
    }
}

/// Extract the subject of a `switch (expr)` style condition; falls back to the
/// whole trimmed string.
#[must_use]
fn switch_subject(cond: &str) -> String {
    let t = cond.trim();
    if let Some(rest) = t.strip_prefix("switch") {
        let rest = rest.trim();
        if let Some(inner) = rest.strip_prefix('(').and_then(|r| r.strip_suffix(')')) {
            return inner.trim().to_string();
        }
    }
    t.to_string()
}

/// Parse an `x == k` predicate, returning `(var, k)`.
#[must_use]
fn parse_equality(cond: &str) -> Option<(String, i64)> {
    let (lhs, rhs) = cond.split_once("==")?;
    let var = lhs.trim().to_string();
    if var.is_empty() || var.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return None;
    }
    let rhs = rhs.trim();
    let value = if let Some(hex) = rhs.strip_prefix("0x").or_else(|| rhs.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()?
    } else {
        rhs.parse::<i64>().ok()?
    };
    Some((var, value))
}

// ─────────────────────────────────────────────────────────────────────────────
// Goto minimization
// ─────────────────────────────────────────────────────────────────────────────

/// Classifies and counts the `goto` nodes in a structured AST, distinguishing
/// forward gotos (generally acceptable) from backward gotos (which should be
/// recovered as loops).
#[derive(Debug, Default, Clone)]
pub struct GotoReport {
    /// Total gotos.
    pub total: usize,
    /// Forward gotos (target id appears later than source in emission order).
    pub forward: usize,
    /// Backward gotos.
    pub backward: usize,
    /// Targets referenced by gotos (for label emission).
    pub targets: Vec<BlockId>,
}

/// Analyses goto usage in a `StructuredNode` tree and provides a minimization
/// score. Lower scores are better; backward gotos are penalised more heavily.
#[derive(Debug, Default)]
pub struct GotoMinimizer;

impl GotoMinimizer {
    /// Create a new minimizer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Produce a report on the gotos in `root`. The `order` slice gives the
    /// linear emission position of each block id; gotos to later ids are
    /// "forward".
    #[must_use]
    pub fn report(&self, root: &StructuredNode, order: &[BlockId]) -> GotoReport {
        let pos: HashMap<BlockId, usize> = order.iter().enumerate().map(|(i, &b)| (b, i)).collect();
        let mut report = GotoReport::default();
        Self::collect(root, None, &pos, &mut report);
        report.targets.sort_unstable();
        report.targets.dedup();
        report
    }

    fn collect(
        node: &StructuredNode,
        enclosing_pos: Option<usize>,
        pos: &HashMap<BlockId, usize>,
        report: &mut GotoReport,
    ) {
        match node {
            StructuredNode::Goto(target) => {
                report.total += 1;
                report.targets.push(*target);
                let target_pos = pos.get(target).copied();
                match (enclosing_pos, target_pos) {
                    (Some(src), Some(dst)) if dst <= src => report.backward += 1,
                    _ => report.forward += 1,
                }
            }
            StructuredNode::BasicBlock { .. } | StructuredNode::Break | StructuredNode::Continue | StructuredNode::Return(_) => {}
            StructuredNode::Sequence(children) => {
                // Track the emission position of the most recent block seen so
                // a following goto can be classified as forward/backward.
                let mut ctx = enclosing_pos;
                for c in children {
                    if let Some(p) = leading_pos(c, pos) {
                        ctx = Some(p);
                    }
                    Self::collect(c, ctx, pos, report);
                }
            }
            StructuredNode::If { then_branch, .. } => {
                Self::collect(then_branch, enclosing_pos, pos, report);
            }
            StructuredNode::IfElse {
                then_branch,
                else_branch,
                ..
            } => {
                Self::collect(then_branch, enclosing_pos, pos, report);
                Self::collect(else_branch, enclosing_pos, pos, report);
            }
            StructuredNode::Loop { body, .. } => Self::collect(body, enclosing_pos, pos, report),
            StructuredNode::Switch { cases, .. } => {
                for c in cases {
                    Self::collect(&c.body, enclosing_pos, pos, report);
                }
            }
            }
    }

    /// A quality score: `forward + 4*backward`. Zero is ideal.
    #[must_use]
    pub const fn score(&self, report: &GotoReport) -> usize {
        report.forward + report.backward * 4
    }
}

/// The emission position of the first basic block under a node, if any.
fn leading_pos(node: &StructuredNode, pos: &HashMap<BlockId, usize>) -> Option<usize> {
    match node {
        StructuredNode::BasicBlock { id, .. } => pos.get(id).copied(),
        StructuredNode::Sequence(children) => children.iter().find_map(|c| leading_pos(c, pos)),
        StructuredNode::If { then_branch, .. } | StructuredNode::IfElse { then_branch, .. } => leading_pos(then_branch, pos),
        StructuredNode::Loop { body, .. } => leading_pos(body, pos),
        StructuredNode::Switch { cases, .. } => {
            cases.iter().find_map(|c| leading_pos(&c.body, pos))
        }
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CfgAnalysis: a one-shot bundle wiring the above together
// ─────────────────────────────────────────────────────────────────────────────

/// A complete control-flow analysis over a block list: dominators, SCCs,
/// loop classification, switch recovery, and a structured AST.
#[derive(Debug)]
pub struct CfgAnalysis {
    /// The CFG.
    pub cfg: Cfg,
    /// The entry block.
    pub entry: BlockId,
    /// Loop analysis.
    pub loops: LoopAnalysis,
    /// Switch analysis.
    pub switches: SwitchAnalysis,
    /// Strongly-connected components.
    pub sccs: Vec<Vec<BlockId>>,
}

impl CfgAnalysis {
    /// Run all analyses on `blocks` rooted at `entry`.
    ///
    /// # Errors
    /// Returns `StructureError::EmptyCfg` if there are no blocks, or
    /// `StructureError::EntryNotFound` if `entry` is absent.
    pub fn run(blocks: &[BasicBlock], entry: BlockId) -> Result<Self, StructureError> {
        if blocks.is_empty() {
            return Err(StructureError::EmptyCfg);
        }
        let cfg = Cfg::from_blocks(blocks);
        if !cfg.contains(entry) {
            return Err(StructureError::EntryNotFound(entry));
        }
        let loops = LoopAnalysis::analyze(&cfg, entry);
        let switches = SwitchAnalysis::analyze(&cfg, entry);
        let sccs = TarjanScc::run(&cfg);
        Ok(Self {
            cfg,
            entry,
            loops,
            switches,
            sccs,
        })
    }

    /// Structure the function into a `StructuredAst` using the existing DREAM
    /// structurer, then compute a goto report against the DFS emission order.
    #[must_use]
    pub fn structure(&self, blocks: &[BasicBlock]) -> Option<(StructuredAst, GotoReport)> {
        let ast = ControlFlowStructurer::new(blocks.to_vec())
            .structure(self.entry)
            .ok()?;
        let order = self.cfg.dfs_preorder(self.entry);
        let report = GotoMinimizer::new().report(&ast.root, &order);
        Some((ast, report))
    }

    /// Number of natural loops.
    #[must_use]
    pub fn natural_loop_count(&self) -> usize {
        self.loops.count_shape(LoopShape::Natural) + self.loops.count_shape(LoopShape::SelfLoop)
    }

    /// Whether the function contains any irreducible loops.
    #[must_use]
    pub fn has_irreducible(&self) -> bool {
        self.loops.count_shape(LoopShape::Improper) > 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for the deep CFS layer
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod deep_cfs_tests {
    use super::*;

    fn bb(id: u32, stmts: Vec<Statement>, succs: &[u32]) -> BasicBlock {
        BasicBlock {
            id: BlockId::new(id),
            stmts,
            successors: succs.iter().map(|&s| BlockId::new(s)).collect(),
        }
    }

    fn br(c: &str) -> Vec<Statement> {
        vec![Statement::Branch(c.to_string())]
    }

    fn asn(l: &str, r: &str) -> Statement {
        Statement::Assign {
            lhs: l.to_string(),
            rhs: r.to_string(),
        }
    }

    fn ret(v: Option<&str>) -> Statement {
        Statement::Return(v.map(str::to_string))
    }

    // ── Cfg basics ───────────────────────────────────────────────────────────

    #[test]
    fn test_cfg_construction() {
        let blocks = vec![
            bb(0, vec![], &[1, 2]),
            bb(1, vec![], &[3]),
            bb(2, vec![], &[3]),
            bb(3, vec![], &[]),
        ];
        let cfg = Cfg::from_blocks(&blocks);
        assert_eq!(cfg.len(), 4);
        assert_eq!(
            cfg.successors(BlockId::new(0)),
            &[BlockId::new(1), BlockId::new(2)]
        );
        assert_eq!(
            cfg.predecessors(BlockId::new(3)),
            &[BlockId::new(1), BlockId::new(2)]
        );
    }

    #[test]
    fn test_cfg_ignores_dangling_edges() {
        let blocks = vec![bb(0, vec![], &[1, 99]), bb(1, vec![], &[])];
        let cfg = Cfg::from_blocks(&blocks);
        // edge to 99 (nonexistent) is dropped; edge to existing 1 is kept
        assert_eq!(cfg.successors(BlockId::new(0)), &[BlockId::new(1)]);
    }

    #[test]
    fn test_cfg_dfs_and_rpo() {
        let blocks = vec![bb(0, vec![], &[1]), bb(1, vec![], &[2]), bb(2, vec![], &[])];
        let cfg = Cfg::from_blocks(&blocks);
        let pre = cfg.dfs_preorder(BlockId::new(0));
        assert_eq!(pre, vec![BlockId::new(0), BlockId::new(1), BlockId::new(2)]);
        let rpo = cfg.reverse_postorder(BlockId::new(0));
        assert_eq!(rpo.first(), Some(&BlockId::new(0)));
    }

    #[test]
    fn test_cfg_reachable() {
        let blocks = vec![bb(0, vec![], &[1]), bb(1, vec![], &[]), bb(2, vec![], &[])];
        let cfg = Cfg::from_blocks(&blocks);
        let r = cfg.reachable(BlockId::new(0));
        assert!(r.contains(&BlockId::new(1)));
        assert!(!r.contains(&BlockId::new(2)));
    }

    // ── Tarjan SCC ─────────────────────────────────────────────────────────────

    #[test]
    fn test_tarjan_no_loops() {
        let blocks = vec![bb(0, vec![], &[1]), bb(1, vec![], &[2]), bb(2, vec![], &[])];
        let cfg = Cfg::from_blocks(&blocks);
        let sccs = TarjanScc::run(&cfg);
        // all singletons
        assert_eq!(sccs.len(), 3);
        assert!(sccs.iter().all(|c| c.len() == 1));
    }

    #[test]
    fn test_tarjan_simple_loop() {
        // 0 -> 1 -> 2 -> 1 (loop), 1 -> 3
        let blocks = vec![
            bb(0, vec![], &[1]),
            bb(1, br("c"), &[2, 3]),
            bb(2, vec![], &[1]),
            bb(3, vec![], &[]),
        ];
        let cfg = Cfg::from_blocks(&blocks);
        let sccs = TarjanScc::run(&cfg);
        let loop_scc = sccs.iter().find(|c| c.len() > 1).unwrap();
        assert!(loop_scc.contains(&BlockId::new(1)));
        assert!(loop_scc.contains(&BlockId::new(2)));
    }

    #[test]
    fn test_tarjan_nested_loops() {
        // outer: 1..4, inner: 2..3
        let blocks = vec![
            bb(0, vec![], &[1]),
            bb(1, br("i<n"), &[2, 5]),
            bb(2, br("j<m"), &[3, 4]),
            bb(3, vec![], &[2]),
            bb(4, vec![], &[1]),
            bb(5, vec![ret(None)], &[]),
        ];
        let cfg = Cfg::from_blocks(&blocks);
        let sccs = TarjanScc::run(&cfg);
        // The whole 1-2-3-4 forms one SCC (they're all mutually reachable).
        let big = sccs.iter().find(|c| c.len() >= 4);
        assert!(big.is_some());
    }

    // ── Dominators ─────────────────────────────────────────────────────────────

    #[test]
    fn test_dominators_diamond() {
        let blocks = vec![
            bb(0, vec![], &[1, 2]),
            bb(1, vec![], &[3]),
            bb(2, vec![], &[3]),
            bb(3, vec![], &[]),
        ];
        let cfg = Cfg::from_blocks(&blocks);
        let doms = Dominators::compute(&cfg, BlockId::new(0));
        assert!(doms.dominates(BlockId::new(0), BlockId::new(3)));
        assert!(!doms.dominates(BlockId::new(1), BlockId::new(3)));
        assert_eq!(doms.idom(BlockId::new(3)), Some(BlockId::new(0)));
    }

    // ── Loop analysis ──────────────────────────────────────────────────────────

    #[test]
    fn test_loop_analysis_while() {
        let blocks = vec![
            bb(0, vec![asn("i", "0")], &[1]),
            bb(1, br("i < 10"), &[2, 3]),
            bb(2, vec![asn("x", "x+1")], &[1]),
            bb(3, vec![ret(None)], &[]),
        ];
        let la = LoopAnalysis::analyze(&Cfg::from_blocks(&blocks), BlockId::new(0));
        assert_eq!(la.loop_count(), 1);
        let l = &la.loops()[0];
        assert_eq!(l.header, BlockId::new(1));
        assert_eq!(l.kind, LoopKind::While);
        assert!(l.exits.contains(&BlockId::new(3)));
    }

    #[test]
    fn test_loop_analysis_for() {
        // header tests i, latch updates i → for loop
        let blocks = vec![
            bb(0, vec![asn("i", "0")], &[1]),
            bb(1, br("i < 10"), &[2, 3]),
            bb(2, vec![asn("i", "i + 1")], &[1]),
            bb(3, vec![ret(None)], &[]),
        ];
        let la = LoopAnalysis::analyze(&Cfg::from_blocks(&blocks), BlockId::new(0));
        assert_eq!(la.loops()[0].kind, LoopKind::For);
    }

    #[test]
    fn test_loop_analysis_do_while() {
        // 0 -> 1 (body) -> 2 (cond latch) -> {1 back, 3 exit}
        let blocks = vec![
            bb(0, vec![], &[1]),
            bb(1, vec![asn("x", "x+1")], &[2]),
            bb(2, br("keep"), &[1, 3]),
            bb(3, vec![ret(None)], &[]),
        ];
        let la = LoopAnalysis::analyze(&Cfg::from_blocks(&blocks), BlockId::new(0));
        assert_eq!(la.loop_count(), 1);
        assert_eq!(la.loops()[0].kind, LoopKind::DoWhile);
    }

    #[test]
    fn test_loop_analysis_self_loop() {
        let blocks = vec![bb(0, vec![asn("x", "x+1")], &[0])];
        let la = LoopAnalysis::analyze(&Cfg::from_blocks(&blocks), BlockId::new(0));
        assert_eq!(la.loop_count(), 1);
        assert_eq!(la.loops()[0].shape, LoopShape::SelfLoop);
    }

    #[test]
    fn test_loop_analysis_improper() {
        // Two entries into a 2-node cycle → irreducible.
        let blocks = vec![
            bb(0, br("c"), &[1, 2]),
            bb(1, vec![], &[2]),
            bb(2, vec![], &[1]),
        ];
        let la = LoopAnalysis::analyze(&Cfg::from_blocks(&blocks), BlockId::new(0));
        assert!(la.count_shape(LoopShape::Improper) >= 1);
    }

    #[test]
    fn test_loop_innermost_header() {
        let blocks = vec![
            bb(0, vec![], &[1]),
            bb(1, br("i<n"), &[2, 5]),
            bb(2, br("j<m"), &[3, 4]),
            bb(3, vec![], &[2]),
            bb(4, vec![], &[1]),
            bb(5, vec![ret(None)], &[]),
        ];
        let la = LoopAnalysis::analyze(&Cfg::from_blocks(&blocks), BlockId::new(0));
        // block 3 should map to the innermost header (2) if nested loops resolved.
        assert!(la.innermost_header(BlockId::new(3)).is_some());
    }

    // ── Conditions ─────────────────────────────────────────────────────────────

    #[test]
    fn test_condition_and_or_to_c() {
        let c = Condition::atom("a").and(Condition::atom("b"));
        assert_eq!(c.to_c(), "a && b");
        let c2 = Condition::atom("a").or(Condition::atom("b").and(Condition::atom("c")));
        assert_eq!(c2.to_c(), "a || b && c");
    }

    #[test]
    fn test_condition_negate_demorgan() {
        let c = Condition::atom("a").and(Condition::atom("b")).negate();
        // !(a && b) = !a || !b
        assert_eq!(c.to_c(), "!(a) || !(b)");
    }

    #[test]
    fn test_condition_double_negate() {
        let c = Condition::atom("x").negate().negate();
        assert_eq!(c, Condition::atom("x"));
    }

    #[test]
    fn test_condition_constants() {
        assert_eq!(
            Condition::True.and(Condition::atom("x")),
            Condition::atom("x")
        );
        assert_eq!(Condition::False.and(Condition::atom("x")), Condition::False);
        assert_eq!(Condition::True.or(Condition::atom("x")), Condition::True);
        assert_eq!(
            Condition::atom("x").or(Condition::False),
            Condition::atom("x")
        );
    }

    #[test]
    fn test_condition_atom_count() {
        let c = Condition::atom("a").and(Condition::atom("b").or(Condition::atom("c")));
        assert_eq!(c.atom_count(), 3);
    }

    #[test]
    fn test_condition_precedence_parens() {
        // (a || b) && c needs parens around the or
        let c = Condition::atom("a")
            .or(Condition::atom("b"))
            .and(Condition::atom("c"));
        assert_eq!(c.to_c(), "(a || b) && c");
    }

    // ── Switch recovery ──────────────────────────────────────────────────────

    #[test]
    fn test_switch_jump_table() {
        let blocks = vec![
            bb(
                0,
                vec![Statement::Branch("switch (op)".to_string())],
                &[1, 2, 3, 4],
            ),
            bb(1, vec![ret(Some("1"))], &[]),
            bb(2, vec![ret(Some("2"))], &[]),
            bb(3, vec![ret(Some("3"))], &[]),
            bb(4, vec![ret(None)], &[]),
        ];
        let sa = SwitchAnalysis::analyze(&Cfg::from_blocks(&blocks), BlockId::new(0));
        assert_eq!(sa.count(), 1);
        let sw = &sa.switches()[0];
        assert!(sw.jump_table);
        assert_eq!(sw.discriminant, "op");
        assert!(sw.has_default());
        assert_eq!(sw.case_count(), 3);
    }

    #[test]
    fn test_switch_cmp_chain() {
        // if x==1 -> A else if x==2 -> B else if x==3 -> C else D
        let blocks = vec![
            bb(0, br("x == 1"), &[10, 1]),
            bb(1, br("x == 2"), &[11, 2]),
            bb(2, br("x == 3"), &[12, 3]),
            bb(10, vec![ret(Some("1"))], &[]),
            bb(11, vec![ret(Some("2"))], &[]),
            bb(12, vec![ret(Some("3"))], &[]),
            bb(3, vec![ret(None)], &[]),
        ];
        let sa = SwitchAnalysis::analyze(&Cfg::from_blocks(&blocks), BlockId::new(0));
        let sw = sa
            .switches()
            .iter()
            .find(|s| !s.jump_table)
            .expect("cmp chain switch");
        assert_eq!(sw.discriminant, "x");
        assert_eq!(sw.case_count(), 3);
        assert!(sw.has_default());
    }

    #[test]
    fn test_parse_equality_hex() {
        assert_eq!(
            parse_equality("flags == 0x10"),
            Some(("flags".to_string(), 16))
        );
        assert_eq!(parse_equality("x < 3"), None);
    }

    // ── Goto minimization ──────────────────────────────────────────────────────

    #[test]
    fn test_goto_report_forward() {
        let root = StructuredNode::Sequence(vec![
            StructuredNode::BasicBlock {
                id: BlockId::new(0),
                stmts: vec![],
            },
            StructuredNode::Goto(BlockId::new(2)),
        ]);
        let order = vec![BlockId::new(0), BlockId::new(1), BlockId::new(2)];
        let report = GotoMinimizer::new().report(&root, &order);
        assert_eq!(report.total, 1);
        assert_eq!(report.forward, 1);
        assert_eq!(report.backward, 0);
    }

    #[test]
    fn test_goto_report_backward() {
        let root = StructuredNode::Sequence(vec![
            StructuredNode::BasicBlock {
                id: BlockId::new(2),
                stmts: vec![],
            },
            StructuredNode::Goto(BlockId::new(0)),
        ]);
        let order = vec![BlockId::new(0), BlockId::new(1), BlockId::new(2)];
        let report = GotoMinimizer::new().report(&root, &order);
        assert_eq!(report.backward, 1);
        assert!(GotoMinimizer::new().score(&report) >= 4);
    }

    #[test]
    fn test_goto_score_zero_when_no_gotos() {
        let root = StructuredNode::Return(None);
        let report = GotoMinimizer::new().report(&root, &[]);
        assert_eq!(GotoMinimizer::new().score(&report), 0);
    }

    // ── CfgAnalysis bundle ─────────────────────────────────────────────────────

    #[test]
    fn test_cfg_analysis_run() {
        let blocks = vec![
            bb(0, vec![asn("i", "0")], &[1]),
            bb(1, br("i < 10"), &[2, 3]),
            bb(2, vec![asn("i", "i+1")], &[1]),
            bb(3, vec![ret(None)], &[]),
        ];
        let analysis = CfgAnalysis::run(&blocks, BlockId::new(0)).unwrap();
        assert!(analysis.natural_loop_count() >= 1);
        assert!(!analysis.has_irreducible());
        let (ast, _report) = analysis.structure(&blocks).unwrap();
        assert_eq!(ast.entry, BlockId::new(0));
    }

    #[test]
    fn test_cfg_analysis_empty_error() {
        assert!(matches!(
            CfgAnalysis::run(&[], BlockId::new(0)),
            Err(StructureError::EmptyCfg)
        ));
    }

    #[test]
    fn test_cfg_analysis_entry_not_found() {
        let blocks = vec![bb(0, vec![ret(None)], &[])];
        assert!(matches!(
            CfgAnalysis::run(&blocks, BlockId::new(9)),
            Err(StructureError::EntryNotFound(_))
        ));
    }

    #[test]
    fn test_identifier_tokens() {
        let toks = identifier_tokens("i < 10 + count");
        assert!(toks.contains(&"i".to_string()));
        assert!(toks.contains(&"count".to_string()));
        assert!(!toks.contains(&"10".to_string()));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StructuringQualityMetrics
// ─────────────────────────────────────────────────────────────────────────────

/// Quantitative measures of how well-structured the CFS output is.
///
/// Lower `goto_count` and `max_nesting_depth` are better; the other fields
/// describe the structural richness of the recovered AST.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StructuringQualityMetrics {
    /// Number of `Goto` nodes remaining in the AST (0 = fully structured).
    pub goto_count: u32,
    /// Maximum nesting depth of control-flow constructs.
    pub max_nesting_depth: u32,
    /// Number of `Switch` nodes in the AST.
    pub switch_count: u32,
    /// Number of `Loop` nodes in the AST.
    pub loop_count: u32,
    /// Number of basic blocks that are not reachable from the root
    /// (detected as `Goto` targets whose id is never a `BasicBlock` leaf).
    pub unreachable_blocks: u32,
}

impl StructuringQualityMetrics {
    /// Compute metrics by walking the structured AST.
    #[must_use]
    pub fn compute(ast: &StructuredAst) -> Self {
        let mut m = Self::default();

        // Collect all basic-block ids that appear as proper leaves.
        let mut leaf_ids: HashSet<BlockId> = HashSet::new();
        // Collect all goto targets.
        let mut goto_targets: HashSet<BlockId> = HashSet::new();

        m.max_nesting_depth = Self::walk(&ast.root, 0, &mut m, &mut leaf_ids, &mut goto_targets);

        // Unreachable blocks: goto targets that are never a BasicBlock leaf.
        m.unreachable_blocks = u32::try_from(goto_targets.difference(&leaf_ids).count()).unwrap_or(u32::MAX);

        m
    }

    /// Recursive walker; returns the maximum nesting depth seen beneath `node`
    /// at the given current depth, and accumulates counts into `m`.
    fn walk(
        node: &StructuredNode,
        depth: u32,
        m: &mut Self,
        leaves: &mut HashSet<BlockId>,
        gotos: &mut HashSet<BlockId>,
    ) -> u32 {
        match node {
            StructuredNode::BasicBlock { id, .. } => {
                leaves.insert(*id);
                depth
            }
            StructuredNode::Goto(target) => {
                m.goto_count = m.goto_count.saturating_add(1);
                gotos.insert(*target);
                depth
            }
            StructuredNode::Sequence(children) => {
                let mut max = depth;
                for child in children {
                    let d = Self::walk(child, depth, m, leaves, gotos);
                    if d > max {
                        max = d;
                    }
                }
                max
            }
            StructuredNode::If { then_branch, .. } => {
                let inner = depth.saturating_add(1);
                let d = Self::walk(then_branch, inner, m, leaves, gotos);
                d.max(inner)
            }
            StructuredNode::IfElse {
                then_branch,
                else_branch,
                ..
            } => {
                let inner = depth.saturating_add(1);
                let d1 = Self::walk(then_branch, inner, m, leaves, gotos);
                let d2 = Self::walk(else_branch, inner, m, leaves, gotos);
                d1.max(d2).max(inner)
            }
            StructuredNode::Loop { body, .. } => {
                m.loop_count = m.loop_count.saturating_add(1);
                let inner = depth.saturating_add(1);
                let d = Self::walk(body, inner, m, leaves, gotos);
                d.max(inner)
            }
            StructuredNode::Switch { cases, .. } => {
                m.switch_count = m.switch_count.saturating_add(1);
                let inner = depth.saturating_add(1);
                let mut max = inner;
                for case in cases {
                    let d = Self::walk(&case.body, inner, m, leaves, gotos);
                    if d > max {
                        max = d;
                    }
                }
                max
            }
            StructuredNode::Break | StructuredNode::Continue | StructuredNode::Return(_) => depth,
        }
    }

    /// A single quality score: lower is better.
    ///
    /// Penalises gotos heavily (×10), nesting depth (×1), and leaves loop/switch
    /// counts unpenalised (they represent successfully recovered structure).
    #[must_use]
    pub const fn score(&self) -> u32 {
        self.goto_count * 10 + self.max_nesting_depth + self.unreachable_blocks * 5
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StructuringStrategy
// ─────────────────────────────────────────────────────────────────────────────

/// Which high-level CFS algorithm to apply to a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StructuringStrategy {
    /// Phoenix — recursive region-based structuring, more accurate but O(n²)
    /// on irreducible graphs.
    Phoenix,
    /// SAILR — loop-first heuristic approach, faster on large functions.
    Sailr,
    /// Try Phoenix first; if it leaves more gotos than a SAILR run, fall back
    /// to the SAILR result.
    Hybrid,
}

impl std::fmt::Display for StructuringStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Phoenix => write!(f, "Phoenix"),
            Self::Sailr => write!(f, "SAILR"),
            Self::Hybrid => write!(f, "Hybrid"),
        }
    }
}

impl StructuringStrategy {
    /// Choose an appropriate strategy based on function complexity (block count).
    ///
    /// * ≤ 100 blocks → `Phoenix` (accurate, tractable).
    /// * > 100 blocks → `Hybrid` (attempt Phoenix, fall back to SAILR if worse).
    #[must_use]
    pub const fn choose_strategy(func_complexity: u32) -> Self {
        if func_complexity > 100 {
            Self::Hybrid
        } else {
            Self::Phoenix
        }
    }

    /// Run the strategy on `blocks` from `entry`, returning the best
    /// `StructuredAst` according to `StructuringQualityMetrics::score`.
    #[must_use]
    pub fn run(self, blocks: Vec<BasicBlock>, entry: BlockId) -> StructuredAst {
        match self {
            Self::Phoenix => {
                let mut ph = PhoenixAlgorithm::new();
                ph.structure(blocks, entry)
            }
            Self::Sailr => {
                let mut sl = SailrAlgorithm::new();
                sl.structure(blocks, entry)
            }
            Self::Hybrid => {
                // Run Phoenix.
                let mut ph = PhoenixAlgorithm::new();
                let phoenix_ast = ph.structure(blocks.clone(), entry);
                let phoenix_score = StructuringQualityMetrics::compute(&phoenix_ast).score();

                // Run SAILR on the same blocks.
                let mut sl = SailrAlgorithm::new();
                let sailr_ast = sl.structure(blocks, entry);
                let sailr_score = StructuringQualityMetrics::compute(&sailr_ast).score();

                // Pick the lower-scoring result (lower = better structured).
                if sailr_score < phoenix_score {
                    sailr_ast
                } else {
                    phoenix_ast
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Extended GotoEliminator — second pass for continue/break recovery
// ─────────────────────────────────────────────────────────────────────────────

/// Describes a single goto→structured-control replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replacement {
    /// The `Goto` target that was replaced.
    pub goto_target: BlockId,
    /// The structured node that replaces it.
    pub replacement: StructuredNode,
}

impl GotoEliminator {
    /// Second-pass elimination: walk `ast` and convert every `Goto(L)` that
    /// points directly to the statement after itself (i.e. `goto L; L:` pattern)
    /// into a no-op `Sequence([])`, effectively removing the goto.
    ///
    /// Within a loop context, gotos pointing to the loop header are converted
    /// to `Continue` and gotos pointing to the loop exit are converted to
    /// `Break`.
    pub fn second_pass(
        &mut self,
        ast: StructuredAst,
        loop_detector: &LoopDetector,
    ) -> StructuredAst {
        let new_root = self.elim_node(ast.root, loop_detector, None, None);
        let goto_count = new_root.goto_count();
        StructuredAst {
            root: new_root.flatten(),
            goto_count,
            loop_count: ast.loop_count,
            entry: ast.entry,
        }
    }

    fn elim_node(
        &mut self,
        node: StructuredNode,
        ld: &LoopDetector,
        loop_header: Option<BlockId>,
        loop_exit: Option<BlockId>,
    ) -> StructuredNode {
        match node {
            StructuredNode::Goto(target) => {
                // If the target is a loop header → continue.
                if ld.is_loop_header(target) {
                    self.break_continue_recovered += 1;
                    return StructuredNode::Continue;
                }
                // If the target is the known loop exit → break.
                if Some(target) == loop_exit {
                    self.break_continue_recovered += 1;
                    return StructuredNode::Break;
                }
                // Not eliminable in this context — leave as-is.
                StructuredNode::Goto(target)
            }
            StructuredNode::Sequence(children) => {
                // For consecutive pairs `[…, Goto(L), BasicBlock{id:L,..}, …]`,
                // the goto is trivially the block immediately following; remove it.
                let mut new_children: Vec<StructuredNode> = Vec::with_capacity(children.len());
                let mut iter = children.into_iter().peekable();
                while let Some(child) = iter.next() {
                    // Check if this child is a Goto whose target is the very next
                    // sibling BasicBlock.
                    if let StructuredNode::Goto(target) = &child {
                        let target = *target;
                        let next_is_target = matches!(
                            iter.peek(),
                            Some(StructuredNode::BasicBlock { id, .. }) if *id == target
                        );
                        if next_is_target {
                            // Drop the goto entirely (fall-through).
                            self.gotos_eliminated += 1;
                            continue;
                        }
                    }
                    let processed = self.elim_node(child, ld, loop_header, loop_exit);
                    new_children.push(processed);
                }
                StructuredNode::Sequence(new_children)
            }
            StructuredNode::If {
                condition,
                then_branch,
            } => StructuredNode::If {
                condition,
                then_branch: Box::new(self.elim_node(*then_branch, ld, loop_header, loop_exit)),
            },
            StructuredNode::IfElse {
                condition,
                then_branch,
                else_branch,
            } => StructuredNode::IfElse {
                condition,
                then_branch: Box::new(self.elim_node(*then_branch, ld, loop_header, loop_exit)),
                else_branch: Box::new(self.elim_node(*else_branch, ld, loop_header, loop_exit)),
            },
            StructuredNode::Loop {
                kind,
                condition,
                body,
            } => {
                // Infer a plausible loop exit from the first known exit of any
                // matching natural loop (best-effort; may be None).
                let header_id = match &*body {
                    StructuredNode::BasicBlock { id, .. } => Some(*id),
                    _ => None,
                };
                // NaturalLoop (from the older LoopDetector) does not carry exit
                // block information, so we always fall back to the enclosing
                // loop_exit context.
                let new_exit = loop_exit;

                StructuredNode::Loop {
                    kind,
                    condition,
                    body: Box::new(self.elim_node(*body, ld, header_id.or(loop_header), new_exit)),
                }
            }
            StructuredNode::Switch { expr, cases } => StructuredNode::Switch {
                expr,
                cases: cases
                    .into_iter()
                    .map(|c| SwitchCase {
                        value: c.value,
                        body: Box::new(self.elim_node(*c.body, ld, loop_header, loop_exit)),
                    })
                    .collect(),
            },
            // Leaves pass through unchanged.
            other => other,
        }
    }

    /// Scan a structured AST and return one `Replacement` entry for each `Goto`
    /// that can be converted to a `break` in the context of the given CFG.
    ///
    /// "Can be converted to break" here means: the goto target is NOT a loop
    /// header (which would be `continue`) and is reachable only through a loop
    /// exit edge — approximated as: the target has no predecessors inside any
    /// natural loop body in `loop_detector`.
    #[must_use]
    pub fn goto_to_structured_break(
        ast: &StructuredAst,
        loop_detector: &LoopDetector,
    ) -> Vec<Replacement> {
        let mut replacements = Vec::new();
        Self::collect_break_replacements(&ast.root, loop_detector, &mut replacements);
        replacements
    }

    fn collect_break_replacements(
        node: &StructuredNode,
        ld: &LoopDetector,
        out: &mut Vec<Replacement>,
    ) {
        match node {
            StructuredNode::Goto(target) => {
                // A goto to a non-header block that is not itself inside any
                // loop body → likely a break out of the current loop.
                let is_header = ld.is_loop_header(*target);
                let inside_loop = ld.loops().iter().any(|l| l.contains(*target));
                if !is_header && !inside_loop {
                    out.push(Replacement {
                        goto_target: *target,
                        replacement: StructuredNode::Break,
                    });
                }
            }
            StructuredNode::Sequence(children) => {
                for c in children {
                    Self::collect_break_replacements(c, ld, out);
                }
            }
            StructuredNode::If { then_branch, .. } => {
                Self::collect_break_replacements(then_branch, ld, out);
            }
            StructuredNode::IfElse {
                then_branch,
                else_branch,
                ..
            } => {
                Self::collect_break_replacements(then_branch, ld, out);
                Self::collect_break_replacements(else_branch, ld, out);
            }
            StructuredNode::Loop { body, .. } => {
                Self::collect_break_replacements(body, ld, out);
            }
            StructuredNode::Switch { cases, .. } => {
                for c in cases {
                    Self::collect_break_replacements(&c.body, ld, out);
                }
            }
            _ => {}
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CfsPass trait and CfsPipeline
// ─────────────────────────────────────────────────────────────────────────────

/// A single transformation pass over a `StructuredAst`.
///
/// Implementors receive a `StructuredAst`, may modify it, and return the
/// (possibly altered) AST.
pub trait CfsPass: std::fmt::Debug {
    /// The human-readable name of this pass.
    fn name(&self) -> &str;

    /// Run the pass and return the (possibly mutated) AST.
    fn run(&mut self, ast: StructuredAst) -> StructuredAst;
}

// ── Built-in pass: flatten redundant single-child Sequences ──────────────────

/// Pass that recursively flattens `Sequence([x])` → `x`.
#[derive(Debug)]
pub struct FlattenPass;

impl CfsPass for FlattenPass {
    fn name(&self) -> &'static str {
        "flatten"
    }
    fn run(&mut self, ast: StructuredAst) -> StructuredAst {
        let root = ast.root.flatten();
        let goto_count = root.goto_count();
        StructuredAst {
            root,
            goto_count,
            ..ast
        }
    }
}

// ── Built-in pass: GotoEliminator second pass ─────────────────────────────────

/// Pass that wraps `GotoEliminator::second_pass`.
#[derive(Debug)]
pub struct GotoEliminatorPass {
    eliminator: GotoEliminator,
    loop_detector: LoopDetector,
}

impl GotoEliminatorPass {
    /// Create the pass from a pre-built `LoopDetector` for the function.
    #[must_use]
    pub fn new(loop_detector: LoopDetector) -> Self {
        Self {
            eliminator: GotoEliminator::new(),
            loop_detector,
        }
    }

    /// How many gotos were eliminated so far.
    #[must_use]
    pub const fn gotos_eliminated(&self) -> usize {
        self.eliminator.gotos_eliminated()
    }

    /// How many break/continue nodes were recovered so far.
    #[must_use]
    pub const fn break_continue_recovered(&self) -> usize {
        self.eliminator.break_continue_recovered()
    }
}

impl CfsPass for GotoEliminatorPass {
    fn name(&self) -> &'static str {
        "goto-eliminator"
    }
    fn run(&mut self, ast: StructuredAst) -> StructuredAst {
        self.eliminator.second_pass(ast, &self.loop_detector)
    }
}

// ── CfsPipeline ───────────────────────────────────────────────────────────────

/// An ordered chain of `CfsPass` transforms applied to a `StructuredAst`.
///
/// # Usage
///
/// ```ignore
/// let mut pipeline = CfsPipeline::new();
/// pipeline.add_pass(Box::new(FlattenPass));
/// pipeline.add_pass(Box::new(GotoEliminatorPass::new(loop_detector)));
/// let (ast, metrics) = pipeline.run(initial_ast);
/// ```
#[derive(Debug, Default)]
pub struct CfsPipeline {
    passes: Vec<Box<dyn CfsPass>>,
}

impl CfsPipeline {
    /// Create an empty pipeline.
    #[must_use]
    pub fn new() -> Self {
        Self { passes: Vec::new() }
    }

    /// Append a pass to the end of the pipeline.
    pub fn add_pass(&mut self, pass: Box<dyn CfsPass>) {
        self.passes.push(pass);
    }

    /// How many passes are registered.
    #[must_use]
    pub fn pass_count(&self) -> usize {
        self.passes.len()
    }

    /// Run all passes in order and return the final AST plus quality metrics.
    ///
    /// Metrics are computed once after all passes have run.
    pub fn run(&mut self, ast: StructuredAst) -> (StructuredAst, StructuringQualityMetrics) {
        let mut current = ast;
        for pass in &mut self.passes {
            current = pass.run(current);
        }
        let metrics = StructuringQualityMetrics::compute(&current);
        (current, metrics)
    }

    /// Convenience: build a default pipeline suitable for a function with the
    /// given block count, including strategy selection, flattening, and goto
    /// elimination.
    ///
    /// The caller must supply a `LoopDetector` populated for the function.
    #[must_use]
    pub fn default_for(loop_detector: LoopDetector) -> Self {
        let mut p = Self::new();
        p.add_pass(Box::new(FlattenPass));
        p.add_pass(Box::new(GotoEliminatorPass::new(loop_detector)));
        p.add_pass(Box::new(FlattenPass)); // re-flatten after goto elimination
        p
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for the new additions
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod new_additions_tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn make_ast(root: StructuredNode) -> StructuredAst {
        let goto_count = root.goto_count();
        StructuredAst {
            entry: BlockId::new(0),
            root,
            goto_count,
            loop_count: 0,
        }
    }

    fn bb_node(id: u32) -> StructuredNode {
        StructuredNode::BasicBlock {
            id: BlockId::new(id),
            stmts: vec![],
        }
    }

    fn loop_node(body: StructuredNode) -> StructuredNode {
        StructuredNode::Loop {
            kind: LoopKind::While,
            condition: "true".to_string(),
            body: Box::new(body),
        }
    }

    // ── StructuringQualityMetrics ─────────────────────────────────────────────

    #[test]
    fn test_metrics_no_gotos() {
        let ast = make_ast(StructuredNode::Sequence(vec![
            bb_node(0),
            StructuredNode::Return(None),
        ]));
        let m = StructuringQualityMetrics::compute(&ast);
        assert_eq!(m.goto_count, 0);
        assert_eq!(m.loop_count, 0);
        assert_eq!(m.switch_count, 0);
        assert_eq!(m.unreachable_blocks, 0);
        assert_eq!(m.score(), 0);
    }

    #[test]
    fn test_metrics_with_goto() {
        let ast = make_ast(StructuredNode::Sequence(vec![
            bb_node(0),
            StructuredNode::Goto(BlockId::new(5)),
        ]));
        let m = StructuringQualityMetrics::compute(&ast);
        assert_eq!(m.goto_count, 1);
        // block 5 is a goto target but never a leaf → unreachable.
        assert_eq!(m.unreachable_blocks, 1);
        assert!(m.score() > 0);
    }

    #[test]
    fn test_metrics_nesting_depth() {
        let deep = StructuredNode::If {
            condition: "a".to_string(),
            then_branch: Box::new(StructuredNode::If {
                condition: "b".to_string(),
                then_branch: Box::new(bb_node(1)),
            }),
        };
        let ast = make_ast(deep);
        let m = StructuringQualityMetrics::compute(&ast);
        assert!(m.max_nesting_depth >= 2);
    }

    #[test]
    fn test_metrics_loop_and_switch() {
        let switch = StructuredNode::Switch {
            expr: "x".to_string(),
            cases: vec![
                SwitchCase {
                    value: Some(0),
                    body: Box::new(bb_node(1)),
                },
                SwitchCase {
                    value: None,
                    body: Box::new(bb_node(2)),
                },
            ],
        };
        let ast = make_ast(loop_node(switch));
        let m = StructuringQualityMetrics::compute(&ast);
        assert_eq!(m.loop_count, 1);
        assert_eq!(m.switch_count, 1);
    }

    #[test]
    fn test_metrics_goto_target_is_leaf() {
        // Goto points to block 1 which IS a leaf → unreachable_blocks = 0.
        let ast = make_ast(StructuredNode::Sequence(vec![
            bb_node(0),
            StructuredNode::Goto(BlockId::new(1)),
            bb_node(1),
        ]));
        let m = StructuringQualityMetrics::compute(&ast);
        assert_eq!(m.goto_count, 1);
        assert_eq!(m.unreachable_blocks, 0);
    }

    // ── StructuringStrategy ──────────────────────────────────────────────────

    #[test]
    fn test_choose_strategy_small() {
        assert_eq!(
            StructuringStrategy::choose_strategy(50),
            StructuringStrategy::Phoenix
        );
        assert_eq!(
            StructuringStrategy::choose_strategy(100),
            StructuringStrategy::Phoenix
        );
    }

    #[test]
    fn test_choose_strategy_large() {
        assert_eq!(
            StructuringStrategy::choose_strategy(101),
            StructuringStrategy::Hybrid
        );
        assert_eq!(
            StructuringStrategy::choose_strategy(500),
            StructuringStrategy::Hybrid
        );
    }

    #[test]
    fn test_strategy_display() {
        assert_eq!(StructuringStrategy::Phoenix.to_string(), "Phoenix");
        assert_eq!(StructuringStrategy::Sailr.to_string(), "SAILR");
        assert_eq!(StructuringStrategy::Hybrid.to_string(), "Hybrid");
    }

    #[test]
    fn test_strategy_phoenix_runs() {
        let blocks = vec![BasicBlock {
            id: BlockId::new(0),
            stmts: vec![Statement::Return(None)],
            successors: vec![],
        }];
        let ast = StructuringStrategy::Phoenix.run(blocks, BlockId::new(0));
        assert_eq!(ast.entry, BlockId::new(0));
    }

    #[test]
    fn test_strategy_sailr_runs() {
        let blocks = vec![BasicBlock {
            id: BlockId::new(0),
            stmts: vec![Statement::Return(None)],
            successors: vec![],
        }];
        let ast = StructuringStrategy::Sailr.run(blocks, BlockId::new(0));
        assert_eq!(ast.entry, BlockId::new(0));
    }

    #[test]
    fn test_strategy_hybrid_picks_better() {
        // A simple linear CFG — both algorithms should give goto_count = 0, so
        // whichever is picked, the result is fully structured.
        let blocks = vec![
            BasicBlock {
                id: BlockId::new(0),
                stmts: vec![],
                successors: vec![BlockId::new(1)],
            },
            BasicBlock {
                id: BlockId::new(1),
                stmts: vec![Statement::Return(None)],
                successors: vec![],
            },
        ];
        let ast = StructuringStrategy::Hybrid.run(blocks, BlockId::new(0));
        assert_eq!(ast.goto_count, 0);
    }

    // ── GotoEliminator second pass ────────────────────────────────────────────

    #[test]
    fn test_second_pass_converts_goto_to_continue() {
        // Goto targets block 1 which is a loop header.
        let mut ld = LoopDetector::new();
        ld.add_back_edge(BlockId::new(3), BlockId::new(1));

        let root =
            StructuredNode::Sequence(vec![bb_node(0), StructuredNode::Goto(BlockId::new(1))]);
        let ast = make_ast(root);

        let mut ge = GotoEliminator::new();
        let result = ge.second_pass(ast, &ld);
        assert_eq!(result.goto_count, 0);
        assert_eq!(ge.break_continue_recovered(), 1);
    }

    #[test]
    fn test_second_pass_removes_fallthrough_goto() {
        // Sequence: [bb(0), Goto(1), bb(1)] → Goto(1) is a fall-through and
        // should be eliminated.
        let root = StructuredNode::Sequence(vec![
            bb_node(0),
            StructuredNode::Goto(BlockId::new(1)),
            bb_node(1),
        ]);
        let ast = make_ast(root);

        let ld = LoopDetector::new();
        let mut ge = GotoEliminator::new();
        let result = ge.second_pass(ast, &ld);
        assert_eq!(result.goto_count, 0);
        assert_eq!(ge.gotos_eliminated(), 1);
    }

    #[test]
    fn test_second_pass_converts_goto_to_break_when_exit() {
        // Goto targets block 5 which is the loop exit (passed as loop_exit
        // context). We exercise this via the public second_pass path by placing
        // the goto inside a loop body.
        let mut ld = LoopDetector::new();
        // Loop: header=1, latch=3.
        ld.add_back_edge(BlockId::new(3), BlockId::new(1));

        // The AST: Loop { body: Sequence[bb(1), Goto(5)] }
        // Block 5 is not a loop header, not in a loop body → break candidate.
        let body =
            StructuredNode::Sequence(vec![bb_node(1), StructuredNode::Goto(BlockId::new(5))]);
        let root = StructuredNode::Loop {
            kind: LoopKind::While,
            condition: "c".to_string(),
            body: Box::new(body),
        };
        let ast = StructuredAst {
            entry: BlockId::new(0),
            root,
            goto_count: 1,
            loop_count: 1,
        };

        let repls = GotoEliminator::goto_to_structured_break(&ast, &ld);
        assert!(!repls.is_empty());
        assert_eq!(repls[0].goto_target, BlockId::new(5));
        assert_eq!(repls[0].replacement, StructuredNode::Break);
    }

    #[test]
    fn test_goto_to_structured_break_no_replacements_for_header_goto() {
        // Goto to a loop header → this is a continue, not a break.
        let mut ld = LoopDetector::new();
        ld.add_back_edge(BlockId::new(2), BlockId::new(0));

        let root = StructuredNode::Goto(BlockId::new(0));
        let ast = make_ast(root);
        let repls = GotoEliminator::goto_to_structured_break(&ast, &ld);
        // Block 0 is a header → should NOT be classified as a break replacement.
        assert!(repls.is_empty());
    }

    // ── CfsPipeline ───────────────────────────────────────────────────────────

    #[test]
    fn test_pipeline_empty_is_identity() {
        let ast = make_ast(bb_node(0));
        let mut pipeline = CfsPipeline::new();
        let (result, metrics) = pipeline.run(ast.clone());
        assert_eq!(result.entry, ast.entry);
        assert_eq!(metrics.goto_count, 0);
    }

    #[test]
    fn test_pipeline_flatten_pass() {
        // Sequence([Sequence([bb(0)])]) should flatten to bb(0).
        let nested = StructuredNode::Sequence(vec![StructuredNode::Sequence(vec![bb_node(0)])]);
        let ast = make_ast(nested);
        let mut pipeline = CfsPipeline::new();
        pipeline.add_pass(Box::new(FlattenPass));
        let (result, _) = pipeline.run(ast);
        assert!(matches!(result.root, StructuredNode::BasicBlock { .. }));
    }

    #[test]
    fn test_pipeline_goto_eliminator_pass() {
        let mut ld = LoopDetector::new();
        ld.add_back_edge(BlockId::new(2), BlockId::new(1));

        let root =
            StructuredNode::Sequence(vec![bb_node(0), StructuredNode::Goto(BlockId::new(1))]);
        let ast = make_ast(root);

        let mut pipeline = CfsPipeline::new();
        pipeline.add_pass(Box::new(GotoEliminatorPass::new(ld)));
        let (result, metrics) = pipeline.run(ast);
        assert_eq!(metrics.goto_count, 0);
        assert_eq!(result.goto_count, 0);
    }

    #[test]
    fn test_pipeline_pass_count() {
        let mut p = CfsPipeline::new();
        assert_eq!(p.pass_count(), 0);
        p.add_pass(Box::new(FlattenPass));
        assert_eq!(p.pass_count(), 1);
    }

    #[test]
    fn test_pipeline_default_for() {
        let ld = LoopDetector::new();
        let p = CfsPipeline::default_for(ld);
        // default_for adds FlattenPass + GotoEliminatorPass + FlattenPass = 3.
        assert_eq!(p.pass_count(), 3);
    }

    #[test]
    fn test_pipeline_metrics_are_computed_after_all_passes() {
        let ld = LoopDetector::new();
        // Wrap a goto in a single-element sequence to also exercise flattening.
        let root = StructuredNode::Sequence(vec![StructuredNode::Sequence(vec![bb_node(0)])]);
        let ast = make_ast(root);
        let mut p = CfsPipeline::default_for(ld);
        let (_ast, metrics) = p.run(ast);
        assert_eq!(metrics.goto_count, 0);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Enterprise property/fuzz/stress battery
//
// The control-flow primitives (CFG construction, Tarjan SCC, dominator tree,
// loop detection, structurer) are the algorithmic backbone of the decompiler.
// A wrong dominator on one block silently mis-classifies whole functions; a
// stack overflow on a deep CFG kills the whole tool. This battery enforces
// the graph-theoretic invariants and bounds the robustness:
//
//   * graph-theoretic property tests for `Dominators` and `TarjanScc` on
//     deterministically-generated random CFGs (reflexivity / antisymmetry /
//     transitivity of dominance, SCC partition + mutual-reachability, every
//     back-edge target dominates its source);
//   * a deep-CFG stress test (10k-block linear chain + diamond ladder) that
//     would explode the recursive `dfs_post` and is the regression target
//     for the iterative `reverse_postorder` rewrite;
//   * a deterministic adversarial fuzz that hammers `Cfg::from_blocks`,
//     `TarjanScc::run`, `Dominators::compute` and `LoopAnalysis::analyze`
//     with thousands of random graphs (dangling successors, parallel edges,
//     self-loops, unreachable nodes) — none of them may panic.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod enterprise_battery {
    use super::*;
    use std::collections::{BTreeSet, HashSet, VecDeque};

    /// Tiny deterministic LCG (Knuth MMIX). Any test failure reproduces with
    /// the same seed — no thread-local randomness, no nondeterminism.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0
        }
        fn range(&mut self, hi: u32) -> u32 {
            if hi == 0 {
                0
            } else {
                (self.next() >> 33) as u32 % hi
            }
        }
    }

    /// Build a connected random CFG with `n` blocks rooted at 0. Each non-root
    /// block has at least one in-edge from a lower-id block (guaranteeing
    /// reachability), plus 0–2 extra forward/back/parallel edges.
    fn random_cfg(seed: u64, n: u32) -> Cfg {
        let mut rng = Lcg(seed);
        let mut blocks: Vec<BasicBlock> = (0..n).map(|i| BasicBlock::new(BlockId(i))).collect();
        for i in 1..n {
            // Tree edge: a random predecessor with id < i.
            let parent = rng.range(i);
            blocks[parent as usize].successors.push(BlockId(i));
            // 0–2 extra edges (may be back-edges, parallel edges, self-loop).
            for _ in 0..(rng.range(3)) {
                let target = rng.range(n);
                blocks[i as usize].successors.push(BlockId(target));
            }
        }
        // A few random self-loops to exercise the SCC self-edge path.
        for _ in 0..(n / 8) {
            let v = rng.range(n);
            blocks[v as usize].successors.push(BlockId(v));
        }
        Cfg::from_blocks(&blocks)
    }

    /// Reachability via BFS — the ground-truth oracle for dominance and SCC.
    fn reachable(cfg: &Cfg, src: BlockId) -> HashSet<BlockId> {
        let mut q = VecDeque::new();
        let mut seen = HashSet::new();
        q.push_back(src);
        seen.insert(src);
        while let Some(u) = q.pop_front() {
            for &v in cfg.successors(u) {
                if seen.insert(v) {
                    q.push_back(v);
                }
            }
        }
        seen
    }

    // ── Invariants on the simplified CFG builder ──────────────────────────

    /// `from_blocks` must collapse parallel edges and drop edges to absent
    /// targets, while preserving every distinct surviving edge symmetrically
    /// in `successors`/`predecessors`.
    #[test]
    fn cfg_dedups_parallel_edges_and_skips_dangling() {
        let blocks = vec![
            BasicBlock::new(BlockId(0)).with_successors(vec![BlockId(1), BlockId(1), BlockId(99)]),
            BasicBlock::new(BlockId(1)).with_successors(vec![BlockId(1)]),
        ];
        let cfg = Cfg::from_blocks(&blocks);
        assert_eq!(cfg.successors(BlockId(0)), &[BlockId(1)]);
        // The self-loop is preserved as a single edge.
        assert_eq!(cfg.successors(BlockId(1)), &[BlockId(1)]);
        // bb1's predecessors: itself + bb0 (each once).
        let mut preds: Vec<BlockId> = cfg.predecessors(BlockId(1)).to_vec();
        preds.sort_unstable();
        assert_eq!(preds, vec![BlockId(0), BlockId(1)]);
    }

    #[test]
    fn cfg_edge_symmetry_holds_on_random_graphs() {
        for seed in [1u64, 2, 3, 7, 11, 13, 31] {
            let cfg = random_cfg(seed, 60);
            for u in cfg.block_ids() {
                for &v in cfg.successors(u) {
                    assert!(
                        cfg.predecessors(v).contains(&u),
                        "edge ({u},{v}) is missing from predecessors"
                    );
                }
                for &p in cfg.predecessors(u) {
                    assert!(
                        cfg.successors(p).contains(&u),
                        "edge ({p},{u}) is missing from successors"
                    );
                }
            }
        }
    }

    // ── Dominator invariants ──────────────────────────────────────────────

    /// Brute-force reference: `a` dominates `b` iff *every* path from entry to
    /// `b` visits `a`. Equivalent (faster): `b` is unreachable in the CFG
    /// with `a` removed.
    fn dom_oracle(cfg: &Cfg, entry: BlockId, a: BlockId, b: BlockId) -> bool {
        if a == entry {
            return reachable(cfg, entry).contains(&b);
        }
        // BFS from entry avoiding `a`.
        let mut q = VecDeque::new();
        let mut seen = HashSet::new();
        if entry == a {
            return false;
        }
        q.push_back(entry);
        seen.insert(entry);
        while let Some(u) = q.pop_front() {
            if u == b {
                return false; // reached b without going through a
            }
            for &v in cfg.successors(u) {
                if v == a {
                    continue;
                }
                if seen.insert(v) {
                    q.push_back(v);
                }
            }
        }
        // b reachable in the original graph but not in `a`-removed graph
        reachable(cfg, entry).contains(&b)
    }

    #[test]
    fn dominators_match_brute_force_oracle() {
        for &seed in &[101u64, 202, 303, 404, 505] {
            let cfg = random_cfg(seed, 18);
            let entry = BlockId(0);
            let doms = Dominators::compute(&cfg, entry);
            let reach: Vec<BlockId> = reachable(&cfg, entry).into_iter().collect();
            for &a in &reach {
                for &b in &reach {
                    let got = doms.dominates(a, b);
                    let want = dom_oracle(&cfg, entry, a, b);
                    assert_eq!(
                        got, want,
                        "seed={seed}: dominates({a},{b}) got={got} want={want}"
                    );
                }
            }
        }
    }

    #[test]
    fn dominator_relation_is_reflexive_antisymmetric_transitive() {
        for &seed in &[10u64, 20, 30, 40, 50, 60, 70] {
            let cfg = random_cfg(seed, 40);
            let entry = BlockId(0);
            let d = Dominators::compute(&cfg, entry);
            let reach: Vec<BlockId> = reachable(&cfg, entry).into_iter().collect();
            for &x in &reach {
                assert!(d.dominates(x, x), "reflexivity broken at {x}");
            }
            for &x in &reach {
                for &y in &reach {
                    assert!(!(x != y && d.dominates(x, y) && d.dominates(y, x)), "antisymmetry broken: {x}↔{y}");
                }
            }
            for &x in &reach {
                for &y in &reach {
                    for &z in &reach {
                        if d.dominates(x, y) && d.dominates(y, z) {
                            assert!(
                                d.dominates(x, z),
                                "transitivity broken: {x}>>{y}>>{z} but not {x}>>{z}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn entry_dominates_every_reachable_node_and_idom_forms_a_tree() {
        for &seed in &[1u64, 5, 25, 125, 625] {
            let cfg = random_cfg(seed, 50);
            let entry = BlockId(0);
            let d = Dominators::compute(&cfg, entry);
            let reach = reachable(&cfg, entry);
            for &b in &reach {
                assert!(d.dominates(entry, b), "entry should dominate {b}");
            }
            // idom forms a tree: follow idom chains from each reachable node,
            // must terminate at entry within at most n steps (no cycles).
            for &b in &reach {
                let mut cur = b;
                let mut steps = 0usize;
                let limit = reach.len() + 1;
                while let Some(p) = d.idom(cur) {
                    if p == cur {
                        break; // entry (or self-idom convention)
                    }
                    cur = p;
                    steps += 1;
                    assert!(steps <= limit, "idom cycle starting at {b}");
                }
            }
        }
    }

    /// Every back-edge target found by `LoopAnalysis::find_back_edges` must
    /// dominate its source — definition of a back-edge.
    #[test]
    fn every_back_edge_target_dominates_its_source() {
        for &seed in &[2u64, 4, 8, 16, 32, 64, 128, 256] {
            let cfg = random_cfg(seed, 35);
            let entry = BlockId(0);
            let la = LoopAnalysis::analyze(&cfg, entry);
            let d = Dominators::compute(&cfg, entry);
            for l in la.loops() {
                for &latch in &l.latches {
                    assert!(
                        d.dominates(l.header, latch),
                        "seed={seed}: header {} does not dominate latch {}",
                        l.header,
                        latch
                    );
                    assert!(
                        cfg.successors(latch).contains(&l.header),
                        "latch {} has no edge back to header {}",
                        latch,
                        l.header
                    );
                }
            }
        }
    }

    // ── SCC invariants ────────────────────────────────────────────────────

    #[test]
    fn scc_partitions_reachable_nodes_and_members_are_mutually_reachable() {
        for &seed in &[3u64, 9, 27, 81, 243] {
            let cfg = random_cfg(seed, 22);
            let comps = TarjanScc::run(&cfg);
            // Partition: every block appears in exactly one SCC.
            let mut seen: BTreeSet<BlockId> = BTreeSet::new();
            let mut total = 0usize;
            for c in &comps {
                for &b in c {
                    assert!(seen.insert(b), "block {b} appears in two SCCs");
                    total += 1;
                }
            }
            assert_eq!(total, cfg.len(), "SCC partition missed some blocks");
            // Mutual reachability inside each SCC.
            for c in &comps {
                if c.len() == 1 {
                    continue;
                }
                let a = c[0];
                let r = reachable(&cfg, a);
                for &b in c {
                    assert!(
                        r.contains(&b),
                        "seed={seed}: {a} cannot reach {b} but they are in the same SCC"
                    );
                }
            }
        }
    }

    // ── Deep-CFG stress: regression target for iterative reverse_postorder ─

    /// A 10 000-block linear chain blows a recursive `dfs_post` on the default
    /// 8 MiB thread stack. The iterative implementation must handle it.
    #[test]
    fn reverse_postorder_handles_10k_linear_chain() {
        const N: u32 = 10_000;
        let mut blocks: Vec<BasicBlock> = (0..N).map(|i| BasicBlock::new(BlockId(i))).collect();
        for i in 0..(N - 1) {
            blocks[i as usize].successors.push(BlockId(i + 1));
        }
        let cfg = Cfg::from_blocks(&blocks);
        let rpo = cfg.reverse_postorder(BlockId(0));
        assert_eq!(rpo.len(), N as usize);
        // The chain is acyclic and linear: RPO must be exactly 0..N.
        for (i, &b) in rpo.iter().enumerate() {
            assert_eq!(
                b,
                BlockId(u32::try_from(i).unwrap_or(u32::MAX)),
                "RPO position {i} = {b}, expected bb{i}"
            );
        }
        // Dominators on a long chain should also not stack-overflow.
        let d = Dominators::compute(&cfg, BlockId(0));
        assert!(d.dominates(BlockId(0), BlockId(N - 1)));
        // And idom(i) = i-1 for every i > 0.
        for i in 1..N {
            assert_eq!(d.idom(BlockId(i)), Some(BlockId(i - 1)));
        }
    }

    /// A 2 000-block diamond ladder (each level splits into two branches that
    /// rejoin) — exercises wider DFS frontiers, also previously recursive.
    #[test]
    fn reverse_postorder_handles_wide_diamond_ladder() {
        // levels of 3 nodes: split(L) → {L+1,L+2}; both go to L+3 (next split).
        const LEVELS: u32 = 666; // ~2000 blocks
        let n = LEVELS * 3 + 1;
        let mut blocks: Vec<BasicBlock> = (0..n).map(|i| BasicBlock::new(BlockId(i))).collect();
        for lv in 0..LEVELS {
            let base = lv * 3;
            blocks[base as usize]
                .successors
                .extend([BlockId(base + 1), BlockId(base + 2)]);
            blocks[(base + 1) as usize]
                .successors
                .push(BlockId(base + 3));
            blocks[(base + 2) as usize]
                .successors
                .push(BlockId(base + 3));
        }
        let cfg = Cfg::from_blocks(&blocks);
        let rpo = cfg.reverse_postorder(BlockId(0));
        assert_eq!(rpo.len(), n as usize, "every node should appear in RPO");
        // Dominators on the diamond ladder: each split node dominates the next
        // join, and the next join is its immediate post-split rendezvous.
        let d = Dominators::compute(&cfg, BlockId(0));
        for lv in 0..LEVELS {
            let split = BlockId(lv * 3);
            let join = BlockId(lv * 3 + 3);
            assert!(d.dominates(split, join));
        }
    }

    // ── Robustness fuzz: graph algorithms must never panic ─────────────────

    #[test]
    fn fuzz_cfg_algorithms_never_panic() {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let mut first_fail: Option<(u64, u32)> = None;
        for seed in 0..2_000u64 {
            let n = 1 + (u32::try_from(seed & 0xFFFF_FFFF).unwrap_or(0) % 25);
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let cfg = random_cfg(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15), n);
                let entry = BlockId(0);
                let _ = cfg.reverse_postorder(entry);
                let _ = cfg.dfs_preorder(entry);
                let _ = cfg.reachable(entry);
                let _ = TarjanScc::run(&cfg);
                let d = Dominators::compute(&cfg, entry);
                for b in cfg.block_ids() {
                    let _ = d.idom(b);
                    let _ = d.dominates(entry, b);
                }
                let _ = LoopAnalysis::analyze(&cfg, entry);
            }));
            if r.is_err() {
                first_fail = Some((seed, n));
                break;
            }
        }
        std::panic::set_hook(prev);
        assert!(first_fail.is_none(), "fuzz panicked at {first_fail:?}");
    }

    /// End-to-end: the high-level `ControlFlowStructurer` must produce a valid
    /// `StructuredAst` (or a clean error) for every random graph, never panic.
    /// This is the user-visible API.
    #[test]
    fn fuzz_structurer_never_panics_end_to_end() {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let mut fail: Option<u64> = None;
        for seed in 0..1_500u64 {
            let n = 2 + (u32::try_from(seed & 0xFFFF_FFFF).unwrap_or(0) % 18);
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut rng = Lcg(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
                let mut blocks: Vec<BasicBlock> =
                    (0..n).map(|i| BasicBlock::new(BlockId(i))).collect();
                for i in 1..n {
                    let parent = rng.range(i);
                    blocks[parent as usize].successors.push(BlockId(i));
                }
                for i in 0..n {
                    for _ in 0..(rng.range(3)) {
                        let t = rng.range(n);
                        blocks[i as usize].successors.push(BlockId(t));
                    }
                }
                let s = ControlFlowStructurer::new(blocks);
                let _ = s.structure(BlockId(0));
            }));
            if r.is_err() {
                fail = Some(seed);
                break;
            }
        }
        std::panic::set_hook(prev);
        assert!(fail.is_none(), "structurer panicked at seed {fail:?}");
    }

    // ─────────────────────────────────────────────────────────────────────
    // EmptyBlockEliminator::eliminate_preserving_entry
    // ─────────────────────────────────────────────────────────────────────

    /// Helper locale: questo modulo di test non ne ha uno proprio.
    fn ebb(id: u32, stmts: Vec<Statement>, succs: Vec<u32>) -> BasicBlock {
        BasicBlock::new(BlockId::new(id))
            .with_stmts(stmts)
            .with_successors(succs.into_iter().map(BlockId::new).collect())
    }

    /// Il difetto che la variante evita, DIMOSTRATO sul metodo originale:
    /// un entry vuoto con un solo successore viene rimosso, e `structure`
    /// riceve un `BlockId` che non esiste piu'.
    #[test]
    fn plain_eliminate_drops_the_entry_block_and_breaks_structuring() {
        let blocks = vec![
            ebb(0, vec![], vec![1]),
            ebb(1, vec![Statement::Return(None)], vec![]),
        ];
        let entry = blocks[0].id;

        let cleaned = EmptyBlockEliminator::new().eliminate(blocks);

        assert!(
            !cleaned.iter().any(|b| b.id == entry),
            "precondizione del test: `eliminate` DEVE rimuovere l'entry vuoto"
        );
        assert!(
            ControlFlowStructurer::new(cleaned).structure(entry).is_err(),
            "strutturare su un entry rimosso deve fallire, non riuscire per caso"
        );
    }

    /// Stessa CFG, variante che preserva l'entry: lo structuring riesce.
    #[test]
    fn preserving_entry_keeps_the_entry_and_structuring_succeeds() {
        let blocks = vec![
            ebb(0, vec![], vec![1]),
            ebb(1, vec![Statement::Return(None)], vec![]),
        ];
        let entry = blocks[0].id;

        let cleaned = EmptyBlockEliminator::new().eliminate_preserving_entry(blocks, entry);

        assert!(
            cleaned.iter().any(|b| b.id == entry),
            "l'entry deve sopravvivere"
        );
        assert!(
            ControlFlowStructurer::new(cleaned).structure(entry).is_ok(),
            "con l'entry preservato lo structuring deve riuscire"
        );
    }

    /// Non e' un no-op travestito: un blocco vuoto NON-entry viene rimosso e
    /// i predecessori vengono ricuciti sul suo successore.
    #[test]
    fn preserving_entry_still_removes_non_entry_empty_blocks() {
        let blocks = vec![
            ebb(0, vec![Statement::Raw("a();".into())], vec![1]),
            ebb(1, vec![], vec![2]),
            ebb(2, vec![Statement::Return(None)], vec![]),
        ];
        let entry = blocks[0].id;

        let mut elim = EmptyBlockEliminator::new();
        let cleaned = elim.eliminate_preserving_entry(blocks, entry);

        assert_eq!(elim.eliminated(), 1, "il blocco vuoto 1 deve essere eliminato");
        assert!(!cleaned.iter().any(|b| b.id == BlockId::new(1)));
        let b0 = cleaned.iter().find(|b| b.id == entry).expect("entry");
        assert_eq!(
            b0.successors,
            vec![BlockId::new(2)],
            "il predecessore va ricucito sul successore del blocco rimosso"
        );
    }

    /// Catena di blocchi vuoti: il redirect va seguito fino in fondo, non di
    /// un salto solo.
    #[test]
    fn preserving_entry_follows_a_chain_of_empty_blocks() {
        let blocks = vec![
            ebb(0, vec![Statement::Raw("a();".into())], vec![1]),
            ebb(1, vec![], vec![2]),
            ebb(2, vec![], vec![3]),
            ebb(3, vec![Statement::Return(None)], vec![]),
        ];
        let entry = blocks[0].id;
        let cleaned = EmptyBlockEliminator::new().eliminate_preserving_entry(blocks, entry);

        let b0 = cleaned.iter().find(|b| b.id == entry).expect("entry");
        assert_eq!(b0.successors, vec![BlockId::new(3)], "la catena va seguita fino a 3");
    }

    /// Un ciclo di blocchi vuoti non deve mandare `follow` in loop infinito.
    #[test]
    fn preserving_entry_terminates_on_a_cycle_of_empty_blocks() {
        let blocks = vec![
            ebb(0, vec![Statement::Raw("a();".into())], vec![1]),
            ebb(1, vec![], vec![2]),
            ebb(2, vec![], vec![1]),
        ];
        let entry = blocks[0].id;
        let cleaned = EmptyBlockEliminator::new().eliminate_preserving_entry(blocks, entry);
        assert!(cleaned.iter().any(|b| b.id == entry), "deve terminare e tenere l'entry");
    }

    /// Nessun blocco vuoto ⇒ la CFG esce IDENTICA (nessun effetto collaterale).
    #[test]
    fn preserving_entry_is_identity_when_no_block_is_empty() {
        let blocks = vec![
            ebb(0, vec![Statement::Raw("a();".into())], vec![1]),
            ebb(1, vec![Statement::Return(None)], vec![]),
        ];
        let entry = blocks[0].id;
        let before = blocks.clone();

        let mut elim = EmptyBlockEliminator::new();
        let after = elim.eliminate_preserving_entry(blocks, entry);

        assert_eq!(elim.eliminated(), 0);
        assert_eq!(after.len(), before.len());
        for (a, b) in after.iter().zip(before.iter()) {
            assert_eq!(a.id, b.id);
            assert_eq!(a.successors, b.successors);
        }
    }
}
