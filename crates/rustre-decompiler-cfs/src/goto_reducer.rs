//! Phoenix-style goto reducer for the CFS decompiler.
//!
//! After the DREAM structuring pass, some back-edges and cross-edges may not have
//! been absorbed into loops or conditionals.  This module implements a second-pass
//! reducer that converts residual `Goto` nodes into structured constructs wherever
//! possible, following the approach described in the Phoenix decompiler paper
//! (Brumley et al., "Native x86 Decompilation using Semantics-Preserving Structural
//! Analysis and Iterative Control-Flow Structuring").
//!
//! The reducer operates on the [`StructuredNode`] tree produced by [`DreamAlgorithm`]
//! and the original [`BasicBlock`] CFG.  It performs up to a configurable number of
//! iteration rounds; each round tries to collapse one more `Goto` node.  If after
//! all rounds some gotos remain they are preserved as `StructuredNode::Goto` leaves
//! in the output tree — the decompiler can still emit a `goto` label in the final
//! pseudocode.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::{BasicBlock, BlockId, StructuredNode, SwitchCase};

// ---------------------------------------------------------------------------
// Public data types
// ---------------------------------------------------------------------------

/// A directed goto edge that was not yet eliminated.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GotoEdge {
    /// Block that contains the goto.
    pub from: BlockId,
    /// Target of the goto.
    pub to: BlockId,
}

impl GotoEdge {
    /// Construct a new goto edge.
    #[must_use] 
    pub const fn new(from: BlockId, to: BlockId) -> Self {
        Self { from, to }
    }
}

/// Classification of a goto edge used to guide the reduction strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GotoClass {
    /// The goto jumps backward to a block that dominates `from`.
    BackEdge,
    /// The goto jumps forward, crossing over sibling regions.
    ForwardCross,
    /// The goto jumps to a join point of an enclosing conditional.
    BreakLike,
    /// The goto jumps to the header of an enclosing loop (continue-like).
    ContinueLike,
    /// Cannot classify — must remain as an explicit goto.
    Residual,
}

/// A single reduced CFG node that wraps a [`StructuredNode`] together with
/// information about which gotos it absorbed or still exposes.
#[derive(Debug)]
pub struct ReducedNode {
    /// The structured subtree (may still contain `Goto` leaves).
    pub node: StructuredNode,
    /// Gotos that entered this node from outside and were resolved.
    pub resolved: Vec<GotoEdge>,
    /// Gotos still unresolved inside this node's subtree.
    pub residual: Vec<GotoEdge>,
}

/// Result of a complete reduction run.
#[derive(Debug)]
pub struct ReducedCfg {
    /// Root of the structured program tree after reduction.
    pub root: StructuredNode,
    /// All goto edges that were successfully eliminated.
    pub eliminated: Vec<GotoEdge>,
    /// All goto edges that could not be eliminated (will appear as `goto` labels).
    pub remaining: Vec<GotoEdge>,
    /// Number of reduction rounds performed.
    pub rounds: u32,
}

impl ReducedCfg {
    /// Convenience: return the number of residual gotos.
    #[must_use] 
    pub const fn remaining_gotos(&self) -> usize {
        self.remaining.len()
    }

    /// Returns `true` when no explicit `goto` statements remain.
    #[must_use] 
    pub const fn is_fully_structured(&self) -> bool {
        self.remaining.is_empty()
    }

    /// Walk `root` and count how many `StructuredNode::Goto` leaves exist.
    #[must_use] 
    pub fn count_goto_leaves(&self) -> usize {
        fn count(n: &StructuredNode) -> usize {
            match n {
                StructuredNode::Goto(_) => 1,
                StructuredNode::Sequence(children) => children.iter().map(count).sum(),
                StructuredNode::If { then_branch, .. } => count(then_branch),
                StructuredNode::IfElse { then_branch, else_branch, .. } => {
                    count(then_branch) + count(else_branch)
                }
                StructuredNode::Loop { body, .. } => count(body),
                StructuredNode::Switch { cases, .. } => {
                    cases.iter().map(|c| count(&c.body)).sum::<usize>()
                }
                StructuredNode::BasicBlock { .. } | StructuredNode::Break
                | StructuredNode::Continue | StructuredNode::Return(_) => 0,
            }
        }
        count(&self.root)
    }
}

// ---------------------------------------------------------------------------
// Internal dominator tree (lightweight, for reduction only)
// ---------------------------------------------------------------------------

struct DomTree {
    /// idom[b] = immediate dominator of b (same as b for entry).
    idom: HashMap<BlockId, BlockId>,
    /// RPO ordering index.
    rpo_index: HashMap<BlockId, usize>,
}

impl DomTree {
    /// Compute predecessor map from successor edges.
    fn compute_preds(blocks: &HashMap<BlockId, BasicBlock>) -> HashMap<BlockId, Vec<BlockId>> {
        let mut preds: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        for (&id, block) in blocks {
            for &s in &block.successors {
                preds.entry(s).or_default().push(id);
            }
            // Ensure the block itself has an entry.
            preds.entry(id).or_default();
        }
        preds
    }

    fn build(blocks: &HashMap<BlockId, BasicBlock>, entry: BlockId) -> Self {
        // Simple Lengauer-Tarjan O(n log n) dominator computation.
        let rpo = Self::compute_rpo(blocks, entry);
        let rpo_index: HashMap<BlockId, usize> =
            rpo.iter().enumerate().map(|(i, &b)| (b, i)).collect();
        let preds = Self::compute_preds(blocks);

        let mut idom: HashMap<BlockId, BlockId> = HashMap::new();
        idom.insert(entry, entry);

        let mut changed = true;
        while changed {
            changed = false;
            for &b in rpo.iter().skip(1) {
                // Compute intersection of all processed predecessors.
                let processed_preds: Vec<BlockId> = preds
                    .get(&b)
                    .map_or(&[][..], std::vec::Vec::as_slice)
                    .iter()
                    .copied()
                    .filter(|p| idom.contains_key(p))
                    .collect();
                if processed_preds.is_empty() {
                    continue;
                }
                let mut new_idom = processed_preds[0];
                for &p in processed_preds.iter().skip(1) {
                    new_idom = Self::intersect(&idom, &rpo_index, new_idom, p);
                }
                if idom.get(&b) != Some(&new_idom) {
                    idom.insert(b, new_idom);
                    changed = true;
                }
            }
        }

        Self { idom, rpo_index }
    }

    fn compute_rpo(blocks: &HashMap<BlockId, BasicBlock>, entry: BlockId) -> Vec<BlockId> {
        let mut visited = HashSet::new();
        let mut post = Vec::new();
        let mut stack = vec![(entry, false)];
        while let Some((b, processed)) = stack.pop() {
            if processed {
                post.push(b);
                continue;
            }
            if !visited.insert(b) {
                continue;
            }
            stack.push((b, true));
            if let Some(bl) = blocks.get(&b) {
                for &s in bl.successors.iter().rev() {
                    stack.push((s, false));
                }
            }
        }
        post.reverse();
        post
    }

    fn intersect(
        idom: &HashMap<BlockId, BlockId>,
        rpo_index: &HashMap<BlockId, usize>,
        mut a: BlockId,
        mut b: BlockId,
    ) -> BlockId {
        while a != b {
            let ia = rpo_index[&a];
            let ib = rpo_index[&b];
            if ia > ib {
                a = idom[&a];
            } else {
                b = idom[&b];
            }
        }
        a
    }

    fn dominates(&self, dominator: BlockId, dominated: BlockId) -> bool {
        let mut cur = dominated;
        loop {
            if cur == dominator {
                return true;
            }
            let parent = self.idom[&cur];
            if parent == cur {
                return false;
            }
            cur = parent;
        }
    }

    fn depth(&self, mut b: BlockId) -> u32 {
        let mut d = 0u32;
        loop {
            let p = self.idom[&b];
            if p == b {
                return d;
            }
            d += 1;
            b = p;
        }
    }
}

// ---------------------------------------------------------------------------
// Loop-nest tree (for continue/break classification)
// ---------------------------------------------------------------------------

/// Identifies which loop (if any) a block belongs to.
#[derive(Debug, Clone)]
struct LoopNest {
    /// Maps each block to its innermost loop header (if inside a loop).
    inner_header: HashMap<BlockId, BlockId>,
    /// Back-edges detected during construction.
    back_edges: HashSet<GotoEdge>,
}

impl LoopNest {
    fn build(blocks: &HashMap<BlockId, BasicBlock>, dom: &DomTree, _entry: BlockId) -> Self {
        let preds = DomTree::compute_preds(blocks);
        let mut back_edges = HashSet::new();
        // A back-edge is one where the target dominates the source.
        for (&b, block) in blocks {
            for &s in &block.successors {
                if dom.dominates(s, b) {
                    back_edges.insert(GotoEdge::new(b, s));
                }
            }
        }

        // BFS from headers to find loop bodies.
        let headers: HashSet<BlockId> = back_edges.iter().map(|e| e.to).collect();
        let mut inner_header: HashMap<BlockId, BlockId> = HashMap::new();

        for &h in &headers {
            // Blocks in this loop's body (reverse traversal from back-edge sources).
            let latches: Vec<BlockId> =
                back_edges.iter().filter(|e| e.to == h).map(|e| e.from).collect();
            let mut body = HashSet::new();
            body.insert(h);
            let mut worklist: VecDeque<BlockId> = latches.into();
            while let Some(b) = worklist.pop_front() {
                if body.insert(b)
                    && let Some(block_preds) = preds.get(&b) {
                        for &p in block_preds {
                            worklist.push_back(p);
                        }
                    }
            }
            // Assign `h` as the inner header for every body block (deepest wins).
            for b in body {
                let depth_h = dom.depth(h);
                let cur_depth = inner_header.get(&b).map_or(0, |&cur| dom.depth(cur));
                if depth_h >= cur_depth {
                    inner_header.insert(b, h);
                }
            }
        }

        Self { inner_header, back_edges }
    }

    fn innermost_loop(&self, b: BlockId) -> Option<BlockId> {
        self.inner_header.get(&b).copied()
    }

    fn is_back_edge(&self, from: BlockId, to: BlockId) -> bool {
        self.back_edges.contains(&GotoEdge { from, to })
    }
}

// ---------------------------------------------------------------------------
// GotoReducer
// ---------------------------------------------------------------------------

/// Configuration for the goto reducer.
#[derive(Debug, Clone)]
pub struct ReducerConfig {
    /// Maximum number of reduction rounds.
    pub max_rounds: u32,
    /// If `true`, emit `continue` nodes for continue-like gotos.
    pub emit_continue: bool,
    /// If `true`, emit `break` nodes for break-like gotos.
    pub emit_break: bool,
}

impl Default for ReducerConfig {
    fn default() -> Self {
        Self { max_rounds: 8, emit_continue: true, emit_break: true }
    }
}

/// The main goto reducer.
///
/// ```text
/// let reducer = GotoReducer::new(blocks, entry);
/// let result  = reducer.reduce(root_node, config);
/// ```
pub struct GotoReducer {
    blocks: HashMap<BlockId, BasicBlock>,
    dom: DomTree,
    loops: LoopNest,
}

impl GotoReducer {
    /// Create a new reducer from the original CFG.
    #[must_use] 
    pub fn new(blocks: HashMap<BlockId, BasicBlock>, entry: BlockId) -> Self {
        let dom = DomTree::build(&blocks, entry);
        let loops = LoopNest::build(&blocks, &dom, entry);
        Self { blocks, dom, loops }
    }

    /// Run the reduction algorithm on `root`, returning a [`ReducedCfg`].
    #[must_use] 
    pub fn reduce(&self, root: StructuredNode, cfg: &ReducerConfig) -> ReducedCfg {
        let mut node = root;
        let mut eliminated = Vec::new();
        let mut rounds = 0u32;

        for _ in 0..cfg.max_rounds {
            let gotos = collect_gotos(&node);
            if gotos.is_empty() {
                break;
            }
            let (new_node, resolved) = self.reduce_round(node, &gotos, cfg);
            node = new_node;
            if resolved.is_empty() {
                break; // No progress — stop.
            }
            eliminated.extend(resolved);
            rounds += 1;
        }

        let remaining = collect_goto_edges(&node);
        ReducedCfg { root: node, eliminated, remaining, rounds }
    }

    // ------------------------------------------------------------------
    // Round: attempt to reduce each goto once
    // ------------------------------------------------------------------

    fn reduce_round(
        &self,
        node: StructuredNode,
        gotos: &[BlockId],
        cfg: &ReducerConfig,
    ) -> (StructuredNode, Vec<GotoEdge>) {
        let mut resolved = Vec::new();
        let new_node = self.transform_node(node, gotos, cfg, &mut resolved);
        (new_node, resolved)
    }

    fn transform_node(
        &self,
        node: StructuredNode,
        targets: &[BlockId],
        cfg: &ReducerConfig,
        resolved: &mut Vec<GotoEdge>,
    ) -> StructuredNode {
        match node {
            StructuredNode::Goto(target) => {
                if targets.contains(&target) {
                    self.try_reduce_goto(target, cfg, resolved)
                } else {
                    StructuredNode::Goto(target)
                }
            }
            StructuredNode::Sequence(children) => {
                let new_children: Vec<StructuredNode> = children
                    .into_iter()
                    .map(|c| self.transform_node(c, targets, cfg, resolved))
                    .collect();
                StructuredNode::Sequence(new_children)
            }
            StructuredNode::If { condition, then_branch } => {
                let new_then =
                    Box::new(self.transform_node(*then_branch, targets, cfg, resolved));
                StructuredNode::If {
                    condition,
                    then_branch: new_then,
                }
            }
            StructuredNode::IfElse { condition, then_branch, else_branch } => {
                let new_then =
                    Box::new(self.transform_node(*then_branch, targets, cfg, resolved));
                let new_else = Box::new(self.transform_node(*else_branch, targets, cfg, resolved));
                StructuredNode::IfElse {
                    condition,
                    then_branch: new_then,
                    else_branch: new_else,
                }
            }
            StructuredNode::Loop { kind, condition, body } => {
                let new_body = Box::new(self.transform_node(*body, targets, cfg, resolved));
                StructuredNode::Loop { kind, condition, body: new_body }
            }
            StructuredNode::Switch { expr, cases } => {
                let new_cases: Vec<SwitchCase> = cases
                    .into_iter()
                    .map(|sc| SwitchCase {
                        value: sc.value,
                        body: Box::new(self.transform_node(*sc.body, targets, cfg, resolved)),
                    })
                    .collect();
                StructuredNode::Switch { expr, cases: new_cases }
            }
            other => other,
        }
    }

    fn try_reduce_goto(
        &self,
        target: BlockId,
        cfg: &ReducerConfig,
        resolved: &mut Vec<GotoEdge>,
    ) -> StructuredNode {
        // We don't know `from` at this point in the tree walk, so we use
        // the target alone to decide what kind of construct to emit.
        // A `continue` is appropriate when `target` is a loop header of the
        // enclosing loop.  A `break` is appropriate when `target` is the
        // exit of the enclosing loop.  Otherwise, keep as Goto.
        let class = self.classify_target(target);
        match class {
            GotoClass::ContinueLike if cfg.emit_continue => {
                resolved.push(GotoEdge { from: target, to: target }); // placeholder
                StructuredNode::Continue
            }
            GotoClass::BreakLike if cfg.emit_break => {
                resolved.push(GotoEdge { from: target, to: target });
                StructuredNode::Break
            }
            _ => StructuredNode::Goto(target),
        }
    }

    fn classify_target(&self, target: BlockId) -> GotoClass {
        // Is `target` a loop header?
        if self.loops.is_back_edge(target, target) {
            return GotoClass::ContinueLike;
        }
        // Is `target` the innermost loop header of some block?
        let is_header = self.blocks.values().any(|bl| {
            self.loops.innermost_loop(bl.id) == Some(target)
        });
        if is_header {
            return GotoClass::ContinueLike;
        }
        // Is `target` a post-dominator exit of some loop?
        // We approximate: if `target` has no inner loop and is reachable
        // only via forward edges, classify as BreakLike.
        if self.loops.innermost_loop(target).is_none() {
            return GotoClass::BreakLike;
        }
        GotoClass::Residual
    }

    // ------------------------------------------------------------------
    // Classification helpers (public for testing)
    // ------------------------------------------------------------------

    /// Classify a goto edge `from -> to`.
    #[must_use] 
    pub fn classify_edge(&self, from: BlockId, to: BlockId) -> GotoClass {
        if self.loops.is_back_edge(from, to) {
            return GotoClass::BackEdge;
        }
        // Is `to` the loop header of the loop containing `from`?
        if let Some(h) = self.loops.innermost_loop(from)
            && h == to {
                return GotoClass::ContinueLike;
            }
        // Is `to` a sibling exit?
        if self.dom.dominates(to, from) {
            return GotoClass::ForwardCross;
        }
        // If `to` has no loop and is forward, treat as break-like.
        if self.loops.innermost_loop(to).is_none() {
            let from_idx = self.dom.rpo_index.get(&from).copied().unwrap_or(0);
            let to_idx = self.dom.rpo_index.get(&to).copied().unwrap_or(0);
            if to_idx > from_idx {
                return GotoClass::BreakLike;
            }
        }
        GotoClass::Residual
    }

    /// Return the set of goto edges still present in `node`.
    #[must_use] 
    pub fn remaining_gotos_in(&self, node: &StructuredNode) -> Vec<GotoEdge> {
        collect_goto_edges(node)
    }
}

// ---------------------------------------------------------------------------
// Helpers: collect goto targets / edges from a StructuredNode tree
// ---------------------------------------------------------------------------

fn collect_gotos(node: &StructuredNode) -> Vec<BlockId> {
    let mut out = Vec::new();
    collect_gotos_inner(node, &mut out);
    out.sort_unstable();
    out.dedup();
    out
}

fn collect_gotos_inner(node: &StructuredNode, out: &mut Vec<BlockId>) {
    match node {
        StructuredNode::Goto(t) => out.push(*t),
        StructuredNode::Sequence(children) => {
            for c in children {
                collect_gotos_inner(c, out);
            }
        }
        StructuredNode::If { then_branch, .. } => {
            collect_gotos_inner(then_branch, out);
        }
        StructuredNode::IfElse { then_branch, else_branch, .. } => {
            collect_gotos_inner(then_branch, out);
            collect_gotos_inner(else_branch, out);
        }
        StructuredNode::Loop { body, .. } => collect_gotos_inner(body, out),
        StructuredNode::Switch { cases, .. } => {
            for c in cases {
                collect_gotos_inner(&c.body, out);
            }
        }
        _ => {}
    }
}

fn collect_goto_edges(node: &StructuredNode) -> Vec<GotoEdge> {
    // Without from-block information in the tree we synthesize edges with
    // from == to (placeholder) so callers can at least count residual gotos.
    collect_gotos(node)
        .into_iter()
        .map(|t| GotoEdge { from: t, to: t })
        .collect()
}

// ---------------------------------------------------------------------------
// Sequence flattening utility
// ---------------------------------------------------------------------------

/// Flatten nested `Sequence` nodes into a single sequence.
#[must_use] 
pub fn flatten_sequence(node: StructuredNode) -> StructuredNode {
    match node {
        StructuredNode::Sequence(children) => {
            let mut flat = Vec::new();
            for c in children {
                match flatten_sequence(c) {
                    StructuredNode::Sequence(inner) => flat.extend(inner),
                    other => flat.push(other),
                }
            }
            if flat.len() == 1 {
                flat.remove(0)
            } else {
                StructuredNode::Sequence(flat)
            }
        }
        StructuredNode::If { condition, then_branch } => {
            StructuredNode::If {
                condition,
                then_branch: Box::new(flatten_sequence(*then_branch)),
            }
        }
        StructuredNode::IfElse { condition, then_branch, else_branch } => {
            StructuredNode::IfElse {
                condition,
                then_branch: Box::new(flatten_sequence(*then_branch)),
                else_branch: Box::new(flatten_sequence(*else_branch)),
            }
        }
        StructuredNode::Loop { kind, condition, body } => {
            StructuredNode::Loop { kind, condition, body: Box::new(flatten_sequence(*body)) }
        }
        StructuredNode::Switch { expr, cases } => {
            let new_cases =
                cases.into_iter().map(|sc| SwitchCase { value: sc.value, body: Box::new(flatten_sequence(*sc.body)) }).collect();
            StructuredNode::Switch { expr, cases: new_cases }
        }
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

/// Counts of node types in a structured tree.
#[derive(Debug, Default, Clone)]
pub struct TreeStats {
    pub blocks: u32,
    pub conditions: u32,
    pub loops: u32,
    pub switches: u32,
    pub breaks: u32,
    pub continues: u32,
    pub gotos: u32,
    pub sequences: u32,
}

impl TreeStats {
    /// Compute statistics for a structured tree.
    #[must_use] 
    pub fn from_tree(node: &StructuredNode) -> Self {
        let mut s = Self::default();
        s.collect(node);
        s
    }

    fn collect(&mut self, node: &StructuredNode) {
        match node {
            StructuredNode::BasicBlock { .. } => self.blocks += 1,
            StructuredNode::Goto(_) => self.gotos += 1,
            StructuredNode::Break => self.breaks += 1,
            StructuredNode::Continue => self.continues += 1,
            StructuredNode::Return(_) => {}
            StructuredNode::Sequence(children) => {
                self.sequences += 1;
                for c in children {
                    self.collect(c);
                }
            }
            StructuredNode::If { then_branch, .. } => {
                self.conditions += 1;
                self.collect(then_branch);
            }
            StructuredNode::IfElse { then_branch, else_branch, .. } => {
                self.conditions += 1;
                self.collect(then_branch);
                self.collect(else_branch);
            }
            StructuredNode::Loop { body, .. } => {
                self.loops += 1;
                self.collect(body);
            }
            StructuredNode::Switch { cases, .. } => {
                self.switches += 1;
                for c in cases {
                    self.collect(&c.body);
                }
            }
        }
    }

    /// Structuredness ratio: fraction of non-goto, non-residual nodes.
    #[must_use] 
    pub fn structuredness(&self) -> f64 {
        let total = self.blocks + self.conditions + self.loops + self.switches
            + self.breaks + self.continues + self.gotos;
        if total == 0 {
            return 1.0;
        }
        let structured = total - self.gotos;
        f64::from(structured) / f64::from(total)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_block(id: u32, succs: &[u32], _preds: &[u32]) -> BasicBlock {
        BasicBlock::new(BlockId(id))
            .with_successors(succs.iter().map(|&x| BlockId(x)).collect())
    }

    #[test]
    fn test_goto_edge_equality() {
        let e1 = GotoEdge::new(BlockId(1), BlockId(2));
        let e2 = GotoEdge::new(BlockId(1), BlockId(2));
        let e3 = GotoEdge::new(BlockId(2), BlockId(3));
        assert_eq!(e1, e2);
        assert_ne!(e1, e3);
    }

    #[test]
    fn test_collect_gotos_empty() {
        let node = StructuredNode::BasicBlock { id: BlockId(0), stmts: vec![] };
        assert!(collect_gotos(&node).is_empty());
    }

    #[test]
    fn test_collect_gotos_single() {
        let node = StructuredNode::Goto(BlockId(5));
        let gotos = collect_gotos(&node);
        assert_eq!(gotos, vec![BlockId(5)]);
    }

    #[test]
    fn test_tree_stats_simple() {
        let node = StructuredNode::Sequence(vec![
            StructuredNode::BasicBlock { id: BlockId(0), stmts: vec![] },
            StructuredNode::Goto(BlockId(3)),
            StructuredNode::Break,
        ]);
        let stats = TreeStats::from_tree(&node);
        assert_eq!(stats.blocks, 1);
        assert_eq!(stats.gotos, 1);
        assert_eq!(stats.breaks, 1);
    }

    #[test]
    fn test_flatten_sequence_nested() {
        let inner = StructuredNode::Sequence(vec![
            StructuredNode::BasicBlock { id: BlockId(1), stmts: vec![] },
            StructuredNode::BasicBlock { id: BlockId(2), stmts: vec![] },
        ]);
        let outer = StructuredNode::Sequence(vec![
            StructuredNode::BasicBlock { id: BlockId(0), stmts: vec![] },
            inner,
        ]);
        let flat = flatten_sequence(outer);
        if let StructuredNode::Sequence(children) = flat {
            assert_eq!(children.len(), 3);
        } else {
            panic!("Expected Sequence");
        }
    }

    #[test]
    fn test_reduced_cfg_fully_structured() {
        let cfg = ReducedCfg {
            root: StructuredNode::BasicBlock { id: BlockId(0), stmts: vec![] },
            eliminated: vec![],
            remaining: vec![],
            rounds: 1,
        };
        assert!(cfg.is_fully_structured());
        assert_eq!(cfg.remaining_gotos(), 0);
        assert_eq!(cfg.count_goto_leaves(), 0);
    }

    #[test]
    fn test_reduced_cfg_with_goto() {
        let cfg = ReducedCfg {
            root: StructuredNode::Goto(BlockId(7)),
            eliminated: vec![],
            remaining: vec![GotoEdge::new(BlockId(7), BlockId(7))],
            rounds: 0,
        };
        assert!(!cfg.is_fully_structured());
        assert_eq!(cfg.count_goto_leaves(), 1);
    }

    #[test]
    fn test_dom_tree_linear() {
        let mut blocks = HashMap::new();
        blocks.insert(BlockId(0), make_block(0, &[1], &[]));
        blocks.insert(BlockId(1), make_block(1, &[2], &[0]));
        blocks.insert(BlockId(2), make_block(2, &[], &[1]));
        let dom = DomTree::build(&blocks, BlockId(0));
        assert!(dom.dominates(BlockId(0), BlockId(1)));
        assert!(dom.dominates(BlockId(0), BlockId(2)));
        assert!(dom.dominates(BlockId(1), BlockId(2)));
        assert!(!dom.dominates(BlockId(2), BlockId(1)));
    }

    #[test]
    fn test_structuredness_ratio() {
        let stats = TreeStats {
            blocks: 5,
            gotos: 1,
            ..TreeStats::default()
        };
        let ratio = stats.structuredness();
        assert!((ratio - 5.0 / 6.0).abs() < 1e-9);
    }

    // ── Added comprehensive tests ─────────────────────────────────────────────

    fn bb(id: u32) -> StructuredNode {
        StructuredNode::BasicBlock { id: BlockId(id), stmts: vec![] }
    }

    #[test]
    fn structuredness_empty_tree_is_unity() {
        let s = TreeStats::default();
        assert!((s.structuredness() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn structuredness_all_gotos_is_zero() {
        let s = TreeStats {
            gotos: 4,
            ..TreeStats::default()
        };
        assert!(s.structuredness().abs() < f64::EPSILON);
    }

    #[test]
    fn tree_stats_counts_full_construct_zoo() {
        let node = StructuredNode::Sequence(vec![
            bb(0),
            StructuredNode::If {
                condition: "c".into(),
                then_branch: Box::new(bb(1)),
            },
            StructuredNode::IfElse {
                condition: "c".into(),
                then_branch: Box::new(bb(2)),
                else_branch: Box::new(StructuredNode::Goto(BlockId(99))),
            },
            StructuredNode::Loop {
                kind: crate::LoopKind::While,
                condition: "c".into(),
                body: Box::new(StructuredNode::Continue),
            },
            StructuredNode::Switch {
                expr: "x".into(),
                cases: vec![SwitchCase {
                    value: Some(1),
                    body: Box::new(StructuredNode::Break),
                }],
            },
            StructuredNode::Return(Some("0".into())),
        ]);
        let s = TreeStats::from_tree(&node);
        assert_eq!(s.blocks, 3);
        assert_eq!(s.conditions, 2);
        assert_eq!(s.loops, 1);
        assert_eq!(s.switches, 1);
        assert_eq!(s.breaks, 1);
        assert_eq!(s.continues, 1);
        assert_eq!(s.gotos, 1);
        assert!(s.sequences >= 1);
    }

    #[test]
    fn collect_gotos_dedupes_and_sorts() {
        let node = StructuredNode::Sequence(vec![
            StructuredNode::Goto(BlockId(5)),
            StructuredNode::Goto(BlockId(2)),
            StructuredNode::Goto(BlockId(5)),
            StructuredNode::Goto(BlockId(2)),
        ]);
        let gotos = collect_gotos(&node);
        assert_eq!(gotos, vec![BlockId(2), BlockId(5)]);
    }

    #[test]
    fn collect_gotos_traverses_nested_constructs() {
        let inner_switch = StructuredNode::Switch {
            expr: "x".into(),
            cases: vec![SwitchCase {
                value: None,
                body: Box::new(StructuredNode::Goto(BlockId(7))),
            }],
        };
        let node = StructuredNode::Loop {
            kind: crate::LoopKind::DoWhile,
            condition: "c".into(),
            body: Box::new(StructuredNode::IfElse {
                condition: "c".into(),
                then_branch: Box::new(StructuredNode::Goto(BlockId(1))),
                else_branch: Box::new(inner_switch),
            }),
        };
        let gotos = collect_gotos(&node);
        assert_eq!(gotos, vec![BlockId(1), BlockId(7)]);
    }

    #[test]
    fn flatten_sequence_single_element_collapses() {
        let node = StructuredNode::Sequence(vec![bb(42)]);
        let flat = flatten_sequence(node);
        assert!(matches!(flat, StructuredNode::BasicBlock { id, .. } if id == BlockId(42)));
    }

    #[test]
    fn flatten_sequence_preserves_non_sequences() {
        let original = StructuredNode::If {
            condition: "c".into(),
            then_branch: Box::new(StructuredNode::Sequence(vec![
                StructuredNode::Sequence(vec![bb(1), bb(2)]),
                bb(3),
            ])),
        };
        let flat = flatten_sequence(original);
        if let StructuredNode::If { then_branch, .. } = flat {
            if let StructuredNode::Sequence(children) = *then_branch {
                assert_eq!(children.len(), 3);
            } else {
                panic!("expected flattened sequence");
            }
        } else {
            panic!("expected If");
        }
    }

    #[test]
    fn flatten_sequence_inside_loops_and_switches() {
        let node = StructuredNode::Loop {
            kind: crate::LoopKind::For,
            condition: "c".into(),
            body: Box::new(StructuredNode::Sequence(vec![
                StructuredNode::Sequence(vec![bb(1)]),
                StructuredNode::Sequence(vec![bb(2), bb(3)]),
            ])),
        };
        let flat = flatten_sequence(node);
        if let StructuredNode::Loop { body, .. } = flat {
            if let StructuredNode::Sequence(c) = *body {
                assert_eq!(c.len(), 3);
            } else {
                panic!("expected sequence in loop body");
            }
        } else {
            panic!("expected loop");
        }
    }

    #[test]
    fn reducer_with_no_gotos_terminates_immediately() {
        let mut blocks = HashMap::new();
        blocks.insert(BlockId(0), make_block(0, &[], &[]));
        let reducer = GotoReducer::new(blocks, BlockId(0));
        let result = reducer.reduce(bb(0), &ReducerConfig::default());
        assert_eq!(result.rounds, 0);
        assert!(result.is_fully_structured());
        assert!(result.eliminated.is_empty());
    }

    #[test]
    fn reducer_max_rounds_zero_no_progress() {
        let mut blocks = HashMap::new();
        blocks.insert(BlockId(0), make_block(0, &[1], &[]));
        blocks.insert(BlockId(1), make_block(1, &[], &[0]));
        let reducer = GotoReducer::new(blocks, BlockId(0));
        let cfg = ReducerConfig {
            max_rounds: 0,
            ..ReducerConfig::default()
        };
        let result = reducer.reduce(StructuredNode::Goto(BlockId(1)), &cfg);
        assert_eq!(result.rounds, 0);
        // Goto preserved.
        assert_eq!(result.remaining_gotos(), 1);
    }

    #[test]
    fn count_goto_leaves_in_deeply_nested_node() {
        let node = StructuredNode::Sequence(vec![
            StructuredNode::Goto(BlockId(1)),
            StructuredNode::IfElse {
                condition: "c".into(),
                then_branch: Box::new(StructuredNode::Goto(BlockId(2))),
                else_branch: Box::new(StructuredNode::Sequence(vec![
                    StructuredNode::Goto(BlockId(3)),
                    StructuredNode::Goto(BlockId(4)),
                ])),
            },
        ]);
        let cfg = ReducedCfg { root: node, eliminated: vec![], remaining: vec![], rounds: 0 };
        assert_eq!(cfg.count_goto_leaves(), 4);
    }

    #[test]
    fn dom_tree_diamond_shape() {
        // 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3
        let mut blocks = HashMap::new();
        blocks.insert(BlockId(0), make_block(0, &[1, 2], &[]));
        blocks.insert(BlockId(1), make_block(1, &[3], &[0]));
        blocks.insert(BlockId(2), make_block(2, &[3], &[0]));
        blocks.insert(BlockId(3), make_block(3, &[], &[1, 2]));
        let dom = DomTree::build(&blocks, BlockId(0));
        // Entry dominates everything.
        assert!(dom.dominates(BlockId(0), BlockId(3)));
        // Neither side of diamond dominates the join.
        assert!(!dom.dominates(BlockId(1), BlockId(3)));
        assert!(!dom.dominates(BlockId(2), BlockId(3)));
    }

    #[test]
    fn dom_tree_back_edge_detected_as_back_edge_in_loop() {
        // 0 -> 1 -> 2 -> 1  (back-edge 2 -> 1)
        let mut blocks = HashMap::new();
        blocks.insert(BlockId(0), make_block(0, &[1], &[]));
        blocks.insert(BlockId(1), make_block(1, &[2], &[0, 2]));
        blocks.insert(BlockId(2), make_block(2, &[1], &[1]));
        let reducer = GotoReducer::new(blocks, BlockId(0));
        assert_eq!(reducer.classify_edge(BlockId(2), BlockId(1)), GotoClass::BackEdge);
    }

    #[test]
    fn reduced_cfg_remaining_count_matches_vec() {
        let cfg = ReducedCfg {
            root: bb(0),
            eliminated: vec![],
            remaining: vec![
                GotoEdge::new(BlockId(1), BlockId(2)),
                GotoEdge::new(BlockId(3), BlockId(4)),
            ],
            rounds: 1,
        };
        assert_eq!(cfg.remaining_gotos(), 2);
        assert!(!cfg.is_fully_structured());
    }

    #[test]
    fn reducer_config_default_emits_break_and_continue() {
        let c = ReducerConfig::default();
        assert!(c.emit_break);
        assert!(c.emit_continue);
        assert!(c.max_rounds > 0);
    }

    #[test]
    fn classify_target_unknown_block_treated_as_break_like() {
        let mut blocks = HashMap::new();
        blocks.insert(BlockId(0), make_block(0, &[], &[]));
        let reducer = GotoReducer::new(blocks, BlockId(0));
        // A target not inside any loop is classified as break-like.
        assert_eq!(reducer.classify_target(BlockId(0)), GotoClass::BreakLike);
    }

    #[test]
    fn remaining_gotos_in_handles_nested_node() {
        let mut blocks = HashMap::new();
        blocks.insert(BlockId(0), make_block(0, &[], &[]));
        let reducer = GotoReducer::new(blocks, BlockId(0));
        let node = StructuredNode::Sequence(vec![
            StructuredNode::Goto(BlockId(5)),
            StructuredNode::Goto(BlockId(7)),
        ]);
        let edges = reducer.remaining_gotos_in(&node);
        assert_eq!(edges.len(), 2);
    }
}
