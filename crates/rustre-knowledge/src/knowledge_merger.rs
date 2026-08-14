//! `knowledge_merger` — Merge two or more knowledge graphs.
//!
//! Provides [`KnowledgeMerger`], [`MergeStrategy`], [`MergeResult`], and
//! the primary entry point [`merge_graphs`].

use std::collections::{HashMap, HashSet};
use std::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{KnowledgeEdge, KnowledgeGraph, KnowledgeNode};

/// Sanitize an untrusted string for inclusion in error / log messages.
///
/// ASCII control characters (including `\n`, `\r`) are replaced with `·` so
/// that attacker-controlled node IDs cannot inject fake log lines.
fn sanitize_for_msg(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_control() { '\u{00B7}' } else { c })
        .collect()
}

impl MergeError {
    /// Construct an [`MergeError::UnresolvableConflict`] with a sanitized node id
    /// so that attacker-controlled graph node ids cannot inject newlines into
    /// error messages / logs.
    #[must_use] 
    pub fn unresolvable(node_id: &str) -> Self {
        Self::UnresolvableConflict(sanitize_for_msg(node_id))
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by merge operations.
#[derive(Debug, Error)]
pub enum MergeError {
    /// One of the input graphs is empty.
    #[error("input graph is empty")]
    EmptyInput,
    /// A conflict could not be resolved under the chosen strategy.
    #[error("unresolvable conflict for node '{0}'")]
    UnresolvableConflict(String),
    /// The merge strategy is invalid for the provided inputs.
    #[error("invalid strategy '{0}' for this merge")]
    InvalidStrategy(String),
    /// Any other error.
    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// MergeStrategy
// ---------------------------------------------------------------------------

/// How to handle conflicts when merging two knowledge graphs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MergeStrategy {
    /// Nodes/edges from the left (primary) graph win all conflicts.
    LeftWins,
    /// Nodes/edges from the right (secondary) graph win all conflicts.
    RightWins,
    /// Keep nodes/edges from both sides; on node conflict, merge metadata.
    Union,
    /// Keep only nodes/edges that exist in both graphs (intersection).
    Intersection,
    /// Keep only nodes/edges in the left graph that are not in the right.
    LeftMinus,
    /// Perform a semantic merge: prefer the node with richer metadata.
    Semantic,
}

impl MergeStrategy {
    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::LeftWins => "left-wins",
            Self::RightWins => "right-wins",
            Self::Union => "union",
            Self::Intersection => "intersection",
            Self::LeftMinus => "left-minus",
            Self::Semantic => "semantic",
        }
    }

    /// Returns `true` if this strategy can produce a result larger than either input.
    #[must_use]
    pub const fn can_grow(self) -> bool {
        matches!(self, Self::Union | Self::Semantic)
    }
}

impl fmt::Display for MergeStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ---------------------------------------------------------------------------
// NodeConflict
// ---------------------------------------------------------------------------

/// A conflict between two nodes with the same ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConflict {
    /// The conflicting node ID.
    pub id: String,
    /// The node from the left graph.
    pub left: KnowledgeNode,
    /// The node from the right graph.
    pub right: KnowledgeNode,
    /// How the conflict was resolved.
    pub resolution: ConflictResolution,
}

/// How a conflict was resolved during merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictResolution {
    /// Left node was kept.
    TookLeft,
    /// Right node was kept.
    TookRight,
    /// Metadata was merged from both sides.
    MergedMetadata,
    /// Node was dropped (intersection miss or left-minus removal).
    Dropped,
}

impl fmt::Display for ConflictResolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TookLeft => write!(f, "took-left"),
            Self::TookRight => write!(f, "took-right"),
            Self::MergedMetadata => write!(f, "merged-metadata"),
            Self::Dropped => write!(f, "dropped"),
        }
    }
}

// ---------------------------------------------------------------------------
// MergeStats
// ---------------------------------------------------------------------------

/// Statistics from a merge operation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MergeStats {
    /// Nodes from the left graph.
    pub left_nodes: usize,
    /// Nodes from the right graph.
    pub right_nodes: usize,
    /// Nodes in the result graph.
    pub result_nodes: usize,
    /// Edges from the left graph.
    pub left_edges: usize,
    /// Edges from the right graph.
    pub right_edges: usize,
    /// Edges in the result graph.
    pub result_edges: usize,
    /// Number of node conflicts encountered.
    pub conflicts: usize,
    /// Number of duplicate edges deduplicated.
    pub duplicate_edges: usize,
}

impl fmt::Display for MergeStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "left(n={},e={}) + right(n={},e={}) => result(n={},e={}) conflicts={}",
            self.left_nodes, self.left_edges,
            self.right_nodes, self.right_edges,
            self.result_nodes, self.result_edges,
            self.conflicts
        )
    }
}

// ---------------------------------------------------------------------------
// MergeResult
// ---------------------------------------------------------------------------

/// The result of merging two knowledge graphs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeResult {
    /// The merged knowledge graph.
    pub graph: KnowledgeGraph,
    /// Statistics from the merge.
    pub stats: MergeStats,
    /// Strategy used.
    pub strategy: MergeStrategy,
    /// Per-node conflict records.
    pub conflicts: Vec<NodeConflict>,
}

impl MergeResult {
    /// Returns `true` if there were no node conflicts.
    #[must_use]
    pub const fn is_conflict_free(&self) -> bool {
        self.conflicts.is_empty()
    }

    /// Conflicts resolved by taking the left node.
    #[must_use]
    pub fn left_wins_count(&self) -> usize {
        self.conflicts.iter()
            .filter(|c| c.resolution == ConflictResolution::TookLeft)
            .count()
    }

    /// Conflicts resolved by taking the right node.
    #[must_use]
    pub fn right_wins_count(&self) -> usize {
        self.conflicts.iter()
            .filter(|c| c.resolution == ConflictResolution::TookRight)
            .count()
    }
}

impl fmt::Display for MergeResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MergeResult[{}] {}", self.strategy, self.stats)
    }
}

// ---------------------------------------------------------------------------
// KnowledgeMerger
// ---------------------------------------------------------------------------

/// Merges two [`KnowledgeGraph`]s according to a configurable strategy.
pub struct KnowledgeMerger {
    strategy: MergeStrategy,
    /// If true, deduplicate edges that have identical from/to/relation.
    dedup_edges: bool,
    /// If true, allow edges whose endpoints may not both be in the result.
    allow_dangling: bool,
}

impl KnowledgeMerger {
    /// Create a new merger with the given strategy.
    #[must_use]
    pub const fn new(strategy: MergeStrategy) -> Self {
        Self { strategy, dedup_edges: true, allow_dangling: false }
    }

    /// Enable or disable edge deduplication.
    #[must_use]
    pub const fn dedup_edges(mut self, dedup: bool) -> Self {
        self.dedup_edges = dedup;
        self
    }

    /// Allow edges whose endpoints may not be in the node set.
    #[must_use]
    pub const fn allow_dangling(mut self, allow: bool) -> Self {
        self.allow_dangling = allow;
        self
    }

    /// Merge two graphs according to the configured strategy.
    ///
    /// # Errors
    ///
    /// Returns [`MergeError::EmptyInput`] if both inputs are empty, or
    /// [`MergeError::UnresolvableConflict`] for unresolvable node conflicts
    /// under strict strategies.
    pub fn merge(&self, left: &KnowledgeGraph, right: &KnowledgeGraph) -> Result<MergeResult, MergeError> {
        if left.node_count() == 0 && right.node_count() == 0 {
            return Err(MergeError::EmptyInput);
        }
        let mut stats = MergeStats {
            left_nodes: left.node_count(),
            right_nodes: right.node_count(),
            left_edges: left.edge_count(),
            right_edges: right.edge_count(),
            ..Default::default()
        };
        let mut conflicts = Vec::new();
        let result_nodes = self.merge_nodes(left, right, &mut stats, &mut conflicts);
        let result_edges = self.merge_edges(left, right, &result_nodes, &mut stats);

        let mut graph = KnowledgeGraph::new();
        for node in result_nodes.into_values() {
            graph.add_node(node);
        }
        for edge in result_edges {
            graph.add_edge(edge);
        }
        stats.result_nodes = graph.node_count();
        stats.result_edges = graph.edge_count();

        Ok(MergeResult { graph, stats, strategy: self.strategy, conflicts })
    }

    /// Merge multiple graphs in sequence (fold over left).
    ///
    /// # Errors
    ///
    /// Returns [`MergeError`] if any pairwise merge fails.
    pub fn merge_many(&self, graphs: &[KnowledgeGraph]) -> Result<MergeResult, MergeError> {
        if graphs.is_empty() {
            return Err(MergeError::EmptyInput);
        }
        if graphs.len() == 1 {
            let result = MergeResult {
                graph: graphs[0].clone(),
                stats: MergeStats {
                    left_nodes: graphs[0].node_count(),
                    result_nodes: graphs[0].node_count(),
                    left_edges: graphs[0].edge_count(),
                    result_edges: graphs[0].edge_count(),
                    ..Default::default()
                },
                strategy: self.strategy,
                conflicts: Vec::new(),
            };
            return Ok(result);
        }
        let mut acc = graphs[0].clone();
        let mut all_conflicts = Vec::new();
        for g in &graphs[1..] {
            let result = self.merge(&acc, g)?;
            all_conflicts.extend(result.conflicts);
            acc = result.graph;
        }
        let stats = MergeStats {
            result_nodes: acc.node_count(),
            result_edges: acc.edge_count(),
            ..Default::default()
        };
        Ok(MergeResult { graph: acc, stats, strategy: self.strategy, conflicts: all_conflicts })
    }

    // -----------------------------------------------------------------------
    // Node merge
    // -----------------------------------------------------------------------

    fn merge_nodes(
        &self,
        left: &KnowledgeGraph,
        right: &KnowledgeGraph,
        stats: &mut MergeStats,
        conflicts: &mut Vec<NodeConflict>,
    ) -> HashMap<String, KnowledgeNode> {
        match self.strategy {
            MergeStrategy::LeftWins => {
                let mut nodes = right.nodes.clone();
                for (id, node) in &left.nodes {
                    if let Some(right_node) = nodes.get(id) {
                        conflicts.push(NodeConflict {
                            id: id.clone(),
                            left: node.clone(),
                            right: right_node.clone(),
                            resolution: ConflictResolution::TookLeft,
                        });
                        stats.conflicts += 1;
                    }
                    nodes.insert(id.clone(), node.clone());
                }
                nodes
            }
            MergeStrategy::RightWins => {
                let mut nodes = left.nodes.clone();
                for (id, node) in &right.nodes {
                    if let Some(left_node) = nodes.get(id) {
                        conflicts.push(NodeConflict {
                            id: id.clone(),
                            left: left_node.clone(),
                            right: node.clone(),
                            resolution: ConflictResolution::TookRight,
                        });
                        stats.conflicts += 1;
                    }
                    nodes.insert(id.clone(), node.clone());
                }
                nodes
            }
            MergeStrategy::Union => {
                let mut nodes = left.nodes.clone();
                for (id, r_node) in &right.nodes {
                    if let Some(l_node) = nodes.get_mut(id) {
                        // Merge metadata: right metadata keys not in left get added
                        for (k, v) in &r_node.metadata {
                            l_node.metadata.entry(k.clone()).or_insert_with(|| v.clone());
                        }
                        conflicts.push(NodeConflict {
                            id: id.clone(),
                            left: l_node.clone(),
                            right: r_node.clone(),
                            resolution: ConflictResolution::MergedMetadata,
                        });
                        stats.conflicts += 1;
                    } else {
                        nodes.insert(id.clone(), r_node.clone());
                    }
                }
                nodes
            }
            MergeStrategy::Intersection => {
                let mut nodes = HashMap::new();
                for (id, l_node) in &left.nodes {
                    if let Some(r_node) = right.nodes.get(id) {
                        // Take left node for the intersection
                        let mut merged = l_node.clone();
                        for (k, v) in &r_node.metadata {
                            merged.metadata.entry(k.clone()).or_insert_with(|| v.clone());
                        }
                        nodes.insert(id.clone(), merged);
                    } else {
                        conflicts.push(NodeConflict {
                            id: id.clone(),
                            left: l_node.clone(),
                            right: l_node.clone(), // placeholder
                            resolution: ConflictResolution::Dropped,
                        });
                        stats.conflicts += 1;
                    }
                }
                nodes
            }
            MergeStrategy::LeftMinus => {
                let mut nodes = HashMap::new();
                for (id, l_node) in &left.nodes {
                    if right.nodes.contains_key(id) {
                        conflicts.push(NodeConflict {
                            id: id.clone(),
                            left: l_node.clone(),
                            right: right.nodes[id].clone(),
                            resolution: ConflictResolution::Dropped,
                        });
                        stats.conflicts += 1;
                    } else {
                        nodes.insert(id.clone(), l_node.clone());
                    }
                }
                nodes
            }
            MergeStrategy::Semantic => Self::merge_nodes_semantic(left, right, stats, conflicts),
        }
    }

    fn merge_nodes_semantic(
        left: &KnowledgeGraph,
        right: &KnowledgeGraph,
        stats: &mut MergeStats,
        conflicts: &mut Vec<NodeConflict>,
    ) -> HashMap<String, KnowledgeNode> {
        // Prefer the node with more metadata entries; otherwise left wins.
        let mut nodes = right.nodes.clone();
        for (id, l_node) in &left.nodes {
            if let Some(r_node) = nodes.get(id) {
                let resolution;
                if l_node.metadata.len() >= r_node.metadata.len() {
                    let mut merged = l_node.clone();
                    for (k, v) in &r_node.metadata {
                        merged.metadata.entry(k.clone()).or_insert_with(|| v.clone());
                    }
                    resolution = ConflictResolution::TookLeft;
                    nodes.insert(id.clone(), merged);
                } else {
                    let mut merged = r_node.clone();
                    for (k, v) in &l_node.metadata {
                        merged.metadata.entry(k.clone()).or_insert_with(|| v.clone());
                    }
                    resolution = ConflictResolution::TookRight;
                    nodes.insert(id.clone(), merged);
                }
                conflicts.push(NodeConflict {
                    id: id.clone(),
                    left: l_node.clone(),
                    right: right.nodes[id].clone(),
                    resolution,
                });
                stats.conflicts += 1;
            } else {
                nodes.insert(id.clone(), l_node.clone());
            }
        }
        nodes
    }

    // -----------------------------------------------------------------------
    // Edge merge
    // -----------------------------------------------------------------------

    fn merge_edges(
        &self,
        left: &KnowledgeGraph,
        right: &KnowledgeGraph,
        result_nodes: &HashMap<String, KnowledgeNode>,
        stats: &mut MergeStats,
    ) -> Vec<KnowledgeEdge> {
        let mut edges: Vec<KnowledgeEdge> = Vec::new();
        let mut seen: HashSet<(String, String, String)> = HashSet::new();

        let left_edges: Vec<&KnowledgeEdge> = left.edges.iter().collect();
        let right_edges: Vec<&KnowledgeEdge> = right.edges.iter().collect();

        let all_edges: Vec<&KnowledgeEdge> = match self.strategy {
            MergeStrategy::LeftMinus => left_edges.clone(),
            MergeStrategy::Intersection => {
                // Only edges where both from and to are in the intersection
                left_edges.iter().copied()
                    .filter(|e| {
                        right.edges.iter().any(|re| {
                            re.from == e.from && re.to == e.to && re.relation == e.relation
                        })
                    })
                    .collect()
            }
            _ => {
                let mut combined = left_edges.clone();
                combined.extend(right_edges.iter().copied());
                combined
            }
        };

        for edge in all_edges {
            if !self.allow_dangling
                && (!result_nodes.contains_key(&edge.from) || !result_nodes.contains_key(&edge.to)) {
                    continue;
                }
            if self.dedup_edges {
                let key = (edge.from.clone(), edge.to.clone(), edge.relation.clone());
                if seen.contains(&key) {
                    stats.duplicate_edges += 1;
                    continue;
                }
                seen.insert(key);
            }
            edges.push(edge.clone());
        }
        edges
    }
}

impl Default for KnowledgeMerger {
    fn default() -> Self {
        Self::new(MergeStrategy::Union)
    }
}

impl fmt::Debug for KnowledgeMerger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KnowledgeMerger(strategy={})", self.strategy)
    }
}

// ---------------------------------------------------------------------------
// merge_graphs — primary entry point
// ---------------------------------------------------------------------------

/// Merge two knowledge graphs using the Union strategy.
///
/// This is the primary one-shot entry point.
///
/// # Errors
///
/// Returns [`MergeError::EmptyInput`] if both graphs are empty.
pub fn merge_graphs(left: &KnowledgeGraph, right: &KnowledgeGraph) -> Result<MergeResult, MergeError> {
    KnowledgeMerger::new(MergeStrategy::Union).merge(left, right)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KnowledgeGraph, KnowledgeNode, KnowledgeEdge};

    fn node(id: &str, kind: &str) -> KnowledgeNode {
        KnowledgeNode::new(id, id, kind)
    }

    fn edge(from: &str, to: &str, rel: &str) -> KnowledgeEdge {
        KnowledgeEdge::new(from, to, rel)
    }

    fn left_graph() -> KnowledgeGraph {
        let mut g = KnowledgeGraph::new();
        g.add_node(node("a", "function"));
        g.add_node(node("b", "function"));
        g.add_node(node("c", "type"));
        g.add_edge(edge("a", "b", "calls"));
        g.add_edge(edge("b", "c", "uses"));
        g
    }

    fn right_graph() -> KnowledgeGraph {
        let mut g = KnowledgeGraph::new();
        g.add_node(node("b", "function")); // shared
        g.add_node(node("d", "variable"));
        g.add_node(node("e", "function"));
        g.add_edge(edge("b", "d", "reads"));
        g.add_edge(edge("d", "e", "references"));
        g
    }

    #[test]
    fn test_merge_union_node_count() {
        let result = merge_graphs(&left_graph(), &right_graph()).unwrap();
        // a, b, c, d, e = 5
        assert_eq!(result.graph.node_count(), 5);
    }

    #[test]
    fn test_merge_union_edge_dedup() {
        let result = merge_graphs(&left_graph(), &right_graph()).unwrap();
        // a→b, b→c, b→d, d→e = 4 (no duplicates)
        assert_eq!(result.graph.edge_count(), 4);
    }

    #[test]
    fn test_merge_left_wins() {
        let merger = KnowledgeMerger::new(MergeStrategy::LeftWins);
        let result = merger.merge(&left_graph(), &right_graph()).unwrap();
        // b should be from left
        assert!(result.graph.nodes.contains_key("b"));
        assert_eq!(result.left_wins_count(), 1);
    }

    #[test]
    fn test_merge_right_wins() {
        let merger = KnowledgeMerger::new(MergeStrategy::RightWins);
        let result = merger.merge(&left_graph(), &right_graph()).unwrap();
        assert_eq!(result.right_wins_count(), 1);
    }

    #[test]
    fn test_merge_intersection() {
        let merger = KnowledgeMerger::new(MergeStrategy::Intersection);
        let result = merger.merge(&left_graph(), &right_graph()).unwrap();
        // Only b is shared
        assert_eq!(result.graph.node_count(), 1);
        assert!(result.graph.nodes.contains_key("b"));
    }

    #[test]
    fn test_merge_left_minus() {
        let merger = KnowledgeMerger::new(MergeStrategy::LeftMinus);
        let result = merger.merge(&left_graph(), &right_graph()).unwrap();
        // a and c are in left but not right
        assert_eq!(result.graph.node_count(), 2);
        assert!(result.graph.nodes.contains_key("a"));
        assert!(result.graph.nodes.contains_key("c"));
    }

    #[test]
    fn test_merge_semantic() {
        let merger = KnowledgeMerger::new(MergeStrategy::Semantic);
        let result = merger.merge(&left_graph(), &right_graph()).unwrap();
        assert_eq!(result.graph.node_count(), 5);
    }

    #[test]
    fn test_merge_both_empty_error() {
        let g1 = KnowledgeGraph::new();
        let g2 = KnowledgeGraph::new();
        let err = merge_graphs(&g1, &g2);
        assert!(matches!(err, Err(MergeError::EmptyInput)));
    }

    #[test]
    fn test_merge_one_empty() {
        let result = merge_graphs(&left_graph(), &KnowledgeGraph::new()).unwrap();
        assert_eq!(result.graph.node_count(), left_graph().node_count());
    }

    #[test]
    fn test_merge_conflict_free_when_disjoint() {
        let mut left = KnowledgeGraph::new();
        left.add_node(node("x", "function"));
        let mut right = KnowledgeGraph::new();
        right.add_node(node("y", "function"));
        let result = merge_graphs(&left, &right).unwrap();
        assert!(result.is_conflict_free());
    }

    #[test]
    fn test_merge_has_conflict_for_shared_node() {
        let result = merge_graphs(&left_graph(), &right_graph()).unwrap();
        assert!(!result.is_conflict_free()); // b is in both
        assert_eq!(result.conflicts.len(), 1);
    }

    #[test]
    fn test_merge_many() {
        let merger = KnowledgeMerger::new(MergeStrategy::Union);
        let graphs = vec![left_graph(), right_graph()];
        let result = merger.merge_many(&graphs).unwrap();
        assert!(result.graph.node_count() > 0);
    }

    #[test]
    fn test_merge_strategy_names() {
        assert_eq!(MergeStrategy::Union.name(), "union");
        assert_eq!(MergeStrategy::LeftWins.name(), "left-wins");
        assert_eq!(MergeStrategy::Intersection.name(), "intersection");
    }

    #[test]
    fn test_merge_strategy_can_grow() {
        assert!(MergeStrategy::Union.can_grow());
        assert!(MergeStrategy::Semantic.can_grow());
        assert!(!MergeStrategy::Intersection.can_grow());
        assert!(!MergeStrategy::LeftMinus.can_grow());
    }

    #[test]
    fn test_merge_result_display() {
        let result = merge_graphs(&left_graph(), &right_graph()).unwrap();
        let s = result.to_string();
        assert!(s.contains("MergeResult"));
        assert!(s.contains("union"));
    }

    #[test]
    fn test_merger_no_dedup() {
        let merger = KnowledgeMerger::new(MergeStrategy::Union).dedup_edges(false);
        // Both graphs have different edges, so no dedup needed anyway
        let result = merger.merge(&left_graph(), &right_graph()).unwrap();
        assert!(result.graph.edge_count() >= 4);
    }
}
