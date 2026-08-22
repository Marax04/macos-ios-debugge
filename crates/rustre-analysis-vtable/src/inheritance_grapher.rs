//! `inheritance_grapher` — Build and query C++ class inheritance graphs.
//!
//! This module provides [`InheritanceGrapher`], which ingests recovered vtable
//! RTTI information and constructs a directed graph (powered by [`petgraph`])
//! where each node is a C++ class and each directed edge represents an
//! inheritance relationship (derived → base).
//!
//! The graph supports:
//! - Building from [`RttiInfo`] slices.
//! - BFS/DFS traversal for reachability.
//! - Computation of the Most-Derived root set.
//! - Cycle detection (should not occur in well-formed C++ hierarchies).
//! - Serialisation of the graph to a simple adjacency-list format.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use petgraph::Direction;
use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};

use crate::{RttiAbi, RttiInfo};

// ── ClassNode ─────────────────────────────────────────────────────────────────

/// A node in the inheritance graph representing a single C++ class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassNode {
    /// Fully-qualified class name (demangled or raw).
    pub name: String,
    /// ABI the class was recovered from.
    pub abi: RttiAbi,
    /// Address of the RTTI structure for this class (0 if synthesised).
    pub rtti_address: u64,
    /// Whether this class was recovered directly (vs. inferred as a base).
    pub is_direct: bool,
}

impl ClassNode {
    /// Create a directly-recovered node.
    #[must_use]
    pub fn new(name: impl Into<String>, abi: RttiAbi, rtti_address: u64) -> Self {
        Self {
            name: name.into(),
            abi,
            rtti_address,
            is_direct: true,
        }
    }

    /// Create an inferred (base-class) node.
    #[must_use]
    pub fn inferred(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            abi: RttiAbi::Unknown,
            rtti_address: 0,
            is_direct: false,
        }
    }
}

impl fmt::Display for ClassNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}{}]",
            self.name,
            match self.abi {
                RttiAbi::Itanium => "itanium",
                RttiAbi::Msvc => "msvc",
                RttiAbi::Unknown => "unknown",
            },
            if self.is_direct { "" } else { ", inferred" }
        )
    }
}

// ── InheritanceEdge ───────────────────────────────────────────────────────────

/// Metadata on a directed inheritance edge (derived → base).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InheritanceEdge {
    /// True if the inheritance is virtual (diamond-safe).
    pub is_virtual: bool,
    /// Access specifier as recovered from RTTI (unknown for most ABIs).
    pub access: InheritanceAccess,
}

impl Default for InheritanceEdge {
    fn default() -> Self {
        Self {
            is_virtual: false,
            access: InheritanceAccess::Unknown,
        }
    }
}

impl fmt::Display for InheritanceEdge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let virt = if self.is_virtual { "virtual " } else { "" };
        write!(f, "{virt}{}", self.access)
    }
}

/// C++ inheritance access specifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InheritanceAccess {
    Public,
    Protected,
    Private,
    Unknown,
}

impl fmt::Display for InheritanceAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => write!(f, "public"),
            Self::Protected => write!(f, "protected"),
            Self::Private => write!(f, "private"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ── GraphStats ────────────────────────────────────────────────────────────────

/// Summary statistics for an inheritance graph.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct GraphStats {
    /// Total number of class nodes.
    pub node_count: usize,
    /// Total number of inheritance edges.
    pub edge_count: usize,
    /// Number of root classes (no base classes).
    pub root_count: usize,
    /// Number of leaf classes (no derived classes).
    pub leaf_count: usize,
    /// Number of classes with multiple bases.
    pub multiple_inheritance_count: usize,
    /// Maximum inheritance depth found by BFS from any root.
    pub max_depth: usize,
    /// Whether a cycle was detected (indicates corrupt RTTI).
    pub has_cycle: bool,
}

impl fmt::Display for GraphStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GraphStats: nodes={} edges={} roots={} leaves={} mi={} max_depth={} cycle={}",
            self.node_count,
            self.edge_count,
            self.root_count,
            self.leaf_count,
            self.multiple_inheritance_count,
            self.max_depth,
            self.has_cycle,
        )
    }
}

// ── InheritanceGrapher ────────────────────────────────────────────────────────

/// Builds and queries a directed class inheritance graph from RTTI information.
///
/// The graph is a [`DiGraph<ClassNode, InheritanceEdge>`] where each edge goes
/// from the derived class to its immediate base class.  Multiple inheritance
/// is represented as multiple out-edges from a single derived-class node.
pub struct InheritanceGrapher {
    /// The underlying petgraph directed graph.
    graph: DiGraph<ClassNode, InheritanceEdge>,
    /// Maps class name → `NodeIndex` for O(1) lookup.
    name_to_node: HashMap<String, NodeIndex>,
}

impl InheritanceGrapher {
    /// Create an empty grapher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            name_to_node: HashMap::new(),
        }
    }

    /// Return the number of class nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Return the number of inheritance edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Look up a node index by class name.
    #[must_use]
    pub fn find_node(&self, name: &str) -> Option<NodeIndex> {
        self.name_to_node.get(name).copied()
    }

    /// Get the class node for a given index.
    #[must_use]
    pub fn node_weight(&self, idx: NodeIndex) -> Option<&ClassNode> {
        self.graph.node_weight(idx)
    }

    /// Get or create a node for `name`.
    fn get_or_create_node(&mut self, name: &str, direct: Option<&RttiInfo>) -> NodeIndex {
        if let Some(&idx) = self.name_to_node.get(name) {
            // Upgrade an inferred node to a direct one if we now have RTTI.
            if let Some(rtti) = direct
                && let Some(w) = self.graph.node_weight_mut(idx)
                    && !w.is_direct {
                        w.is_direct = true;
                        w.abi = rtti.abi.clone();
                        w.rtti_address = rtti.rtti_address;
                    }
            return idx;
        }
        let node = match direct {
            Some(rtti) => ClassNode::new(name, rtti.abi.clone(), rtti.rtti_address),
            None => ClassNode::inferred(name),
        };
        let idx = self.graph.add_node(node);
        self.name_to_node.insert(name.to_owned(), idx);
        idx
    }

    /// Add a single [`RttiInfo`] record to the graph.
    ///
    /// Creates nodes for the class and all its direct bases, and adds
    /// directed edges from the derived class to each base.
    pub fn add_rtti(&mut self, rtti: &RttiInfo) {
        let derived_idx = self.get_or_create_node(&rtti.type_name, Some(rtti));
        for base_name in &rtti.base_classes {
            let base_idx = self.get_or_create_node(base_name, None);
            // Avoid duplicate edges.
            if !self.graph.contains_edge(derived_idx, base_idx) {
                self.graph.add_edge(derived_idx, base_idx, InheritanceEdge::default());
            }
        }
    }

    /// Build the graph from a slice of [`RttiInfo`] records.
    ///
    /// This is the primary entry point used by analysis pipelines.
    pub fn build_from_rtti(&mut self, rtti_list: &[RttiInfo]) {
        for rtti in rtti_list {
            self.add_rtti(rtti);
        }
    }

    /// Collect all root classes — classes that have no base class (no out-edges).
    #[must_use]
    pub fn roots(&self) -> Vec<NodeIndex> {
        self.graph
            .node_indices()
            .filter(|&n| self.graph.edges_directed(n, Direction::Outgoing).count() == 0)
            .collect()
    }

    /// Collect all leaf classes — classes with no derived classes (no in-edges).
    #[must_use]
    pub fn leaves(&self) -> Vec<NodeIndex> {
        self.graph
            .node_indices()
            .filter(|&n| self.graph.edges_directed(n, Direction::Incoming).count() == 0)
            .collect()
    }

    /// Perform BFS from `start` following inheritance edges in `direction`.
    ///
    /// - `Direction::Outgoing`: walk from derived → base (ancestors).
    /// - `Direction::Incoming`: walk from base → derived (descendants).
    ///
    /// Returns node indices in BFS order (excluding `start`).
    #[must_use]
    pub fn bfs(&self, start: NodeIndex, direction: Direction) -> Vec<NodeIndex> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut result = Vec::new();

        visited.insert(start);
        queue.push_back(start);

        while let Some(current) = queue.pop_front() {
            for neighbor in self.graph.neighbors_directed(current, direction) {
                if visited.insert(neighbor) {
                    result.push(neighbor);
                    queue.push_back(neighbor);
                }
            }
        }
        result
    }

    /// Perform DFS from `start` following edges in `direction`.
    ///
    /// Returns node indices in DFS discovery order (excluding `start`).
    #[must_use]
    pub fn dfs(&self, start: NodeIndex, direction: Direction) -> Vec<NodeIndex> {
        // Mark and emit at POP time, not at push time.
        //
        // Marking at push is only sound for BFS, where first discovery is also
        // the shortest path — which is exactly why `bfs` above can do it. On a
        // LIFO it emits every neighbour of the current node before descending
        // into any of them, so the sequence is neither DFS pre-order nor BFS:
        // for a diamond D→{B,C}, B→A, C→A it returned [C, B, A], emitting the
        // sibling B before finishing C's subtree.
        let mut visited = HashSet::new();
        let mut stack = vec![start];
        let mut result = Vec::new();

        while let Some(current) = stack.pop() {
            if !visited.insert(current) {
                continue;
            }
            if current != start {
                result.push(current);
            }
            // Push in reverse so the first neighbour is explored first.
            let mut neighbors: Vec<NodeIndex> =
                self.graph.neighbors_directed(current, direction).collect();
            neighbors.reverse();
            for neighbor in neighbors {
                if !visited.contains(&neighbor) {
                    stack.push(neighbor);
                }
            }
        }
        result
    }

    /// Return all ancestors of `class_name` (classes that it directly or indirectly inherits from).
    ///
    /// Returns an empty vec if the class is not in the graph.
    #[must_use]
    pub fn ancestors(&self, class_name: &str) -> Vec<String> {
        let Some(start) = self.find_node(class_name) else {
            return Vec::new();
        };
        self.bfs(start, Direction::Outgoing)
            .into_iter()
            .filter_map(|n| self.graph.node_weight(n))
            .map(|w| w.name.clone())
            .collect()
    }

    /// Return all descendants of `class_name` (classes that directly or indirectly derive from it).
    #[must_use]
    pub fn descendants(&self, class_name: &str) -> Vec<String> {
        let Some(start) = self.find_node(class_name) else {
            return Vec::new();
        };
        self.bfs(start, Direction::Incoming)
            .into_iter()
            .filter_map(|n| self.graph.node_weight(n))
            .map(|w| w.name.clone())
            .collect()
    }

    /// Return the direct base classes of `class_name`.
    #[must_use]
    pub fn direct_bases(&self, class_name: &str) -> Vec<String> {
        let Some(start) = self.find_node(class_name) else {
            return Vec::new();
        };
        self.graph
            .neighbors_directed(start, Direction::Outgoing)
            .filter_map(|n| self.graph.node_weight(n))
            .map(|w| w.name.clone())
            .collect()
    }

    /// Return the direct derived classes of `class_name`.
    #[must_use]
    pub fn direct_derived(&self, class_name: &str) -> Vec<String> {
        let Some(start) = self.find_node(class_name) else {
            return Vec::new();
        };
        self.graph
            .neighbors_directed(start, Direction::Incoming)
            .filter_map(|n| self.graph.node_weight(n))
            .map(|w| w.name.clone())
            .collect()
    }

    /// Detect whether the graph contains a cycle (should not occur in valid C++).
    ///
    /// Uses an explicit-stack (iterative) three-colour DFS so that arbitrarily
    /// deep inheritance chains cannot overflow the native call stack.
    #[must_use]
    pub fn has_cycle(&self) -> bool {
        #[derive(Clone, Copy, PartialEq)]
        enum Color {
            White,
            Gray,
            Black,
        }
        let mut color = vec![Color::White; self.graph.node_count()];

        for start in self.graph.node_indices() {
            if color[start.index()] != Color::White {
                continue;
            }
            // Stack entries: (node, exiting). `exiting == true` marks the
            // post-order return, at which point the node turns Black.
            let mut stack: Vec<(NodeIndex, bool)> = vec![(start, false)];
            while let Some((node, exiting)) = stack.pop() {
                if exiting {
                    color[node.index()] = Color::Black;
                    continue;
                }
                match color[node.index()] {
                    Color::Gray | Color::Black => continue,
                    Color::White => {}
                }
                color[node.index()] = Color::Gray;
                stack.push((node, true));
                for neighbor in self.graph.neighbors_directed(node, Direction::Outgoing) {
                    match color[neighbor.index()] {
                        Color::Gray => return true,
                        Color::White => stack.push((neighbor, false)),
                        Color::Black => {}
                    }
                }
            }
        }
        false
    }

    /// Compute the BFS depth of every node from the given root.
    ///
    /// Returns a map from `NodeIndex` to depth (0 = root itself).
    #[must_use]
    pub fn depth_map(&self, root: NodeIndex) -> HashMap<NodeIndex, usize> {
        let mut depths = HashMap::new();
        let mut queue = VecDeque::new();

        depths.insert(root, 0);
        queue.push_back(root);

        while let Some(current) = queue.pop_front() {
            let depth = depths[&current];
            for neighbor in self.graph.neighbors_directed(current, Direction::Incoming) {
                if !depths.contains_key(&neighbor) {
                    depths.insert(neighbor, depth + 1);
                    queue.push_back(neighbor);
                }
            }
        }
        depths
    }

    /// Compute aggregate graph statistics.
    #[must_use]
    pub fn stats(&self) -> GraphStats {
        let node_count = self.graph.node_count();
        let edge_count = self.graph.edge_count();
        let roots = self.roots();
        let root_count = roots.len();
        let leaf_count = self.leaves().len();

        let multiple_inheritance_count = self
            .graph
            .node_indices()
            .filter(|&n| self.graph.edges_directed(n, Direction::Outgoing).count() > 1)
            .count();

        let max_depth = roots
            .iter()
            .flat_map(|&r| self.depth_map(r).into_values())
            .max()
            .unwrap_or(0);

        let has_cycle = self.has_cycle();

        GraphStats {
            node_count,
            edge_count,
            root_count,
            leaf_count,
            multiple_inheritance_count,
            max_depth,
            has_cycle,
        }
    }

    /// Export the graph as an adjacency list: `class_name → [base_names]`.
    #[must_use]
    pub fn to_adjacency_list(&self) -> HashMap<String, Vec<String>> {
        let mut adj: HashMap<String, Vec<String>> = HashMap::new();
        for node in self.graph.node_indices() {
            let name = self.graph.node_weight(node).map_or("", |w| &w.name).to_owned();
            let bases: Vec<String> = self
                .graph
                .neighbors_directed(node, Direction::Outgoing)
                .filter_map(|n| self.graph.node_weight(n))
                .map(|w| w.name.clone())
                .collect();
            adj.insert(name, bases);
        }
        adj
    }

    /// List all class names present in the graph.
    #[must_use]
    pub fn all_class_names(&self) -> Vec<String> {
        self.graph
            .node_indices()
            .filter_map(|n| self.graph.node_weight(n))
            .map(|w| w.name.clone())
            .collect()
    }

    /// Check whether `derived` inherits from `base` (directly or transitively).
    #[must_use]
    pub fn inherits_from(&self, derived: &str, base: &str) -> bool {
        if derived == base {
            return false;
        }
        let Some(start) = self.find_node(derived) else {
            return false;
        };
        self.bfs(start, Direction::Outgoing)
            .into_iter()
            .any(|n| self.graph.node_weight(n).is_some_and(|w| w.name == base))
    }
}

impl Default for InheritanceGrapher {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for InheritanceGrapher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InheritanceGrapher")
            .field("nodes", &self.graph.node_count())
            .field("edges", &self.graph.edge_count())
            .finish()
    }
}

// ── reconstruct_all ───────────────────────────────────────────────────────────

/// Build a complete [`InheritanceGrapher`] from a slice of [`RttiInfo`] records.
///
/// This is the primary free-function entry point.  All RTTI records are ingested
/// in a single pass; inferred base-class nodes are created for any base that does
/// not itself appear as a top-level `RttiInfo`.
#[must_use]
pub fn reconstruct_all(rtti_list: &[RttiInfo]) -> InheritanceGrapher {
    let mut grapher = InheritanceGrapher::new();
    grapher.build_from_rtti(rtti_list);
    grapher
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RttiAbi;

    fn make_rtti(name: &str, bases: &[&str], abi: RttiAbi) -> RttiInfo {
        RttiInfo {
            type_name: name.to_owned(),
            base_classes: bases.iter().map(|s| s.to_string()).collect(),
            rtti_address: 0,
            abi,
        }
    }

    // ── Basic construction ───────────────────────────────────────────────────

    #[test]
    fn new_is_empty() {
        let g = InheritanceGrapher::new();
        assert_eq!(g.node_count(), 0);
        assert_eq!(g.edge_count(), 0);
    }

    #[test]
    fn add_rtti_creates_nodes() {
        let mut g = InheritanceGrapher::new();
        g.add_rtti(&make_rtti("Derived", &["Base"], RttiAbi::Itanium));
        assert_eq!(g.node_count(), 2);
        assert_eq!(g.edge_count(), 1);
    }

    #[test]
    fn add_rtti_no_bases() {
        let mut g = InheritanceGrapher::new();
        g.add_rtti(&make_rtti("Root", &[], RttiAbi::Msvc));
        assert_eq!(g.node_count(), 1);
        assert_eq!(g.edge_count(), 0);
    }

    #[test]
    fn duplicate_edge_not_added() {
        let mut g = InheritanceGrapher::new();
        let rtti = make_rtti("D", &["B"], RttiAbi::Itanium);
        g.add_rtti(&rtti);
        g.add_rtti(&rtti);
        assert_eq!(g.edge_count(), 1);
    }

    #[test]
    fn multiple_inheritance_two_bases() {
        let mut g = InheritanceGrapher::new();
        g.add_rtti(&make_rtti("D", &["A", "B"], RttiAbi::Itanium));
        assert_eq!(g.node_count(), 3);
        assert_eq!(g.edge_count(), 2);
    }

    // ── reconstruct_all ──────────────────────────────────────────────────────

    #[test]
    fn reconstruct_all_builds_graph() {
        let list = vec![
            make_rtti("Animal", &[], RttiAbi::Itanium),
            make_rtti("Dog", &["Animal"], RttiAbi::Itanium),
            make_rtti("GoldenRetriever", &["Dog"], RttiAbi::Itanium),
        ];
        let g = reconstruct_all(&list);
        assert_eq!(g.node_count(), 3);
        assert_eq!(g.edge_count(), 2);
    }

    // ── Roots and leaves ─────────────────────────────────────────────────────

    #[test]
    fn roots_are_classes_without_bases() {
        let list = vec![
            make_rtti("Base", &[], RttiAbi::Itanium),
            make_rtti("Derived", &["Base"], RttiAbi::Itanium),
        ];
        let g = reconstruct_all(&list);
        let roots = g.roots();
        assert_eq!(roots.len(), 1);
        let root_name = &g.node_weight(roots[0]).unwrap().name;
        assert_eq!(root_name, "Base");
    }

    #[test]
    fn leaves_are_classes_without_derived() {
        let list = vec![
            make_rtti("Base", &[], RttiAbi::Itanium),
            make_rtti("Mid", &["Base"], RttiAbi::Itanium),
            make_rtti("Leaf", &["Mid"], RttiAbi::Itanium),
        ];
        let g = reconstruct_all(&list);
        let leaves = g.leaves();
        assert_eq!(leaves.len(), 1);
        let leaf_name = &g.node_weight(leaves[0]).unwrap().name;
        assert_eq!(leaf_name, "Leaf");
    }

    // ── BFS / DFS ────────────────────────────────────────────────────────────

    #[test]
    fn ancestors_walks_up() {
        let list = vec![
            make_rtti("Base", &[], RttiAbi::Itanium),
            make_rtti("Mid", &["Base"], RttiAbi::Itanium),
            make_rtti("Leaf", &["Mid"], RttiAbi::Itanium),
        ];
        let g = reconstruct_all(&list);
        let ancs = g.ancestors("Leaf");
        assert!(ancs.contains(&"Mid".to_string()));
        assert!(ancs.contains(&"Base".to_string()));
    }

    #[test]
    fn descendants_walks_down() {
        let list = vec![
            make_rtti("Base", &[], RttiAbi::Itanium),
            make_rtti("Mid", &["Base"], RttiAbi::Itanium),
            make_rtti("Leaf", &["Mid"], RttiAbi::Itanium),
        ];
        let g = reconstruct_all(&list);
        let desc = g.descendants("Base");
        assert!(desc.contains(&"Mid".to_string()));
        assert!(desc.contains(&"Leaf".to_string()));
    }

    #[test]
    fn ancestors_unknown_class_empty() {
        let g = InheritanceGrapher::new();
        assert!(g.ancestors("NoSuchClass").is_empty());
    }

    // ── inherits_from ────────────────────────────────────────────────────────

    #[test]
    fn inherits_from_direct() {
        let list = vec![
            make_rtti("Base", &[], RttiAbi::Itanium),
            make_rtti("Derived", &["Base"], RttiAbi::Itanium),
        ];
        let g = reconstruct_all(&list);
        assert!(g.inherits_from("Derived", "Base"));
        assert!(!g.inherits_from("Base", "Derived"));
    }

    #[test]
    fn inherits_from_transitive() {
        let list = vec![
            make_rtti("A", &[], RttiAbi::Itanium),
            make_rtti("B", &["A"], RttiAbi::Itanium),
            make_rtti("C", &["B"], RttiAbi::Itanium),
        ];
        let g = reconstruct_all(&list);
        assert!(g.inherits_from("C", "A"));
    }

    #[test]
    fn inherits_from_self_is_false() {
        let list = vec![make_rtti("A", &[], RttiAbi::Itanium)];
        let g = reconstruct_all(&list);
        assert!(!g.inherits_from("A", "A"));
    }

    // ── Stats ────────────────────────────────────────────────────────────────

    #[test]
    fn stats_empty_graph() {
        let g = InheritanceGrapher::new();
        let s = g.stats();
        assert_eq!(s.node_count, 0);
        assert_eq!(s.edge_count, 0);
        assert_eq!(s.root_count, 0);
        assert_eq!(s.max_depth, 0);
        assert!(!s.has_cycle);
    }

    #[test]
    fn stats_multiple_inheritance_counted() {
        let list = vec![make_rtti("D", &["A", "B"], RttiAbi::Itanium)];
        let g = reconstruct_all(&list);
        let s = g.stats();
        assert_eq!(s.multiple_inheritance_count, 1);
    }

    #[test]
    fn stats_display() {
        let g = InheritanceGrapher::new();
        let s = g.stats();
        assert!(s.to_string().contains("GraphStats"));
    }

    // ── has_cycle ────────────────────────────────────────────────────────────

    #[test]
    fn no_cycle_in_normal_hierarchy() {
        let list = vec![
            make_rtti("A", &[], RttiAbi::Itanium),
            make_rtti("B", &["A"], RttiAbi::Itanium),
        ];
        let g = reconstruct_all(&list);
        assert!(!g.has_cycle());
    }

    // ── ClassNode display ─────────────────────────────────────────────────────

    #[test]
    fn class_node_display_direct() {
        let n = ClassNode::new("MyClass", RttiAbi::Msvc, 0x1000);
        let s = n.to_string();
        assert!(s.contains("MyClass"));
        assert!(s.contains("msvc"));
    }

    #[test]
    fn class_node_display_inferred() {
        let n = ClassNode::inferred("InferredBase");
        let s = n.to_string();
        assert!(s.contains("inferred"));
    }

    // ── Adjacency list ────────────────────────────────────────────────────────

    #[test]
    fn adjacency_list_correct() {
        let list = vec![
            make_rtti("Base", &[], RttiAbi::Itanium),
            make_rtti("D", &["Base"], RttiAbi::Itanium),
        ];
        let g = reconstruct_all(&list);
        let adj = g.to_adjacency_list();
        let d_bases = adj.get("D").expect("D should be in the map");
        assert!(d_bases.contains(&"Base".to_string()));
    }

    // ── Debug format ─────────────────────────────────────────────────────────

    #[test]
    fn debug_format() {
        let g = InheritanceGrapher::new();
        let s = format!("{g:?}");
        assert!(s.contains("InheritanceGrapher"));
    }

    // ── InheritanceEdge ────────────────────────────────────────────────────────

    #[test]
    fn edge_display_virtual_public() {
        let e = InheritanceEdge {
            is_virtual: true,
            access: InheritanceAccess::Public,
        };
        assert!(e.to_string().contains("virtual"));
        assert!(e.to_string().contains("public"));
    }

    #[test]
    fn edge_default() {
        let e = InheritanceEdge::default();
        assert!(!e.is_virtual);
        assert_eq!(e.access, InheritanceAccess::Unknown);
    }

    // ── find_node ─────────────────────────────────────────────────────────────

    #[test]
    fn find_node_exists() {
        let list = vec![make_rtti("MyClass", &[], RttiAbi::Itanium)];
        let g = reconstruct_all(&list);
        assert!(g.find_node("MyClass").is_some());
        assert!(g.find_node("Other").is_none());
    }

    // ── direct_bases / direct_derived ────────────────────────────────────────

    #[test]
    fn direct_bases_correct() {
        let list = vec![make_rtti("D", &["A", "B"], RttiAbi::Itanium)];
        let g = reconstruct_all(&list);
        let bases = g.direct_bases("D");
        assert_eq!(bases.len(), 2);
        assert!(bases.contains(&"A".to_string()));
        assert!(bases.contains(&"B".to_string()));
    }

    // ── Regressions & property tests (graph-algorithm hardening pass) ────────

    /// `dfs_cycle` used native recursion: a 200k-deep inheritance chain
    /// overflowed the thread stack. Now iterative.
    #[test]
    fn regress_has_cycle_deep_chain_no_stack_overflow() {
        const N: usize = 200_000;
        let list: Vec<RttiInfo> = (0..N)
            .map(|i| make_rtti(&format!("C{i}"), &[&format!("C{}", i + 1)], RttiAbi::Itanium))
            .collect();
        let g = reconstruct_all(&list);
        assert!(!g.has_cycle());
        // Deep BFS-based queries must also survive.
        assert_eq!(g.ancestors("C0").len(), N);
    }

    #[test]
    fn regress_has_cycle_detects_deep_cycle() {
        const N: usize = 50_000;
        let mut list: Vec<RttiInfo> = (0..N)
            .map(|i| make_rtti(&format!("C{i}"), &[&format!("C{}", i + 1)], RttiAbi::Itanium))
            .collect();
        // Close the loop: C{N} inherits from C0.
        list.push(make_rtti(&format!("C{N}"), &["C0"], RttiAbi::Itanium));
        let g = reconstruct_all(&list);
        assert!(g.has_cycle());
    }

    #[test]
    fn regress_has_cycle_self_loop() {
        let g = reconstruct_all(&[make_rtti("A", &["A"], RttiAbi::Itanium)]);
        assert!(g.has_cycle());
    }

    use crate::test_prng::xorshift;

    /// Brute-force oracle: cycle exists iff Kahn's algorithm cannot
    /// eliminate all nodes.
    fn oracle_has_cycle(n: usize, edges: &[(usize, usize)]) -> bool {
        let mut out_deg = vec![0usize; n];
        let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
        for &(a, b) in edges {
            out_deg[a] += 1;
            preds[b].push(a);
        }
        let mut queue: Vec<usize> = (0..n).filter(|&i| out_deg[i] == 0).collect();
        let mut removed = 0;
        while let Some(v) = queue.pop() {
            removed += 1;
            for &p in &preds[v] {
                out_deg[p] -= 1;
                if out_deg[p] == 0 {
                    queue.push(p);
                }
            }
        }
        removed != n
    }

    /// Brute-force transitive-closure oracle (Floyd–Warshall boolean).
    fn oracle_reachable(n: usize, edges: &[(usize, usize)]) -> Vec<Vec<bool>> {
        let mut r = vec![vec![false; n]; n];
        for &(a, b) in edges {
            r[a][b] = true;
        }
        for k in 0..n {
            for i in 0..n {
                if r[i][k] {
                    for j in 0..n {
                        if r[k][j] {
                            r[i][j] = true;
                        }
                    }
                }
            }
        }
        r
    }

    /// Differential test: `has_cycle` / ancestors / descendants / `inherits_from`
    /// vs brute-force oracles on hundreds of random graphs.
    #[test]
    fn property_random_graphs_vs_oracles() {
        let mut seed = 0x1234_5678_9abc_def0_u64;
        for round in 0..300 {
            let n = 2 + (xorshift(&mut seed) % 9) as usize; // 2..=10 nodes
            let edge_count = (xorshift(&mut seed) % (2 * n as u64)) as usize;
            let mut edges: Vec<(usize, usize)> = Vec::new();
            for _ in 0..edge_count {
                let a = (xorshift(&mut seed) % n as u64) as usize;
                let b = (xorshift(&mut seed) % n as u64) as usize;
                if !edges.contains(&(a, b)) {
                    edges.push((a, b));
                }
            }

            // Build the grapher: one RttiInfo per node listing its bases.
            let list: Vec<RttiInfo> = (0..n)
                .map(|i| {
                    let bases: Vec<String> = edges
                        .iter()
                        .filter(|&&(a, _)| a == i)
                        .map(|&(_, b)| format!("N{b}"))
                        .collect();
                    RttiInfo {
                        type_name: format!("N{i}"),
                        base_classes: bases,
                        rtti_address: 0,
                        abi: RttiAbi::Itanium,
                    }
                })
                .collect();
            let g = reconstruct_all(&list);

            assert_eq!(
                g.has_cycle(),
                oracle_has_cycle(n, &edges),
                "cycle mismatch round {round}: n={n} edges={edges:?}"
            );

            let reach = oracle_reachable(n, &edges);
            for i in 0..n {
                let anc: HashSet<String> = g.ancestors(&format!("N{i}")).into_iter().collect();
                let desc: HashSet<String> = g.descendants(&format!("N{i}")).into_iter().collect();
                for j in 0..n {
                    let name_j = format!("N{j}");
                    // ancestors excludes self even on self-reachability via cycle,
                    // except BFS re-reaches start through a cycle — it never
                    // re-adds start, so membership matches reach for i != j.
                    if i != j {
                        assert_eq!(
                            anc.contains(&name_j),
                            reach[i][j],
                            "ancestor mismatch round {round}: {i}->{j} edges={edges:?}"
                        );
                        assert_eq!(
                            desc.contains(&name_j),
                            reach[j][i],
                            "descendant mismatch round {round}: {j}->{i} edges={edges:?}"
                        );
                        assert_eq!(
                            g.inherits_from(&format!("N{i}"), &name_j),
                            reach[i][j],
                            "inherits_from mismatch round {round}"
                        );
                    }
                }
            }
        }
    }

    /// `depth_map` must terminate and be consistent on cyclic graphs.
    #[test]
    fn regress_depth_map_terminates_on_cycle() {
        let list = vec![
            make_rtti("A", &["B"], RttiAbi::Itanium),
            make_rtti("B", &["A"], RttiAbi::Itanium),
        ];
        let g = reconstruct_all(&list);
        let a = g.find_node("A").unwrap();
        let depths = g.depth_map(a);
        assert!(depths.len() <= 2);
        let _ = g.stats(); // must also terminate
    }

    #[test]
    fn direct_derived_correct() {
        let list = vec![
            make_rtti("Base", &[], RttiAbi::Itanium),
            make_rtti("D1", &["Base"], RttiAbi::Itanium),
            make_rtti("D2", &["Base"], RttiAbi::Itanium),
        ];
        let g = reconstruct_all(&list);
        let derived = g.direct_derived("Base");
        assert_eq!(derived.len(), 2);
    }
}
