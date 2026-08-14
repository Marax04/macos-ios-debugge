//! `pass_dependency_graph` — dependency management for IL passes.
//!
//! Provides `PassDependencyGraph`, `DependencyNode`, `CycleDetector`,
//! `PassOrder`, `ConflictDetector`, and `PassImpact`.
//!
//! **Not currently wired into any pipeline runner.** `PassScheduler` here can
//! compute a dependency-respecting topological pass order
//! (`ordered_passes`/`PassOrder::compute`) and detect cycles/conflicts, but
//! `crate::PassPipeline` (the V2 `IlOptPass` runner) and its
//! `standard_pipeline()`/`fast_pipeline()` builders use a fixed, hand-written
//! pass order instead of consulting this module. This module is exercised
//! only by its own unit tests. See the crate root doc comment for the
//! broader V1 (`AnalysisPass`, canonical) vs V2 (`IlOptPass`, experimental)
//! picture.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

// Re-export the canonical profiler from pass_metrics; PassProfiler was a
// duplicate of MetricsCollector with a simpler API. Use MetricsCollector
// directly, or call record_pass(id, changes) for the simple case.
pub use crate::pass_metrics::MetricsCollector as PassProfiler;

// ── PassImpact ────────────────────────────────────────────────────────────────

/// What a pass reads or writes in the IL representation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PassImpact {
    /// Reads the instruction list without modification.
    Read,
    /// Modifies instruction contents (but not structure).
    Modify,
    /// May add or remove instructions.
    Structural,
    /// Invalidates a named analysis result.
    Invalidates(String),
    /// Requires a named analysis to be current.
    Requires(String),
}

impl PassImpact {
    #[must_use]
    pub const fn is_write(&self) -> bool {
        matches!(self, Self::Modify | Self::Structural)
    }
    #[must_use]
    pub const fn is_read(&self) -> bool {
        matches!(self, Self::Read | Self::Requires(_))
    }
    #[must_use]
    pub const fn invalidated(&self) -> Option<&str> {
        if let Self::Invalidates(s) = self {
            Some(s.as_str())
        } else {
            None
        }
    }
    #[must_use]
    pub const fn required(&self) -> Option<&str> {
        if let Self::Requires(s) = self {
            Some(s.as_str())
        } else {
            None
        }
    }
}

// ── DependencyNode ────────────────────────────────────────────────────────────

/// A node in the pass dependency graph representing a single pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyNode {
    /// Unique pass identifier.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Direct prerequisites (pass IDs that must run before this one).
    pub prerequisites: Vec<String>,
    /// Passes this one must run before.
    pub must_precede: Vec<String>,
    /// What this pass reads/writes.
    pub impacts: Vec<PassImpact>,
    /// Whether this pass is enabled.
    pub enabled: bool,
    /// Execution priority (lower = earlier when no ordering constraint exists).
    pub priority: i32,
}

impl DependencyNode {
    /// Create a basic pass node.
    #[must_use]
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            prerequisites: Vec::new(),
            must_precede: Vec::new(),
            impacts: Vec::new(),
            enabled: true,
            priority: 0,
        }
    }

    /// Add a prerequisite pass.
    #[must_use]
    pub fn requires(mut self, id: impl Into<String>) -> Self {
        self.prerequisites.push(id.into());
        self
    }

    /// Add an ordering constraint (this must precede the given pass).
    #[must_use]
    pub fn before(mut self, id: impl Into<String>) -> Self {
        self.must_precede.push(id.into());
        self
    }

    /// Add an impact declaration.
    #[must_use]
    pub fn impact(mut self, i: PassImpact) -> Self {
        self.impacts.push(i);
        self
    }

    /// Set priority.
    #[must_use]
    pub const fn priority(mut self, p: i32) -> Self {
        self.priority = p;
        self
    }

    /// Whether this node has the given prerequisite.
    #[must_use]
    pub fn depends_on(&self, id: &str) -> bool {
        self.prerequisites.iter().any(|p| p == id)
    }
}

// ── CycleDetector ─────────────────────────────────────────────────────────────

/// Detects cycles in the dependency graph using DFS.
pub struct CycleDetector;

impl CycleDetector {
    /// Maximum DFS recursion depth, to prevent stack-overflow on deep dependency
    /// chains in attacker-controlled graphs.
    const MAX_DEPTH: usize = 1024;

    /// Detect cycles in the dependency graph.
    /// Returns `Ok(())` if no cycles, or `Err(cycle_path)` for the first cycle found.
    ///
    /// # Errors
    /// Returns `Err` containing the cycle path if a cycle is detected.
    pub fn detect(graph: &PassDependencyGraph) -> Result<(), Vec<String>> {
        let mut visited: HashSet<String> = HashSet::new();
        let mut on_stack: HashSet<String> = HashSet::new();
        let mut path: Vec<String> = Vec::new();

        for id in graph.nodes.keys() {
            if !visited.contains(id) {
                Self::dfs(id, graph, &mut visited, &mut on_stack, &mut path, 0)?;
            }
        }
        Ok(())
    }

    fn dfs(
        node: &str,
        graph: &PassDependencyGraph,
        visited: &mut HashSet<String>,
        on_stack: &mut HashSet<String>,
        path: &mut Vec<String>,
        depth: usize,
    ) -> Result<(), Vec<String>> {
        // Guard against stack overflow from deeply nested dependency chains in
        // graphs built from untrusted input (dos-unbounded-recursion).
        if depth >= Self::MAX_DEPTH {
            return Err(vec![format!(
                "dependency chain exceeds maximum depth ({}) at node '{}'",
                Self::MAX_DEPTH,
                node
            )]);
        }

        visited.insert(node.to_string());
        on_stack.insert(node.to_string());
        path.push(node.to_string());

        if let Some(n) = graph.nodes.get(node) {
            for dep in &n.prerequisites {
                if !visited.contains(dep) {
                    Self::dfs(dep, graph, visited, on_stack, path, depth + 1)?;
                } else if on_stack.contains(dep) {
                    // Found a cycle
                    let cycle_start = path.iter().position(|x| x == dep).unwrap_or(0);
                    return Err(path[cycle_start..].to_vec());
                }
            }
        }

        path.pop();
        on_stack.remove(node);
        Ok(())
    }

    /// Return true if the graph has no cycles.
    #[must_use]
    pub fn is_acyclic(graph: &PassDependencyGraph) -> bool {
        Self::detect(graph).is_ok()
    }
}

// ── ConflictDetector ──────────────────────────────────────────────────────────

/// Detects ordering conflicts and incompatible passes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictReport {
    pub pass_a: String,
    pub pass_b: String,
    pub reason: String,
}

pub struct ConflictDetector;

impl ConflictDetector {
    /// Detect conflicts in the dependency graph.
    #[must_use]
    pub fn detect(graph: &PassDependencyGraph) -> Vec<ConflictReport> {
        let mut conflicts = Vec::new();

        // Check for "must_precede" contradictions
        for (id_a, node_a) in &graph.nodes {
            for must_before in &node_a.must_precede {
                if let Some(node_b) = graph.nodes.get(must_before) {
                    // If B also says it must precede A, that's a conflict
                    if node_b.must_precede.iter().any(|mp| mp == id_a) {
                        conflicts.push(ConflictReport {
                            pass_a: id_a.clone(),
                            pass_b: must_before.clone(),
                            reason: format!(
                                "{id_a} and {must_before} both claim to precede each other"
                            ),
                        });
                    }
                }
            }
        }

        // Check for write-write conflicts (two passes both modify the same analysis)
        let mut writes: HashMap<String, Vec<String>> = HashMap::new();
        for (id, node) in &graph.nodes {
            for impact in &node.impacts {
                if let PassImpact::Invalidates(s) = impact {
                    writes.entry(s.clone()).or_default().push(id.clone());
                }
            }
        }
        for (target, passlist) in &writes {
            if passlist.len() > 1 {
                for i in 0..passlist.len() {
                    for j in (i + 1)..passlist.len() {
                        conflicts.push(ConflictReport {
                            pass_a: passlist[i].clone(),
                            pass_b: passlist[j].clone(),
                            reason: format!("Both invalidate '{target}'"),
                        });
                    }
                }
            }
        }

        conflicts
    }
}

// ── PassOrder ─────────────────────────────────────────────────────────────────

/// Produces a valid topological execution order for all enabled passes.
pub struct PassOrder;

impl PassOrder {
    /// Compute a topological sort of enabled passes.
    ///
    /// Returns `Err(cycle)` if the dependency graph contains a cycle.
    ///
    /// # Errors
    /// Returns `Err` containing the cycle path if the dependency graph has a cycle.
    pub fn compute(graph: &PassDependencyGraph) -> Result<Vec<String>, Vec<String>> {
        CycleDetector::detect(graph)?;

        // Kahn's algorithm
        let enabled_nodes: Vec<&DependencyNode> =
            graph.nodes.values().filter(|n| n.enabled).collect();

        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        for node in &enabled_nodes {
            in_degree.entry(&node.id).or_insert(0);
            for dep in &node.prerequisites {
                if graph.nodes.get(dep).is_some_and(|n| n.enabled) {
                    *in_degree.entry(dep).or_insert(0) += 0; // ensure key exists
                    *in_degree.entry(&node.id).or_insert(0) += 1;
                }
            }
        }

        // Start with nodes that have no prerequisites
        let mut queue: VecDeque<&str> = in_degree
            .iter()
            .filter(|&(_, deg)| *deg == 0)
            .map(|(&id, _)| id)
            .collect();

        // Sort queue by priority for determinism
        let mut queue_vec: Vec<&str> = std::mem::take(&mut queue).into_iter().collect();
        queue_vec.sort_by_key(|id| graph.nodes[*id].priority);
        queue.extend(queue_vec);

        let mut order = Vec::new();
        while let Some(current) = queue.pop_front() {
            order.push(current.to_string());
            // Reduce in-degree for all nodes that depend on current
            for (id, node) in &graph.nodes {
                if node.enabled && node.prerequisites.iter().any(|d| d == current)
                    && let Some(deg) = in_degree.get_mut(id.as_str()) {
                        if *deg > 0 {
                            *deg -= 1;
                        }
                        if *deg == 0 {
                            queue.push_back(id.as_str());
                        }
                    }
            }
        }

        Ok(order)
    }

    /// Return the execution order as a list of `DependencyNode` refs.
    ///
    /// # Errors
    /// Returns `Err` containing the cycle path if the dependency graph has a cycle.
    pub fn compute_nodes(
        graph: &PassDependencyGraph,
    ) -> Result<Vec<&DependencyNode>, Vec<String>> {
        let order = Self::compute(graph)?;
        Ok(order.iter().filter_map(|id| graph.nodes.get(id)).collect())
    }
}

// ── PassDependencyGraph ───────────────────────────────────────────────────────

/// A directed acyclic graph of pass dependencies.
#[derive(Debug, Default)]
pub struct PassDependencyGraph {
    pub nodes: HashMap<String, DependencyNode>,
}

impl PassDependencyGraph {
    /// Create an empty dependency graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a pass node.
    pub fn add_pass(&mut self, node: DependencyNode) {
        self.nodes.insert(node.id.clone(), node);
    }

    /// Remove a pass by ID.
    pub fn remove_pass(&mut self, id: &str) -> Option<DependencyNode> {
        self.nodes.remove(id)
    }

    /// Enable or disable a pass.
    pub fn set_enabled(&mut self, id: &str, enabled: bool) {
        if let Some(node) = self.nodes.get_mut(id) {
            node.enabled = enabled;
        }
    }

    /// Get a pass node by ID.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&DependencyNode> {
        self.nodes.get(id)
    }

    /// Total number of registered passes.
    #[must_use]
    pub fn pass_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of enabled passes.
    #[must_use]
    pub fn enabled_count(&self) -> usize {
        self.nodes.values().filter(|n| n.enabled).count()
    }

    /// Return all direct dependents (nodes that depend on `id`).
    #[must_use]
    pub fn dependents_of(&self, id: &str) -> Vec<&DependencyNode> {
        self.nodes.values().filter(|n| n.depends_on(id)).collect()
    }

    /// Return all transitive prerequisites of a pass.
    #[must_use]
    pub fn transitive_prerequisites(&self, id: &str) -> HashSet<String> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        if let Some(node) = self.nodes.get(id) {
            queue.extend(node.prerequisites.iter().cloned());
        }
        while let Some(dep) = queue.pop_front() {
            if visited.insert(dep.clone())
                && let Some(node) = self.nodes.get(&dep) {
                    queue.extend(node.prerequisites.iter().cloned());
                }
        }
        visited
    }

    /// Check whether running `a` before `b` is consistent with all constraints.
    #[must_use]
    pub fn is_valid_order(&self, a: &str, b: &str) -> bool {
        // b must not be a prerequisite of a
        let Some(node_a) = self.nodes.get(a) else { return true };
        if node_a.prerequisites.iter().any(|p| p == b) {
            return false; // b must come before a, not after
        }
        // a must not say it must_precede b when b is already ordered after a
        // (no additional constraint violated in this direction)
        true
    }

    /// Return all passes whose impacts include a given analysis requirement.
    #[must_use]
    pub fn providers_of(&self, analysis: &str) -> Vec<&DependencyNode> {
        self.nodes
            .values()
            .filter(|n| {
                n.impacts.iter().any(|i| {
                    if let PassImpact::Invalidates(s) = i {
                        s == analysis
                    } else {
                        false
                    }
                })
            })
            .collect()
    }

    /// Build a standard optimization pipeline graph.
    #[must_use]
    pub fn standard_pipeline() -> Self {
        let mut g = Self::new();
        g.add_pass(
            DependencyNode::new("ConstantFolding", "Constant Folding")
                .priority(-10)
                .impact(PassImpact::Modify)
                .impact(PassImpact::Invalidates("def-use".into())),
        );
        g.add_pass(
            DependencyNode::new("DeadCodeElim", "Dead Code Elimination")
                .requires("ConstantFolding")
                .priority(-5)
                .impact(PassImpact::Structural)
                .impact(PassImpact::Invalidates("cfg".into())),
        );
        g.add_pass(
            DependencyNode::new("CSE", "Common Subexpression Elimination")
                .requires("ConstantFolding")
                .priority(0)
                .impact(PassImpact::Modify),
        );
        g.add_pass(
            DependencyNode::new("InlineSmall", "Inline Small Functions")
                .requires("DeadCodeElim")
                .priority(5)
                .impact(PassImpact::Structural),
        );
        g
    }
}

// ── PassRegistry ─────────────────────────────────────────────────────────────

/// A global registry of available passes that can be instantiated into a graph.
#[derive(Debug, Default)]
pub struct PassRegistry {
    descriptors: Vec<PassDescriptor>,
}

/// Metadata for a registrable pass.
#[derive(Debug, Clone)]
pub struct PassDescriptor {
    pub id: String,
    pub display_name: String,
    pub default_enabled: bool,
    pub default_priority: i32,
    pub category: PassCategory,
}

/// Broad category of pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassCategory {
    Analysis,
    Optimization,
    Transformation,
    Verification,
}

impl PassRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a pass descriptor.
    pub fn register(&mut self, desc: PassDescriptor) {
        self.descriptors.push(desc);
    }

    /// Build a dependency graph with all registered passes (no dependencies set).
    #[must_use]
    pub fn build_graph(&self) -> PassDependencyGraph {
        let mut g = PassDependencyGraph::new();
        for desc in &self.descriptors {
            let node =
                DependencyNode::new(&desc.id, &desc.display_name).priority(desc.default_priority);
            let mut node = node;
            node.enabled = desc.default_enabled;
            g.add_pass(node);
        }
        g
    }

    /// All registered pass IDs.
    #[must_use]
    pub fn all_ids(&self) -> Vec<&str> {
        self.descriptors.iter().map(|d| d.id.as_str()).collect()
    }

    /// Passes in a given category.
    #[must_use]
    pub fn by_category(&self, cat: PassCategory) -> Vec<&PassDescriptor> {
        self.descriptors
            .iter()
            .filter(|d| d.category == cat)
            .collect()
    }

    /// Number of registered passes.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.descriptors.len()
    }
}

// ── PassReport ────────────────────────────────────────────────────────────────

/// A summary report after running a pass pipeline.
#[derive(Debug, Clone, Default)]
pub struct PassReport {
    pub order: Vec<String>,
    pub passes_run: usize,
    pub total_changes: usize,
    pub conflicts: Vec<String>,
    pub has_cycle: bool,
}

impl PassReport {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate a report from a graph and profiler.
    #[must_use] 
    pub fn generate(graph: &PassDependencyGraph, profiler: &PassProfiler) -> Self {
        let order =
            PassOrder::compute(graph).unwrap_or_else(|cycle| vec![format!("CYCLE: {:?}", cycle)]);
        let conflicts: Vec<String> = ConflictDetector::detect(graph)
            .into_iter()
            .map(|c| c.reason)
            .collect();
        let has_cycle = !CycleDetector::is_acyclic(graph);
        Self {
            passes_run: order.len(),
            total_changes: usize::try_from(profiler.total_transforms()).unwrap_or(usize::MAX),
            order,
            conflicts,
            has_cycle,
        }
    }

    /// Human-readable one-liner.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} passes, {} changes, {} conflicts{}",
            self.passes_run,
            self.total_changes,
            self.conflicts.len(),
            if self.has_cycle { " [CYCLE!]" } else { "" }
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_graph() -> PassDependencyGraph {
        let mut g = PassDependencyGraph::new();
        g.add_pass(DependencyNode::new("A", "Pass A").priority(0));
        g.add_pass(DependencyNode::new("B", "Pass B").requires("A").priority(1));
        g.add_pass(DependencyNode::new("C", "Pass C").requires("B").priority(2));
        g
    }

    // ── PassImpact ─────────────────────────────────────────────────────────────

    #[test]
    fn test_impact_is_write() {
        assert!(PassImpact::Modify.is_write());
        assert!(PassImpact::Structural.is_write());
        assert!(!PassImpact::Read.is_write());
    }

    #[test]
    fn test_impact_is_read() {
        assert!(PassImpact::Read.is_read());
        assert!(PassImpact::Requires("cfg".into()).is_read());
        assert!(!PassImpact::Modify.is_read());
    }

    #[test]
    fn test_impact_invalidated() {
        let i = PassImpact::Invalidates("def-use".into());
        assert_eq!(i.invalidated(), Some("def-use"));
        assert_eq!(PassImpact::Read.invalidated(), None);
    }

    #[test]
    fn test_impact_required() {
        let i = PassImpact::Requires("cfg".into());
        assert_eq!(i.required(), Some("cfg"));
        assert_eq!(PassImpact::Modify.required(), None);
    }

    // ── DependencyNode ─────────────────────────────────────────────────────────

    #[test]
    fn test_node_new_defaults() {
        let n = DependencyNode::new("P1", "Pass 1");
        assert_eq!(n.id, "P1");
        assert!(n.enabled);
        assert_eq!(n.priority, 0);
        assert!(n.prerequisites.is_empty());
    }

    #[test]
    fn test_node_builder_chain() {
        let n = DependencyNode::new("P2", "Pass 2")
            .requires("P1")
            .before("P3")
            .impact(PassImpact::Modify)
            .priority(5);
        assert!(n.depends_on("P1"));
        assert_eq!(n.must_precede, vec!["P3".to_string()]);
        assert_eq!(n.impacts, vec![PassImpact::Modify]);
        assert_eq!(n.priority, 5);
    }

    #[test]
    fn test_node_depends_on() {
        let n = DependencyNode::new("P3", "Pass 3")
            .requires("P1")
            .requires("P2");
        assert!(n.depends_on("P1"));
        assert!(n.depends_on("P2"));
        assert!(!n.depends_on("P4"));
    }

    // ── PassDependencyGraph ────────────────────────────────────────────────────

    #[test]
    fn test_graph_add_and_count() {
        let g = simple_graph();
        assert_eq!(g.pass_count(), 3);
        assert_eq!(g.enabled_count(), 3);
    }

    #[test]
    fn test_graph_set_disabled() {
        let mut g = simple_graph();
        g.set_enabled("A", false);
        assert_eq!(g.enabled_count(), 2);
    }

    #[test]
    fn test_graph_remove_pass() {
        let mut g = simple_graph();
        let removed = g.remove_pass("C");
        assert!(removed.is_some());
        assert_eq!(g.pass_count(), 2);
    }

    #[test]
    fn test_graph_dependents_of() {
        let g = simple_graph();
        let deps = g.dependents_of("A");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].id, "B");
    }

    #[test]
    fn test_graph_transitive_prerequisites() {
        let g = simple_graph();
        let prereqs = g.transitive_prerequisites("C");
        assert!(prereqs.contains("A"));
        assert!(prereqs.contains("B"));
    }

    #[test]
    fn test_graph_providers_of() {
        let mut g = PassDependencyGraph::new();
        g.add_pass(DependencyNode::new("P1", "P1").impact(PassImpact::Invalidates("cfg".into())));
        let providers = g.providers_of("cfg");
        assert_eq!(providers.len(), 1);
    }

    #[test]
    fn test_graph_standard_pipeline() {
        let g = PassDependencyGraph::standard_pipeline();
        assert!(g.pass_count() > 0);
        assert!(g.get("ConstantFolding").is_some());
    }

    // ── CycleDetector ─────────────────────────────────────────────────────────

    #[test]
    fn test_cycle_detector_no_cycle() {
        let g = simple_graph();
        assert!(CycleDetector::is_acyclic(&g));
        assert!(CycleDetector::detect(&g).is_ok());
    }

    #[test]
    fn test_cycle_detector_detects_cycle() {
        let mut g = PassDependencyGraph::new();
        g.add_pass(DependencyNode::new("A", "A").requires("B"));
        g.add_pass(DependencyNode::new("B", "B").requires("A"));
        assert!(!CycleDetector::is_acyclic(&g));
        assert!(CycleDetector::detect(&g).is_err());
    }

    #[test]
    fn test_cycle_detector_self_loop() {
        let mut g = PassDependencyGraph::new();
        g.add_pass(DependencyNode::new("A", "A").requires("A"));
        assert!(!CycleDetector::is_acyclic(&g));
    }

    #[test]
    fn test_cycle_detector_three_node_cycle() {
        let mut g = PassDependencyGraph::new();
        g.add_pass(DependencyNode::new("A", "A").requires("C"));
        g.add_pass(DependencyNode::new("B", "B").requires("A"));
        g.add_pass(DependencyNode::new("C", "C").requires("B"));
        assert!(!CycleDetector::is_acyclic(&g));
    }

    #[test]
    fn test_cycle_reports_path() {
        let mut g = PassDependencyGraph::new();
        g.add_pass(DependencyNode::new("A", "A").requires("B"));
        g.add_pass(DependencyNode::new("B", "B").requires("A"));
        let result = CycleDetector::detect(&g);
        assert!(result.is_err());
        let path = result.unwrap_err();
        assert!(!path.is_empty());
    }

    // ── ConflictDetector ──────────────────────────────────────────────────────

    #[test]
    fn test_conflict_no_conflicts() {
        let g = simple_graph();
        let conflicts = ConflictDetector::detect(&g);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_conflict_circular_must_precede() {
        let mut g = PassDependencyGraph::new();
        g.add_pass(DependencyNode::new("A", "A").before("B"));
        g.add_pass(DependencyNode::new("B", "B").before("A"));
        let conflicts = ConflictDetector::detect(&g);
        assert!(!conflicts.is_empty());
    }

    #[test]
    fn test_conflict_write_write() {
        let mut g = PassDependencyGraph::new();
        g.add_pass(DependencyNode::new("P1", "P1").impact(PassImpact::Invalidates("cfg".into())));
        g.add_pass(DependencyNode::new("P2", "P2").impact(PassImpact::Invalidates("cfg".into())));
        let conflicts = ConflictDetector::detect(&g);
        assert!(!conflicts.is_empty());
    }

    // ── PassOrder ─────────────────────────────────────────────────────────────

    #[test]
    fn test_pass_order_simple() {
        let g = simple_graph();
        let order = PassOrder::compute(&g).unwrap();
        let a_pos = order.iter().position(|x| x == "A").unwrap();
        let b_pos = order.iter().position(|x| x == "B").unwrap();
        let c_pos = order.iter().position(|x| x == "C").unwrap();
        assert!(a_pos < b_pos);
        assert!(b_pos < c_pos);
    }

    #[test]
    fn test_pass_order_cycle_returns_err() {
        let mut g = PassDependencyGraph::new();
        g.add_pass(DependencyNode::new("A", "A").requires("B"));
        g.add_pass(DependencyNode::new("B", "B").requires("A"));
        assert!(PassOrder::compute(&g).is_err());
    }

    #[test]
    fn test_pass_order_disabled_excluded() {
        let mut g = simple_graph();
        g.set_enabled("C", false);
        let order = PassOrder::compute(&g).unwrap();
        assert!(!order.contains(&"C".to_string()));
        assert_eq!(order.len(), 2);
    }

    #[test]
    fn test_pass_order_single_node() {
        let mut g = PassDependencyGraph::new();
        g.add_pass(DependencyNode::new("Solo", "Solo"));
        let order = PassOrder::compute(&g).unwrap();
        assert_eq!(order, vec!["Solo".to_string()]);
    }

    #[test]
    fn test_pass_order_priority_used() {
        let mut g = PassDependencyGraph::new();
        g.add_pass(DependencyNode::new("High", "High").priority(-10));
        g.add_pass(DependencyNode::new("Low", "Low").priority(10));
        let order = PassOrder::compute(&g).unwrap();
        let hi = order.iter().position(|x| x == "High").unwrap();
        let lo = order.iter().position(|x| x == "Low").unwrap();
        assert!(hi < lo);
    }

    #[test]
    fn test_pass_order_standard_pipeline() {
        let g = PassDependencyGraph::standard_pipeline();
        let order = PassOrder::compute(&g).unwrap();
        let cf_pos = order.iter().position(|x| x == "ConstantFolding").unwrap();
        let dce_pos = order.iter().position(|x| x == "DeadCodeElim").unwrap();
        assert!(cf_pos < dce_pos);
    }

    #[test]
    fn test_pass_order_compute_nodes() {
        let g = simple_graph();
        let nodes = PassOrder::compute_nodes(&g).unwrap();
        assert_eq!(nodes.len(), 3);
        // A should come first
        assert_eq!(nodes[0].id, "A");
    }

    #[test]
    fn test_graph_get_node() {
        let g = simple_graph();
        let node = g.get("B").unwrap();
        assert_eq!(node.name, "Pass B");
    }

    #[test]
    fn test_graph_is_valid_order_ok() {
        let g = simple_graph();
        // A before B is valid (B requires A)
        assert!(g.is_valid_order("A", "B"));
    }

    #[test]
    fn test_graph_is_valid_order_violation() {
        let g = simple_graph();
        // B before A is NOT valid (B requires A, so A must come first)
        assert!(!g.is_valid_order("B", "A"));
    }

    #[test]
    fn test_graph_add_and_get_pass() {
        let mut g = PassDependencyGraph::new();
        g.add_pass(DependencyNode::new("X", "Pass X").priority(42));
        let n = g.get("X").unwrap();
        assert_eq!(n.priority, 42);
    }

    #[test]
    fn test_graph_transitive_empty_for_root() {
        let g = simple_graph();
        let prereqs = g.transitive_prerequisites("A");
        assert!(prereqs.is_empty());
    }

    #[test]
    fn test_dependency_node_enabled_default() {
        let n = DependencyNode::new("P", "Pass P");
        assert!(n.enabled);
    }

    #[test]
    fn test_pass_impact_equality() {
        assert_eq!(PassImpact::Read, PassImpact::Read);
        assert_ne!(PassImpact::Modify, PassImpact::Read);
        assert_eq!(
            PassImpact::Invalidates("cfg".into()),
            PassImpact::Invalidates("cfg".into()),
        );
        assert_ne!(
            PassImpact::Invalidates("cfg".into()),
            PassImpact::Invalidates("dom".into()),
        );
    }

    #[test]
    fn test_conflict_no_conflicts_standard_pipeline() {
        let g = PassDependencyGraph::standard_pipeline();
        // Standard pipeline should have no must_precede conflicts
        
        assert!(!ConflictDetector::detect(&g)
            .into_iter().any(|c| c.reason.contains("both claim to precede")));
    }

    #[test]
    fn test_graph_enabled_count_after_bulk_disable() {
        let mut g = simple_graph();
        g.set_enabled("A", false);
        g.set_enabled("B", false);
        assert_eq!(g.enabled_count(), 1);
    }

    #[test]
    fn test_pass_order_empty_graph() {
        let g = PassDependencyGraph::new();
        let order = PassOrder::compute(&g).unwrap();
        assert!(order.is_empty());
    }

    #[test]
    fn test_dependency_node_before_builder() {
        let n = DependencyNode::new("A", "A").before("B").before("C");
        assert_eq!(n.must_precede.len(), 2);
    }

    // ── Additional integration tests ──────────────────────────────────────────

    #[test]
    fn test_full_pipeline_ordering() {
        // Build a realistic pipeline with 6 passes
        let mut g = PassDependencyGraph::new();
        g.add_pass(DependencyNode::new("Lift", "IL Lift").priority(0));
        g.add_pass(
            DependencyNode::new("SSA", "SSA Conversion")
                .requires("Lift")
                .priority(1),
        );
        g.add_pass(
            DependencyNode::new("CF", "Constant Fold")
                .requires("SSA")
                .priority(2),
        );
        g.add_pass(
            DependencyNode::new("DCE", "Dead Code Elim")
                .requires("CF")
                .priority(3),
        );
        g.add_pass(DependencyNode::new("CSE", "CSE").requires("CF").priority(3));
        g.add_pass(
            DependencyNode::new("EmitHLIL", "Emit HLIL")
                .requires("DCE")
                .requires("CSE")
                .priority(10),
        );

        assert!(CycleDetector::is_acyclic(&g));
        let order = PassOrder::compute(&g).unwrap();
        assert_eq!(order[0], "Lift");
        assert!(order.contains(&"SSA".to_string()));
        // EmitHLIL must come after DCE and CSE
        let dce_pos = order.iter().position(|x| x == "DCE").unwrap();
        let cse_pos = order.iter().position(|x| x == "CSE").unwrap();
        let emit_pos = order.iter().position(|x| x == "EmitHLIL").unwrap();
        assert!(dce_pos < emit_pos);
        assert!(cse_pos < emit_pos);
    }

    #[test]
    fn test_transitive_prerequisites_deep() {
        let mut g = PassDependencyGraph::new();
        g.add_pass(DependencyNode::new("A", "A").priority(0));
        g.add_pass(DependencyNode::new("B", "B").requires("A"));
        g.add_pass(DependencyNode::new("C", "C").requires("B"));
        g.add_pass(DependencyNode::new("D", "D").requires("C"));
        let prereqs = g.transitive_prerequisites("D");
        assert!(prereqs.contains("A"));
        assert!(prereqs.contains("B"));
        assert!(prereqs.contains("C"));
        assert!(!prereqs.contains("D"));
    }
}

// ── PassScheduler ─────────────────────────────────────────────────────────────

/// Schedules passes for iterative execution until a fixed point is reached.
pub struct PassScheduler {
    graph: PassDependencyGraph,
    /// Maximum number of overall iterations before giving up.
    pub max_iterations: usize,
}

impl PassScheduler {
    /// Create a scheduler from a dependency graph.
    #[must_use]
    pub const fn new(graph: PassDependencyGraph, max_iterations: usize) -> Self {
        Self {
            graph,
            max_iterations,
        }
    }

    /// Compute the ordered pass list (Err on cycle).
    ///
    /// # Errors
    /// Returns `Err` containing the cycle path if the dependency graph has a cycle.
    pub fn ordered_passes(&self) -> Result<Vec<String>, Vec<String>> {
        PassOrder::compute(&self.graph)
    }

    /// Run `passes` in the computed order, calling `run_pass` for each.
    /// Returns the number of iterations until fixpoint (or `max_iterations`).
    ///
    /// # Errors
    /// Returns `Err` containing the cycle path if the dependency graph has a cycle.
    pub fn run_until_fixpoint<F>(&self, mut run_pass: F) -> Result<usize, Vec<String>>
    where
        F: FnMut(&str) -> bool,
    {
        let order = self.ordered_passes()?;
        for iteration in 0..self.max_iterations {
            let mut any_changed = false;
            for pass_id in &order {
                let changed = run_pass(pass_id);
                if changed {
                    any_changed = true;
                }
            }
            if !any_changed {
                return Ok(iteration + 1);
            }
        }
        Ok(self.max_iterations)
    }

    /// Check if the graph is valid for scheduling.
    #[must_use]
    pub fn is_schedulable(&self) -> bool {
        CycleDetector::is_acyclic(&self.graph)
            && ConflictDetector::detect(&self.graph)
                .iter()
                .all(|c| !c.reason.contains("both claim"))
    }

    /// Graph reference.
    #[must_use]
    pub const fn graph(&self) -> &PassDependencyGraph {
        &self.graph
    }
}

// PassProfiler is now a type alias for MetricsCollector (see top of file).
// All existing call sites using PassProfiler::new(), record(), total(), etc.
// continue to work through MetricsCollector's API or the new record_pass /
// total_transforms helpers added to MetricsCollector.

#[cfg(test)]
mod extra_tests {
    use super::*;

    fn simple_graph() -> PassDependencyGraph {
        let mut g = PassDependencyGraph::new();
        g.add_pass(DependencyNode::new("A", "Pass A").priority(0));
        g.add_pass(DependencyNode::new("B", "Pass B").requires("A").priority(1));
        g
    }

    // ── PassScheduler ─────────────────────────────────────────────────────────

    #[test]
    fn test_scheduler_ordered_passes() {
        let g = simple_graph();
        let sched = PassScheduler::new(g, 10);
        let order = sched.ordered_passes().unwrap();
        let a_pos = order.iter().position(|x| x == "A").unwrap();
        let b_pos = order.iter().position(|x| x == "B").unwrap();
        assert!(a_pos < b_pos);
    }

    #[test]
    fn test_scheduler_fixpoint_no_changes() {
        let g = simple_graph();
        let sched = PassScheduler::new(g, 5);
        // Pass that never changes anything
        let iters = sched.run_until_fixpoint(|_| false).unwrap();
        assert_eq!(iters, 1); // converges in first iteration
    }

    #[test]
    fn test_scheduler_fixpoint_always_changes() {
        let g = simple_graph();
        let sched = PassScheduler::new(g, 3);
        let iters = sched.run_until_fixpoint(|_| true).unwrap();
        assert_eq!(iters, 3); // hits max
    }

    #[test]
    fn test_scheduler_is_schedulable() {
        let g = simple_graph();
        let sched = PassScheduler::new(g, 5);
        assert!(sched.is_schedulable());
    }

    #[test]
    fn test_scheduler_not_schedulable_cycle() {
        let mut g = PassDependencyGraph::new();
        g.add_pass(DependencyNode::new("A", "A").requires("B"));
        g.add_pass(DependencyNode::new("B", "B").requires("A"));
        let sched = PassScheduler::new(g, 5);
        assert!(!sched.is_schedulable());
    }

    // ── PassProfiler (now MetricsCollector alias) ─────────────────────────────
    // Tests migrated to use MetricsCollector's canonical API.

    #[test]
    fn test_profiler_record_and_retrieve() {
        let mut p = PassProfiler::new();
        p.record_pass("CF", 5);
        p.record_pass("CF", 3);
        // run_count is the invocation count; total_transforms is the sum of changes.
        let prof = p.profile_for("CF").expect("profile should exist");
        assert_eq!(prof.run_count, 2);
        assert_eq!(prof.total_transforms, 8);
    }

    #[test]
    fn test_profiler_most_active() {
        let mut p = PassProfiler::new();
        p.record_pass("CF", 10);
        p.record_pass("DCE", 3);
        // Compute most-active by iterating profiles (replaces old most_active()).
        let most = p.profiles.iter()
            .max_by_key(|(_, prof)| prof.total_transforms)
            .map(|(id, _)| id.as_str());
        assert_eq!(most, Some("CF"));
    }

    #[test]
    fn test_profiler_total() {
        let mut p = PassProfiler::new();
        p.record_pass("A", 5);
        p.record_pass("B", 7);
        assert_eq!(p.total_transforms(), 12);
    }

    #[test]
    fn test_profiler_unknown_pass_zero() {
        let p = PassProfiler::new();
        assert_eq!(p.profile_for("unknown").map_or(0, |pr| pr.run_count), 0);
        assert_eq!(p.profile_for("unknown").map_or(0, |pr| pr.total_transforms), 0);
    }

    #[test]
    fn test_profiler_most_active_empty() {
        let p = PassProfiler::new();
        let most = p.profiles.iter()
            .max_by_key(|(_, prof)| prof.total_transforms)
            .map(|(id, _)| id.as_str());
        assert!(most.is_none());
    }
}
