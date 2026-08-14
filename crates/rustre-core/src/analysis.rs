//! Analysis pass infrastructure for the RustRE platform.
//!
//! This module provides a topologically-ordered pass manager that can run
//! registered [`AnalysisPass`] implementations in dependency order, detect
//! cycles, and report per-pass results.
//!
//! # Example
//!
//! ```
//! use rustre_core::analysis::{AnalysisPassInfo, PassManager};
//!
//! let mut manager = PassManager::new();
//! manager.register_pass(AnalysisPassInfo::new("cfg-build", &[]));
//! manager.register_pass(AnalysisPassInfo::new("type-infer", &["cfg-build"]));
//! let order = manager.topological_order().expect("no cycles");
//! assert_eq!(order[0], "cfg-build");
//! ```

use crate::errors::{CoreError, Result};
use std::collections::{HashMap, HashSet, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// PassResult
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome returned by a single analysis pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PassResult {
    /// The pass ran successfully and made progress.
    Ok,
    /// The pass ran successfully but made no changes (already converged).
    Unchanged,
    /// The pass was skipped because a dependency failed.
    Skipped,
    /// The pass failed with a diagnostic message.
    Failed(String),
}

impl PassResult {
    /// Return `true` if the pass succeeded (either Ok or Unchanged).
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Ok | Self::Unchanged)
    }

    /// Return `true` if the pass made changes.
    #[must_use]
    pub const fn is_progress(&self) -> bool {
        matches!(self, Self::Ok)
    }
}

impl std::fmt::Display for PassResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => write!(f, "ok"),
            Self::Unchanged => write!(f, "unchanged"),
            Self::Skipped => write!(f, "skipped"),
            Self::Failed(msg) => write!(f, "failed: {msg}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PassDependency
// ─────────────────────────────────────────────────────────────────────────────

/// A dependency edge between analysis passes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassDependency {
    /// The name of the pass that must run first.
    pub name: String,
    /// Whether the dependency is hard (must succeed) or soft (best-effort).
    pub required: bool,
}

impl PassDependency {
    /// Construct a hard dependency.
    #[must_use]
    pub fn required(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            required: true,
        }
    }

    /// Construct a soft dependency.
    #[must_use]
    pub fn optional(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            required: false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisPassInfo — lightweight descriptor (no dyn overhead)
// ─────────────────────────────────────────────────────────────────────────────

/// Static metadata for an analysis pass.
///
/// Used by the [`PassManager`] to build the dependency graph and topological
/// ordering without requiring the pass implementation to be type-erased.
#[derive(Debug, Clone)]
pub struct AnalysisPassInfo {
    /// Unique name identifying this pass (used as the dependency key).
    pub name: String,
    /// Names of passes that must run before this one.
    pub dependencies: Vec<String>,
    /// Human-readable description of what the pass does.
    pub description: String,
    /// Whether to run this pass in parallel with independent peers.
    pub parallelizable: bool,
}

impl AnalysisPassInfo {
    /// Construct minimal pass info with no description.
    #[must_use]
    pub fn new(name: &str, dependencies: &[&str]) -> Self {
        Self {
            name: name.to_owned(),
            dependencies: dependencies
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            description: String::new(),
            parallelizable: false,
        }
    }

    /// Attach a description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Mark this pass as safe to run in parallel.
    #[must_use]
    pub const fn parallelizable(mut self) -> Self {
        self.parallelizable = true;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisPass — the trait that concrete passes implement
// ─────────────────────────────────────────────────────────────────────────────

/// The core trait for analysis passes.
///
/// Implementors produce or refine analysis data stored in `BinaryView` or
/// some external store.  The trait is object-safe so passes can be collected
/// into `Vec<Box<dyn AnalysisPass>>`.
pub trait AnalysisPass: Send + Sync + std::fmt::Debug {
    /// Return the static metadata for this pass.
    fn info(&self) -> AnalysisPassInfo;

    /// Execute the pass.  Implementations should be idempotent where possible.
    ///
    /// # Errors
    /// Returns [`CoreError`] on unrecoverable failures.
    fn run(&self) -> Result<PassResult>;

    /// Return `true` if the pass is currently applicable (e.g. all preconditions
    /// are satisfied without running dependencies).  Defaults to `true`.
    fn is_applicable(&self) -> bool {
        true
    }

    /// Optional cleanup / teardown called after the pass manager finishes.
    fn cleanup(&self) {}
}

// ─────────────────────────────────────────────────────────────────────────────
// PassManager — dependency-aware pass scheduler
// ─────────────────────────────────────────────────────────────────────────────

/// Manages the registration and topological ordering of analysis passes.
///
/// ## Dependency resolution
///
/// Passes declare their dependencies in [`AnalysisPassInfo::dependencies`].
/// The pass manager builds a directed acyclic graph (DAG) and uses
/// Kahn's algorithm to produce a linear topological order.  A cycle in
/// the dependency graph returns [`CoreError::AnalysisError`].
///
/// ## Usage
///
/// ```
/// use rustre_core::analysis::{AnalysisPassInfo, PassManager};
///
/// let mut manager = PassManager::new();
/// manager.register_pass(AnalysisPassInfo::new("cfg", &[]));
/// manager.register_pass(AnalysisPassInfo::new("dom-tree", &["cfg"]));
/// let order = manager.topological_order().unwrap();
///
/// // A dependency must be scheduled before the pass that needs it.
/// assert_eq!(order, vec!["cfg", "dom-tree"]);
/// ```
#[derive(Debug, Default)]
pub struct PassManager {
    /// All registered pass descriptors, in insertion order.
    passes: Vec<AnalysisPassInfo>,
}

impl PassManager {
    /// Create an empty pass manager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a pass.  Duplicate names are silently replaced.
    pub fn register_pass(&mut self, info: AnalysisPassInfo) {
        if let Some(existing) = self.passes.iter_mut().find(|p| p.name == info.name) {
            *existing = info;
        } else {
            self.passes.push(info);
        }
    }

    /// Remove a pass by name.  Returns `true` if it was present.
    pub fn unregister_pass(&mut self, name: &str) -> bool {
        let before = self.passes.len();
        self.passes.retain(|p| p.name != name);
        self.passes.len() < before
    }

    /// Return the number of registered passes.
    #[must_use]
    pub const fn pass_count(&self) -> usize {
        self.passes.len()
    }

    /// Return `true` if a pass with `name` is registered.
    #[must_use]
    pub fn has_pass(&self, name: &str) -> bool {
        self.passes.iter().any(|p| p.name == name)
    }

    /// Return a reference to the pass info with the given name.
    #[must_use]
    pub fn get_pass(&self, name: &str) -> Option<&AnalysisPassInfo> {
        self.passes.iter().find(|p| p.name == name)
    }

    /// Compute a topological ordering of all registered passes using
    /// Kahn's algorithm.
    ///
    /// # Errors
    /// Returns [`CoreError::AnalysisError`] if a cycle is detected in the
    /// dependency graph.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
    pub fn topological_order(&self) -> Result<Vec<String>> {
        // Build adjacency list: name → set of successors (passes that depend on it).
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        let mut successors: HashMap<&str, Vec<&str>> = HashMap::new();

        for pass in &self.passes {
            in_degree.entry(&pass.name).or_insert(0);
            for dep in &pass.dependencies {
                successors.entry(dep.as_str()).or_default().push(&pass.name);
                *in_degree.entry(&pass.name).or_insert(0) += 1;
            }
        }

        // Kahn's BFS: start with all nodes that have in-degree 0.
        let mut queue: VecDeque<&str> = in_degree
            .iter()
            .filter(|&(_, deg)| *deg == 0)
            .map(|(name, _)| *name)
            .collect();
        // Sort queue for deterministic output (in-place via contiguous slice).
        queue.make_contiguous().sort_unstable();

        let mut order: Vec<String> = Vec::with_capacity(self.passes.len());

        while let Some(name) = queue.pop_front() {
            order.push(name.to_owned());
            if let Some(succs) = successors.get(name) {
                let mut next: Vec<&str> = Vec::new();
                for &succ in succs {
                    let deg = in_degree.get_mut(succ).expect("in_degree entry missing");
                    *deg -= 1;
                    if *deg == 0 {
                        next.push(succ);
                    }
                }
                next.sort_unstable();
                queue.extend(next);
            }
        }

        if order.len() != self.passes.len() {
            return Err(CoreError::analysis(
                "analysis pass dependency graph contains a cycle",
            ));
        }

        Ok(order)
    }

    /// Return all passes in topological order as `AnalysisPassInfo` references.
    ///
    /// # Errors
    /// Propagates cycle detection errors from [`topological_order`](Self::topological_order).
    pub fn ordered_passes(&self) -> Result<Vec<&AnalysisPassInfo>> {
        let order = self.topological_order()?;
        Ok(order
            .iter()
            .filter_map(|name| self.passes.iter().find(|p| &p.name == name))
            .collect())
    }

    /// Return names of all passes that directly or transitively depend on `name`.
    #[must_use]
    pub fn dependents_of(&self, name: &str) -> Vec<String> {
        let mut visited: HashSet<String> = HashSet::new();
        let mut frontier: VecDeque<String> = VecDeque::new();

        // Direct dependents first.
        for pass in &self.passes {
            if pass.dependencies.iter().any(|d| d == name) {
                frontier.push_back(pass.name.clone());
            }
        }

        while let Some(current) = frontier.pop_front() {
            if visited.insert(current.clone()) {
                for pass in &self.passes {
                    if pass.dependencies.iter().any(|d| d == &current) {
                        frontier.push_back(pass.name.clone());
                    }
                }
            }
        }

        let mut result: Vec<String> = visited.into_iter().collect();
        result.sort();
        result
    }

    /// Return names of all passes that `name` directly or transitively depends on.
    #[must_use]
    pub fn dependencies_of(&self, name: &str) -> Vec<String> {
        let mut visited: HashSet<String> = HashSet::new();
        let mut frontier: VecDeque<String> = VecDeque::new();

        // Seed with the direct dependencies of `name`.
        if let Some(pass) = self.passes.iter().find(|p| p.name == name) {
            for dep in &pass.dependencies {
                frontier.push_back(dep.clone());
            }
        }

        while let Some(current) = frontier.pop_front() {
            if visited.insert(current.clone())
                && let Some(pass) = self.passes.iter().find(|p| p.name == current)
            {
                for dep in &pass.dependencies {
                    frontier.push_back(dep.clone());
                }
            }
        }

        let mut result: Vec<String> = visited.into_iter().collect();
        result.sort();
        result
    }

    /// Clear all registered passes.
    pub fn clear(&mut self) {
        self.passes.clear();
    }

    /// Validate that every dependency named by a registered pass is itself
    /// registered.  Returns a list of `(pass_name, missing_dep)` pairs.
    #[must_use]
    pub fn validate_dependencies(&self) -> Vec<(String, String)> {
        let names: HashSet<&str> = self.passes.iter().map(|p| p.name.as_str()).collect();
        let mut missing = Vec::new();
        for pass in &self.passes {
            for dep in &pass.dependencies {
                if !names.contains(dep.as_str()) {
                    missing.push((pass.name.clone(), dep.clone()));
                }
            }
        }
        missing
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager(names_and_deps: &[(&str, &[&str])]) -> PassManager {
        let mut m = PassManager::new();
        for &(name, deps) in names_and_deps {
            m.register_pass(AnalysisPassInfo::new(name, deps));
        }
        m
    }

    #[test]
    fn empty_manager() {
        let m = PassManager::new();
        assert_eq!(m.pass_count(), 0);
        assert!(m.topological_order().unwrap().is_empty());
    }

    #[test]
    fn single_pass_no_deps() {
        let m = make_manager(&[("cfg", &[])]);
        let order = m.topological_order().unwrap();
        assert_eq!(order, vec!["cfg"]);
    }

    #[test]
    fn linear_chain() {
        let m = make_manager(&[("a", &[]), ("b", &["a"]), ("c", &["b"])]);
        let order = m.topological_order().unwrap();
        assert_eq!(order, vec!["a", "b", "c"]);
    }

    #[test]
    fn diamond_dependency() {
        let m = make_manager(&[
            ("root", &[]),
            ("left", &["root"]),
            ("right", &["root"]),
            ("join", &["left", "right"]),
        ]);
        let order = m.topological_order().unwrap();
        let root_pos = order.iter().position(|n| n == "root").unwrap();
        let left_pos = order.iter().position(|n| n == "left").unwrap();
        let right_pos = order.iter().position(|n| n == "right").unwrap();
        let join_pos = order.iter().position(|n| n == "join").unwrap();
        assert!(root_pos < left_pos);
        assert!(root_pos < right_pos);
        assert!(left_pos < join_pos);
        assert!(right_pos < join_pos);
    }

    #[test]
    fn cycle_detection() {
        let m = make_manager(&[("a", &["b"]), ("b", &["c"]), ("c", &["a"])]);
        assert!(m.topological_order().is_err());
    }

    #[test]
    fn self_loop_detected() {
        let m = make_manager(&[("a", &["a"])]);
        assert!(m.topological_order().is_err());
    }

    #[test]
    fn register_duplicate_replaces() {
        let mut m = PassManager::new();
        m.register_pass(AnalysisPassInfo::new("a", &[]));
        m.register_pass(AnalysisPassInfo::new("a", &[]).with_description("updated"));
        assert_eq!(m.pass_count(), 1);
        assert_eq!(m.get_pass("a").unwrap().description, "updated");
    }

    #[test]
    fn unregister_pass() {
        let mut m = make_manager(&[("a", &[]), ("b", &[])]);
        assert!(m.unregister_pass("a"));
        assert!(!m.has_pass("a"));
        assert_eq!(m.pass_count(), 1);
        assert!(!m.unregister_pass("nonexistent"));
    }

    #[test]
    fn dependents_of() {
        let m = make_manager(&[("base", &[]), ("mid", &["base"]), ("top", &["mid"])]);
        let deps = m.dependents_of("base");
        assert!(deps.contains(&"mid".to_string()));
        assert!(deps.contains(&"top".to_string()));
    }

    #[test]
    fn dependencies_of() {
        let m = make_manager(&[("base", &[]), ("mid", &["base"]), ("top", &["mid"])]);
        let deps = m.dependencies_of("top");
        assert!(deps.contains(&"base".to_string()));
        assert!(deps.contains(&"mid".to_string()));
    }

    #[test]
    fn validate_missing_deps() {
        let m = make_manager(&[("a", &["missing_pass"])]);
        let missing = m.validate_dependencies();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].0, "a");
        assert_eq!(missing[0].1, "missing_pass");
    }

    #[test]
    fn validate_all_present() {
        let m = make_manager(&[("a", &[]), ("b", &["a"])]);
        assert!(m.validate_dependencies().is_empty());
    }

    #[test]
    fn pass_result_predicates() {
        assert!(PassResult::Ok.is_success());
        assert!(PassResult::Unchanged.is_success());
        assert!(!PassResult::Skipped.is_success());
        assert!(!PassResult::Failed("err".into()).is_success());

        assert!(PassResult::Ok.is_progress());
        assert!(!PassResult::Unchanged.is_progress());
    }

    #[test]
    fn pass_result_display() {
        assert_eq!(PassResult::Ok.to_string(), "ok");
        assert_eq!(PassResult::Unchanged.to_string(), "unchanged");
        assert_eq!(PassResult::Skipped.to_string(), "skipped");
        assert_eq!(
            PassResult::Failed("boom".into()).to_string(),
            "failed: boom"
        );
    }

    #[test]
    fn ordered_passes_returns_all() {
        let m = make_manager(&[("x", &[]), ("y", &["x"])]);
        let ordered = m.ordered_passes().unwrap();
        assert_eq!(ordered.len(), 2);
        assert_eq!(ordered[0].name, "x");
        assert_eq!(ordered[1].name, "y");
    }

    #[test]
    fn clear_empties_manager() {
        let mut m = make_manager(&[("a", &[]), ("b", &[])]);
        m.clear();
        assert_eq!(m.pass_count(), 0);
        assert!(m.topological_order().unwrap().is_empty());
    }

    #[test]
    fn pass_dependency_constructors() {
        let hard = PassDependency::required("cfg");
        assert!(hard.required);
        assert_eq!(hard.name, "cfg");

        let soft = PassDependency::optional("debug-info");
        assert!(!soft.required);
    }

    #[test]
    fn pass_info_builder() {
        let info = AnalysisPassInfo::new("my-pass", &["dep-a", "dep-b"])
            .with_description("does stuff")
            .parallelizable();
        assert_eq!(info.name, "my-pass");
        assert_eq!(info.dependencies.len(), 2);
        assert_eq!(info.description, "does stuff");
        assert!(info.parallelizable);
    }

    #[test]
    fn many_independent_passes_all_appear() {
        let passes: Vec<(&str, &[&str])> = (0..10)
            .map(|i| {
                (
                    Box::leak(format!("pass_{i}").into_boxed_str()) as &str,
                    &[][..],
                )
            })
            .collect();
        let m = make_manager(&passes);
        let order = m.topological_order().unwrap();
        assert_eq!(order.len(), 10);
    }

    #[test]
    fn complex_graph_no_cycle() {
        let m = make_manager(&[
            ("a", &[]),
            ("b", &[]),
            ("c", &["a", "b"]),
            ("d", &["c"]),
            ("e", &["c"]),
            ("f", &["d", "e"]),
        ]);
        let order = m.topological_order().unwrap();
        assert_eq!(order.len(), 6);
        let a_pos = order.iter().position(|n| n == "a").unwrap();
        let b_pos = order.iter().position(|n| n == "b").unwrap();
        let c_pos = order.iter().position(|n| n == "c").unwrap();
        let f_pos = order.iter().position(|n| n == "f").unwrap();
        assert!(a_pos < c_pos);
        assert!(b_pos < c_pos);
        assert!(c_pos < f_pos);
    }
}
