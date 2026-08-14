//! Analysis pass scheduler.
//!
//! Provides [`AnalysisScheduler`], a topological-sort engine that orders
//! [`AnalysisPass`]es according to their declared dependencies before
//! execution, and detects dependency cycles at registration time.
//!
//! The scheduler is intentionally decoupled from any execution engine: it
//! produces a [`ScheduleOrder`] (a plain list of pass names) that the caller
//! can use to drive its own executor.
//!
//! Key types:
//! - [`PassDependency`] — declares that one pass must run after another.
//! - [`ScheduleOrder`] — the resolved execution order.
//! - [`ScheduleGroup`] — a set of passes with no mutual dependencies that may
//!   run concurrently.
//! - [`AnalysisScheduler`] — the scheduler itself.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// PassDependency
// ─────────────────────────────────────────────────────────────────────────────

/// Declares a dependency between two analysis passes.
///
/// A `PassDependency { before, after }` means that `before` must complete
/// before `after` can start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassDependency {
    /// The pass that must run first.
    pub before: String,
    /// The pass that must run second.
    pub after: String,
}

impl PassDependency {
    /// Create a new dependency.
    #[must_use]
    pub fn new(before: impl Into<String>, after: impl Into<String>) -> Self {
        Self {
            before: before.into(),
            after: after.into(),
        }
    }
}

impl fmt::Display for PassDependency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} → {}", self.before, self.after)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ScheduleOrder
// ─────────────────────────────────────────────────────────────────────────────

/// A resolved linear execution order for analysis passes.
///
/// The order is guaranteed to satisfy all registered [`PassDependency`]
/// constraints.
#[derive(Debug, Clone)]
pub struct ScheduleOrder {
    /// Pass names in execution order.
    pub order: Vec<String>,
    /// Total number of passes scheduled.
    pub pass_count: usize,
    /// Whether the schedule was resolved from a cycle-free graph.
    pub is_valid: bool,
}

impl ScheduleOrder {
    const fn new(order: Vec<String>) -> Self {
        let count = order.len();
        Self {
            order,
            pass_count: count,
            is_valid: true,
        }
    }

    /// Return the position of `pass_name` in the schedule (0-based).
    #[must_use]
    pub fn position(&self, pass_name: &str) -> Option<usize> {
        self.order.iter().position(|n| n == pass_name)
    }

    /// Return `true` if `a` is scheduled before `b`.
    #[must_use]
    pub fn is_before(&self, a: &str, b: &str) -> bool {
        match (self.position(a), self.position(b)) {
            (Some(pa), Some(pb)) => pa < pb,
            _ => false,
        }
    }

    /// Iterate over the pass names in execution order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.order.iter().map(String::as_str)
    }
}

impl fmt::Display for ScheduleOrder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ScheduleOrder[{}]", self.order.join(", "))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ScheduleGroup
// ─────────────────────────────────────────────────────────────────────────────

/// A set of passes that can run concurrently because they have no mutual
/// dependencies.
#[derive(Debug, Clone)]
pub struct ScheduleGroup {
    /// Index of this group in the parallel schedule (0-based).
    pub group_index: usize,
    /// Pass names in this group.
    pub passes: Vec<String>,
}

impl ScheduleGroup {
    /// Number of passes in this group.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.passes.len()
    }

    /// True if the group contains no passes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.passes.is_empty()
    }
}

impl fmt::Display for ScheduleGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Group#{} [{}]", self.group_index, self.passes.join(", "))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ScheduleError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from [`AnalysisScheduler`].
#[derive(Debug, Clone)]
pub enum ScheduleError {
    /// A dependency cycle was detected; field contains the cycle members.
    CycleDetected(Vec<String>),
    /// A dependency references a pass name that was never registered.
    UnknownPass(String),
    /// A pass was registered twice with different priorities.
    DuplicatePass(String),
}

impl fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CycleDetected(cycle) => {
                write!(f, "dependency cycle: {}", cycle.join(" → "))
            }
            Self::UnknownPass(name) => write!(f, "unknown pass in dependency: '{name}'"),
            Self::DuplicatePass(name) => write!(f, "duplicate pass registration: '{name}'"),
        }
    }
}

impl std::error::Error for ScheduleError {}

// ─────────────────────────────────────────────────────────────────────────────
// PassRegistration
// ─────────────────────────────────────────────────────────────────────────────

/// Internal registration record for one analysis pass.
#[derive(Debug, Clone)]
struct PassRegistration {
    name: String,
    priority: i32,
    tags: Vec<String>,
    disabled: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisScheduler
// ─────────────────────────────────────────────────────────────────────────────

/// Orders analysis passes according to declared dependencies.
///
/// Passes are registered with [`register`](Self::register), dependencies with
/// [`add_dependency`](Self::add_dependency).  Call [`schedule`](Self::schedule)
/// to produce a [`ScheduleOrder`] or
/// [`schedule_parallel`](Self::schedule_parallel) for concurrent groups.
#[derive(Debug, Default)]
pub struct AnalysisScheduler {
    /// All registered passes in registration order.
    passes: Vec<PassRegistration>,
    /// Name → index into `passes`.
    pass_index: HashMap<String, usize>,
    /// Dependency edges: (before, after).
    dependencies: Vec<PassDependency>,
}

impl AnalysisScheduler {
    /// Create an empty scheduler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ── Registration ─────────────────────────────────────────────────────────

    /// Register a pass with the given name and priority.
    ///
    /// Higher `priority` values run earlier when no dependency ordering
    /// constrains them.
    ///
    /// # Errors
    ///
    /// Returns [`ScheduleError::DuplicatePass`] if `name` was already
    /// registered.
    pub fn register(&mut self, name: impl Into<String>, priority: i32) -> Result<(), ScheduleError> {
        let name = name.into();
        if self.pass_index.contains_key(&name) {
            return Err(ScheduleError::DuplicatePass(name));
        }
        let idx = self.passes.len();
        self.pass_index.insert(name.clone(), idx);
        self.passes.push(PassRegistration {
            name,
            priority,
            tags: Vec::new(),
            disabled: false,
        });
        Ok(())
    }

    /// Register a pass with default priority 0.
    ///
    /// # Errors
    ///
    /// Propagates from [`register`](Self::register).
    pub fn register_default(&mut self, name: impl Into<String>) -> Result<(), ScheduleError> {
        self.register(name, 0)
    }

    /// Add a tag to a registered pass. Returns `false` if the pass is unknown.
    pub fn add_tag(&mut self, pass_name: &str, tag: impl Into<String>) -> bool {
        if let Some(&idx) = self.pass_index.get(pass_name) {
            self.passes[idx].tags.push(tag.into());
            true
        } else {
            false
        }
    }

    /// Disable a registered pass so it is excluded from schedules.
    pub fn disable_pass(&mut self, pass_name: &str) -> bool {
        if let Some(&idx) = self.pass_index.get(pass_name) {
            self.passes[idx].disabled = true;
            true
        } else {
            false
        }
    }

    /// Re-enable a previously disabled pass.
    pub fn enable_pass(&mut self, pass_name: &str) -> bool {
        if let Some(&idx) = self.pass_index.get(pass_name) {
            self.passes[idx].disabled = false;
            true
        } else {
            false
        }
    }

    // ── Dependencies ─────────────────────────────────────────────────────────

    /// Add a dependency: `before` must complete before `after` starts.
    ///
    /// # Errors
    ///
    /// Returns [`ScheduleError::UnknownPass`] if either name was not
    /// registered.
    pub fn add_dependency(
        &mut self,
        before: impl Into<String>,
        after: impl Into<String>,
    ) -> Result<(), ScheduleError> {
        let before = before.into();
        let after = after.into();
        if !self.pass_index.contains_key(&before) {
            return Err(ScheduleError::UnknownPass(before));
        }
        if !self.pass_index.contains_key(&after) {
            return Err(ScheduleError::UnknownPass(after));
        }
        self.dependencies.push(PassDependency::new(before, after));
        Ok(())
    }

    // ── Scheduling ────────────────────────────────────────────────────────────

    /// Compute a linear [`ScheduleOrder`] respecting all dependencies.
    ///
    /// Passes with higher priority run earlier among those that are ready at
    /// the same time.
    ///
    /// # Errors
    ///
    /// Returns [`ScheduleError::CycleDetected`] if the dependency graph has
    /// a cycle.
    pub fn schedule(&self) -> Result<ScheduleOrder, ScheduleError> {
        let active: Vec<&PassRegistration> =
            self.passes.iter().filter(|p| !p.disabled).collect();

        let mut in_degree: HashMap<&str, usize> = active
            .iter()
            .map(|p| (p.name.as_str(), 0))
            .collect();
        let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();

        for dep in &self.dependencies {
            if !in_degree.contains_key(dep.before.as_str())
                || !in_degree.contains_key(dep.after.as_str())
            {
                continue; // skip edges involving disabled passes
            }
            *in_degree.entry(dep.after.as_str()).or_insert(0) += 1;
            dependents
                .entry(dep.before.as_str())
                .or_default()
                .push(dep.after.as_str());
        }

        // Kahn's algorithm with priority tie-breaking
        let mut ready: Vec<&PassRegistration> = active
            .iter()
            .filter(|p| in_degree.get(p.name.as_str()).copied().unwrap_or(0) == 0)
            .copied()
            .collect();
        ready.sort_unstable_by(|a, b| b.priority.cmp(&a.priority));

        let mut queue: VecDeque<&PassRegistration> = ready.into_iter().collect();
        let mut order: Vec<String> = Vec::new();

        while let Some(pass) = queue.pop_front() {
            order.push(pass.name.clone());
            if let Some(deps) = dependents.get(pass.name.as_str()) {
                let mut newly_ready: Vec<&PassRegistration> = Vec::new();
                for &dep_name in deps {
                    if let Some(degree) = in_degree.get_mut(dep_name) {
                        *degree = degree.saturating_sub(1);
                        if *degree == 0
                            && let Some(&idx) = self.pass_index.get(dep_name) {
                                newly_ready.push(&self.passes[idx]);
                            }
                    }
                }
                newly_ready.sort_unstable_by(|a, b| b.priority.cmp(&a.priority));
                for p in newly_ready {
                    queue.push_back(p);
                }
            }
        }

        if order.len() != active.len() {
            let in_cycle: Vec<String> = active
                .iter()
                .filter(|p| !order.contains(&p.name))
                .map(|p| p.name.clone())
                .collect();
            return Err(ScheduleError::CycleDetected(in_cycle));
        }

        Ok(ScheduleOrder::new(order))
    }

    /// Compute a parallel schedule as a list of [`ScheduleGroup`]s.
    ///
    /// Passes in the same group have no mutual dependencies and can run
    /// concurrently.
    ///
    /// # Errors
    ///
    /// Returns [`ScheduleError::CycleDetected`] if the dependency graph has a
    /// cycle.
    pub fn schedule_parallel(&self) -> Result<Vec<ScheduleGroup>, ScheduleError> {
        let active: Vec<&PassRegistration> =
            self.passes.iter().filter(|p| !p.disabled).collect();

        let mut in_degree: HashMap<&str, usize> = active
            .iter()
            .map(|p| (p.name.as_str(), 0))
            .collect();
        let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();

        for dep in &self.dependencies {
            if !in_degree.contains_key(dep.before.as_str())
                || !in_degree.contains_key(dep.after.as_str())
            {
                continue;
            }
            *in_degree.entry(dep.after.as_str()).or_insert(0) += 1;
            dependents
                .entry(dep.before.as_str())
                .or_default()
                .push(dep.after.as_str());
        }

        let mut groups: Vec<ScheduleGroup> = Vec::new();
        let mut total = 0usize;
        let mut group_index = 0usize;

        loop {
            let mut ready: Vec<&PassRegistration> = active
                .iter()
                .filter(|p| in_degree.contains_key(p.name.as_str()))
                .filter(|p| in_degree.get(p.name.as_str()).copied().unwrap_or(1) == 0)
                .copied()
                .collect();

            if ready.is_empty() {
                break;
            }

            ready.sort_unstable_by(|a, b| b.priority.cmp(&a.priority));

            let passes: Vec<String> = ready.iter().map(|p| p.name.clone()).collect();
            total += passes.len();

            // Remove ready passes from consideration
            for p in &ready {
                in_degree.remove(p.name.as_str());
            }

            // Decrement in-degrees of dependents
            for p in &ready {
                if let Some(deps) = dependents.get(p.name.as_str()) {
                    for &dep_name in deps {
                        if let Some(degree) = in_degree.get_mut(dep_name) {
                            *degree = degree.saturating_sub(1);
                        }
                    }
                }
            }

            groups.push(ScheduleGroup { group_index, passes });
            group_index += 1;
        }

        if total != active.len() {
            let scheduled: HashSet<&str> = groups
                .iter()
                .flat_map(|g| g.passes.iter().map(String::as_str))
                .collect();
            let in_cycle: Vec<String> = active
                .iter()
                .filter(|p| !scheduled.contains(p.name.as_str()))
                .map(|p| p.name.clone())
                .collect();
            return Err(ScheduleError::CycleDetected(in_cycle));
        }

        Ok(groups)
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    /// Return `true` if `name` is a registered (possibly disabled) pass.
    #[must_use]
    pub fn is_registered(&self, name: &str) -> bool {
        self.pass_index.contains_key(name)
    }

    /// Number of registered passes (including disabled ones).
    #[must_use]
    pub const fn pass_count(&self) -> usize {
        self.passes.len()
    }

    /// Number of registered dependencies.
    #[must_use]
    pub const fn dependency_count(&self) -> usize {
        self.dependencies.len()
    }

    /// Return all dependencies declared for a given pass (as the *after* side).
    #[must_use]
    pub fn dependencies_of(&self, pass_name: &str) -> Vec<&PassDependency> {
        self.dependencies
            .iter()
            .filter(|d| d.after == pass_name)
            .collect()
    }

    /// Return the names of passes that must run before `pass_name`.
    #[must_use]
    pub fn prerequisites(&self, pass_name: &str) -> Vec<&str> {
        self.dependencies
            .iter()
            .filter(|d| d.after == pass_name)
            .map(|d| d.before.as_str())
            .collect()
    }

    /// Validate the dependency graph without producing a schedule.
    ///
    /// # Errors
    ///
    /// Returns [`ScheduleError::CycleDetected`] if a cycle exists.
    pub fn validate(&self) -> Result<(), ScheduleError> {
        self.schedule().map(|_| ())
    }

    /// Clear all registered passes and dependencies.
    pub fn clear(&mut self) {
        self.passes.clear();
        self.pass_index.clear();
        self.dependencies.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SchedulerBuilder — fluent construction
// ─────────────────────────────────────────────────────────────────────────────

/// Fluent builder for [`AnalysisScheduler`].
pub struct SchedulerBuilder {
    scheduler: AnalysisScheduler,
}

impl SchedulerBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            scheduler: AnalysisScheduler::new(),
        }
    }

    /// Register a pass with default priority.
    ///
    /// # Panics
    ///
    /// Panics if the pass name is a duplicate.
    #[must_use]
    pub fn pass(mut self, name: &str) -> Self {
        self.scheduler
            .register(name, 0)
            .expect("duplicate pass registration");
        self
    }

    /// Register a pass with a specific priority.
    ///
    /// # Panics
    ///
    /// Panics if the pass name is a duplicate.
    #[must_use]
    pub fn pass_with_priority(mut self, name: &str, priority: i32) -> Self {
        self.scheduler
            .register(name, priority)
            .expect("duplicate pass registration");
        self
    }

    /// Add a dependency.
    ///
    /// # Panics
    ///
    /// Panics if either pass name was not previously registered.
    #[must_use]
    pub fn dep(mut self, before: &str, after: &str) -> Self {
        self.scheduler
            .add_dependency(before, after)
            .expect("dependency registration failed");
        self
    }

    /// Build the [`AnalysisScheduler`].
    #[must_use]
    pub fn build(self) -> AnalysisScheduler {
        self.scheduler
    }
}

impl Default for SchedulerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_scheduler() -> AnalysisScheduler {
        SchedulerBuilder::new()
            .pass("A")
            .pass("B")
            .pass("C")
            .dep("A", "B")
            .dep("B", "C")
            .build()
    }

    #[test]
    fn test_linear_schedule_respects_deps() {
        let sched = simple_scheduler();
        let order = sched.schedule().unwrap();
        assert!(order.is_before("A", "B"));
        assert!(order.is_before("B", "C"));
        assert!(order.is_before("A", "C"));
    }

    #[test]
    fn test_schedule_order_len() {
        let sched = simple_scheduler();
        let order = sched.schedule().unwrap();
        assert_eq!(order.pass_count, 3);
    }

    #[test]
    fn test_cycle_detection() {
        let mut sched = AnalysisScheduler::new();
        sched.register("X", 0).unwrap();
        sched.register("Y", 0).unwrap();
        sched.add_dependency("X", "Y").unwrap();
        sched.add_dependency("Y", "X").unwrap();
        let err = sched.schedule().unwrap_err();
        assert!(matches!(err, ScheduleError::CycleDetected(_)));
    }

    #[test]
    fn test_unknown_pass_in_dep() {
        let mut sched = AnalysisScheduler::new();
        sched.register("A", 0).unwrap();
        let err = sched.add_dependency("A", "Ghost");
        assert!(matches!(err, Err(ScheduleError::UnknownPass(_))));
    }

    #[test]
    fn test_duplicate_registration() {
        let mut sched = AnalysisScheduler::new();
        sched.register("A", 0).unwrap();
        let err = sched.register("A", 1);
        assert!(matches!(err, Err(ScheduleError::DuplicatePass(_))));
    }

    #[test]
    fn test_parallel_schedule_groups() {
        let sched = SchedulerBuilder::new()
            .pass("A")
            .pass("B")
            .pass("C")
            .pass("D")
            .dep("A", "C")
            .dep("B", "C")
            .dep("C", "D")
            .build();
        let groups = sched.schedule_parallel().unwrap();
        // Group 0: A and B (both independent)
        // Group 1: C (depends on A and B)
        // Group 2: D (depends on C)
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].passes.len(), 2);
        assert_eq!(groups[1].passes.len(), 1);
        assert_eq!(groups[2].passes.len(), 1);
        assert!(groups[1].passes.contains(&"C".to_string()));
        assert!(groups[2].passes.contains(&"D".to_string()));
    }

    #[test]
    fn test_priority_ordering() {
        let sched = SchedulerBuilder::new()
            .pass_with_priority("Low", 0)
            .pass_with_priority("High", 10)
            .build();
        let order = sched.schedule().unwrap();
        assert!(order.is_before("High", "Low"));
    }

    #[test]
    fn test_disabled_pass_excluded() {
        let mut sched = simple_scheduler();
        sched.disable_pass("B");
        let order = sched.schedule().unwrap();
        // B is excluded; C has its dependency on B removed from the active graph,
        // so C should still appear.
        assert!(!order.order.contains(&"B".to_string()));
        assert!(order.order.contains(&"C".to_string()));
    }

    #[test]
    fn test_enable_pass() {
        let mut sched = simple_scheduler();
        sched.disable_pass("B");
        sched.enable_pass("B");
        let order = sched.schedule().unwrap();
        assert_eq!(order.pass_count, 3);
    }

    #[test]
    fn test_validate_clean() {
        let sched = simple_scheduler();
        assert!(sched.validate().is_ok());
    }

    #[test]
    fn test_prerequisites() {
        let sched = simple_scheduler();
        let prereqs = sched.prerequisites("C");
        assert_eq!(prereqs, vec!["B"]);
        let prereqs_b = sched.prerequisites("B");
        assert_eq!(prereqs_b, vec!["A"]);
    }

    #[test]
    fn test_pass_count_and_dep_count() {
        let sched = simple_scheduler();
        assert_eq!(sched.pass_count(), 3);
        assert_eq!(sched.dependency_count(), 2);
    }

    #[test]
    fn test_schedule_order_position() {
        let sched = simple_scheduler();
        let order = sched.schedule().unwrap();
        assert!(order.position("A").is_some());
        assert!(order.position("Ghost").is_none());
    }

    #[test]
    fn test_schedule_order_display() {
        let sched = simple_scheduler();
        let order = sched.schedule().unwrap();
        let s = order.to_string();
        assert!(s.contains("A") && s.contains("B") && s.contains("C"));
    }

    #[test]
    fn test_empty_scheduler() {
        let sched = AnalysisScheduler::new();
        let order = sched.schedule().unwrap();
        assert_eq!(order.pass_count, 0);
    }

    #[test]
    fn test_clear() {
        let mut sched = simple_scheduler();
        sched.clear();
        assert_eq!(sched.pass_count(), 0);
        assert_eq!(sched.dependency_count(), 0);
    }

    #[test]
    fn test_builder_default() {
        let _b = SchedulerBuilder::default();
    }
}
