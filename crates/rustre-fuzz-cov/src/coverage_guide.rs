//! Coverage-guided fuzzing directives: goals, progress tracking, adaptive
//! mutation, and reporting.
//!
//! # Structs
//! - [`CoverageTarget`]      — a specific coverage goal (edge / block / function)
//! - [`CoverageGoal`]        — a named collection of targets
//! - [`CoverageProgress`]    — tracks progress toward a goal
//! - [`AdaptiveMutation`]    — adjusts mutation strategy based on coverage
//! - [`GoalReport`]          — summary produced after a guided campaign
//! - [`CoverageGuide`]       — top-level coordinator

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from the coverage guidance subsystem.
#[derive(Debug, Error)]
pub enum GuideError {
    #[error("target not found: {0}")]
    TargetNotFound(u64),
    #[error("goal not found: {0}")]
    GoalNotFound(String),
    #[error("duplicate target id: {0}")]
    DuplicateTarget(u64),
    #[error("invalid range")]
    InvalidRange,
    #[error("coverage data empty")]
    Empty,
}

// ─────────────────────────────────────────────────────────────────────────────
// TargetKind
// ─────────────────────────────────────────────────────────────────────────────

/// What a coverage target refers to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetKind {
    /// A specific (from, to) edge.
    Edge { from: u64, to: u64 },
    /// A basic block at a given address.
    Block { addr: u64 },
    /// A function entry point.
    Function { addr: u64, name: Option<String> },
    /// A source line (file, line).
    SourceLine { file: String, line: u32 },
    /// A branch condition (address, taken/not-taken).
    Branch { addr: u64, taken: bool },
    /// A custom label.
    Custom { label: String },
}

impl std::fmt::Display for TargetKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Edge { from, to } => write!(f, "edge({from:#x}->{to:#x})"),
            Self::Block { addr } => write!(f, "block({addr:#x})"),
            Self::Function { addr, name } => {
                if let Some(n) = name {
                    write!(f, "fn({n}@{addr:#x})")
                } else {
                    write!(f, "fn({addr:#x})")
                }
            }
            Self::SourceLine { file, line } => write!(f, "src({file}:{line})"),
            Self::Branch { addr, taken } => write!(f, "branch({addr:#x}, taken={taken})"),
            Self::Custom { label } => write!(f, "custom({label})"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TargetPriority
// ─────────────────────────────────────────────────────────────────────────────

/// Importance of reaching a coverage target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TargetPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Must = 3,
}

impl std::fmt::Display for TargetPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Normal => write!(f, "normal"),
            Self::High => write!(f, "high"),
            Self::Must => write!(f, "must"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CoverageTarget
// ─────────────────────────────────────────────────────────────────────────────

/// A single coverage objective.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageTarget {
    /// Unique id.
    pub id: u64,
    /// What this target refers to.
    pub kind: TargetKind,
    /// Priority.
    pub priority: TargetPriority,
    /// Whether this target has been reached.
    pub reached: bool,
    /// When first reached.
    pub reached_at: Option<SystemTime>,
    /// Execution count when reached (0 if not yet).
    pub reached_at_exec: u64,
    /// Human-readable description.
    pub description: String,
    /// Optional weight for computing weighted coverage.
    pub weight: f64,
}

impl CoverageTarget {
    /// Create a new unreached target.
    #[must_use]
    pub fn new(id: u64, kind: TargetKind, priority: TargetPriority) -> Self {
        let description = kind.to_string();
        Self {
            id,
            kind,
            priority,
            reached: false,
            reached_at: None,
            reached_at_exec: 0,
            description,
            weight: 1.0,
        }
    }

    /// Mark this target as reached.
    pub fn mark_reached(&mut self, exec_count: u64) {
        self.reached = true;
        self.reached_at = Some(SystemTime::now());
        self.reached_at_exec = exec_count;
    }

    /// Time-to-reach in seconds.
    #[must_use]
    pub fn time_to_reach_secs(&self, campaign_start: SystemTime) -> Option<f64> {
        let hit = self.reached_at?;
        hit.duration_since(campaign_start)
            .ok()
            .map(|d| d.as_secs_f64())
    }

    /// Weighted contribution: weight if reached, 0 otherwise.
    #[must_use]
    pub const fn weighted_contribution(&self) -> f64 {
        if self.reached { self.weight } else { 0.0 }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CoverageGoal
// ─────────────────────────────────────────────────────────────────────────────

/// A named, themed collection of coverage targets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageGoal {
    /// Unique name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Ordered target ids.
    pub target_ids: Vec<u64>,
    /// Target table.
    pub targets: HashMap<u64, CoverageTarget>,
    /// Tags.
    pub tags: Vec<String>,
    /// When this goal was created.
    pub created_at: SystemTime,
    /// Next target id.
    next_id: u64,
}

impl CoverageGoal {
    /// Create an empty goal.
    #[must_use]
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            target_ids: Vec::new(),
            targets: HashMap::new(),
            tags: Vec::new(),
            created_at: SystemTime::now(),
            next_id: 1,
        }
    }

    /// Add a target to this goal.  Returns the assigned id.
    pub fn add_target(&mut self, kind: TargetKind, priority: TargetPriority) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let target = CoverageTarget::new(id, kind, priority);
        self.target_ids.push(id);
        self.targets.insert(id, target);
        id
    }

    /// Total targets in this goal.
    #[must_use]
    pub fn total(&self) -> usize {
        self.targets.len()
    }

    /// Reached targets.
    #[must_use]
    pub fn reached_count(&self) -> usize {
        self.targets.values().filter(|t| t.reached).count()
    }

    /// Unreached targets.
    #[must_use]
    pub fn unreached_count(&self) -> usize {
        self.total() - self.reached_count()
    }

    /// Fraction reached [0.0, 1.0].
    #[must_use]
    pub fn completion_fraction(&self) -> f64 {
        if self.total() == 0 {
            return 1.0;
        }
        crate::casts::usize_to_f64(self.reached_count()) / crate::casts::usize_to_f64(self.total())
    }

    /// Completion percentage [0.0, 100.0].
    #[must_use]
    pub fn completion_pct(&self) -> f64 {
        self.completion_fraction() * 100.0
    }

    /// Weighted completion: sum(reached weight) / sum(all weight).
    #[must_use]
    pub fn weighted_completion(&self) -> f64 {
        let total_w: f64 = self.targets.values().map(|t| t.weight).sum();
        if total_w <= 0.0 {
            return 0.0;
        }
        let reached_w: f64 = self
            .targets
            .values()
            .map(CoverageTarget::weighted_contribution)
            .sum();
        reached_w / total_w
    }

    /// Whether all MUST targets have been reached.
    #[must_use]
    pub fn must_targets_satisfied(&self) -> bool {
        self.targets
            .values()
            .filter(|t| t.priority == TargetPriority::Must)
            .all(|t| t.reached)
    }

    /// Unreached targets sorted by priority (high first).
    #[must_use]
    pub fn unreached_by_priority(&self) -> Vec<&CoverageTarget> {
        let mut v: Vec<&CoverageTarget> = self.targets.values().filter(|t| !t.reached).collect();
        v.sort_unstable_by(|a, b| b.priority.cmp(&a.priority));
        v
    }

    /// Mark target `id` as reached.
    ///
    /// # Errors
    /// Returns `GuideError::TargetNotFound` if the id doesn't exist.
    pub fn mark_target_reached(&mut self, id: u64, exec_count: u64) -> Result<(), GuideError> {
        self.targets
            .get_mut(&id)
            .ok_or(GuideError::TargetNotFound(id))?
            .mark_reached(exec_count);
        Ok(())
    }

    /// Bulk-mark targets as reached by a set of addresses (blocks).
    pub fn update_from_addresses(&mut self, addresses: &HashSet<u64>, exec_count: u64) {
        for target in self.targets.values_mut() {
            if target.reached {
                continue;
            }
            let hit = match &target.kind {
                TargetKind::Block { addr } | TargetKind::Function { addr, .. } => addresses.contains(addr),
                TargetKind::Edge { from, to } => addresses.contains(from) && addresses.contains(to),
                _ => false,
            };
            if hit {
                target.mark_reached(exec_count);
            }
        }
    }

    /// Merge another goal's targets into this one.
    pub fn merge(&mut self, other: &Self) {
        for t in other.targets.values() {
            let id = self.next_id;
            self.next_id += 1;
            let mut cloned = t.clone();
            cloned.id = id;
            self.target_ids.push(id);
            self.targets.insert(id, cloned);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CoverageProgress
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks progress toward a goal over time.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CoverageProgress {
    /// History: (`execution_count`, `pct_reached`, timestamp).
    pub history: Vec<(u64, f64, SystemTime)>,
    /// Campaign start (wall-clock, for display/serialisation only).
    pub campaign_start: Option<SystemTime>,
    /// Monotonic start instant — used for elapsed-time measurement to avoid
    /// wall-clock jumps (time-monotonic-vs-system fix).
    #[serde(skip)]
    campaign_start_instant: Option<Instant>,
    /// Total executions processed.
    pub total_executions: u64,
    /// Number of times a new target was reached.
    pub new_target_events: u64,
    /// Stagnation counter: executions since last improvement.
    pub stagnation_execs: u64,
    /// Threshold for considering the campaign stagnant.
    pub stagnation_threshold: u64,
}

impl CoverageProgress {
    /// Create a new progress tracker.
    #[must_use]
    pub fn new(stagnation_threshold: u64) -> Self {
        Self {
            stagnation_threshold,
            ..Default::default()
        }
    }

    /// Start tracking.
    pub fn start(&mut self) {
        self.campaign_start = Some(SystemTime::now());
        self.campaign_start_instant = Some(Instant::now());
    }

    /// Record a progress snapshot.
    pub fn record(&mut self, exec_count: u64, pct: f64) {
        let improved = self
            .history
            .last()
            .is_none_or(|(_, prev_pct, _)| pct > *prev_pct);

        if improved {
            self.new_target_events += 1;
            self.stagnation_execs = 0;
        } else {
            self.stagnation_execs += exec_count.saturating_sub(self.total_executions);
        }
        self.total_executions = exec_count;
        self.history.push((exec_count, pct, SystemTime::now()));
    }

    /// Returns `true` when the campaign appears stagnant.
    #[must_use]
    pub const fn is_stagnant(&self) -> bool {
        self.stagnation_threshold > 0 && self.stagnation_execs >= self.stagnation_threshold
    }

    /// Latest progress percentage.
    #[must_use]
    pub fn latest_pct(&self) -> f64 {
        self.history.last().map_or(0.0, |(_, p, _)| *p)
    }

    /// Improvement rate: pct gained per million executions.
    #[must_use]
    pub fn improvement_rate(&self) -> f64 {
        if self.total_executions == 0 {
            return 0.0;
        }
        let pct = self.latest_pct();
        pct / (crate::casts::u64_to_f64(self.total_executions) / 1_000_000.0)
    }

    /// Elapsed seconds since campaign start.
    ///
    /// Uses a monotonic [`Instant`] so wall-clock adjustments (NTP, DST, manual
    /// changes) do not cause the elapsed time to go negative or jump forward.
    #[must_use]
    pub fn elapsed_secs(&self) -> f64 {
        self.campaign_start_instant
            .map_or(0.0, |i| i.elapsed().as_secs_f64())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MutationBias
// ─────────────────────────────────────────────────────────────────────────────

/// How mutations should be biased toward a set of target addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub enum MutationBias {
    /// No bias – uniform mutation.
    Uniform,
    /// Prefer mutations that cover new edges near `target_addresses`.
    EdgeProximity,
    /// Prefer mutations that cover uncovered basic blocks.
    #[default]
    UncoveredBlocks,
    /// Prefer rare / less-hit edges.
    RareEdges,
    /// Combine all bias strategies.
    Combined,
}


// ─────────────────────────────────────────────────────────────────────────────
// MutationWeight
// ─────────────────────────────────────────────────────────────────────────────

/// Per-strategy weight used by the adaptive mutation engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationWeight {
    pub strategy: String,
    pub weight: f64,
    pub hits: u64,
    pub misses: u64,
}

impl MutationWeight {
    #[must_use]
    pub fn new(strategy: impl Into<String>) -> Self {
        Self {
            strategy: strategy.into(),
            weight: 1.0,
            hits: 0,
            misses: 0,
        }
    }

    /// Effectiveness: hits / (hits + misses).
    #[must_use]
    pub fn effectiveness(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            return 0.5;
        }
        crate::casts::u64_to_f64(self.hits) / crate::casts::u64_to_f64(total)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AdaptiveMutation
// ─────────────────────────────────────────────────────────────────────────────

/// Adjusts mutation strategy weights based on coverage feedback.
#[derive(Debug)]
pub struct AdaptiveMutation {
    /// Strategy weights.
    pub weights: HashMap<String, MutationWeight>,
    /// Current bias.
    pub bias: MutationBias,
    /// Addresses of unreached targets (guides towards them).
    pub target_addresses: HashSet<u64>,
    /// Executions since last weight update.
    pub update_interval: u64,
    execs_since_update: u64,
    /// Total weight updates performed.
    pub update_count: u64,
}

impl AdaptiveMutation {
    /// Create with the given bias and update interval.
    #[must_use]
    pub fn new(bias: MutationBias, update_interval: u64) -> Self {
        let strategies = [
            "bit_flip",
            "byte_flip",
            "arithmetic",
            "interesting_value",
            "dictionary",
            "splice",
            "havoc",
            "insert",
            "delete",
        ];
        let weights = strategies
            .iter()
            .map(|&s| (s.to_string(), MutationWeight::new(s)))
            .collect();
        Self {
            weights,
            bias,
            target_addresses: HashSet::new(),
            update_interval: update_interval.max(1),
            execs_since_update: 0,
            update_count: 0,
        }
    }

    /// Record that `strategy` produced `new_coverage` new edges.
    pub fn record_result(&mut self, strategy: &str, new_coverage: u32) {
        let w = self
            .weights
            .entry(strategy.to_string())
            .or_insert_with(|| MutationWeight::new(strategy));
        if new_coverage > 0 {
            w.hits += 1;
        } else {
            w.misses += 1;
        }
    }

    /// Advance one execution and update weights if the interval elapsed.
    pub fn tick(&mut self) {
        self.execs_since_update += 1;
        if self.execs_since_update >= self.update_interval {
            self.update_weights();
            self.execs_since_update = 0;
            self.update_count += 1;
        }
    }

    fn update_weights(&mut self) {
        for w in self.weights.values_mut() {
            let eff = w.effectiveness();
            // Exponential moving average: w_new = 0.7 * w_old + 0.3 * eff * 2.0
            w.weight = 0.7f64.mul_add(w.weight, 0.3 * eff * 2.0);
            // Clamp to [0.01, 10.0]
            w.weight = w.weight.clamp(0.01, 10.0);
        }
    }

    /// Choose a strategy using weighted random selection (deterministic round-robin fallback).
    #[must_use]
    pub fn choose_strategy(&self, seed: u64) -> Option<String> {
        let total_w: f64 = self.weights.values().map(|w| w.weight).sum();
        if total_w <= 0.0 {
            return None;
        }
        // Use the seed as a pseudo-random selector.
        let mut selector = (crate::casts::u64_to_f64(seed) / crate::casts::u64_to_f64(u64::MAX)) * total_w;
        let mut names: Vec<&str> = self.weights.keys().map(std::string::String::as_str).collect();
        names.sort_unstable(); // deterministic order
        for name in names {
            let w = self.weights[name].weight;
            if selector < w {
                return Some(name.to_string());
            }
            selector -= w;
        }
        self.weights.keys().next().cloned()
    }

    /// Best strategy by effectiveness.
    #[must_use]
    pub fn best_strategy(&self) -> Option<&str> {
        self.weights
            .values()
            .max_by(|a, b| {
                a.effectiveness()
                    .partial_cmp(&b.effectiveness())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|w| w.strategy.as_str())
    }

    /// Worst strategy by effectiveness.
    #[must_use]
    pub fn worst_strategy(&self) -> Option<&str> {
        self.weights
            .values()
            .min_by(|a, b| {
                a.effectiveness()
                    .partial_cmp(&b.effectiveness())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|w| w.strategy.as_str())
    }

    /// Add a target address to guide mutations toward.
    pub fn add_target_addr(&mut self, addr: u64) {
        self.target_addresses.insert(addr);
    }

    /// Remove an address once its target is reached.
    pub fn remove_target_addr(&mut self, addr: u64) {
        self.target_addresses.remove(&addr);
    }

    /// Number of remaining target addresses.
    #[must_use]
    pub fn target_count(&self) -> usize {
        self.target_addresses.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GoalReport
// ─────────────────────────────────────────────────────────────────────────────

/// Summary produced at the end of a coverage-guided campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoalReport {
    /// Goal name.
    pub goal_name: String,
    /// Target binary.
    pub target: String,
    /// When generated.
    pub generated_at: SystemTime,
    /// Total executions.
    pub total_executions: u64,
    /// Campaign wall-clock duration.
    pub duration: Duration,
    /// Targets reached.
    pub reached_count: usize,
    /// Total targets.
    pub total_targets: usize,
    /// Completion percentage [0, 100].
    pub completion_pct: f64,
    /// Weighted completion.
    pub weighted_completion: f64,
    /// Whether all MUST targets were satisfied.
    pub must_satisfied: bool,
    /// Stagnation detected.
    pub stagnated: bool,
    /// Best mutation strategy.
    pub best_strategy: Option<String>,
    /// Unreached MUST-priority targets.
    pub unsatisfied_must_targets: Vec<String>,
}

impl GoalReport {
    /// Build from the component objects.
    #[must_use]
    pub fn build(
        goal: &CoverageGoal,
        target: &str,
        progress: &CoverageProgress,
        mutation: &AdaptiveMutation,
        duration: Duration,
    ) -> Self {
        let unsatisfied_must_targets: Vec<String> = goal
            .targets
            .values()
            .filter(|t| t.priority == TargetPriority::Must && !t.reached)
            .map(|t| t.description.clone())
            .collect();

        Self {
            goal_name: goal.name.clone(),
            target: target.to_string(),
            generated_at: SystemTime::now(),
            total_executions: progress.total_executions,
            duration,
            reached_count: goal.reached_count(),
            total_targets: goal.total(),
            completion_pct: goal.completion_pct(),
            weighted_completion: goal.weighted_completion(),
            must_satisfied: goal.must_targets_satisfied(),
            stagnated: progress.is_stagnant(),
            best_strategy: mutation.best_strategy().map(String::from),
            unsatisfied_must_targets,
        }
    }

    /// Returns `true` if the goal was fully satisfied.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.completion_pct >= 100.0 || self.must_satisfied
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CoverageGuide
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level coverage-guided fuzzing coordinator.
pub struct CoverageGuide {
    /// Target identifier.
    pub target: String,
    /// Primary coverage goal.
    pub goal: CoverageGoal,
    /// Progress tracker.
    pub progress: CoverageProgress,
    /// Adaptive mutation engine.
    pub mutation: AdaptiveMutation,
    /// Whether the guide is active.
    pub running: bool,
    /// Total executions handled.
    pub total_executions: u64,
    /// Campaign start time (wall-clock, for display / serialisation only).
    pub started_at: Option<SystemTime>,
    /// Campaign end time (wall-clock, for display / serialisation only).
    pub ended_at: Option<SystemTime>,
    /// Monotonic start instant — used for duration measurement to avoid
    /// wall-clock jumps (time-monotonic-vs-system fix).
    started_instant: Option<Instant>,
    /// Monotonic end instant.
    ended_instant: Option<Instant>,
    /// Covered addresses accumulated.
    covered_addresses: HashSet<u64>,
}

impl CoverageGuide {
    /// Create a guide for the given target and goal.
    #[must_use]
    pub fn new(target: impl Into<String>, goal: CoverageGoal) -> Self {
        Self {
            target: target.into(),
            goal,
            progress: CoverageProgress::new(1_000_000),
            mutation: AdaptiveMutation::new(MutationBias::default(), 10_000),
            running: false,
            total_executions: 0,
            started_at: None,
            ended_at: None,
            started_instant: None,
            ended_instant: None,
            covered_addresses: HashSet::new(),
        }
    }

    /// Start the campaign.
    pub fn start(&mut self) {
        self.running = true;
        self.started_at = Some(SystemTime::now());
        self.started_instant = Some(Instant::now());
        self.progress.start();
    }

    /// Stop the campaign.
    pub fn stop(&mut self) {
        self.running = false;
        self.ended_at = Some(SystemTime::now());
        self.ended_instant = Some(Instant::now());
    }

    /// Feed coverage data from one execution into the guide.
    ///
    /// `new_addresses` is the set of basic-block / edge addresses hit.
    /// `strategy` is the mutation strategy that produced the input.
    /// `new_coverage_bits` is the number of new bitmap bits.
    pub fn feed(&mut self, new_addresses: &HashSet<u64>, strategy: &str, new_coverage_bits: u32) {
        self.total_executions += 1;
        self.mutation.record_result(strategy, new_coverage_bits);
        self.mutation.tick();

        let prev_reached = self.goal.reached_count();
        self.covered_addresses.extend(new_addresses.iter().copied());
        self.goal
            .update_from_addresses(new_addresses, self.total_executions);

        // Remove newly reached addresses from mutation targets.
        for addr in new_addresses {
            self.mutation.remove_target_addr(*addr);
        }

        let now_reached = self.goal.reached_count();
        if now_reached > prev_reached {
            // New target reached — add remaining unreached as mutation targets.
            for t in self.goal.unreached_by_priority() {
                if let TargetKind::Block { addr } | TargetKind::Function { addr, .. } = &t.kind {
                    self.mutation.add_target_addr(*addr);
                }
            }
        }

        let pct = self.goal.completion_pct();
        self.progress.record(self.total_executions, pct);
    }

    /// Choose the next mutation strategy.
    #[must_use]
    pub fn next_strategy(&self) -> Option<String> {
        self.mutation.choose_strategy(self.total_executions)
    }

    /// Generate the final report.
    #[must_use]
    pub fn report(&self) -> GoalReport {
        // Use monotonic Instant for duration to avoid wall-clock jump skew.
        let duration = match (self.started_instant, self.ended_instant) {
            (Some(s), Some(e)) => e.duration_since(s),
            (Some(s), None) => s.elapsed(),
            _ => Duration::ZERO,
        };
        GoalReport::build(
            &self.goal,
            &self.target,
            &self.progress,
            &self.mutation,
            duration,
        )
    }

    /// Whether all goals are satisfied.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.goal.completion_fraction() >= 1.0 || self.progress.is_stagnant()
    }

    /// Completion percentage.
    #[must_use]
    pub fn completion_pct(&self) -> f64 {
        self.goal.completion_pct()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_block_goal() -> CoverageGoal {
        let mut g = CoverageGoal::new("test-goal", "test");
        g.add_target(TargetKind::Block { addr: 0x1000 }, TargetPriority::Normal);
        g.add_target(TargetKind::Block { addr: 0x2000 }, TargetPriority::High);
        g.add_target(TargetKind::Block { addr: 0x3000 }, TargetPriority::Must);
        g
    }

    // ── TargetKind ────────────────────────────────────────────────────────────

    #[test]
    fn target_kind_display() {
        let e = TargetKind::Edge {
            from: 0x100,
            to: 0x200,
        };
        assert!(e.to_string().contains("edge"));
        let b = TargetKind::Block { addr: 0xDEAD };
        assert!(b.to_string().contains("block"));
        let f = TargetKind::Function {
            addr: 0x400,
            name: Some("main".into()),
        };
        assert!(f.to_string().contains("main"));
    }

    #[test]
    fn target_priority_ordering() {
        assert!(TargetPriority::Must > TargetPriority::High);
        assert!(TargetPriority::High > TargetPriority::Normal);
        assert!(TargetPriority::Normal > TargetPriority::Low);
    }

    // ── CoverageTarget ────────────────────────────────────────────────────────

    #[test]
    fn target_new_unreached() {
        let t = CoverageTarget::new(
            1,
            TargetKind::Block { addr: 0x1000 },
            TargetPriority::Normal,
        );
        assert!(!t.reached);
        assert!(t.reached_at.is_none());
    }

    #[test]
    fn target_mark_reached() {
        let mut t = CoverageTarget::new(
            1,
            TargetKind::Block { addr: 0x1000 },
            TargetPriority::Normal,
        );
        t.mark_reached(5000);
        assert!(t.reached);
        assert_eq!(t.reached_at_exec, 5000);
        assert!(t.reached_at.is_some());
    }

    #[test]
    fn target_weighted_contribution() {
        let mut t = CoverageTarget::new(
            1,
            TargetKind::Block { addr: 0x1000 },
            TargetPriority::Normal,
        );
        t.weight = 2.5;
        assert!(t.weighted_contribution().abs() < f64::EPSILON);
        t.mark_reached(1);
        assert!((t.weighted_contribution() - 2.5).abs() < f64::EPSILON);
    }

    // ── CoverageGoal ──────────────────────────────────────────────────────────

    #[test]
    fn goal_completion_zero() {
        let g = make_block_goal();
        assert_eq!(g.reached_count(), 0);
        assert!((g.completion_fraction()).abs() < 1e-9);
    }

    #[test]
    fn goal_mark_target_reached() {
        let mut g = make_block_goal();
        let ids: Vec<u64> = g.target_ids.clone();
        g.mark_target_reached(ids[0], 100).unwrap();
        assert_eq!(g.reached_count(), 1);
    }

    #[test]
    fn goal_completion_full() {
        let mut g = make_block_goal();
        let ids: Vec<u64> = g.target_ids.clone();
        for id in &ids {
            g.mark_target_reached(*id, 1).unwrap();
        }
        assert!((g.completion_fraction() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn goal_must_targets_satisfied() {
        let mut g = make_block_goal();
        assert!(!g.must_targets_satisfied());
        // find MUST target id
        let must_id = g
            .targets
            .values()
            .find(|t| t.priority == TargetPriority::Must)
            .map(|t| t.id)
            .unwrap();
        g.mark_target_reached(must_id, 1).unwrap();
        assert!(g.must_targets_satisfied());
    }

    #[test]
    fn goal_update_from_addresses() {
        let mut g = make_block_goal();
        let mut addrs = HashSet::new();
        addrs.insert(0x1000u64);
        addrs.insert(0x2000u64);
        g.update_from_addresses(&addrs, 100);
        assert_eq!(g.reached_count(), 2);
    }

    #[test]
    fn goal_unreached_by_priority_order() {
        let g = make_block_goal();
        let v = g.unreached_by_priority();
        // First unreached should be Must or High (highest priority first)
        assert!(v[0].priority >= v[v.len() - 1].priority);
    }

    #[test]
    fn goal_completion_pct() {
        let mut g = make_block_goal();
        let id = g.target_ids[0];
        g.mark_target_reached(id, 1).unwrap();
        let pct = g.completion_pct();
        assert!((pct - 100.0 / 3.0).abs() < 0.1);
    }

    #[test]
    fn goal_weighted_completion() {
        let mut g = CoverageGoal::new("g", "");
        let id = g.add_target(TargetKind::Block { addr: 0x1 }, TargetPriority::Normal);
        g.targets.get_mut(&id).unwrap().weight = 2.0;
        g.add_target(TargetKind::Block { addr: 0x2 }, TargetPriority::Normal);
        g.mark_target_reached(id, 1).unwrap();
        let wc = g.weighted_completion();
        assert!(wc > 0.0 && wc < 1.0);
    }

    #[test]
    fn goal_merge() {
        let mut g1 = CoverageGoal::new("g1", "");
        g1.add_target(TargetKind::Block { addr: 0x1 }, TargetPriority::Normal);
        let mut g2 = CoverageGoal::new("g2", "");
        g2.add_target(TargetKind::Block { addr: 0x2 }, TargetPriority::Normal);
        g1.merge(&g2);
        assert_eq!(g1.total(), 2);
    }

    // ── CoverageProgress ──────────────────────────────────────────────────────

    #[test]
    fn progress_record_and_latest() {
        let mut p = CoverageProgress::new(1_000_000);
        p.record(1000, 10.0);
        p.record(2000, 20.0);
        assert!((p.latest_pct() - 20.0).abs() < 1e-9);
    }

    #[test]
    fn progress_stagnation() {
        let mut p = CoverageProgress::new(100);
        p.record(50, 10.0);
        p.record(200, 10.0); // no improvement, 150 execs since last
        assert!(p.is_stagnant());
    }

    #[test]
    fn progress_improvement_resets_stagnation() {
        let mut p = CoverageProgress::new(100);
        p.record(50, 10.0);
        p.record(150, 10.0); // stagnant
        p.record(160, 20.0); // improvement
        assert!(!p.is_stagnant());
    }

    #[test]
    fn progress_new_target_events() {
        let mut p = CoverageProgress::new(1_000_000);
        p.record(1000, 10.0);
        p.record(2000, 20.0);
        assert_eq!(p.new_target_events, 2);
    }

    // ── MutationWeight ────────────────────────────────────────────────────────

    #[test]
    fn mutation_weight_effectiveness_50_50() {
        let mut w = MutationWeight::new("havoc");
        w.hits = 5;
        w.misses = 5;
        assert!((w.effectiveness() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn mutation_weight_effectiveness_all_hits() {
        let mut w = MutationWeight::new("bit_flip");
        w.hits = 10;
        w.misses = 0;
        assert!((w.effectiveness() - 1.0).abs() < 1e-9);
    }

    // ── AdaptiveMutation ──────────────────────────────────────────────────────

    #[test]
    fn adaptive_mutation_new_has_strategies() {
        let a = AdaptiveMutation::new(MutationBias::Uniform, 1000);
        assert!(!a.weights.is_empty());
    }

    #[test]
    fn adaptive_mutation_record_result() {
        let mut a = AdaptiveMutation::new(MutationBias::Uniform, 1000);
        a.record_result("havoc", 5);
        a.record_result("havoc", 0);
        let w = &a.weights["havoc"];
        assert_eq!(w.hits, 1);
        assert_eq!(w.misses, 1);
    }

    #[test]
    fn adaptive_mutation_choose_strategy() {
        let a = AdaptiveMutation::new(MutationBias::Uniform, 1000);
        let s = a.choose_strategy(12345);
        assert!(s.is_some());
    }

    #[test]
    fn adaptive_mutation_best_worst_strategy() {
        let mut a = AdaptiveMutation::new(MutationBias::Uniform, 1000);
        // Make bit_flip perfect, delete terrible
        if let Some(w) = a.weights.get_mut("bit_flip") {
            w.hits = 100;
            w.misses = 0;
        }
        if let Some(w) = a.weights.get_mut("delete") {
            w.hits = 0;
            w.misses = 100;
        }
        let best = a.best_strategy();
        assert!(best.is_some());
    }

    #[test]
    fn adaptive_mutation_target_addr() {
        let mut a = AdaptiveMutation::new(MutationBias::EdgeProximity, 1000);
        a.add_target_addr(0x1000);
        assert_eq!(a.target_count(), 1);
        a.remove_target_addr(0x1000);
        assert_eq!(a.target_count(), 0);
    }

    #[test]
    fn adaptive_mutation_weight_update_on_tick() {
        let mut a = AdaptiveMutation::new(MutationBias::Uniform, 2);
        a.record_result("bit_flip", 10);
        a.tick();
        a.tick();
        assert_eq!(a.update_count, 1);
    }

    // ── GoalReport ────────────────────────────────────────────────────────────

    #[test]
    fn goal_report_complete() {
        let mut g = make_block_goal();
        let ids: Vec<u64> = g.target_ids.clone();
        for id in &ids {
            g.mark_target_reached(*id, 1).unwrap();
        }
        let p = CoverageProgress::new(1_000_000);
        let a = AdaptiveMutation::new(MutationBias::Uniform, 1000);
        let r = GoalReport::build(&g, "t", &p, &a, Duration::from_secs(1));
        assert!(r.is_complete());
    }

    #[test]
    fn goal_report_incomplete() {
        let g = make_block_goal();
        let p = CoverageProgress::new(1_000_000);
        let a = AdaptiveMutation::new(MutationBias::Uniform, 1000);
        let r = GoalReport::build(&g, "t", &p, &a, Duration::from_secs(1));
        assert!(!r.is_complete());
        assert!(!r.unsatisfied_must_targets.is_empty());
    }

    // ── CoverageGuide ─────────────────────────────────────────────────────────

    #[test]
    fn guide_start_stop() {
        let g = make_block_goal();
        let mut guide = CoverageGuide::new("target", g);
        guide.start();
        assert!(guide.running);
        guide.stop();
        assert!(!guide.running);
    }

    #[test]
    fn guide_feed_updates_coverage() {
        let g = make_block_goal();
        let mut guide = CoverageGuide::new("target", g);
        guide.start();
        let mut addrs = HashSet::new();
        addrs.insert(0x1000u64);
        guide.feed(&addrs, "bit_flip", 5);
        assert!(guide.goal.reached_count() >= 1);
        assert_eq!(guide.total_executions, 1);
    }

    #[test]
    fn guide_next_strategy() {
        let g = make_block_goal();
        let guide = CoverageGuide::new("target", g);
        assert!(guide.next_strategy().is_some());
    }

    #[test]
    fn guide_report() {
        let g = make_block_goal();
        let mut guide = CoverageGuide::new("my-target", g);
        guide.start();
        guide.stop();
        let r = guide.report();
        assert_eq!(r.target, "my-target");
    }

    #[test]
    fn guide_is_done_after_full_coverage() {
        let mut g = CoverageGoal::new("g", "");
        let _id = g.add_target(TargetKind::Block { addr: 0x1 }, TargetPriority::Normal);
        let mut guide = CoverageGuide::new("t", g);
        guide.start();
        let mut addrs = HashSet::new();
        addrs.insert(0x1u64);
        guide.feed(&addrs, "havoc", 1);
        assert!(guide.is_done());
    }

    #[test]
    fn guide_completion_pct() {
        let g = make_block_goal();
        let guide = CoverageGuide::new("t", g);
        assert!((guide.completion_pct() - 0.0).abs() < 1e-9);
    }
}
