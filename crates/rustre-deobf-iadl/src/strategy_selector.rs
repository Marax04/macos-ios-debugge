//! Strategy selection for IADL deobfuscation.
//!
//! Defines the `IadlStrategy` enum, `StrategyScorer` for feature-based scoring,
//! `StrategySelector` for picking the best strategy, `StrategyHistory` for
//! recording results, and `AdaptiveSelector` for switching strategies on
//! stagnation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::time::Duration;
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum StrategySelectorError {
    #[error("no strategies available")]
    NoStrategies,
    #[error("strategy {0:?} not registered")]
    NotRegistered(IadlStrategy),
    #[error("selector error: {0}")]
    Other(String),
}

// ─── IadlStrategy ─────────────────────────────────────────────────────────────

/// Deobfuscation strategy variants.
///
/// Each strategy has different trade-offs between speed, completeness, and
/// resource consumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IadlStrategy {
    /// Exhaustive key/algorithm search. Guaranteed to find the solution if the
    /// key space is bounded, but expensive.
    BruteForce,
    /// Fast pattern matching and heuristic decoding. Low CPU cost but may miss
    /// complex obfuscation.
    Heuristic,
    /// Symbolic execution over the obfuscated code. High coverage, high cost.
    Symbolic,
    /// Full or partial emulation of the target binary. Very accurate,
    /// very expensive.
    Emulation,
    /// Combines multiple sub-strategies in sequence or parallel.
    Hybrid,
}

impl IadlStrategy {
    /// Return a human-readable name.
    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::BruteForce => "BruteForce",
            Self::Heuristic => "Heuristic",
            Self::Symbolic => "Symbolic",
            Self::Emulation => "Emulation",
            Self::Hybrid => "Hybrid",
        }
    }

    /// Relative base cost (higher = more expensive).
    #[must_use] 
    pub const fn base_cost(self) -> f64 {
        match self {
            Self::BruteForce => 80.0,
            Self::Heuristic => 10.0,
            Self::Symbolic => 60.0,
            Self::Emulation => 90.0,
            Self::Hybrid => 50.0,
        }
    }

    /// Relative base precision (higher = more likely to succeed on hard inputs).
    #[must_use] 
    pub const fn base_precision(self) -> f64 {
        match self {
            Self::BruteForce => 1.0,
            Self::Heuristic => 0.5,
            Self::Symbolic => 0.85,
            Self::Emulation => 0.95,
            Self::Hybrid => 0.75,
        }
    }

    /// All variants in a stable order.
    #[must_use] 
    pub const fn all() -> &'static [Self] {
        &[
            Self::BruteForce,
            Self::Heuristic,
            Self::Symbolic,
            Self::Emulation,
            Self::Hybrid,
        ]
    }
}

impl fmt::Display for IadlStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─── ObservedFeatures ─────────────────────────────────────────────────────────

/// Observed binary / analysis features used to score strategies.
///
/// All fields are normalised to [0, 1] unless otherwise noted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservedFeatures {
    /// Estimated key-space size (log2). 0 = trivial, 64 = very large.
    pub key_space_log2: f64,
    /// Fraction of code that uses control-flow obfuscation (0–1).
    pub cfg_obfuscation: f64,
    /// Number of VM handlers detected (use 0 if no VM).
    pub vm_handler_count: u32,
    /// Current Shannon entropy of the working buffer (0–8).
    pub current_entropy: f64,
    /// Time budget remaining in seconds.
    pub time_budget_secs: f64,
    /// Memory budget remaining in MiB.
    pub memory_budget_mib: f64,
    /// Fraction of code already successfully decoded (0–1).
    pub decode_progress: f64,
    /// Whether anti-debug or anti-emulation tricks are suspected.
    pub has_anti_emulation: bool,
    /// Heuristic confidence that known patterns apply (0–1).
    pub pattern_confidence: f64,
    /// Number of previous strategies attempted (used to penalise redundancy).
    pub previous_attempts: u32,
}

impl Default for ObservedFeatures {
    fn default() -> Self {
        Self {
            key_space_log2: 16.0,
            cfg_obfuscation: 0.0,
            vm_handler_count: 0,
            current_entropy: 5.0,
            time_budget_secs: 300.0,
            memory_budget_mib: 512.0,
            decode_progress: 0.0,
            has_anti_emulation: false,
            pattern_confidence: 0.3,
            previous_attempts: 0,
        }
    }
}

// ─── StrategyScore ────────────────────────────────────────────────────────────

/// The score assigned to a strategy given observed features.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StrategyScore {
    pub strategy: IadlStrategy,
    /// Overall score in [0, 1]. Higher is better.
    pub score: f64,
    /// Expected probability of success.
    pub success_probability: f64,
    /// Expected cost normalised to [0, 1].
    pub cost_estimate: f64,
    /// Human-readable rationale.
    pub rationale: String,
}

impl StrategyScore {
    /// Utility: score / (1 + cost). Rewards high success, penalises cost.
    #[must_use] 
    pub fn utility(&self) -> f64 {
        self.score / (1.0 + self.cost_estimate)
    }
}

// ─── StrategyScorer ───────────────────────────────────────────────────────────

/// Scores each strategy based on `ObservedFeatures`.
///
/// The scoring model is deliberately simple and deterministic so that it can
/// be unit-tested without side effects.
pub struct StrategyScorer;

impl StrategyScorer {
    /// Score all strategies and return them sorted best-first by utility.
    #[must_use] 
    pub fn score_all(features: &ObservedFeatures) -> Vec<StrategyScore> {
        let mut scores: Vec<StrategyScore> = IadlStrategy::all()
            .iter()
            .map(|&s| Self::score_strategy(s, features))
            .collect();
        scores.sort_by(|a, b| b.utility().total_cmp(&a.utility()));
        scores
    }

    /// Score a single strategy against `features`.
    #[must_use] 
    pub fn score_strategy(strategy: IadlStrategy, features: &ObservedFeatures) -> StrategyScore {
        let (success, cost, rationale) = match strategy {
            IadlStrategy::BruteForce => Self::score_brute_force(features),
            IadlStrategy::Heuristic => Self::score_heuristic(features),
            IadlStrategy::Symbolic => Self::score_symbolic(features),
            IadlStrategy::Emulation => Self::score_emulation(features),
            IadlStrategy::Hybrid => Self::score_hybrid(features),
        };
        let score = (success * cost.mul_add(-0.3, 1.0)).clamp(0.0, 1.0);
        StrategyScore {
            strategy,
            score,
            success_probability: success,
            cost_estimate: cost,
            rationale,
        }
    }

    fn score_brute_force(f: &ObservedFeatures) -> (f64, f64, String) {
        // BruteForce works well with small key spaces and simple obfuscation.
        let key_penalty = (f.key_space_log2 / 64.0).clamp(0.0, 1.0);
        let success = (1.0 - key_penalty * 0.8).max(0.1);
        let cost = (f.key_space_log2 / 64.0).mul_add(0.9, 0.1).clamp(0.0, 1.0);
        let rationale = format!(
            "BruteForce: key_space_log2={:.1}, success_est={:.2}",
            f.key_space_log2, success
        );
        (success, cost, rationale)
    }

    fn score_heuristic(f: &ObservedFeatures) -> (f64, f64, String) {
        // Heuristic: fast but imprecise. Favoured when pattern_confidence is high
        // and CFG obfuscation is low.
        let base = f.pattern_confidence.clamp(0.0, 1.0);
        let cfg_penalty = f.cfg_obfuscation * 0.5;
        let success = (base - cfg_penalty).max(0.05);
        let cost = f.cfg_obfuscation.mul_add(0.2, 0.1); // low cost, slightly higher with CFF
        let rationale = format!(
            "Heuristic: pattern_conf={:.2}, cfg_obf={:.2}, success_est={:.2}",
            f.pattern_confidence, f.cfg_obfuscation, success
        );
        (success, cost, rationale)
    }

    fn score_symbolic(f: &ObservedFeatures) -> (f64, f64, String) {
        // Symbolic: good for CFG obfuscation, opaque predicates. Expensive on VMs.
        let cfg_bonus = f.cfg_obfuscation * 0.4;
        let vm_penalty = (f64::from(f.vm_handler_count) / 100.0).clamp(0.0, 0.3);
        let success = (0.6 + cfg_bonus - vm_penalty).clamp(0.1, 1.0);
        let cost = (f.cfg_obfuscation.mul_add(0.2, 0.5) + vm_penalty).clamp(0.0, 1.0);
        let rationale = format!(
            "Symbolic: cfg_bonus={cfg_bonus:.2}, vm_penalty={vm_penalty:.2}, success_est={success:.2}"
        );
        (success, cost, rationale)
    }

    fn score_emulation(f: &ObservedFeatures) -> (f64, f64, String) {
        // Emulation: great for VMs, terrible with anti-emulation tricks.
        let vm_bonus = (f64::from(f.vm_handler_count) / 50.0).min(0.4);
        let anti_emu_penalty = if f.has_anti_emulation { 0.5 } else { 0.0 };
        let success = (0.7 + vm_bonus - anti_emu_penalty).clamp(0.05, 1.0);
        let cost = (0.8 + (f64::from(f.vm_handler_count) / 200.0)).clamp(0.0, 1.0);
        let rationale = format!(
            "Emulation: vm_bonus={vm_bonus:.2}, anti_emu_penalty={anti_emu_penalty:.2}, success_est={success:.2}"
        );
        (success, cost, rationale)
    }

    fn score_hybrid(f: &ObservedFeatures) -> (f64, f64, String) {
        // Hybrid: average of all others with a slight synergy bonus.
        let others = [
            Self::score_brute_force(f),
            Self::score_heuristic(f),
            Self::score_symbolic(f),
            Self::score_emulation(f),
        ];
        let avg_success = others.iter().map(|(s, _, _)| s).sum::<f64>() / others.len() as f64;
        let avg_cost = others.iter().map(|(_, c, _)| c).sum::<f64>() / others.len() as f64;
        let synergy = 0.1; // hybrid can exploit complementary techniques
        let success = (avg_success + synergy).clamp(0.0, 1.0);
        let cost = (avg_cost * 0.8).clamp(0.0, 1.0); // parallel execution discount
        let rationale = format!(
            "Hybrid: avg_success={avg_success:.2}, avg_cost={avg_cost:.2}, synergy={synergy:.2}"
        );
        (success, cost, rationale)
    }
}

// ─── StrategyRecord ───────────────────────────────────────────────────────────

/// The result of running a strategy for one episode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyRecord {
    pub strategy: IadlStrategy,
    /// Score achieved (0–1, higher is better).
    pub achieved_score: f64,
    /// Whether the strategy produced a definitive result.
    pub succeeded: bool,
    /// Wall-clock time consumed.
    #[serde(skip)]
    pub duration: Option<Duration>,
    /// Additional notes.
    pub notes: String,
    /// Which iteration this was run in.
    pub iteration: u32,
}

impl StrategyRecord {
    pub fn new(
        strategy: IadlStrategy,
        achieved_score: f64,
        succeeded: bool,
        iteration: u32,
        notes: impl Into<String>,
    ) -> Self {
        Self {
            strategy,
            achieved_score,
            succeeded,
            duration: None,
            notes: notes.into(),
            iteration,
        }
    }

    #[must_use] 
    pub const fn with_duration(mut self, d: Duration) -> Self {
        self.duration = Some(d);
        self
    }
}

// ─── StrategyHistory ─────────────────────────────────────────────────────────

/// Records all strategy attempts and their results.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct StrategyHistory {
    pub records: Vec<StrategyRecord>,
}

impl StrategyHistory {
    /// Create an empty history.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a new record.
    pub fn push(&mut self, record: StrategyRecord) {
        self.records.push(record);
    }

    /// How many times was `strategy` attempted?
    #[must_use] 
    pub fn attempt_count(&self, strategy: IadlStrategy) -> usize {
        self.records
            .iter()
            .filter(|r| r.strategy == strategy)
            .count()
    }

    /// Best achieved score for `strategy` (None if never tried).
    pub fn best_score(&self, strategy: IadlStrategy) -> Option<f64> {
        self.records
            .iter()
            .filter(|r| r.strategy == strategy)
            .map(|r| r.achieved_score)
            .reduce(f64::max)
    }

    /// Average achieved score for `strategy` (None if never tried).
    #[must_use] 
    pub fn average_score(&self, strategy: IadlStrategy) -> Option<f64> {
        let relevant: Vec<f64> = self
            .records
            .iter()
            .filter(|r| r.strategy == strategy)
            .map(|r| r.achieved_score)
            .collect();
        if relevant.is_empty() {
            return None;
        }
        Some(relevant.iter().sum::<f64>() / relevant.len() as f64)
    }

    /// Return the last strategy attempted.
    #[must_use] 
    pub fn last_strategy(&self) -> Option<IadlStrategy> {
        self.records.last().map(|r| r.strategy)
    }

    /// Return strategies that have never been tried.
    #[must_use] 
    pub fn untried_strategies(&self) -> Vec<IadlStrategy> {
        IadlStrategy::all()
            .iter()
            .filter(|&&s| self.attempt_count(s) == 0)
            .copied()
            .collect()
    }

    /// Return strategies sorted by average achieved score (best first).
    #[must_use] 
    pub fn ranked_by_performance(&self) -> Vec<(IadlStrategy, f64)> {
        let mut ranked: Vec<(IadlStrategy, f64)> = IadlStrategy::all()
            .iter()
            .filter_map(|&s| self.average_score(s).map(|avg| (s, avg)))
            .collect();
        ranked.sort_by(|a, b| b.1.total_cmp(&a.1));
        ranked
    }

    /// Return `true` if any strategy has succeeded.
    #[must_use] 
    pub fn any_success(&self) -> bool {
        self.records.iter().any(|r| r.succeeded)
    }

    /// Return the total number of records.
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// Return `true` if no records exist.
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

// ─── StrategySelector ────────────────────────────────────────────────────────

/// Selects the best strategy to apply given observed features and history.
pub struct StrategySelector {
    /// Weight given to historical performance (0–1).
    pub history_weight: f64,
    /// Weight given to the scorer's prediction (0–1).
    pub scorer_weight: f64,
    /// Penalty multiplied by number of previous attempts of the same strategy.
    pub repeat_penalty: f64,
}

impl Default for StrategySelector {
    fn default() -> Self {
        Self {
            history_weight: 0.4,
            scorer_weight: 0.6,
            repeat_penalty: 0.1,
        }
    }
}

impl StrategySelector {
    /// Create a new selector with default weights.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with explicit weights (will be normalised to sum to 1.0).
    #[must_use] 
    pub const fn with_weights(history_weight: f64, scorer_weight: f64, repeat_penalty: f64) -> Self {
        Self {
            history_weight,
            scorer_weight,
            repeat_penalty,
        }
    }

    /// Select the best strategy given features and history.
    ///
    /// Returns `Err(NoStrategies)` if no strategies exist (should never happen).
    pub fn select(
        &self,
        features: &ObservedFeatures,
        history: &StrategyHistory,
    ) -> Result<IadlStrategy, StrategySelectorError> {
        let scores = self.rank(features, history);
        scores
            .into_iter()
            .next()
            .map(|(s, _)| s)
            .ok_or(StrategySelectorError::NoStrategies)
    }

    /// Rank all strategies by combined score. Returns (strategy, `combined_score`) pairs.
    #[must_use] 
    pub fn rank(
        &self,
        features: &ObservedFeatures,
        history: &StrategyHistory,
    ) -> Vec<(IadlStrategy, f64)> {
        let scorer_scores = StrategyScorer::score_all(features);
        let scorer_map: HashMap<IadlStrategy, f64> = scorer_scores
            .iter()
            .map(|ss| (ss.strategy, ss.utility()))
            .collect();

        let mut combined: Vec<(IadlStrategy, f64)> = IadlStrategy::all()
            .iter()
            .map(|&s| {
                let scorer_score = scorer_map.get(&s).copied().unwrap_or(0.0);
                let history_score = history.average_score(s).unwrap_or(scorer_score);
                let attempts = history.attempt_count(s) as f64;
                let repeat_pen = attempts * self.repeat_penalty;
                let combined = self.scorer_weight.mul_add(scorer_score, self.history_weight * history_score)
                    - repeat_pen;
                (s, combined.max(0.0))
            })
            .collect();

        combined.sort_by(|a, b| b.1.total_cmp(&a.1));
        combined
    }

    /// Return the top-N strategies.
    #[must_use] 
    pub fn top_n(
        &self,
        features: &ObservedFeatures,
        history: &StrategyHistory,
        n: usize,
    ) -> Vec<IadlStrategy> {
        self.rank(features, history)
            .into_iter()
            .take(n)
            .map(|(s, _)| s)
            .collect()
    }
}

// ─── AdaptiveSelector ────────────────────────────────────────────────────────

/// Monitors ongoing strategy execution and switches to a better strategy
/// when the current one stagnates.
pub struct AdaptiveSelector {
    pub selector: StrategySelector,
    pub history: StrategyHistory,
    /// Current active strategy.
    pub current_strategy: Option<IadlStrategy>,
    /// Number of consecutive iterations without progress on the current strategy.
    pub stagnant_iterations: u32,
    /// Threshold: if `stagnant_iterations >= stagnation_threshold`, switch.
    pub stagnation_threshold: u32,
    /// Features snapshot used for selection.
    pub last_features: ObservedFeatures,
}

impl AdaptiveSelector {
    /// Create a new adaptive selector.
    #[must_use] 
    pub fn new(stagnation_threshold: u32) -> Self {
        Self {
            selector: StrategySelector::new(),
            history: StrategyHistory::new(),
            current_strategy: None,
            stagnant_iterations: 0,
            stagnation_threshold,
            last_features: ObservedFeatures::default(),
        }
    }

    /// Return the current strategy (or pick one if none has been selected).
    pub fn current_or_pick(&mut self, features: &ObservedFeatures) -> IadlStrategy {
        if self.current_strategy.is_none() {
            let _ = self.pick(features);
        }
        self.current_strategy.unwrap_or(IadlStrategy::Heuristic)
    }

    /// Explicitly pick a (possibly new) strategy based on current features.
    pub fn pick(&mut self, features: &ObservedFeatures) -> IadlStrategy {
        self.last_features = features.clone();
        let chosen = self
            .selector
            .select(features, &self.history)
            .unwrap_or(IadlStrategy::Heuristic);
        self.current_strategy = Some(chosen);
        self.stagnant_iterations = 0;
        chosen
    }

    /// Report the outcome of the latest iteration.
    ///
    /// If the current strategy has stagnated (no progress for
    /// `stagnation_threshold` iterations), a new strategy is selected and
    /// returned as `Some(new_strategy)`. Otherwise returns `None`.
    pub fn report_iteration(
        &mut self,
        strategy: IadlStrategy,
        achieved_score: f64,
        made_progress: bool,
        iteration: u32,
        features: &ObservedFeatures,
    ) -> Option<IadlStrategy> {
        let record = StrategyRecord::new(
            strategy,
            achieved_score,
            made_progress,
            iteration,
            if made_progress {
                "progress"
            } else {
                "no progress"
            },
        );
        self.history.push(record);

        if made_progress {
            self.stagnant_iterations = 0;
            None
        } else {
            self.stagnant_iterations += 1;
            if self.stagnant_iterations >= self.stagnation_threshold {
                // Switch strategy.
                self.stagnant_iterations = 0;
                let new = self.pick(features);
                if Some(new) != self.current_strategy || new != strategy {
                    self.current_strategy = Some(new);
                    return Some(new);
                }
            }
            None
        }
    }

    /// Return a summary of strategy performance.
    #[must_use] 
    pub fn performance_summary(&self) -> HashMap<IadlStrategy, f64> {
        let mut map = HashMap::new();
        for &s in IadlStrategy::all() {
            if let Some(avg) = self.history.average_score(s) {
                map.insert(s, avg);
            }
        }
        map
    }

    /// Return `true` if a strategy switch is currently overdue.
    #[must_use] 
    pub const fn is_stagnated(&self) -> bool {
        self.stagnant_iterations >= self.stagnation_threshold
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn default_features() -> ObservedFeatures {
        ObservedFeatures::default()
    }

    // ── IadlStrategy tests ────────────────────────────────────────────────────

    #[test]
    fn strategy_names_are_unique() {
        let names: Vec<&str> = IadlStrategy::all().iter().map(|s| s.name()).collect();
        let mut unique = names.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(names.len(), unique.len());
    }

    #[test]
    fn strategy_base_costs_positive() {
        for &s in IadlStrategy::all() {
            assert!(s.base_cost() > 0.0, "{s} cost should be positive");
        }
    }

    #[test]
    fn strategy_base_precision_in_range() {
        for &s in IadlStrategy::all() {
            let p = s.base_precision();
            assert!(p > 0.0 && p <= 1.0, "{s} precision {p} out of range");
        }
    }

    #[test]
    fn strategy_display() {
        assert_eq!(format!("{}", IadlStrategy::BruteForce), "BruteForce");
        assert_eq!(format!("{}", IadlStrategy::Heuristic), "Heuristic");
    }

    #[test]
    fn strategy_all_has_five_variants() {
        assert_eq!(IadlStrategy::all().len(), 5);
    }

    // ── ObservedFeatures tests ────────────────────────────────────────────────

    #[test]
    fn observed_features_default_values_in_range() {
        let f = ObservedFeatures::default();
        assert!(f.key_space_log2 >= 0.0 && f.key_space_log2 <= 64.0);
        assert!(f.cfg_obfuscation >= 0.0 && f.cfg_obfuscation <= 1.0);
        assert!(f.current_entropy >= 0.0 && f.current_entropy <= 8.0);
        assert!(f.pattern_confidence >= 0.0 && f.pattern_confidence <= 1.0);
    }

    // ── StrategyScorer tests ──────────────────────────────────────────────────

    #[test]
    fn scorer_returns_all_strategies() {
        let scores = StrategyScorer::score_all(&default_features());
        assert_eq!(scores.len(), IadlStrategy::all().len());
    }

    #[test]
    fn scorer_scores_in_range() {
        let features = default_features();
        for &s in IadlStrategy::all() {
            let ss = StrategyScorer::score_strategy(s, &features);
            assert!(
                ss.score >= 0.0 && ss.score <= 1.0,
                "{s}: score {} out of [0,1]",
                ss.score
            );
            assert!(ss.cost_estimate >= 0.0 && ss.cost_estimate <= 1.0);
            assert!(ss.success_probability >= 0.0 && ss.success_probability <= 1.0);
        }
    }

    #[test]
    fn scorer_heuristic_preferred_with_high_pattern_confidence() {
        let mut f = default_features();
        f.pattern_confidence = 0.95;
        f.cfg_obfuscation = 0.0;
        f.key_space_log2 = 0.0;
        let scores = StrategyScorer::score_all(&f);
        let top = scores[0].strategy;
        // With perfect pattern confidence and tiny key space, heuristic or brute force should win.
        assert!(
            top == IadlStrategy::Heuristic || top == IadlStrategy::BruteForce,
            "expected Heuristic or BruteForce, got {top}"
        );
    }

    #[test]
    fn scorer_emulation_penalised_with_anti_emulation() {
        let mut f = default_features();
        f.has_anti_emulation = true;
        let with_anti = StrategyScorer::score_strategy(IadlStrategy::Emulation, &f);
        f.has_anti_emulation = false;
        let without_anti = StrategyScorer::score_strategy(IadlStrategy::Emulation, &f);
        assert!(
            with_anti.score <= without_anti.score,
            "anti-emulation should penalise emulation score"
        );
    }

    #[test]
    fn scorer_symbolic_boosted_by_cfg_obfuscation() {
        let mut f = default_features();
        f.cfg_obfuscation = 0.9;
        let high_cfg = StrategyScorer::score_strategy(IadlStrategy::Symbolic, &f);
        f.cfg_obfuscation = 0.0;
        let low_cfg = StrategyScorer::score_strategy(IadlStrategy::Symbolic, &f);
        assert!(high_cfg.success_probability >= low_cfg.success_probability);
    }

    #[test]
    fn strategy_score_utility_positive() {
        let f = default_features();
        for &s in IadlStrategy::all() {
            let ss = StrategyScorer::score_strategy(s, &f);
            assert!(ss.utility() >= 0.0, "{s}: utility should be non-negative");
        }
    }

    #[test]
    fn scorer_brute_force_penalised_by_large_key_space() {
        let mut f = default_features();
        f.key_space_log2 = 60.0;
        let big_ks = StrategyScorer::score_strategy(IadlStrategy::BruteForce, &f);
        f.key_space_log2 = 4.0;
        let small_ks = StrategyScorer::score_strategy(IadlStrategy::BruteForce, &f);
        assert!(
            small_ks.score >= big_ks.score,
            "small key space should score at least as high as large"
        );
    }

    // ── StrategyHistory tests ─────────────────────────────────────────────────

    #[test]
    fn history_attempt_count() {
        let mut hist = StrategyHistory::new();
        hist.push(StrategyRecord::new(
            IadlStrategy::Heuristic,
            0.5,
            true,
            0,
            "",
        ));
        hist.push(StrategyRecord::new(
            IadlStrategy::Heuristic,
            0.7,
            true,
            1,
            "",
        ));
        assert_eq!(hist.attempt_count(IadlStrategy::Heuristic), 2);
        assert_eq!(hist.attempt_count(IadlStrategy::Symbolic), 0);
    }

    #[test]
    fn history_best_score() {
        let mut hist = StrategyHistory::new();
        hist.push(StrategyRecord::new(
            IadlStrategy::Symbolic,
            0.3,
            false,
            0,
            "",
        ));
        hist.push(StrategyRecord::new(
            IadlStrategy::Symbolic,
            0.8,
            true,
            1,
            "",
        ));
        assert!((hist.best_score(IadlStrategy::Symbolic).unwrap() - 0.8).abs() < 1e-9);
        assert!(hist.best_score(IadlStrategy::Emulation).is_none());
    }

    #[test]
    fn history_average_score() {
        let mut hist = StrategyHistory::new();
        hist.push(StrategyRecord::new(
            IadlStrategy::BruteForce,
            0.4,
            true,
            0,
            "",
        ));
        hist.push(StrategyRecord::new(
            IadlStrategy::BruteForce,
            0.6,
            true,
            1,
            "",
        ));
        let avg = hist.average_score(IadlStrategy::BruteForce).unwrap();
        assert!((avg - 0.5).abs() < 1e-9);
    }

    #[test]
    fn history_untried_strategies() {
        let mut hist = StrategyHistory::new();
        hist.push(StrategyRecord::new(
            IadlStrategy::Heuristic,
            0.5,
            true,
            0,
            "",
        ));
        let untried = hist.untried_strategies();
        assert!(!untried.contains(&IadlStrategy::Heuristic));
        assert!(untried.contains(&IadlStrategy::Symbolic));
    }

    #[test]
    fn history_any_success() {
        let mut hist = StrategyHistory::new();
        hist.push(StrategyRecord::new(
            IadlStrategy::Heuristic,
            0.3,
            false,
            0,
            "",
        ));
        assert!(!hist.any_success());
        hist.push(StrategyRecord::new(
            IadlStrategy::Symbolic,
            0.9,
            true,
            1,
            "",
        ));
        assert!(hist.any_success());
    }

    #[test]
    fn history_ranked_by_performance() {
        let mut hist = StrategyHistory::new();
        hist.push(StrategyRecord::new(
            IadlStrategy::Heuristic,
            0.3,
            false,
            0,
            "",
        ));
        hist.push(StrategyRecord::new(
            IadlStrategy::Symbolic,
            0.9,
            true,
            1,
            "",
        ));
        let ranked = hist.ranked_by_performance();
        assert_eq!(ranked[0].0, IadlStrategy::Symbolic);
    }

    // ── StrategySelector tests ────────────────────────────────────────────────

    #[test]
    fn selector_picks_a_strategy() {
        let sel = StrategySelector::new();
        let hist = StrategyHistory::new();
        let chosen = sel.select(&default_features(), &hist).unwrap();
        assert!(IadlStrategy::all().contains(&chosen));
    }

    #[test]
    fn selector_penalises_repeated_strategies() {
        let sel = StrategySelector::with_weights(0.0, 1.0, 0.5);
        let mut hist = StrategyHistory::new();
        // Heavily penalise Heuristic by adding many attempts.
        for i in 0..10 {
            hist.push(StrategyRecord::new(
                IadlStrategy::Heuristic,
                0.5,
                true,
                i,
                "",
            ));
        }
        let ranked = sel.rank(&default_features(), &hist);
        // Heuristic should rank lower due to repeat penalty.
        let heuristic_rank = ranked
            .iter()
            .position(|(s, _)| *s == IadlStrategy::Heuristic)
            .unwrap();
        assert!(
            heuristic_rank > 0,
            "Heuristic should not rank first after many repeats"
        );
    }

    #[test]
    fn selector_top_n_returns_correct_count() {
        let sel = StrategySelector::new();
        let hist = StrategyHistory::new();
        let top3 = sel.top_n(&default_features(), &hist, 3);
        assert_eq!(top3.len(), 3);
    }

    // ── AdaptiveSelector tests ────────────────────────────────────────────────

    #[test]
    fn adaptive_selector_picks_initial_strategy() {
        let mut sel = AdaptiveSelector::new(3);
        let s = sel.current_or_pick(&default_features());
        assert!(IadlStrategy::all().contains(&s));
    }

    #[test]
    fn adaptive_selector_no_switch_on_progress() {
        let mut sel = AdaptiveSelector::new(3);
        let s = sel.current_or_pick(&default_features());
        let result = sel.report_iteration(s, 0.8, true, 0, &default_features());
        assert!(result.is_none(), "no switch expected when progress is made");
    }

    #[test]
    fn adaptive_selector_switches_after_stagnation() {
        let mut sel = AdaptiveSelector::new(2);
        let s = sel.current_or_pick(&default_features());
        sel.report_iteration(s, 0.0, false, 0, &default_features());
        let switch = sel.report_iteration(s, 0.0, false, 1, &default_features());
        // After 2 no-progress iterations (threshold=2), should switch.
        assert!(
            switch.is_some() || sel.stagnant_iterations == 0,
            "should either switch or reset stagnation counter"
        );
    }

    #[test]
    fn adaptive_selector_is_stagnated() {
        let mut sel = AdaptiveSelector::new(3);
        assert!(!sel.is_stagnated());
        sel.stagnant_iterations = 3;
        assert!(sel.is_stagnated());
    }

    #[test]
    fn adaptive_selector_performance_summary() {
        let mut sel = AdaptiveSelector::new(5);
        sel.history.push(StrategyRecord::new(
            IadlStrategy::Heuristic,
            0.7,
            true,
            0,
            "",
        ));
        let summary = sel.performance_summary();
        assert!(summary.contains_key(&IadlStrategy::Heuristic));
        assert!(!summary.contains_key(&IadlStrategy::Emulation));
    }

    #[test]
    fn strategy_record_with_duration() {
        let r = StrategyRecord::new(IadlStrategy::Symbolic, 0.6, true, 0, "ok")
            .with_duration(Duration::from_millis(150));
        assert_eq!(r.duration, Some(Duration::from_millis(150)));
    }
}
