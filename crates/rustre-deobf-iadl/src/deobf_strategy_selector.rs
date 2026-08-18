//! Strategy selector for the IADL deobfuscation loop.
//!
//! Given a set of observable features extracted from a binary (opaque predicate
//! density, virtual call ratio, junk-instruction ratio, etc.), this module
//! selects the most appropriate deobfuscation strategy for the next IADL
//! iteration.
//!
//! The selector implements a lightweight decision-tree / scoring approach rather
//! than a full ML model, keeping the implementation dependency-free and fully
//! deterministic.
//!
//! Key types:
//! - [`StrategyFeature`] — an observable feature extracted from the binary.
//! - [`DeobfStrategy`]   — an enumeration of available deobfuscation strategies.
//! - [`FeatureVector`]   — a collection of features for one analysis round.
//! - [`StrategyScore`]   — a strategy together with its computed score.
//! - [`DeobfStrategySelector`] — the main selector.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

// ---------------------------------------------------------------------------
// StrategyFeature
// ---------------------------------------------------------------------------

/// An observable feature extracted from the binary or the current IADL state.
///
/// Each variant carries a normalised score in `[0.0, 1.0]` unless otherwise
/// stated.
#[derive(Debug, Clone, PartialEq)]
pub enum StrategyFeature {
    /// Fraction of conditional branches that appear to be opaque predicates.
    OpaquePredDensity(f64),
    /// Fraction of call sites that are indirect (via pointer/register).
    IndirectCallRatio(f64),
    /// Fraction of instructions classified as junk / dead code.
    JunkInstrRatio(f64),
    /// Fraction of basic blocks that contain only a single control-flow
    /// transfer (jump-over-junk pattern).
    JumpOverJunkRatio(f64),
    /// Relative size increase vs. estimated unobfuscated size (≥ 0).
    CodeBloatFactor(f64),
    /// Detected use of stack-based VM interpreter (0 or 1).
    HasVirtualisation(bool),
    /// Number of distinct obfuscation patterns detected.
    ObfPatternCount(u32),
    /// Current IADL global quality score.
    CurrentScore(f64),
    /// Current structural complexity metric.
    CurrentComplexity(u64),
    /// Whether a convergence plateau was detected recently.
    PlateauDetected(bool),
}

impl StrategyFeature {
    /// Human-readable name for this feature.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            StrategyFeature::OpaquePredDensity(_)  => "opaque_pred_density",
            StrategyFeature::IndirectCallRatio(_)  => "indirect_call_ratio",
            StrategyFeature::JunkInstrRatio(_)     => "junk_instr_ratio",
            StrategyFeature::JumpOverJunkRatio(_)  => "jump_over_junk_ratio",
            StrategyFeature::CodeBloatFactor(_)    => "code_bloat_factor",
            StrategyFeature::HasVirtualisation(_)  => "has_virtualisation",
            StrategyFeature::ObfPatternCount(_)    => "obf_pattern_count",
            StrategyFeature::CurrentScore(_)       => "current_score",
            StrategyFeature::CurrentComplexity(_)  => "current_complexity",
            StrategyFeature::PlateauDetected(_)    => "plateau_detected",
        }
    }

    /// Return the normalised floating-point value (booleans → 0.0/1.0).
    #[must_use]
    pub fn as_f64(&self) -> f64 {
        match self {
            StrategyFeature::OpaquePredDensity(v)  => *v,
            StrategyFeature::IndirectCallRatio(v)  => *v,
            StrategyFeature::JunkInstrRatio(v)     => *v,
            StrategyFeature::JumpOverJunkRatio(v)  => *v,
            StrategyFeature::CodeBloatFactor(v)    => (*v).min(10.0) / 10.0,
            StrategyFeature::HasVirtualisation(b)  => if *b { 1.0 } else { 0.0 },
            StrategyFeature::ObfPatternCount(n)    => (*n as f64 / 20.0).min(1.0),
            StrategyFeature::CurrentScore(v)       => *v,
            StrategyFeature::CurrentComplexity(c)  => (*c as f64 / 1_000_000.0).min(1.0),
            StrategyFeature::PlateauDetected(b)    => if *b { 1.0 } else { 0.0 },
        }
    }
}

// ---------------------------------------------------------------------------
// FeatureVector
// ---------------------------------------------------------------------------

/// A collection of features describing the current analysis state.
#[derive(Debug, Clone, Default)]
pub struct FeatureVector {
    features: Vec<StrategyFeature>,
}

impl FeatureVector {
    /// Create an empty feature vector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a feature.
    pub fn push(&mut self, feature: StrategyFeature) {
        self.features.push(feature);
    }

    /// Look up the first feature of a given name and return its f64 value.
    #[must_use]
    pub fn get_f64(&self, name: &str) -> Option<f64> {
        self.features.iter().find(|f| f.name() == name).map(|f| f.as_f64())
    }

    /// Iterate over all features.
    pub fn iter(&self) -> impl Iterator<Item = &StrategyFeature> {
        self.features.iter()
    }

    /// Number of features.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.features.len()
    }

    /// Whether the vector is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.features.is_empty()
    }

    /// Build a name→value map for scoring.
    #[must_use]
    pub fn as_map(&self) -> BTreeMap<&str, f64> {
        self.features.iter().map(|f| (f.name(), f.as_f64())).collect()
    }
}

// ---------------------------------------------------------------------------
// DeobfStrategy
// ---------------------------------------------------------------------------

/// An enumeration of deobfuscation strategies that the IADL loop can apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeobfStrategy {
    /// Evaluate and remove opaque predicates.
    OpaquePredicateElimination,
    /// Resolve indirect call / jump targets via value-set analysis.
    IndirectCallResolution,
    /// Delete dead / junk instructions.
    DeadCodeElimination,
    /// Unfold jump-over-junk patterns into direct branches.
    JumpUnfolding,
    /// Lift virtualised code back to native IR.
    VirtualisationLifting,
    /// Apply aggressive constant folding and propagation.
    ConstantPropagation,
    /// Merge basic blocks split by the obfuscator.
    BlockMerging,
    /// Reconstruct natural loops from obfuscated control flow.
    LoopReconstruction,
    /// Restructure the CFG using dominance-based region analysis.
    RegionStructuring,
    /// No-op: keep the current state unchanged.
    NoOp,
}

impl DeobfStrategy {
    /// Human-readable name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            DeobfStrategy::OpaquePredicateElimination => "opaque-predicate-elimination",
            DeobfStrategy::IndirectCallResolution      => "indirect-call-resolution",
            DeobfStrategy::DeadCodeElimination         => "dead-code-elimination",
            DeobfStrategy::JumpUnfolding               => "jump-unfolding",
            DeobfStrategy::VirtualisationLifting       => "virtualisation-lifting",
            DeobfStrategy::ConstantPropagation         => "constant-propagation",
            DeobfStrategy::BlockMerging                => "block-merging",
            DeobfStrategy::LoopReconstruction          => "loop-reconstruction",
            DeobfStrategy::RegionStructuring           => "region-structuring",
            DeobfStrategy::NoOp                        => "no-op",
        }
    }

    /// All non-NoOp strategies.
    #[must_use]
    pub const fn all() -> &'static [DeobfStrategy] {
        &[
            DeobfStrategy::OpaquePredicateElimination,
            DeobfStrategy::IndirectCallResolution,
            DeobfStrategy::DeadCodeElimination,
            DeobfStrategy::JumpUnfolding,
            DeobfStrategy::VirtualisationLifting,
            DeobfStrategy::ConstantPropagation,
            DeobfStrategy::BlockMerging,
            DeobfStrategy::LoopReconstruction,
            DeobfStrategy::RegionStructuring,
        ]
    }
}

impl fmt::Display for DeobfStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// StrategyScore
// ---------------------------------------------------------------------------

/// A strategy together with its computed applicability score.
#[derive(Debug, Clone)]
pub struct StrategyScore {
    /// The strategy.
    pub strategy: DeobfStrategy,
    /// Computed score (higher = more applicable).
    pub score: f64,
    /// Explanation of the score components.
    pub components: BTreeMap<String, f64>,
}

impl StrategyScore {
    const fn new(strategy: DeobfStrategy, score: f64, components: BTreeMap<String, f64>) -> Self {
        Self { strategy, score, components }
    }
}

// ---------------------------------------------------------------------------
// ScoringRule
// ---------------------------------------------------------------------------

/// A scoring rule that maps a feature vector to an incremental score for
/// one or more strategies.
struct ScoringRule {
    /// Feature name to look up.
    feature: &'static str,
    /// Threshold above which this rule fires.
    threshold: f64,
    /// Strategies boosted and by how much.
    boosts: &'static [(DeobfStrategy, f64)],
    /// Label for this rule (used in `components`).
    label: &'static str,
}

// ---------------------------------------------------------------------------
// DeobfStrategySelector
// ---------------------------------------------------------------------------

/// The strategy selector.
///
/// Maintains a table of scoring rules, a history of selected strategies, and
/// per-strategy success scores accumulated from caller feedback.
pub struct DeobfStrategySelector {
    /// Weight given to rule-based score vs. history-based score.
    rule_weight: f64,
    /// History of selections: (strategy, `outcome_score`).
    history: Vec<(DeobfStrategy, f64)>,
    /// Accumulated success scores per strategy.
    success: HashMap<DeobfStrategy, f64>,
    /// Number of times each strategy was selected.
    use_count: HashMap<DeobfStrategy, u32>,
    /// Maximum history length.
    max_history: usize,
}

impl DeobfStrategySelector {
    /// Create a new selector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rule_weight: 0.7,
            history: Vec::new(),
            success: HashMap::new(),
            use_count: HashMap::new(),
            max_history: 64,
        }
    }

    /// Set the weight of rule-based vs. history-based scoring (0.0–1.0).
    pub const fn set_rule_weight(&mut self, w: f64) {
        // `f64::clamp` propagates NaN, which would poison every score this
        // weight multiplies. Fall back to the documented lower bound.
        self.rule_weight = if w.is_nan() { 0.0 } else { w.clamp(0.0, 1.0) };
    }

    /// Score all strategies against the given feature vector and return them
    /// sorted by descending score.
    #[must_use]
    pub fn score_all(&self, features: &FeatureVector) -> Vec<StrategyScore> {
        let map = features.as_map();
        let mut scores: HashMap<DeobfStrategy, (f64, BTreeMap<String, f64>)> = HashMap::new();

        // Apply each scoring rule.
        for rule in Self::rules() {
            if let Some(&val) = map.get(rule.feature) {
                if val > rule.threshold {
                    let weight = val - rule.threshold;
                    for &(strategy, boost) in rule.boosts {
                        let entry = scores.entry(strategy).or_default();
                        let contribution = boost * weight;
                        entry.0 += contribution;
                        entry.1.insert(rule.label.to_string(), contribution);
                    }
                }
            }
        }

        // Blend in history-based scores.
        for (&strat, &acc) in &self.success {
            let uses = self.use_count.get(&strat).copied().unwrap_or(1).max(1);
            let history_score = acc / uses as f64;
            let entry = scores.entry(strat).or_default();
            let hist_contribution = history_score * (1.0 - self.rule_weight);
            entry.0 += hist_contribution;
            entry.1.insert("history".to_string(), hist_contribution);
        }

        // Build result vector.
        let mut result: Vec<StrategyScore> = DeobfStrategy::all()
            .iter()
            .map(|&s| {
                let (score, components) = scores
                    .remove(&s)
                    .unwrap_or_else(|| (0.0, BTreeMap::new()));
                StrategyScore::new(s, score, components)
            })
            .collect();

        result.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        result
    }

    /// Select the best strategy for the given feature vector.
    #[must_use]
    pub fn select_best(&self, features: &FeatureVector) -> DeobfStrategy {
        let scores = self.score_all(features);
        scores.first().map(|s| s.strategy).unwrap_or(DeobfStrategy::NoOp)
    }

    /// Select the top-N strategies.
    #[must_use]
    pub fn select_top_n(&self, features: &FeatureVector, n: usize) -> Vec<DeobfStrategy> {
        self.score_all(features)
            .into_iter()
            .take(n)
            .map(|s| s.strategy)
            .collect()
    }

    /// Record the outcome of applying a strategy (score delta, positive = good).
    pub fn record_outcome(&mut self, strategy: DeobfStrategy, outcome: f64) {
        if self.history.len() >= self.max_history {
            if let Some((old_strat, old_score)) = self.history.drain(..1).next() {
                if let Some(acc) = self.success.get_mut(&old_strat) {
                    *acc -= old_score;
                }
            }
        }
        self.history.push((strategy, outcome));
        *self.success.entry(strategy).or_insert(0.0) += outcome;
        *self.use_count.entry(strategy).or_insert(0) += 1;
    }

    /// Average outcome score for a given strategy.
    #[must_use]
    pub fn avg_outcome(&self, strategy: DeobfStrategy) -> f64 {
        let uses = self.use_count.get(&strategy).copied().unwrap_or(0);
        if uses == 0 {
            return 0.0;
        }
        self.success.get(&strategy).copied().unwrap_or(0.0) / uses as f64
    }

    /// Reset history and success scores.
    pub fn reset_history(&mut self) {
        self.history.clear();
        self.success.clear();
        self.use_count.clear();
    }

    // ------------------------------------------------------------------
    // Scoring rules
    // ------------------------------------------------------------------

    fn rules() -> &'static [ScoringRule] {
        static RULES: &[ScoringRule] = &[
            ScoringRule {
                feature: "opaque_pred_density",
                threshold: 0.1,
                boosts: &[
                    (DeobfStrategy::OpaquePredicateElimination, 3.0),
                    (DeobfStrategy::ConstantPropagation, 1.0),
                ],
                label: "high_opaque_pred",
            },
            ScoringRule {
                feature: "indirect_call_ratio",
                threshold: 0.15,
                boosts: &[
                    (DeobfStrategy::IndirectCallResolution, 3.0),
                    (DeobfStrategy::BlockMerging, 0.5),
                ],
                label: "high_indirect_call",
            },
            ScoringRule {
                feature: "junk_instr_ratio",
                threshold: 0.05,
                boosts: &[
                    (DeobfStrategy::DeadCodeElimination, 2.5),
                    (DeobfStrategy::BlockMerging, 0.8),
                ],
                label: "high_junk",
            },
            ScoringRule {
                feature: "jump_over_junk_ratio",
                threshold: 0.05,
                boosts: &[
                    (DeobfStrategy::JumpUnfolding, 2.0),
                    (DeobfStrategy::DeadCodeElimination, 1.0),
                ],
                label: "jump_over_junk",
            },
            ScoringRule {
                feature: "code_bloat_factor",
                threshold: 0.3,
                boosts: &[
                    (DeobfStrategy::DeadCodeElimination, 1.5),
                    (DeobfStrategy::OpaquePredicateElimination, 1.0),
                    (DeobfStrategy::BlockMerging, 1.0),
                ],
                label: "bloated",
            },
            ScoringRule {
                feature: "has_virtualisation",
                threshold: 0.5,
                boosts: &[
                    (DeobfStrategy::VirtualisationLifting, 5.0),
                    (DeobfStrategy::IndirectCallResolution, 1.0),
                ],
                label: "virtualised",
            },
            ScoringRule {
                feature: "obf_pattern_count",
                threshold: 0.1,
                boosts: &[
                    (DeobfStrategy::OpaquePredicateElimination, 1.0),
                    (DeobfStrategy::DeadCodeElimination, 1.0),
                    (DeobfStrategy::ConstantPropagation, 0.8),
                ],
                label: "many_patterns",
            },
            ScoringRule {
                feature: "plateau_detected",
                threshold: 0.5,
                boosts: &[
                    (DeobfStrategy::RegionStructuring, 2.0),
                    (DeobfStrategy::LoopReconstruction, 1.5),
                    (DeobfStrategy::BlockMerging, 1.0),
                ],
                label: "plateau",
            },
            ScoringRule {
                feature: "current_complexity",
                threshold: 0.4,
                boosts: &[
                    (DeobfStrategy::RegionStructuring, 1.5),
                    (DeobfStrategy::LoopReconstruction, 1.0),
                    (DeobfStrategy::BlockMerging, 0.8),
                ],
                label: "complex",
            },
        ];
        RULES
    }
}

impl Default for DeobfStrategySelector {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn opaque_features() -> FeatureVector {
        let mut fv = FeatureVector::new();
        fv.push(StrategyFeature::OpaquePredDensity(0.8));
        fv.push(StrategyFeature::JunkInstrRatio(0.05));
        fv
    }

    fn virt_features() -> FeatureVector {
        let mut fv = FeatureVector::new();
        fv.push(StrategyFeature::HasVirtualisation(true));
        fv.push(StrategyFeature::IndirectCallRatio(0.6));
        fv
    }

    #[test]
    fn test_feature_as_f64_bool() {
        assert_eq!(StrategyFeature::HasVirtualisation(true).as_f64(), 1.0);
        assert_eq!(StrategyFeature::HasVirtualisation(false).as_f64(), 0.0);
    }

    #[test]
    fn test_feature_vector_get_f64() {
        let mut fv = FeatureVector::new();
        fv.push(StrategyFeature::OpaquePredDensity(0.5));
        assert!((fv.get_f64("opaque_pred_density").unwrap() - 0.5).abs() < 1e-9);
        assert!(fv.get_f64("nonexistent").is_none());
    }

    #[test]
    fn test_select_best_opaque() {
        let sel = DeobfStrategySelector::new();
        let best = sel.select_best(&opaque_features());
        assert_eq!(best, DeobfStrategy::OpaquePredicateElimination);
    }

    #[test]
    fn test_select_best_virtualised() {
        let sel = DeobfStrategySelector::new();
        let best = sel.select_best(&virt_features());
        assert_eq!(best, DeobfStrategy::VirtualisationLifting);
    }

    #[test]
    fn test_score_all_sorted() {
        let sel = DeobfStrategySelector::new();
        let scores = sel.score_all(&opaque_features());
        for w in scores.windows(2) {
            assert!(w[0].score >= w[1].score);
        }
    }

    #[test]
    fn test_record_outcome_and_avg() {
        let mut sel = DeobfStrategySelector::new();
        sel.record_outcome(DeobfStrategy::DeadCodeElimination, 1.0);
        sel.record_outcome(DeobfStrategy::DeadCodeElimination, 3.0);
        let avg = sel.avg_outcome(DeobfStrategy::DeadCodeElimination);
        assert!((avg - 2.0).abs() < 1e-9);
    }

    #[test]
    fn test_history_influences_selection() {
        let mut sel = DeobfStrategySelector::new();
        // Bias history strongly toward BlockMerging.
        for _ in 0..10 {
            sel.record_outcome(DeobfStrategy::BlockMerging, 10.0);
        }
        sel.set_rule_weight(0.0); // pure history
        let fv = FeatureVector::new();
        let best = sel.select_best(&fv);
        assert_eq!(best, DeobfStrategy::BlockMerging);
    }

    #[test]
    fn test_select_top_n() {
        let sel = DeobfStrategySelector::new();
        let top3 = sel.select_top_n(&opaque_features(), 3);
        assert_eq!(top3.len(), 3);
        assert!(top3.contains(&DeobfStrategy::OpaquePredicateElimination));
    }

    #[test]
    fn test_reset_history() {
        let mut sel = DeobfStrategySelector::new();
        sel.record_outcome(DeobfStrategy::BlockMerging, 5.0);
        sel.reset_history();
        assert_eq!(sel.avg_outcome(DeobfStrategy::BlockMerging), 0.0);
    }

    #[test]
    fn test_empty_features_returns_noop_or_any() {
        let sel = DeobfStrategySelector::new();
        let scores = sel.score_all(&FeatureVector::new());
        // All scores should be 0.0 (no rules fired, no history).
        for s in &scores {
            assert!((s.score - 0.0).abs() < 1e-9, "score={}", s.score);
        }
    }

    #[test]
    fn test_deobf_strategy_display() {
        assert_eq!(
            format!("{}", DeobfStrategy::VirtualisationLifting),
            "virtualisation-lifting"
        );
    }
}
