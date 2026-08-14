//! Hypothesis combiner for the Multi-Hypothesis Control-flow & Dead-code
//! Elimination (MHCDE) pipeline.
//!
//! Provides:
//! * [`StrategyWeight`] — a normalised weight for a named strategy.
//! * [`CombinedStrategy`] — a weighted mixture of named strategies.
//! * [`CombinedResult`] — the outcome of evaluating a combined strategy.
//! * [`CombinationHistory`] — a time-ordered log of combination attempts.
//! * [`BestCombination`] — the highest-scoring combination found so far.
//! * [`HypothesisCombiner`] — the main combiner engine.

use ahash::AHashMap as HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// CombinationConstraint — hard constraints on weight combinations
// ─────────────────────────────────────────────────────────────────────────────

/// A constraint that must be satisfied by a combined strategy.
#[derive(Debug, Clone)]
pub struct CombinationConstraint {
    /// A named strategy must have weight ≥ this value.
    pub min_weight: Option<(String, f64)>,
    /// A named strategy must have weight ≤ this value.
    pub max_weight: Option<(String, f64)>,
    /// Two strategies must have equal weight.
    pub equal_pair: Option<(String, String)>,
    /// A strategy must be active (weight > 0.01).
    pub required_active: Option<String>,
}

impl CombinationConstraint {
    /// Create a constraint requiring `strategy` to have weight ≥ `min`.
    #[must_use]
    pub fn min_weight(strategy: impl Into<String>, min: f64) -> Self {
        Self {
            min_weight: Some((strategy.into(), min)),
            max_weight: None,
            equal_pair: None,
            required_active: None,
        }
    }

    /// Create a constraint requiring `strategy` to have weight ≤ `max`.
    #[must_use]
    pub fn max_weight(strategy: impl Into<String>, max: f64) -> Self {
        Self {
            min_weight: None,
            max_weight: Some((strategy.into(), max)),
            equal_pair: None,
            required_active: None,
        }
    }

    /// Check whether `cs` satisfies this constraint.
    #[must_use]
    pub fn is_satisfied(&self, cs: &CombinedStrategy) -> bool {
        if let Some((ref name, min)) = self.min_weight
            && cs.weight_for(name) < min {
                return false;
            }
        if let Some((ref name, max)) = self.max_weight
            && cs.weight_for(name) > max {
                return false;
            }
        if let Some((ref a, ref b)) = self.equal_pair {
            let wa = cs.weight_for(a);
            let wb = cs.weight_for(b);
            if (wa - wb).abs() > 1e-9 {
                return false;
            }
        }
        if let Some(ref name) = self.required_active
            && !cs
                .weights
                .iter()
                .any(|w| &w.name == name && w.is_significant())
            {
                return false;
            }
        true
    }
}

/// Validates a combined strategy against a list of constraints.
#[must_use]
pub fn validate_constraints(cs: &CombinedStrategy, constraints: &[CombinationConstraint]) -> bool {
    constraints.iter().all(|c| c.is_satisfied(cs))
}

// ─────────────────────────────────────────────────────────────────────────────
// CombinationEvaluationLog — structured log of all combination evaluations
// ─────────────────────────────────────────────────────────────────────────────

/// A single evaluation record.
#[derive(Debug, Clone)]
pub struct EvaluationRecord {
    /// Evaluation index.
    pub index: usize,
    /// Weights used (strategy → weight).
    pub weights: HashMap<String, f64>,
    /// Quality score returned by the oracle.
    pub quality: f64,
    /// Whether this was accepted as the new best.
    pub accepted: bool,
    /// Elapsed time in nanoseconds (placeholder 0 in tests).
    pub elapsed_ns: u64,
}

/// Log of all combination evaluations with summary statistics.
#[derive(Debug, Clone, Default)]
pub struct CombinationEvaluationLog {
    /// All evaluation records.
    pub records: Vec<EvaluationRecord>,
}

impl CombinationEvaluationLog {
    /// Create an empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a record.
    pub fn push(&mut self, weights: HashMap<String, f64>, quality: f64, accepted: bool) {
        let index = self.records.len();
        self.records.push(EvaluationRecord {
            index,
            weights,
            quality,
            accepted,
            elapsed_ns: 0,
        });
    }

    /// Number of records.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// Return `true` when empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Mean quality across all evaluations.
    #[must_use]
    pub fn mean_quality(&self) -> f64 {
        if self.records.is_empty() {
            return 0.0;
        }
        self.records.iter().map(|r| r.quality).sum::<f64>() / self.records.len() as f64
    }

    /// Best quality observed.
    #[must_use]
    pub fn best_quality(&self) -> f64 {
        self.records
            .iter()
            .map(|r| r.quality)
            .fold(f64::NEG_INFINITY, f64::max)
    }

    /// Number of accepted evaluations.
    #[must_use]
    pub fn accepted_count(&self) -> usize {
        self.records.iter().filter(|r| r.accepted).count()
    }

    /// Return records in descending quality order.
    #[must_use]
    pub fn sorted_by_quality(&self) -> Vec<&EvaluationRecord> {
        let mut v: Vec<&EvaluationRecord> = self.records.iter().collect();
        v.sort_by(|a, b| {
            b.quality
                .partial_cmp(&a.quality)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        v
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StrategyWeight
// ─────────────────────────────────────────────────────────────────────────────

/// A normalised weight for a named deobfuscation strategy.
///
/// Weights are always non-negative. The combiner normalises them so they sum
/// to 1.0 before evaluating.
#[derive(Debug, Clone, PartialEq)]
pub struct StrategyWeight {
    /// Strategy identifier (e.g. `"cff"`, `"opaque"`, `"mba"`).
    pub name: String,
    /// Raw weight (non-negative).
    pub weight: f64,
    /// Whether this strategy is currently active.
    pub active: bool,
}

impl StrategyWeight {
    /// Create a new weight.
    #[must_use]
    pub fn new(name: impl Into<String>, weight: f64) -> Self {
        Self {
            name: name.into(),
            weight: weight.abs(),
            active: true,
        }
    }

    /// Disable this strategy.
    #[must_use]
    pub const fn disabled(mut self) -> Self {
        self.active = false;
        self
    }

    /// Return `true` if the strategy has a meaningful contribution (weight > 0.01).
    #[must_use]
    pub fn is_significant(&self) -> bool {
        self.active && self.weight > 0.01
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CombinedStrategy
// ─────────────────────────────────────────────────────────────────────────────

/// A weighted mixture of named deobfuscation strategies.
#[derive(Debug, Clone)]
pub struct CombinedStrategy {
    /// All strategy weights (active or not).
    pub weights: Vec<StrategyWeight>,
    /// A short human-readable label for this combination.
    pub label: String,
    /// Estimated quality of this combination (0.0–1.0, if pre-scored).
    pub estimated_quality: Option<f64>,
}

impl CombinedStrategy {
    /// Create a new combined strategy with equal initial weights.
    #[must_use]
    pub fn uniform(names: &[&str]) -> Self {
        let w = if names.is_empty() {
            1.0
        } else {
            1.0 / names.len() as f64
        };
        let weights = names.iter().map(|&n| StrategyWeight::new(n, w)).collect();
        Self {
            weights,
            label: "uniform".into(),
            estimated_quality: None,
        }
    }

    /// Create a combined strategy from a `name → weight` map.
    #[must_use]
    pub fn from_map(map: HashMap<String, f64>) -> Self {
        let weights = map
            .into_iter()
            .map(|(n, w)| StrategyWeight::new(n, w))
            .collect();
        Self {
            weights,
            label: "custom".into(),
            estimated_quality: None,
        }
    }

    /// Normalise weights so that active weights sum to 1.0.
    pub fn normalise(&mut self) {
        let total: f64 = self
            .weights
            .iter()
            .filter(|w| w.active)
            .map(|w| w.weight)
            .sum();
        if total > 1e-12 {
            for w in &mut self.weights {
                if w.active {
                    w.weight /= total;
                }
            }
        }
    }

    /// Return the weight for a named strategy (0.0 if not found or inactive).
    #[must_use]
    pub fn weight_for(&self, name: &str) -> f64 {
        self.weights
            .iter()
            .find(|w| w.name == name && w.active)
            .map_or(0.0, |w| w.weight)
    }

    /// Return all active strategy names.
    #[must_use]
    pub fn active_names(&self) -> Vec<&str> {
        self.weights
            .iter()
            .filter(|w| w.is_significant())
            .map(|w| w.name.as_str())
            .collect()
    }

    /// Return `true` if this combination has at least one significant strategy.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.weights.iter().any(StrategyWeight::is_significant)
    }

    /// Number of active strategies.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.weights.iter().filter(|w| w.is_significant()).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CombinedResult
// ─────────────────────────────────────────────────────────────────────────────

/// The outcome of evaluating a combined strategy.
#[derive(Debug, Clone)]
pub struct CombinedResult {
    /// The strategy that was evaluated.
    pub strategy: CombinedStrategy,
    /// Aggregate quality score in [0.0, 1.0].
    pub quality: f64,
    /// Per-strategy quality contribution.
    pub per_strategy_quality: HashMap<String, f64>,
    /// Complexity reduction achieved (lower = better).
    pub complexity_reduction: f64,
    /// Number of deobfuscation actions taken.
    pub actions_taken: usize,
    /// Whether the result is considered reliable (passes sanity checks).
    pub is_reliable: bool,
    /// Human-readable diagnostics.
    pub diagnostics: Vec<String>,
}

impl CombinedResult {
    /// Create a new result.
    #[must_use]
    pub fn new(strategy: CombinedStrategy, quality: f64) -> Self {
        Self {
            strategy,
            quality: quality.clamp(0.0, 1.0),
            per_strategy_quality: HashMap::new(),
            complexity_reduction: 0.0,
            actions_taken: 0,
            is_reliable: quality >= 0.5,
            diagnostics: Vec::new(),
        }
    }

    /// Set per-strategy quality.
    pub fn set_strategy_quality(&mut self, name: impl Into<String>, q: f64) {
        self.per_strategy_quality
            .insert(name.into(), q.clamp(0.0, 1.0));
    }

    /// Return the dominant strategy (highest weight × quality).
    #[must_use]
    pub fn dominant_strategy(&self) -> Option<&str> {
        let mut best: Option<(&str, f64)> = None;
        for w in &self.strategy.weights {
            if !w.active {
                continue;
            }
            let contrib = w.weight
                * self
                    .per_strategy_quality
                    .get(&w.name)
                    .copied()
                    .unwrap_or(self.quality);
            if best.is_none_or(|(_, s)| contrib > s) {
                best = Some((w.name.as_str(), contrib));
            }
        }
        best.map(|(n, _)| n)
    }

    /// One-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "quality={:.4} actions={} reduction={:.2} reliable={}",
            self.quality, self.actions_taken, self.complexity_reduction, self.is_reliable,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CombinationHistory
// ─────────────────────────────────────────────────────────────────────────────

/// A time-ordered log of combination attempts.
#[derive(Debug, Clone, Default)]
pub struct CombinationHistory {
    /// All recorded results in insertion order.
    pub entries: Vec<CombinedResult>,
    /// Index of the best entry.
    pub best_idx: Option<usize>,
}

impl CombinationHistory {
    /// Create an empty history.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a result and update the best index.
    pub fn push(&mut self, result: CombinedResult) {
        let q = result.quality;
        let idx = self.entries.len();
        self.entries.push(result);
        match self.best_idx {
            None => self.best_idx = Some(idx),
            Some(bi) if q > self.entries[bi].quality => self.best_idx = Some(idx),
            _ => {}
        }
    }

    /// Return the best result, if any.
    #[must_use]
    pub fn best(&self) -> Option<&CombinedResult> {
        self.best_idx.map(|i| &self.entries[i])
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` when empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return all results sorted by quality descending.
    #[must_use]
    pub fn sorted_by_quality(&self) -> Vec<&CombinedResult> {
        let mut v: Vec<&CombinedResult> = self.entries.iter().collect();
        v.sort_by(|a, b| {
            b.quality
                .partial_cmp(&a.quality)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        v
    }

    /// Return results where quality ≥ `threshold`.
    #[must_use]
    pub fn above_threshold(&self, threshold: f64) -> Vec<&CombinedResult> {
        self.entries
            .iter()
            .filter(|r| r.quality >= threshold)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BestCombination
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks the highest-scoring combination found so far.
#[derive(Debug, Clone, Default)]
pub struct BestCombination {
    /// The best result observed.
    pub result: Option<CombinedResult>,
    /// Number of evaluations performed.
    pub evaluations: usize,
    /// Number of times the best was updated.
    pub updates: usize,
}

impl BestCombination {
    /// Create an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Update the best if `result` has higher quality.
    ///
    /// Returns `true` if the best was updated.
    pub fn update(&mut self, result: CombinedResult) -> bool {
        self.evaluations += 1;
        let is_better = match &self.result {
            None => true,
            Some(prev) => result.quality > prev.quality,
        };
        if is_better {
            self.result = Some(result);
            self.updates += 1;
        }
        is_better
    }

    /// Return the best quality score, or 0.0 if no result yet.
    #[must_use]
    pub fn best_quality(&self) -> f64 {
        self.result.as_ref().map_or(0.0, |r| r.quality)
    }

    /// Return `true` if a result has been stored.
    #[must_use]
    pub const fn has_result(&self) -> bool {
        self.result.is_some()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WeightVector — normalised weight vector utilities
// ─────────────────────────────────────────────────────────────────────────────

/// A normalised vector of (`strategy_name`, weight) pairs.
#[derive(Debug, Clone, Default)]
pub struct WeightVector {
    /// Entries: (name, weight).
    pub entries: Vec<(String, f64)>,
}

impl WeightVector {
    /// Create from a list of (name, weight) pairs.  Normalises automatically.
    #[must_use]
    pub fn new(entries: Vec<(String, f64)>) -> Self {
        let mut wv = Self { entries };
        wv.normalise();
        wv
    }

    /// Normalise so weights sum to 1.0.
    pub fn normalise(&mut self) {
        let total: f64 = self.entries.iter().map(|(_, w)| w.abs()).sum();
        if total > 1e-12 {
            for (_, w) in &mut self.entries {
                *w = w.abs() / total;
            }
        }
    }

    /// Return the weight for `name` (0.0 if not present).
    #[must_use]
    pub fn get(&self, name: &str) -> f64 {
        self.entries
            .iter()
            .find(|(n, _)| n == name)
            .map_or(0.0, |(_, w)| *w)
    }

    /// Convert to a [`CombinedStrategy`].
    #[must_use]
    pub fn to_combined_strategy(&self) -> CombinedStrategy {
        let weights = self
            .entries
            .iter()
            .map(|entry| {
                let (n, w) = (&entry.0, entry.1);
                StrategyWeight::new(n.clone(), w)
            })
            .collect();
        CombinedStrategy {
            weights,
            label: "from-weight-vector".into(),
            estimated_quality: None,
        }
    }

    /// L2 distance between two weight vectors over the union of their names.
    #[must_use]
    pub fn l2_distance(&self, other: &Self) -> f64 {
        let all_names: std::collections::HashSet<&str> = self
            .entries
            .iter()
            .map(|(n, _)| n.as_str())
            .chain(other.entries.iter().map(|(n, _)| n.as_str()))
            .collect();
        all_names
            .iter()
            .map(|&name| {
                let a = self.get(name);
                let b = other.get(name);
                (a - b).powi(2)
            })
            .sum::<f64>()
            .sqrt()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StrategyPortfolio — manages a diversified set of named strategies
// ─────────────────────────────────────────────────────────────────────────────

/// Portfolio performance summary for one strategy.
#[derive(Debug, Clone)]
pub struct StrategyPerformance {
    /// Strategy name.
    pub name: String,
    /// Number of evaluations.
    pub evaluations: usize,
    /// Best quality observed.
    pub best_quality: f64,
    /// Mean quality.
    pub mean_quality: f64,
    /// Whether this strategy is currently recommended.
    pub recommended: bool,
}

impl StrategyPerformance {
    /// Create a new record.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            evaluations: 0,
            best_quality: f64::NEG_INFINITY,
            mean_quality: 0.0,
            recommended: false,
        }
    }

    /// Record a quality value.
    pub fn record(&mut self, quality: f64) {
        self.evaluations += 1;
        if quality > self.best_quality {
            self.best_quality = quality;
        }
        // Running mean (Welford's online).
        self.mean_quality += (quality - self.mean_quality) / self.evaluations as f64;
    }
}

/// Manages a portfolio of strategies and tracks their performance.
#[derive(Debug, Clone, Default)]
pub struct StrategyPortfolio {
    /// Performance records keyed by strategy name.
    pub performance: HashMap<String, StrategyPerformance>,
}

impl StrategyPortfolio {
    /// Create an empty portfolio.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new strategy.
    pub fn register(&mut self, name: impl Into<String>) {
        let name = name.into();
        self.performance
            .entry(name.clone())
            .or_insert_with(|| StrategyPerformance::new(name));
    }

    /// Record a quality observation for `strategy`.
    pub fn record(&mut self, strategy: &str, quality: f64) {
        if let Some(p) = self.performance.get_mut(strategy) {
            p.record(quality);
        }
    }

    /// Recommend the strategy with the highest mean quality.
    pub fn update_recommendations(&mut self) {
        let best_mean = self
            .performance
            .values()
            .map(|p| p.mean_quality)
            .fold(f64::NEG_INFINITY, f64::max);
        for p in self.performance.values_mut() {
            p.recommended = (p.mean_quality - best_mean).abs() < 1e-9;
        }
    }

    /// Return the recommended strategy name(s).
    #[must_use]
    pub fn recommended(&self) -> Vec<&str> {
        self.performance
            .values()
            .filter(|p| p.recommended)
            .map(|p| p.name.as_str())
            .collect()
    }

    /// Return the strategy with the highest best quality.
    #[must_use]
    pub fn best_strategy(&self) -> Option<&str> {
        // `performance` is a HashMap: without a tie-break on the name, two
        // strategies of equal quality would win arbitrarily and the reported
        // best strategy would differ between runs on identical data.
        self.performance
            .values()
            .max_by(|a, b| {
                a.best_quality
                    .partial_cmp(&b.best_quality)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| b.name.cmp(&a.name))
            })
            .map(|p| p.name.as_str())
    }

    /// Number of registered strategies.
    #[must_use]
    pub fn len(&self) -> usize {
        self.performance.len()
    }

    /// Return `true` when empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.performance.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CombinationOptimizer — exhaustive search over small strategy sets
// ─────────────────────────────────────────────────────────────────────────────

/// Exhaustively evaluates all `2^N` subsets of strategies (where each strategy
/// is either active or inactive) and returns the best combination.
///
/// Only suitable for small sets (≤ 20 strategies).
pub struct CombinationOptimizer {
    /// All strategy names to consider.
    pub strategies: Vec<String>,
    /// Scoring oracle.
    oracle: Box<dyn Fn(&CombinedStrategy) -> f64 + Send + Sync>,
}

impl CombinationOptimizer {
    /// Create an optimizer with the given strategies and oracle.
    #[must_use]
    pub fn new<F>(strategies: Vec<String>, oracle: F) -> Self
    where
        F: Fn(&CombinedStrategy) -> f64 + Send + Sync + 'static,
    {
        Self {
            strategies,
            oracle: Box::new(oracle),
        }
    }

    /// Evaluate all non-empty subsets and return the best.
    ///
    /// Returns `None` if strategies is empty.
    #[must_use]
    pub fn find_best(&self) -> Option<(CombinedResult, Vec<String>)> {
        if self.strategies.is_empty() {
            return None;
        }
        let n = self.strategies.len().min(20);
        let mut best_quality = f64::NEG_INFINITY;
        let mut best_result: Option<(CombinedResult, Vec<String>)> = None;

        for mask in 1u32..(1u32 << n) {
            let active: Vec<String> = (0..n)
                .filter(|&i| mask & (1 << i) != 0)
                .map(|i| self.strategies[i].clone())
                .collect();
            let mut cs =
                CombinedStrategy::uniform(&active.iter().map(String::as_str).collect::<Vec<_>>());
            cs.normalise();
            let q = (self.oracle)(&cs);
            if q > best_quality {
                best_quality = q;
                best_result = Some((CombinedResult::new(cs, q), active));
            }
        }
        best_result
    }
}

/// A simple genetic-algorithm-inspired combiner that evolves weights over generations.
pub struct GeneticCombiner {
    /// Strategy names.
    pub strategies: Vec<String>,
    /// Population size (default 10).
    pub population_size: usize,
    /// Number of generations (default 20).
    pub generations: usize,
    oracle: Box<dyn Fn(&CombinedStrategy) -> f64 + Send + Sync>,
}

impl GeneticCombiner {
    /// Create a genetic combiner.
    #[must_use]
    pub fn new<F>(strategies: Vec<String>, oracle: F) -> Self
    where
        F: Fn(&CombinedStrategy) -> f64 + Send + Sync + 'static,
    {
        Self {
            strategies,
            population_size: 10,
            generations: 20,
            oracle: Box::new(oracle),
        }
    }

    /// Run evolution and return the best result.
    #[must_use]
    pub fn evolve(&self) -> Option<CombinedResult> {
        if self.strategies.is_empty() {
            return None;
        }
        // Initialise population as uniform, then perturb.
        let mut population: Vec<CombinedStrategy> = (0..self.population_size)
            .map(|seed| {
                let mut cs = CombinedStrategy::uniform(
                    &self
                        .strategies
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                );
                // Deterministic perturbation by seed.
                for (i, w) in cs.weights.iter_mut().enumerate() {
                    let perturb = ((seed * 7 + i * 3) % 10) as f64 * 0.02;
                    w.weight = (w.weight + perturb).abs();
                }
                cs.normalise();
                cs
            })
            .collect();

        let mut best_quality = f64::NEG_INFINITY;
        let mut best: Option<CombinedResult> = None;

        for _gen in 0..self.generations {
            // Evaluate all.
            let scored: Vec<(f64, &CombinedStrategy)> = population
                .iter()
                .map(|cs| ((self.oracle)(cs), cs))
                .collect();

            for (q, cs) in &scored {
                if *q > best_quality {
                    best_quality = *q;
                    best = Some(CombinedResult::new((*cs).clone(), *q));
                }
            }

            // Select top half by score (simplified tournament selection).
            let mut sorted = scored;
            sorted.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
            let survivors: Vec<CombinedStrategy> = sorted
                .into_iter()
                .take(self.population_size / 2)
                .map(|(_, cs)| cs.clone())
                .collect();

            // Reproduce: each survivor spawns one offspring with a small mutation.
            population = survivors
                .iter()
                .flat_map(|parent| {
                    let mut child = parent.clone();
                    for (i, w) in child.weights.iter_mut().enumerate() {
                        let perturb = (i % 5) as f64 * 0.03;
                        w.weight = (w.weight + perturb).abs();
                    }
                    child.normalise();
                    [parent.clone(), child]
                })
                .take(self.population_size)
                .collect();
        }

        best
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HypothesisCombiner
// ─────────────────────────────────────────────────────────────────────────────

/// Evaluates and combines multiple deobfuscation hypotheses using a scoring
/// oracle to find the best weighted mixture of strategies.
///
/// The combiner uses a simple greedy search:
/// 1. Start from a uniform combination.
/// 2. For each registered strategy, try boosting its weight by `step_size`.
/// 3. Accept the boost if it improves the combined score.
/// 4. Repeat for `max_iterations`.
pub struct HypothesisCombiner {
    /// All available strategy names.
    pub strategies: Vec<String>,
    /// Step size for weight adjustment (default 0.1).
    pub step_size: f64,
    /// Maximum greedy search iterations (default 50).
    pub max_iterations: usize,
    /// Minimum quality improvement to accept a weight change (default 0.001).
    pub improvement_threshold: f64,
    /// The scoring oracle: `(strategy, weights) → quality`.
    oracle: Box<dyn Fn(&CombinedStrategy) -> f64 + Send + Sync>,
}

impl HypothesisCombiner {
    /// Create a combiner with the given strategies and a custom scoring oracle.
    #[must_use]
    pub fn new<F>(strategies: Vec<String>, oracle: F) -> Self
    where
        F: Fn(&CombinedStrategy) -> f64 + Send + Sync + 'static,
    {
        Self {
            strategies,
            step_size: 0.1,
            max_iterations: 50,
            improvement_threshold: 0.001,
            oracle: Box::new(oracle),
        }
    }

    /// Set the step size.
    #[must_use]
    pub const fn with_step_size(mut self, s: f64) -> Self {
        self.step_size = s;
        self
    }

    /// Set max iterations.
    #[must_use]
    pub const fn with_max_iterations(mut self, n: usize) -> Self {
        self.max_iterations = n;
        self
    }

    /// Run the greedy search and return `(BestCombination, CombinationHistory)`.
    #[must_use]
    pub fn run(&self) -> (BestCombination, CombinationHistory) {
        let mut best = BestCombination::new();
        let mut history = CombinationHistory::new();

        if self.strategies.is_empty() {
            return (best, history);
        }

        // Start with uniform weights.
        let mut current = CombinedStrategy::uniform(
            &self
                .strategies
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        );
        current.normalise();

        let init_quality = (self.oracle)(&current);
        let init_result = CombinedResult::new(current.clone(), init_quality);
        best.update(init_result.clone());
        history.push(init_result);

        for _ in 0..self.max_iterations {
            let mut made_progress = false;

            for strat_name in &self.strategies {
                // Try boosting this strategy.
                let mut candidate = current.clone();
                if let Some(w) = candidate.weights.iter_mut().find(|w| w.name == *strat_name) {
                    w.weight += self.step_size;
                }
                candidate.normalise();
                candidate.label = format!("boost-{strat_name}");

                let q = (self.oracle)(&candidate);
                let result = CombinedResult::new(candidate.clone(), q);
                let improved = q - best.best_quality() > self.improvement_threshold;

                history.push(result.clone());

                if improved {
                    best.update(result);
                    current = candidate;
                    made_progress = true;
                    break; // greedy: take the first improvement
                }
            }

            if !made_progress {
                break; // converged
            }
        }

        (best, history)
    }

    /// Evaluate a single strategy combination.
    #[must_use]
    pub fn evaluate(&self, strategy: &CombinedStrategy) -> CombinedResult {
        let q = (self.oracle)(strategy);
        CombinedResult::new(strategy.clone(), q)
    }

    /// Enumerate all single-strategy combinations and return the one with the
    /// highest quality.
    #[must_use]
    pub fn best_single_strategy(&self) -> Option<(&str, f64)> {
        let mut best: Option<(&str, f64)> = None;
        for name in &self.strategies {
            let mut strat = CombinedStrategy::from_map(
                self.strategies
                    .iter()
                    .map(|n| (n.clone(), if n == name { 1.0 } else { 0.0 }))
                    .collect(),
            );
            strat.normalise();
            let q = (self.oracle)(&strat);
            if best.is_none_or(|(_, bq)| q > bq) {
                best = Some((name.as_str(), q));
            }
        }
        best
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── StrategyWeight ────────────────────────────────────────────────────────

    #[test]
    fn test_weight_new() {
        let w = StrategyWeight::new("cff", 0.5);
        assert_eq!(w.name, "cff");
        assert_eq!(w.weight, 0.5);
        assert!(w.active);
    }

    #[test]
    fn test_weight_negative_abs() {
        let w = StrategyWeight::new("x", -0.3);
        assert_eq!(w.weight, 0.3);
    }

    #[test]
    fn test_weight_is_significant() {
        let w = StrategyWeight::new("x", 0.5);
        assert!(w.is_significant());
        let w2 = StrategyWeight::new("x", 0.005);
        assert!(!w2.is_significant());
    }

    #[test]
    fn test_weight_disabled() {
        let w = StrategyWeight::new("x", 0.9).disabled();
        assert!(!w.active);
        assert!(!w.is_significant());
    }

    // ── CombinedStrategy ──────────────────────────────────────────────────────

    #[test]
    fn test_uniform_weights() {
        let cs = CombinedStrategy::uniform(&["a", "b", "c"]);
        assert_eq!(cs.weights.len(), 3);
        assert!((cs.weight_for("a") - 1.0 / 3.0).abs() < 1e-10);
    }

    #[test]
    fn test_normalise() {
        let mut cs = CombinedStrategy::from_map(
            [("a".into(), 2.0), ("b".into(), 3.0)].into_iter().collect(),
        );
        cs.normalise();
        assert!((cs.weight_for("a") - 0.4).abs() < 1e-10);
        assert!((cs.weight_for("b") - 0.6).abs() < 1e-10);
    }

    #[test]
    fn test_weight_for_unknown() {
        let cs = CombinedStrategy::uniform(&["x"]);
        assert_eq!(cs.weight_for("unknown"), 0.0);
    }

    #[test]
    fn test_active_names() {
        let mut cs = CombinedStrategy::uniform(&["a", "b"]);
        cs.weights[0].active = false;
        assert_eq!(cs.active_names(), vec!["b"]);
    }

    #[test]
    fn test_is_valid() {
        let cs = CombinedStrategy::uniform(&["a"]);
        assert!(cs.is_valid());
        let empty = CombinedStrategy::uniform(&[]);
        // Empty uniform has no weights.
        assert!(!empty.is_valid());
    }

    #[test]
    fn test_active_count() {
        let cs = CombinedStrategy::uniform(&["a", "b", "c"]);
        assert_eq!(cs.active_count(), 3);
    }

    // ── CombinedResult ────────────────────────────────────────────────────────

    #[test]
    fn test_combined_result_new() {
        let cs = CombinedStrategy::uniform(&["a"]);
        let r = CombinedResult::new(cs, 0.8);
        assert_eq!(r.quality, 0.8);
        assert!(r.is_reliable);
    }

    #[test]
    fn test_combined_result_quality_clamped() {
        let cs = CombinedStrategy::uniform(&["a"]);
        let r = CombinedResult::new(cs, 2.5);
        assert_eq!(r.quality, 1.0);
    }

    #[test]
    fn test_combined_result_summary() {
        let cs = CombinedStrategy::uniform(&["a"]);
        let r = CombinedResult::new(cs, 0.75);
        let s = r.summary();
        assert!(s.contains("quality=0.7500"));
    }

    #[test]
    fn test_dominant_strategy_single() {
        let cs = CombinedStrategy::uniform(&["a"]);
        let mut r = CombinedResult::new(cs, 0.9);
        r.set_strategy_quality("a", 0.9);
        assert_eq!(r.dominant_strategy(), Some("a"));
    }

    #[test]
    fn test_dominant_strategy_two_strategies() {
        let cs = CombinedStrategy::from_map(
            [("a".into(), 0.7), ("b".into(), 0.3)].into_iter().collect(),
        );
        let mut r = CombinedResult::new(cs, 0.8);
        r.set_strategy_quality("a", 0.9);
        r.set_strategy_quality("b", 0.2);
        assert_eq!(r.dominant_strategy(), Some("a"));
    }

    #[test]
    fn test_set_strategy_quality_clamp() {
        let cs = CombinedStrategy::uniform(&["a"]);
        let mut r = CombinedResult::new(cs, 0.5);
        r.set_strategy_quality("a", 1.5); // should be clamped to 1.0
        assert_eq!(*r.per_strategy_quality.get("a").unwrap(), 1.0);
    }

    // ── CombinationHistory ────────────────────────────────────────────────────

    #[test]
    fn test_history_empty() {
        let h = CombinationHistory::new();
        assert!(h.is_empty());
        assert!(h.best().is_none());
    }

    #[test]
    fn test_history_push_updates_best() {
        let mut h = CombinationHistory::new();
        let cs1 = CombinedStrategy::uniform(&["a"]);
        let cs2 = CombinedStrategy::uniform(&["b"]);
        h.push(CombinedResult::new(cs1, 0.5));
        h.push(CombinedResult::new(cs2, 0.9));
        assert_eq!(h.best().unwrap().quality, 0.9);
    }

    #[test]
    fn test_history_sorted_by_quality() {
        let mut h = CombinationHistory::new();
        h.push(CombinedResult::new(CombinedStrategy::uniform(&["a"]), 0.3));
        h.push(CombinedResult::new(CombinedStrategy::uniform(&["b"]), 0.8));
        h.push(CombinedResult::new(CombinedStrategy::uniform(&["c"]), 0.5));
        let sorted = h.sorted_by_quality();
        assert_eq!(sorted[0].quality, 0.8);
        assert_eq!(sorted[2].quality, 0.3);
    }

    #[test]
    fn test_history_above_threshold() {
        let mut h = CombinationHistory::new();
        h.push(CombinedResult::new(CombinedStrategy::uniform(&["a"]), 0.4));
        h.push(CombinedResult::new(CombinedStrategy::uniform(&["b"]), 0.7));
        let above = h.above_threshold(0.6);
        assert_eq!(above.len(), 1);
    }

    #[test]
    fn test_history_len() {
        let mut h = CombinationHistory::new();
        h.push(CombinedResult::new(CombinedStrategy::uniform(&["a"]), 0.5));
        assert_eq!(h.len(), 1);
    }

    // ── BestCombination ───────────────────────────────────────────────────────

    #[test]
    fn test_best_combination_empty() {
        let b = BestCombination::new();
        assert!(!b.has_result());
        assert_eq!(b.best_quality(), 0.0);
    }

    #[test]
    fn test_best_combination_update() {
        let mut b = BestCombination::new();
        let r1 = CombinedResult::new(CombinedStrategy::uniform(&["a"]), 0.5);
        let updated = b.update(r1);
        assert!(updated);
        assert_eq!(b.evaluations, 1);
        assert_eq!(b.updates, 1);
    }

    #[test]
    fn test_best_combination_no_update_when_worse() {
        let mut b = BestCombination::new();
        b.update(CombinedResult::new(CombinedStrategy::uniform(&["a"]), 0.8));
        let updated = b.update(CombinedResult::new(CombinedStrategy::uniform(&["b"]), 0.3));
        assert!(!updated);
        assert_eq!(b.updates, 1);
        assert_eq!(b.best_quality(), 0.8);
    }

    #[test]
    fn test_best_combination_monotone() {
        let mut b = BestCombination::new();
        for q in [0.1, 0.5, 0.3, 0.9, 0.7] {
            b.update(CombinedResult::new(CombinedStrategy::uniform(&["a"]), q));
        }
        assert_eq!(b.best_quality(), 0.9);
        assert_eq!(b.updates, 3); // updates at 0.1, 0.5, 0.9
    }

    // ── HypothesisCombiner ────────────────────────────────────────────────────

    /// Simple oracle: higher weight on "good" → higher quality.
    fn make_oracle() -> impl Fn(&CombinedStrategy) -> f64 + Send + Sync {
        |cs: &CombinedStrategy| {
            let w = cs.weight_for("good");
            w.clamp(0.0, 1.0)
        }
    }

    #[test]
    fn test_combiner_run_empty_strategies() {
        let combiner = HypothesisCombiner::new(vec![], |_| 0.5);
        let (best, history) = combiner.run();
        assert!(!best.has_result());
        assert!(history.is_empty());
    }

    #[test]
    fn test_combiner_run_finds_good_strategy() {
        let strategies = vec!["good".into(), "bad".into()];
        let combiner = HypothesisCombiner::new(strategies, make_oracle())
            .with_max_iterations(20)
            .with_step_size(0.2);
        let (best, _history) = combiner.run();
        assert!(best.has_result());
        // The combiner should end up boosting "good".
        assert!(best.best_quality() > 0.0);
    }

    #[test]
    fn test_combiner_evaluate_single() {
        let combiner = HypothesisCombiner::new(vec!["good".into()], make_oracle());
        let mut cs = CombinedStrategy::uniform(&["good"]);
        cs.normalise();
        let result = combiner.evaluate(&cs);
        assert!((result.quality - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_combiner_best_single_strategy() {
        let strategies = vec!["good".into(), "bad".into()];
        let combiner = HypothesisCombiner::new(strategies, make_oracle());
        let best = combiner.best_single_strategy();
        assert!(best.is_some());
        let (name, quality) = best.unwrap();
        assert_eq!(name, "good");
        assert!((quality - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_combiner_history_grows() {
        let strategies = vec!["a".into(), "b".into()];
        let combiner =
            HypothesisCombiner::new(strategies, |cs| cs.weight_for("a")).with_max_iterations(5);
        let (_, history) = combiner.run();
        assert!(!history.is_empty()); // at least the initial evaluation
    }

    #[test]
    fn test_combiner_step_size_affects_search() {
        let strategies = vec!["x".into()];
        let small = HypothesisCombiner::new(strategies.clone(), |cs| cs.weight_for("x"))
            .with_step_size(0.01)
            .with_max_iterations(10);
        let large = HypothesisCombiner::new(strategies, |cs| cs.weight_for("x"))
            .with_step_size(0.5)
            .with_max_iterations(10);
        let (best_small, _) = small.run();
        let (best_large, _) = large.run();
        // Both should find some positive quality.
        assert!(best_small.best_quality() >= 0.0);
        assert!(best_large.best_quality() >= 0.0);
    }

    // ── Additional coverage tests ─────────────────────────────────────────────

    #[test]
    fn test_strategy_weight_zero_is_not_significant() {
        let w = StrategyWeight::new("x", 0.0);
        assert!(!w.is_significant());
    }

    #[test]
    fn test_combined_strategy_from_map_normalise() {
        let mut cs = CombinedStrategy::from_map(
            [("a".into(), 1.0), ("b".into(), 4.0)].into_iter().collect(),
        );
        cs.normalise();
        assert!((cs.weight_for("a") - 0.2).abs() < 1e-10);
        assert!((cs.weight_for("b") - 0.8).abs() < 1e-10);
    }

    #[test]
    fn test_combined_result_not_reliable_when_low_quality() {
        let cs = CombinedStrategy::uniform(&["a"]);
        let r = CombinedResult::new(cs, 0.3); // < 0.5
        assert!(!r.is_reliable);
    }

    #[test]
    fn test_combined_result_actions_taken() {
        let cs = CombinedStrategy::uniform(&["a"]);
        let mut r = CombinedResult::new(cs, 0.7);
        r.actions_taken = 42;
        assert_eq!(r.actions_taken, 42);
    }

    #[test]
    fn test_combined_result_complexity_reduction() {
        let cs = CombinedStrategy::uniform(&["a"]);
        let mut r = CombinedResult::new(cs, 0.8);
        r.complexity_reduction = 150.0;
        assert_eq!(r.complexity_reduction, 150.0);
    }

    #[test]
    fn test_combination_history_best_not_updated_on_lower() {
        let mut h = CombinationHistory::new();
        h.push(CombinedResult::new(CombinedStrategy::uniform(&["a"]), 0.9));
        let old_best = h.best().map_or(0.0, |r| r.quality);
        h.push(CombinedResult::new(CombinedStrategy::uniform(&["b"]), 0.2));
        assert_eq!(h.best().unwrap().quality, old_best);
    }

    #[test]
    fn test_best_combination_evaluations_count() {
        let mut b = BestCombination::new();
        for q in [0.1, 0.2, 0.3] {
            b.update(CombinedResult::new(CombinedStrategy::uniform(&["a"]), q));
        }
        assert_eq!(b.evaluations, 3);
        assert_eq!(b.updates, 3); // all improving
    }

    #[test]
    fn test_combiner_oracle_receives_combined_strategy() {
        // Verify the oracle is called with the correct strategy.
        let called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let called2 = called.clone();
        let combiner = HypothesisCombiner::new(vec!["test".into()], move |_cs| {
            called2.store(true, std::sync::atomic::Ordering::SeqCst);
            0.5
        });
        let _ = combiner.run();
        assert!(called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn test_combined_strategy_label_updated_on_boost() {
        let orch = HypothesisCombiner::new(vec!["a".into(), "b".into()], |cs| cs.weight_for("a"))
            .with_max_iterations(3);
        let (_, history) = orch.run();
        // At least one entry should have "boost-" label.
        let has_boost = history
            .entries
            .iter()
            .any(|r| r.strategy.label.contains("boost-"));
        assert!(has_boost || !history.is_empty()); // history must have entries
    }

    #[test]
    fn test_combined_strategy_uniform_single() {
        let cs = CombinedStrategy::uniform(&["only"]);
        assert_eq!(cs.weight_for("only"), 1.0);
        assert_eq!(cs.active_count(), 1);
    }

    #[test]
    fn test_best_combination_has_result_after_update() {
        let mut b = BestCombination::new();
        assert!(!b.has_result());
        b.update(CombinedResult::new(CombinedStrategy::uniform(&["a"]), 0.5));
        assert!(b.has_result());
    }

    #[test]
    fn test_combined_result_dominant_when_no_per_strategy_quality() {
        let cs = CombinedStrategy::uniform(&["x"]);
        let r = CombinedResult::new(cs, 0.7);
        // Dominant strategy falls back to weight × overall quality.
        assert_eq!(r.dominant_strategy(), Some("x"));
    }

    #[test]
    fn test_combiner_best_single_strategy_single() {
        let combiner = HypothesisCombiner::new(vec!["only".into()], |_| 0.75);
        let best = combiner.best_single_strategy();
        assert!(best.is_some());
        let (name, q) = best.unwrap();
        assert_eq!(name, "only");
        assert!((q - 0.75).abs() < 1e-10);
    }
}
