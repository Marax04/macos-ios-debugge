//! Threat scoring — aggregate scores from multiple sources with decay and context boost.
//!
//! # Model
//!
//! Each `IoC` has a **threat score** `[0.0, 1.0]` derived from:
//!
//! 1. **Source signals** — weighted scores from individual providers (VT, MISP, Malpedia, etc.)
//! 2. **Temporal decay** — older observations contribute less; configurable half-life.
//! 3. **Context boost** — if the `IoC` was found in a sample currently being analysed, +boost.
//! 4. **Aggregation** — weighted mean → non-linear sigmoid squash to `[0.0, 1.0]`.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ── Source weights ────────────────────────────────────────────────────────────

/// Identifier for a threat intelligence provider.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TiProvider {
    VirusTotal,
    Misp,
    Malpedia,
    MalwareBazaar,
    OtxAlienVault,
    RecordedFuture,
    Custom(String),
}

impl TiProvider {
    /// Base weight for this provider in score aggregation.
    /// Higher weight → more influence on the final score.
    #[must_use] 
    pub const fn base_weight(&self) -> f32 {
        match self {
            Self::VirusTotal => 1.5,       // Large corpus, high coverage
            Self::RecordedFuture => 1.4,   // Premium, curated
            Self::Malpedia => 1.2,         // Expert curated malware DB
            // Community, variable quality / MalwareBazaar / custom default
            Self::Misp | Self::MalwareBazaar | Self::Custom(_) => 1.0,
            Self::OtxAlienVault => 0.8,    // Very open, more noise
        }
    }
}

// ── Source signal ─────────────────────────────────────────────────────────────

/// A single raw signal from one provider for one `IoC`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceSignal {
    /// The provider emitting this signal.
    pub provider: TiProvider,
    /// Raw score from the provider `[0.0, 1.0]`.
    /// For VT this would be `detections / total_engines`.
    pub raw_score: f32,
    /// UNIX timestamp (seconds) when this signal was observed.
    pub observed_at: u64,
    /// Optional provider-specific confidence in the signal itself.
    pub provider_confidence: Option<f32>,
    /// Metadata tags (e.g. `["ransomware", "c2"]`).
    pub tags: Vec<String>,
}

impl SourceSignal {
    /// Create a new signal with the current timestamp.
    #[must_use] 
    pub fn new_now(provider: TiProvider, raw_score: f32) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        Self {
            provider,
            raw_score: raw_score.clamp(0.0, 1.0),
            observed_at: now,
            provider_confidence: None,
            tags: vec![],
        }
    }
}

// ── Decay model ───────────────────────────────────────────────────────────────

/// Configuration for temporal decay of `IoC` scores.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecayConfig {
    /// Half-life in seconds. After this duration, a signal contributes half its original weight.
    pub half_life_secs: u64,
    /// Minimum multiplier applied even for very old `IoCs` (`[0.0, 1.0]`).
    pub floor: f32,
}

impl Default for DecayConfig {
    fn default() -> Self {
        Self {
            half_life_secs: 30 * 24 * 3600, // 30 days
            floor: 0.1,
        }
    }
}

impl DecayConfig {
    /// Compute the decay multiplier for a signal observed `age_secs` ago.
    #[must_use] 
    pub fn multiplier(&self, age_secs: u64) -> f32 {
        let t = crate::casts::u64_to_f32(age_secs);
        let half = crate::casts::u64_to_f32(self.half_life_secs);
        let decayed = (-std::f32::consts::LN_2 * t / half).exp();
        decayed.max(self.floor)
    }

    /// Compute the decay multiplier given an absolute observation timestamp.
    #[must_use] 
    pub fn multiplier_for_ts(&self, observed_at: u64) -> f32 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let age = now.saturating_sub(observed_at);
        self.multiplier(age)
    }
}

// ── Context boost ─────────────────────────────────────────────────────────────

/// Contextual evidence that raises an `IoC`'s threat score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextBoost {
    /// Label describing the boost source.
    pub label: String,
    /// Additive boost applied to the aggregated score `[0.0, 1.0]`.
    pub boost: f32,
}

impl ContextBoost {
    /// `IoC` found in a sample currently under active analysis.
    #[must_use] 
    pub fn active_sample_analysis(boost: f32) -> Self {
        Self {
            label: "active_sample_analysis".into(),
            boost: boost.clamp(0.0, 0.3),
        }
    }

    /// `IoC` observed in sandbox network traffic.
    #[must_use] 
    pub fn sandbox_traffic(boost: f32) -> Self {
        Self {
            label: "sandbox_traffic".into(),
            boost: boost.clamp(0.0, 0.25),
        }
    }

    /// `IoC` directly correlated with a known malware family.
    #[must_use] 
    pub fn malware_family_match(boost: f32) -> Self {
        Self {
            label: "malware_family_match".into(),
            boost: boost.clamp(0.0, 0.2),
        }
    }
}

// ── Score breakdown ───────────────────────────────────────────────────────────

/// Detailed breakdown of how a final score was computed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    /// Weighted, decayed scores per provider before aggregation.
    pub per_provider: HashMap<String, f32>,
    /// Raw weighted mean before context boosts.
    pub weighted_mean: f32,
    /// Total context boost applied.
    pub total_boost: f32,
    /// Final score after boost and squash `[0.0, 1.0]`.
    pub final_score: f32,
    /// Number of signals contributing.
    pub signal_count: usize,
    /// Severity label derived from the final score.
    pub severity: SeverityLabel,
}

/// Human-readable severity labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeverityLabel {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityLabel {
    #[must_use] 
    pub fn from_score(score: f32) -> Self {
        match score {
            s if s < 0.2 => Self::Unknown,
            s if s < 0.4 => Self::Low,
            s if s < 0.6 => Self::Medium,
            s if s < 0.8 => Self::High,
            _ => Self::Critical,
        }
    }
}

// ── Aggregation strategies ───────────────────────────────────────────────────

/// Strategy for combining multiple provider scores.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AggregationStrategy {
    /// Weighted mean across all signals.
    WeightedMean,
    /// Take the maximum signal (most alarmist).
    Max,
    /// Take the minimum signal (most conservative).
    Min,
    /// Bayesian update treating each signal as independent evidence.
    BayesianUpdate,
}

// ── Threat scorer ─────────────────────────────────────────────────────────────

/// Scorer configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScorerConfig {
    pub decay: DecayConfig,
    pub aggregation: AggregationStrategy,
    /// Cap on total context boost applied.
    pub max_boost: f32,
    /// Whether to normalize final score through a sigmoid.
    pub apply_sigmoid: bool,
}

impl Default for ScorerConfig {
    fn default() -> Self {
        Self {
            decay: DecayConfig::default(),
            aggregation: AggregationStrategy::WeightedMean,
            max_boost: 0.4,
            apply_sigmoid: true,
        }
    }
}

/// Aggregates signals from multiple providers into a single threat score.
impl Default for ThreatScorer {
    fn default() -> Self {
        Self::new(ScorerConfig::default())
    }
}

pub struct ThreatScorer {
    config: ScorerConfig,
}

impl ThreatScorer {
    #[must_use] 
    pub const fn new(config: ScorerConfig) -> Self {
        Self { config }
    }

    /// Compute the final score for an `IoC` given its signals and optional context boosts.
    pub fn score(
        &self,
        signals: &[SourceSignal],
        boosts: &[ContextBoost],
    ) -> ScoreBreakdown {
        if signals.is_empty() {
            return ScoreBreakdown {
                per_provider: HashMap::new(),
                weighted_mean: 0.0,
                total_boost: 0.0,
                final_score: 0.0,
                signal_count: 0,
                severity: SeverityLabel::Unknown,
            };
        }

        // Step 1: apply decay and compute effective (weight, score) per signal
        let effective: Vec<(f32, f32, String)> = signals
            .iter()
            .map(|sig| {
                let decay = self.config.decay.multiplier_for_ts(sig.observed_at);
                let provider_weight = sig.provider.base_weight();
                let conf = sig.provider_confidence.unwrap_or(1.0);
                let effective_weight = provider_weight * conf * decay;
                let provider_label = format!("{:?}", sig.provider);
                (effective_weight, sig.raw_score, provider_label)
            })
            .collect();

        // Step 2: aggregate
        let aggregated = match self.config.aggregation {
            AggregationStrategy::WeightedMean => Self::weighted_mean(&effective),
            AggregationStrategy::Max => effective
                .iter()
                .map(|(_, s, _)| *s)
                .fold(0.0_f32, f32::max),
            AggregationStrategy::Min => effective
                .iter()
                .map(|(_, s, _)| *s)
                .fold(1.0_f32, f32::min),
            AggregationStrategy::BayesianUpdate => Self::bayesian_update(&effective),
        };

        // Per-provider map (decayed)
        let mut per_provider: HashMap<String, f32> = HashMap::new();
        for (w, s, label) in &effective {
            per_provider
                .entry(label.clone())
                .and_modify(|v| *v = f32::midpoint(*v, w * s))
                .or_insert(w * s);
        }

        // Step 3: apply context boosts
        let total_boost: f32 = boosts.iter().map(|b| b.boost).sum::<f32>().min(self.config.max_boost);
        let boosted = (aggregated + total_boost).clamp(0.0, 1.0);

        // Step 4: optional sigmoid squash for smooth distribution
        let final_score = if self.config.apply_sigmoid {
            Self::sigmoid(boosted)
        } else {
            boosted
        };

        ScoreBreakdown {
            per_provider,
            weighted_mean: aggregated,
            total_boost,
            final_score,
            signal_count: signals.len(),
            severity: SeverityLabel::from_score(final_score),
        }
    }

    fn weighted_mean(effective: &[(f32, f32, String)]) -> f32 {
        let total_w: f32 = effective.iter().map(|(w, _, _)| w).sum();
        // `!(x > 0.0)`, not `x == 0.0`: weights originate from public unvalidated
        // score fields, and a NaN passes the equality form untouched.
        if !(total_w > 0.0) {
            return 0.0;
        }
        let sum: f32 = effective.iter().map(|(w, s, _)| w * s).sum();
        let mean = (sum / total_w).clamp(0.0, 1.0);
        if mean.is_finite() { mean } else { 0.0 }
    }

    fn bayesian_update(effective: &[(f32, f32, String)]) -> f32 {
        // Prior: uniform 0.5; update with each signal as independent Bernoulli evidence
        let mut p = 0.5_f32;
        for (w, s, _) in effective {
            // Likelihood ratio: evidence strength scaled by weight
            let lr = (s * w + 0.001) / (1.0 - s * w + 0.001);
            let odds = p / (1.0 - p + 1e-6);
            let new_odds = odds * lr;
            let updated = new_odds / (1.0 + new_odds);
            // `s * w == 1.001` makes the `lr` denominator exactly zero, and a
            // non-finite weight or strength poisons it outright; either way
            // `p` would become NaN and stay NaN for every remaining signal,
            // which `clamp` propagates. Skipping the bad update keeps the
            // evidence accumulated so far instead of discarding all of it.
            if updated.is_finite() {
                p = updated;
            }
        }
        p.clamp(0.0, 1.0)
    }

    fn sigmoid(x: f32) -> f32 {
        // Centered sigmoid that maps [0,1] → [0,1] with boosted mid-range separation
        let shifted = (x - 0.5) * 8.0; // steepness
        1.0 / (1.0 + (-shifted).exp())
    }
}

// ── Batch scorer ──────────────────────────────────────────────────────────────

/// Score a map of `ioc_id → signals` in batch.
pub struct BatchScorer {
    scorer: ThreatScorer,
}

impl BatchScorer {
    #[must_use] 
    pub const fn new(scorer: ThreatScorer) -> Self {
        Self { scorer }
    }

    /// Score all `IoCs`, returning a map `ioc_id → ScoreBreakdown`.
    #[must_use] 
    pub fn score_all(
        &self,
        signals_map: HashMap<String, Vec<SourceSignal>>,
        boosts_map: &HashMap<String, Vec<ContextBoost>>,
    ) -> HashMap<String, ScoreBreakdown> {
        signals_map
            .into_iter()
            .map(|(ioc_id, signals)| {
                let boosts = boosts_map.get(&ioc_id).map_or(&[][..], std::vec::Vec::as_slice);
                let breakdown = self.scorer.score(&signals, boosts);
                (ioc_id, breakdown)
            })
            .collect()
    }

    /// Return only `IoCs` exceeding a score threshold.
    ///
    /// # Panics
    ///
    /// Panics if the internal score comparator encounters NaN.
    #[must_use]
    pub fn filter_by_score(
        results: &HashMap<String, ScoreBreakdown>,
        threshold: f32,
    ) -> Vec<(&str, f32)> {
        let mut out: Vec<(&str, f32)> = results
            .iter()
            .filter(|(_, b)| b.final_score >= threshold)
            .map(|(id, b)| (id.as_str(), b.final_score))
            .collect();
        out.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        out
    }
}

// ── Score cache ───────────────────────────────────────────────────────────────

/// Time-limited cache for `IoC` scores, keyed by `IoC` canonical value.
pub struct ScoreCache {
    entries: HashMap<String, (ScoreBreakdown, u64)>,
    ttl_secs: u64,
}

impl ScoreCache {
    #[must_use] 
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            entries: HashMap::new(),
            ttl_secs,
        }
    }

    pub fn insert(&mut self, key: String, breakdown: ScoreBreakdown) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        self.entries.insert(key, (breakdown, now));
    }

    #[must_use] 
    pub fn get(&self, key: &str) -> Option<&ScoreBreakdown> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        self.entries.get(key).and_then(|(b, ts)| {
            if now.saturating_sub(*ts) < self.ttl_secs {
                Some(b)
            } else {
                None
            }
        })
    }

    pub fn evict_stale(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let ttl = self.ttl_secs;
        self.entries.retain(|_, (_, ts)| now.saturating_sub(*ts) < ttl);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the cache contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ts_days_ago(days: u64) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(days * 86400)
    }

    #[test]
    fn decay_half_life() {
        let cfg = DecayConfig {
            half_life_secs: 30 * 86400,
            floor: 0.0,
        };
        let m = cfg.multiplier(30 * 86400);
        assert!((m - 0.5).abs() < 0.01, "multiplier should be ~0.5 at half-life: {m}");
    }

    #[test]
    fn scorer_basic() {
        let scorer = ThreatScorer::default();
        let signals = vec![
            SourceSignal {
                provider: TiProvider::VirusTotal,
                raw_score: 0.9,
                observed_at: ts_days_ago(1),
                provider_confidence: None,
                tags: vec![],
            },
            SourceSignal {
                provider: TiProvider::Misp,
                raw_score: 0.7,
                observed_at: ts_days_ago(5),
                provider_confidence: None,
                tags: vec![],
            },
        ];
        let bd = scorer.score(&signals, &[]);
        assert!(bd.final_score > 0.5, "score should be > 0.5: {}", bd.final_score);
        assert_eq!(bd.signal_count, 2);
    }

    #[test]
    fn context_boost_raises_score() {
        let scorer = ThreatScorer::default();
        let signals = vec![SourceSignal {
            provider: TiProvider::OtxAlienVault,
            raw_score: 0.3,
            observed_at: ts_days_ago(2),
            provider_confidence: None,
            tags: vec![],
        }];
        let no_boost = scorer.score(&signals, &[]).final_score;
        let boost = scorer
            .score(&signals, &[ContextBoost::active_sample_analysis(0.3)])
            .final_score;
        assert!(boost > no_boost, "boost should raise score: {no_boost} → {boost}");
    }

    #[test]
    fn empty_signals() {
        let scorer = ThreatScorer::default();
        let bd = scorer.score(&[], &[]);
        assert!((bd.final_score - 0.0).abs() < f32::EPSILON);
        assert_eq!(bd.severity, SeverityLabel::Unknown);
    }

    #[test]
    fn severity_labels() {
        assert_eq!(SeverityLabel::from_score(0.1), SeverityLabel::Unknown);
        assert_eq!(SeverityLabel::from_score(0.3), SeverityLabel::Low);
        assert_eq!(SeverityLabel::from_score(0.5), SeverityLabel::Medium);
        assert_eq!(SeverityLabel::from_score(0.7), SeverityLabel::High);
        assert_eq!(SeverityLabel::from_score(0.9), SeverityLabel::Critical);
    }

    #[test]
    fn cache_basic() {
        let scorer = ThreatScorer::default();
        let bd = scorer.score(
            &[SourceSignal::new_now(TiProvider::VirusTotal, 0.8)],
            &[],
        );
        let mut cache = ScoreCache::new(60);
        cache.insert("evil.com".into(), bd);
        assert!(cache.get("evil.com").is_some());
        assert!(cache.get("good.com").is_none());
    }
}
