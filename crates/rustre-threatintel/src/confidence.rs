//! Confidence scoring engine for threat intelligence.
//!
//! Implements a multi-factor Bayesian-style confidence scorer that combines
//! signals from multiple sources to produce a calibrated confidence estimate
//! in [0, 100].

use serde::{Deserialize, Serialize};
use std::fmt;

/// A single evidence signal that contributes to a confidence estimate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSignal {
    /// Descriptive name of this signal (e.g. `"virustotal_detections"`).
    pub name: String,
    /// Raw signal value in [0.0, 1.0].
    pub value: f64,
    /// Weight applied to this signal, in [0.0, 1.0].
    pub weight: f64,
    /// Human-readable explanation.
    pub rationale: String,
}

impl EvidenceSignal {
    /// Create a new evidence signal.
    ///
    /// # Panics
    ///
    /// Panics in debug mode if `value` or `weight` is outside [0.0, 1.0].
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        value: f64,
        weight: f64,
        rationale: impl Into<String>,
    ) -> Self {
        // Out-of-range inputs are silently clamped (see `clamp` below); the
        // caller is allowed to pass arbitrary values.
        Self {
            name: name.into(),
            value: value.clamp(0.0, 1.0),
            weight: weight.clamp(0.0, 1.0),
            rationale: rationale.into(),
        }
    }

    /// Weighted contribution of this signal.
    #[must_use]
    pub fn contribution(&self) -> f64 {
        self.value * self.weight
    }
}

impl fmt::Display for EvidenceSignal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} = {:.2} (weight={:.2}) — {}",
            self.name, self.value, self.weight, self.rationale
        )
    }
}

// ---------------------------------------------------------------------------
// ConfidenceModel
// ---------------------------------------------------------------------------

/// Method used to aggregate evidence signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationMethod {
    /// Weighted arithmetic mean of all signals.
    WeightedMean,
    /// Maximum signal value (optimistic upper bound).
    Maximum,
    /// Minimum signal value (pessimistic lower bound).
    Minimum,
    /// Median of weighted contributions.
    WeightedMedian,
}

impl fmt::Display for AggregationMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::WeightedMean => "Weighted Mean",
            Self::Maximum => "Maximum",
            Self::Minimum => "Minimum",
            Self::WeightedMedian => "Weighted Median",
        };
        f.write_str(s)
    }
}

/// Confidence scoring model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceModel {
    /// All evidence signals considered.
    pub signals: Vec<EvidenceSignal>,
    /// Aggregation method.
    pub method: AggregationMethod,
    /// Optional prior probability in [0.0, 1.0] (Bayesian prior).
    pub prior: Option<f64>,
}

impl ConfidenceModel {
    /// Create a new model with no signals.
    #[must_use]
    pub const fn new(method: AggregationMethod) -> Self {
        Self {
            signals: Vec::new(),
            method,
            prior: None,
        }
    }

    /// Add an evidence signal.
    #[must_use]
    pub fn with_signal(mut self, signal: EvidenceSignal) -> Self {
        self.signals.push(signal);
        self
    }

    /// Set the Bayesian prior.
    #[must_use]
    pub const fn with_prior(mut self, prior: f64) -> Self {
        self.prior = Some(prior.clamp(0.0, 1.0));
        self
    }

    /// Add a signal by component values.
    pub fn add_signal(
        &mut self,
        name: impl Into<String>,
        value: f64,
        weight: f64,
        rationale: impl Into<String>,
    ) {
        self.signals
            .push(EvidenceSignal::new(name, value, weight, rationale));
    }

    /// Compute the raw score in [0.0, 1.0] from all signals.
    #[must_use]
    pub fn raw_score(&self) -> f64 {
        if self.signals.is_empty() {
            return self.prior.unwrap_or(0.5);
        }

        let score = match self.method {
            AggregationMethod::WeightedMean => {
                let total_weight: f64 = self.signals.iter().map(|s| s.weight).sum();
                // `!(x >= EPSILON)`, not `x < EPSILON`: `EvidenceSignal::weight`
                // is a public unvalidated field, and `NaN < EPSILON` is false,
                // so the plain form would let a NaN denominator through.
                if !(total_weight >= f64::EPSILON) {
                    return self.prior.unwrap_or(0.5);
                }
                let weighted_sum: f64 = self.signals.iter().map(EvidenceSignal::contribution).sum();
                weighted_sum / total_weight
            }
            AggregationMethod::Maximum => {
                self.signals.iter().map(|s| s.value).fold(0.0_f64, f64::max)
            }
            AggregationMethod::Minimum => {
                self.signals.iter().map(|s| s.value).fold(1.0_f64, f64::min)
            }
            AggregationMethod::WeightedMedian => {
                let mut contributions: Vec<f64> =
                    self.signals.iter().map(EvidenceSignal::contribution).collect();
                contributions.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                let n = contributions.len();
                if n.is_multiple_of(2) {
                    f64::midpoint(contributions[n / 2 - 1], contributions[n / 2])
                } else {
                    contributions[n / 2]
                }
            }
        };

        // Bayesian update if prior is set: P(H|E) ∝ P(E|H)*P(H)
        let out = self.prior.map_or_else(
            || score.clamp(0.0, 1.0),
            |prior| {
                let likelihood = score;
                let posterior = (likelihood * prior)
                    / (1.0 - likelihood).mul_add(1.0 - prior, likelihood * prior);
                posterior.clamp(0.0, 1.0)
            },
        );
        // `EvidenceSignal::value` is public and unvalidated, so a single NaN
        // poisons the aggregate even when every weight is sane; the posterior
        // division can also produce a non-finite result on its own. `clamp` does
        // not bound either case, so the [0,1] contract is enforced here.
        if out.is_finite() {
            out
        } else {
            self.prior.unwrap_or(0.5)
        }
    }

    /// Return the confidence as an integer in [0, 100].
    #[must_use]
    pub fn score_pct(&self) -> u8 {
        let v = (self.raw_score() * 100.0).round().clamp(0.0, 255.0);
        crate::casts::f64_to_u8_sat(v)
    }

    /// Classify the score into a human-readable tier.
    #[must_use]
    pub fn tier(&self) -> ConfidenceTier {
        ConfidenceTier::from_score(self.score_pct())
    }

    /// Return the signal with the highest weighted contribution.
    #[must_use]
    pub fn dominant_signal(&self) -> Option<&EvidenceSignal> {
        self.signals.iter().max_by(|a, b| {
            a.contribution()
                .partial_cmp(&b.contribution())
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }
}

impl fmt::Display for ConfidenceModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Confidence {}% ({}) — {} signal(s)",
            self.score_pct(),
            self.method,
            self.signals.len()
        )
    }
}

// ---------------------------------------------------------------------------
// ConfidenceTier
// ---------------------------------------------------------------------------

/// Qualitative confidence tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceTier {
    /// 0–19: extremely low confidence.
    VeryLow,
    /// 20–39: low confidence — treat with caution.
    Low,
    /// 40–59: moderate confidence — corroboration recommended.
    Moderate,
    /// 60–79: high confidence — reliable indicator.
    High,
    /// 80–100: very high confidence — act on this.
    VeryHigh,
}

impl ConfidenceTier {
    /// Derive a tier from an integer score in [0, 100].
    #[must_use]
    pub const fn from_score(score: u8) -> Self {
        match score {
            0..=19 => Self::VeryLow,
            20..=39 => Self::Low,
            40..=59 => Self::Moderate,
            60..=79 => Self::High,
            _ => Self::VeryHigh,
        }
    }

    /// Lower bound score for this tier.
    #[must_use]
    pub const fn lower_bound(&self) -> u8 {
        match self {
            Self::VeryLow => 0,
            Self::Low => 20,
            Self::Moderate => 40,
            Self::High => 60,
            Self::VeryHigh => 80,
        }
    }
}

impl fmt::Display for ConfidenceTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::VeryLow => "Very Low",
            Self::Low => "Low",
            Self::Moderate => "Moderate",
            Self::High => "High",
            Self::VeryHigh => "Very High",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// ConfidenceDecay
// ---------------------------------------------------------------------------

/// Models how confidence decays over time as intelligence ages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceDecay {
    /// Base confidence at time zero.
    pub initial_score: f64,
    /// Half-life in seconds after which score drops to 50 % of `initial_score`.
    pub half_life_secs: f64,
}

impl ConfidenceDecay {
    /// Create a new decay model.
    #[must_use]
    pub const fn new(initial_score: f64, half_life_secs: f64) -> Self {
        Self {
            initial_score: initial_score.clamp(0.0, 1.0),
            half_life_secs: half_life_secs.max(1.0),
        }
    }

    /// Compute the decayed score given an `age_secs` elapsed since observation.
    #[must_use]
    pub fn score_at_age(&self, age_secs: f64) -> f64 {
        // `new()` establishes `half_life_secs >= 1.0` and `initial_score` in
        // [0,1], but both are PUBLIC fields, so those invariants do not hold
        // here — re-apply them instead of trusting them. `f64::max` also
        // sanitises NaN (unlike `clamp`), which is why it is used for the
        // half-life. With `half_life_secs == 0.0` the lambda is +inf, and
        // `inf * 0.0` (an `age_secs` of zero) is NaN, which `exp` and `clamp`
        // both propagate.
        let half_life = self.half_life_secs.max(1.0);
        let lambda = std::f64::consts::LN_2 / half_life;
        let decayed = (self.initial_score * (-lambda * age_secs).exp()).clamp(0.0, 1.0);
        // `age_secs` is caller-supplied and `initial_score` is public, so the
        // result still has to be checked: `clamp` does not bound NaN.
        if decayed.is_finite() { decayed } else { 0.0 }
    }

    /// Return the decayed score as a percentage in [0, 100].
    #[must_use]
    pub fn score_pct_at_age(&self, age_secs: f64) -> u8 {
        let v = (self.score_at_age(age_secs) * 100.0).round();
        crate::casts::f64_to_u8_sat(v)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn basic_model() -> ConfidenceModel {
        let mut m = ConfidenceModel::new(AggregationMethod::WeightedMean);
        m.add_signal("vt_detections", 0.9, 0.6, "70/80 engines");
        m.add_signal("malpedia_match", 0.8, 0.4, "known hash");
        m
    }

    #[test]
    fn test_model_weighted_mean() {
        let m = basic_model();
        let score = m.score_pct();
        assert!(score > 0);
        assert!(score <= 100);
    }

    #[test]
    fn test_model_no_signals_returns_prior() {
        let m = ConfidenceModel::new(AggregationMethod::WeightedMean).with_prior(0.3);
        assert_eq!(m.score_pct(), 30);
    }

    #[test]
    fn test_model_no_signals_no_prior() {
        let m = ConfidenceModel::new(AggregationMethod::WeightedMean);
        assert_eq!(m.score_pct(), 50); // default prior = 0.5
    }

    #[test]
    fn test_model_maximum_method() {
        let mut m = ConfidenceModel::new(AggregationMethod::Maximum);
        m.add_signal("a", 0.3, 1.0, "low");
        m.add_signal("b", 0.9, 1.0, "high");
        assert_eq!(m.score_pct(), 90);
    }

    #[test]
    fn test_model_minimum_method() {
        let mut m = ConfidenceModel::new(AggregationMethod::Minimum);
        m.add_signal("a", 0.3, 1.0, "low");
        m.add_signal("b", 0.9, 1.0, "high");
        assert_eq!(m.score_pct(), 30);
    }

    #[test]
    fn test_model_median_method_odd() {
        let mut m = ConfidenceModel::new(AggregationMethod::WeightedMedian);
        m.add_signal("a", 0.2, 1.0, "");
        m.add_signal("b", 0.5, 1.0, "");
        m.add_signal("c", 0.8, 1.0, "");
        let pct = m.score_pct();
        assert_eq!(pct, 50);
    }

    #[test]
    fn test_model_with_prior_bayesian_update() {
        let m = ConfidenceModel::new(AggregationMethod::WeightedMean)
            .with_prior(0.1)
            .with_signal(EvidenceSignal::new("vt", 0.95, 1.0, "high detections"));
        let score = m.raw_score();
        // With a low prior of 0.1 and strong evidence 0.95 the posterior should
        // be between 0.5 and 0.95.
        assert!(score > 0.5);
        assert!(score < 0.99);
    }

    #[test]
    fn test_evidence_signal_contribution() {
        let s = EvidenceSignal::new("test", 0.8, 0.5, "");
        assert!((s.contribution() - 0.4).abs() < 1e-10);
    }

    #[test]
    fn test_evidence_signal_display() {
        let s = EvidenceSignal::new("sig", 0.75, 0.5, "rationale text");
        let out = s.to_string();
        assert!(out.contains("sig"));
        assert!(out.contains("rationale text"));
    }

    #[test]
    fn test_model_dominant_signal() {
        let m = basic_model();
        let dom = m.dominant_signal().unwrap();
        assert_eq!(dom.name, "vt_detections"); // 0.9 * 0.6 = 0.54 vs 0.8 * 0.4 = 0.32
    }

    #[test]
    fn test_model_dominant_signal_empty() {
        let m = ConfidenceModel::new(AggregationMethod::WeightedMean);
        assert!(m.dominant_signal().is_none());
    }

    #[test]
    fn test_model_tier() {
        let mut m = ConfidenceModel::new(AggregationMethod::Maximum);
        m.add_signal("a", 0.85, 1.0, "");
        assert_eq!(m.tier(), ConfidenceTier::VeryHigh);
    }

    #[test]
    fn test_model_display() {
        let m = basic_model();
        let s = m.to_string();
        assert!(s.contains("Confidence"));
        assert!(s.contains("Weighted Mean"));
    }

    #[test]
    fn test_confidence_tier_from_score() {
        assert_eq!(ConfidenceTier::from_score(0), ConfidenceTier::VeryLow);
        assert_eq!(ConfidenceTier::from_score(19), ConfidenceTier::VeryLow);
        assert_eq!(ConfidenceTier::from_score(20), ConfidenceTier::Low);
        assert_eq!(ConfidenceTier::from_score(39), ConfidenceTier::Low);
        assert_eq!(ConfidenceTier::from_score(40), ConfidenceTier::Moderate);
        assert_eq!(ConfidenceTier::from_score(59), ConfidenceTier::Moderate);
        assert_eq!(ConfidenceTier::from_score(60), ConfidenceTier::High);
        assert_eq!(ConfidenceTier::from_score(79), ConfidenceTier::High);
        assert_eq!(ConfidenceTier::from_score(80), ConfidenceTier::VeryHigh);
        assert_eq!(ConfidenceTier::from_score(100), ConfidenceTier::VeryHigh);
    }

    #[test]
    fn test_confidence_tier_ordering() {
        assert!(ConfidenceTier::VeryLow < ConfidenceTier::High);
        assert!(ConfidenceTier::Moderate < ConfidenceTier::VeryHigh);
    }

    #[test]
    fn test_confidence_tier_lower_bound() {
        assert_eq!(ConfidenceTier::VeryLow.lower_bound(), 0);
        assert_eq!(ConfidenceTier::Low.lower_bound(), 20);
        assert_eq!(ConfidenceTier::Moderate.lower_bound(), 40);
        assert_eq!(ConfidenceTier::High.lower_bound(), 60);
        assert_eq!(ConfidenceTier::VeryHigh.lower_bound(), 80);
    }

    #[test]
    fn test_confidence_tier_display() {
        assert_eq!(ConfidenceTier::VeryHigh.to_string(), "Very High");
        assert_eq!(ConfidenceTier::Low.to_string(), "Low");
    }

    #[test]
    fn test_aggregation_method_display() {
        assert_eq!(AggregationMethod::WeightedMean.to_string(), "Weighted Mean");
        assert_eq!(AggregationMethod::Maximum.to_string(), "Maximum");
    }

    #[test]
    fn test_confidence_decay_half_life() {
        let decay = ConfidenceDecay::new(1.0, 86400.0); // half-life = 1 day
        let after_one_day = decay.score_at_age(86400.0);
        assert!((after_one_day - 0.5).abs() < 1e-6);
    }

    #[test]
    fn test_confidence_decay_age_zero() {
        let decay = ConfidenceDecay::new(0.8, 3600.0);
        let at_zero = decay.score_at_age(0.0);
        assert!((at_zero - 0.8).abs() < 1e-10);
    }

    #[test]
    fn test_confidence_decay_large_age() {
        let decay = ConfidenceDecay::new(1.0, 3600.0);
        // After 100 half-lives the score should be negligible.
        let very_old = decay.score_pct_at_age(3600.0 * 100.0);
        assert_eq!(very_old, 0);
    }

    #[test]
    fn test_confidence_decay_pct() {
        let decay = ConfidenceDecay::new(1.0, 86400.0);
        let pct = decay.score_pct_at_age(86400.0);
        assert_eq!(pct, 50);
    }

    #[test]
    fn test_model_serialization() {
        let m = basic_model();
        let json = serde_json::to_string(&m).unwrap();
        let decoded: ConfidenceModel = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.signals.len(), 2);
    }

    #[test]
    fn test_evidence_signal_value_clamped() {
        let s = EvidenceSignal::new("s", 2.0, 0.5, "over range");
        assert!((s.value - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_model_zero_weight_signals() {
        let mut m = ConfidenceModel::new(AggregationMethod::WeightedMean);
        m.add_signal("a", 0.9, 0.0, "zero weight");
        // Total weight is 0 → falls back to default prior 0.5
        assert_eq!(m.score_pct(), 50);
    }
}
