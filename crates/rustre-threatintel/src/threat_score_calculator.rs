//! `threat_score_calculator` — Compute numerical threat scores for `IoCs` and reports.
//!
//! Produces a normalised [`ThreatScore`] in [0.0, 100.0] by combining multiple
//! evidence dimensions via configurable weights.

use std::collections::HashMap;

use crate::ioc::{IoC, IoCType, Severity};
use crate::report::ThreatReport;

// ─────────────────────────────────────────────────────────────────────────────
// ScoreComponents
// ─────────────────────────────────────────────────────────────────────────────

/// Individual scoring dimensions that make up a [`ThreatScore`].
#[derive(Debug, Clone, Default)]
pub struct ScoreComponents {
    /// Base score derived from `IoC` type.  0.0–25.0.
    pub ioc_type_base: f64,
    /// Corroboration bonus — higher when multiple sources agree.  0.0–20.0.
    pub corroboration: f64,
    /// Severity uplift from the highest severity signal.  0.0–25.0.
    pub severity_uplift: f64,
    /// Staleness penalty — reduces score for old `IoCs`.  0.0–15.0.
    pub staleness_penalty: f64,
    /// Contextual enrichment bonus (PDNS hits, WHOIS age, ASN reputation).  0.0–15.0.
    pub enrichment_bonus: f64,
    /// Manual analyst override bonus/penalty.  -10.0–10.0.
    pub analyst_override: f64,
}

impl ScoreComponents {
    #[must_use]
    pub fn total(&self) -> f64 {
        let raw = self.ioc_type_base
            + self.corroboration
            + self.severity_uplift
            - self.staleness_penalty
            + self.enrichment_bonus
            + self.analyst_override;
        // Every component is a public unvalidated `f64` (and `analyst_override`
        // is meant to be written directly), so `raw` can be NaN — from a single
        // non-finite component, or from `inf - inf` between a bonus and the
        // staleness penalty. `clamp` propagates NaN rather than bounding it, and
        // a NaN score then fails `exceeds(threshold)` for every threshold, so
        // the IoC silently drops out of every filtered result instead of
        // scoring high or low. This is also what keeps the report average
        // finite: each element it divides is bounded here.
        if raw.is_finite() {
            raw.clamp(0.0, 100.0)
        } else {
            0.0
        }
    }
}

impl std::fmt::Display for ScoreComponents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "  ioc_type_base     : {:5.2}", self.ioc_type_base)?;
        writeln!(f, "  corroboration     : {:5.2}", self.corroboration)?;
        writeln!(f, "  severity_uplift   : {:5.2}", self.severity_uplift)?;
        writeln!(f, "  staleness_penalty : {:5.2}", self.staleness_penalty)?;
        writeln!(f, "  enrichment_bonus  : {:5.2}", self.enrichment_bonus)?;
        writeln!(f, "  analyst_override  : {:5.2}", self.analyst_override)?;
        writeln!(f, "  TOTAL             : {:5.2}", self.total())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ThreatScore
// ─────────────────────────────────────────────────────────────────────────────

/// A scored threat assessment for an `IoC` or report.
#[derive(Debug, Clone)]
pub struct ThreatScore {
    /// Normalised score in [0.0, 100.0].
    pub score: f64,
    /// Human-readable label derived from the score.
    pub label: ScoreLabel,
    /// Breakdown of how the score was computed.
    pub components: ScoreComponents,
    /// The subject value (`IoC` value or report title).
    pub subject: String,
}

impl ThreatScore {
    #[must_use]
    pub fn new(subject: impl Into<String>, components: ScoreComponents) -> Self {
        let score = components.total();
        let label = ScoreLabel::from_score(score);
        Self {
            score,
            label,
            components,
            subject: subject.into(),
        }
    }

    /// Whether this score exceeds a given threshold.
    #[must_use]
    pub fn exceeds(&self, threshold: f64) -> bool {
        self.score >= threshold
    }
}

impl std::fmt::Display for ThreatScore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{:?}] {:.1}/100 — {}",
            self.label, self.score, self.subject
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ScoreLabel
// ─────────────────────────────────────────────────────────────────────────────

/// Categorical risk band corresponding to a numeric score.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScoreLabel {
    /// 0–19: no significant threat signal.
    Benign,
    /// 20–39: weak/unconfirmed signal.
    Low,
    /// 40–59: moderate confidence threat.
    Medium,
    /// 60–79: high confidence threat.
    High,
    /// 80–100: critical / confirmed threat.
    Critical,
}

impl ScoreLabel {
    #[must_use]
    pub fn from_score(s: f64) -> Self {
        match crate::casts::f64_to_u32_sat(s) {
            0..=19 => Self::Benign,
            20..=39 => Self::Low,
            40..=59 => Self::Medium,
            60..=79 => Self::High,
            _ => Self::Critical,
        }
    }
}

impl std::fmt::Display for ScoreLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ScoringWeights
// ─────────────────────────────────────────────────────────────────────────────

/// Configurable weights for each scoring dimension.
#[derive(Debug, Clone)]
pub struct ScoringWeights {
    /// Multiplier applied to the `ioc_type` base score.  Default 1.0.
    pub ioc_type_weight: f64,
    /// Multiplier applied to the corroboration score.  Default 1.0.
    pub corroboration_weight: f64,
    /// Multiplier applied to severity uplift.  Default 1.0.
    pub severity_weight: f64,
    /// Multiplier applied to staleness penalty.  Default 1.0.
    pub staleness_weight: f64,
    /// Multiplier applied to enrichment bonus.  Default 1.0.
    pub enrichment_weight: f64,
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            ioc_type_weight: 1.0,
            corroboration_weight: 1.0,
            severity_weight: 1.0,
            staleness_weight: 1.0,
            enrichment_weight: 1.0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ThreatScoreCalculator
// ─────────────────────────────────────────────────────────────────────────────

/// Computes [`ThreatScore`] objects for `IoCs` and threat reports.
pub struct ThreatScoreCalculator {
    weights: ScoringWeights,
    /// Custom per-IoC-type base scores.  Overrides the built-in table.
    custom_type_bases: HashMap<IoCType, f64>,
    /// Days after which an `IoC` is considered stale for penalty calculation.
    staleness_threshold_days: u64,
}

impl ThreatScoreCalculator {
    #[must_use]
    pub fn new() -> Self {
        Self {
            weights: ScoringWeights::default(),
            custom_type_bases: HashMap::new(),
            staleness_threshold_days: 90,
        }
    }

    #[must_use]
    pub const fn with_weights(mut self, w: ScoringWeights) -> Self {
        self.weights = w;
        self
    }

    pub const fn set_staleness_threshold(&mut self, days: u64) {
        self.staleness_threshold_days = days;
    }

    pub fn set_custom_type_base(&mut self, ioc_type: IoCType, base: f64) {
        self.custom_type_bases.insert(ioc_type, base.clamp(0.0, 25.0));
    }

    // ── core scoring ─────────────────────────────────────────────────────────

    /// Compute a threat score for a single `IoC`.
    ///
    /// `report_count` — number of distinct reports corroborating this `IoC`.
    /// `age_days` — how many days old the first-seen date is.
    /// `severity` — optional severity from the contributing reports.
    /// `enrichment_hits` — number of positive enrichment data points (PDNS, WHOIS, etc.)
    #[must_use]
    pub fn compute_score(
        &self,
        ioc: &IoC,
        report_count: usize,
        age_days: u64,
        severity: Option<Severity>,
        enrichment_hits: usize,
    ) -> ThreatScore {
        let comps = ScoreComponents {
            // 1. IoC type base
            ioc_type_base: self.type_base_score(&ioc.ioc_type) * self.weights.ioc_type_weight,
            // 2. Corroboration bonus
            corroboration: Self::corroboration_score(report_count) * self.weights.corroboration_weight,
            // 3. Severity uplift
            severity_uplift: Self::severity_score(severity) * self.weights.severity_weight,
            // 4. Staleness penalty
            staleness_penalty: self.staleness_penalty(age_days) * self.weights.staleness_weight,
            // 5. Enrichment bonus
            enrichment_bonus: Self::enrichment_score(enrichment_hits) * self.weights.enrichment_weight,
            ..ScoreComponents::default()
        };

        ThreatScore::new(ioc.value.clone(), comps)
    }

    /// Compute an aggregate score for an entire threat report.
    ///
    /// The report score is the weighted average of its `IoC` scores, capped by
    /// severity and number of `IoCs`.
    #[must_use]
    pub fn compute_report_score(&self, report: &ThreatReport) -> ThreatScore {
        if report.iocs.is_empty() {
            let comps = ScoreComponents::default();
            return ThreatScore::new(report.title.clone(), comps);
        }

        // Derive the maximum severity from the report's IoCs (ThreatReport has no severity field).
        let max_severity: Option<Severity> = report
            .iocs
            .iter()
            .map(|ioc| ioc.severity)
            .max();

        let per_ioc: Vec<ThreatScore> = report
            .iocs
            .iter()
            .map(|ioc| {
                self.compute_score(ioc, 1, 0, Some(ioc.severity), 0)
            })
            .collect();

        let avg_score = per_ioc.iter().map(|s| s.score).sum::<f64>() / crate::casts::usize_to_f64(per_ioc.len());
        let max_score = per_ioc.iter().map(|s| s.score).fold(0.0f64, f64::max);

        // Blend: 60% max, 40% average — a single critical IoC should pull the report up.
        let blended = 0.6f64.mul_add(max_score, 0.4 * avg_score);

        let comps = ScoreComponents {
            ioc_type_base: blended,
            corroboration: (crate::casts::usize_to_f64(report.iocs.len()) * 0.5).clamp(0.0, 10.0),
            severity_uplift: Self::severity_score(max_severity),
            ..ScoreComponents::default()
        };

        ThreatScore::new(report.title.clone(), comps)
    }

    /// Score a batch of `IoCs` and return them sorted by descending score.
    #[must_use]
    pub fn batch_score_iocs(&self, iocs: &[IoC]) -> Vec<ThreatScore> {
        let mut scores: Vec<ThreatScore> = iocs
            .iter()
            .map(|ioc| self.compute_score(ioc, 1, 0, None, 0))
            .collect();
        scores.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        scores
    }

    /// Return the average score across a batch.
    #[must_use]
    pub fn average_score(&self, iocs: &[IoC]) -> f64 {
        if iocs.is_empty() {
            return 0.0;
        }
        let sum: f64 = iocs
            .iter()
            .map(|i| self.compute_score(i, 1, 0, None, 0).score)
            .sum();
        sum / crate::casts::usize_to_f64(iocs.len())
    }

    /// Filter `IoCs` whose score meets or exceeds `threshold`.
    #[must_use]
    pub fn filter_by_score<'a>(&self, iocs: &'a [IoC], threshold: f64) -> Vec<(&'a IoC, ThreatScore)> {
        iocs.iter()
            .filter_map(|ioc| {
                let s = self.compute_score(ioc, 1, 0, None, 0);
                if s.score >= threshold { Some((ioc, s)) } else { None }
            })
            .collect()
    }

    // ── scoring helpers ───────────────────────────────────────────────────────

    fn type_base_score(&self, t: &IoCType) -> f64 {
        if let Some(&custom) = self.custom_type_bases.get(t) {
            return custom;
        }
        match t {
            IoCType::Ip => 15.0,
            IoCType::Domain => 12.0,
            IoCType::Url => 14.0,
            IoCType::Sha256 | IoCType::Sha512 => 20.0,
            IoCType::Md5 | IoCType::Sha1 => 18.0,
            IoCType::Email => 8.0,
            IoCType::Filename => 10.0,
            IoCType::Registry => 13.0,
            IoCType::Mutex => 9.0,
            IoCType::Yara => 5.0,
        }
    }

    fn corroboration_score(report_count: usize) -> f64 {
        // Logarithmic growth, max 20.0
        if report_count == 0 {
            return 0.0;
        }
        crate::casts::usize_to_f64(report_count).ln().mul_add(7.0, 5.0)
    }

    const fn severity_score(severity: Option<Severity>) -> f64 {
        match severity {
            None => 0.0,
            Some(Severity::Low) => 8.0,
            Some(Severity::Medium) => 15.0,
            Some(Severity::High) => 20.0,
            Some(Severity::Critical) => 25.0,
        }
    }

    fn staleness_penalty(&self, age_days: u64) -> f64 {
        if age_days <= self.staleness_threshold_days {
            return 0.0;
        }
        let excess = age_days - self.staleness_threshold_days;
        // Linear penalty up to 15 over 365 days
        (crate::casts::u64_to_f64(excess) / 365.0 * 15.0).clamp(0.0, 15.0)
    }

    fn enrichment_score(hits: usize) -> f64 {
        // Up to 15 points
        (crate::casts::usize_to_f64(hits) * 3.0).clamp(0.0, 15.0)
    }
}

impl Default for ThreatScoreCalculator {
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

    fn ip_ioc() -> IoC {
        IoC::new(IoCType::Ip, "1.2.3.4".into(), "test".into())
    }

    fn sha256_ioc() -> IoC {
        IoC::new(IoCType::Sha256, "abc123".into(), "test".into())
    }

    fn calc() -> ThreatScoreCalculator {
        ThreatScoreCalculator::new()
    }

    #[test]
    fn test_score_ip_basic() {
        let s = calc().compute_score(&ip_ioc(), 1, 0, None, 0);
        assert!(s.score > 0.0);
    }

    #[test]
    fn test_sha256_higher_base_than_ip() {
        let c = calc();
        let s_sha = c.compute_score(&sha256_ioc(), 1, 0, None, 0).score;
        let s_ip  = c.compute_score(&ip_ioc(), 1, 0, None, 0).score;
        assert!(s_sha > s_ip);
    }

    #[test]
    fn test_corroboration_raises_score() {
        let c = calc();
        let s1 = c.compute_score(&ip_ioc(), 1,  0, None, 0).score;
        let s5 = c.compute_score(&ip_ioc(), 10, 0, None, 0).score;
        assert!(s5 > s1);
    }

    #[test]
    fn test_severity_raises_score() {
        let c = calc();
        let s_none = c.compute_score(&ip_ioc(), 1, 0, None, 0).score;
        let s_crit = c.compute_score(&ip_ioc(), 1, 0, Some(Severity::Critical), 0).score;
        assert!(s_crit > s_none);
    }

    #[test]
    fn test_staleness_penalty() {
        let c = calc();
        let s_fresh = c.compute_score(&ip_ioc(), 1, 0, None, 0).score;
        let s_old   = c.compute_score(&ip_ioc(), 1, 500, None, 0).score;
        assert!(s_old < s_fresh);
    }

    #[test]
    fn test_enrichment_bonus() {
        let c = calc();
        let s_no  = c.compute_score(&ip_ioc(), 1, 0, None, 0).score;
        let s_yes = c.compute_score(&ip_ioc(), 1, 0, None, 5).score;
        assert!(s_yes > s_no);
    }

    #[test]
    fn test_score_clamped_to_100() {
        let c = calc();
        let s = c.compute_score(&sha256_ioc(), 1000, 0, Some(Severity::Critical), 1000).score;
        assert!(s <= 100.0);
    }

    #[test]
    fn test_score_label_from_score() {
        assert_eq!(ScoreLabel::from_score(10.0), ScoreLabel::Benign);
        assert_eq!(ScoreLabel::from_score(30.0), ScoreLabel::Low);
        assert_eq!(ScoreLabel::from_score(50.0), ScoreLabel::Medium);
        assert_eq!(ScoreLabel::from_score(70.0), ScoreLabel::High);
        assert_eq!(ScoreLabel::from_score(90.0), ScoreLabel::Critical);
    }

    #[test]
    fn test_threat_score_display() {
        let comps = ScoreComponents { ioc_type_base: 50.0, ..Default::default() };
        let s = ThreatScore::new("evil.com", comps);
        let d = s.to_string();
        assert!(d.contains("evil.com"));
        assert!(d.contains("/100"));
    }

    #[test]
    fn test_score_components_total() {
        let comps = ScoreComponents {
            ioc_type_base: 20.0,
            corroboration: 10.0,
            severity_uplift: 15.0,
            staleness_penalty: 5.0,
            enrichment_bonus: 5.0,
            analyst_override: -2.0,
        };
        let total = comps.total();
        assert!((total - 43.0).abs() < 0.01);
    }

    #[test]
    fn test_score_components_display() {
        let c = ScoreComponents { ioc_type_base: 15.0, ..Default::default() };
        let s = c.to_string();
        assert!(s.contains("TOTAL"));
    }

    #[test]
    fn test_batch_score_sorted() {
        let c = calc();
        let iocs = vec![ip_ioc(), sha256_ioc()];
        let scores = c.batch_score_iocs(&iocs);
        assert_eq!(scores.len(), 2);
        assert!(scores[0].score >= scores[1].score);
    }

    #[test]
    fn test_average_score_empty() {
        let c = calc();
        assert!((c.average_score(&[]) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_filter_by_score() {
        let c = calc();
        let iocs = vec![ip_ioc()];
        let filtered = c.filter_by_score(&iocs, 0.0);
        assert_eq!(filtered.len(), 1);
        let none = c.filter_by_score(&iocs, 200.0);
        assert_eq!(none.len(), 0);
    }

    #[test]
    fn test_custom_type_base() {
        let mut c = calc();
        c.set_custom_type_base(IoCType::Ip, 25.0);
        let s = c.compute_score(&ip_ioc(), 1, 0, None, 0).score;
        assert!(s >= 25.0);
    }

    #[test]
    fn test_compute_report_score() {
        let c = calc();
        let mut r = ThreatReport::new("R1".into(), "analyst".into());
        r.add_ioc(ip_ioc());
        r.add_ioc(sha256_ioc());
        let s = c.compute_report_score(&r);
        assert!(s.score > 0.0);
    }

    #[test]
    fn test_compute_report_score_empty() {
        let c = calc();
        let r = ThreatReport::new("Empty".into(), "analyst".into());
        let s = c.compute_report_score(&r);
        assert!((s.score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_scoring_weights() {
        let w = ScoringWeights { ioc_type_weight: 2.0, ..Default::default() };
        let c = ThreatScoreCalculator::new().with_weights(w);
        let s1 = calc().compute_score(&ip_ioc(), 1, 0, None, 0).score;
        let s2 = c.compute_score(&ip_ioc(), 1, 0, None, 0).score;
        assert!(s2 > s1);
    }

    #[test]
    fn test_exceeds() {
        let comps = ScoreComponents { ioc_type_base: 80.0, ..Default::default() };
        let s = ThreatScore::new("test", comps);
        assert!(s.exceeds(50.0));
        assert!(!s.exceeds(90.0));
    }
}
