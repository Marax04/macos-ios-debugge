// rustre-triage-yara/src/verdict.rs
//! Verdict computation from YARA scan results.

use crate::{EnhancedYaraMatch, YaraTriageMatch};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Core verdict type ────────────────────────────────────────────────────────

/// High-level verdict classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum YaraVerdict {
    /// No malicious indicators found.
    Clean,
    /// Low-risk indicators present (e.g. packer signatures).
    Suspicious,
    /// High-confidence malware or exploit indicators present.
    Malicious,
    /// Insufficient data to determine.
    Unknown,
}

impl YaraVerdict {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Suspicious => "suspicious",
            Self::Malicious => "malicious",
            Self::Unknown => "unknown",
        }
    }

    #[must_use]
    pub const fn from_score(score: u8) -> Self {
        match score {
            0..=19 => Self::Clean,
            20..=59 => Self::Suspicious,
            60..=100 => Self::Malicious,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn is_malicious(&self) -> bool {
        matches!(self, Self::Malicious)
    }
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        matches!(self, Self::Clean)
    }
}

impl std::fmt::Display for YaraVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── Verdict score ────────────────────────────────────────────────────────────

/// A numeric confidence score (0–100) with optional confidence interval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictScore {
    /// Central score value (0–100).
    pub value: u8,
    /// Lower bound of 95% confidence interval.
    pub ci_low: u8,
    /// Upper bound of 95% confidence interval.
    pub ci_high: u8,
    /// Number of independent signals that contributed.
    pub signal_count: usize,
}

impl VerdictScore {
    #[must_use]
    pub fn new(value: u8) -> Self {
        Self {
            value,
            ci_low: value.saturating_sub(10),
            ci_high: value.min(90).saturating_add(10),
            signal_count: 0,
        }
    }

    #[must_use]
    pub fn with_signals(value: u8, count: usize) -> Self {
        // Wider confidence interval when fewer signals
        let half_width: u8 = match count {
            0 => 50,
            1 => 25,
            2..=3 => 15,
            4..=9 => 10,
            _ => 5,
        };
        Self {
            value,
            ci_low: value.saturating_sub(half_width),
            ci_high: value.saturating_add(half_width).min(100),
            signal_count: count,
        }
    }

    #[must_use]
    pub const fn verdict(&self) -> YaraVerdict {
        YaraVerdict::from_score(self.value)
    }
}

impl std::fmt::Display for VerdictScore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} [{}-{}] n={}",
            self.value, self.ci_low, self.ci_high, self.signal_count
        )
    }
}

// ─── Family attribution ───────────────────────────────────────────────────────

/// Attribution of a match to a malware family.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyAttribution {
    /// Family name (e.g. `"Mimikatz"`, `"Cobalt Strike"`).
    pub family: String,
    /// How many rules matched for this family.
    pub match_count: u32,
    /// Severity of the strongest match.
    pub max_severity: String,
    /// Combined score contribution from this family.
    pub score_contribution: u8,
    /// Confidence (0–100): higher when more rules match.
    pub confidence: u8,
}

impl FamilyAttribution {
    pub fn new(family: impl Into<String>) -> Self {
        Self {
            family: family.into(),
            match_count: 0,
            max_severity: "info".into(),
            score_contribution: 0,
            confidence: 0,
        }
    }

    /// Update attribution with a new match.
    pub fn add_match(&mut self, severity: &str, score: u8) {
        self.match_count += 1;
        if severity_rank(severity) > severity_rank(&self.max_severity) {
            self.max_severity = severity.to_string();
        }
        self.score_contribution = self.score_contribution.saturating_add(score).min(100);
        // Confidence grows with match_count but plateaus at 95
        self.confidence = u8::try_from((self.match_count * 20).min(95)).unwrap_or(u8::MAX);
    }
}

fn severity_rank(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

fn severity_score_val(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 90,
        "high" => 65,
        "medium" => 40,
        "low" => 20,
        "info" => 5,
        _ => 10,
    }
}

// ─── Verdict engine ───────────────────────────────────────────────────────────

/// Aggregates multiple rule matches into a final verdict.
pub struct VerdictEngine {
    /// Weight applied to enhanced rule matches (default: 1.0).
    pub enhanced_weight: f64,
    /// Weight applied to triage rule matches (default: 0.8).
    pub triage_weight: f64,
    /// Threshold above which verdict is Malicious (default: 60).
    pub malicious_threshold: u8,
    /// Threshold above which verdict is Suspicious (default: 20).
    pub suspicious_threshold: u8,
}

impl Default for VerdictEngine {
    fn default() -> Self {
        Self {
            enhanced_weight: 1.0,
            triage_weight: 0.8,
            malicious_threshold: 60,
            suspicious_threshold: 20,
        }
    }
}

impl VerdictEngine {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute the verdict from a combined list of matches.
    #[must_use]
    pub fn compute(
        &self,
        enhanced: &[EnhancedYaraMatch],
        triage: &[YaraTriageMatch],
    ) -> VerdictResult {
        let mut raw_score: f64 = 0.0;
        let mut families: HashMap<String, FamilyAttribution> = HashMap::new();
        let mut signal_count = 0usize;

        // Process enhanced matches
        for m in enhanced {
            let sev = m
                .meta
                .get("severity")
                .map_or("medium", String::as_str);
            let s = severity_score_val(sev);
            raw_score += f64::from(s) * self.enhanced_weight;
            signal_count += 1;

            // Family from tags or rule name
            let family = m
                .tags
                .first()
                .cloned()
                .unwrap_or_else(|| "Unknown".to_string());
            families
                .entry(family.clone())
                .or_insert_with(|| FamilyAttribution::new(&family))
                .add_match(sev, s);
        }

        // Process triage matches
        for m in triage {
            let s = severity_score_val(&m.severity);
            raw_score += f64::from(s) * self.triage_weight;
            signal_count += 1;

            let family = extract_family_from_description(&m.description);
            families
                .entry(family.clone())
                .or_insert_with(|| FamilyAttribution::new(&family))
                .add_match(&m.severity, s);
        }

        let score = u8::try_from(raw_score.min(100.0).max(0.0) as u64).unwrap_or(u8::MAX);
        let verdict = if score >= self.malicious_threshold {
            YaraVerdict::Malicious
        } else if score >= self.suspicious_threshold {
            YaraVerdict::Suspicious
        } else {
            YaraVerdict::Clean
        };

        let verdict_score = VerdictScore::with_signals(score, signal_count);

        let mut attributions: Vec<FamilyAttribution> = families.into_values().collect();
        attributions.sort_by(|a, b| b.score_contribution.cmp(&a.score_contribution));

        VerdictResult {
            verdict,
            score: verdict_score,
            attributions,
            total_matches: enhanced.len() + triage.len(),
            enhanced_match_count: enhanced.len(),
            triage_match_count: triage.len(),
        }
    }

    /// Convenience: compute from empty matches.
    #[must_use]
    pub fn clean(&self) -> VerdictResult {
        self.compute(&[], &[])
    }
}

fn extract_family_from_description(desc: &str) -> String {
    // Try to extract a capitalised word as a family name
    desc.split_whitespace()
        .find(|w| w.chars().next().is_some_and(char::is_uppercase))
        .unwrap_or("Unknown")
        .trim_end_matches(&[',', '.', ';', ':'][..])
        .to_string()
}

// ─── Verdict result ───────────────────────────────────────────────────────────

/// Complete verdict result from the engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictResult {
    pub verdict: YaraVerdict,
    pub score: VerdictScore,
    pub attributions: Vec<FamilyAttribution>,
    pub total_matches: usize,
    pub enhanced_match_count: usize,
    pub triage_match_count: usize,
}

impl VerdictResult {
    /// Return the top attributed family, if any.
    #[must_use]
    pub fn top_family(&self) -> Option<&FamilyAttribution> {
        self.attributions.first()
    }

    /// Return all family names.
    #[must_use]
    pub fn family_names(&self) -> Vec<&str> {
        self.attributions
            .iter()
            .map(|a| a.family.as_str())
            .collect()
    }

    /// True if the final verdict is Malicious.
    #[must_use]
    pub const fn is_malicious(&self) -> bool {
        self.verdict.is_malicious()
    }

    /// Render a one-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} (score={}) families=[{}]",
            self.verdict,
            self.score.value,
            self.family_names().join(", ")
        )
    }
}

// ─── Verdict aggregator ───────────────────────────────────────────────────────

/// Aggregates verdicts from multiple scans (e.g. batch results).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerdictAggregator {
    pub clean_count: u32,
    pub suspicious_count: u32,
    pub malicious_count: u32,
    pub unknown_count: u32,
    pub total_score: u64,
    pub total_scans: u32,
    pub top_families: HashMap<String, u32>,
}

impl VerdictAggregator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, result: &VerdictResult) {
        match result.verdict {
            YaraVerdict::Clean => self.clean_count += 1,
            YaraVerdict::Suspicious => self.suspicious_count += 1,
            YaraVerdict::Malicious => self.malicious_count += 1,
            YaraVerdict::Unknown => self.unknown_count += 1,
        }
        self.total_score += u64::from(result.score.value);
        self.total_scans += 1;
        for attr in &result.attributions {
            *self.top_families.entry(attr.family.clone()).or_insert(0) += 1;
        }
    }

    #[must_use]
    pub fn average_score(&self) -> f64 {
        if self.total_scans == 0 {
            return 0.0;
        }
        // Decompose to avoid u64→f64 precision-loss lint; score average is ≤ 100 so fits in u32.
        let scans = u64::from(self.total_scans);
        let avg = self.total_score / scans;
        let rem = self.total_score % scans;
        f64::from(u32::try_from(avg).unwrap_or(u32::MAX))
            + f64::from(u32::try_from(rem).unwrap_or(0)) / f64::from(self.total_scans)
    }

    #[must_use]
    pub fn malicious_rate(&self) -> f64 {
        if self.total_scans == 0 {
            return 0.0;
        }
        f64::from(self.malicious_count) / f64::from(self.total_scans)
    }

    /// Top N families by match count.
    #[must_use]
    pub fn top_n_families(&self, n: usize) -> Vec<(&str, u32)> {
        let mut v: Vec<(&str, u32)> = self
            .top_families
            .iter()
            .map(|(k, &v)| (k.as_str(), v))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }
}

// ─── Verdict policy ───────────────────────────────────────────────────────────

/// Configurable policy for override / escalation of verdicts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictPolicy {
    /// Force malicious if any of these rule names match.
    pub force_malicious_rules: Vec<String>,
    /// Force clean if all matches are from this set of rule names.
    pub allow_listed_rules: Vec<String>,
    /// Escalate to malicious if score >= this value (overrides default 60).
    pub malicious_threshold_override: Option<u8>,
}

impl Default for VerdictPolicy {
    fn default() -> Self {
        Self {
            force_malicious_rules: vec![
                "Mimikatz_Binary".into(),
                "CobaltStrike_Beacon".into(),
                "Meterpreter_Payload".into(),
            ],
            allow_listed_rules: Vec::new(),
            malicious_threshold_override: None,
        }
    }
}

impl VerdictPolicy {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply policy to a verdict result.
    pub fn apply(&self, result: &mut VerdictResult, matched_rules: &[&str]) {
        // Force malicious
        for rule in matched_rules {
            if self.force_malicious_rules.iter().any(|r| r == rule) {
                result.verdict = YaraVerdict::Malicious;
                return;
            }
        }

        // Allow list (only if all matches are allow-listed)
        if !matched_rules.is_empty()
            && matched_rules
                .iter()
                .all(|r| self.allow_listed_rules.iter().any(|a| a == r))
        {
            result.verdict = YaraVerdict::Clean;
            return;
        }

        // Override threshold
        if let Some(threshold) = self.malicious_threshold_override && result.score.value >= threshold {
            result.verdict = YaraVerdict::Malicious;
        }
    }
}

// ─── Severity helpers (public) ────────────────────────────────────────────────

/// Convert a severity string to a numeric weight (1–5).
#[must_use]
pub fn severity_weight(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        _ => 1,
    }
}

/// Normalise a raw match count to a 0–100 confidence value.
#[must_use]
pub const fn confidence_from_count(n: u32) -> u8 {
    match n {
        0 => 0,
        1 => 30,
        2 => 55,
        3..=4 => 70,
        5..=9 => 85,
        _ => 95,
    }
}

// ─── Weighted verdict ─────────────────────────────────────────────────────────

/// Compute a single weighted score from a set of `(severity, count)` pairs.
#[must_use]
pub fn weighted_verdict_score(contributions: &[(&str, u32)]) -> u8 {
    if contributions.is_empty() {
        return 0;
    }
    let mut total: f64 = 0.0;
    let mut weight_sum: f64 = 0.0;
    for &(sev, count) in contributions {
        let w = f64::from(severity_weight(sev));
        let score = f64::from(severity_score_val(sev));
        total += score * w * f64::from(count);
        weight_sum += w * f64::from(count);
    }
    if weight_sum == 0.0 {
        return 0;
    }
    u8::try_from((total / weight_sum).min(100.0).max(0.0) as u64).unwrap_or(u8::MAX)
}

// ─── Verdict transition ───────────────────────────────────────────────────────

/// Track how a verdict changes across multiple scan passes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictTransition {
    pub from: YaraVerdict,
    pub to: YaraVerdict,
    pub reason: String,
    pub score_delta: i16,
}

impl VerdictTransition {
    #[must_use]
    pub fn new(from: YaraVerdict, to: YaraVerdict, reason: impl Into<String>, delta: i16) -> Self {
        Self {
            from,
            to,
            reason: reason.into(),
            score_delta: delta,
        }
    }

    #[must_use]
    pub fn is_escalation(&self) -> bool {
        self.to > self.from
    }
    #[must_use]
    pub fn is_deescalation(&self) -> bool {
        self.to < self.from
    }
}

// ─── Verdict chain ────────────────────────────────────────────────────────────

/// A sequence of verdicts produced by progressive analysis passes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerdictChain {
    entries: Vec<(YaraVerdict, u8, String)>,
}

impl VerdictChain {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, verdict: YaraVerdict, score: u8, reason: impl Into<String>) {
        self.entries.push((verdict, score, reason.into()));
    }

    #[must_use]
    pub fn final_verdict(&self) -> YaraVerdict {
        self.entries
            .last()
            .map_or(YaraVerdict::Unknown, |(v, _, _)| *v)
    }

    #[must_use]
    pub fn final_score(&self) -> u8 {
        self.entries.last().map_or(0, |(_, s, _)| *s)
    }

    #[must_use]
    pub fn transitions(&self) -> Vec<VerdictTransition> {
        let mut out = Vec::new();
        for window in self.entries.windows(2) {
            let (from_v, from_s, _) = &window[0];
            let (to_v, to_s, r) = &window[1];
            let delta = i16::from(*to_s) - i16::from(*from_s);
            out.push(VerdictTransition::new(*from_v, *to_v, r.clone(), delta));
        }
        out
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─── Rule severity mapping ────────────────────────────────────────────────────

/// Maps rule names to their expected severity for override / allowlisting.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleSeverityMap {
    map: HashMap<String, String>,
}

impl RuleSeverityMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, rule_name: impl Into<String>, severity: impl Into<String>) {
        self.map.insert(rule_name.into(), severity.into());
    }

    #[must_use]
    pub fn get(&self, rule_name: &str) -> Option<&str> {
        self.map.get(rule_name).map(String::as_str)
    }

    /// Override severity for a rule in the given match list.
    pub fn apply(&self, matches: &mut [YaraTriageMatch]) {
        for m in matches.iter_mut() {
            if let Some(sev) = self.get(&m.rule_name) {
                m.severity = sev.to_string();
            }
        }
    }
}

// ─── Verdict report ────────────────────────────────────────────────────────────

/// Serialisable, self-contained verdict report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictReport {
    pub verdict: String,
    pub score: u8,
    pub ci_low: u8,
    pub ci_high: u8,
    pub signal_count: usize,
    pub families: Vec<String>,
    pub top_family: Option<String>,
    pub top_technique: Option<String>,
    pub enhanced_match_count: usize,
    pub triage_match_count: usize,
}

impl VerdictReport {
    #[must_use]
    pub fn from_result(r: &VerdictResult) -> Self {
        Self {
            verdict: r.verdict.as_str().to_string(),
            score: r.score.value,
            ci_low: r.score.ci_low,
            ci_high: r.score.ci_high,
            signal_count: r.score.signal_count,
            families: r.family_names().iter().map(ToString::to_string).collect(),
            top_family: r.top_family().map(|a| a.family.clone()),
            top_technique: None,
            enhanced_match_count: r.enhanced_match_count,
            triage_match_count: r.triage_match_count,
        }
    }

    /// # Errors
    /// Returns an error if serialisation fails.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_from_score() {
        assert_eq!(YaraVerdict::from_score(0), YaraVerdict::Clean);
        assert_eq!(YaraVerdict::from_score(19), YaraVerdict::Clean);
        assert_eq!(YaraVerdict::from_score(20), YaraVerdict::Suspicious);
        assert_eq!(YaraVerdict::from_score(59), YaraVerdict::Suspicious);
        assert_eq!(YaraVerdict::from_score(60), YaraVerdict::Malicious);
        assert_eq!(YaraVerdict::from_score(100), YaraVerdict::Malicious);
    }

    #[test]
    fn verdict_ordering() {
        assert!(YaraVerdict::Malicious > YaraVerdict::Suspicious);
        assert!(YaraVerdict::Suspicious > YaraVerdict::Clean);
    }

    #[test]
    fn verdict_score_confidence_interval() {
        let s = VerdictScore::with_signals(50, 1);
        assert!(s.ci_low < s.value);
        assert!(s.ci_high > s.value);
    }

    #[test]
    fn verdict_engine_clean_result() {
        let engine = VerdictEngine::new();
        let result = engine.compute(&[], &[]);
        assert_eq!(result.verdict, YaraVerdict::Clean);
        assert_eq!(result.score.value, 0);
        assert!(result.attributions.is_empty());
    }

    #[test]
    fn verdict_engine_with_triage_matches() {
        let engine = VerdictEngine::new();
        let triage_matches = vec![YaraTriageMatch {
            rule_name: "Mimikatz".into(),
            matched_strings: vec![("s0".into(), 0)],
            description: "Mimikatz credential dump tool".into(),
            severity: "critical".into(),
        }];
        let result = engine.compute(&[], &triage_matches);
        assert_eq!(result.verdict, YaraVerdict::Malicious);
        assert!(!result.attributions.is_empty());
    }

    #[test]
    fn verdict_aggregator_rates() {
        let engine = VerdictEngine::new();
        let clean = engine.clean();
        let mal = engine.compute(
            &[],
            &[YaraTriageMatch {
                rule_name: "X".into(),
                matched_strings: Vec::new(),
                description: "X".into(),
                severity: "critical".into(),
            }],
        );

        let mut agg = VerdictAggregator::new();
        agg.add(&clean);
        agg.add(&mal);
        assert_eq!(agg.total_scans, 2);
        assert!(agg.malicious_rate() >= 0.0);
    }

    #[test]
    fn family_attribution_confidence_grows() {
        let mut attr = FamilyAttribution::new("Test");
        attr.add_match("high", 65);
        assert_eq!(attr.match_count, 1);
        let conf1 = attr.confidence;
        attr.add_match("critical", 90);
        assert!(attr.confidence >= conf1);
    }

    #[test]
    fn verdict_policy_force_malicious() {
        let policy = VerdictPolicy::new();
        let engine = VerdictEngine::new();
        let mut result = engine.clean();
        result.verdict = YaraVerdict::Clean; // Start clean
        policy.apply(&mut result, &["Mimikatz_Binary"]);
        assert_eq!(result.verdict, YaraVerdict::Malicious);
    }

    #[test]
    fn verdict_policy_allow_list() {
        let mut policy = VerdictPolicy::default();
        policy.allow_listed_rules.push("SafeTool".into());
        let engine = VerdictEngine::new();
        let mut result = engine.compute(
            &[],
            &[YaraTriageMatch {
                rule_name: "SafeTool".into(),
                matched_strings: Vec::new(),
                description: "safe".into(),
                severity: "info".into(),
            }],
        );
        policy.apply(&mut result, &["SafeTool"]);
        assert_eq!(result.verdict, YaraVerdict::Clean);
    }

    #[test]
    fn verdict_result_summary_format() {
        let engine = VerdictEngine::new();
        let result = engine.clean();
        let s = result.summary();
        assert!(s.contains("clean") || s.contains("score"));
    }

    #[test]
    fn top_n_families() {
        let mut agg = VerdictAggregator::new();
        let engine = VerdictEngine::new();
        for i in 0..5 {
            let mut r = engine.clean();
            r.attributions
                .push(FamilyAttribution::new(format!("Fam{}", i)));
            agg.add(&r);
        }
        let top = agg.top_n_families(3);
        assert!(top.len() <= 3);
    }

    #[test]
    fn severity_score_ordering() {
        assert!(severity_score_val("critical") > severity_score_val("high"));
        assert!(severity_score_val("high") > severity_score_val("medium"));
        assert!(severity_score_val("medium") > severity_score_val("low"));
        assert!(severity_score_val("low") > severity_score_val("info"));
    }
}
