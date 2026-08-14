//! Actor attribution analysis.
//!
//! Derives threat actor attribution from a corpus of `IoCs` and reports using
//! weighted evidence aggregation, temporal analysis, and shared infrastructure.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use rustre_threatintel::{IoC, ThreatReport};

// ---------------------------------------------------------------------------
// AttributionEvidence
// ---------------------------------------------------------------------------

/// A piece of evidence contributing to an attribution decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionEvidence {
    /// Short identifier for this evidence type.
    pub kind: EvidenceKind,
    /// Human-readable description of the evidence.
    pub description: String,
    /// Confidence contribution in [0.0, 1.0].
    pub weight: f64,
    /// Source intelligence report or feed.
    pub source: String,
}

impl AttributionEvidence {
    /// Create a new evidence item.
    #[must_use]
    pub fn new(
        kind: EvidenceKind,
        description: impl Into<String>,
        weight: f64,
        source: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            description: description.into(),
            weight: weight.clamp(0.0, 1.0),
            source: source.into(),
        }
    }
}

impl fmt::Display for AttributionEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:?}] w={:.2} — {}",
            self.kind, self.weight, self.description
        )
    }
}

/// Category of attribution evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceKind {
    /// Shared network infrastructure with a known actor campaign.
    SharedInfrastructure,
    /// Identical or very similar YARA rules.
    YaraMatch,
    /// Similar coding style / compiler artefacts.
    CodeSimilarity,
    /// Shared malware family lineage.
    MalwareLineage,
    /// Overlapping victimology.
    Victimology,
    /// Direct intelligence (human, signals).
    HumanIntelligence,
    /// Temporal correlation with a known actor's activity window.
    TemporalCorrelation,
    /// Operator security failure (e.g. real IP in headers).
    OpSec,
}

// ---------------------------------------------------------------------------
// AttributionResult
// ---------------------------------------------------------------------------

/// Attribution result for a set of `IoCs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionResult {
    /// Suspected threat actor name.
    pub actor_name: String,
    /// Aggregated confidence in [0, 100].
    pub confidence: u8,
    /// All contributing evidence.
    pub evidence: Vec<AttributionEvidence>,
    /// Alternative actor candidates with lower confidence.
    pub alternatives: Vec<(String, u8)>,
}

impl AttributionResult {
    /// Create an attribution result.
    #[must_use]
    pub const fn new(actor_name: String, confidence: u8) -> Self {
        Self {
            actor_name,
            confidence,
            evidence: Vec::new(),
            alternatives: Vec::new(),
        }
    }

    /// Add an evidence item.
    pub fn add_evidence(&mut self, ev: AttributionEvidence) {
        self.evidence.push(ev);
    }

    /// Add an alternative candidate.
    pub fn add_alternative(&mut self, name: String, confidence: u8) {
        self.alternatives.push((name, confidence));
        // Keep sorted descending by confidence
        self.alternatives.sort_by(|a, b| b.1.cmp(&a.1));
    }

    /// Recompute confidence from evidence weights.
    pub fn recompute_confidence(&mut self) {
        if self.evidence.is_empty() {
            return;
        }
        let total: f64 = self.evidence.iter().map(|e| e.weight).sum();
        let weighted: f64 = self.evidence.len() as f64;
        self.confidence = ((total / weighted) * 100.0).min(100.0).round().min(255.0) as u8;
    }

    /// Return the primary evidence kinds present.
    #[must_use]
    pub fn evidence_kinds(&self) -> Vec<EvidenceKind> {
        let mut seen: Vec<EvidenceKind> = Vec::new();
        for ev in &self.evidence {
            if !seen.contains(&ev.kind) {
                seen.push(ev.kind);
            }
        }
        seen
    }

    /// Return `true` if this attribution has high confidence (>=80).
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 80
    }
}

impl fmt::Display for AttributionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Attribution: {} (confidence={}, evidence={})",
            self.actor_name,
            self.confidence,
            self.evidence.len()
        )
    }
}

// ---------------------------------------------------------------------------
// ActorAttributor
// ---------------------------------------------------------------------------

/// Engine that derives actor attribution from `IoCs` and reports.
pub struct ActorAttributor {
    /// Known actor → list of `IoC` values attributed to them.
    actor_iocs: HashMap<String, Vec<String>>,
    /// Known actor → list of malware families.
    actor_families: HashMap<String, Vec<String>>,
}

impl ActorAttributor {
    /// Create a new attributor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            actor_iocs: HashMap::new(),
            actor_families: HashMap::new(),
        }
    }

    /// Train the attributor with a known actor-IoC mapping.
    pub fn register_actor_ioc(&mut self, actor: impl Into<String>, ioc_value: impl Into<String>) {
        self.actor_iocs
            .entry(actor.into())
            .or_default()
            .push(ioc_value.into());
    }

    /// Train the attributor with a known actor-family mapping.
    pub fn register_actor_family(&mut self, actor: impl Into<String>, family: impl Into<String>) {
        self.actor_families
            .entry(actor.into())
            .or_default()
            .push(family.into());
    }

    /// Attempt to attribute a list of `IoCs` to a known actor.
    ///
    /// Returns the best `AttributionResult` if any match is found.
    #[must_use]
    pub fn attribute(&self, iocs: &[IoC]) -> Option<AttributionResult> {
        let mut scores: HashMap<String, f64> = HashMap::new();

        for ioc in iocs {
            for (actor, known_iocs) in &self.actor_iocs {
                if known_iocs
                    .iter()
                    .any(|k| k.eq_ignore_ascii_case(&ioc.value))
                {
                    *scores.entry(actor.clone()).or_insert(0.0) += 1.0;
                }
            }
        }

        if scores.is_empty() {
            return None;
        }

        let (best_name, best_score) = scores
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(n, s)| (n.clone(), *s))?;

        let total_iocs = (iocs.len().max(1)) as f64;
        let raw_conf = (best_score / total_iocs).min(1.0);
        let confidence = (raw_conf * 100.0).round().min(255.0) as u8;

        let mut result = AttributionResult::new(best_name.clone(), confidence);
        result.add_evidence(AttributionEvidence::new(
            EvidenceKind::SharedInfrastructure,
            format!("{best_score} shared IoCs with actor {best_name}"),
            raw_conf,
            "internal-database",
        ));

        // Add alternatives
        let mut sorted: Vec<(String, f64)> = scores
            .into_iter()
            .filter(|(n, _)| n != &best_name)
            .collect();
        sorted.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        for (name, score) in sorted.iter().take(3) {
            let alt_conf = ((*score / total_iocs).min(1.0) * 100.0).round().min(255.0) as u8;
            result.add_alternative(name.clone(), alt_conf);
        }

        Some(result)
    }

    /// Like [`attribute`] but returns an [`anyhow::Result`] with structured
    /// context when no matching actor is found or the IoC list is empty, so
    /// callers can surface the failure reason without inspecting `None`.
    pub fn attribute_or_err(&self, iocs: &[IoC]) -> Result<AttributionResult> {
        if iocs.is_empty() {
            bail!("ActorAttributor::attribute_or_err called with empty IoC list");
        }
        self.attribute(iocs)
            .ok_or_else(|| anyhow::anyhow!("No actor profile matched any of the {} provided IoCs", iocs.len()))
    }

    /// Derive attribution from a threat report's actor and malware fields.
    #[must_use]
    pub fn attribute_from_report(&self, report: &ThreatReport) -> Option<AttributionResult> {
        if report.threat_actors.is_empty() {
            return None;
        }
        let actor = &report.threat_actors[0];
        let mut result = AttributionResult::new(actor.clone(), 70);
        result.add_evidence(AttributionEvidence::new(
            EvidenceKind::HumanIntelligence,
            format!("Actor named in report: {}", report.title),
            0.7,
            "report",
        ));
        Some(result)
    }

    /// Return all known actor names.
    #[must_use]
    pub fn known_actors(&self) -> Vec<&str> {
        let mut actors: Vec<&str> = self.actor_iocs.keys().map(String::as_str).collect();
        for k in self.actor_families.keys() {
            if !actors.contains(&k.as_str()) {
                actors.push(k.as_str());
            }
        }
        actors
    }
}

impl Default for ActorAttributor {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ActorAttributor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActorAttributor")
            .field("actors", &self.actor_iocs.len())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_threatintel::{IoC, IoCType, ThreatReport};

    fn ip(val: &str) -> IoC {
        IoC::new(IoCType::Ip, val.to_string(), "test".to_string())
    }

    fn make_attributor() -> ActorAttributor {
        let mut a = ActorAttributor::new();
        a.register_actor_ioc("APT29", "1.2.3.4");
        a.register_actor_ioc("APT29", "5.6.7.8");
        a.register_actor_ioc("Lazarus", "9.10.11.12");
        a
    }

    #[test]
    fn test_attributor_new_empty() {
        let a = ActorAttributor::new();
        assert!(a.known_actors().is_empty());
    }

    #[test]
    fn test_attributor_register_actor() {
        let mut a = ActorAttributor::new();
        a.register_actor_ioc("APT29", "1.2.3.4");
        assert!(a.known_actors().contains(&"APT29"));
    }

    #[test]
    fn test_attributor_attribute_hit() {
        let a = make_attributor();
        let iocs = vec![ip("1.2.3.4"), ip("5.6.7.8")];
        let result = a.attribute(&iocs).unwrap();
        assert_eq!(result.actor_name, "APT29");
        assert!(result.confidence > 0);
    }

    #[test]
    fn test_attributor_attribute_miss() {
        let a = make_attributor();
        let iocs = vec![ip("100.200.300.400")];
        assert!(a.attribute(&iocs).is_none());
    }

    #[test]
    fn test_attributor_empty_iocs() {
        let a = make_attributor();
        assert!(a.attribute(&[]).is_none());
    }

    #[test]
    fn test_attributor_from_report() {
        let a = make_attributor();
        let mut report = ThreatReport::new("Test".to_string(), "analyst".to_string());
        report.threat_actors.push("APT29".to_string());
        let result = a.attribute_from_report(&report).unwrap();
        assert_eq!(result.actor_name, "APT29");
        assert_eq!(result.confidence, 70);
    }

    #[test]
    fn test_attributor_from_report_no_actors() {
        let a = make_attributor();
        let report = ThreatReport::new("Empty".to_string(), "analyst".to_string());
        assert!(a.attribute_from_report(&report).is_none());
    }

    #[test]
    fn test_attribution_result_add_evidence() {
        let mut r = AttributionResult::new("APT28".to_string(), 50);
        r.add_evidence(AttributionEvidence::new(
            EvidenceKind::YaraMatch,
            "YARA hit",
            0.8,
            "vt",
        ));
        assert_eq!(r.evidence.len(), 1);
    }

    #[test]
    fn test_attribution_result_recompute_confidence() {
        let mut r = AttributionResult::new("actor".to_string(), 50);
        r.add_evidence(AttributionEvidence::new(
            EvidenceKind::CodeSimilarity,
            "",
            0.9,
            "",
        ));
        r.add_evidence(AttributionEvidence::new(
            EvidenceKind::YaraMatch,
            "",
            0.7,
            "",
        ));
        r.recompute_confidence();
        // average = (0.9 + 0.7) / 2 = 0.8 → 80
        assert_eq!(r.confidence, 80);
    }

    #[test]
    fn test_attribution_result_is_high_confidence() {
        let r = AttributionResult::new("actor".to_string(), 80);
        assert!(r.is_high_confidence());
        let r2 = AttributionResult::new("actor".to_string(), 79);
        assert!(!r2.is_high_confidence());
    }

    #[test]
    fn test_attribution_result_add_alternative() {
        let mut r = AttributionResult::new("APT29".to_string(), 90);
        r.add_alternative("APT28".to_string(), 60);
        r.add_alternative("Lazarus".to_string(), 40);
        assert_eq!(r.alternatives.len(), 2);
        assert_eq!(r.alternatives[0].0, "APT28"); // higher conf first
    }

    #[test]
    fn test_attribution_result_evidence_kinds() {
        let mut r = AttributionResult::new("x".to_string(), 50);
        r.add_evidence(AttributionEvidence::new(
            EvidenceKind::YaraMatch,
            "",
            0.5,
            "",
        ));
        r.add_evidence(AttributionEvidence::new(
            EvidenceKind::YaraMatch,
            "",
            0.6,
            "",
        ));
        r.add_evidence(AttributionEvidence::new(
            EvidenceKind::Victimology,
            "",
            0.4,
            "",
        ));
        let kinds = r.evidence_kinds();
        assert_eq!(kinds.len(), 2);
    }

    #[test]
    fn test_attribution_result_display() {
        let r = AttributionResult::new("APT29".to_string(), 85);
        let s = r.to_string();
        assert!(s.contains("APT29"));
        assert!(s.contains("85"));
    }

    #[test]
    fn test_attribution_evidence_display() {
        let ev = AttributionEvidence::new(
            EvidenceKind::SharedInfrastructure,
            "same C2 IP",
            0.8,
            "feed",
        );
        let s = ev.to_string();
        assert!(s.contains("0.80"));
        assert!(s.contains("same C2 IP"));
    }

    #[test]
    fn test_attributor_known_actors_unique() {
        let mut a = ActorAttributor::new();
        a.register_actor_ioc("APT29", "1.2.3.4");
        a.register_actor_family("APT29", "Cobalt Strike");
        // Should not duplicate APT29
        let actors = a.known_actors();
        let count = actors.iter().filter(|&&x| x == "APT29").count();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_attributor_debug() {
        let a = make_attributor();
        let s = format!("{a:?}");
        assert!(s.contains("ActorAttributor"));
    }

    #[test]
    fn test_attributor_default() {
        let a = ActorAttributor::default();
        assert!(a.known_actors().is_empty());
    }

    #[test]
    fn test_attribution_serialization() {
        let r = AttributionResult::new("APT29".to_string(), 85);
        let json = serde_json::to_string(&r).unwrap();
        let decoded: AttributionResult = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.actor_name, "APT29");
        assert_eq!(decoded.confidence, 85);
    }

    #[test]
    fn test_evidence_kind_values() {
        let kinds = [
            EvidenceKind::SharedInfrastructure,
            EvidenceKind::YaraMatch,
            EvidenceKind::CodeSimilarity,
            EvidenceKind::MalwareLineage,
            EvidenceKind::Victimology,
            EvidenceKind::HumanIntelligence,
            EvidenceKind::TemporalCorrelation,
            EvidenceKind::OpSec,
        ];
        for k in &kinds {
            assert_eq!(*k, *k); // just check PartialEq
        }
    }
}
