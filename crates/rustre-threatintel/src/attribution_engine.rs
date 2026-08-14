//! Attribution engine — correlate `IoCs` to threat actors and compute confidence intervals.
//!
//! # Approach
//!
//! Attribution is inherently probabilistic.  This module combines multiple
//! independent evidence streams and produces a [`AttributionResult`] with a
//! confidence interval rather than a point estimate:
//!
//! * **`IoC` → actor mapping** from threat-intel databases.
//! * **TTP clustering** based on MITRE ATT&CK technique overlap.
//! * **Code similarity** between malware families (embedding cosine similarity).
//! * **Infrastructure overlap** — shared C2 IPs/domains across campaigns.
//! * **Temporal correlation** — co-occurring activity windows.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ── Evidence kinds ────────────────────────────────────────────────────────────

/// Kinds of evidence used to attribute activity to a threat actor.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceKind {
    /// Exact match of an `IoC` previously attributed to this actor.
    IoCMatch,
    /// Overlap in MITRE ATT&CK techniques used.
    TtpOverlap,
    /// Code similarity between binaries (e.g. shared function, packer).
    CodeSimilarity,
    /// Shared infrastructure (same C2 IP, hosting AS, domain registrar).
    InfrastructureOverlap,
    /// Temporal co-occurrence of activity.
    TemporalCorrelation,
    /// Linguistic artifacts in binaries/scripts matching known actor.
    LinguisticMatch,
    /// Human analyst attribution note.
    AnalystNote,
}

impl EvidenceKind {
    /// Default evidence weight for this kind when contributing to confidence.
    #[must_use] 
    pub const fn default_weight(&self) -> f32 {
        match self {
            Self::IoCMatch => 0.9,
            Self::CodeSimilarity => 0.8,
            Self::InfrastructureOverlap => 0.75,
            Self::TtpOverlap => 0.6,
            Self::TemporalCorrelation => 0.4,
            Self::LinguisticMatch => 0.5,
            Self::AnalystNote => 0.7,
        }
    }
}

// ── Evidence unit ────────────────────────────────────────────────────────────

/// A single piece of evidence linking activity to a threat actor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionEvidence {
    /// Kind of evidence.
    pub kind: EvidenceKind,
    /// Strength of this evidence `[0.0, 1.0]`.
    pub strength: f32,
    /// Human-readable description.
    pub description: String,
    /// Timestamp of the evidence.
    pub observed_at: u64,
    /// Optional reference URL or report ID.
    pub reference: Option<String>,
}

impl AttributionEvidence {
    pub fn new(kind: EvidenceKind, strength: f32, description: impl Into<String>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        Self {
            kind,
            strength: strength.clamp(0.0, 1.0),
            description: description.into(),
            observed_at: now,
            reference: None,
        }
    }

    #[must_use]
    pub fn with_reference(mut self, reference: impl Into<String>) -> Self {
        self.reference = Some(reference.into());
        self
    }
}

// ── Attribution result ────────────────────────────────────────────────────────

/// Attribution of activity to a specific threat actor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionResult {
    /// Threat actor ID (e.g. `"APT28"`, `"G0007"`).
    pub actor_id: String,
    /// Human-readable actor name.
    pub actor_name: String,
    /// Point estimate of confidence `[0.0, 1.0]`.
    pub confidence: f32,
    /// 90% confidence interval `(lower, upper)`.
    pub confidence_interval: (f32, f32),
    /// Individual evidence items.
    pub evidence: Vec<AttributionEvidence>,
    /// MITRE ATT&CK group ID if known.
    pub mitre_group_id: Option<String>,
    /// Alternative actors considered (ranked by confidence).
    pub alternatives: Vec<(String, f32)>,
}

impl AttributionResult {
    /// Whether this attribution meets a minimum confidence threshold.
    #[must_use] 
    pub fn is_confident(&self, threshold: f32) -> bool {
        self.confidence >= threshold
    }

    /// Confidence label: Low / Medium / High / Very High.
    #[must_use] 
    pub fn confidence_label(&self) -> &'static str {
        match self.confidence {
            c if c < 0.3 => "Low",
            c if c < 0.55 => "Medium",
            c if c < 0.75 => "High",
            _ => "Very High",
        }
    }
}

// ── TTP cluster ───────────────────────────────────────────────────────────────

/// A cluster of MITRE ATT&CK techniques associated with one actor or sample set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtpCluster {
    pub actor_id: String,
    /// Set of MITRE technique IDs (e.g. `"T1059.001"`).
    pub techniques: HashSet<String>,
    /// Tactics covered (e.g. `"TA0002"` Execution).
    pub tactics: HashSet<String>,
}

impl TtpCluster {
    /// Jaccard similarity to another cluster `[0.0, 1.0]`.
    #[must_use] 
    pub fn jaccard(&self, other: &Self) -> f32 {
        let intersection = self.techniques.intersection(&other.techniques).count();
        let union = self.techniques.union(&other.techniques).count();
        if union == 0 {
            return 0.0;
        }
        crate::casts::usize_to_f32(intersection) / crate::casts::usize_to_f32(union)
    }

    /// Number of tactic categories shared.
    #[must_use] 
    pub fn shared_tactics(&self, other: &Self) -> usize {
        self.tactics.intersection(&other.tactics).count()
    }
}

// ── Infrastructure overlap ────────────────────────────────────────────────────

/// Infrastructure node used to detect shared infrastructure between actors.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InfraNode {
    Ip(String),
    Domain(String),
    AutonomousSystem(u32),
    DomainRegistrar(String),
    HostingProvider(String),
}

/// Detected infrastructure overlap between two entities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfraOverlap {
    pub entity_a: String,
    pub entity_b: String,
    pub shared_nodes: Vec<InfraNode>,
    pub overlap_score: f32,
}

impl InfraOverlap {
    #[must_use] 
    pub fn compute(
        entity_a: &str,
        infra_a: &HashSet<InfraNode>,
        entity_b: &str,
        infra_b: &HashSet<InfraNode>,
    ) -> Self {
        let shared: Vec<InfraNode> = infra_a.intersection(infra_b).cloned().collect();
        let union = infra_a.union(infra_b).count();
        let overlap_score = if union == 0 {
            0.0
        } else {
            crate::casts::usize_to_f32(shared.len()) / crate::casts::usize_to_f32(union)
        };
        Self {
            entity_a: entity_a.to_string(),
            entity_b: entity_b.to_string(),
            shared_nodes: shared,
            overlap_score,
        }
    }
}

// ── Temporal correlation ──────────────────────────────────────────────────────

/// Detects temporal co-occurrence of activity between actors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalWindow {
    pub start_ts: u64,
    pub end_ts: u64,
}

impl TemporalWindow {
    #[must_use] 
    pub const fn new(start_ts: u64, end_ts: u64) -> Self {
        Self { start_ts, end_ts }
    }

    /// Check if this window overlaps with another.
    #[must_use] 
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.start_ts < other.end_ts && other.start_ts < self.end_ts
    }

    /// Overlap duration in seconds.
    #[must_use] 
    pub fn overlap_secs(&self, other: &Self) -> u64 {
        let start = self.start_ts.max(other.start_ts);
        let end = self.end_ts.min(other.end_ts);
        end.saturating_sub(start)
    }
}

// ── Attribution engine ────────────────────────────────────────────────────────

/// Database of known actor profiles used by the engine.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActorDatabase {
    /// `actor_id` → (`actor_name`, MITRE group ID, known TTPs, infrastructure)
    actors: HashMap<String, ActorProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorProfile {
    pub actor_id: String,
    pub actor_name: String,
    pub mitre_group_id: Option<String>,
    pub known_iocs: HashSet<String>,
    pub ttp_cluster: TtpCluster,
    pub infrastructure: HashSet<InfraNode>,
    pub known_malware_families: HashSet<String>,
    /// Typical operation windows (UTC hours) e.g. `(8, 17)` = 08:00–17:00 UTC
    pub operation_hours: Option<(u8, u8)>,
}

impl ActorDatabase {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            actors: HashMap::new(),
        }
    }

    pub fn add_actor(&mut self, profile: ActorProfile) {
        self.actors.insert(profile.actor_id.clone(), profile);
    }

    #[must_use] 
    pub fn get(&self, actor_id: &str) -> Option<&ActorProfile> {
        self.actors.get(actor_id)
    }

    pub fn all_actors(&self) -> impl Iterator<Item = &ActorProfile> {
        self.actors.values()
    }
}

/// Configuration for the attribution engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionConfig {
    /// Minimum confidence to include a result.
    pub min_confidence: f32,
    /// Maximum number of alternative actors to report.
    pub max_alternatives: usize,
    /// Weight override per evidence kind (if None, uses kind default).
    pub evidence_weights: HashMap<String, f32>,
    /// Apply temporal decay to old `IoC` matches (half-life in days).
    pub ioc_match_half_life_days: Option<u64>,
}

impl Default for AttributionConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.2,
            max_alternatives: 3,
            evidence_weights: HashMap::new(),
            ioc_match_half_life_days: Some(90),
        }
    }
}

/// Core attribution engine.
pub struct AttributionEngine {
    db: ActorDatabase,
    config: AttributionConfig,
}

impl AttributionEngine {
    #[must_use] 
    pub const fn new(db: ActorDatabase, config: AttributionConfig) -> Self {
        Self { db, config }
    }

    /// Attribute a set of `IoCs` and TTPs to known threat actors.
    ///
    /// Returns results ranked by confidence (highest first).
    #[must_use]
    pub fn attribute(
        &self,
        observed_iocs: &HashSet<String>,
        observed_ttps: &TtpCluster,
        observed_infra: &HashSet<InfraNode>,
        analyst_notes: &[AttributionEvidence],
    ) -> Vec<AttributionResult> {
        let mut results: Vec<AttributionResult> = self
            .db
            .all_actors()
            .filter_map(|actor| {
                self.score_actor(actor, observed_iocs, observed_ttps, observed_infra, analyst_notes)
            })
            .filter(|r| r.confidence >= self.config.min_confidence)
            .collect();

        // Confidences are finite by construction (see `aggregate_evidence`), but
        // a library sort should not be one arithmetic edge away from panicking:
        // order any unorderable pair as equal and keep the result total.
        results.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Fill alternatives into each result
        let top_ids: Vec<(String, f32)> = results
            .iter()
            .take(self.config.max_alternatives + 1)
            .map(|r| (r.actor_id.clone(), r.confidence))
            .collect();

        for (i, result) in results.iter_mut().enumerate() {
            result.alternatives = top_ids
                .iter()
                .filter(|(id, _)| id != &result.actor_id)
                .take(self.config.max_alternatives)
                .cloned()
                .collect();
            let _ = i;
        }

        results
    }

    fn score_actor(
        &self,
        actor: &ActorProfile,
        observed_iocs: &HashSet<String>,
        observed_ttps: &TtpCluster,
        observed_infra: &HashSet<InfraNode>,
        analyst_notes: &[AttributionEvidence],
    ) -> Option<AttributionResult> {
        let mut evidence: Vec<AttributionEvidence> = Vec::new();

        // ── IoC matches ───────────────────────────────────────────────────
        let matched_iocs: Vec<&String> = observed_iocs
            .iter()
            .filter(|ioc| actor.known_iocs.contains(*ioc))
            .collect();

        if !matched_iocs.is_empty() {
            let strength = (crate::casts::usize_to_f32(matched_iocs.len())
                / crate::casts::usize_to_f32(matched_iocs.len() + 3))  // asymptotic
                .min(0.95);
            evidence.push(AttributionEvidence::new(
                EvidenceKind::IoCMatch,
                strength,
                format!("{} IoC(s) matched actor {}", matched_iocs.len(), actor.actor_id),
            ));
        }

        // ── TTP overlap ───────────────────────────────────────────────────
        let jaccard = observed_ttps.jaccard(&actor.ttp_cluster);
        if jaccard > 0.05 {
            evidence.push(AttributionEvidence::new(
                EvidenceKind::TtpOverlap,
                jaccard,
                format!(
                    "TTP Jaccard similarity {:.2} with {}",
                    jaccard, actor.actor_id
                ),
            ));
        }

        // ── Infrastructure overlap ────────────────────────────────────────
        let infra_overlap = InfraOverlap::compute(
            "observed",
            observed_infra,
            &actor.actor_id,
            &actor.infrastructure,
        );
        if infra_overlap.overlap_score > 0.0 {
            evidence.push(AttributionEvidence::new(
                EvidenceKind::InfrastructureOverlap,
                infra_overlap.overlap_score,
                format!(
                    "{} shared infra node(s) with {}",
                    infra_overlap.shared_nodes.len(),
                    actor.actor_id
                ),
            ));
        }

        // ── Analyst notes ─────────────────────────────────────────────────
        for note in analyst_notes {
            evidence.push(note.clone());
        }

        if evidence.is_empty() {
            return None;
        }

        // ── Aggregate evidence into confidence ────────────────────────────
        let (confidence, interval) = self.aggregate_evidence(&evidence);

        Some(AttributionResult {
            actor_id: actor.actor_id.clone(),
            actor_name: actor.actor_name.clone(),
            confidence,
            confidence_interval: interval,
            evidence,
            mitre_group_id: actor.mitre_group_id.clone(),
            alternatives: vec![],
        })
    }

    /// Aggregate a list of evidence items into a point confidence and 90% CI.
    fn aggregate_evidence(&self, evidence: &[AttributionEvidence]) -> (f32, (f32, f32)) {
        if evidence.is_empty() {
            return (0.0, (0.0, 0.0));
        }

        // Weighted mean of (strength × kind_weight)
        let mut total_weight = 0.0_f32;
        let mut weighted_sum = 0.0_f32;

        for ev in evidence {
            let kind_key = format!("{:?}", ev.kind);
            let kind_weight = self
                .config
                .evidence_weights
                .get(&kind_key)
                .copied()
                .unwrap_or_else(|| ev.kind.default_weight());
            let w = kind_weight;
            weighted_sum = ev.strength.mul_add(w, weighted_sum);
            total_weight += w;
        }

        // `evidence_weights` is a public, unvalidated config field, and zeroing
        // a weight is the natural way to disable a kind of evidence. If every
        // item present is of a zeroed kind, `total_weight` is 0 and this is
        // 0.0/0.0 = NaN — and `clamp` does NOT sanitise NaN, it propagates it,
        // so the [0,1] invariant this line appears to establish would not hold.
        // Fall back to the same value as the empty-evidence branch above.
        // Written as `!(total_weight > 0.0)` on purpose: every comparison with
        // NaN is false, so `total_weight <= 0.0` would let a NaN weight straight
        // through. This form rejects zero, negative AND NaN denominators.
        if !(total_weight > 0.0) {
            return (0.0, (0.0, 0.0));
        }
        let point = (weighted_sum / total_weight).clamp(0.0, 1.0);
        // A NaN `strength` on any single item poisons the weighted sum even when
        // the weights are sane, and `clamp` propagates NaN rather than bounding
        // it — so the [0,1] invariant has to be checked, not assumed.
        if !point.is_finite() {
            return (0.0, (0.0, 0.0));
        }

        // Approximate CI via standard error of weighted mean
        let variance: f32 = evidence
            .iter()
            .map(|ev| {
                let kind_key = format!("{:?}", ev.kind);
                let kind_weight = self
                    .config
                    .evidence_weights
                    .get(&kind_key)
                    .copied()
                    .unwrap_or_else(|| ev.kind.default_weight());
                let diff = ev.strength - point;
                kind_weight * diff * diff
            })
            .sum::<f32>()
            / total_weight;

        let std_err = variance.sqrt() / crate::casts::usize_to_f32(evidence.len()).sqrt();
        // 90% CI: ±1.645 × SE. A non-finite standard error degrades to a zero
        // margin (interval collapses to the point estimate) rather than
        // producing NaN bounds that `clamp` would pass through untouched.
        let margin = if std_err.is_finite() { 1.645 * std_err } else { 0.0 };
        let lower = (point - margin).clamp(0.0, 1.0);
        let upper = (point + margin).clamp(0.0, 1.0);

        (point, (lower, upper))
    }
}

// ── Code similarity helper ────────────────────────────────────────────────────

/// Cosine similarity between two feature vectors (e.g. function embeddings).
#[must_use] 
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    // `!(x > 0.0)`, not `x == 0.0`: the vectors are caller-supplied, and a NaN
    // component makes the norm NaN, which the equality form lets through — the
    // trailing `.clamp(-1.0, 1.0)` then propagates NaN instead of bounding it.
    if !(norm_a > 0.0) || !(norm_b > 0.0) {
        return 0.0;
    }
    // The denominator guard alone is NOT enough: an INFINITE component passes
    // `> 0.0` (its norm is +inf), and `dot / (inf * inf)` is inf/inf = NaN,
    // which `clamp` propagates. Checking the result is what actually enforces
    // the bound — guarding only the inputs left this case open.
    let sim = (dot / (norm_a * norm_b)).clamp(-1.0, 1.0);
    if sim.is_finite() { sim } else { 0.0 }
}

/// Build an [`AttributionEvidence`] from binary code similarity.
#[must_use] 
pub fn code_similarity_evidence(
    family_a: &str,
    family_b: &str,
    embedding_a: &[f32],
    embedding_b: &[f32],
) -> AttributionEvidence {
    let similarity = cosine_similarity(embedding_a, embedding_b);
    AttributionEvidence::new(
        EvidenceKind::CodeSimilarity,
        similarity.max(0.0),
        format!(
            "Code similarity {similarity:.3} between '{family_a}' and '{family_b}'"
        ),
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_actor() -> ActorProfile {
        let mut techniques = HashSet::new();
        techniques.insert("T1059.001".into()); // PowerShell
        techniques.insert("T1486".into());     // Data Encrypted for Impact
        techniques.insert("T1071.001".into()); // Web Protocols C2

        let mut tactics = HashSet::new();
        tactics.insert("TA0002".into()); // Execution
        tactics.insert("TA0040".into()); // Impact
        tactics.insert("TA0011".into()); // C&C

        let mut iocs = HashSet::new();
        iocs.insert("1.2.3.4".to_string());
        iocs.insert("evil.com".to_string());

        let mut infra = HashSet::new();
        infra.insert(InfraNode::Ip("1.2.3.4".into()));
        infra.insert(InfraNode::Domain("evil.com".into()));

        ActorProfile {
            actor_id: "APT99".into(),
            actor_name: "APT99 (Fancy Panda)".into(),
            mitre_group_id: Some("G9999".into()),
            known_iocs: iocs,
            ttp_cluster: TtpCluster {
                actor_id: "APT99".into(),
                techniques,
                tactics,
            },
            infrastructure: infra,
            known_malware_families: HashSet::new(),
            operation_hours: Some((9, 17)),
        }
    }

    #[test]
    fn attribution_ioc_match() {
        let mut db = ActorDatabase::new();
        db.add_actor(sample_actor());
        let engine = AttributionEngine::new(db, AttributionConfig::default());

        let mut observed_iocs = HashSet::new();
        observed_iocs.insert("evil.com".to_string());

        let observed_ttps = TtpCluster {
            actor_id: "observed".into(),
            techniques: HashSet::new(),
            tactics: HashSet::new(),
        };

        let results = engine.attribute(
            &observed_iocs,
            &observed_ttps,
            &HashSet::new(),
            &[],
        );
        assert!(!results.is_empty());
        assert_eq!(results[0].actor_id, "APT99");
    }

    #[test]
    fn ttp_jaccard() {
        let a = TtpCluster {
            actor_id: "A".into(),
            techniques: ["T1", "T2", "T3"].iter().map(std::string::ToString::to_string).collect(),
            tactics: HashSet::new(),
        };
        let b = TtpCluster {
            actor_id: "B".into(),
            techniques: ["T2", "T3", "T4"].iter().map(std::string::ToString::to_string).collect(),
            tactics: HashSet::new(),
        };
        // intersection: {T2,T3} = 2; union: {T1,T2,T3,T4} = 4 → 0.5
        let j = a.jaccard(&b);
        assert!((j - 0.5).abs() < 0.01, "Jaccard: {j}");
    }

    #[test]
    fn cosine_sim_identical() {
        let v = [1.0_f32, 0.5, 0.3];
        assert!((cosine_similarity(&v, &v) - 1.0).abs() < 1e-5);
    }

    #[test]
    fn cosine_sim_orthogonal() {
        let a = [1.0_f32, 0.0];
        let b = [0.0_f32, 1.0];
        assert!((cosine_similarity(&a, &b)).abs() < 1e-5);
    }

    #[test]
    fn infra_overlap() {
        let mut ia: HashSet<InfraNode> = HashSet::new();
        ia.insert(InfraNode::Ip("1.2.3.4".into()));
        ia.insert(InfraNode::Domain("evil.com".into()));
        let mut ib: HashSet<InfraNode> = HashSet::new();
        ib.insert(InfraNode::Ip("1.2.3.4".into()));
        ib.insert(InfraNode::Ip("5.6.7.8".into()));

        let overlap = InfraOverlap::compute("A", &ia, "B", &ib);
        assert_eq!(overlap.shared_nodes.len(), 1);
        // Jaccard: 1 / 3 = 0.333…
        assert!((overlap.overlap_score - 1.0 / 3.0).abs() < 0.01);
    }
}
