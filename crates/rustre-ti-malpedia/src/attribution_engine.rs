//! Malware attribution engine: cluster samples by hash similarity, link to families,
//! score confidence, and produce attribution reports.
//!
//! Implements import-hash clustering, TLSH fuzzy matching, and YARA correlation.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────────────────────────────────────
// Hash types
// ──────────────────────────────────────────────────────────────────────────────

/// Hash types used for sample clustering and matching.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashKind {
    Sha256,
    Sha1,
    Md5,
    /// MD5 of the IAT (import address table).
    ImpHash,
    /// TLSH fuzzy hash.
    Tlsh,
    /// SSDEEP context-triggered piecewise hash.
    Ssdeep,
    /// Rich header hash (PE-specific).
    RichHash,
    /// Authenticode certificate hash.
    AuthenticodeHash,
}

/// A typed hash value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TypedHash {
    pub kind: HashKind,
    pub value: String,
}

impl TypedHash {
    #[must_use]
    pub fn new(kind: HashKind, value: impl Into<String>) -> Self {
        Self { kind, value: value.into() }
    }

    #[must_use]
    pub fn imphash(v: impl Into<String>) -> Self {
        Self::new(HashKind::ImpHash, v)
    }

    #[must_use]
    pub fn tlsh(v: impl Into<String>) -> Self {
        Self::new(HashKind::Tlsh, v)
    }

    #[must_use]
    pub fn sha256(v: impl Into<String>) -> Self {
        Self::new(HashKind::Sha256, v)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Sample record
// ──────────────────────────────────────────────────────────────────────────────

/// A sample record used by the attribution engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionSample {
    pub sha256: String,
    pub hashes: Vec<TypedHash>,
    pub compile_timestamp: Option<u64>,
    pub file_size: Option<u64>,
    pub arch: Option<String>,
    /// Known family label (if pre-labelled).
    pub known_family: Option<String>,
    /// YARA rule names that matched this sample.
    pub yara_matches: Vec<String>,
    /// Analyst-assigned tags.
    pub tags: Vec<String>,
}

impl AttributionSample {
    /// Create a new sample record.
    #[must_use]
    pub fn new(sha256: impl Into<String>) -> Self {
        Self {
            sha256: sha256.into(),
            hashes: Vec::new(),
            compile_timestamp: None,
            file_size: None,
            arch: None,
            known_family: None,
            yara_matches: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Add a typed hash.
    pub fn add_hash(&mut self, hash: TypedHash) {
        self.hashes.push(hash);
    }

    /// Get the value of a hash by kind.
    #[must_use]
    pub fn get_hash(&self, kind: &HashKind) -> Option<&str> {
        self.hashes
            .iter()
            .find(|h| &h.kind == kind)
            .map(|h| h.value.as_str())
    }

    /// Returns `true` if this sample has an import hash.
    #[must_use]
    pub fn has_imphash(&self) -> bool {
        self.get_hash(&HashKind::ImpHash).is_some()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Cluster
// ──────────────────────────────────────────────────────────────────────────────

/// A cluster of samples that are considered related.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleCluster {
    /// Cluster identifier.
    pub id: String,
    /// SHA-256 hashes of member samples.
    pub members: Vec<String>,
    /// Why this cluster was formed.
    pub cluster_reason: ClusterReason,
    /// The common hash value that links the cluster (if applicable).
    pub pivot_value: Option<String>,
    /// Candidate family labels from members.
    pub candidate_families: Vec<String>,
    /// Confidence that this cluster represents one family [0, 100].
    pub cohesion_score: u8,
}

impl SampleCluster {
    /// Create a new cluster.
    #[must_use]
    pub fn new(id: impl Into<String>, reason: ClusterReason) -> Self {
        Self {
            id: id.into(),
            members: Vec::new(),
            cluster_reason: reason,
            pivot_value: None,
            candidate_families: Vec::new(),
            cohesion_score: 0,
        }
    }

    /// Add a member sample hash.
    pub fn add_member(&mut self, sha256: impl Into<String>) {
        self.members.push(sha256.into());
    }

    /// Number of members.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.members.len()
    }

    /// Best-guess family label (most common among members).
    #[must_use]
    pub fn primary_family(&self) -> Option<&str> {
        self.candidate_families.first().map(String::as_str)
    }
}

/// Reason a cluster was formed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterReason {
    /// Samples share the same import hash.
    SharedImpHash,
    /// Samples are similar by TLSH fuzzy hash.
    TlshSimilarity,
    /// Samples matched the same YARA rule.
    YaraMatch(String),
    /// Samples share the same Rich header hash.
    SharedRichHash,
    /// Samples share compile timestamp.
    SharedCompileTime,
    /// Multiple signals combined.
    Combined,
}

impl std::fmt::Display for ClusterReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SharedImpHash => write!(f, "shared-imphash"),
            Self::TlshSimilarity => write!(f, "tlsh-similarity"),
            Self::YaraMatch(rule) => write!(f, "yara:{rule}"),
            Self::SharedRichHash => write!(f, "shared-rich-hash"),
            Self::SharedCompileTime => write!(f, "shared-compile-time"),
            Self::Combined => write!(f, "combined"),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Attribution evidence
// ──────────────────────────────────────────────────────────────────────────────

/// A single piece of attribution evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub description: String,
    pub weight: u8,
}

/// Kind of attribution evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceKind {
    HashMatch,
    YaraRule,
    ImportHash,
    TlshSimilarity,
    CompileArtifact,
    CodeReuse,
    InfrastructureOverlap,
    TtpOverlap,
    AnalystJudgment,
}

impl Evidence {
    #[must_use]
    pub fn new(kind: EvidenceKind, description: impl Into<String>, weight: u8) -> Self {
        Self { kind, description: description.into(), weight }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Attribution result
// ──────────────────────────────────────────────────────────────────────────────

/// Attribution of a sample or cluster to a family.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyAttribution {
    /// Attributed family name.
    pub family: String,
    /// Attributed actor name (if known).
    pub actor: Option<String>,
    /// Confidence score [0, 100].
    pub confidence: u8,
    /// Evidence items supporting this attribution.
    pub evidence: Vec<Evidence>,
    /// Attribution method.
    pub method: AttributionMethod,
    /// Analyst notes.
    pub notes: Option<String>,
}

/// The primary attribution method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttributionMethod {
    ExactHashMatch,
    ImportHashCluster,
    TlshCluster,
    YaraSignature,
    HeuristicSimilarity,
    ManualAnalysis,
    Combined,
}

impl FamilyAttribution {
    /// Create a new attribution.
    #[must_use]
    pub fn new(family: impl Into<String>, confidence: u8, method: AttributionMethod) -> Self {
        Self {
            family: family.into(),
            actor: None,
            confidence,
            evidence: Vec::new(),
            method,
            notes: None,
        }
    }

    /// Add evidence.
    pub fn add_evidence(&mut self, e: Evidence) {
        self.evidence.push(e);
    }

    /// Returns `true` if confidence is high (≥ 75).
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 75
    }

    /// Total evidence weight.
    #[must_use]
    pub fn total_weight(&self) -> u32 {
        self.evidence.iter().map(|e| u32::from(e.weight)).sum()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// TLSH distance helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Compute a simplified TLSH distance (character difference count).
///
/// Real TLSH distance is more complex; this is a placeholder that counts
/// differing hex nybbles, suitable for testing.
#[must_use]
pub fn tlsh_distance(a: &str, b: &str) -> u32 {
    let a = a.trim_start_matches("T1").trim_start_matches("t1");
    let b = b.trim_start_matches("T1").trim_start_matches("t1");
    let len = a.len().min(b.len());
    let diff = u32::try_from(a.chars().zip(b.chars()).take(len)
        .filter(|(ca, cb)| ca != cb)
        .count()).unwrap_or(u32::MAX);
    diff + u32::try_from(a.len().abs_diff(b.len())).unwrap_or(u32::MAX)
}

/// Threshold below which two TLSH hashes are considered similar.
pub const TLSH_SIMILARITY_THRESHOLD: u32 = 30;

// ──────────────────────────────────────────────────────────────────────────────
// AttributionEngine
// ──────────────────────────────────────────────────────────────────────────────

/// Configuration for the attribution engine.
#[derive(Debug, Clone)]
pub struct AttributionConfig {
    pub tlsh_threshold: u32,
    pub min_cluster_size: usize,
    pub min_confidence: u8,
    pub enable_imphash_clustering: bool,
    pub enable_tlsh_clustering: bool,
    pub enable_yara_clustering: bool,
    pub enable_rich_hash_clustering: bool,
}

impl Default for AttributionConfig {
    fn default() -> Self {
        Self {
            tlsh_threshold: TLSH_SIMILARITY_THRESHOLD,
            min_cluster_size: 2,
            min_confidence: 40,
            enable_imphash_clustering: true,
            enable_tlsh_clustering: true,
            enable_yara_clustering: true,
            enable_rich_hash_clustering: true,
        }
    }
}

/// The core attribution engine.
#[derive(Debug)]
pub struct AttributionEngine {
    config: AttributionConfig,
    /// `family_name` → set of known hashes.
    family_hashes: HashMap<String, HashSet<String>>,
    /// `family_name` → set of known imphashes.
    family_imphashes: HashMap<String, HashSet<String>>,
    /// `family_name` → YARA rules.
    family_yara: HashMap<String, Vec<String>>,
    /// `family_name` → actor.
    family_actors: HashMap<String, String>,
    /// All indexed samples.
    samples: Vec<AttributionSample>,
    cluster_counter: u64,
}

impl AttributionEngine {
    /// Create a new engine with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: AttributionConfig::default(),
            family_hashes: HashMap::new(),
            family_imphashes: HashMap::new(),
            family_yara: HashMap::new(),
            family_actors: HashMap::new(),
            samples: Vec::new(),
            cluster_counter: 0,
        }
    }

    /// Create with custom configuration.
    #[must_use]
    pub fn with_config(config: AttributionConfig) -> Self {
        Self { config, ..Self::new() }
    }

    /// Allocate and return the next monotonic cluster id from this engine's
    /// internal counter. Useful when callers want to assign stable, unique
    /// identifiers across multiple clustering passes (e.g. when persisting
    /// results to a database).
    pub const fn next_cluster_id(&mut self) -> u64 {
        let id = self.cluster_counter;
        self.cluster_counter = self.cluster_counter.wrapping_add(1);
        id
    }

    /// Returns the number of cluster ids issued so far by
    /// [`Self::next_cluster_id`].
    #[must_use]
    pub const fn cluster_id_count(&self) -> u64 {
        self.cluster_counter
    }

    /// Register a family's known SHA-256 hashes.
    pub fn register_family_hashes(&mut self, family: &str, hashes: &[String]) {
        let set = self.family_hashes.entry(family.to_string()).or_default();
        for h in hashes {
            set.insert(h.to_lowercase());
        }
    }

    /// Register a family's known import hashes.
    pub fn register_family_imphashes(&mut self, family: &str, imphashes: &[String]) {
        let set = self.family_imphashes.entry(family.to_string()).or_default();
        for h in imphashes {
            set.insert(h.to_lowercase());
        }
    }

    /// Register YARA rules for a family.
    pub fn register_family_yara(&mut self, family: &str, rules: Vec<String>) {
        self.family_yara.insert(family.to_string(), rules);
    }

    /// Register actor attribution for a family.
    pub fn register_actor(&mut self, family: &str, actor: &str) {
        self.family_actors.insert(family.to_string(), actor.to_string());
    }

    /// Add a sample to the engine's corpus.
    pub fn add_sample(&mut self, sample: AttributionSample) {
        self.samples.push(sample);
    }

    /// Add multiple samples.
    pub fn add_samples(&mut self, samples: Vec<AttributionSample>) {
        self.samples.extend(samples);
    }

    /// Look up a sample by SHA-256.
    #[must_use]
    pub fn get_sample(&self, sha256: &str) -> Option<&AttributionSample> {
        self.samples.iter().find(|s| s.sha256.eq_ignore_ascii_case(sha256))
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Attribution
    // ──────────────────────────────────────────────────────────────────────────

    /// Attribute a single sample to the best-matching family.
    #[must_use]
    pub fn attribute_sample(&self, sample: &AttributionSample) -> Vec<FamilyAttribution> {
        let mut attributions: Vec<FamilyAttribution> = Vec::new();

        // 1. Exact SHA-256 match
        for (family, hashes) in &self.family_hashes {
            if hashes.contains(&sample.sha256.to_lowercase()) {
                let mut a = FamilyAttribution::new(
                    family,
                    95,
                    AttributionMethod::ExactHashMatch,
                );
                a.add_evidence(Evidence::new(
                    EvidenceKind::HashMatch,
                    format!("exact SHA-256 match: {}", sample.sha256),
                    50,
                ));
                a.actor = self.family_actors.get(family).cloned();
                attributions.push(a);
            }
        }

        // 2. Import hash match
        if self.config.enable_imphash_clustering
            && let Some(imphash) = sample.get_hash(&HashKind::ImpHash)
        {
            for (family, imphashes) in &self.family_imphashes {
                if imphashes.contains(&imphash.to_lowercase()) {
                    let mut a = FamilyAttribution::new(
                        family,
                        75,
                        AttributionMethod::ImportHashCluster,
                    );
                    a.add_evidence(Evidence::new(
                        EvidenceKind::ImportHash,
                        format!("imphash match: {imphash}"),
                        30,
                    ));
                    a.actor = self.family_actors.get(family).cloned();
                    attributions.push(a);
                }
            }
        }

        // 3. YARA rule matches
        if self.config.enable_yara_clustering {
            for matched_rule in &sample.yara_matches {
                for (family, rules) in &self.family_yara {
                    if rules.contains(matched_rule) {
                        let existing = attributions.iter_mut().find(|a| &a.family == family);
                        if let Some(a) = existing {
                            a.add_evidence(Evidence::new(
                                EvidenceKind::YaraRule,
                                format!("YARA rule: {matched_rule}"),
                                25,
                            ));
                            a.confidence = a.confidence.saturating_add(10).min(100);
                        } else {
                            let mut a = FamilyAttribution::new(
                                family,
                                60,
                                AttributionMethod::YaraSignature,
                            );
                            a.add_evidence(Evidence::new(
                                EvidenceKind::YaraRule,
                                format!("YARA rule: {matched_rule}"),
                                25,
                            ));
                            a.actor = self.family_actors.get(family).cloned();
                            attributions.push(a);
                        }
                    }
                }
            }
        }

        // Sort by confidence descending
        attributions.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        attributions
    }

    /// Attribute all samples in the corpus.
    #[must_use]
    pub fn attribute_all(&self) -> HashMap<String, Vec<FamilyAttribution>> {
        let mut results = HashMap::new();
        for sample in &self.samples {
            let attrs = self.attribute_sample(sample);
            if !attrs.is_empty() {
                results.insert(sample.sha256.clone(), attrs);
            }
        }
        results
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Clustering
    // ──────────────────────────────────────────────────────────────────────────

    /// Cluster samples by import hash.
    #[must_use]
    pub fn cluster_by_imphash(&self) -> Vec<SampleCluster> {
        let mut groups: HashMap<String, Vec<String>> = HashMap::new();
        for sample in &self.samples {
            if let Some(imphash) = sample.get_hash(&HashKind::ImpHash) {
                let key = imphash.to_lowercase();
                groups.entry(key.clone()).or_default().push(sample.sha256.clone());
            }
        }

        let mut clusters = Vec::new();
        let mut idx = 0u64;
        for (pivot, members) in groups {
            if members.len() < self.config.min_cluster_size {
                continue;
            }
            let mut cluster = SampleCluster::new(
                format!("imphash_{idx}"),
                ClusterReason::SharedImpHash,
            );
            idx += 1;
            cluster.pivot_value = Some(pivot);
            for m in members {
                cluster.add_member(m);
            }
            cluster.cohesion_score = 70;
            // Collect family labels from members
            for sha in &cluster.members {
                if let Some(s) = self.get_sample(sha)
                    && let Some(f) = &s.known_family
                    && !cluster.candidate_families.contains(f)
                {
                    cluster.candidate_families.push(f.clone());
                }
            }
            clusters.push(cluster);
        }
        clusters
    }

    /// Cluster samples by TLSH similarity (O(n²) brute force).
    #[must_use]
    pub fn cluster_by_tlsh(&self) -> Vec<SampleCluster> {
        let tlsh_samples: Vec<(&AttributionSample, &str)> = self
            .samples
            .iter()
            .filter_map(|s| s.get_hash(&HashKind::Tlsh).map(|h| (s, h)))
            .collect();

        let mut visited = vec![false; tlsh_samples.len()];
        let mut clusters = Vec::new();
        let mut idx = 0u64;

        for i in 0..tlsh_samples.len() {
            if visited[i] { continue; }
            let (si, hi) = tlsh_samples[i];
            let mut group = vec![si.sha256.clone()];
            visited[i] = true;

            for j in (i + 1)..tlsh_samples.len() {
                if visited[j] { continue; }
                let (sj, hj) = tlsh_samples[j];
                if tlsh_distance(hi, hj) <= self.config.tlsh_threshold {
                    group.push(sj.sha256.clone());
                    visited[j] = true;
                }
            }

            if group.len() >= self.config.min_cluster_size {
                let mut cluster = SampleCluster::new(
                    format!("tlsh_{idx}"),
                    ClusterReason::TlshSimilarity,
                );
                idx += 1;
                cluster.pivot_value = Some(hi.to_string());
                for sha in group {
                    cluster.add_member(sha);
                }
                cluster.cohesion_score = 60;
                clusters.push(cluster);
            }
        }
        clusters
    }

    /// Cluster samples by shared YARA rule matches.
    #[must_use]
    pub fn cluster_by_yara(&self) -> Vec<SampleCluster> {
        let mut rule_groups: HashMap<String, Vec<String>> = HashMap::new();
        for sample in &self.samples {
            for rule in &sample.yara_matches {
                rule_groups.entry(rule.clone()).or_default().push(sample.sha256.clone());
            }
        }

        let mut clusters = Vec::new();
        let mut idx = 0u64;
        for (rule, members) in rule_groups {
            if members.len() < self.config.min_cluster_size {
                continue;
            }
            let mut cluster = SampleCluster::new(
                format!("yara_{idx}"),
                ClusterReason::YaraMatch(rule.clone()),
            );
            idx += 1;
            cluster.pivot_value = Some(rule);
            for sha in members {
                cluster.add_member(sha);
            }
            cluster.cohesion_score = 65;
            clusters.push(cluster);
        }
        clusters
    }

    /// Run all clustering algorithms and merge results.
    #[must_use]
    pub fn cluster_all(&self) -> Vec<SampleCluster> {
        let mut all = Vec::new();
        if self.config.enable_imphash_clustering {
            all.extend(self.cluster_by_imphash());
        }
        if self.config.enable_tlsh_clustering {
            all.extend(self.cluster_by_tlsh());
        }
        if self.config.enable_yara_clustering {
            all.extend(self.cluster_by_yara());
        }
        all
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Confidence scoring
    // ──────────────────────────────────────────────────────────────────────────

    /// Score the confidence of an attribution.
    ///
    /// Takes into account: exact hash match, imphash cluster, YARA rules,
    /// TLSH similarity, and analyst override.
    #[must_use]
    pub fn score_confidence(attribution: &FamilyAttribution) -> u8 {
        // Base from the attribution method
        let base: u32 = match attribution.method {
            AttributionMethod::ExactHashMatch => 90,
            AttributionMethod::ImportHashCluster => 70,
            AttributionMethod::YaraSignature => 60,
            AttributionMethod::TlshCluster => 55,
            AttributionMethod::HeuristicSimilarity => 40,
            AttributionMethod::ManualAnalysis => 85,
            AttributionMethod::Combined => 75,
        };

        // Evidence weight bonus
        let weight_bonus: u32 = attribution.total_weight().min(20);

        // Actor presence bonus
        let actor_bonus: u32 = if attribution.actor.is_some() { 5 } else { 0 };

        (base + weight_bonus + actor_bonus).min(100) as u8
    }

    /// Generate a full attribution report for all samples.
    #[must_use]
    pub fn generate_report(&self) -> AttributionReport {
        let attributions = self.attribute_all();
        let clusters = self.cluster_all();

        let mut family_counts: HashMap<String, u32> = HashMap::new();
        let mut high_confidence_count = 0u32;
        let mut total_attributed = 0u32;

        for attrs in attributions.values() {
            if let Some(best) = attrs.first() {
                *family_counts.entry(best.family.clone()).or_default() += 1;
                total_attributed += 1;
                if best.is_high_confidence() {
                    high_confidence_count += 1;
                }
            }
        }

        let top_families: Vec<(String, u32)> = {
            let mut v: Vec<_> = family_counts.into_iter().collect();
            v.sort_by(|a, b| b.1.cmp(&a.1));
            v.into_iter().take(10).collect()
        };

        AttributionReport {
            total_samples: self.samples.len(),
            attributed: total_attributed as usize,
            high_confidence: high_confidence_count as usize,
            clusters: clusters.len(),
            top_families,
            cluster_summary: Self::cluster_summary(&self.cluster_all()),
        }
    }

    fn cluster_summary(clusters: &[SampleCluster]) -> Vec<ClusterSummary> {
        clusters
            .iter()
            .map(|c| ClusterSummary {
                id: c.id.clone(),
                size: c.size(),
                reason: c.cluster_reason.to_string(),
                primary_family: c.primary_family().map(str::to_string),
                cohesion_score: c.cohesion_score,
            })
            .collect()
    }

    /// Sample count in the corpus.
    #[must_use]
    pub const fn sample_count(&self) -> usize {
        self.samples.len()
    }

    /// Registered family count.
    #[must_use]
    pub fn family_count(&self) -> usize {
        self.family_hashes.len()
    }
}

impl Default for AttributionEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Report types
// ──────────────────────────────────────────────────────────────────────────────

/// Summary for one cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterSummary {
    pub id: String,
    pub size: usize,
    pub reason: String,
    pub primary_family: Option<String>,
    pub cohesion_score: u8,
}

/// Full attribution report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionReport {
    pub total_samples: usize,
    pub attributed: usize,
    pub high_confidence: usize,
    pub clusters: usize,
    pub top_families: Vec<(String, u32)>,
    pub cluster_summary: Vec<ClusterSummary>,
}

impl AttributionReport {
    /// Attribution rate (0.0–1.0).
    #[must_use]
    pub fn attribution_rate(&self) -> f64 {
        if self.total_samples == 0 { return 0.0; }
        self.attributed as f64 / self.total_samples as f64
    }

    /// High-confidence rate among attributed samples.
    #[must_use]
    pub fn high_confidence_rate(&self) -> f64 {
        if self.attributed == 0 { return 0.0; }
        self.high_confidence as f64 / self.attributed as f64
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sample(sha: &str, imphash: Option<&str>) -> AttributionSample {
        let mut s = AttributionSample::new(sha);
        if let Some(ih) = imphash {
            s.add_hash(TypedHash::imphash(ih));
        }
        s
    }

    fn sample_with_tlsh(sha: &str, tlsh: &str) -> AttributionSample {
        let mut s = AttributionSample::new(sha);
        s.add_hash(TypedHash::tlsh(tlsh));
        s
    }

    fn sample_with_yara(sha: &str, rule: &str) -> AttributionSample {
        let mut s = AttributionSample::new(sha);
        s.yara_matches.push(rule.to_string());
        s
    }

    fn engine_with_data() -> AttributionEngine {
        let mut e = AttributionEngine::new();
        e.register_family_hashes("win.emotet", &["deadbeef".to_string()]);
        e.register_family_imphashes("win.trickbot", &["imphash_abc".to_string()]);
        e.register_family_yara("win.wannacry", vec!["detect_wannacry".to_string()]);
        e.register_actor("win.emotet", "TA542");
        e
    }

    #[test]
    fn test_attribute_exact_hash() {
        let e = engine_with_data();
        let sample = make_sample("deadbeef", None);
        let attrs = e.attribute_sample(&sample);
        assert!(!attrs.is_empty());
        assert_eq!(attrs[0].family, "win.emotet");
        assert!(attrs[0].confidence >= 90);
        assert_eq!(attrs[0].actor.as_deref(), Some("TA542"));
    }

    #[test]
    fn test_attribute_imphash() {
        let e = engine_with_data();
        let sample = make_sample("new_sha256", Some("imphash_abc"));
        let attrs = e.attribute_sample(&sample);
        assert!(attrs.iter().any(|a| a.family == "win.trickbot"));
    }

    #[test]
    fn test_attribute_yara() {
        let e = engine_with_data();
        let sample = sample_with_yara("some_sha256", "detect_wannacry");
        let attrs = e.attribute_sample(&sample);
        assert!(attrs.iter().any(|a| a.family == "win.wannacry"));
    }

    #[test]
    fn test_cluster_by_imphash() {
        let mut e = AttributionEngine::new();
        e.add_sample(make_sample("sha1", Some("abc123")));
        e.add_sample(make_sample("sha2", Some("abc123")));
        e.add_sample(make_sample("sha3", Some("def456")));

        let clusters = e.cluster_by_imphash();
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].size(), 2);
        assert!(matches!(clusters[0].cluster_reason, ClusterReason::SharedImpHash));
    }

    #[test]
    fn test_cluster_by_yara() {
        let mut e = AttributionEngine::new();
        e.add_sample(sample_with_yara("s1", "rule_x"));
        e.add_sample(sample_with_yara("s2", "rule_x"));
        e.add_sample(sample_with_yara("s3", "rule_y"));

        let clusters = e.cluster_by_yara();
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].size(), 2);
    }

    #[test]
    fn test_cluster_by_tlsh() {
        let mut e = AttributionEngine::new();
        // Very similar hashes
        e.add_sample(sample_with_tlsh("s1", "T1aaaaaa"));
        e.add_sample(sample_with_tlsh("s2", "T1aaaaab")); // 1 char diff
        e.add_sample(sample_with_tlsh("s3", "T1zzzzzz")); // very different

        let clusters = e.cluster_by_tlsh();
        assert!(!clusters.is_empty());
        // s1 and s2 should be in the same cluster
        let cluster = clusters.iter().find(|c| c.members.contains(&"s1".to_string())).unwrap();
        assert!(cluster.members.contains(&"s2".to_string()));
    }

    #[test]
    fn test_tlsh_distance_same() {
        assert_eq!(tlsh_distance("T1abcdef", "T1abcdef"), 0);
    }

    #[test]
    fn test_tlsh_distance_different() {
        let d = tlsh_distance("T1abcdef", "T1abczzz");
        assert!(d > 0);
    }

    #[test]
    fn test_attribution_report() {
        let mut e = engine_with_data();
        e.add_sample(make_sample("deadbeef", None));
        let report = e.generate_report();
        assert_eq!(report.total_samples, 1);
        assert!(report.attributed >= 1);
    }

    #[test]
    fn test_attribution_rate() {
        let report = AttributionReport {
            total_samples: 10,
            attributed: 7,
            high_confidence: 5,
            clusters: 3,
            top_families: vec![],
            cluster_summary: vec![],
        };
        assert!((report.attribution_rate() - 0.7).abs() < 0.001);
        assert!((report.high_confidence_rate() - 5.0 / 7.0).abs() < 0.001);
    }

    #[test]
    fn test_score_confidence_exact_hash() {
        let a = FamilyAttribution::new("win.emotet", 95, AttributionMethod::ExactHashMatch);
        let score = AttributionEngine::score_confidence(&a);
        assert!(score >= 90);
    }

    #[test]
    fn test_score_confidence_yara() {
        let mut a = FamilyAttribution::new("win.wannacry", 60, AttributionMethod::YaraSignature);
        a.add_evidence(Evidence::new(EvidenceKind::YaraRule, "detect_wannacry", 20));
        let score = AttributionEngine::score_confidence(&a);
        assert!(score >= 60);
    }

    #[test]
    fn test_sample_has_imphash() {
        let s = make_sample("sha", Some("abc"));
        assert!(s.has_imphash());
        let s2 = make_sample("sha", None);
        assert!(!s2.has_imphash());
    }

    #[test]
    fn test_cluster_reason_display() {
        assert_eq!(ClusterReason::SharedImpHash.to_string(), "shared-imphash");
        let y = ClusterReason::YaraMatch("detect_x".into());
        assert!(y.to_string().contains("detect_x"));
    }

    #[test]
    fn test_engine_counts() {
        let mut e = engine_with_data();
        e.add_sample(make_sample("sha1", None));
        assert_eq!(e.sample_count(), 1);
        assert!(e.family_count() >= 1);
    }

    #[test]
    fn test_high_confidence_threshold() {
        let hi = FamilyAttribution::new("f", 80, AttributionMethod::ExactHashMatch);
        assert!(hi.is_high_confidence());
        let lo = FamilyAttribution::new("f", 50, AttributionMethod::HeuristicSimilarity);
        assert!(!lo.is_high_confidence());
    }

    #[test]
    fn test_total_weight() {
        let mut a = FamilyAttribution::new("f", 70, AttributionMethod::Combined);
        a.add_evidence(Evidence::new(EvidenceKind::HashMatch, "e1", 30));
        a.add_evidence(Evidence::new(EvidenceKind::YaraRule, "e2", 20));
        assert_eq!(a.total_weight(), 50);
    }
}
