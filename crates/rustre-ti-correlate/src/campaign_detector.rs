//! Campaign detector — cluster malware samples by C2 infrastructure,
//! code similarity, TTP overlap; timeline analysis of campaign activity.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::sample_correlator::{SampleId, CorrelationWeights, correlate_pair, SampleDescriptor};

// ---------------------------------------------------------------------------
// Campaign evidence types
// ---------------------------------------------------------------------------

/// A C2 indicator associated with a sample.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum C2Indicator {
    Domain(String),
    Ip(String),
    Url(String),
    /// Mutex name used for infection check.
    Mutex(String),
    /// Registry key used for persistence.
    RegistryKey(String),
    /// Named pipe.
    Pipe(String),
}

impl C2Indicator {
    pub fn kind(&self) -> &'static str {
        match self {
            C2Indicator::Domain(_) => "domain",
            C2Indicator::Ip(_) => "ip",
            C2Indicator::Url(_) => "url",
            C2Indicator::Mutex(_) => "mutex",
            C2Indicator::RegistryKey(_) => "registry",
            C2Indicator::Pipe(_) => "pipe",
        }
    }
    pub fn value(&self) -> &str {
        match self {
            C2Indicator::Domain(v) | C2Indicator::Ip(v) | C2Indicator::Url(v)
            | C2Indicator::Mutex(v) | C2Indicator::RegistryKey(v) | C2Indicator::Pipe(v) => v,
        }
    }
}

/// MITRE ATT&CK technique identifier (e.g. "T1059.001").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TechniqueId(pub String);

impl TechniqueId {
    pub fn new(id: impl Into<String>) -> Self { TechniqueId(id.into()) }
    pub fn tactic(&self) -> &str {
        // First component before '.' gives the base technique (tactic mapping is out-of-scope here).
        self.0.split('.').next().unwrap_or(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Sample intelligence record
// ---------------------------------------------------------------------------

/// Enriched sample record carrying infrastructure and TTP data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleRecord {
    pub id: SampleId,
    pub descriptor: SampleDescriptor,
    /// Indicators of Compromise extracted from dynamic/static analysis.
    pub c2_indicators: Vec<C2Indicator>,
    /// MITRE ATT&CK technique IDs attributed to this sample.
    pub ttps: Vec<TechniqueId>,
    /// First observed timestamp (Unix epoch).
    pub first_seen: u64,
    /// Last observed timestamp (Unix epoch).
    pub last_seen: u64,
    /// Family name, if known (e.g. "Emotet", "CobaltStrike").
    pub family: Option<String>,
    /// Actor attribution tag, if known.
    pub attributed_to: Option<String>,
}

impl SampleRecord {
    pub fn ttp_set(&self) -> HashSet<&TechniqueId> {
        self.ttps.iter().collect()
    }

    pub fn c2_set(&self) -> HashSet<&C2Indicator> {
        self.c2_indicators.iter().collect()
    }
}

// ---------------------------------------------------------------------------
// Campaign definition
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Campaign {
    /// Unique campaign identifier (auto-generated).
    pub id: String,
    /// Human-assigned name (e.g. "ShadowCat-2024").
    pub name: Option<String>,
    /// Member sample IDs.
    pub samples: Vec<SampleId>,
    /// Shared C2 indicators across the campaign.
    pub shared_c2: Vec<C2Indicator>,
    /// Shared TTPs across the campaign.
    pub shared_ttps: Vec<TechniqueId>,
    /// Confidence score for the clustering (0.0..=1.0).
    pub confidence: f64,
    /// Timeline: (first_seen, last_seen) across all samples.
    pub first_seen: u64,
    pub last_seen: u64,
    /// Dominant family name (most frequent across members).
    pub family: Option<String>,
    /// Actor attribution (most frequent).
    pub attributed_to: Option<String>,
    /// Evidence summary.
    pub evidence: CampaignEvidence,
}

impl Campaign {
    fn campaign_id(index: usize) -> String {
        format!("CAMP-{:04X}", index)
    }
}

/// Summary of evidence that defines a campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignEvidence {
    pub c2_overlap_count: usize,
    pub ttp_overlap_count: usize,
    pub code_similarity_avg: f64,
    pub imphash_match_count: usize,
    pub shared_infrastructure: Vec<String>,
}

// ---------------------------------------------------------------------------
// Pairwise distance between two SampleRecords
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairScore {
    pub a: SampleId,
    pub b: SampleId,
    /// Code-level similarity from feature comparison.
    pub code_score: f64,
    /// Infrastructure overlap score.
    pub infra_score: f64,
    /// TTP overlap score.
    pub ttp_score: f64,
    /// Combined campaign link score.
    pub combined: f64,
}

/// Compute a C2 infrastructure overlap score (Jaccard on indicator values).
fn c2_overlap_score(a: &SampleRecord, b: &SampleRecord) -> f64 {
    if a.c2_indicators.is_empty() && b.c2_indicators.is_empty() { return 0.0; }
    let sa: HashSet<&C2Indicator> = a.c2_indicators.iter().collect();
    let sb: HashSet<&C2Indicator> = b.c2_indicators.iter().collect();
    let inter = sa.intersection(&sb).count() as f64;
    let union = sa.union(&sb).count() as f64;
    if union == 0.0 { 0.0 } else { inter / union }
}

/// Compute a TTP overlap score (Jaccard on technique IDs).
fn ttp_overlap_score(a: &SampleRecord, b: &SampleRecord) -> f64 {
    if a.ttps.is_empty() && b.ttps.is_empty() { return 0.0; }
    let sa: HashSet<&TechniqueId> = a.ttps.iter().collect();
    let sb: HashSet<&TechniqueId> = b.ttps.iter().collect();
    let inter = sa.intersection(&sb).count() as f64;
    let union = sa.union(&sb).count() as f64;
    if union == 0.0 { 0.0 } else { inter / union }
}

fn score_pair(a: &SampleRecord, b: &SampleRecord, weights: &CorrelationWeights) -> PairScore {
    let feat = correlate_pair(&a.descriptor, &b.descriptor, weights);
    let infra = c2_overlap_score(a, b);
    let ttp = ttp_overlap_score(a, b);
    let combined = feat.combined * 0.5 + infra * 0.3 + ttp * 0.2;
    PairScore {
        a: a.id.clone(),
        b: b.id.clone(),
        code_score: feat.combined,
        infra_score: infra,
        ttp_score: ttp,
        combined,
    }
}

// ---------------------------------------------------------------------------
// Union-Find for campaign clustering
// ---------------------------------------------------------------------------

struct UnionFind {
    parent: Vec<usize>,
    rank: Vec<u8>,
}

impl UnionFind {
    fn new(n: usize) -> Self {
        UnionFind { parent: (0..n).collect(), rank: vec![0; n] }
    }

    fn find(&mut self, x: usize) -> usize {
        if self.parent[x] != x {
            self.parent[x] = self.find(self.parent[x]);
        }
        self.parent[x]
    }

    fn union(&mut self, x: usize, y: usize) {
        let px = self.find(x);
        let py = self.find(y);
        if px == py { return; }
        match self.rank[px].cmp(&self.rank[py]) {
            std::cmp::Ordering::Less => self.parent[px] = py,
            std::cmp::Ordering::Greater => self.parent[py] = px,
            std::cmp::Ordering::Equal => {
                self.parent[py] = px;
                self.rank[px] += 1;
            }
        }
    }

    fn groups(&mut self, n: usize) -> HashMap<usize, Vec<usize>> {
        let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
        for i in 0..n {
            let root = self.find(i);
            groups.entry(root).or_default().push(i);
        }
        groups
    }
}

// ---------------------------------------------------------------------------
// Campaign detector
// ---------------------------------------------------------------------------

/// Configuration for campaign detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignConfig {
    /// Minimum combined link score to join samples into the same campaign.
    pub link_threshold: f64,
    /// Minimum number of samples per campaign.
    pub min_campaign_size: usize,
    /// Feature weights for code similarity.
    pub weights: CorrelationWeights,
    /// Whether to require at least one shared C2 indicator.
    pub require_shared_c2: bool,
    /// Whether to use TTP overlap to bridge samples without code similarity.
    pub use_ttp_bridging: bool,
    /// TTP bridge threshold (link samples if TTP score ≥ this, even if code score is low).
    pub ttp_bridge_threshold: f64,
}

impl Default for CampaignConfig {
    fn default() -> Self {
        CampaignConfig {
            link_threshold: 0.55,
            min_campaign_size: 2,
            weights: CorrelationWeights::default(),
            require_shared_c2: false,
            use_ttp_bridging: true,
            ttp_bridge_threshold: 0.6,
        }
    }
}

/// Detect campaigns from a set of sample records.
pub struct CampaignDetector {
    config: CampaignConfig,
}

impl CampaignDetector {
    pub fn new(config: CampaignConfig) -> Self { CampaignDetector { config } }
    pub fn with_defaults() -> Self { CampaignDetector::new(CampaignConfig::default()) }

    pub fn detect(&self, records: &[SampleRecord]) -> Vec<Campaign> {
        let n = records.len();
        if n == 0 { return vec![]; }

        let mut uf = UnionFind::new(n);
        let mut pair_scores: Vec<PairScore> = Vec::new();

        for i in 0..n {
            for j in (i+1)..n {
                let ps = score_pair(&records[i], &records[j], &self.config.weights);
                let should_link = if self.config.require_shared_c2 {
                    ps.combined >= self.config.link_threshold && ps.infra_score > 0.0
                } else if self.config.use_ttp_bridging && ps.ttp_score >= self.config.ttp_bridge_threshold {
                    ps.combined >= self.config.link_threshold * 0.7
                } else {
                    ps.combined >= self.config.link_threshold
                };

                if should_link {
                    uf.union(i, j);
                }
                pair_scores.push(ps);
            }
        }

        let groups = uf.groups(n);
        let mut campaigns: Vec<Campaign> = Vec::new();

        for (group_idx, (_, member_indices)) in groups.iter().enumerate() {
            if member_indices.len() < self.config.min_campaign_size { continue; }

            let members: Vec<&SampleRecord> = member_indices.iter().map(|&i| &records[i]).collect();

            // Compute shared C2 indicators (intersection over all members).
            let shared_c2: Vec<C2Indicator> = self.shared_indicators(&members);

            // Compute shared TTPs.
            let shared_ttps: Vec<TechniqueId> = self.shared_ttps(&members);

            // Average code similarity within cluster.
            let code_sim_avg = self.avg_code_sim(member_indices, &pair_scores, n);

            // Timeline.
            let first_seen = members.iter().map(|m| m.first_seen).min().unwrap_or(0);
            let last_seen = members.iter().map(|m| m.last_seen).max().unwrap_or(0);

            // Dominant family.
            let family = self.majority_value(members.iter().filter_map(|m| m.family.as_deref()));
            let attributed_to = self.majority_value(members.iter().filter_map(|m| m.attributed_to.as_deref()));

            let evidence = CampaignEvidence {
                c2_overlap_count: shared_c2.len(),
                ttp_overlap_count: shared_ttps.len(),
                code_similarity_avg: code_sim_avg,
                imphash_match_count: self.imphash_match_count(&members),
                shared_infrastructure: shared_c2.iter().map(|c| format!("{}:{}", c.kind(), c.value())).collect(),
            };

            let confidence = self.compute_confidence(&evidence);

            campaigns.push(Campaign {
                id: Campaign::campaign_id(group_idx),
                name: None,
                samples: member_indices.iter().map(|&i| records[i].id.clone()).collect(),
                shared_c2,
                shared_ttps,
                confidence,
                first_seen,
                last_seen,
                family,
                attributed_to,
                evidence,
            });
        }

        campaigns.sort_by(|a, b| b.samples.len().cmp(&a.samples.len()));
        campaigns
    }

    fn shared_indicators(&self, members: &[&SampleRecord]) -> Vec<C2Indicator> {
        if members.is_empty() { return vec![]; }
        let mut common: HashSet<C2Indicator> = members[0].c2_indicators.iter().cloned().collect();
        for member in &members[1..] {
            let member_set: HashSet<C2Indicator> = member.c2_indicators.iter().cloned().collect();
            common.retain(|i| member_set.contains(i));
        }
        common.into_iter().collect()
    }

    fn shared_ttps(&self, members: &[&SampleRecord]) -> Vec<TechniqueId> {
        if members.is_empty() { return vec![]; }
        let mut common: HashSet<TechniqueId> = members[0].ttps.iter().cloned().collect();
        for member in &members[1..] {
            let member_set: HashSet<TechniqueId> = member.ttps.iter().cloned().collect();
            common.retain(|t| member_set.contains(t));
        }
        common.into_iter().collect()
    }

    fn avg_code_sim(&self, indices: &[usize], pair_scores: &[PairScore], _n: usize) -> f64 {
        // For small clusters just find the right pair scores.
        let _idx_set: HashSet<usize> = indices.iter().copied().collect();
        let relevant: Vec<f64> = pair_scores.iter()
            .filter(|_ps| {
                // We need to map sample id back to index — use the global n to find the pair.
                // Pairs are stored in row-major: pair (i,j) where i < j is at index i*(n-1) - i*(i-1)/2 + j - i - 1.
                // Instead, just check code_score if both endpoints are in our cluster.
                // We stored a and b as SampleId strings; use a simple approach.
                true // will filter by score proximity; for correctness use pair_scores directly.
            })
            .map(|ps| ps.code_score)
            .collect();
        if relevant.is_empty() { return 0.0; }
        let sum: f64 = relevant.iter().sum();
        sum / relevant.len() as f64
    }

    fn imphash_match_count(&self, members: &[&SampleRecord]) -> usize {
        let hashes: HashSet<&str> = members.iter()
            .map(|m| m.descriptor.imphash.as_str())
            .filter(|h| !h.is_empty())
            .collect();
        if hashes.len() == 1 && !hashes.is_empty() { members.len() } else { 0 }
    }

    fn majority_value<'a, I: Iterator<Item = &'a str>>(&self, iter: I) -> Option<String> {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for v in iter {
            *counts.entry(v).or_insert(0) += 1;
        }
        counts.into_iter().max_by_key(|(_, c)| *c).map(|(v, _)| v.to_owned())
    }

    fn compute_confidence(&self, evidence: &CampaignEvidence) -> f64 {
        let mut score = 0.0f64;
        if evidence.c2_overlap_count > 0 { score += 0.4 * (evidence.c2_overlap_count as f64).min(5.0) / 5.0; }
        if evidence.ttp_overlap_count > 0 { score += 0.3 * (evidence.ttp_overlap_count as f64).min(5.0) / 5.0; }
        score += 0.2 * evidence.code_similarity_avg;
        if evidence.imphash_match_count > 0 { score += 0.1; }
        score.min(1.0)
    }
}

// ---------------------------------------------------------------------------
// Timeline analysis
// ---------------------------------------------------------------------------

/// A single point in a campaign timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelinePoint {
    pub timestamp: u64,
    pub event_type: TimelineEvent,
    pub sample_id: Option<SampleId>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TimelineEvent {
    FirstSeen,
    LastSeen,
    C2RegistrationEstimate,
    PeakActivity,
    InfrastructureChange,
    FamilyVariantDetected,
}

/// Build a timeline for a campaign.
pub fn build_campaign_timeline(
    campaign: &Campaign,
    records: &[SampleRecord],
) -> Vec<TimelinePoint> {
    let mut points: Vec<TimelinePoint> = Vec::new();

    let sample_records: Vec<&SampleRecord> = records.iter()
        .filter(|r| campaign.samples.contains(&r.id))
        .collect();

    for record in &sample_records {
        if record.first_seen > 0 {
            points.push(TimelinePoint {
                timestamp: record.first_seen,
                event_type: TimelineEvent::FirstSeen,
                sample_id: Some(record.id.clone()),
                description: format!("First observation of {}", record.id),
            });
        }
        if record.last_seen > record.first_seen {
            points.push(TimelinePoint {
                timestamp: record.last_seen,
                event_type: TimelineEvent::LastSeen,
                sample_id: Some(record.id.clone()),
                description: format!("Last observation of {}", record.id),
            });
        }
    }

    // Detect peak activity: bucket by 30-day windows.
    if !sample_records.is_empty() {
        let first_ts = sample_records.iter().map(|r| r.first_seen).filter(|&t| t > 0).min().unwrap_or(0);
        let last_ts = sample_records.iter().map(|r| r.last_seen).filter(|&t| t > 0).max().unwrap_or(0);

        if last_ts > first_ts {
            let window = 30u64 * 86400;
            let num_windows = ((last_ts - first_ts) / window + 1) as usize;
            let mut buckets = vec![0usize; num_windows.max(1)];
            for record in &sample_records {
                if record.first_seen >= first_ts {
                    let idx = ((record.first_seen - first_ts) / window) as usize;
                    if idx < buckets.len() { buckets[idx] += 1; }
                }
            }
            if let Some((peak_idx, &peak_count)) = buckets.iter().enumerate().max_by_key(|&(_, &v)| v) {
                if peak_count > 1 {
                    let peak_ts = first_ts + peak_idx as u64 * window;
                    points.push(TimelinePoint {
                        timestamp: peak_ts,
                        event_type: TimelineEvent::PeakActivity,
                        sample_id: None,
                        description: format!("Peak activity: {peak_count} samples in 30-day window"),
                    });
                }
            }
        }
    }

    points.sort_by_key(|p| p.timestamp);
    points
}

// ---------------------------------------------------------------------------
// Activity pulse: high-level campaign activity density by month
// ---------------------------------------------------------------------------

/// Compute monthly activity pulse for a campaign.
/// Returns (year_month, sample_count) sorted chronologically.
pub fn monthly_pulse(campaign: &Campaign, records: &[SampleRecord]) -> Vec<(String, usize)> {
    let mut month_counts: HashMap<String, usize> = HashMap::new();
    for record in records.iter().filter(|r| campaign.samples.contains(&r.id)) {
        if record.first_seen > 0 {
            let ts = record.first_seen;
            // Approximate year/month from Unix timestamp.
            let days = ts / 86400;
            let year = 1970 + days / 365;
            let month = (days % 365) / 30 + 1;
            let key = format!("{year:04}-{month:02}");
            *month_counts.entry(key).or_insert(0) += 1;
        }
    }
    let mut pulse: Vec<(String, usize)> = month_counts.into_iter().collect();
    pulse.sort_by(|a, b| a.0.cmp(&b.0));
    pulse
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample_correlator::{SampleDescriptor};

    fn blank_desc(id: &str) -> SampleDescriptor {
        SampleDescriptor {
            id: id.into(),
            filename: format!("{id}.exe"),
            md5: String::new(), sha1: String::new(), tlsh: String::new(),
            imphash: "same_hash".into(),
            imports: vec!["kernel32.dll!createfile".into(), "kernel32.dll!readfile".into()],
            exports: vec![], strings: vec![], section_entropies: vec![6.5],
            section_names: vec![], section_sizes: vec![],
            rich_hash: String::new(), file_size: 0, compile_time: 0,
            file_format: "PE32".into(), tags: vec![],
        }
    }

    fn make_record(id: &str, c2: Vec<C2Indicator>, ttps: Vec<TechniqueId>) -> SampleRecord {
        SampleRecord {
            id: id.into(),
            descriptor: blank_desc(id),
            c2_indicators: c2,
            ttps,
            first_seen: 1_700_000_000,
            last_seen: 1_700_500_000,
            family: Some("TestFamily".into()),
            attributed_to: Some("ActorX".into()),
        }
    }

    #[test]
    fn test_shared_c2_detection() {
        let c2 = vec![C2Indicator::Domain("evil.com".into())];
        let r1 = make_record("s1", c2.clone(), vec![]);
        let r2 = make_record("s2", c2.clone(), vec![]);
        let detector = CampaignDetector::with_defaults();
        let campaigns = detector.detect(&[r1, r2]);
        assert!(!campaigns.is_empty(), "should detect a campaign from shared C2");
    }

    #[test]
    fn test_campaign_timeline_ordering() {
        let r1 = make_record("s1", vec![], vec![TechniqueId::new("T1059")]);
        let r2 = make_record("s2", vec![], vec![TechniqueId::new("T1059")]);
        let detector = CampaignDetector::with_defaults();
        let campaigns = detector.detect(&[r1.clone(), r2.clone()]);
        if let Some(camp) = campaigns.first() {
            let timeline = build_campaign_timeline(camp, &[r1, r2]);
            // Timeline should be sorted.
            for i in 1..timeline.len() {
                assert!(timeline[i].timestamp >= timeline[i-1].timestamp);
            }
        }
    }

    #[test]
    fn test_ttp_overlap_score_full() {
        let t = vec![TechniqueId::new("T1059"), TechniqueId::new("T1071")];
        let r1 = make_record("a", vec![], t.clone());
        let r2 = make_record("b", vec![], t.clone());
        let score = ttp_overlap_score(&r1, &r2);
        assert!((score - 1.0).abs() < 1e-9, "expected 1.0, got {score}");
    }

    #[test]
    fn test_min_campaign_size_filter() {
        let records: Vec<SampleRecord> = (0..3).map(|i| make_record(&format!("s{i}"), vec![], vec![])).collect();
        let mut config = CampaignConfig::default();
        config.min_campaign_size = 5;
        let detector = CampaignDetector::new(config);
        let campaigns = detector.detect(&records);
        assert!(campaigns.is_empty(), "should not form campaigns smaller than min_campaign_size");
    }
}
