//! Campaign analysis: cluster detection, infrastructure overlap, TTP similarity,
//! temporal correlation, and campaign reporting.

use std::collections::HashSet;

pub use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── CampaignCluster ──────────────────────────────────────────────────────────

/// A cluster of related threat activity forming a campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignCluster {
    pub id: String,
    pub name: String,
    pub description: String,
    /// Indicator IDs belonging to this cluster.
    pub indicator_ids: Vec<String>,
    /// Attributed threat actor(s).
    pub attributed_actors: Vec<String>,
    /// MITRE ATT&CK technique IDs observed.
    pub ttp_ids: Vec<String>,
    /// Targeted sectors.
    pub target_sectors: Vec<String>,
    /// Targeted regions/countries.
    pub target_regions: Vec<String>,
    /// Malware families used.
    pub malware_families: Vec<String>,
    /// Cluster confidence (0–100).
    pub confidence: u8,
    /// First observed timestamp (Unix ms).
    pub first_seen_ms: u64,
    /// Last observed timestamp (Unix ms).
    pub last_seen_ms: u64,
    /// Tags.
    pub tags: Vec<String>,
}

impl CampaignCluster {
    /// Create a new cluster.
    #[must_use]
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            indicator_ids: vec![],
            attributed_actors: vec![],
            ttp_ids: vec![],
            target_sectors: vec![],
            target_regions: vec![],
            malware_families: vec![],
            confidence: 50,
            first_seen_ms: 0,
            last_seen_ms: 0,
            tags: vec![],
        }
    }

    /// Duration of the campaign in days.
    #[must_use]
    pub const fn duration_days(&self) -> u64 {
        if self.last_seen_ms <= self.first_seen_ms {
            return 0;
        }
        (self.last_seen_ms - self.first_seen_ms) / (86_400 * 1000)
    }

    /// Returns `true` if this cluster is high-confidence.
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 75
    }

    /// Add an indicator ID.
    pub fn add_indicator(&mut self, id: impl Into<String>) {
        self.indicator_ids.push(id.into());
    }
    /// Add a TTP.
    pub fn add_ttp(&mut self, ttp: impl Into<String>) {
        self.ttp_ids.push(ttp.into());
    }
    /// Add an actor.
    pub fn add_actor(&mut self, actor: impl Into<String>) {
        self.attributed_actors.push(actor.into());
    }
    /// Add a tag.
    pub fn tag(&mut self, t: impl Into<String>) {
        self.tags.push(t.into());
    }

    /// TTP count.
    #[must_use]
    pub const fn ttp_count(&self) -> usize {
        self.ttp_ids.len()
    }

    /// Returns `true` if two clusters share at least one TTP.
    #[must_use]
    pub fn shares_ttp(&self, other: &Self) -> bool {
        let a: HashSet<&str> = self.ttp_ids.iter().map(String::as_str).collect();
        other.ttp_ids.iter().any(|t| a.contains(t.as_str()))
    }

    /// Returns `true` if two clusters share at least one attributed actor.
    #[must_use]
    pub fn shares_actor(&self, other: &Self) -> bool {
        let a: HashSet<&str> = self.attributed_actors.iter().map(String::as_str).collect();
        other
            .attributed_actors
            .iter()
            .any(|x| a.contains(x.as_str()))
    }
}

// ─── InfrastructureOverlap ────────────────────────────────────────────────────

/// Shared infrastructure between two campaigns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureOverlap {
    pub campaign_a: String,
    pub campaign_b: String,
    pub shared_ips: Vec<String>,
    pub shared_domains: Vec<String>,
    pub shared_asns: Vec<u32>,
    pub overlap_score: f64,
}

impl InfrastructureOverlap {
    /// Compute overlap from two sets of IOC values.
    #[must_use]
    pub fn compute(
        campaign_a: impl Into<String>,
        campaign_b: impl Into<String>,
        iocs_a: &[&str],
        iocs_b: &[&str],
    ) -> Self {
        let set_a: HashSet<&str> = iocs_a.iter().copied().collect();
        let set_b: HashSet<&str> = iocs_b.iter().copied().collect();
        let shared: Vec<String> = set_a.intersection(&set_b).map(std::string::ToString::to_string).collect();
        let total = set_a.len() + set_b.len();
        let score = if total == 0 {
            0.0
        } else {
            (shared.len() as f64) * 2.0 / (total as f64)
        };

        // Heuristic split: IPs look like n.n.n.n
        let (ips, domains): (Vec<&String>, Vec<&String>) = shared.iter().partition(|s| {
            s.chars().filter(|&c| c == '.').count() == 3
                && s.split('.').all(|p| p.parse::<u8>().is_ok())
        });
        let ips: Vec<String> = ips.into_iter().cloned().collect();
        let domains: Vec<String> = domains.into_iter().cloned().collect();

        Self {
            campaign_a: campaign_a.into(),
            campaign_b: campaign_b.into(),
            shared_ips: ips,
            shared_domains: domains,
            shared_asns: vec![],
            overlap_score: score,
        }
    }

    /// Returns `true` if there is meaningful overlap.
    #[must_use]
    pub fn is_significant(&self, threshold: f64) -> bool {
        self.overlap_score >= threshold
    }

    /// Total shared indicators.
    #[must_use]
    pub const fn total_shared(&self) -> usize {
        self.shared_ips.len() + self.shared_domains.len() + self.shared_asns.len()
    }
}

// ─── TtpSimilarity ────────────────────────────────────────────────────────────

/// Measures TTP similarity between two clusters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtpSimilarity {
    pub cluster_a: String,
    pub cluster_b: String,
    pub shared_ttps: Vec<String>,
    pub jaccard_score: f64,
    pub is_related: bool,
}

impl TtpSimilarity {
    /// Compute Jaccard similarity between two TTP sets.
    #[must_use]
    pub fn compute(cluster_a: &CampaignCluster, cluster_b: &CampaignCluster) -> Self {
        let set_a: HashSet<&str> = cluster_a.ttp_ids.iter().map(String::as_str).collect();
        let set_b: HashSet<&str> = cluster_b.ttp_ids.iter().map(String::as_str).collect();
        let intersection: Vec<String> = set_a.intersection(&set_b).map(std::string::ToString::to_string).collect();
        let union_size = set_a.union(&set_b).count();
        let jaccard = if union_size == 0 {
            0.0
        } else {
            (intersection.len() as f64) / (union_size as f64)
        };

        Self {
            cluster_a: cluster_a.id.clone(),
            cluster_b: cluster_b.id.clone(),
            shared_ttps: intersection,
            jaccard_score: jaccard,
            is_related: jaccard >= 0.3,
        }
    }

    /// Shared TTP count.
    #[must_use]
    pub const fn shared_count(&self) -> usize {
        self.shared_ttps.len()
    }
}

// ─── TemporalCorrelation ──────────────────────────────────────────────────────

/// Temporal relationship between two campaigns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalCorrelation {
    pub cluster_a: String,
    pub cluster_b: String,
    pub gap_days: i64,
    pub overlap_days: u64,
    pub relationship: TemporalRelationship,
}

/// How two campaigns relate temporally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TemporalRelationship {
    /// A ended before B started.
    Sequential,
    /// B started while A was active.
    Overlapping,
    /// A and B active at exactly the same time.
    Concurrent,
    /// A started after B ended.
    BPrecedesA,
}

impl fmt::Display for TemporalRelationship {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sequential => write!(f, "sequential"),
            Self::Overlapping => write!(f, "overlapping"),
            Self::Concurrent => write!(f, "concurrent"),
            Self::BPrecedesA => write!(f, "b_precedes_a"),
        }
    }
}

impl TemporalCorrelation {
    /// Compute the temporal relationship between two clusters.
    #[must_use]
    pub fn compute(a: &CampaignCluster, b: &CampaignCluster) -> Self {
        let gap_ms: i64 = b.first_seen_ms.cast_signed() - a.last_seen_ms.cast_signed();
        let gap_days = gap_ms / (86_400_000i64);

        let overlap_start = a.first_seen_ms.max(b.first_seen_ms);
        let overlap_end = a.last_seen_ms.min(b.last_seen_ms);
        let overlap_days = if overlap_end > overlap_start {
            (overlap_end - overlap_start) / (86_400 * 1000)
        } else {
            0
        };

        let relationship = if a.first_seen_ms == b.first_seen_ms && a.last_seen_ms == b.last_seen_ms
        {
            TemporalRelationship::Concurrent
        } else if overlap_days > 0 {
            TemporalRelationship::Overlapping
        } else if gap_ms >= 0 {
            TemporalRelationship::Sequential
        } else {
            TemporalRelationship::BPrecedesA
        };

        Self {
            cluster_a: a.id.clone(),
            cluster_b: b.id.clone(),
            gap_days,
            overlap_days,
            relationship,
        }
    }
}

// ─── CampaignReport ───────────────────────────────────────────────────────────

/// A comprehensive campaign analysis report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignReport {
    pub title: String,
    pub case_id: String,
    pub clusters: Vec<CampaignCluster>,
    pub infrastructure_overlaps: Vec<InfrastructureOverlap>,
    pub ttp_similarities: Vec<TtpSimilarity>,
    pub temporal_correlations: Vec<TemporalCorrelation>,
    pub related_cluster_pairs: Vec<(String, String)>,
    pub total_indicators: usize,
    pub high_confidence_clusters: usize,
    pub executive_summary: String,
}

impl CampaignReport {
    /// Create a new report.
    #[must_use]
    pub fn new(title: impl Into<String>, case_id: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            case_id: case_id.into(),
            clusters: vec![],
            infrastructure_overlaps: vec![],
            ttp_similarities: vec![],
            temporal_correlations: vec![],
            related_cluster_pairs: vec![],
            total_indicators: 0,
            high_confidence_clusters: 0,
            executive_summary: String::new(),
        }
    }

    /// Render report as Markdown.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = format!("# {}\n\n**Case:** {}\n\n", self.title, self.case_id);
        use std::fmt::Write as _;
        let _ = write!(out, "**Summary:** {}\n\n", self.executive_summary);
        let _ = write!(
            out,
            "Total clusters: {} | High-confidence: {} | Total indicators: {}\n\n",
            self.clusters.len(),
            self.high_confidence_clusters,
            self.total_indicators
        );
        out.push_str("## Clusters\n\n");
        for c in &self.clusters {
            let _ = write!(out, "### {} ({})\n", c.name, c.id);
            let _ = write!(out, "- Confidence: {}%\n", c.confidence);
            let _ = write!(out, "- TTPs: {}\n", c.ttp_ids.join(", "));
            let _ = write!(out, "- Actors: {}\n\n", c.attributed_actors.join(", "));
        }
        out.push_str("## Infrastructure Overlaps\n\n");
        for ov in &self.infrastructure_overlaps {
            let _ = write!(
                out,
                "- {} ↔ {} (score: {:.2})\n",
                ov.campaign_a, ov.campaign_b, ov.overlap_score
            );
        }
        out
    }

    /// Render report as JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

// ─── CampaignAnalysis ─────────────────────────────────────────────────────────

/// Main campaign analysis engine.
pub struct CampaignAnalysis {
    pub clusters: Vec<CampaignCluster>,
    /// Minimum Jaccard score to mark two clusters as related.
    pub ttp_threshold: f64,
    /// Minimum infrastructure overlap score to flag shared infrastructure.
    pub infra_threshold: f64,
}

impl CampaignAnalysis {
    /// Create a new analysis engine.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            clusters: vec![],
            ttp_threshold: 0.3,
            infra_threshold: 0.1,
        }
    }

    /// Add a cluster.
    pub fn add_cluster(&mut self, cluster: CampaignCluster) {
        self.clusters.push(cluster);
    }

    /// Compute all pairwise TTP similarities.
    #[must_use]
    pub fn compute_ttp_similarities(&self) -> Vec<TtpSimilarity> {
        let mut results = Vec::new();
        for i in 0..self.clusters.len() {
            for j in (i + 1)..self.clusters.len() {
                let sim = TtpSimilarity::compute(&self.clusters[i], &self.clusters[j]);
                if sim.jaccard_score > 0.0 {
                    results.push(sim);
                }
            }
        }
        results
    }

    /// Compute all pairwise temporal correlations.
    #[must_use]
    pub fn compute_temporal_correlations(&self) -> Vec<TemporalCorrelation> {
        let mut results = Vec::new();
        for i in 0..self.clusters.len() {
            for j in (i + 1)..self.clusters.len() {
                let tc = TemporalCorrelation::compute(&self.clusters[i], &self.clusters[j]);
                results.push(tc);
            }
        }
        results
    }

    /// Identify clusters likely belonging to the same actor.
    #[must_use]
    pub fn related_cluster_pairs(&self) -> Vec<(String, String)> {
        let sims = self.compute_ttp_similarities();
        sims.iter()
            .filter(|s| s.is_related)
            .map(|s| (s.cluster_a.clone(), s.cluster_b.clone()))
            .collect()
    }

    /// Build the full campaign report.
    #[must_use]
    pub fn generate_report(&self, title: &str, case_id: &str) -> CampaignReport {
        let ttp_sims = self.compute_ttp_similarities();
        let temporal = self.compute_temporal_correlations();
        let related = self.related_cluster_pairs();
        let total_indicators: usize = self.clusters.iter().map(|c| c.indicator_ids.len()).sum();
        let high_conf = self
            .clusters
            .iter()
            .filter(|c| c.is_high_confidence())
            .count();

        CampaignReport {
            title: title.to_string(),
            case_id: case_id.to_string(),
            clusters: self.clusters.clone(),
            infrastructure_overlaps: vec![],
            ttp_similarities: ttp_sims,
            temporal_correlations: temporal,
            related_cluster_pairs: related,
            total_indicators,
            high_confidence_clusters: high_conf,
            executive_summary: format!(
                "Analysis of {} campaign cluster(s) with {} total indicators.",
                self.clusters.len(),
                total_indicators
            ),
        }
    }

    /// Build a mock analysis for testing.
    #[must_use]
    pub fn mock() -> Self {
        let mut analysis = Self::new();

        let mut c1 = CampaignCluster::new("CAMP-001", "Operation DarkSide 2023");
        c1.confidence = 85;
        c1.first_seen_ms = 1_680_000_000_000;
        c1.last_seen_ms = 1_690_000_000_000;
        c1.add_actor("APT28");
        c1.add_ttp("T1055");
        c1.add_ttp("T1486");
        c1.add_ttp("T1071.001");
        c1.add_indicator("IND-001");
        c1.add_indicator("IND-002");
        c1.malware_families.push("SOFACY".into());
        c1.target_sectors.push("energy".into());
        c1.tag("ransomware");
        analysis.add_cluster(c1);

        let mut c2 = CampaignCluster::new("CAMP-002", "Operation IceFire 2023");
        c2.confidence = 70;
        c2.first_seen_ms = 1_688_000_000_000;
        c2.last_seen_ms = 1_695_000_000_000;
        c2.add_actor("APT28");
        c2.add_ttp("T1055");
        c2.add_ttp("T1059.001");
        c2.add_ttp("T1071.001");
        c2.add_indicator("IND-003");
        c2.malware_families.push("IceFire".into());
        c2.target_sectors.push("finance".into());
        analysis.add_cluster(c2);

        let mut c3 = CampaignCluster::new("CAMP-003", "Operation Ghost 2022");
        c3.confidence = 55;
        c3.first_seen_ms = 1_640_000_000_000;
        c3.last_seen_ms = 1_660_000_000_000;
        c3.add_actor("APT29");
        c3.add_ttp("T1547.001");
        c3.add_ttp("T1003.001");
        c3.add_indicator("IND-004");
        c3.target_regions.push("europe".into());
        analysis.add_cluster(c3);

        analysis
    }
}

impl Default for CampaignAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mock() -> CampaignAnalysis {
        CampaignAnalysis::mock()
    }

    // CampaignCluster
    #[test]
    fn test_cluster_new() {
        let c = CampaignCluster::new("C1", "Test Campaign");
        assert_eq!(c.id, "C1");
        assert!(!c.is_high_confidence());
    }
    #[test]
    fn test_cluster_high_confidence() {
        let mut c = CampaignCluster::new("C1", "Test");
        c.confidence = 80;
        assert!(c.is_high_confidence());
    }
    #[test]
    fn test_cluster_duration_days() {
        let mut c = CampaignCluster::new("C1", "Test");
        c.first_seen_ms = 0;
        c.last_seen_ms = 7 * 86_400 * 1000;
        assert_eq!(c.duration_days(), 7);
    }
    #[test]
    fn test_cluster_duration_zero_if_same() {
        let mut c = CampaignCluster::new("C1", "Test");
        c.first_seen_ms = 1000;
        c.last_seen_ms = 1000;
        assert_eq!(c.duration_days(), 0);
    }
    #[test]
    fn test_cluster_shares_ttp() {
        let mut a = CampaignCluster::new("A", "");
        a.add_ttp("T1055");
        a.add_ttp("T1486");
        let mut b = CampaignCluster::new("B", "");
        b.add_ttp("T1055");
        assert!(a.shares_ttp(&b));
    }
    #[test]
    fn test_cluster_no_shares_ttp() {
        let mut a = CampaignCluster::new("A", "");
        a.add_ttp("T1055");
        let mut b = CampaignCluster::new("B", "");
        b.add_ttp("T1486");
        assert!(!a.shares_ttp(&b));
    }
    #[test]
    fn test_cluster_shares_actor() {
        let mut a = CampaignCluster::new("A", "");
        a.add_actor("APT28");
        let mut b = CampaignCluster::new("B", "");
        b.add_actor("APT28");
        assert!(a.shares_actor(&b));
    }
    #[test]
    fn test_cluster_ttp_count() {
        let m = mock();
        assert!(m.clusters[0].ttp_count() >= 3);
    }

    // InfrastructureOverlap
    #[test]
    fn test_infra_overlap_shared() {
        let ov = InfrastructureOverlap::compute(
            "A",
            "B",
            &["1.2.3.4", "evil.com"],
            &["1.2.3.4", "good.com"],
        );
        assert!(ov.overlap_score > 0.0);
    }
    #[test]
    fn test_infra_overlap_none() {
        let ov = InfrastructureOverlap::compute("A", "B", &["1.2.3.4"], &["5.6.7.8"]);
        assert_eq!(ov.overlap_score, 0.0);
    }
    #[test]
    fn test_infra_overlap_is_significant() {
        let ov = InfrastructureOverlap::compute(
            "A",
            "B",
            &["1.2.3.4", "evil.com"],
            &["1.2.3.4", "evil.com"],
        );
        assert!(ov.is_significant(0.5));
    }
    #[test]
    fn test_infra_overlap_total_shared() {
        let ov = InfrastructureOverlap::compute("A", "B", &["1.2.3.4"], &["1.2.3.4", "other.com"]);
        assert_eq!(ov.total_shared(), 1);
    }

    // TtpSimilarity
    #[test]
    fn test_ttp_similarity_compute() {
        let m = mock();
        let sim = TtpSimilarity::compute(&m.clusters[0], &m.clusters[1]);
        assert!(sim.jaccard_score > 0.0);
        assert!(sim.is_related);
    }
    #[test]
    fn test_ttp_similarity_no_overlap() {
        let m = mock();
        let sim = TtpSimilarity::compute(&m.clusters[0], &m.clusters[2]);
        assert_eq!(sim.jaccard_score, 0.0);
        assert!(!sim.is_related);
    }
    #[test]
    fn test_ttp_similarity_shared_count() {
        let m = mock();
        let sim = TtpSimilarity::compute(&m.clusters[0], &m.clusters[1]);
        assert!(sim.shared_count() >= 2);
    }

    // TemporalCorrelation
    #[test]
    fn test_temporal_sequential() {
        let mut a = CampaignCluster::new("A", "");
        a.first_seen_ms = 0;
        a.last_seen_ms = 1000;
        let mut b = CampaignCluster::new("B", "");
        b.first_seen_ms = 2000;
        b.last_seen_ms = 3000;
        let tc = TemporalCorrelation::compute(&a, &b);
        assert_eq!(tc.relationship, TemporalRelationship::Sequential);
    }
    #[test]
    fn test_temporal_overlapping() {
        let mut a = CampaignCluster::new("A", "");
        a.first_seen_ms = 0;
        a.last_seen_ms = 100 * 86_400_000;
        let mut b = CampaignCluster::new("B", "");
        b.first_seen_ms = 50 * 86_400_000;
        b.last_seen_ms = 200 * 86_400_000;
        let tc = TemporalCorrelation::compute(&a, &b);
        assert_eq!(tc.relationship, TemporalRelationship::Overlapping);
    }
    #[test]
    fn test_temporal_concurrent() {
        let mut a = CampaignCluster::new("A", "");
        a.first_seen_ms = 1000;
        a.last_seen_ms = 2000;
        let mut b = CampaignCluster::new("B", "");
        b.first_seen_ms = 1000;
        b.last_seen_ms = 2000;
        let tc = TemporalCorrelation::compute(&a, &b);
        assert_eq!(tc.relationship, TemporalRelationship::Concurrent);
    }
    #[test]
    fn test_temporal_display() {
        assert_eq!(TemporalRelationship::Sequential.to_string(), "sequential");
    }

    // CampaignAnalysis
    #[test]
    fn test_analysis_new() {
        let a = CampaignAnalysis::new();
        assert!(a.clusters.is_empty());
    }
    #[test]
    fn test_analysis_add_cluster() {
        let mut a = CampaignAnalysis::new();
        a.add_cluster(CampaignCluster::new("C1", "test"));
        assert_eq!(a.clusters.len(), 1);
    }
    #[test]
    fn test_analysis_ttp_similarities() {
        let m = mock();
        let sims = m.compute_ttp_similarities();
        assert!(!sims.is_empty());
    }
    #[test]
    fn test_analysis_temporal_correlations() {
        let m = mock();
        let tc = m.compute_temporal_correlations();
        assert!(!tc.is_empty());
    }
    #[test]
    fn test_analysis_related_pairs() {
        let m = mock();
        let pairs = m.related_cluster_pairs();
        assert!(!pairs.is_empty());
    }
    #[test]
    fn test_analysis_report() {
        let m = mock();
        let report = m.generate_report("Test Report", "CASE-001");
        assert_eq!(report.clusters.len(), 3);
        assert!(report.total_indicators > 0);
    }
    #[test]
    fn test_report_markdown() {
        let m = mock();
        let report = m.generate_report("Test", "C-001");
        let md = report.to_markdown();
        assert!(md.contains("Test"));
    }
    #[test]
    fn test_report_json() {
        let m = mock();
        let report = m.generate_report("Test", "C-001");
        let json = report.to_json();
        assert!(json.contains("CAMP-"));
    }
    #[test]
    fn test_analysis_mock_clusters_count() {
        let m = mock();
        assert_eq!(m.clusters.len(), 3);
    }
    #[test]
    fn test_analysis_high_confidence_count() {
        let m = mock();
        let report = m.generate_report("T", "C");
        assert!(report.high_confidence_clusters >= 1);
    }
    #[test]
    fn test_cluster_malware_family() {
        let m = mock();
        assert!(
            m.clusters[0]
                .malware_families
                .contains(&"SOFACY".to_string())
        );
    }
    #[test]
    fn test_cluster_target_sector() {
        let m = mock();
        assert!(m.clusters[0].target_sectors.contains(&"energy".to_string()));
    }
    #[test]
    fn test_cluster_target_region() {
        let m = mock();
        assert!(m.clusters[2].target_regions.contains(&"europe".to_string()));
    }
    #[test]
    fn test_ttp_sim_empty_sets() {
        let a = CampaignCluster::new("A", "");
        let b = CampaignCluster::new("B", "");
        let sim = TtpSimilarity::compute(&a, &b);
        assert_eq!(sim.jaccard_score, 0.0);
    }
    #[test]
    fn test_campaign_report_new() {
        let r = CampaignReport::new("Title", "CASE-X");
        assert_eq!(r.title, "Title");
    }
}
