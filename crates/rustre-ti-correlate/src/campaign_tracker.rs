//! Campaign tracking — cluster threat reports into coherent malware campaigns.
//!
//! [`CampaignTracker`] maintains a live set of [`Campaign`] objects, each
//! representing a group of related threat reports, IoCs, and TTPs that appear
//! to share the same adversary objective or infrastructure.  The tracker
//! accepts new [`CampaignLink`] observations and uses a Union-Find algorithm
//! to merge campaigns that share enough evidence.
//!
//! The top-level entry point is [`cluster_by_ttps`], which takes a slice of
//! [`rustre_threatintel::ThreatReport`] values and returns a fully-populated
//! `CampaignTracker`.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use rustre_threatintel::{Ttp, ThreatReport};

// ---------------------------------------------------------------------------
// CampaignLink — evidence that two reports belong to the same campaign
// ---------------------------------------------------------------------------

/// A link between two threat reports that are believed to belong to the same
/// campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignLink {
    /// Identifier of the first report.
    pub report_a: String,
    /// Identifier of the second report.
    pub report_b: String,
    /// Evidence type that justifies the link.
    pub evidence: LinkEvidence,
    /// Confidence in the link, 0–100.
    pub confidence: u8,
    /// Optional description.
    pub description: Option<String>,
}

impl CampaignLink {
    /// Create a new link.
    #[must_use]
    pub fn new(
        report_a: impl Into<String>,
        report_b: impl Into<String>,
        evidence: LinkEvidence,
        confidence: u8,
    ) -> Self {
        Self {
            report_a: report_a.into(),
            report_b: report_b.into(),
            evidence,
            confidence,
            description: None,
        }
    }

    /// Attach a description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

impl fmt::Display for CampaignLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ↔ {} [{}] conf={}",
            self.report_a, self.report_b, self.evidence, self.confidence
        )
    }
}

/// The type of evidence linking two reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkEvidence {
    /// Shared MITRE ATT&CK TTPs.
    SharedTtp,
    /// Shared network infrastructure (IP / domain overlap).
    SharedInfrastructure,
    /// Code / binary similarity above a threshold.
    CodeSimilarity,
    /// Shared malware family.
    SharedFamily,
    /// Temporal proximity (reports within a tight time window).
    TemporalProximity,
    /// Analyst-supplied manual link.
    Manual,
    /// Custom evidence with a label.
    Custom(String),
}

impl fmt::Display for LinkEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SharedTtp            => write!(f, "shared-ttp"),
            Self::SharedInfrastructure => write!(f, "shared-infra"),
            Self::CodeSimilarity       => write!(f, "code-sim"),
            Self::SharedFamily         => write!(f, "shared-family"),
            Self::TemporalProximity    => write!(f, "temporal"),
            Self::Manual               => write!(f, "manual"),
            Self::Custom(s)            => write!(f, "custom:{}", s),
        }
    }
}

// ---------------------------------------------------------------------------
// Campaign
// ---------------------------------------------------------------------------

/// A coherent cluster of threat reports attributed to the same adversary
/// campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Campaign {
    /// Unique identifier (assigned by the tracker).
    pub id: u64,
    /// Optional human-readable name (may be auto-generated).
    pub name: Option<String>,
    /// Report identifiers belonging to this campaign.
    pub members: HashSet<String>,
    /// All evidence links within this campaign.
    pub links: Vec<CampaignLink>,
    /// Union of all TTPs observed across member reports.
    pub ttps: HashSet<String>,
    /// Confidence score for the cluster, 0–100.
    pub confidence: u8,
}

impl Campaign {
    /// Create a new empty campaign.
    #[must_use]
    pub fn new(id: u64) -> Self {
        Self {
            id,
            name: None,
            members: HashSet::new(),
            links: Vec::new(),
            ttps: HashSet::new(),
            confidence: 50,
        }
    }

    /// Add a member report.
    pub fn add_member(&mut self, report_id: impl Into<String>) {
        self.members.insert(report_id.into());
    }

    /// Add a link and update the confidence.
    pub fn add_link(&mut self, link: CampaignLink) {
        let conf = link.confidence;
        self.links.push(link);
        // Update campaign confidence as a running average, then bias slightly
        // toward the most recent evidence (`conf`) so high-confidence links
        // immediately raise our trust in the campaign cluster.
        // Use u64 for the sum to avoid overflow when many links are present.
        let total: u64 = self.links.iter().map(|l| u64::from(l.confidence)).sum();
        let avg = (total / self.links.len() as u64).min(100) as u8;
        self.confidence = avg.saturating_add(conf / 32).min(100);
    }

    /// Add TTPs (as raw IDs).
    pub fn add_ttps(&mut self, ttps: impl IntoIterator<Item = impl Into<String>>) {
        for t in ttps {
            self.ttps.insert(t.into());
        }
    }

    /// Add structured [`Ttp`] objects, indexing them by their `id` field.
    /// Returns the number of *new* TTPs added.
    pub fn add_ttp_objects<'a>(&mut self, ttps: impl IntoIterator<Item = &'a Ttp>) -> usize {
        let mut added = 0;
        for t in ttps {
            if self.ttps.insert(t.technique_id.clone()) {
                added += 1;
            }
        }
        added
    }

    /// Size of the campaign (number of member reports).
    #[must_use]
    pub fn size(&self) -> usize {
        self.members.len()
    }

    /// Jaccard similarity to another campaign based on TTP overlap.
    #[must_use]
    pub fn ttp_jaccard(&self, other: &Campaign) -> f64 {
        let inter = self.ttps.intersection(&other.ttps).count();
        let union = self.ttps.union(&other.ttps).count();
        if union == 0 { return 1.0; }
        inter as f64 / union as f64
    }

    /// Auto-generate a name from the largest shared TTP if none is set.
    #[must_use]
    pub fn display_name(&self) -> String {
        if let Some(ref n) = self.name {
            return n.clone();
        }
        if let Some(ttp) = self.ttps.iter().next() {
            return format!("Campaign-{}-{}", self.id, ttp);
        }
        format!("Campaign-{}", self.id)
    }
}

impl fmt::Display for Campaign {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} members={} ttps={} conf={}",
            self.display_name(),
            self.size(),
            self.ttps.len(),
            self.confidence
        )
    }
}

// ---------------------------------------------------------------------------
// Union-Find
// ---------------------------------------------------------------------------

struct UnionFind {
    parent: Vec<usize>,
    rank: Vec<usize>,
}

impl UnionFind {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
            rank: vec![0; n],
        }
    }

    fn find(&mut self, x: usize) -> usize {
        if self.parent[x] != x {
            self.parent[x] = self.find(self.parent[x]);
        }
        self.parent[x]
    }

    fn union(&mut self, x: usize, y: usize) {
        let rx = self.find(x);
        let ry = self.find(y);
        if rx == ry { return; }
        match self.rank[rx].cmp(&self.rank[ry]) {
            std::cmp::Ordering::Less    => self.parent[rx] = ry,
            std::cmp::Ordering::Greater => self.parent[ry] = rx,
            std::cmp::Ordering::Equal   => {
                self.parent[ry] = rx;
                self.rank[rx] += 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CampaignTracker
// ---------------------------------------------------------------------------

/// Maintains a live set of campaigns.
pub struct CampaignTracker {
    campaigns: Vec<Campaign>,
    report_to_campaign: HashMap<String, u64>,
    next_id: u64,
    /// Minimum TTP Jaccard similarity to auto-link two reports.
    pub min_ttp_similarity: f64,
    /// Minimum confidence required to form a link.
    pub min_link_confidence: u8,
}

impl Default for CampaignTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl CampaignTracker {
    /// Create a new tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            campaigns: Vec::new(),
            report_to_campaign: HashMap::new(),
            next_id: 1,
            min_ttp_similarity: 0.3,
            min_link_confidence: 50,
        }
    }

    /// Override the minimum TTP Jaccard similarity threshold.
    pub fn with_min_ttp_similarity(mut self, t: f64) -> Self {
        self.min_ttp_similarity = t;
        self
    }

    /// Override the minimum link confidence.
    pub fn with_min_link_confidence(mut self, c: u8) -> Self {
        self.min_link_confidence = c;
        self
    }

    /// Register a new campaign link and merge campaigns as needed.
    ///
    /// If either endpoint already belongs to a campaign the two campaigns are
    /// merged; otherwise a new campaign is created.
    pub fn add_link(&mut self, link: CampaignLink) {
        if link.confidence < self.min_link_confidence {
            return;
        }
        let campaign_a = self.report_to_campaign.get(&link.report_a).copied();
        let campaign_b = self.report_to_campaign.get(&link.report_b).copied();

        match (campaign_a, campaign_b) {
            (None, None) => {
                // New campaign for both
                let id = self.new_id();
                let mut c = Campaign::new(id);
                c.add_member(link.report_a.clone());
                c.add_member(link.report_b.clone());
                self.report_to_campaign.insert(link.report_a.clone(), id);
                self.report_to_campaign.insert(link.report_b.clone(), id);
                c.add_link(link);
                self.campaigns.push(c);
            }
            (Some(id), None) => {
                let report_b = link.report_b.clone();
                self.report_to_campaign.insert(report_b.clone(), id);
                if let Some(c) = self.campaigns.iter_mut().find(|c| c.id == id) {
                    c.add_member(report_b);
                    c.add_link(link);
                }
            }
            (None, Some(id)) => {
                let report_a = link.report_a.clone();
                self.report_to_campaign.insert(report_a.clone(), id);
                if let Some(c) = self.campaigns.iter_mut().find(|c| c.id == id) {
                    c.add_member(report_a);
                    c.add_link(link);
                }
            }
            (Some(ia), Some(ib)) if ia == ib => {
                // Already in same campaign — just add the link
                if let Some(c) = self.campaigns.iter_mut().find(|c| c.id == ia) {
                    c.add_link(link);
                }
            }
            (Some(ia), Some(ib)) => {
                // Merge campaign ib into ia
                self.merge_campaigns(ia, ib, link);
            }
        }
    }

    /// Return all campaigns.
    #[must_use]
    pub fn campaigns(&self) -> &[Campaign] {
        &self.campaigns
    }

    /// Find the campaign a report belongs to.
    #[must_use]
    pub fn campaign_for_report(&self, report_id: &str) -> Option<&Campaign> {
        let id = self.report_to_campaign.get(report_id)?;
        self.campaigns.iter().find(|c| c.id == *id)
    }

    /// Total number of campaigns.
    #[must_use]
    pub fn len(&self) -> usize {
        self.campaigns.len()
    }

    /// Returns `true` when no campaigns have been created.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.campaigns.is_empty()
    }

    /// Produce a sorted listing.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut lines = vec![format!(
            "CampaignTracker: {} campaigns",
            self.campaigns.len()
        )];
        let mut sorted = self.campaigns.clone();
        sorted.sort_by(|a, b| b.size().cmp(&a.size()));
        for c in &sorted {
            lines.push(format!("  {}", c));
        }
        lines.join("\n")
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn new_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn merge_campaigns(&mut self, keep: u64, absorb: u64, link: CampaignLink) {
        // Collect the absorb campaign's data
        let absorb_idx = match self.campaigns.iter().position(|c| c.id == absorb) {
            Some(i) => i,
            None => return,
        };
        let absorbed = self.campaigns.swap_remove(absorb_idx);

        // Redirect all absorbed members
        for member in &absorbed.members {
            self.report_to_campaign.insert(member.clone(), keep);
        }

        // Merge into keep
        if let Some(c) = self.campaigns.iter_mut().find(|c| c.id == keep) {
            for member in absorbed.members {
                c.add_member(member);
            }
            for l in absorbed.links {
                c.links.push(l);
            }
            c.add_link(link);
            for ttp in absorbed.ttps {
                c.ttps.insert(ttp);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// cluster_by_ttps — top-level entry point
// ---------------------------------------------------------------------------

/// Cluster [`ThreatReport`] values into campaigns based on TTP overlap.
///
/// Reports sharing at least `min_jaccard` TTP Jaccard similarity are linked
/// with [`LinkEvidence::SharedTtp`].
#[must_use]
pub fn cluster_by_ttps(reports: &[ThreatReport], min_jaccard: f64) -> CampaignTracker {
    let mut tracker = CampaignTracker::new()
        .with_min_ttp_similarity(min_jaccard)
        .with_min_link_confidence(0);

    // Extract TTP sets per report
    let ttp_sets: Vec<HashSet<String>> = reports
        .iter()
        .map(|r| r.ttps.iter().map(|t| format!("{:?}", t)).collect())
        .collect();

    let n = reports.len();
    // Union-Find to build clusters
    let mut uf = UnionFind::new(n);

    for i in 0..n {
        for j in (i + 1)..n {
            let inter = ttp_sets[i].intersection(&ttp_sets[j]).count();
            let union = ttp_sets[i].union(&ttp_sets[j]).count();
            if union == 0 { continue; }
            let jaccard = inter as f64 / union as f64;
            if jaccard >= min_jaccard {
                uf.union(i, j);
            }
        }
    }

    // Convert Union-Find roots into CampaignLinks and push them
    let mut root_to_reports: HashMap<usize, Vec<usize>> = HashMap::new();
    for i in 0..n {
        let root = uf.find(i);
        root_to_reports.entry(root).or_default().push(i);
    }

    for (_, members) in &root_to_reports {
        if members.len() < 2 {
            continue;
        }
        // Emit links between consecutive members
        for window in members.windows(2) {
            let a = &reports[window[0]];
            let b = &reports[window[1]];
            let inter = ttp_sets[window[0]].intersection(&ttp_sets[window[1]]).count();
            let union = ttp_sets[window[0]].union(&ttp_sets[window[1]]).count();
            let jaccard = if union == 0 { 1.0 } else { inter as f64 / union as f64 };
            let conf = (jaccard * 100.0) as u8;
            let link = CampaignLink::new(
                a.id.map(|v| v.to_string()).unwrap_or_default(),
                b.id.map(|v| v.to_string()).unwrap_or_default(),
                LinkEvidence::SharedTtp,
                conf,
            );
            tracker.add_link(link);
        }
        // Add TTPs to the resulting campaign
        let id_a = reports[members[0]].id.map(|v| v.to_string()).unwrap_or_default();
        if let Some(c) = tracker.campaigns.iter_mut().find(|c| c.members.contains(id_a.as_str())) {
            for &idx in members {
                for ttp_str in &ttp_sets[idx] {
                    c.ttps.insert(ttp_str.clone());
                }
            }
        }
    }

    tracker
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_threatintel::TlpLevel;

    fn make_report(id: &str, ttps: &[&str]) -> ThreatReport {
        let numeric_id = id.chars().filter(|c| c.is_ascii_digit()).collect::<String>().parse::<u64>().ok();
        ThreatReport {
            id: numeric_id,
            title: id.to_string(),
            description: String::new(),
            tlp: TlpLevel::White,
            iocs: Vec::new(),
            malware_families: Vec::new(),
            threat_actors: Vec::new(),
            ttps: ttps.iter().map(|s| Ttp {
                technique_id: s.to_string(),
                name: s.to_string(),
                tactic: String::new(),
                sub_technique: None,
            }).collect(),
            created_at: 0,
            updated_at: 0,
            author: String::new(),
            tags: Vec::new(),
        }
    }

    #[test]
    fn test_add_link_creates_campaign() {
        let mut tracker = CampaignTracker::new().with_min_link_confidence(0);
        let link = CampaignLink::new("R1", "R2", LinkEvidence::SharedTtp, 80);
        tracker.add_link(link);
        assert_eq!(tracker.len(), 1);
        let c = &tracker.campaigns()[0];
        assert!(c.members.contains("R1"));
        assert!(c.members.contains("R2"));
    }

    #[test]
    fn test_add_link_extends_existing_campaign() {
        let mut tracker = CampaignTracker::new().with_min_link_confidence(0);
        tracker.add_link(CampaignLink::new("R1", "R2", LinkEvidence::SharedTtp, 80));
        tracker.add_link(CampaignLink::new("R2", "R3", LinkEvidence::SharedTtp, 75));
        assert_eq!(tracker.len(), 1);
        assert_eq!(tracker.campaigns()[0].size(), 3);
    }

    #[test]
    fn test_add_link_merges_campaigns() {
        let mut tracker = CampaignTracker::new().with_min_link_confidence(0);
        tracker.add_link(CampaignLink::new("R1", "R2", LinkEvidence::SharedTtp, 80));
        tracker.add_link(CampaignLink::new("R3", "R4", LinkEvidence::SharedTtp, 80));
        tracker.add_link(CampaignLink::new("R2", "R3", LinkEvidence::SharedTtp, 70));
        assert_eq!(tracker.len(), 1);
        assert_eq!(tracker.campaigns()[0].size(), 4);
    }

    #[test]
    fn test_low_confidence_link_ignored() {
        let mut tracker = CampaignTracker::new().with_min_link_confidence(60);
        let link = CampaignLink::new("R1", "R2", LinkEvidence::SharedTtp, 40);
        tracker.add_link(link);
        assert!(tracker.is_empty());
    }

    #[test]
    fn test_campaign_for_report() {
        let mut tracker = CampaignTracker::new().with_min_link_confidence(0);
        tracker.add_link(CampaignLink::new("R1", "R2", LinkEvidence::SharedTtp, 80));
        let c = tracker.campaign_for_report("R1");
        assert!(c.is_some());
        assert!(c.unwrap().members.contains("R2"));
    }

    #[test]
    fn test_campaign_display_name_no_name() {
        let c = Campaign::new(42);
        assert!(c.display_name().contains("42"));
    }

    #[test]
    fn test_campaign_ttp_jaccard_identical() {
        let mut a = Campaign::new(1);
        let mut b = Campaign::new(2);
        a.add_ttps(["T1", "T2"]);
        b.add_ttps(["T1", "T2"]);
        assert_eq!(a.ttp_jaccard(&b), 1.0);
    }

    #[test]
    fn test_campaign_ttp_jaccard_disjoint() {
        let mut a = Campaign::new(1);
        let mut b = Campaign::new(2);
        a.add_ttps(["T1"]);
        b.add_ttps(["T2"]);
        assert_eq!(a.ttp_jaccard(&b), 0.0);
    }

    #[test]
    fn test_cluster_by_ttps_two_reports_similar() {
        let r1 = make_report("R1", &["T1", "T2", "T3"]);
        let r2 = make_report("R2", &["T1", "T2", "T4"]);
        let tracker = cluster_by_ttps(&[r1, r2], 0.3);
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn test_cluster_by_ttps_disjoint() {
        let r1 = make_report("R1", &["T1"]);
        let r2 = make_report("R2", &["T2"]);
        let tracker = cluster_by_ttps(&[r1, r2], 0.5);
        assert_eq!(tracker.len(), 0);
    }

    #[test]
    fn test_link_display() {
        let link = CampaignLink::new("R1", "R2", LinkEvidence::SharedTtp, 80);
        let s = link.to_string();
        assert!(s.contains("R1"));
        assert!(s.contains("R2"));
        assert!(s.contains("shared-ttp"));
    }

    #[test]
    fn test_summary_non_empty() {
        let mut tracker = CampaignTracker::new().with_min_link_confidence(0);
        tracker.add_link(CampaignLink::new("R1", "R2", LinkEvidence::SharedTtp, 80));
        let s = tracker.summary();
        assert!(s.contains("CampaignTracker"));
    }
}
