//! Campaign correlation analysis.
//!
//! Finds structural and evidential overlaps between threat campaigns by
//! comparing their `IoC` sets, TTPs, targeted sectors, threat actors, and
//! temporal activity windows.

use std::collections::{HashMap, HashSet};
use std::fmt;

use rustre_threatintel::ThreatReport;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// OverlapCategory
// ---------------------------------------------------------------------------

/// Category of overlap found between two campaigns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OverlapCategory {
    /// Campaigns share one or more `IoC` values.
    SharedIoC,
    /// Campaigns target the same sector or industry.
    SharedTargetSector,
    /// Campaigns were active during overlapping time windows.
    TemporalOverlap,
    /// Campaigns are attributed to the same threat actor(s).
    SharedThreatActor,
    /// Campaigns use the same malware families.
    SharedMalwareFamily,
    /// Campaigns share MITRE ATT&CK technique identifiers.
    SharedTtp,
    /// Campaigns share network infrastructure (IP or domain space).
    SharedInfrastructure,
}

impl fmt::Display for OverlapCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::SharedIoC => "Shared IoC",
            Self::SharedTargetSector => "Shared Target Sector",
            Self::TemporalOverlap => "Temporal Overlap",
            Self::SharedThreatActor => "Shared Threat Actor",
            Self::SharedMalwareFamily => "Shared Malware Family",
            Self::SharedTtp => "Shared TTP",
            Self::SharedInfrastructure => "Shared Infrastructure",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// CampaignOverlap
// ---------------------------------------------------------------------------

/// A single overlap dimension found between two campaigns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignOverlap {
    /// Category of the overlap.
    pub category: OverlapCategory,
    /// Number of shared items in this dimension (`IoCs`, TTPs, etc.).
    pub shared_count: usize,
    /// Confidence contribution [0.0, 1.0] for this dimension.
    pub weight: f64,
    /// Human-readable description.
    pub description: String,
}

impl CampaignOverlap {
    /// Create a new overlap record.
    #[must_use]
    pub fn new(
        category: OverlapCategory,
        shared_count: usize,
        weight: f64,
        description: impl Into<String>,
    ) -> Self {
        Self {
            category,
            shared_count,
            weight: weight.clamp(0.0, 1.0),
            description: description.into(),
        }
    }

    /// Return the contribution to overall confidence (`shared_count` × weight).
    #[must_use]
    pub fn contribution(&self) -> f64 {
        (self.shared_count as f64) * self.weight
    }
}

impl fmt::Display for CampaignOverlap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] count={} weight={:.2}: {}",
            self.category, self.shared_count, self.weight, self.description
        )
    }
}

// ---------------------------------------------------------------------------
// CampaignLinkKind
// ---------------------------------------------------------------------------

/// Strength classification of a campaign link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CampaignLinkKind {
    /// Very strong evidence the campaigns are the same operation.
    SameOperation,
    /// Strong evidence they are closely related or spawned from each other.
    Related,
    /// Some shared elements, may be coincidence or shared tooling.
    Correlated,
    /// Weak signals only — treat with caution.
    Weak,
}

impl CampaignLinkKind {
    /// Derive a link kind from an aggregated confidence score in [0, 100].
    #[must_use]
    pub const fn from_confidence(score: u8) -> Self {
        match score {
            80..=100 => Self::SameOperation,
            60..=79 => Self::Related,
            35..=59 => Self::Correlated,
            _ => Self::Weak,
        }
    }

    /// Return the minimum confidence value that maps to this kind.
    #[must_use]
    pub const fn lower_bound(self) -> u8 {
        match self {
            Self::SameOperation => 80,
            Self::Related => 60,
            Self::Correlated => 35,
            Self::Weak => 0,
        }
    }
}

impl fmt::Display for CampaignLinkKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::SameOperation => "Same Operation",
            Self::Related => "Related",
            Self::Correlated => "Correlated",
            Self::Weak => "Weak",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// CampaignLink
// ---------------------------------------------------------------------------

/// A detected link between two named campaigns (threat reports).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignLink {
    /// Name / title of the first campaign.
    pub campaign_a: String,
    /// Name / title of the second campaign.
    pub campaign_b: String,
    /// Aggregated confidence [0, 100].
    pub confidence: u8,
    /// Classification of the link strength.
    pub kind: CampaignLinkKind,
    /// All detected overlaps contributing to this link.
    pub overlaps: Vec<CampaignOverlap>,
}

impl CampaignLink {
    /// Build a link from two report titles and a list of detected overlaps.
    #[must_use]
    pub fn from_overlaps(
        campaign_a: impl Into<String>,
        campaign_b: impl Into<String>,
        overlaps: Vec<CampaignOverlap>,
    ) -> Self {
        let total_contribution: f64 = overlaps.iter().map(CampaignOverlap::contribution).sum();
        // Normalise to [0, 100]; cap raw contribution at 10.0 → 100.
        let raw_score = (total_contribution / 10.0).min(1.0);
        let confidence = (raw_score * 100.0).round().min(255.0) as u8;
        let kind = CampaignLinkKind::from_confidence(confidence);
        Self {
            campaign_a: campaign_a.into(),
            campaign_b: campaign_b.into(),
            confidence,
            kind,
            overlaps,
        }
    }

    /// Return `true` if this link is at least as strong as `Related`.
    #[must_use]
    pub const fn is_significant(&self) -> bool {
        self.confidence >= CampaignLinkKind::Related.lower_bound()
    }

    /// Return all overlap categories present in this link.
    #[must_use]
    pub fn overlap_categories(&self) -> Vec<OverlapCategory> {
        let mut seen: Vec<OverlapCategory> = Vec::new();
        for o in &self.overlaps {
            if !seen.contains(&o.category) {
                seen.push(o.category);
            }
        }
        seen
    }

    /// Return the total number of shared items across all overlap dimensions.
    #[must_use]
    pub fn total_shared_items(&self) -> usize {
        self.overlaps.iter().map(|o| o.shared_count).sum()
    }
}

impl fmt::Display for CampaignLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} <-> {} [{}] confidence={}",
            self.campaign_a, self.campaign_b, self.kind, self.confidence
        )
    }
}

// ---------------------------------------------------------------------------
// CampaignDescriptor — internal lightweight representation
// ---------------------------------------------------------------------------

/// Internal descriptor built from a `ThreatReport` for fast set operations.
struct CampaignDescriptor {
    title: String,
    ioc_values: HashSet<String>,
    threat_actors: HashSet<String>,
    malware_families: HashSet<String>,
    /// `technique_id` strings extracted from Ttp entries.
    ttp_ids: HashSet<String>,
    /// (`first_seen_min`, `first_seen_max`) epoch seconds across all `IoCs`.
    time_window: Option<(u64, u64)>,
    /// /24 prefixes extracted from IP `IoCs`.
    ip_prefixes: HashSet<String>,
    /// Classification tags used as a proxy for target sectors.
    tags: HashSet<String>,
}

impl CampaignDescriptor {
    fn from_report(report: &ThreatReport) -> Self {
        let ioc_values: HashSet<String> = report
            .iocs
            .iter()
            .map(|i| i.value.to_ascii_lowercase())
            .collect();

        let ip_prefixes: HashSet<String> = report
            .iocs
            .iter()
            .filter_map(|i| ip_prefix_24(&i.value))
            .collect();

        let time_window = {
            let timestamps: Vec<u64> = report
                .iocs
                .iter()
                .filter(|i| i.first_seen > 0)
                .map(|i| i.first_seen)
                .collect();
            if timestamps.is_empty() {
                None
            } else {
                let min = *timestamps.iter().min().unwrap();
                let max = *timestamps.iter().max().unwrap();
                Some((min, max))
            }
        };

        let ttp_ids: HashSet<String> = report.ttps.iter().map(|t| t.technique_id.clone()).collect();

        let tags: HashSet<String> = report.tags.iter().cloned().collect();

        Self {
            title: report.title.clone(),
            ioc_values,
            threat_actors: report.threat_actors.iter().cloned().collect(),
            malware_families: report.malware_families.iter().cloned().collect(),
            ttp_ids,
            time_window,
            ip_prefixes,
            tags,
        }
    }

    /// Compute all overlaps between `self` and `other`.
    /// Push a `CampaignOverlap` if `count > 0`, using `example` as description suffix.
    fn push_set_overlap(
        overlaps: &mut Vec<CampaignOverlap>,
        category: OverlapCategory,
        count: usize,
        weight: f64,
        desc: String,
    ) {
        if count > 0 {
            overlaps.push(CampaignOverlap::new(category, count, weight, desc));
        }
    }

    /// Compute the temporal overlap component between two descriptors.
    fn temporal_overlap(
        a_window: Option<(u64, u64)>,
        b_window: Option<(u64, u64)>,
    ) -> Option<CampaignOverlap> {
        const TEMPORAL_TOLERANCE_SECS: u64 = 86_400;
        let ((a_min, a_max), (b_min, b_max)) = (a_window?, b_window?);
        let a_lo = a_min.saturating_sub(TEMPORAL_TOLERANCE_SECS);
        let a_hi = a_max.saturating_add(TEMPORAL_TOLERANCE_SECS);
        let b_lo = b_min.saturating_sub(TEMPORAL_TOLERANCE_SECS);
        let b_hi = b_max.saturating_add(TEMPORAL_TOLERANCE_SECS);
        if !(a_lo <= b_hi && b_lo <= a_hi) {
            return None;
        }
        let overlap_start = a_min.max(b_min);
        let overlap_end = a_max.min(b_max);
        let overlap_days = if overlap_end >= overlap_start {
            (overlap_end - overlap_start) / 86_400 + 1
        } else {
            0
        };
        Some(CampaignOverlap::new(
            OverlapCategory::TemporalOverlap,
            usize::try_from(overlap_days).unwrap_or(usize::MAX),
            0.3,
            format!("Activity windows overlap for ~{overlap_days} day(s)"),
        ))
    }

    fn overlaps_with(&self, other: &Self) -> Vec<CampaignOverlap> {
        let mut overlaps = Vec::new();

        let shared_ioc_count = self.ioc_values.intersection(&other.ioc_values).count();
        let ioc_example = self.ioc_values.intersection(&other.ioc_values).next().cloned().unwrap_or_default();
        Self::push_set_overlap(&mut overlaps, OverlapCategory::SharedIoC, shared_ioc_count, 0.9,
            format!("{shared_ioc_count} IoC(s) shared, e.g. {ioc_example}"));

        let shared_actor_count = self.threat_actors.intersection(&other.threat_actors).count();
        let actor_example = self.threat_actors.intersection(&other.threat_actors).next().cloned().unwrap_or_default();
        Self::push_set_overlap(&mut overlaps, OverlapCategory::SharedThreatActor, shared_actor_count, 0.8,
            format!("{shared_actor_count} shared actor(s): {actor_example}"));

        let shared_fam_count = self.malware_families.intersection(&other.malware_families).count();
        let fam_example = self.malware_families.intersection(&other.malware_families).next().cloned().unwrap_or_default();
        Self::push_set_overlap(&mut overlaps, OverlapCategory::SharedMalwareFamily, shared_fam_count, 0.7,
            format!("{shared_fam_count} shared family(ies): {fam_example}"));

        let shared_ttp_count = self.ttp_ids.intersection(&other.ttp_ids).count();
        let ttp_example = self.ttp_ids.intersection(&other.ttp_ids).next().cloned().unwrap_or_default();
        Self::push_set_overlap(&mut overlaps, OverlapCategory::SharedTtp, shared_ttp_count, 0.6,
            format!("{shared_ttp_count} shared TTP(s): {ttp_example}"));

        let shared_tag_count = self.tags.intersection(&other.tags).count();
        let tag_example = self.tags.intersection(&other.tags).next().cloned().unwrap_or_default();
        Self::push_set_overlap(&mut overlaps, OverlapCategory::SharedTargetSector, shared_tag_count, 0.4,
            format!("{shared_tag_count} shared tag(s)/sector(s): {tag_example}"));

        if let Some(ov) = Self::temporal_overlap(self.time_window, other.time_window) {
            overlaps.push(ov);
        }

        let shared_prefix_count = self.ip_prefixes.intersection(&other.ip_prefixes).count();
        let prefix_example = self.ip_prefixes.intersection(&other.ip_prefixes).next().cloned().unwrap_or_default();
        Self::push_set_overlap(&mut overlaps, OverlapCategory::SharedInfrastructure, shared_prefix_count, 0.65,
            format!("{shared_prefix_count} shared /24 prefix(es): {prefix_example}"));

        overlaps
    }
}

// ---------------------------------------------------------------------------
// CampaignCorrelationEngine
// ---------------------------------------------------------------------------

/// Engine that correlates threat campaigns (represented as [`ThreatReport`]s).
pub struct CampaignCorrelationEngine {
    descriptors: Vec<CampaignDescriptor>,
}

impl CampaignCorrelationEngine {
    /// Create an empty engine.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            descriptors: Vec::new(),
        }
    }

    /// Ingest a threat report into the engine.
    pub fn add_report(&mut self, report: &ThreatReport) {
        self.descriptors
            .push(CampaignDescriptor::from_report(report));
    }

    /// Correlate all ingested campaigns pairwise.
    ///
    /// Returns every detected link (including weak ones).
    #[must_use]
    pub fn correlate_all(&self) -> Vec<CampaignLink> {
        let mut links = Vec::new();
        for i in 0..self.descriptors.len() {
            for j in (i + 1)..self.descriptors.len() {
                let a = &self.descriptors[i];
                let b = &self.descriptors[j];
                let overlaps = a.overlaps_with(b);
                if !overlaps.is_empty() {
                    links.push(CampaignLink::from_overlaps(
                        a.title.clone(),
                        b.title.clone(),
                        overlaps,
                    ));
                }
            }
        }
        links
    }

    /// Return only significant links (confidence >= Related lower bound).
    #[must_use]
    pub fn significant_links(&self) -> Vec<CampaignLink> {
        self.correlate_all()
            .into_iter()
            .filter(CampaignLink::is_significant)
            .collect()
    }

    /// Return all links involving the campaign with the given title (exact match).
    #[must_use]
    pub fn links_for_campaign(&self, title: &str) -> Vec<CampaignLink> {
        self.correlate_all()
            .into_iter()
            .filter(|l| l.campaign_a == title || l.campaign_b == title)
            .collect()
    }

    /// Build a summary map: campaign title → list of linked campaign titles.
    #[must_use]
    pub fn link_map(&self) -> HashMap<String, Vec<String>> {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for link in self.correlate_all() {
            map.entry(link.campaign_a.clone())
                .or_default()
                .push(link.campaign_b.clone());
            map.entry(link.campaign_b.clone())
                .or_default()
                .push(link.campaign_a.clone());
        }
        map
    }

    /// Return the campaign that has the most links to other campaigns.
    ///
    /// Returns `None` when no links exist.
    #[must_use]
    pub fn most_connected_campaign(&self) -> Option<String> {
        let map = self.link_map();
        map.into_iter().max_by_key(|(_, v)| v.len()).map(|(k, _)| k)
    }

    /// Number of ingested campaigns.
    #[must_use]
    pub const fn campaign_count(&self) -> usize {
        self.descriptors.len()
    }

    /// Compute the Jaccard similarity of two campaigns' `IoC` sets.
    ///
    /// Returns `None` if either campaign is not found.
    #[must_use]
    pub fn ioc_jaccard(&self, title_a: &str, title_b: &str) -> Option<f64> {
        let a = self.descriptors.iter().find(|d| d.title == title_a)?;
        let b = self.descriptors.iter().find(|d| d.title == title_b)?;
        let inter = a.ioc_values.intersection(&b.ioc_values).count();
        let union = a.ioc_values.union(&b.ioc_values).count();
        if union == 0 {
            Some(1.0)
        } else {
            Some((inter as f64) / (union as f64))
        }
    }
}

impl Default for CampaignCorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CampaignCorrelationEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CampaignCorrelationEngine")
            .field("campaigns", &self.descriptors.len())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Network helpers
// ---------------------------------------------------------------------------

fn ip_prefix_24(ip: &str) -> Option<String> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 {
        Some(format!("{}.{}.{}", parts[0], parts[1], parts[2]))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests (30+)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_threatintel::{IoC, IoCType, ThreatReport};

    fn simple_report(title: &str) -> ThreatReport {
        ThreatReport::new(title.to_string(), "analyst".to_string())
    }

    fn report_with_actor(title: &str, actor: &str) -> ThreatReport {
        let mut r = simple_report(title);
        r.threat_actors.push(actor.to_string());
        r
    }

    fn report_with_family(title: &str, family: &str) -> ThreatReport {
        let mut r = simple_report(title);
        r.malware_families.push(family.to_string());
        r
    }

    fn report_with_ip(title: &str, ip: &str, ts: u64) -> ThreatReport {
        let mut r = simple_report(title);
        let mut ioc = IoC::new(IoCType::Ip, ip.to_string(), title.to_string());
        ioc.first_seen = ts;
        r.add_ioc(ioc);
        r
    }

    // ---- OverlapCategory ----

    #[test]
    fn test_overlap_category_display() {
        let cats = [
            OverlapCategory::SharedIoC,
            OverlapCategory::SharedTargetSector,
            OverlapCategory::TemporalOverlap,
            OverlapCategory::SharedThreatActor,
            OverlapCategory::SharedMalwareFamily,
            OverlapCategory::SharedTtp,
            OverlapCategory::SharedInfrastructure,
        ];
        for c in &cats {
            assert!(!c.to_string().is_empty());
        }
    }

    // ---- CampaignLinkKind ----

    #[test]
    fn test_link_kind_from_confidence() {
        assert_eq!(
            CampaignLinkKind::from_confidence(95),
            CampaignLinkKind::SameOperation
        );
        assert_eq!(
            CampaignLinkKind::from_confidence(70),
            CampaignLinkKind::Related
        );
        assert_eq!(
            CampaignLinkKind::from_confidence(50),
            CampaignLinkKind::Correlated
        );
        assert_eq!(
            CampaignLinkKind::from_confidence(10),
            CampaignLinkKind::Weak
        );
    }

    #[test]
    fn test_link_kind_lower_bound() {
        assert_eq!(CampaignLinkKind::SameOperation.lower_bound(), 80);
        assert_eq!(CampaignLinkKind::Related.lower_bound(), 60);
        assert_eq!(CampaignLinkKind::Correlated.lower_bound(), 35);
        assert_eq!(CampaignLinkKind::Weak.lower_bound(), 0);
    }

    #[test]
    fn test_link_kind_display() {
        assert!(CampaignLinkKind::SameOperation.to_string().contains("Same"));
        assert!(CampaignLinkKind::Related.to_string().contains("Related"));
        assert!(
            CampaignLinkKind::Correlated
                .to_string()
                .contains("Correlated")
        );
        assert!(CampaignLinkKind::Weak.to_string().contains("Weak"));
    }

    // ---- CampaignOverlap ----

    #[test]
    fn test_overlap_contribution() {
        let o = CampaignOverlap::new(OverlapCategory::SharedIoC, 5, 0.8, "test");
        assert!((o.contribution() - 4.0).abs() < 1e-9);
    }

    #[test]
    fn test_overlap_weight_clamped() {
        let o = CampaignOverlap::new(OverlapCategory::SharedIoC, 1, 2.5, "test");
        assert!(o.weight <= 1.0);
    }

    #[test]
    fn test_overlap_display() {
        let o = CampaignOverlap::new(OverlapCategory::SharedTtp, 3, 0.5, "test desc");
        let s = o.to_string();
        assert!(s.contains("Shared TTP"));
        assert!(s.contains("test desc"));
    }

    // ---- CampaignLink ----

    #[test]
    fn test_campaign_link_from_overlaps_no_overlap() {
        let link = CampaignLink::from_overlaps("A", "B", vec![]);
        assert_eq!(link.confidence, 0);
        assert_eq!(link.kind, CampaignLinkKind::Weak);
        assert!(!link.is_significant());
    }

    #[test]
    fn test_campaign_link_from_overlaps_high() {
        let overlaps = vec![CampaignOverlap::new(
            OverlapCategory::SharedIoC,
            10,
            1.0,
            "",
        )];
        let link = CampaignLink::from_overlaps("A", "B", overlaps);
        assert!(link.confidence >= 80);
        assert!(link.is_significant());
    }

    #[test]
    fn test_campaign_link_total_shared_items() {
        let overlaps = vec![
            CampaignOverlap::new(OverlapCategory::SharedIoC, 3, 0.9, ""),
            CampaignOverlap::new(OverlapCategory::SharedTtp, 2, 0.6, ""),
        ];
        let link = CampaignLink::from_overlaps("A", "B", overlaps);
        assert_eq!(link.total_shared_items(), 5);
    }

    #[test]
    fn test_campaign_link_overlap_categories() {
        let overlaps = vec![
            CampaignOverlap::new(OverlapCategory::SharedIoC, 1, 0.9, ""),
            CampaignOverlap::new(OverlapCategory::SharedIoC, 1, 0.9, ""),
            CampaignOverlap::new(OverlapCategory::SharedTtp, 2, 0.6, ""),
        ];
        let link = CampaignLink::from_overlaps("X", "Y", overlaps);
        let cats = link.overlap_categories();
        assert_eq!(cats.len(), 2);
    }

    #[test]
    fn test_campaign_link_display() {
        let link = CampaignLink::from_overlaps("Alpha", "Beta", vec![]);
        let s = link.to_string();
        assert!(s.contains("Alpha"));
        assert!(s.contains("Beta"));
    }

    // ---- CampaignCorrelationEngine ----

    #[test]
    fn test_engine_new_empty() {
        let e = CampaignCorrelationEngine::new();
        assert_eq!(e.campaign_count(), 0);
        assert!(e.correlate_all().is_empty());
    }

    #[test]
    fn test_engine_default() {
        let e = CampaignCorrelationEngine::default();
        assert_eq!(e.campaign_count(), 0);
    }

    #[test]
    fn test_engine_debug() {
        let e = CampaignCorrelationEngine::new();
        let s = format!("{e:?}");
        assert!(s.contains("CampaignCorrelationEngine"));
    }

    #[test]
    fn test_engine_add_report() {
        let mut e = CampaignCorrelationEngine::new();
        let r = simple_report("Report A");
        e.add_report(&r);
        assert_eq!(e.campaign_count(), 1);
    }

    #[test]
    fn test_engine_no_link_different_campaigns() {
        let mut e = CampaignCorrelationEngine::new();
        e.add_report(&simple_report("Report A"));
        e.add_report(&simple_report("Report B"));
        // No shared attributes → no links.
        let links = e.correlate_all();
        assert!(links.is_empty());
    }

    #[test]
    fn test_engine_shared_ioc_link() {
        let mut e = CampaignCorrelationEngine::new();
        e.add_report(&report_with_ip("A", "1.2.3.4", 0));
        e.add_report(&report_with_ip("B", "1.2.3.4", 0));
        let links = e.correlate_all();
        assert!(!links.is_empty());
        assert!(
            links[0]
                .overlaps
                .iter()
                .any(|o| o.category == OverlapCategory::SharedIoC)
        );
    }

    #[test]
    fn test_engine_shared_actor() {
        let mut e = CampaignCorrelationEngine::new();
        e.add_report(&report_with_actor("A", "APT29"));
        e.add_report(&report_with_actor("B", "APT29"));
        let links = e.correlate_all();
        assert!(
            links
                .iter()
                .flat_map(|l| l.overlaps.iter())
                .any(|o| o.category == OverlapCategory::SharedThreatActor)
        );
    }

    #[test]
    fn test_engine_shared_malware_family() {
        let mut e = CampaignCorrelationEngine::new();
        e.add_report(&report_with_family("A", "Emotet"));
        e.add_report(&report_with_family("B", "Emotet"));
        let links = e.correlate_all();
        assert!(
            links
                .iter()
                .flat_map(|l| l.overlaps.iter())
                .any(|o| o.category == OverlapCategory::SharedMalwareFamily)
        );
    }

    #[test]
    fn test_engine_shared_ttp() {
        use rustre_threatintel::Ttp;
        let mut e = CampaignCorrelationEngine::new();
        let mut r1 = simple_report("A");
        let mut r2 = simple_report("B");
        r1.ttps
            .push(Ttp::new("T1059.001", "PowerShell", "Execution"));
        r2.ttps
            .push(Ttp::new("T1059.001", "PowerShell", "Execution"));
        e.add_report(&r1);
        e.add_report(&r2);
        let links = e.correlate_all();
        assert!(
            links
                .iter()
                .flat_map(|l| l.overlaps.iter())
                .any(|o| o.category == OverlapCategory::SharedTtp)
        );
    }

    #[test]
    fn test_engine_shared_tag_as_sector() {
        let mut e = CampaignCorrelationEngine::new();
        let mut r1 = simple_report("A");
        let mut r2 = simple_report("B");
        r1.tags.push("finance".to_string());
        r2.tags.push("finance".to_string());
        e.add_report(&r1);
        e.add_report(&r2);
        let links = e.correlate_all();
        assert!(
            links
                .iter()
                .flat_map(|l| l.overlaps.iter())
                .any(|o| o.category == OverlapCategory::SharedTargetSector)
        );
    }

    #[test]
    fn test_engine_temporal_overlap() {
        let ts1 = 1_700_000_000u64;
        let ts2 = 1_700_000_000u64 + 3600;
        let mut e = CampaignCorrelationEngine::new();
        let mut r1 = simple_report("A");
        let mut r2 = simple_report("B");
        let mut ioc1 = IoC::new(IoCType::Sha256, "hash1".to_string(), "A".to_string());
        ioc1.first_seen = ts1;
        let mut ioc2 = IoC::new(IoCType::Sha256, "hash2".to_string(), "B".to_string());
        ioc2.first_seen = ts2;
        r1.add_ioc(ioc1);
        r2.add_ioc(ioc2);
        e.add_report(&r1);
        e.add_report(&r2);
        let links = e.correlate_all();
        assert!(
            links
                .iter()
                .flat_map(|l| l.overlaps.iter())
                .any(|o| o.category == OverlapCategory::TemporalOverlap)
        );
    }

    #[test]
    fn test_engine_no_temporal_overlap() {
        let ts1 = 1_000_000u64;
        let ts2 = 2_000_000u64;
        let mut e = CampaignCorrelationEngine::new();
        let mut r1 = simple_report("A");
        let mut r2 = simple_report("B");
        let mut ioc1 = IoC::new(IoCType::Sha256, "h1".to_string(), "A".to_string());
        ioc1.first_seen = ts1;
        let mut ioc2 = IoC::new(IoCType::Sha256, "h2".to_string(), "B".to_string());
        ioc2.first_seen = ts2;
        r1.add_ioc(ioc1);
        r2.add_ioc(ioc2);
        e.add_report(&r1);
        e.add_report(&r2);
        let links = e.correlate_all();
        assert!(
            !links
                .iter()
                .flat_map(|l| l.overlaps.iter())
                .any(|o| o.category == OverlapCategory::TemporalOverlap)
        );
    }

    #[test]
    fn test_engine_shared_ip_prefix() {
        let mut e = CampaignCorrelationEngine::new();
        e.add_report(&report_with_ip("A", "10.0.0.1", 0));
        e.add_report(&report_with_ip("B", "10.0.0.2", 0));
        let links = e.correlate_all();
        assert!(
            links
                .iter()
                .flat_map(|l| l.overlaps.iter())
                .any(|o| o.category == OverlapCategory::SharedInfrastructure)
        );
    }

    #[test]
    fn test_engine_significant_links() {
        let mut e = CampaignCorrelationEngine::new();
        // Share many attributes for high confidence.
        let mut r1 = simple_report("High A");
        let mut r2 = simple_report("High B");
        r1.threat_actors.push("APT99".to_string());
        r2.threat_actors.push("APT99".to_string());
        r1.malware_families.push("MalX".to_string());
        r2.malware_families.push("MalX".to_string());
        for i in 1..=10u8 {
            let ioc1 = IoC::new(IoCType::Ip, format!("1.2.3.{i}"), "High A".to_string());
            let ioc2 = IoC::new(IoCType::Ip, format!("1.2.3.{i}"), "High B".to_string());
            r1.add_ioc(ioc1);
            r2.add_ioc(ioc2);
        }
        e.add_report(&r1);
        e.add_report(&r2);
        let sig = e.significant_links();
        assert!(!sig.is_empty());
    }

    #[test]
    fn test_engine_links_for_campaign() {
        let mut e = CampaignCorrelationEngine::new();
        e.add_report(&report_with_actor("Alpha", "APT1"));
        e.add_report(&report_with_actor("Beta", "APT1"));
        e.add_report(&report_with_actor("Gamma", "APT2"));
        let links = e.links_for_campaign("Alpha");
        assert!(
            links
                .iter()
                .any(|l| l.campaign_b == "Beta" || l.campaign_a == "Beta")
        );
        assert!(
            !links
                .iter()
                .any(|l| l.campaign_b == "Gamma" || l.campaign_a == "Gamma")
        );
    }

    #[test]
    fn test_engine_link_map() {
        let mut e = CampaignCorrelationEngine::new();
        e.add_report(&report_with_actor("A", "X"));
        e.add_report(&report_with_actor("B", "X"));
        let map = e.link_map();
        assert!(map.contains_key("A"));
        assert!(map["A"].contains(&"B".to_string()));
    }

    #[test]
    fn test_engine_most_connected_campaign_none() {
        let e = CampaignCorrelationEngine::new();
        assert!(e.most_connected_campaign().is_none());
    }

    #[test]
    fn test_engine_most_connected_campaign() {
        let mut e = CampaignCorrelationEngine::new();
        e.add_report(&report_with_actor("A", "X"));
        e.add_report(&report_with_actor("B", "X"));
        e.add_report(&report_with_actor("C", "X"));
        let most = e.most_connected_campaign();
        assert!(most.is_some());
    }

    #[test]
    fn test_engine_ioc_jaccard_equal() {
        let mut e = CampaignCorrelationEngine::new();
        e.add_report(&report_with_ip("A", "1.2.3.4", 0));
        e.add_report(&report_with_ip("B", "1.2.3.4", 0));
        let j = e.ioc_jaccard("A", "B").unwrap();
        assert!((j - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_engine_ioc_jaccard_disjoint() {
        let mut e = CampaignCorrelationEngine::new();
        e.add_report(&report_with_ip("A", "1.2.3.4", 0));
        e.add_report(&report_with_ip("B", "5.6.7.8", 0));
        let j = e.ioc_jaccard("A", "B").unwrap();
        assert!(j < 1e-9);
    }

    #[test]
    fn test_engine_ioc_jaccard_missing() {
        let e = CampaignCorrelationEngine::new();
        assert!(e.ioc_jaccard("A", "B").is_none());
    }

    #[test]
    fn test_engine_ioc_jaccard_empty_sets() {
        let mut e = CampaignCorrelationEngine::new();
        e.add_report(&simple_report("A"));
        e.add_report(&simple_report("B"));
        let j = e.ioc_jaccard("A", "B").unwrap();
        // Both empty → union is 0 → we return 1.0 (identical vacuously)
        assert!((j - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_ip_prefix_24_valid() {
        assert_eq!(ip_prefix_24("192.168.1.5"), Some("192.168.1".to_string()));
    }

    #[test]
    fn test_ip_prefix_24_invalid() {
        assert_eq!(ip_prefix_24("not-an-ip"), None);
    }

    #[test]
    fn test_link_serde() {
        let overlaps = vec![CampaignOverlap::new(
            OverlapCategory::SharedThreatActor,
            2,
            0.8,
            "same actor",
        )];
        let link = CampaignLink::from_overlaps("A", "B", overlaps);
        let json = serde_json::to_string(&link).unwrap();
        let decoded: CampaignLink = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.campaign_a, "A");
        assert_eq!(decoded.campaign_b, "B");
    }
}
