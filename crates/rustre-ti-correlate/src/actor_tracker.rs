//! Threat-actor tracking and TTP mapping.
//!
//! Provides [`ActorTracker`] which maintains profiles for known threat actors,
//! maps observed TTPs to MITRE ATT&CK technique identifiers, links campaigns
//! together, and computes actor attribution confidence based on TTP overlap.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use rustre_threatintel::{IoC, ThreatReport};

// ── TtpMapping ────────────────────────────────────────────────────────────────

/// Maps a set of observed TTPs to MITRE ATT&CK technique identifiers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtpMapping {
    /// MITRE ATT&CK tactic name (e.g. "Defense Evasion").
    pub tactic: String,
    /// Technique identifier and name (e.g. "T1055 Process Injection").
    pub technique: String,
    /// Confidence that this TTP applies [0, 100].
    pub confidence: u8,
    /// Source evidence strings.
    pub evidence: Vec<String>,
}

impl TtpMapping {
    /// Create a new TTP mapping.
    #[must_use]
    pub fn new(tactic: impl Into<String>, technique: impl Into<String>, confidence: u8) -> Self {
        Self {
            tactic: tactic.into(),
            technique: technique.into(),
            confidence,
            evidence: Vec::new(),
        }
    }

    /// Add an evidence string.
    pub fn add_evidence(&mut self, ev: impl Into<String>) {
        self.evidence.push(ev.into());
    }

    /// Return `true` if this mapping meets a minimum confidence threshold.
    #[must_use]
    pub const fn meets_threshold(&self, min: u8) -> bool {
        self.confidence >= min
    }
}

impl fmt::Display for TtpMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} confidence={}",
            self.tactic, self.technique, self.confidence
        )
    }
}

// ── CampaignLink ──────────────────────────────────────────────────────────────

/// A relationship between two campaigns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignLink {
    /// Name of the first campaign.
    pub campaign_a: String,
    /// Name of the second campaign.
    pub campaign_b: String,
    /// Number of shared TTPs between the two campaigns.
    pub shared_ttp_count: usize,
    /// Jaccard similarity of TTP sets [0.0, 1.0].
    pub ttp_overlap: f32,
    /// Number of shared IoC values.
    pub shared_ioc_count: usize,
    /// Whether both campaigns are attributed to the same actor.
    pub same_actor: bool,
}

impl CampaignLink {
    /// Return `true` if the campaigns are likely related (overlap > 0.5).
    #[must_use]
    pub fn is_related(&self) -> bool {
        self.ttp_overlap > 0.5 || self.shared_ioc_count > 3 || self.same_actor
    }
}

impl fmt::Display for CampaignLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} <-> {} ttps={} iocs={} overlap={:.2}",
            self.campaign_a,
            self.campaign_b,
            self.shared_ttp_count,
            self.shared_ioc_count,
            self.ttp_overlap
        )
    }
}

// ── ActorProfile ─────────────────────────────────────────────────────────────

/// A threat actor profile built from accumulated intelligence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorProfile {
    /// Actor name or group identifier.
    pub name: String,
    /// Alternative aliases for this actor.
    pub aliases: Vec<String>,
    /// Associated campaign names.
    pub campaigns: Vec<String>,
    /// All TTPs mapped to this actor.
    pub ttps: Vec<TtpMapping>,
    /// All IoCs associated with this actor.
    pub iocs: Vec<IoC>,
    /// Targeted sectors (e.g. "Finance", "Energy").
    pub targeted_sectors: Vec<String>,
    /// Likely nation-state or origin (heuristic only).
    pub suspected_origin: Option<String>,
    /// Confidence in the overall attribution [0, 100].
    pub attribution_confidence: u8,
    /// Timestamp of the most recent observed activity (Unix seconds).
    pub last_seen: u64,
    /// Timestamp of the first observed activity.
    pub first_seen: u64,
}

impl ActorProfile {
    /// Create a new, empty actor profile.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            aliases: Vec::new(),
            campaigns: Vec::new(),
            ttps: Vec::new(),
            iocs: Vec::new(),
            targeted_sectors: Vec::new(),
            suspected_origin: None,
            attribution_confidence: 0,
            last_seen: 0,
            first_seen: u64::MAX,
        }
    }

    /// Add a campaign to this actor's profile.
    pub fn add_campaign(&mut self, campaign: impl Into<String>) {
        let c = campaign.into();
        if !self.campaigns.contains(&c) {
            self.campaigns.push(c);
        }
    }

    /// Add a TTP mapping.
    pub fn add_ttp(&mut self, ttp: TtpMapping) {
        self.ttps.push(ttp);
    }

    /// Add an IoC to the profile (deduplicated by value).
    pub fn add_ioc(&mut self, ioc: IoC) {
        if !self.iocs.iter().any(|e| e.value == ioc.value) {
            self.iocs.push(ioc);
        }
    }

    /// Update the first/last seen timestamps from a new observation at `ts`.
    pub fn update_timestamps(&mut self, ts: u64) {
        if ts > 0 {
            if ts > self.last_seen {
                self.last_seen = ts;
            }
            if ts < self.first_seen {
                self.first_seen = ts;
            }
        }
    }

    /// Return all unique tactic names in this actor's TTP set.
    #[must_use]
    pub fn tactics(&self) -> Vec<&str> {
        let mut seen: HashSet<&str> = HashSet::new();
        let mut v = Vec::new();
        for t in &self.ttps {
            if seen.insert(t.tactic.as_str()) {
                v.push(t.tactic.as_str());
            }
        }
        v
    }

    /// Return the number of distinct MITRE techniques.
    #[must_use]
    pub fn technique_count(&self) -> usize {
        self.ttps
            .iter()
            .map(|t| t.technique.as_str())
            .collect::<HashSet<_>>()
            .len()
    }

    /// Compute an overlap score [0.0, 1.0] with another actor profile based
    /// on shared techniques (Jaccard similarity).
    #[must_use]
    pub fn technique_overlap(&self, other: &ActorProfile) -> f32 {
        let set_a: HashSet<&str> = self.ttps.iter().map(|t| t.technique.as_str()).collect();
        let set_b: HashSet<&str> = other.ttps.iter().map(|t| t.technique.as_str()).collect();
        let intersection = set_a.intersection(&set_b).count();
        let union = set_a.union(&set_b).count();
        if union == 0 {
            0.0
        } else {
            intersection as f32 / union as f32
        }
    }
}

impl fmt::Display for ActorProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Actor[{}] campaigns={} ttps={} iocs={} confidence={}",
            self.name,
            self.campaigns.len(),
            self.ttps.len(),
            self.iocs.len(),
            self.attribution_confidence
        )
    }
}

// ── ActorTracker ─────────────────────────────────────────────────────────────

/// Tracks multiple threat actors, ingests reports, and provides attribution.
pub struct ActorTracker {
    /// All known actor profiles, keyed by canonical name.
    profiles: HashMap<String, ActorProfile>,
    /// Campaign-to-actor mapping.
    campaign_actor: HashMap<String, String>,
}

impl ActorTracker {
    /// Create an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
            campaign_actor: HashMap::new(),
        }
    }

    /// Register a new actor profile (or update an existing one).
    pub fn register_actor(&mut self, profile: ActorProfile) {
        self.profiles.insert(profile.name.clone(), profile);
    }

    /// Ingest a [`ThreatReport`] and update actor/campaign state.
    ///
    /// If the report names one or more threat actors, their profiles are
    /// updated with the report's IoCs, campaigns, and TTPs.
    pub fn ingest_report(&mut self, report: &ThreatReport) {
        for actor_name in &report.threat_actors {
            let profile = self
                .profiles
                .entry(actor_name.clone())
                .or_insert_with(|| ActorProfile::new(actor_name));

            // Add IoCs.
            for ioc in &report.iocs {
                profile.add_ioc(ioc.clone());
                profile.update_timestamps(ioc.first_seen);
            }

            // Add campaigns from malware family names (heuristic).
            for family in &report.malware_families {
                profile.add_campaign(family.clone());
                self.campaign_actor
                    .insert(family.clone(), actor_name.clone());
            }

            // Map TTPs.
            for ttp in &report.ttps {
                let mapping = TtpMapping::new(
                    ttp.tactic.as_str(),
                    &ttp.technique_id,
                    70,
                );
                profile.add_ttp(mapping);
            }

            // Update attribution confidence based on data richness.
            let ioc_score = profile.iocs.len().min(50) as u8 * 2; // max 100
            let ttp_score = profile.ttps.len().min(20) as u8 * 2; // max 40
            profile.attribution_confidence = (ioc_score / 2 + ttp_score / 4).min(100);
        }
    }

    /// Return the profile for a named actor, if known.
    #[must_use]
    pub fn profile(&self, actor_name: &str) -> Option<&ActorProfile> {
        self.profiles.get(actor_name)
    }

    /// Return all actor profiles.
    #[must_use]
    pub fn all_profiles(&self) -> Vec<&ActorProfile> {
        let mut v: Vec<_> = self.profiles.values().collect();
        v.sort_by(|a, b| b.attribution_confidence.cmp(&a.attribution_confidence));
        v
    }

    /// Return the actor associated with a campaign name, if known.
    #[must_use]
    pub fn actor_for_campaign(&self, campaign: &str) -> Option<&str> {
        self.campaign_actor
            .get(campaign)
            .map(String::as_str)
    }

    /// Compute pairwise campaign links for all registered actors.
    #[must_use]
    pub fn compute_campaign_links(&self) -> Vec<CampaignLink> {
        let actors: Vec<&ActorProfile> = self.all_profiles();
        let mut links = Vec::new();

        for i in 0..actors.len() {
            for j in (i + 1)..actors.len() {
                let a = actors[i];
                let b = actors[j];

                // Cross-campaign pairs.
                for ca in &a.campaigns {
                    for cb in &b.campaigns {
                        if ca == cb {
                            continue;
                        }
                        let overlap = a.technique_overlap(b);
                        let shared_iocs = {
                            let vals_a: HashSet<&str> = a.iocs.iter().map(|i| i.value.as_str()).collect();
                            b.iocs.iter().filter(|i| vals_a.contains(i.value.as_str())).count()
                        };
                        links.push(CampaignLink {
                            campaign_a: ca.clone(),
                            campaign_b: cb.clone(),
                            shared_ttp_count: (overlap * (a.ttps.len() + b.ttps.len()) as f32 / 2.0) as usize,
                            ttp_overlap: overlap,
                            shared_ioc_count: shared_iocs,
                            same_actor: false,
                        });
                    }
                }

                // Same-actor campaign pairs.
                for ca in &a.campaigns {
                    for cb in &a.campaigns {
                        if ca >= cb {
                            continue;
                        }
                        links.push(CampaignLink {
                            campaign_a: ca.clone(),
                            campaign_b: cb.clone(),
                            shared_ttp_count: a.technique_count(),
                            ttp_overlap: 1.0,
                            shared_ioc_count: a.iocs.len(),
                            same_actor: true,
                        });
                    }
                }
            }
        }
        links
    }

    /// Attribute an IoC to the most likely actor, or `None` if ambiguous.
    #[must_use]
    pub fn attribute_ioc(&self, ioc_value: &str) -> Option<(&ActorProfile, u8)> {
        let mut best: Option<(&ActorProfile, u8)> = None;
        for profile in self.profiles.values() {
            if profile.iocs.iter().any(|i| i.value == ioc_value) {
                let conf = profile.attribution_confidence;
                if best.map_or(true, |(_, c)| conf > c) {
                    best = Some((profile, conf));
                }
            }
        }
        best
    }

    /// Return the number of known actors.
    #[must_use]
    pub fn actor_count(&self) -> usize {
        self.profiles.len()
    }

    /// Find actors whose TTP sets overlap with the given technique IDs.
    #[must_use]
    pub fn find_by_techniques(&self, techniques: &[&str]) -> Vec<(&ActorProfile, usize)> {
        let needle: HashSet<&str> = techniques.iter().copied().collect();
        let mut results = Vec::new();
        for profile in self.profiles.values() {
            let actor_techs: HashSet<&str> = profile
                .ttps
                .iter()
                .map(|t| t.technique.as_str())
                .collect();
            let overlap = actor_techs.intersection(&needle).count();
            if overlap > 0 {
                results.push((profile, overlap));
            }
        }
        results.sort_by(|a, b| b.1.cmp(&a.1));
        results
    }
}

impl Default for ActorTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ActorTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActorTracker")
            .field("actors", &self.profiles.len())
            .finish()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_threatintel::{IoCType, ThreatReport};

    fn make_report(actor: &str, families: &[&str]) -> ThreatReport {
        let mut r = ThreatReport::new("Test".to_string(), "analyst".to_string());
        r.threat_actors.push(actor.to_string());
        for f in families {
            r.malware_families.push((*f).to_string());
        }
        r
    }

    fn ip_ioc(v: &str) -> IoC {
        IoC::new(IoCType::Ip, v.to_string(), "test".to_string())
    }

    #[test]
    fn test_tracker_empty() {
        let t = ActorTracker::new();
        assert_eq!(t.actor_count(), 0);
    }

    #[test]
    fn test_register_actor() {
        let mut t = ActorTracker::new();
        t.register_actor(ActorProfile::new("APT1"));
        assert_eq!(t.actor_count(), 1);
    }

    #[test]
    fn test_ingest_report_creates_profile() {
        let mut t = ActorTracker::new();
        let r = make_report("APT28", &["Sofacy"]);
        t.ingest_report(&r);
        assert!(t.profile("APT28").is_some());
    }

    #[test]
    fn test_ingest_report_campaign() {
        let mut t = ActorTracker::new();
        let r = make_report("APT29", &["Cozy Bear"]);
        t.ingest_report(&r);
        let p = t.profile("APT29").unwrap();
        assert!(p.campaigns.contains(&"Cozy Bear".to_string()));
    }

    #[test]
    fn test_actor_for_campaign() {
        let mut t = ActorTracker::new();
        let r = make_report("APT28", &["Sofacy"]);
        t.ingest_report(&r);
        assert_eq!(t.actor_for_campaign("Sofacy"), Some("APT28"));
    }

    #[test]
    fn test_profile_ioc_added() {
        let mut t = ActorTracker::new();
        let mut r = make_report("FancyBear", &[]);
        r.iocs.push(ip_ioc("8.8.8.8"));
        t.ingest_report(&r);
        let p = t.profile("FancyBear").unwrap();
        assert!(p.iocs.iter().any(|i| i.value == "8.8.8.8"));
    }

    #[test]
    fn test_attribute_ioc() {
        let mut t = ActorTracker::new();
        let mut r = make_report("APT1", &[]);
        r.iocs.push(ip_ioc("1.2.3.4"));
        t.ingest_report(&r);
        let attr = t.attribute_ioc("1.2.3.4");
        assert!(attr.is_some());
        assert_eq!(attr.unwrap().0.name, "APT1");
    }

    #[test]
    fn test_attribute_ioc_missing() {
        let t = ActorTracker::new();
        assert!(t.attribute_ioc("99.99.99.99").is_none());
    }

    #[test]
    fn test_all_profiles_sorted() {
        let mut t = ActorTracker::new();
        t.register_actor(ActorProfile::new("A"));
        t.register_actor(ActorProfile::new("B"));
        let all = t.all_profiles();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_ttp_mapping_new() {
        let m = TtpMapping::new("Defense Evasion", "T1055 Process Injection", 80);
        assert_eq!(m.tactic, "Defense Evasion");
        assert!(m.meets_threshold(80));
        assert!(!m.meets_threshold(81));
    }

    #[test]
    fn test_ttp_mapping_display() {
        let m = TtpMapping::new("Execution", "T1059 Scripting", 60);
        let s = m.to_string();
        assert!(s.contains("Execution"));
        assert!(s.contains("60"));
    }

    #[test]
    fn test_actor_profile_techniques() {
        let mut p = ActorProfile::new("TestActor");
        p.add_ttp(TtpMapping::new("Execution", "T1059", 70));
        p.add_ttp(TtpMapping::new("Defense Evasion", "T1055", 80));
        assert_eq!(p.technique_count(), 2);
    }

    #[test]
    fn test_actor_profile_tactics() {
        let mut p = ActorProfile::new("TestActor");
        p.add_ttp(TtpMapping::new("Execution", "T1059", 70));
        p.add_ttp(TtpMapping::new("Execution", "T1059.001", 70));
        let tactics = p.tactics();
        assert_eq!(tactics.len(), 1);
        assert_eq!(tactics[0], "Execution");
    }

    #[test]
    fn test_technique_overlap_disjoint() {
        let mut a = ActorProfile::new("A");
        let mut b = ActorProfile::new("B");
        a.add_ttp(TtpMapping::new("T1", "T1001", 50));
        b.add_ttp(TtpMapping::new("T2", "T2001", 50));
        assert!((a.technique_overlap(&b) - 0.0).abs() < 1e-6);
    }

    #[test]
    fn test_technique_overlap_identical() {
        let mut a = ActorProfile::new("A");
        let mut b = ActorProfile::new("B");
        a.add_ttp(TtpMapping::new("X", "T9999", 50));
        b.add_ttp(TtpMapping::new("X", "T9999", 50));
        assert!((a.technique_overlap(&b) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_campaign_link_display() {
        let link = CampaignLink {
            campaign_a: "Op1".to_string(),
            campaign_b: "Op2".to_string(),
            shared_ttp_count: 3,
            ttp_overlap: 0.6,
            shared_ioc_count: 2,
            same_actor: false,
        };
        let s = link.to_string();
        assert!(s.contains("Op1"));
    }

    #[test]
    fn test_campaign_link_is_related_same_actor() {
        let link = CampaignLink {
            campaign_a: "A".to_string(),
            campaign_b: "B".to_string(),
            shared_ttp_count: 0,
            ttp_overlap: 0.0,
            shared_ioc_count: 0,
            same_actor: true,
        };
        assert!(link.is_related());
    }

    #[test]
    fn test_actor_profile_display() {
        let p = ActorProfile::new("Lazarus");
        let s = p.to_string();
        assert!(s.contains("Lazarus"));
    }

    #[test]
    fn test_tracker_debug_format() {
        let t = ActorTracker::new();
        let s = format!("{t:?}");
        assert!(s.contains("ActorTracker"));
    }

    #[test]
    fn test_find_by_techniques_match() {
        let mut t = ActorTracker::new();
        let mut p = ActorProfile::new("APT-X");
        p.add_ttp(TtpMapping::new("Exfiltration", "T1048", 80));
        t.register_actor(p);
        let found = t.find_by_techniques(&["T1048"]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1, 1);
    }

    #[test]
    fn test_find_by_techniques_no_match() {
        let t = ActorTracker::new();
        let found = t.find_by_techniques(&["T9999"]);
        assert!(found.is_empty());
    }

    #[test]
    fn test_timestamps_update() {
        let mut p = ActorProfile::new("X");
        p.update_timestamps(1_000_000);
        p.update_timestamps(2_000_000);
        p.update_timestamps(500_000);
        assert_eq!(p.last_seen, 2_000_000);
        assert_eq!(p.first_seen, 500_000);
    }
}
