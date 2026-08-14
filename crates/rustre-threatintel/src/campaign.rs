//! Campaign tracking types for threat intelligence.
//!
//! A campaign represents a coordinated series of attacks attributed to a threat
//! actor over a defined time window with shared TTPs and infrastructure.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::ioc::IoC;
use crate::threat_actor::Ttp;

/// Phase of an attack campaign in the kill-chain model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillChainPhase {
    /// Initial target reconnaissance.
    Reconnaissance,
    /// Weaponisation / payload construction.
    Weaponization,
    /// Delivery of the weaponised payload to the victim.
    Delivery,
    /// Exploitation of a vulnerability or user action.
    Exploitation,
    /// Establishment of a persistent foothold.
    Installation,
    /// Command & Control channel establishment.
    CommandAndControl,
    /// Achievement of the actor's goal.
    ActionsOnObjective,
}

impl fmt::Display for KillChainPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Reconnaissance => "Reconnaissance",
            Self::Weaponization => "Weaponization",
            Self::Delivery => "Delivery",
            Self::Exploitation => "Exploitation",
            Self::Installation => "Installation",
            Self::CommandAndControl => "Command & Control",
            Self::ActionsOnObjective => "Actions on Objective",
        };
        f.write_str(s)
    }
}

/// Geographic targeting scope of a campaign.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetingScope {
    /// Single nation-state target.
    SingleNation(String),
    /// Specific industry vertical.
    IndustrySector(String),
    /// Technology vendor or platform target.
    TechVendor(String),
    /// Opportunistic broad targeting.
    Opportunistic,
    /// Highly targeted (fewer than five victims).
    HighlyTargeted,
}

impl fmt::Display for TargetingScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SingleNation(n) => write!(f, "Single Nation ({n})"),
            Self::IndustrySector(s) => write!(f, "Industry Sector ({s})"),
            Self::TechVendor(v) => write!(f, "Tech Vendor ({v})"),
            Self::Opportunistic => f.write_str("Opportunistic"),
            Self::HighlyTargeted => f.write_str("Highly Targeted"),
        }
    }
}

/// A coordinated threat campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Campaign {
    /// Database row identifier (absent before first persist).
    pub id: Option<u64>,
    /// Campaign short name (e.g. `Operation Ghost`, `SolarWinds Supply Chain`).
    pub name: String,
    /// Free-text narrative description.
    pub description: String,
    /// Primary threat actor name attributed to this campaign.
    pub attributed_actor: Option<String>,
    /// Secondary / possible attribution candidates.
    pub alternative_attributions: Vec<String>,
    /// Malware families observed across campaign operations.
    pub malware_families: Vec<String>,
    /// ATT&CK TTPs observed in this campaign.
    pub ttps: Vec<Ttp>,
    /// `IoCs` collected during this campaign.
    pub iocs: Vec<IoC>,
    /// Kill-chain phases covered by this campaign.
    pub kill_chain_phases: Vec<KillChainPhase>,
    /// Targeting scope description.
    pub targeting: TargetingScope,
    /// Industry sectors targeted.
    pub target_sectors: Vec<String>,
    /// Victim countries (ISO-3166-1 alpha-2 codes).
    pub target_countries: Vec<String>,
    /// Unix timestamp of the earliest observed activity.
    pub start_date: Option<u64>,
    /// Unix timestamp of the most recent observed activity.
    pub end_date: Option<u64>,
    /// Analyst confidence in attribution, [0, 100].
    pub confidence: u8,
    /// Reference URLs for further reading.
    pub references: Vec<String>,
    /// Classification tags.
    pub tags: Vec<String>,
}

impl Campaign {
    /// Create a minimal campaign record.
    #[must_use]
    pub const fn new(name: String, targeting: TargetingScope) -> Self {
        Self {
            id: None,
            name,
            description: String::new(),
            attributed_actor: None,
            alternative_attributions: Vec::new(),
            malware_families: Vec::new(),
            ttps: Vec::new(),
            iocs: Vec::new(),
            kill_chain_phases: Vec::new(),
            targeting,
            target_sectors: Vec::new(),
            target_countries: Vec::new(),
            start_date: None,
            end_date: None,
            confidence: 50,
            references: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Builder: set the attributed actor.
    #[must_use]
    pub fn with_actor(mut self, actor: String) -> Self {
        self.attributed_actor = Some(actor);
        self
    }

    /// Builder: add a malware family.
    #[must_use]
    pub fn with_malware(mut self, family: String) -> Self {
        self.malware_families.push(family);
        self
    }

    /// Builder: add a TTP.
    #[must_use]
    pub fn with_ttp(mut self, ttp: Ttp) -> Self {
        self.ttps.push(ttp);
        self
    }

    /// Builder: add an `IoC`.
    #[must_use]
    pub fn with_ioc(mut self, ioc: IoC) -> Self {
        self.iocs.push(ioc);
        self
    }

    /// Builder: add a kill-chain phase.
    #[must_use]
    pub fn with_phase(mut self, phase: KillChainPhase) -> Self {
        if !self.kill_chain_phases.contains(&phase) {
            self.kill_chain_phases.push(phase);
        }
        self
    }

    /// Builder: add a target country code.
    #[must_use]
    pub fn with_target_country(mut self, code: String) -> Self {
        self.target_countries.push(code);
        self
    }

    /// Builder: add a target industry sector.
    #[must_use]
    pub fn with_target_sector(mut self, sector: String) -> Self {
        self.target_sectors.push(sector);
        self
    }

    /// Return `true` if this campaign has a confirmed attribution.
    #[must_use]
    pub const fn is_attributed(&self) -> bool {
        self.attributed_actor.is_some()
    }

    /// Return `true` if this campaign is still active (no end date).
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.end_date.is_none()
    }

    /// Count the total number of `IoCs` in this campaign.
    #[must_use]
    pub const fn ioc_count(&self) -> usize {
        self.iocs.len()
    }

    /// Return the duration in seconds if both dates are set.
    #[must_use]
    pub const fn duration_secs(&self) -> Option<u64> {
        match (self.start_date, self.end_date) {
            (Some(s), Some(e)) if e >= s => Some(e - s),
            _ => None,
        }
    }

    /// Compute a simple campaign complexity score [0, 100].
    ///
    /// Score is derived from:
    /// - Number of TTPs (capped at 20)
    /// - Number of kill-chain phases (capped at 7)
    /// - Number of target countries (capped at 10)
    /// - Whether attribution exists (+10)
    #[must_use]
    pub fn complexity_score(&self) -> u8 {
        let ttp_score = (crate::casts::usize_to_f64(self.ttps.len().min(20)) / 20.0) * 40.0;
        let phase_score = (crate::casts::usize_to_f64(self.kill_chain_phases.len().min(7)) / 7.0) * 30.0;
        let country_score = (crate::casts::usize_to_f64(self.target_countries.len().min(10)) / 10.0) * 20.0;
        let attr_score = if self.attributed_actor.is_some() {
            10.0_f64
        } else {
            0.0_f64
        };
        let total = (ttp_score + phase_score + country_score + attr_score).round();
        crate::casts::f64_to_u8_sat(total)
    }

    /// Return all unique tactic names across this campaign's TTPs.
    #[must_use]
    pub fn unique_tactics(&self) -> Vec<&str> {
        let mut seen: Vec<&str> = Vec::new();
        for ttp in &self.ttps {
            if !seen.contains(&ttp.tactic.as_str()) {
                seen.push(&ttp.tactic);
            }
        }
        seen
    }
}

impl fmt::Display for Campaign {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Campaign '{}' [{:?}] — {} IoC(s), {} TTP(s), confidence={}",
            self.name,
            self.targeting,
            self.iocs.len(),
            self.ttps.len(),
            self.confidence,
        )
    }
}

// ---------------------------------------------------------------------------
// Campaign Store
// ---------------------------------------------------------------------------

/// In-memory campaign store backed by a `Vec`.
///
/// For production use, persist via the `IoCStore` SQLite/MySQL backend or
/// serialize with `serde_json`.
#[derive(Debug, Default)]
pub struct CampaignStore {
    campaigns: Vec<Campaign>,
    next_id: u64,
}

impl CampaignStore {
    /// Create an empty campaign store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a campaign and assign it an auto-incremented id.
    pub fn insert(&mut self, mut campaign: Campaign) -> u64 {
        self.next_id += 1;
        campaign.id = Some(self.next_id);
        self.campaigns.push(campaign);
        self.next_id
    }

    /// Look up a campaign by its id.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<&Campaign> {
        self.campaigns.iter().find(|c| c.id == Some(id))
    }

    /// Return all campaigns attributed to the given actor name.
    #[must_use]
    pub fn by_actor(&self, actor: &str) -> Vec<&Campaign> {
        self.campaigns
            .iter()
            .filter(|c| c.attributed_actor.as_deref() == Some(actor))
            .collect()
    }

    /// Return all active campaigns.
    #[must_use]
    pub fn active(&self) -> Vec<&Campaign> {
        self.campaigns.iter().filter(|c| c.is_active()).collect()
    }

    /// Return all campaigns that use the given malware family.
    #[must_use]
    pub fn by_malware_family(&self, family: &str) -> Vec<&Campaign> {
        self.campaigns
            .iter()
            .filter(|c| {
                c.malware_families
                    .iter()
                    .any(|f| f.eq_ignore_ascii_case(family))
            })
            .collect()
    }

    /// Total number of campaigns in this store.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.campaigns.len()
    }

    /// Serialize the entire store to JSON.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] if serialisation fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.campaigns)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::{IoC, IoCType};
    use crate::threat_actor::Ttp;

    fn make_campaign() -> Campaign {
        Campaign::new("Op Ghost".to_string(), TargetingScope::Opportunistic)
    }

    #[test]
    fn test_campaign_new_defaults() {
        let c = make_campaign();
        assert_eq!(c.name, "Op Ghost");
        assert!(c.attributed_actor.is_none());
        assert!(c.iocs.is_empty());
        assert!(c.is_active());
        assert!(!c.is_attributed());
        assert_eq!(c.ioc_count(), 0);
    }

    #[test]
    fn test_campaign_with_actor() {
        let c = make_campaign().with_actor("APT29".to_string());
        assert!(c.is_attributed());
        assert_eq!(c.attributed_actor.as_deref(), Some("APT29"));
    }

    #[test]
    fn test_campaign_with_malware() {
        let c = make_campaign().with_malware("Cobalt Strike".to_string());
        assert_eq!(c.malware_families.len(), 1);
    }

    #[test]
    fn test_campaign_with_ttp() {
        let ttp = Ttp::new("T1055", "Process Injection", "Defense Evasion");
        let c = make_campaign().with_ttp(ttp);
        assert_eq!(c.ttps.len(), 1);
    }

    #[test]
    fn test_campaign_with_ioc() {
        let ioc = IoC::new(IoCType::Ip, "1.2.3.4".to_string(), "test".to_string());
        let c = make_campaign().with_ioc(ioc);
        assert_eq!(c.ioc_count(), 1);
    }

    #[test]
    fn test_campaign_with_phase_dedup() {
        let c = make_campaign()
            .with_phase(KillChainPhase::Delivery)
            .with_phase(KillChainPhase::Delivery);
        assert_eq!(c.kill_chain_phases.len(), 1);
    }

    #[test]
    fn test_campaign_duration_secs() {
        let mut c = make_campaign();
        c.start_date = Some(1_000_000);
        c.end_date = Some(1_100_000);
        assert_eq!(c.duration_secs(), Some(100_000));
    }

    #[test]
    fn test_campaign_duration_active() {
        let c = make_campaign();
        assert!(c.duration_secs().is_none());
    }

    #[test]
    fn test_campaign_complexity_score_empty() {
        let c = make_campaign();
        assert_eq!(c.complexity_score(), 0);
    }

    #[test]
    fn test_campaign_complexity_score_with_data() {
        let mut c = make_campaign().with_actor("APT29".to_string());
        for i in 0u32..10 {
            c.ttps.push(Ttp::new(
                format!("T{i}"),
                format!("TTP {i}"),
                "Tactic".to_string(),
            ));
        }
        c.kill_chain_phases = vec![KillChainPhase::Delivery, KillChainPhase::Exploitation];
        let score = c.complexity_score();
        assert!(score > 0);
    }

    #[test]
    fn test_campaign_unique_tactics() {
        let c = make_campaign()
            .with_ttp(Ttp::new("T1055", "PI", "Defense Evasion"))
            .with_ttp(Ttp::new("T1059", "Shell", "Execution"))
            .with_ttp(Ttp::new("T1056", "Keylog", "Defense Evasion"));
        let tactics = c.unique_tactics();
        assert_eq!(tactics.len(), 2);
    }

    #[test]
    fn test_campaign_display() {
        let c = make_campaign();
        let s = c.to_string();
        assert!(s.contains("Op Ghost"));
        assert!(s.contains("confidence=50"));
    }

    #[test]
    fn test_campaign_serialization() {
        let c = make_campaign().with_actor("Fancy Bear".to_string());
        let json = serde_json::to_string(&c).unwrap();
        let decoded: Campaign = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.name, "Op Ghost");
        assert_eq!(decoded.attributed_actor.as_deref(), Some("Fancy Bear"));
    }

    #[test]
    fn test_kill_chain_phase_display() {
        assert_eq!(KillChainPhase::Reconnaissance.to_string(), "Reconnaissance");
        assert_eq!(
            KillChainPhase::CommandAndControl.to_string(),
            "Command & Control"
        );
        assert_eq!(
            KillChainPhase::ActionsOnObjective.to_string(),
            "Actions on Objective"
        );
    }

    #[test]
    fn test_kill_chain_phase_ordering() {
        assert!(KillChainPhase::Reconnaissance < KillChainPhase::Delivery);
        assert!(KillChainPhase::Delivery < KillChainPhase::ActionsOnObjective);
    }

    #[test]
    fn test_targeting_scope_display() {
        assert!(
            TargetingScope::SingleNation("US".to_string())
                .to_string()
                .contains("US")
        );
        assert!(
            TargetingScope::IndustrySector("Finance".to_string())
                .to_string()
                .contains("Finance")
        );
        assert_eq!(TargetingScope::Opportunistic.to_string(), "Opportunistic");
        assert_eq!(
            TargetingScope::HighlyTargeted.to_string(),
            "Highly Targeted"
        );
    }

    #[test]
    fn test_campaign_store_insert_and_get() {
        let mut store = CampaignStore::new();
        let id = store.insert(make_campaign());
        assert!(id > 0);
        let fetched = store.get(id).unwrap();
        assert_eq!(fetched.name, "Op Ghost");
    }

    #[test]
    fn test_campaign_store_by_actor() {
        let mut store = CampaignStore::new();
        store.insert(make_campaign().with_actor("APT29".to_string()));
        store.insert(make_campaign());
        let apt29 = store.by_actor("APT29");
        assert_eq!(apt29.len(), 1);
    }

    #[test]
    fn test_campaign_store_active() {
        let mut store = CampaignStore::new();
        let mut closed = make_campaign();
        closed.end_date = Some(1_000_000);
        store.insert(closed);
        store.insert(make_campaign());
        assert_eq!(store.active().len(), 1);
    }

    #[test]
    fn test_campaign_store_by_malware_family() {
        let mut store = CampaignStore::new();
        store.insert(make_campaign().with_malware("Cobalt Strike".to_string()));
        store.insert(make_campaign());
        let cs = store.by_malware_family("cobalt strike");
        assert_eq!(cs.len(), 1);
    }

    #[test]
    fn test_campaign_store_count() {
        let mut store = CampaignStore::new();
        store.insert(make_campaign());
        store.insert(make_campaign());
        assert_eq!(store.count(), 2);
    }

    #[test]
    fn test_campaign_store_to_json() {
        let mut store = CampaignStore::new();
        store.insert(make_campaign());
        let json = store.to_json().unwrap();
        assert!(json.contains("Op Ghost"));
    }

    #[test]
    fn test_campaign_with_target_sector_country() {
        let c = make_campaign()
            .with_target_sector("Finance".to_string())
            .with_target_country("US".to_string())
            .with_target_country("GB".to_string());
        assert_eq!(c.target_sectors.len(), 1);
        assert_eq!(c.target_countries.len(), 2);
    }
}
