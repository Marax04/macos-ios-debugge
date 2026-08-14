//! Threat actor attribution engine with 20+ hardcoded actor profiles and
//! evidence-based confidence scoring.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Static threat-actor database entries.
/// Fields: (name, aliases, country, motivations, sectors, ttps, malware, sophistication, since, description)
type ActorRow = (
    &'static str,
    &'static [&'static str],
    Option<&'static str>,
    &'static [&'static str],
    &'static [&'static str],
    &'static [&'static str],
    &'static [&'static str],
    &'static str,
    Option<u16>,
    &'static str,
);

const ACTOR_DATABASE: &[ActorRow] = &[
    ("APT28", &["Fancy Bear","Sofacy","Pawn Storm","STRONTIUM","Forest Blizzard"], Some("RU"), &["espionage"], &["government","defense","energy"], &["T1566","T1078","T1055","T1071","T1082","T1113"], &["win.x_agent","win.zebrocy"], "nation-state", Some(2004), "Russian GRU threat actor targeting Western governments"),
    ("APT29", &["Cozy Bear","The Dukes","YTTRIUM","Midnight Blizzard","IRON HEMLOCK"], Some("RU"), &["espionage"], &["government","think-tank","ngo"], &["T1566","T1195","T1027","T1071"], &["win.cozycar","win.sunburst","win.polyglot"], "nation-state", Some(2008), "Russian SVR cyber espionage group"),
    ("Lazarus", &["HIDDEN COBRA","Zinc","Kimsuky","APT38","Diamond Sleet"], Some("KP"), &["espionage","financial"], &["financial","defense","crypto"], &["T1486","T1566","T1059","T1082"], &["win.wannacry","win.lazarus_rat","win.destover"], "nation-state", Some(2009), "North Korean state-sponsored group"),
    ("Equation Group", &["EQGRP","Shadow Brokers"], Some("US"), &["espionage"], &["government","telecom","energy"], &["T1210","T1055","T1027"], &["win.equation_doublepulsar","win.stuxnet"], "nation-state", Some(2001), "Highly sophisticated NSA-linked operator"),
    ("Turla", &["Snake","Uroburos","Carbon","Waterbug","VENOMOUS BEAR"], Some("RU"), &["espionage"], &["government","military","defense"], &["T1071","T1027","T1070","T1566"], &["win.turla","win.carbon"], "nation-state", Some(2006), "FSB-linked group using novel C2 techniques"),
    ("Sandworm", &["Voodoo Bear","BlackEnergy","Telebots","Seashell Blizzard","IRON VIKING"], Some("RU"), &["sabotage","espionage"], &["energy","government","critical-infrastructure"], &["T1485","T1542","T1210","T1071"], &["win.notpetya","win.industroyer","win.blackenergy"], "nation-state", Some(2008), "GRU-linked destructive operator behind Ukraine power attacks"),
    ("FIN7", &["Carbanak","Cobalt Group","Anunak","Navigator Group"], Some("RU"), &["financial"], &["financial","retail","hospitality"], &["T1566","T1059","T1021","T1055"], &["win.carbanak","win.cobalt_strike","win.darkside"], "high", Some(2013), "Financially-motivated group targeting PoS systems"),
    ("APT1", &["Comment Crew","Comment Group","PLA Unit 61398","Byzantine Candor"], Some("CN"), &["espionage"], &["aerospace","defense","energy"], &["T1566","T1078","T1082"], &["win.gh0strat","win.poisonivy"], "high", Some(2006), "Chinese PLA cyber espionage operation"),
    ("APT10", &["Stone Panda","MenuPass","BRONZE RIVERSIDE","Cloud Hopper","Potassium"], Some("CN"), &["espionage"], &["government","msp","health"], &["T1566","T1021","T1071"], &["win.quasar","win.plugx"], "high", Some(2009), "Chinese MSP-targeting espionage group"),
    ("APT41", &["Double Dragon","Barium","Winnti","BRONZE ATLAS","Brass Typhoon"], Some("CN"), &["espionage","financial"], &["government","gaming","health","telecom"], &["T1195","T1059","T1027","T1055"], &["win.shadowpad","win.plugx"], "nation-state", Some(2012), "Dual espionage / financial operations group"),
    ("Charming Kitten", &["APT35","Phosphorus","TA453","Mint Sandstorm","NewsBeef"], Some("IR"), &["espionage"], &["government","media","human-rights"], &["T1566","T1598","T1078"], &["win.hyperscrape"], "high", Some(2014), "IRGC-linked phishing-focused group"),
    ("MuddyWater", &["MERCURY","Seedworm","Static Kitten","Mango Sandstorm"], Some("IR"), &["espionage"], &["government","telecom","military"], &["T1059","T1566","T1071"], &["win.powerstats"], "medium", Some(2017), "Iranian MOI-linked operator"),
    ("Lazarus (Andariel)", &["Andariel","Silent Chollima","Stonefly","DarkSeoul"], Some("KP"), &["financial","sabotage"], &["financial","defense"], &["T1486","T1059","T1082"], &["win.maui","win.stonefly"], "high", Some(2015), "Lazarus sub-group focused on financial gain and disruption"),
    ("TA505", &["Evil Corp splinter","Hive0065"], Some("RU"), &["financial"], &["financial","retail","health"], &["T1566","T1059","T1027"], &["win.dridex","win.clop","win.flexispy"], "high", Some(2014), "Prolific cybercriminal group distributing Dridex"),
    ("Evil Corp", &["Indrik Spider","Dridex Gang","TA2101"], Some("RU"), &["financial"], &["financial","insurance","government"], &["T1486","T1059","T1021"], &["win.dridex","win.wasted_locker","win.phoenix_locker"], "high", Some(2011), "Russian cybercriminal syndicate responsible for Dridex"),
    ("Wizard Spider", &["UNC1878","Gold Blackburn","Grim Spider","Hive0091"], Some("RU"), &["financial"], &["financial","health","government"], &["T1486","T1059","T1027"], &["win.ryuk","win.conti","win.trickbot","win.bazarloader"], "high", Some(2016), "Russian eCrime group operating TrickBot / Conti / Ryuk"),
    ("REvil", &["Gold Southfield","Pinchy Spider","UNC2190"], Some("RU"), &["financial"], &["technology","legal","food"], &["T1486","T1490","T1078"], &["win.revil","win.sodinokibi"], "high", Some(2019), "RaaS group responsible for Kaseya and JBS attacks"),
    ("LockBit Group", &["LockBit","Gold Mystic","BITWISE SPIDER"], None, &["financial"], &["manufacturing","government","health"], &["T1486","T1490","T1021","T1078"], &["win.lockbit"], "high", Some(2019), "Most prolific RaaS group 2022-2024"),
    ("APT32", &["OceanLotus","APT-C-00","SeaLotus","Bronze Vinewood"], Some("VN"), &["espionage"], &["government","media","civil-society"], &["T1566","T1059","T1071"], &["win.oceanlotus","win.cobalt_strike"], "high", Some(2012), "Vietnamese state-sponsored espionage group"),
    ("Kimsuky", &["Velvet Chollima","Black Banshee","Thallium","Emerald Sleet"], Some("KP"), &["espionage"], &["government","research","defense"], &["T1566","T1598","T1059"], &["win.kimsuky_rat","win.babyshark"], "medium", Some(2012), "North Korean intelligence collection group"),
];

// ---------------------------------------------------------------------------
// EvidenceKind
// ---------------------------------------------------------------------------

/// Type of evidence supporting an attribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceKind {
    /// Shared MITRE ATT&CK TTP matches.
    TtpMatch,
    /// Overlapping infrastructure (IPs, domains).
    InfrastructureOverlap,
    /// Code similarity (shared functions, strings, imports).
    CodeSimilarity,
    /// Shared victim profile / targeting pattern.
    Victimology,
    /// Time-of-day / working hours pattern.
    TemporalPattern,
    /// Linguistic artefacts in binaries or C2 traffic.
    LinguisticArtefact,
    /// Open-source intelligence report attribution.
    OsintReport,
    /// Digital certificate reuse.
    CertificateReuse,
    /// Shared malware family / toolset.
    SharedToolset,
}

impl std::fmt::Display for EvidenceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::TtpMatch => "TTP Match",
            Self::InfrastructureOverlap => "Infrastructure Overlap",
            Self::CodeSimilarity => "Code Similarity",
            Self::Victimology => "Victimology",
            Self::TemporalPattern => "Temporal Pattern",
            Self::LinguisticArtefact => "Linguistic Artefact",
            Self::OsintReport => "OSINT Report",
            Self::CertificateReuse => "Certificate Reuse",
            Self::SharedToolset => "Shared Toolset",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// AttributionEvidence
// ---------------------------------------------------------------------------

/// A single piece of attribution evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionEvidence {
    /// Kind of evidence.
    pub kind: EvidenceKind,
    /// Human-readable description.
    pub description: String,
    /// Confidence contribution [0, 100].
    pub weight: u8,
    /// Supporting artefact (e.g. technique ID, domain, hash).
    pub artefact: Option<String>,
}

impl AttributionEvidence {
    /// Create a new evidence item.
    #[must_use]
    pub fn new(kind: EvidenceKind, description: impl Into<String>, weight: u8) -> Self {
        Self {
            kind,
            description: description.into(),
            weight,
            artefact: None,
        }
    }

    /// Attach an artefact identifier.
    #[must_use]
    pub fn with_artefact(mut self, a: impl Into<String>) -> Self {
        self.artefact = Some(a.into());
        self
    }
}

// ---------------------------------------------------------------------------
// ThreatActor (database entry)
// ---------------------------------------------------------------------------

/// Static profile for a known threat actor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActor {
    /// Common name / designation.
    pub name: String,
    /// Alternative names used in the industry.
    pub aliases: Vec<String>,
    /// Suspected nation-state sponsor (ISO country code).
    pub country: Option<String>,
    /// Motivation (espionage, financial, hacktivism, etc.).
    pub motivation: Vec<String>,
    /// Target industry sectors.
    pub target_sectors: Vec<String>,
    /// Known MITRE ATT&CK technique IDs.
    pub ttps: Vec<String>,
    /// Associated malware family canonical names.
    pub malware_families: Vec<String>,
    /// Sophistication level (low / medium / high / nation-state).
    pub sophistication: String,
    /// Actor active since year (approximate).
    pub active_since: Option<u16>,
    /// Brief description.
    pub description: String,
}

impl ThreatActor {
    /// Return `true` if the given TTP is associated with this actor.
    #[must_use]
    pub fn has_ttp(&self, ttp: &str) -> bool {
        self.ttps.iter().any(|t| t.eq_ignore_ascii_case(ttp))
    }

    /// Return `true` if the actor uses the given malware family.
    #[must_use]
    pub fn uses_malware(&self, family: &str) -> bool {
        self.malware_families
            .iter()
            .any(|f| f.eq_ignore_ascii_case(family))
    }

    /// Return `true` if `name` matches any known alias.
    #[must_use]
    pub fn matches_name(&self, name: &str) -> bool {
        let n = name.to_lowercase();
        self.name.to_lowercase() == n || self.aliases.iter().any(|a| a.to_lowercase() == n)
    }
}

// ---------------------------------------------------------------------------
// AttributionResult
// ---------------------------------------------------------------------------

/// The result of attributing observable artefacts to a threat actor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionResult {
    /// Attributed threat actor name.
    pub actor_name: String,
    /// Overall attribution confidence [0, 100].
    pub confidence: u8,
    /// Evidence items supporting this attribution.
    pub evidence: Vec<AttributionEvidence>,
    /// Whether this is a high-confidence attribution (≥ 70).
    pub high_confidence: bool,
    /// Confidence breakdown by evidence kind.
    pub breakdown: HashMap<String, u8>,
}

impl AttributionResult {
    /// Build an attribution result from evidence items.
    #[must_use]
    pub fn from_evidence(
        actor_name: impl Into<String>,
        evidence: Vec<AttributionEvidence>,
    ) -> Self {
        let total_weight: u32 = evidence.iter().map(|e| u32::from(e.weight)).sum();
        let confidence = (total_weight.min(100)) as u8;

        let mut breakdown: HashMap<String, u8> = HashMap::new();
        for ev in &evidence {
            let k = ev.kind.to_string();
            let entry = breakdown.entry(k).or_insert(0);
            *entry = entry.saturating_add(ev.weight);
        }

        Self {
            actor_name: actor_name.into(),
            confidence,
            high_confidence: confidence >= 70,
            evidence,
            breakdown,
        }
    }

    /// Return the strongest piece of evidence.
    #[must_use]
    pub fn strongest_evidence(&self) -> Option<&AttributionEvidence> {
        self.evidence.iter().max_by_key(|e| e.weight)
    }
}

// ---------------------------------------------------------------------------
// AttributionEngine
// ---------------------------------------------------------------------------

/// Engine that scores observable artefacts against a built-in actor database.
pub struct AttributionEngine {
    actors: Vec<ThreatActor>,
}

impl AttributionEngine {
    /// Create an engine populated with the built-in actor database.
    #[must_use]
    pub fn new() -> Self {
        let mut e = Self { actors: Vec::new() };
        e.populate();
        e
    }

    /// Return all actors.
    #[must_use]
    pub fn actors(&self) -> &[ThreatActor] {
        &self.actors
    }

    /// Find an actor by name or alias.
    #[must_use]
    pub fn find_actor(&self, name: &str) -> Option<&ThreatActor> {
        self.actors.iter().find(|a| a.matches_name(name))
    }

    /// Score a set of TTPs and malware families against all actors in the
    /// database. Returns results sorted by descending confidence.
    #[must_use]
    pub fn attribute(
        &self,
        observed_ttps: &[String],
        observed_families: &[String],
        observed_sectors: &[String],
    ) -> Vec<AttributionResult> {
        let mut results: Vec<AttributionResult> = self
            .actors
            .iter()
            .filter_map(|actor| {
                let mut evidence: Vec<AttributionEvidence> = Vec::new();

                // TTP overlap.
                let ttp_matches: Vec<&String> =
                    observed_ttps.iter().filter(|t| actor.has_ttp(t)).collect();
                for t in &ttp_matches {
                    evidence.push(
                        AttributionEvidence::new(
                            EvidenceKind::TtpMatch,
                            format!("Observed TTP {} matches {}", t, actor.name),
                            15,
                        )
                        .with_artefact((*t).clone()),
                    );
                }

                // Malware family overlap.
                let family_matches: Vec<&String> = observed_families
                    .iter()
                    .filter(|f| actor.uses_malware(f))
                    .collect();
                for fam in &family_matches {
                    evidence.push(
                        AttributionEvidence::new(
                            EvidenceKind::SharedToolset,
                            format!("Malware family {} associated with {}", fam, actor.name),
                            25,
                        )
                        .with_artefact((*fam).clone()),
                    );
                }

                // Victimology overlap.
                let sector_matches: Vec<&String> = observed_sectors
                    .iter()
                    .filter(|s| {
                        actor
                            .target_sectors
                            .iter()
                            .any(|ts| ts.eq_ignore_ascii_case(s))
                    })
                    .collect();
                for sec in &sector_matches {
                    evidence.push(AttributionEvidence::new(
                        EvidenceKind::Victimology,
                        format!("Target sector {} matches {}", sec, actor.name),
                        10,
                    ));
                }

                if evidence.is_empty() {
                    return None;
                }

                Some(AttributionResult::from_evidence(&actor.name, evidence))
            })
            .collect();

        results.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        results
    }

    /// Attribute by TTP list only.
    #[must_use]
    pub fn attribute_by_ttps(&self, ttps: &[String]) -> Vec<AttributionResult> {
        self.attribute(ttps, &[], &[])
    }

    /// Attribute by malware family only.
    #[must_use]
    pub fn attribute_by_family(&self, families: &[String]) -> Vec<AttributionResult> {
        self.attribute(&[], families, &[])
    }

    /// Return actors suspected from a given country code.
    #[must_use]
    pub fn actors_by_country(&self, country: &str) -> Vec<&ThreatActor> {
        self.actors
            .iter()
            .filter(|a| {
                a.country
                    .as_deref().is_some_and(|c| c.eq_ignore_ascii_case(country))
            })
            .collect()
    }

    // ---- Database population ----

    fn populate(&mut self) {
        for &(name, aliases, country, motivation, sectors, ttps, malware, soph, since, desc) in
            ACTOR_DATABASE
        {
            self.actors.push(ThreatActor {
                name: name.to_string(),
                aliases: aliases.iter().map(std::string::ToString::to_string).collect(),
                country: country.map(str::to_string),
                motivation: motivation.iter().map(std::string::ToString::to_string).collect(),
                target_sectors: sectors.iter().map(std::string::ToString::to_string).collect(),
                ttps: ttps.iter().map(std::string::ToString::to_string).collect(),
                malware_families: malware.iter().map(std::string::ToString::to_string).collect(),
                sophistication: soph.to_string(),
                active_since: since,
                description: desc.to_string(),
            });
        }
    }
}

impl Default for AttributionEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> AttributionEngine {
        AttributionEngine::new()
    }

    // ---- Database size ----

    #[test]
    fn test_at_least_20_actors() {
        assert!(engine().actors().len() >= 20);
    }

    // ---- find_actor ----

    #[test]
    fn test_find_actor_by_name() {
        let e = engine();
        assert!(e.find_actor("APT28").is_some());
    }

    #[test]
    fn test_find_actor_by_alias() {
        let e = engine();
        let a = e.find_actor("Fancy Bear");
        assert!(a.is_some());
        assert_eq!(a.unwrap().name, "APT28");
    }

    #[test]
    fn test_find_actor_case_insensitive() {
        assert!(engine().find_actor("apt28").is_some());
    }

    #[test]
    fn test_find_actor_unknown_returns_none() {
        assert!(engine().find_actor("NonExistentActor12345").is_none());
    }

    // ---- ThreatActor helpers ----

    #[test]
    fn test_actor_has_ttp() {
        let e = engine();
        let apt28 = e.find_actor("APT28").unwrap();
        assert!(apt28.has_ttp("T1566"));
    }

    #[test]
    fn test_actor_has_ttp_false() {
        let e = engine();
        let apt28 = e.find_actor("APT28").unwrap();
        assert!(!apt28.has_ttp("T9999"));
    }

    #[test]
    fn test_actor_uses_malware() {
        let e = engine();
        let lazarus = e.find_actor("Lazarus").unwrap();
        assert!(lazarus.uses_malware("win.wannacry"));
    }

    #[test]
    fn test_actor_uses_malware_false() {
        let e = engine();
        let apt29 = e.find_actor("APT29").unwrap();
        assert!(!apt29.uses_malware("win.wannacry"));
    }

    // ---- AttributionEvidence ----

    #[test]
    fn test_evidence_new() {
        let ev = AttributionEvidence::new(EvidenceKind::TtpMatch, "TTP matched", 20);
        assert_eq!(ev.weight, 20);
        assert!(ev.artefact.is_none());
    }

    #[test]
    fn test_evidence_with_artefact() {
        let ev = AttributionEvidence::new(EvidenceKind::TtpMatch, "TTP", 20).with_artefact("T1055");
        assert_eq!(ev.artefact.as_deref(), Some("T1055"));
    }

    // ---- EvidenceKind display ----

    #[test]
    fn test_evidence_kind_display() {
        assert_eq!(EvidenceKind::TtpMatch.to_string(), "TTP Match");
        assert_eq!(EvidenceKind::CodeSimilarity.to_string(), "Code Similarity");
        assert_eq!(EvidenceKind::SharedToolset.to_string(), "Shared Toolset");
    }

    // ---- AttributionResult ----

    #[test]
    fn test_attribution_result_from_evidence() {
        let ev = vec![
            AttributionEvidence::new(EvidenceKind::TtpMatch, "T1", 30),
            AttributionEvidence::new(EvidenceKind::SharedToolset, "Fam", 25),
        ];
        let r = AttributionResult::from_evidence("APT28", ev);
        assert_eq!(r.actor_name, "APT28");
        assert_eq!(r.confidence, 55);
        assert!(!r.high_confidence);
    }

    #[test]
    fn test_attribution_result_high_confidence() {
        let ev = vec![
            AttributionEvidence::new(EvidenceKind::TtpMatch, "T1", 30),
            AttributionEvidence::new(EvidenceKind::SharedToolset, "Fam", 25),
            AttributionEvidence::new(EvidenceKind::Victimology, "Sec", 20),
        ];
        let r = AttributionResult::from_evidence("APT28", ev);
        assert!(r.high_confidence);
    }

    #[test]
    fn test_attribution_result_capped_at_100() {
        let ev = vec![
            AttributionEvidence::new(EvidenceKind::TtpMatch, "T1", 60),
            AttributionEvidence::new(EvidenceKind::TtpMatch, "T2", 60),
        ];
        let r = AttributionResult::from_evidence("APT28", ev);
        assert!(r.confidence <= 100);
    }

    #[test]
    fn test_attribution_strongest_evidence() {
        let ev = vec![
            AttributionEvidence::new(EvidenceKind::TtpMatch, "T1", 15),
            AttributionEvidence::new(EvidenceKind::SharedToolset, "Fam", 25),
        ];
        let r = AttributionResult::from_evidence("APT28", ev);
        let strongest = r.strongest_evidence().unwrap();
        assert_eq!(strongest.weight, 25);
    }

    // ---- AttributionEngine::attribute ----

    #[test]
    fn test_attribute_by_wannacry_family() {
        let results = engine().attribute_by_family(&["win.wannacry".to_string()]);
        assert!(!results.is_empty());
        // Lazarus should be top result.
        assert_eq!(results[0].actor_name, "Lazarus");
    }

    #[test]
    fn test_attribute_by_conti_family() {
        let results = engine().attribute_by_family(&["win.conti".to_string()]);
        assert!(!results.is_empty());
        assert_eq!(results[0].actor_name, "Wizard Spider");
    }

    #[test]
    fn test_attribute_by_dridex_family() {
        let results = engine().attribute_by_family(&["win.dridex".to_string()]);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_attribute_by_ttps_sorted_descending() {
        let ttps: Vec<String> = vec!["T1486".to_string(), "T1490".to_string()];
        let results = engine().attribute_by_ttps(&ttps);
        for w in results.windows(2) {
            assert!(w[0].confidence >= w[1].confidence);
        }
    }

    #[test]
    fn test_attribute_no_match_returns_empty() {
        let results = engine().attribute(
            &["T9999".to_string()],
            &["win.nonexistent".to_string()],
            &[],
        );
        assert!(results.is_empty());
    }

    #[test]
    fn test_attribute_with_sector() {
        let results = engine().attribute(&[], &[], &["government".to_string()]);
        assert!(!results.is_empty());
    }

    // ---- actors_by_country ----

    #[test]
    fn test_actors_by_country_ru() {
        let e = engine();
        let ru = e.actors_by_country("RU");
        assert!(!ru.is_empty());
        assert!(ru.iter().all(|a| a.country.as_deref() == Some("RU")));
    }

    #[test]
    fn test_actors_by_country_cn() {
        let e = engine();
        let cn = e.actors_by_country("CN");
        assert!(!cn.is_empty());
    }

    #[test]
    fn test_actors_by_country_kp() {
        let e = engine();
        let kp = e.actors_by_country("KP");
        assert!(!kp.is_empty());
    }

    #[test]
    fn test_actors_by_country_unknown_empty() {
        let e = engine();
        let xx = e.actors_by_country("ZZ");
        assert!(xx.is_empty());
    }

    // ---- Attribution result breakdown ----

    #[test]
    fn test_breakdown_populated() {
        let results = engine().attribute_by_family(&["win.conti".to_string()]);
        assert!(!results.is_empty());
        assert!(!results[0].breakdown.is_empty());
    }

    // ---- multiple evidence kinds ----

    #[test]
    fn test_attribute_combined_ttp_and_family() {
        let ttps = vec!["T1486".to_string()];
        let families = vec!["win.ryuk".to_string()];
        let results = engine().attribute(&ttps, &families, &[]);
        // At least Wizard Spider should appear.
        assert!(results.iter().any(|r| r.actor_name == "Wizard Spider"));
    }

    // ---- AttributionEvidence serde ----

    #[test]
    fn test_evidence_serde() {
        let ev = AttributionEvidence::new(EvidenceKind::CodeSimilarity, "code match", 20)
            .with_artefact("deadbeef");
        let json = serde_json::to_string(&ev).unwrap();
        let ev2: AttributionEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(ev2.weight, 20);
        assert_eq!(ev2.artefact.as_deref(), Some("deadbeef"));
    }

    // ---- AttributionResult serde ----

    #[test]
    fn test_attribution_result_serde() {
        let ev = vec![AttributionEvidence::new(
            EvidenceKind::TtpMatch,
            "T1566",
            30,
        )];
        let r = AttributionResult::from_evidence("APT28", ev);
        let json = serde_json::to_string(&r).unwrap();
        let r2: AttributionResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r2.actor_name, "APT28");
        assert_eq!(r2.confidence, 30);
    }

    // ---- ThreatActor serde ----

    #[test]
    fn test_threat_actor_serde() {
        let e = engine();
        let apt28 = e.find_actor("APT28").unwrap().clone();
        let json = serde_json::to_string(&apt28).unwrap();
        let apt28b: ThreatActor = serde_json::from_str(&json).unwrap();
        assert_eq!(apt28b.name, "APT28");
        assert!(!apt28b.ttps.is_empty());
    }

    // ---- attribution returns results sorted by confidence ----

    #[test]
    fn test_results_sorted_descending() {
        let families = vec![
            "win.wannacry".to_string(),
            "win.trickbot".to_string(),
            "win.ryuk".to_string(),
        ];
        let results = engine().attribute_by_family(&families);
        for w in results.windows(2) {
            assert!(w[0].confidence >= w[1].confidence);
        }
    }

    // ---- actor sophistication ----

    #[test]
    fn test_nation_state_actors_exist() {
        let e = engine();
        
        assert!(e
            .actors()
            .iter().any(|a| a.sophistication == "nation-state"));
    }

    // ---- APT29 aliases ----

    #[test]
    fn test_apt29_aliases() {
        let e = engine();
        assert!(e.find_actor("Cozy Bear").is_some());
        assert!(e.find_actor("IRON HEMLOCK").is_some());
        assert!(e.find_actor("Midnight Blizzard").is_some());
    }

    // ---- Equation Group ----

    #[test]
    fn test_equation_group_exists() {
        assert!(engine().find_actor("Equation Group").is_some());
    }

    // ---- MuddyWater ----

    #[test]
    fn test_muddywater_exists() {
        let e = engine();
        assert!(e.find_actor("MuddyWater").is_some());
        let seedworm = e.find_actor("Seedworm");
        assert!(seedworm.is_some());
        assert_eq!(seedworm.unwrap().name, "MuddyWater");
    }

    // ---- actors_by_country IR ----

    #[test]
    fn test_actors_by_country_ir() {
        let e = engine();
        let ir = e.actors_by_country("IR");
        assert!(!ir.is_empty());
    }

    // ---- Evidence kind display exhaustive ----

    #[test]
    fn test_evidence_kind_all_display() {
        let kinds = [
            EvidenceKind::TtpMatch,
            EvidenceKind::InfrastructureOverlap,
            EvidenceKind::CodeSimilarity,
            EvidenceKind::Victimology,
            EvidenceKind::TemporalPattern,
            EvidenceKind::LinguisticArtefact,
            EvidenceKind::OsintReport,
            EvidenceKind::CertificateReuse,
            EvidenceKind::SharedToolset,
        ];
        for k in &kinds {
            assert!(!k.to_string().is_empty());
        }
    }

    // ---- strongest_evidence with single item ----

    #[test]
    fn test_strongest_evidence_single() {
        let ev = vec![AttributionEvidence::new(
            EvidenceKind::TtpMatch,
            "T1566",
            40,
        )];
        let r = AttributionResult::from_evidence("X", ev);
        assert_eq!(r.strongest_evidence().unwrap().weight, 40);
    }

    // ---- FIN7 aliases ----

    #[test]
    fn test_fin7_aliases() {
        let e = engine();
        assert!(e.find_actor("Carbanak").is_some());
        assert!(e.find_actor("FIN7").is_some());
    }

    // ---- active_since field ----

    #[test]
    fn test_apt28_active_since() {
        let e = engine();
        let apt28 = e.find_actor("APT28").unwrap();
        assert_eq!(apt28.active_since, Some(2004));
    }

    // ---- Turla country ----

    #[test]
    fn test_turla_country_ru() {
        let e = engine();
        let turla = e.find_actor("Turla").unwrap();
        assert_eq!(turla.country.as_deref(), Some("RU"));
    }

    // ---- actors all have descriptions ----

    #[test]
    fn test_all_actors_have_descriptions() {
        let e = engine();
        for actor in e.actors() {
            assert!(
                !actor.description.is_empty(),
                "Actor {} missing description",
                actor.name
            );
        }
    }

    // ---- actors all have at least one TTP ----

    #[test]
    fn test_all_actors_have_ttps() {
        let e = engine();
        for actor in e.actors() {
            assert!(!actor.ttps.is_empty(), "Actor {} has no TTPs", actor.name);
        }
    }

    // ---- Kimsuky aliases ----

    #[test]
    fn test_kimsuky_aliases() {
        let e = engine();
        assert!(e.find_actor("Kimsuky").is_some());
        assert!(e.find_actor("Velvet Chollima").is_some());
    }

    // ---- REvil malware families ----

    #[test]
    fn test_revil_malware_families() {
        let e = engine();
        let revil = e.find_actor("REvil").unwrap();
        assert!(revil.uses_malware("win.revil"));
        assert!(revil.uses_malware("win.sodinokibi"));
    }

    // ---- Lazarus attribution with Andariel alias ----

    #[test]
    fn test_lazarus_andariel_found() {
        let e = engine();
        assert!(e.find_actor("Andariel").is_some());
    }

    // ---- Multiple families → multiple attributions ----

    #[test]
    fn test_multiple_families_multiple_results() {
        let families = vec![
            "win.wannacry".to_string(),
            "win.cobalt_strike".to_string(),
            "win.conti".to_string(),
        ];
        let results = engine().attribute_by_family(&families);
        // Multiple actors should match at least one family each.
        assert!(results.len() >= 2);
    }

    // ---- attribution evidence with zero weight ----

    #[test]
    fn test_zero_weight_evidence() {
        let ev = AttributionEvidence::new(EvidenceKind::OsintReport, "low confidence", 0);
        let r = AttributionResult::from_evidence("Unknown", vec![ev]);
        assert_eq!(r.confidence, 0);
        assert!(!r.high_confidence);
    }

    // ---- actor active_since for different actors ----

    #[test]
    fn test_lazarus_active_since() {
        let e = engine();
        let l = e.find_actor("Lazarus").unwrap();
        assert_eq!(l.active_since, Some(2009));
    }

    #[test]
    fn test_sandworm_active_since() {
        let e = engine();
        let s = e.find_actor("Sandworm").unwrap();
        assert_eq!(s.active_since, Some(2008));
    }

    // ---- actors_by_country VN ----

    #[test]
    fn test_actors_by_country_vn() {
        let e = engine();
        let vn = e.actors_by_country("VN");
        assert!(!vn.is_empty());
    }

    // ---- LockBit group aliases ----

    #[test]
    fn test_lockbit_aliases() {
        let e = engine();
        assert!(e.find_actor("LockBit Group").is_some());
        assert!(e.find_actor("Gold Mystic").is_some());
    }
}
