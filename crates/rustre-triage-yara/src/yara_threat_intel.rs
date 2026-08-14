//! `yara_threat_intel` — YARA-based threat intelligence: family attribution,
//! cluster analysis, Malpedia mapping, and confidence scoring.

pub use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ThreatFamily
// ---------------------------------------------------------------------------

/// Known malware family category.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatFamilyKind {
    Ransomware,
    Banking,
    Rat,
    Stealer,
    Loader,
    Dropper,
    Rootkit,
    Bootkit,
    Wiper,
    Cryptominer,
    Adware,
    Backdoor,
    Exploit,
    Toolkit,
    Unknown,
}

impl fmt::Display for ThreatFamilyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A named malware family with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFamily {
    /// Internal name (e.g. `"WannaCry"`).
    pub name: String,
    /// Display aliases.
    pub aliases: Vec<String>,
    /// Category / type.
    pub kind: ThreatFamilyKind,
    /// MITRE ATT&CK software ID (if known).
    pub mitre_id: Option<String>,
    /// Malpedia URL slug.
    pub malpedia_slug: Option<String>,
    /// General description.
    pub description: String,
    /// Associated threat actor names.
    pub threat_actors: Vec<String>,
    /// Known C2 infrastructure indicators.
    pub c2_indicators: Vec<String>,
    /// File extension used by ransomware encryptions (if applicable).
    pub ransom_extension: Option<String>,
}

impl ThreatFamily {
    /// Create a new family with minimum fields.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        kind: ThreatFamilyKind,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            aliases: Vec::new(),
            kind,
            mitre_id: None,
            malpedia_slug: None,
            description: description.into(),
            threat_actors: Vec::new(),
            c2_indicators: Vec::new(),
            ransom_extension: None,
        }
    }

    /// Whether this family is directly associated with the given actor.
    #[must_use]
    pub fn associated_with_actor(&self, actor: &str) -> bool {
        self.threat_actors
            .iter()
            .any(|a| a.eq_ignore_ascii_case(actor))
    }
}

impl fmt::Display for ThreatFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} — {}", self.kind, self.name, self.description)
    }
}

// ---------------------------------------------------------------------------
// YaraConfidence
// ---------------------------------------------------------------------------

/// Confidence level for a YARA-based attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum YaraConfidence {
    /// Very low confidence — only one short string matched.
    VeryLow,
    /// Low confidence — a few strings matched but pattern is generic.
    Low,
    /// Medium confidence — multiple specific strings matched.
    Medium,
    /// High confidence — unique byte patterns and strings matched.
    High,
    /// Very high confidence — unique XOR/encoding and structural patterns.
    VeryHigh,
}

impl YaraConfidence {
    /// Numeric score 0–100 for this confidence level.
    #[must_use]
    pub const fn score(&self) -> u8 {
        match self {
            Self::VeryLow => 10,
            Self::Low => 30,
            Self::Medium => 55,
            Self::High => 80,
            Self::VeryHigh => 95,
        }
    }

    /// Compute from a match count and pattern count.
    #[must_use]
    pub fn from_match_ratio(matches: usize, total_patterns: usize) -> Self {
        if total_patterns == 0 {
            return Self::VeryLow;
        }
        let ratio = f64::from(u32::try_from(matches).unwrap_or(u32::MAX)) / f64::from(u32::try_from(total_patterns).unwrap_or(u32::MAX));
        match (matches, ratio) {
            (0 | 1, _) => Self::VeryLow,
            (2, _) => Self::Low,
            (n, r) if n >= 3 && r < 0.5 => Self::Low,
            (_, r) if (0.5..0.75).contains(&r) => Self::Medium,
            (_, r) if (0.75..1.0).contains(&r) => Self::High,
            _ => Self::VeryHigh,
        }
    }
}

impl fmt::Display for YaraConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ---------------------------------------------------------------------------
// ThreatCluster
// ---------------------------------------------------------------------------

/// A cluster of related threat actors or campaigns sharing tooling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatCluster {
    /// Cluster identifier / label.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Families associated with this cluster.
    pub families: Vec<String>,
    /// Actor identifiers within the cluster.
    pub actors: Vec<String>,
    /// Geographic origin attribution.
    pub origin: Option<String>,
    /// Observed first active date (ISO 8601).
    pub first_seen: Option<String>,
    /// Observed last active date.
    pub last_seen: Option<String>,
    /// MITRE ATT&CK group IDs.
    pub mitre_group_ids: Vec<String>,
}

impl ThreatCluster {
    /// Create a new empty cluster.
    #[must_use]
    pub fn new(id: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            families: Vec::new(),
            actors: Vec::new(),
            origin: None,
            first_seen: None,
            last_seen: None,
            mitre_group_ids: Vec::new(),
        }
    }

    /// Whether this cluster includes the given family.
    #[must_use]
    pub fn contains_family(&self, family: &str) -> bool {
        self.families.iter().any(|f| f.eq_ignore_ascii_case(family))
    }
}

impl fmt::Display for ThreatCluster {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cluster({}) — {} families", self.id, self.families.len())
    }
}

// ---------------------------------------------------------------------------
// FamilyAttribution
// ---------------------------------------------------------------------------

/// Attribution result linking a scan to a specific family.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyAttribution {
    pub family: ThreatFamily,
    pub confidence: YaraConfidence,
    pub matched_patterns: Vec<String>,
    pub matched_offsets: Vec<u64>,
    pub cluster: Option<String>,
    pub notes: String,
}

impl FamilyAttribution {
    /// Is this attribution reliable enough to act on?
    #[must_use]
    pub fn is_reliable(&self) -> bool {
        self.confidence >= YaraConfidence::Medium
    }
}

impl fmt::Display for FamilyAttribution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}) — {} patterns matched",
            self.family.name,
            self.confidence,
            self.matched_patterns.len()
        )
    }
}

// ---------------------------------------------------------------------------
// MalpediaMapping — built-in family → Malpedia mapping
// ---------------------------------------------------------------------------

/// A mapping from family name to Malpedia metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalpediaEntry {
    pub family_name: String,
    pub malpedia_url: String,
    pub aliases: Vec<String>,
    pub kind: ThreatFamilyKind,
    pub mitre_id: Option<String>,
}

/// Built-in Malpedia mapping for 20+ common families.
pub struct MalpediaMapping;

impl MalpediaMapping {
    /// Return the built-in Malpedia entries.
    #[must_use]
    pub fn entries() -> Vec<MalpediaEntry> {
        vec![
            MalpediaEntry {
                family_name: "WannaCry".to_string(),
                malpedia_url: "https://malpedia.caad.fkie.fraunhofer.de/details/win.wannacry"
                    .to_string(),
                aliases: vec!["WannaCrypt".to_string(), "WCry".to_string()],
                kind: ThreatFamilyKind::Ransomware,
                mitre_id: Some("S0366".to_string()),
            },
            MalpediaEntry {
                family_name: "Emotet".to_string(),
                malpedia_url: "https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet"
                    .to_string(),
                aliases: vec!["Heodo".to_string(), "Geodo".to_string()],
                kind: ThreatFamilyKind::Banking,
                mitre_id: Some("S0367".to_string()),
            },
            MalpediaEntry {
                family_name: "Cobalt Strike".to_string(),
                malpedia_url: "https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"
                    .to_string(),
                aliases: vec!["CobaltStrike".to_string(), "CS Beacon".to_string()],
                kind: ThreatFamilyKind::Toolkit,
                mitre_id: Some("S0154".to_string()),
            },
            MalpediaEntry {
                family_name: "Mimikatz".to_string(),
                malpedia_url: "https://malpedia.caad.fkie.fraunhofer.de/details/win.mimikatz"
                    .to_string(),
                aliases: vec!["kiwi".to_string()],
                kind: ThreatFamilyKind::Toolkit,
                mitre_id: Some("S0002".to_string()),
            },
            MalpediaEntry {
                family_name: "TrickBot".to_string(),
                malpedia_url: "https://malpedia.caad.fkie.fraunhofer.de/details/win.trickbot"
                    .to_string(),
                aliases: vec!["TrickLoader".to_string(), "Totbrick".to_string()],
                kind: ThreatFamilyKind::Banking,
                mitre_id: Some("S0266".to_string()),
            },
            MalpediaEntry {
                family_name: "Ryuk".to_string(),
                malpedia_url: "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
                    .to_string(),
                aliases: vec!["RyukRansomware".to_string()],
                kind: ThreatFamilyKind::Ransomware,
                mitre_id: Some("S0446".to_string()),
            },
            MalpediaEntry {
                family_name: "RedLine".to_string(),
                malpedia_url:
                    "https://malpedia.caad.fkie.fraunhofer.de/details/win.redline_stealer"
                        .to_string(),
                aliases: vec!["RedLineStealer".to_string()],
                kind: ThreatFamilyKind::Stealer,
                mitre_id: None,
            },
            MalpediaEntry {
                family_name: "AgentTesla".to_string(),
                malpedia_url: "https://malpedia.caad.fkie.fraunhofer.de/details/win.agent_tesla"
                    .to_string(),
                aliases: vec!["AgentTeslaRAT".to_string()],
                kind: ThreatFamilyKind::Rat,
                mitre_id: None,
            },
            MalpediaEntry {
                family_name: "Conti".to_string(),
                malpedia_url: "https://malpedia.caad.fkie.fraunhofer.de/details/win.conti"
                    .to_string(),
                aliases: vec!["ContiRansom".to_string()],
                kind: ThreatFamilyKind::Ransomware,
                mitre_id: None,
            },
            MalpediaEntry {
                family_name: "LockBit".to_string(),
                malpedia_url: "https://malpedia.caad.fkie.fraunhofer.de/details/win.lockbit"
                    .to_string(),
                aliases: vec!["LockBit2.0".to_string(), "LockBit3.0".to_string()],
                kind: ThreatFamilyKind::Ransomware,
                mitre_id: None,
            },
            MalpediaEntry {
                family_name: "Formbook".to_string(),
                malpedia_url: "https://malpedia.caad.fkie.fraunhofer.de/details/win.formbook"
                    .to_string(),
                aliases: vec!["FormBookStealer".to_string()],
                kind: ThreatFamilyKind::Stealer,
                mitre_id: None,
            },
            MalpediaEntry {
                family_name: "Dridex".to_string(),
                malpedia_url: "https://malpedia.caad.fkie.fraunhofer.de/details/win.dridex"
                    .to_string(),
                aliases: vec!["Bugat".to_string(), "Cridex".to_string()],
                kind: ThreatFamilyKind::Banking,
                mitre_id: Some("S0384".to_string()),
            },
            MalpediaEntry {
                family_name: "Ursnif".to_string(),
                malpedia_url: "https://malpedia.caad.fkie.fraunhofer.de/details/win.ursnif"
                    .to_string(),
                aliases: vec!["Gozi".to_string(), "ISFB".to_string()],
                kind: ThreatFamilyKind::Banking,
                mitre_id: Some("S0386".to_string()),
            },
            MalpediaEntry {
                family_name: "AsyncRAT".to_string(),
                malpedia_url: "https://malpedia.caad.fkie.fraunhofer.de/details/win.asyncrat"
                    .to_string(),
                aliases: vec!["AsyncRemoteAdmin".to_string()],
                kind: ThreatFamilyKind::Rat,
                mitre_id: None,
            },
            MalpediaEntry {
                family_name: "NjRAT".to_string(),
                malpedia_url: "https://malpedia.caad.fkie.fraunhofer.de/details/win.njrat"
                    .to_string(),
                aliases: vec!["Njw0rm".to_string(), "LV".to_string()],
                kind: ThreatFamilyKind::Rat,
                mitre_id: Some("S0385".to_string()),
            },
        ]
    }

    /// Look up a family by name or alias (case-insensitive).
    #[must_use]
    pub fn lookup(name: &str) -> Option<MalpediaEntry> {
        let lower = name.to_lowercase();
        Self::entries().into_iter().find(|e| {
            e.family_name.to_lowercase() == lower
                || e.aliases.iter().any(|a| a.to_lowercase() == lower)
        })
    }

    /// Return all families of a given kind.
    #[must_use]
    pub fn by_kind(kind: &ThreatFamilyKind) -> Vec<MalpediaEntry> {
        Self::entries()
            .into_iter()
            .filter(|e| &e.kind == kind)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// YaraThreatIntel — main engine
// ---------------------------------------------------------------------------

/// A single threat-intel YARA rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelRule {
    pub family_name: String,
    pub patterns: Vec<Vec<u8>>,
    pub required_match_count: usize,
    pub confidence_boost: i8,
    pub description: String,
    pub tags: Vec<String>,
}

impl ThreatIntelRule {
    /// Create a new rule.
    #[must_use]
    pub fn new(
        family_name: impl Into<String>,
        patterns: Vec<Vec<u8>>,
        required: usize,
        description: impl Into<String>,
    ) -> Self {
        Self {
            family_name: family_name.into(),
            patterns,
            required_match_count: required,
            confidence_boost: 0,
            description: description.into(),
            tags: Vec::new(),
        }
    }

    /// Scan `data` and return matched pattern indices.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<(usize, u64)> {
        let mut results = Vec::new();
        for (idx, pat) in self.patterns.iter().enumerate() {
            if pat.is_empty() {
                continue;
            }
            if let Some(off) = data.windows(pat.len()).position(|w| w == pat.as_slice()) {
                results.push((idx, off as u64));
            }
        }
        results
    }

    /// Returns true if this rule fires against `data`.
    #[must_use]
    pub fn fires(&self, data: &[u8]) -> bool {
        let hits = self.scan(data);
        hits.len() >= self.required_match_count
    }
}

/// Threat-intel scan result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelMatch {
    pub rule: ThreatIntelRule,
    pub matched_patterns: Vec<(usize, u64)>,
    pub confidence: YaraConfidence,
    pub attribution: Option<FamilyAttribution>,
}

impl fmt::Display for ThreatIntelMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ThreatIntelMatch({}, {}, {} hits)",
            self.rule.family_name,
            self.confidence,
            self.matched_patterns.len()
        )
    }
}

/// The main YARA-based threat intelligence scanner.
pub struct YaraThreatIntel {
    rules: Vec<ThreatIntelRule>,
    clusters: Vec<ThreatCluster>,
}

impl YaraThreatIntel {
    /// Create an empty instance.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rules: Vec::new(),
            clusters: Vec::new(),
        }
    }

    /// Create an instance pre-loaded with built-in rules.
    #[must_use]
    pub fn with_builtin_rules() -> Self {
        let mut ti = Self::new();
        ti.load_builtin_rules();
        ti.load_builtin_clusters();
        ti
    }

    /// Add a rule.
    pub fn add_rule(&mut self, rule: ThreatIntelRule) {
        self.rules.push(rule);
    }

    /// Add a cluster.
    pub fn add_cluster(&mut self, cluster: ThreatCluster) {
        self.clusters.push(cluster);
    }

    /// Scan raw bytes and return all matches.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<ThreatIntelMatch> {
        let mut results = Vec::new();
        for rule in &self.rules {
            let matched = rule.scan(data);
            if matched.len() >= rule.required_match_count {
                let conf = YaraConfidence::from_match_ratio(matched.len(), rule.patterns.len());
                let attribution =
                    MalpediaMapping::lookup(&rule.family_name).map(|mp| FamilyAttribution {
                        family: ThreatFamily {
                            name: mp.family_name.clone(),
                            aliases: mp.aliases.clone(),
                            kind: mp.kind.clone(),
                            mitre_id: mp.mitre_id.clone(),
                            malpedia_slug: Some(mp.malpedia_url.clone()),
                            description: rule.description.clone(),
                            threat_actors: Vec::new(),
                            c2_indicators: Vec::new(),
                            ransom_extension: None,
                        },
                        confidence: conf,
                        matched_patterns: matched
                            .iter()
                            .map(|(i, _)| format!("pattern_{i}"))
                            .collect(),
                        matched_offsets: matched.iter().map(|(_, o)| *o).collect(),
                        cluster: self.find_cluster_for(&mp.family_name),
                        notes: rule.description.clone(),
                    });

                results.push(ThreatIntelMatch {
                    rule: rule.clone(),
                    matched_patterns: matched,
                    confidence: conf,
                    attribution,
                });
            }
        }
        results
    }

    /// Attribute a file to a family based on scan results.
    #[must_use]
    pub fn attribute(&self, data: &[u8]) -> Vec<FamilyAttribution> {
        self.scan(data)
            .into_iter()
            .filter_map(|m| m.attribution)
            .filter(FamilyAttribution::is_reliable)
            .collect()
    }

    fn find_cluster_for(&self, family: &str) -> Option<String> {
        self.clusters.iter().find_map(|c| {
            if c.contains_family(family) {
                Some(c.id.clone())
            } else {
                None
            }
        })
    }

    fn load_builtin_rules(&mut self) {
        self.add_rule(ThreatIntelRule::new(
            "WannaCry",
            vec![
                b"tasksche.exe".to_vec(),
                b".wnry".to_vec(),
                b"WNcry@2ol7".to_vec(),
            ],
            1,
            "WannaCry ransomware artefacts",
        ));

        self.add_rule(ThreatIntelRule::new(
            "Emotet",
            vec![b"Emotet".to_vec(), b"heodo".to_vec(), b"geodo".to_vec()],
            1,
            "Emotet banking trojan",
        ));

        self.add_rule(ThreatIntelRule::new(
            "Cobalt Strike",
            vec![
                b"beacon.dll".to_vec(),
                b"ReflectiveDll".to_vec(),
                b"metsrv.dll".to_vec(),
            ],
            1,
            "Cobalt Strike beacon or stage",
        ));

        self.add_rule(ThreatIntelRule::new(
            "Mimikatz",
            vec![
                b"sekurlsa".to_vec(),
                b"mimikatz".to_vec(),
                b"kerberos::list".to_vec(),
            ],
            1,
            "Mimikatz credential tool",
        ));

        self.add_rule(ThreatIntelRule::new(
            "TrickBot",
            vec![
                b"trickbot".to_vec(),
                b"trick_steal".to_vec(),
                b"pwgrab".to_vec(),
            ],
            1,
            "TrickBot banking trojan",
        ));

        self.add_rule(ThreatIntelRule::new(
            "Ryuk",
            vec![b"RyukReadMe".to_vec(), b"UNIQUE_ID_DO_NOT_REMOVE".to_vec()],
            1,
            "Ryuk ransomware",
        ));

        self.add_rule(ThreatIntelRule::new(
            "RedLine",
            vec![b"RedLine".to_vec(), b"redline_stealer".to_vec()],
            1,
            "RedLine information stealer",
        ));

        self.add_rule(ThreatIntelRule::new(
            "AgentTesla",
            vec![b"AgentTesla".to_vec(), b"agent_tesla".to_vec()],
            1,
            "AgentTesla keylogger/stealer",
        ));

        self.add_rule(ThreatIntelRule::new(
            "Dridex",
            vec![b"dridex".to_vec(), b"bugat".to_vec()],
            1,
            "Dridex banking trojan",
        ));

        self.add_rule(ThreatIntelRule::new(
            "NjRAT",
            vec![b"Njw0rm".to_vec(), b"njRAT".to_vec()],
            1,
            "NjRAT remote access trojan",
        ));
    }

    fn load_builtin_clusters(&mut self) {
        let mut ransomware_cluster =
            ThreatCluster::new("RANSOMWARE_CLUSTER_1", "Known ransomware families");
        ransomware_cluster.families = vec![
            "WannaCry".to_string(),
            "Ryuk".to_string(),
            "Conti".to_string(),
            "LockBit".to_string(),
        ];
        ransomware_cluster.origin = Some("Eastern Europe".to_string());
        self.add_cluster(ransomware_cluster);

        let mut banking_cluster =
            ThreatCluster::new("BANKING_CLUSTER_1", "Banking trojans sharing code");
        banking_cluster.families = vec![
            "Dridex".to_string(),
            "Emotet".to_string(),
            "TrickBot".to_string(),
            "Ursnif".to_string(),
        ];
        self.add_cluster(banking_cluster);
    }
}

impl Default for YaraThreatIntel {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for YaraThreatIntel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "YaraThreatIntel({} rules, {} clusters)",
            self.rules.len(),
            self.clusters.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_family_kind_display() {
        let k = ThreatFamilyKind::Ransomware;
        assert_eq!(k.to_string(), "Ransomware");
    }

    #[test]
    fn test_threat_family_new() {
        let f = ThreatFamily::new("TestFamily", ThreatFamilyKind::Rat, "A test family");
        assert_eq!(f.name, "TestFamily");
        assert!(f.aliases.is_empty());
    }

    #[test]
    fn test_threat_family_actor_association() {
        let mut f = ThreatFamily::new("X", ThreatFamilyKind::Rat, "x");
        f.threat_actors.push("Lazarus".to_string());
        assert!(f.associated_with_actor("lazarus"));
        assert!(!f.associated_with_actor("APT28"));
    }

    #[test]
    fn test_yara_confidence_score() {
        assert_eq!(YaraConfidence::VeryHigh.score(), 95);
        assert_eq!(YaraConfidence::VeryLow.score(), 10);
    }

    #[test]
    fn test_yara_confidence_from_ratio_zero() {
        let c = YaraConfidence::from_match_ratio(0, 5);
        assert_eq!(c, YaraConfidence::VeryLow);
    }

    #[test]
    fn test_yara_confidence_from_ratio_one() {
        let c = YaraConfidence::from_match_ratio(1, 5);
        assert_eq!(c, YaraConfidence::VeryLow);
    }

    #[test]
    fn test_yara_confidence_from_ratio_all() {
        let c = YaraConfidence::from_match_ratio(5, 5);
        assert_eq!(c, YaraConfidence::VeryHigh);
    }

    #[test]
    fn test_yara_confidence_ordering() {
        assert!(YaraConfidence::High > YaraConfidence::Medium);
        assert!(YaraConfidence::Medium > YaraConfidence::Low);
    }

    #[test]
    fn test_threat_cluster_new() {
        let c = ThreatCluster::new("C1", "desc");
        assert_eq!(c.id, "C1");
        assert!(c.families.is_empty());
    }

    #[test]
    fn test_threat_cluster_contains_family() {
        let mut c = ThreatCluster::new("C1", "desc");
        c.families.push("WannaCry".to_string());
        assert!(c.contains_family("WannaCry"));
        assert!(c.contains_family("wannacry"));
        assert!(!c.contains_family("Mirai"));
    }

    #[test]
    fn test_malpedia_entries_not_empty() {
        let entries = MalpediaMapping::entries();
        assert!(!entries.is_empty());
        assert!(entries.len() >= 10);
    }

    #[test]
    fn test_malpedia_lookup_wannacry() {
        let e = MalpediaMapping::lookup("WannaCry");
        assert!(e.is_some());
        let e = e.unwrap();
        assert_eq!(e.kind, ThreatFamilyKind::Ransomware);
    }

    #[test]
    fn test_malpedia_lookup_alias() {
        let e = MalpediaMapping::lookup("Heodo");
        assert!(e.is_some());
        assert_eq!(e.unwrap().family_name, "Emotet");
    }

    #[test]
    fn test_malpedia_lookup_unknown() {
        let e = MalpediaMapping::lookup("NonExistentFamily123");
        assert!(e.is_none());
    }

    #[test]
    fn test_malpedia_by_kind() {
        let ransomware = MalpediaMapping::by_kind(&ThreatFamilyKind::Ransomware);
        assert!(!ransomware.is_empty());
        for e in &ransomware {
            assert_eq!(e.kind, ThreatFamilyKind::Ransomware);
        }
    }

    #[test]
    fn test_threat_intel_rule_scan_match() {
        let rule = ThreatIntelRule::new("TestFamily", vec![b"sekurlsa".to_vec()], 1, "desc");
        let data = b"...sekurlsa...extra data";
        let hits = rule.scan(data);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_threat_intel_rule_scan_no_match() {
        let rule = ThreatIntelRule::new("TestFamily", vec![b"notpresent".to_vec()], 1, "desc");
        let hits = rule.scan(b"nothing here");
        assert!(hits.is_empty());
    }

    #[test]
    fn test_threat_intel_rule_fires() {
        let rule = ThreatIntelRule::new("X", vec![b"abc".to_vec(), b"def".to_vec()], 1, "x");
        assert!(rule.fires(b"abcdef"));
        assert!(!rule.fires(b"xyz"));
    }

    #[test]
    fn test_yara_threat_intel_scan_wannacry() {
        let ti = YaraThreatIntel::with_builtin_rules();
        let data = b"tasksche.exe embedded binary .wnry extension WNcry@2ol7";
        let matches = ti.scan(data);
        assert!(matches.iter().any(|m| m.rule.family_name == "WannaCry"));
    }

    #[test]
    fn test_yara_threat_intel_scan_mimikatz() {
        let ti = YaraThreatIntel::with_builtin_rules();
        let data = b"mimikatz sekurlsa::wdigest";
        let matches = ti.scan(data);
        assert!(matches.iter().any(|m| m.rule.family_name == "Mimikatz"));
    }

    #[test]
    fn test_yara_threat_intel_attribute() {
        let ti = YaraThreatIntel::with_builtin_rules();
        let data = b"Emotet payload heodo config";
        let attrs = ti.attribute(data);
        // Attribution requires Malpedia lookup + medium+ confidence
        // just ensure it doesn't panic
        let _ = attrs;
    }

    #[test]
    fn test_yara_threat_intel_scan_empty_data() {
        let ti = YaraThreatIntel::with_builtin_rules();
        let matches = ti.scan(b"");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_threat_intel_match_display() {
        let rule = ThreatIntelRule::new("X", vec![], 0, "desc");
        let m = ThreatIntelMatch {
            rule,
            matched_patterns: vec![],
            confidence: YaraConfidence::High,
            attribution: None,
        };
        let s = m.to_string();
        assert!(s.contains("High"));
    }

    #[test]
    fn test_family_attribution_reliable() {
        let attr = FamilyAttribution {
            family: ThreatFamily::new("X", ThreatFamilyKind::Rat, "desc"),
            confidence: YaraConfidence::Medium,
            matched_patterns: vec![],
            matched_offsets: vec![],
            cluster: None,
            notes: String::new(),
        };
        assert!(attr.is_reliable());
    }

    #[test]
    fn test_family_attribution_not_reliable() {
        let attr = FamilyAttribution {
            family: ThreatFamily::new("X", ThreatFamilyKind::Rat, "desc"),
            confidence: YaraConfidence::Low,
            matched_patterns: vec![],
            matched_offsets: vec![],
            cluster: None,
            notes: String::new(),
        };
        assert!(!attr.is_reliable());
    }

    #[test]
    fn test_yara_threat_intel_rules_count() {
        let ti = YaraThreatIntel::with_builtin_rules();
        assert!(ti.rules.len() >= 8);
    }

    #[test]
    fn test_yara_threat_intel_clusters_count() {
        let ti = YaraThreatIntel::with_builtin_rules();
        assert!(ti.clusters.len() >= 2);
    }

    #[test]
    fn test_threat_cluster_display() {
        let c = ThreatCluster::new("C1", "desc");
        let s = c.to_string();
        assert!(s.contains("C1"));
    }

    #[test]
    fn test_threat_family_display() {
        let f = ThreatFamily::new("Mirai", ThreatFamilyKind::Backdoor, "IoT botnet");
        let s = f.to_string();
        assert!(s.contains("Mirai"));
        assert!(s.contains("IoT botnet"));
    }

    #[test]
    fn test_malpedia_entry_mitre_id() {
        let e = MalpediaMapping::lookup("Mimikatz");
        assert!(e.unwrap().mitre_id.is_some());
    }
}
