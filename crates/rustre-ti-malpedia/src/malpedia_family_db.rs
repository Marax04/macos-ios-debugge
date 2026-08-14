//! Malpedia malware family database.
//!
//! Provides a typed, indexed database of Malpedia malware families with
//! alias resolution, platform filtering, and rich family metadata including
//! ATT&CK mapping, actor attribution, and sample correlation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// PlatformTag
// ---------------------------------------------------------------------------

/// Target operating system / platform tag used by Malpedia.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PlatformTag {
    /// Microsoft Windows (any variant).
    Win,
    /// Linux (any distribution).
    Linux,
    /// macOS / OS X.
    Osx,
    /// Google Android.
    Android,
    /// Apple iOS.
    Ios,
    /// Cross-platform / multiplatform.
    Multi,
    /// FreeBSD or other BSD variants.
    Bsd,
    /// Bare-metal / firmware.
    Firmware,
    /// Network device (router firmware, etc.).
    Network,
    /// WebAssembly target.
    Wasm,
    /// Unknown or unclassified platform.
    Unknown,
    /// A platform not covered by the known variants.
    Other(String),
}

impl PlatformTag {
    /// Parse a platform string as used in Malpedia family identifiers.
    ///
    /// Malpedia encodes the platform as the prefix before the first dot in the
    /// family name, e.g. `win.emotet` → `Win`.
    #[must_use]
    pub fn from_malpedia_prefix(prefix: &str) -> Self {
        match prefix.to_lowercase().as_str() {
            "win" | "windows" => Self::Win,
            "linux" | "lin" | "nix" => Self::Linux,
            "osx" | "macos" | "mac" => Self::Osx,
            "android" | "apk" => Self::Android,
            "ios" | "iphone" => Self::Ios,
            "multi" | "cross" => Self::Multi,
            "bsd" | "freebsd" | "openbsd" => Self::Bsd,
            "firmware" | "fw" | "uefi" => Self::Firmware,
            "network" | "router" | "cisco" => Self::Network,
            "wasm" => Self::Wasm,
            "" | "unknown" => Self::Unknown,
            other => Self::Other(other.to_string()),
        }
    }

    /// Return the canonical lowercase Malpedia prefix string.
    #[must_use]
    pub const fn to_prefix(&self) -> &str {
        match self {
            Self::Win => "win",
            Self::Linux => "linux",
            Self::Osx => "osx",
            Self::Android => "android",
            Self::Ios => "ios",
            Self::Multi => "multi",
            Self::Bsd => "bsd",
            Self::Firmware => "firmware",
            Self::Network => "network",
            Self::Wasm => "wasm",
            Self::Unknown => "unknown",
            Self::Other(s) => s.as_str(),
        }
    }

    /// Return `true` if this is a desktop/server OS platform.
    #[must_use]
    pub const fn is_desktop_server(&self) -> bool {
        matches!(self, Self::Win | Self::Linux | Self::Osx | Self::Bsd)
    }

    /// Return `true` if this is a mobile platform.
    #[must_use]
    pub const fn is_mobile(&self) -> bool {
        matches!(self, Self::Android | Self::Ios)
    }

    /// Return `true` if this is an embedded / firmware platform.
    #[must_use]
    pub const fn is_embedded(&self) -> bool {
        matches!(self, Self::Firmware | Self::Network)
    }
}

impl std::fmt::Display for PlatformTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_prefix())
    }
}

// ---------------------------------------------------------------------------
// FamilyAlias
// ---------------------------------------------------------------------------

/// An alternative name for a malware family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyAlias {
    /// The alias string (not normalised).
    pub name: String,
    /// Optional source attribution for this alias (e.g. vendor name).
    pub source: Option<String>,
    /// Whether this alias is also commonly used in the media.
    pub is_media_name: bool,
}

impl FamilyAlias {
    /// Create a simple alias with no attribution.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            source: None,
            is_media_name: false,
        }
    }

    /// Create an alias attributed to a specific vendor / source.
    #[must_use]
    pub fn with_source(name: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            source: Some(source.into()),
            is_media_name: false,
        }
    }

    /// Mark this alias as a commonly used media/press name.
    #[must_use]
    pub const fn as_media_name(mut self) -> Self {
        self.is_media_name = true;
        self
    }

    /// Return the lowercase normalised form.
    #[must_use]
    pub fn normalised(&self) -> String {
        self.name.to_lowercase().replace([' ', '-'], "_")
    }
}

// ---------------------------------------------------------------------------
// MalpediaFamily
// ---------------------------------------------------------------------------

/// A complete Malpedia malware family record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalpediaFamily {
    /// Canonical Malpedia identifier (e.g. `win.emotet`).
    pub id: String,
    /// Human-readable common name.
    pub common_name: String,
    /// Target platform.
    pub platform: PlatformTag,
    /// Malware type classification string (e.g. "trojan", "ransomware").
    pub malware_type: String,
    /// Known alternative names.
    pub aliases: Vec<FamilyAlias>,
    /// Related family IDs (e.g. variants, loaders).
    pub related_families: Vec<String>,
    /// Attribution to threat actor groups.
    pub attributed_actors: Vec<String>,
    /// MITRE ATT&CK technique identifiers.
    pub attack_techniques: Vec<String>,
    /// SHA-256 hashes of known samples.
    pub sample_hashes: Vec<String>,
    /// Number of YARA rules available (0 if none).
    pub yara_rule_count: u32,
    /// Optional description.
    pub description: Option<String>,
    /// Optional country of origin (ISO-3166-1 alpha-2).
    pub country_of_origin: Option<String>,
    /// Reference URLs.
    pub references: Vec<String>,
    /// Malpedia URL for this family.
    pub malpedia_url: Option<String>,
    /// When this record was last updated (Unix timestamp).
    pub last_updated: u64,
    /// Whether this family is considered active / under development.
    pub is_active: bool,
}

impl MalpediaFamily {
    /// Create a minimal family record.
    #[must_use]
    pub fn new(id: impl Into<String>, common_name: impl Into<String>, platform: PlatformTag) -> Self {
        let id = id.into();
        let common_name = common_name.into();
        let malpedia_url = Some(format!(
            "https://malpedia.caad.fkie.fraunhofer.de/details/{id}"
        ));
        Self {
            id,
            common_name,
            platform,
            malware_type: "unknown".to_string(),
            aliases: Vec::new(),
            related_families: Vec::new(),
            attributed_actors: Vec::new(),
            attack_techniques: Vec::new(),
            sample_hashes: Vec::new(),
            yara_rule_count: 0,
            description: None,
            country_of_origin: None,
            references: Vec::new(),
            malpedia_url,
            last_updated: 0,
            is_active: true,
        }
    }

    /// Parse the platform prefix from the family id.
    ///
    /// For `win.emotet` this returns `"win"`.
    #[must_use]
    pub fn platform_prefix(&self) -> &str {
        self.id.find('.').map_or_else(|| self.platform.to_prefix(), |dot| &self.id[..dot])
    }

    /// Return the family name without the platform prefix.
    ///
    /// For `win.emotet` this returns `"emotet"`.
    #[must_use]
    pub fn short_name(&self) -> &str {
        if let Some(dot) = self.id.find('.') {
            &self.id[dot + 1..]
        } else {
            &self.id
        }
    }

    /// Return `true` if this family has YARA rules available.
    #[must_use]
    pub const fn has_yara_rules(&self) -> bool {
        self.yara_rule_count > 0
    }

    /// Return `true` if any alias matches `name` (case-insensitive).
    #[must_use]
    pub fn has_alias(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        self.aliases
            .iter()
            .any(|a| a.name.to_lowercase() == lower || a.normalised() == lower)
    }

    /// Return `true` if the family targets Windows.
    #[must_use]
    pub fn is_windows(&self) -> bool {
        self.platform == PlatformTag::Win
    }

    /// Return all aliases as a flat list of strings.
    #[must_use]
    pub fn alias_names(&self) -> Vec<&str> {
        self.aliases.iter().map(|a| a.name.as_str()).collect()
    }

    /// Compute a simple threat score [0..100] based on type and technique count.
    #[must_use]
    pub fn threat_score(&self) -> u8 {
        let base: u8 = match self.malware_type.to_lowercase().as_str() {
            "ransomware" => 90,
            "worm" | "virus" => 80,
            "rootkit" | "bootkit" => 85,
            "trojan" | "backdoor" => 70,
            "stealer" | "infostealer" | "botnet" | "bot" => 65,
            "dropper" | "loader" | "downloader" | "banker" | "banking" => 60,
            "spyware" => 55,
            "cryptominer" => 40,
            "tool" => 30,
            "adware" | "pua" | "pup" => 20,
            _ => 50,
        };
        // Boost by technique count (each technique adds ~0.5, capped at 10).
        let boost = u8::try_from(self.attack_techniques.len().min(20) / 2).unwrap_or(10);
        base.saturating_add(boost).min(100)
    }
}

// ---------------------------------------------------------------------------
// MalpediaFamilyDb
// ---------------------------------------------------------------------------

/// An indexed, queryable database of Malpedia malware families.
///
/// Supports lookup by canonical ID, alias, platform, malware type, actor
/// attribution, and ATT&CK technique.
pub struct MalpediaFamilyDb {
    /// Primary index: family id → family record.
    families: HashMap<String, MalpediaFamily>,
    /// Secondary alias index: lowercase alias → family id.
    alias_index: HashMap<String, String>,
}

impl MalpediaFamilyDb {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self {
            families: HashMap::new(),
            alias_index: HashMap::new(),
        }
    }

    /// Create a database pre-populated with representative mock data.
    #[must_use]
    pub fn with_mock_data() -> Self {
        let mut db = Self::new();
        db.populate_mock();
        db
    }

    /// Insert a family record, building alias indices.
    pub fn insert(&mut self, family: MalpediaFamily) {
        // Index all aliases.
        for alias in &family.aliases {
            self.alias_index
                .insert(alias.normalised(), family.id.clone());
            self.alias_index
                .insert(alias.name.to_lowercase(), family.id.clone());
        }
        // The id itself is also a lookup key.
        self.alias_index
            .insert(family.id.to_lowercase(), family.id.clone());
        // Common name.
        self.alias_index
            .insert(family.common_name.to_lowercase(), family.id.clone());
        self.families.insert(family.id.clone(), family);
    }

    /// Look up a family by its canonical Malpedia id.
    ///
    /// Returns `None` if the id is not known.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&MalpediaFamily> {
        self.families.get(id)
    }

    /// Look up a family by any name (canonical id, common name, or alias).
    #[must_use]
    pub fn resolve(&self, name: &str) -> Option<&MalpediaFamily> {
        let lower = name.to_lowercase();
        let id = self.alias_index.get(&lower)?;
        self.families.get(id)
    }

    /// Return all families.
    #[must_use]
    pub fn all(&self) -> Vec<&MalpediaFamily> {
        self.families.values().collect()
    }

    /// Total number of families in the database.
    #[must_use]
    pub fn len(&self) -> usize {
        self.families.len()
    }

    /// Return `true` if the database contains no families.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.families.is_empty()
    }

    /// Search families by partial name match (case-insensitive).
    ///
    /// Matches against id, common name, and aliases.
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&MalpediaFamily> {
        let q = query.to_lowercase();
        self.families
            .values()
            .filter(|f| {
                f.id.to_lowercase().contains(&q)
                    || f.common_name.to_lowercase().contains(&q)
                    || f.aliases.iter().any(|a| a.name.to_lowercase().contains(&q))
            })
            .collect()
    }

    /// Filter families by platform tag.
    #[must_use]
    pub fn by_platform(&self, platform: &PlatformTag) -> Vec<&MalpediaFamily> {
        self.families
            .values()
            .filter(|f| &f.platform == platform)
            .collect()
    }

    /// Filter families by malware type (case-insensitive prefix match).
    #[must_use]
    pub fn by_type(&self, malware_type: &str) -> Vec<&MalpediaFamily> {
        let t = malware_type.to_lowercase();
        self.families
            .values()
            .filter(|f| f.malware_type.to_lowercase().starts_with(&t))
            .collect()
    }

    /// Filter families attributed to a specific actor.
    #[must_use]
    pub fn by_actor(&self, actor: &str) -> Vec<&MalpediaFamily> {
        let a = actor.to_lowercase();
        self.families
            .values()
            .filter(|f| {
                f.attributed_actors
                    .iter()
                    .any(|ac| ac.to_lowercase() == a)
            })
            .collect()
    }

    /// Filter families that use a specific ATT&CK technique id.
    #[must_use]
    pub fn by_technique(&self, technique_id: &str) -> Vec<&MalpediaFamily> {
        let t = technique_id.to_uppercase();
        self.families
            .values()
            .filter(|f| f.attack_techniques.iter().any(|ti| ti.to_uppercase() == t))
            .collect()
    }

    /// Filter families that have YARA rules available.
    #[must_use]
    pub fn with_yara_rules(&self) -> Vec<&MalpediaFamily> {
        self.families
            .values()
            .filter(|f| f.has_yara_rules())
            .collect()
    }

    /// Return families targeting a specific country of origin.
    #[must_use]
    pub fn by_origin_country(&self, iso2: &str) -> Vec<&MalpediaFamily> {
        let c = iso2.to_uppercase();
        self.families
            .values()
            .filter(|f| {
                f.country_of_origin
                    .as_deref()
                    .is_some_and(|co| co.to_uppercase() == c)
            })
            .collect()
    }

    /// Return platform breakdown as a `HashMap<platform_prefix, count>`.
    #[must_use]
    pub fn platform_breakdown(&self) -> HashMap<String, usize> {
        let mut map: HashMap<String, usize> = HashMap::new();
        for f in self.families.values() {
            *map.entry(f.platform.to_prefix().to_string()).or_insert(0) += 1;
        }
        map
    }

    /// Return malware-type breakdown as a `HashMap<type, count>`.
    #[must_use]
    pub fn type_breakdown(&self) -> HashMap<String, usize> {
        let mut map: HashMap<String, usize> = HashMap::new();
        for f in self.families.values() {
            *map.entry(f.malware_type.clone()).or_insert(0) += 1;
        }
        map
    }

    /// Top-N families by threat score (descending).
    #[must_use]
    pub fn top_by_threat_score(&self, n: usize) -> Vec<&MalpediaFamily> {
        let mut families: Vec<&MalpediaFamily> = self.families.values().collect();
        families.sort_by_key(|b| std::cmp::Reverse(b.threat_score()));
        families.truncate(n);
        families
    }

    /// Populate database with well-known malware families for testing.
    fn populate_mock(&mut self) {
        // Emotet
        let mut emotet = MalpediaFamily::new("win.emotet", "Emotet", PlatformTag::Win);
        emotet.malware_type = "trojan".to_string();
        emotet.aliases = vec![
            FamilyAlias::with_source("Heodo", "ESET").as_media_name(),
            FamilyAlias::with_source("Geodo", "G Data"),
            FamilyAlias::new("TA542"),
        ];
        emotet.attributed_actors = vec!["TA542".to_string()];
        emotet.attack_techniques = vec!["T1071".to_string(), "T1055".to_string(), "T1082".to_string()];
        emotet.yara_rule_count = 8;
        emotet.description = Some("Polymorphic banking trojan turned loader/botnet dropper.".to_string());
        emotet.sample_hashes = vec![
            "e3b0c44298fc1c149afbf4c8996fb924".to_string(),
        ];
        self.insert(emotet);

        // WannaCry
        let mut wc = MalpediaFamily::new("win.wannacry", "WannaCry", PlatformTag::Win);
        wc.malware_type = "ransomware".to_string();
        wc.aliases = vec![
            FamilyAlias::new("WanaCrypt0r").as_media_name(),
            FamilyAlias::new("WCry"),
            FamilyAlias::new("WannaCrypt"),
        ];
        wc.attributed_actors = vec!["Lazarus".to_string()];
        wc.country_of_origin = Some("KP".to_string());
        wc.attack_techniques = vec!["T1486".to_string(), "T1210".to_string()];
        wc.yara_rule_count = 12;
        wc.description = Some("Ransomware worm that exploits EternalBlue (CVE-2017-0144).".to_string());
        self.insert(wc);

        // Mimikatz
        let mut mimi = MalpediaFamily::new("win.mimikatz", "Mimikatz", PlatformTag::Win);
        mimi.malware_type = "tool".to_string();
        mimi.aliases = vec![FamilyAlias::new("gentilkiwi")];
        mimi.attack_techniques = vec!["T1003".to_string(), "T1550".to_string()];
        mimi.yara_rule_count = 5;
        mimi.description = Some("Credential dumping tool that extracts cleartext passwords from LSASS memory.".to_string());
        self.insert(mimi);

        // Mirai
        let mut mirai = MalpediaFamily::new("linux.mirai", "Mirai", PlatformTag::Linux);
        mirai.malware_type = "botnet".to_string();
        mirai.aliases = vec![FamilyAlias::new("Aidra"), FamilyAlias::new("LizardStresser")];
        mirai.attack_techniques = vec!["T1498".to_string(), "T1059".to_string()];
        mirai.yara_rule_count = 3;
        mirai.description = Some("IoT botnet used for large-scale DDoS attacks.".to_string());
        self.insert(mirai);

        // Pegasus
        let mut pegasus = MalpediaFamily::new("android.pegasus", "Pegasus", PlatformTag::Android);
        pegasus.malware_type = "spyware".to_string();
        pegasus.aliases = vec![FamilyAlias::with_source("FORCEDENTRY", "Citizen Lab")];
        pegasus.attributed_actors = vec!["NSO Group".to_string()];
        pegasus.attack_techniques = vec!["T1430".to_string(), "T1512".to_string(), "T1636".to_string()];
        pegasus.yara_rule_count = 2;
        pegasus.description = Some("Commercial spyware targeting mobile devices via zero-click exploits.".to_string());
        self.insert(pegasus);

        // CobaltStrike Beacon
        let mut cs = MalpediaFamily::new("win.cobalt_strike", "CobaltStrike", PlatformTag::Win);
        cs.malware_type = "tool".to_string();
        cs.aliases = vec![
            FamilyAlias::new("CS Beacon").as_media_name(),
            FamilyAlias::new("Beacon"),
        ];
        cs.attack_techniques = vec!["T1059".to_string(), "T1055".to_string(), "T1071".to_string()];
        cs.yara_rule_count = 20;
        cs.description = Some("Commercial post-exploitation framework widely used in red-team and APT operations.".to_string());
        self.insert(cs);
    }
}

impl Default for MalpediaFamilyDb {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FamilyDbStats
// ---------------------------------------------------------------------------

/// Aggregate statistics derived from a `MalpediaFamilyDb`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyDbStats {
    /// Total family count.
    pub total_families: usize,
    /// Number of families with YARA rules.
    pub families_with_yara: usize,
    /// Number of active families.
    pub active_families: usize,
    /// Platform breakdown.
    pub platform_breakdown: HashMap<String, usize>,
    /// Malware type breakdown.
    pub type_breakdown: HashMap<String, usize>,
}

impl FamilyDbStats {
    /// Compute stats from a database reference.
    #[must_use]
    pub fn from_db(db: &MalpediaFamilyDb) -> Self {
        let total_families = db.len();
        let families_with_yara = db.with_yara_rules().len();
        let active_families = db
            .families
            .values()
            .filter(|f| f.is_active)
            .count();
        Self {
            total_families,
            families_with_yara,
            active_families,
            platform_breakdown: db.platform_breakdown(),
            type_breakdown: db.type_breakdown(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> MalpediaFamilyDb {
        MalpediaFamilyDb::with_mock_data()
    }

    #[test]
    fn test_db_not_empty() {
        assert!(!db().is_empty());
    }

    #[test]
    fn test_db_len() {
        assert!(db().len() >= 6);
    }

    #[test]
    fn test_get_by_id() {
        let d = db();
        let f = d.get("win.emotet");
        assert!(f.is_some());
        assert_eq!(f.unwrap().common_name, "Emotet");
    }

    #[test]
    fn test_resolve_by_common_name() {
        let d = db();
        let f = d.resolve("Emotet");
        assert!(f.is_some());
    }

    #[test]
    fn test_resolve_by_alias() {
        let d = db();
        let f = d.resolve("heodo");
        assert!(f.is_some());
        assert_eq!(f.unwrap().id, "win.emotet");
    }

    #[test]
    fn test_resolve_case_insensitive() {
        let d = db();
        let f = d.resolve("WANNACRY");
        assert!(f.is_some());
    }

    #[test]
    fn test_search() {
        let d = db();
        let results = d.search("mirai");
        assert!(!results.is_empty());
        assert!(results.iter().any(|f| f.id == "linux.mirai"));
    }

    #[test]
    fn test_by_platform_win() {
        let d = db();
        let wins = d.by_platform(&PlatformTag::Win);
        assert!(wins.len() >= 3);
    }

    #[test]
    fn test_by_platform_linux() {
        let d = db();
        let linuxes = d.by_platform(&PlatformTag::Linux);
        assert!(!linuxes.is_empty());
    }

    #[test]
    fn test_by_type_ransomware() {
        let d = db();
        let r = d.by_type("ransomware");
        assert!(!r.is_empty());
    }

    #[test]
    fn test_by_actor() {
        let d = db();
        let r = d.by_actor("lazarus");
        assert!(!r.is_empty());
        assert!(r.iter().any(|f| f.id == "win.wannacry"));
    }

    #[test]
    fn test_by_technique() {
        let d = db();
        let r = d.by_technique("T1486");
        assert!(!r.is_empty());
    }

    #[test]
    fn test_with_yara_rules() {
        let d = db();
        let r = d.with_yara_rules();
        assert!(!r.is_empty());
    }

    #[test]
    fn test_by_origin_country() {
        let d = db();
        let r = d.by_origin_country("KP");
        assert!(!r.is_empty());
    }

    #[test]
    fn test_platform_breakdown() {
        let d = db();
        let bd = d.platform_breakdown();
        assert!(bd.contains_key("win"));
    }

    #[test]
    fn test_top_by_threat_score() {
        let d = db();
        let top = d.top_by_threat_score(3);
        assert_eq!(top.len(), 3);
        // Ransomware should be near the top.
        assert!(top[0].threat_score() >= 80);
    }

    #[test]
    fn test_family_short_name() {
        let d = db();
        let f = d.get("win.emotet").unwrap();
        assert_eq!(f.short_name(), "emotet");
        assert_eq!(f.platform_prefix(), "win");
    }

    #[test]
    fn test_family_has_alias() {
        let d = db();
        let f = d.get("win.emotet").unwrap();
        assert!(f.has_alias("Heodo"));
        assert!(!f.has_alias("Lazarus"));
    }

    #[test]
    fn test_platform_tag_parse() {
        assert_eq!(PlatformTag::from_malpedia_prefix("win"), PlatformTag::Win);
        assert_eq!(PlatformTag::from_malpedia_prefix("linux"), PlatformTag::Linux);
        assert_eq!(PlatformTag::from_malpedia_prefix("osx"), PlatformTag::Osx);
    }

    #[test]
    fn test_platform_tag_is_desktop() {
        assert!(PlatformTag::Win.is_desktop_server());
        assert!(!PlatformTag::Android.is_desktop_server());
    }

    #[test]
    fn test_platform_tag_is_mobile() {
        assert!(PlatformTag::Android.is_mobile());
        assert!(PlatformTag::Ios.is_mobile());
        assert!(!PlatformTag::Linux.is_mobile());
    }

    #[test]
    fn test_family_alias_normalised() {
        let a = FamilyAlias::new("Cobalt Strike");
        assert_eq!(a.normalised(), "cobalt_strike");
    }

    #[test]
    fn test_family_db_stats() {
        let d = db();
        let stats = FamilyDbStats::from_db(&d);
        assert!(stats.total_families > 0);
        assert!(stats.families_with_yara > 0);
        assert!(!stats.platform_breakdown.is_empty());
    }

    #[test]
    fn test_threat_score_ransomware() {
        let d = db();
        let f = d.get("win.wannacry").unwrap();
        assert!(f.threat_score() >= 85);
    }

    #[test]
    fn test_threat_score_tool() {
        let d = db();
        let f = d.get("win.mimikatz").unwrap();
        // Tools score lower than ransomware.
        assert!(f.threat_score() < d.get("win.wannacry").unwrap().threat_score());
    }

    #[test]
    fn test_is_windows() {
        let d = db();
        assert!(d.get("win.emotet").unwrap().is_windows());
        assert!(!d.get("linux.mirai").unwrap().is_windows());
    }

    #[test]
    fn test_alias_media_name() {
        let a = FamilyAlias::new("WannaCry").as_media_name();
        assert!(a.is_media_name);
    }

    #[test]
    fn test_alias_with_source() {
        let a = FamilyAlias::with_source("Heodo", "ESET");
        assert_eq!(a.source.as_deref(), Some("ESET"));
    }

    #[test]
    fn test_family_alias_names() {
        let d = db();
        let f = d.get("win.emotet").unwrap();
        let names = f.alias_names();
        assert!(!names.is_empty());
        assert!(names.contains(&"Heodo"));
    }
}
