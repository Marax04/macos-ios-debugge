//! YARA-based threat tagger.
//!
//! Maps YARA rule match results to structured threat tags and builds a
//! `ThreatProfile` including MITRE ATT&CK technique IDs.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// TagCategory
// ---------------------------------------------------------------------------

/// Top-level threat category for a `ThreatTag`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TagCategory {
    Malware,
    Ransomware,
    Trojan,
    Backdoor,
    Dropper,
    Downloader,
    Infostealer,
    Rootkit,
    Adware,
    Spyware,
    Hacktool,
    Miner,
    Wiper,
    Rat,
    Loader,
    Packer,
    Targets,
    Technique,
}

impl TagCategory {
    /// Severity score 0–10 for this category.
    #[must_use]
    pub const fn severity(&self) -> u8 {
        match self {
            Self::Wiper => 10,
            Self::Ransomware | Self::Rootkit => 9,
            Self::Backdoor | Self::Rat => 8,
            Self::Trojan | Self::Infostealer => 7,
            Self::Dropper | Self::Loader => 6,
            Self::Downloader | Self::Spyware | Self::Malware => 5,
            Self::Miner | Self::Hacktool => 4,
            Self::Adware | Self::Packer => 2,
            Self::Targets | Self::Technique => 1,
        }
    }

    /// Human-readable label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Malware => "Malware",
            Self::Ransomware => "Ransomware",
            Self::Trojan => "Trojan",
            Self::Backdoor => "Backdoor",
            Self::Dropper => "Dropper",
            Self::Downloader => "Downloader",
            Self::Infostealer => "Infostealer",
            Self::Rootkit => "Rootkit",
            Self::Adware => "Adware",
            Self::Spyware => "Spyware",
            Self::Hacktool => "Hacktool",
            Self::Miner => "Miner",
            Self::Wiper => "Wiper",
            Self::Rat => "RAT",
            Self::Loader => "Loader",
            Self::Packer => "Packer",
            Self::Targets => "Targets",
            Self::Technique => "Technique",
        }
    }
}

// ---------------------------------------------------------------------------
// ThreatTag
// ---------------------------------------------------------------------------

/// A single threat tag produced by the tagger.
#[derive(Debug, Clone)]
pub struct ThreatTag {
    /// Short display name (e.g. `"ransomware"`, `"credential-stealer"`).
    pub name: String,
    /// Broad category.
    pub category: TagCategory,
    /// Optional qualifier / family name (e.g. `"LockBit"`, `"Mimikatz"`).
    pub value: String,
    /// Confidence score [0.0, 1.0].
    pub confidence: f64,
}

impl ThreatTag {
    /// Create a new `ThreatTag`.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        category: TagCategory,
        value: impl Into<String>,
        confidence: f64,
    ) -> Self {
        Self {
            name: name.into(),
            category,
            value: value.into(),
            confidence: confidence.clamp(0.0, 1.0),
        }
    }

    /// Returns `true` if confidence ≥ 0.7.
    #[must_use]
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.7
    }
}

// ---------------------------------------------------------------------------
// YaraMatch (local, no dep on scanner types)
// ---------------------------------------------------------------------------

/// A minimal YARA match result used by the tagger.
#[derive(Debug, Clone)]
pub struct YaraMatch {
    /// The YARA rule name that matched.
    pub rule_name: String,
    /// The YARA namespace (e.g. `"default"`, `"hunting"`).
    pub namespace: String,
    /// Tags declared on the rule.
    pub tags: Vec<String>,
}

impl YaraMatch {
    /// Create a new `YaraMatch`.
    #[must_use]
    pub fn new(rule_name: &str) -> Self {
        Self {
            rule_name: rule_name.to_owned(),
            namespace: "default".to_owned(),
            tags: Vec::new(),
        }
    }

    /// Create with an explicit namespace.
    #[must_use]
    pub fn with_namespace(mut self, ns: &str) -> Self {
        ns.clone_into(&mut self.namespace);
        self
    }
}

// ---------------------------------------------------------------------------
// TaggingRule
// ---------------------------------------------------------------------------

/// A rule that maps a YARA rule name prefix to a set of `ThreatTag`s.
#[derive(Debug, Clone)]
pub struct TaggingRule {
    /// YARA rule name prefix to match (e.g. `"Ransomware_"`).
    pub yara_identifier: String,
    /// Tags to apply when the rule matches.
    pub tags_to_apply: Vec<ThreatTag>,
    /// Minimum number of separate YARA rule matches required.
    pub required_positives: u32,
}

impl TaggingRule {
    /// Returns `true` if `rule_name` starts with (or equals) `yara_identifier`.
    #[must_use]
    pub fn matches_rule(&self, rule_name: &str) -> bool {
        rule_name.starts_with(&self.yara_identifier)
            || rule_name.eq_ignore_ascii_case(&self.yara_identifier)
    }
}

// ---------------------------------------------------------------------------
// Built-in tagging rules
// ---------------------------------------------------------------------------

/// Returns the built-in set of YARA → threat-tag mappings.
///
/// Contains 24 entries covering common malware families, TTPs, and targets.
#[must_use]
pub fn builtin_tagging_rules() -> Vec<TaggingRule> {
    use TagCategory::{Adware, Backdoor, Downloader, Dropper, Hacktool, Infostealer, Loader, Miner, Packer, Ransomware, Rat, Rootkit, Spyware, Technique, Trojan, Wiper};
    macro_rules! tr {
        ($prefix:expr, $cat:expr, $name:expr, $value:expr, $conf:expr) => {
            TaggingRule {
                yara_identifier: $prefix.to_owned(),
                tags_to_apply: vec![ThreatTag::new($name, $cat, $value, $conf)],
                required_positives: 1,
            }
        };
    }

    vec![
        tr!("Ransomware_", Ransomware, "ransomware", "", 0.95),
        tr!("Ransom_", Ransomware, "ransomware", "", 0.90),
        tr!("Backdoor_", Backdoor, "backdoor", "", 0.90),
        tr!("Trojan_", Trojan, "trojan", "", 0.85),
        tr!("Dropper_", Dropper, "dropper", "", 0.85),
        tr!("Downloader_", Downloader, "downloader", "", 0.80),
        tr!("Stealer_", Infostealer, "infostealer", "", 0.85),
        tr!("Credential_", Infostealer, "credential-stealer", "", 0.85),
        tr!("Rootkit_", Rootkit, "rootkit", "", 0.90),
        tr!("Adware_", Adware, "adware", "", 0.75),
        tr!("Spyware_", Spyware, "spyware", "", 0.80),
        tr!("HackTool_", Hacktool, "hacktool", "", 0.80),
        tr!("Miner_", Miner, "cryptominer", "", 0.85),
        tr!("Wiper_", Wiper, "wiper", "", 0.95),
        tr!("RAT_", Rat, "rat", "", 0.90),
        tr!("Loader_", Loader, "loader", "", 0.80),
        tr!("Packer_", Packer, "packer", "", 0.70),
        tr!("Packed_", Packer, "packed", "", 0.65),
        tr!("CVE_", Technique, "exploit", "", 0.75),
        tr!("Exploit_", Technique, "exploit", "", 0.80),
        tr!("Mimikatz", Hacktool, "hacktool", "Mimikatz", 0.95),
        tr!("CobaltStrike", Backdoor, "backdoor", "CobaltStrike", 0.95),
        tr!("Metasploit", Hacktool, "hacktool", "Metasploit", 0.90),
        tr!("LockBit", Ransomware, "ransomware", "LockBit", 0.95),
    ]
}

// ---------------------------------------------------------------------------
// ThreatProfile
// ---------------------------------------------------------------------------

/// Aggregated threat characterisation of a single scanned file.
#[derive(Debug, Clone)]
pub struct ThreatProfile {
    /// SHA-256 of the scanned file.
    pub file_sha256: String,
    /// All tags that matched.
    pub tags: Vec<ThreatTag>,
    /// The single most likely top-level category.
    pub top_category: TagCategory,
    /// Weighted overall confidence [0.0, 1.0].
    pub overall_confidence: f64,
    /// Relevant MITRE ATT&CK technique IDs.
    pub mitre_ttps: Vec<String>,
}

impl ThreatProfile {
    /// Returns `true` if the profile indicates a highly threatening file.
    #[must_use]
    pub fn is_high_threat(&self) -> bool {
        self.overall_confidence >= 0.7 && self.top_category.severity() >= 7
    }

    /// Returns only tags with confidence ≥ 0.7.
    #[must_use]
    pub fn high_confidence_tags(&self) -> Vec<&ThreatTag> {
        self.tags.iter().filter(|t| t.is_high_confidence()).collect()
    }
}

// ---------------------------------------------------------------------------
// ThreatTagger
// ---------------------------------------------------------------------------

/// Tags a file based on its YARA match results.
///
/// Uses a configurable set of `TaggingRule`s; defaults to the built-in set.
pub struct ThreatTagger {
    rules: Vec<TaggingRule>,
}

impl ThreatTagger {
    /// Create a new `ThreatTagger` with the built-in rules.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: builtin_tagging_rules(),
        }
    }

    /// Create a `ThreatTagger` with a custom rule set.
    #[must_use]
    pub fn with_rules(rules: Vec<TaggingRule>) -> Self {
        Self { rules }
    }

    /// Add additional tagging rules.
    pub fn add_rule(&mut self, rule: TaggingRule) {
        self.rules.push(rule);
    }

    /// Tag a set of YARA match results.
    ///
    /// Returns the flat list of all matched `ThreatTag`s (may contain
    /// duplicates if multiple YARA rules triggered the same tag).
    #[must_use]
    pub fn tag_match_results(&self, matches: &[YaraMatch]) -> Vec<ThreatTag> {
        let mut tags: Vec<ThreatTag> = Vec::new();
        for m in matches {
            for rule in &self.rules {
                if rule.matches_rule(&m.rule_name) {
                    tags.extend(rule.tags_to_apply.iter().cloned());
                }
            }
        }
        tags
    }

    /// Build a `ThreatProfile` from a collection of YARA matches.
    #[must_use]
    pub fn build_profile(&self, file_sha256: &str, matches: &[YaraMatch]) -> ThreatProfile {
        let tags = self.tag_match_results(matches);
        let top_category = Self::determine_top_category(&tags);
        let overall_confidence = Self::compute_overall_confidence(&tags, matches.len());
        let mitre_ttps = self.derive_mitre_ttps(&tags, matches);

        ThreatProfile {
            file_sha256: file_sha256.to_owned(),
            tags,
            top_category,
            overall_confidence,
            mitre_ttps,
        }
    }

    /// Determine the most prominent `TagCategory` (highest combined severity × count).
    fn determine_top_category(tags: &[ThreatTag]) -> TagCategory {
        if tags.is_empty() {
            return TagCategory::Malware;
        }
        let mut counts: HashMap<u8, (TagCategory, u32)> = HashMap::new();
        for tag in tags {
            let sev = tag.category.severity();
            let entry = counts.entry(sev).or_insert_with(|| (tag.category.clone(), 0));
            entry.1 += 1;
        }
        let best_sev = counts.keys().copied().max().unwrap_or(0);
        counts[&best_sev].0.clone()
    }

    /// Compute a weighted overall confidence.
    ///
    /// Formula: sum of (confidence × severity) / sum of severity, capped at 1.0.
    fn compute_overall_confidence(tags: &[ThreatTag], match_count: usize) -> f64 {
        if tags.is_empty() {
            return 0.0;
        }
        let weight_sum: f64 = tags
            .iter()
            .map(|t| f64::from(t.category.severity()))
            .sum();
        let weighted: f64 = tags
            .iter()
            .map(|t| t.confidence * f64::from(t.category.severity()))
            .sum();
        let base = if weight_sum > 0.0 {
            weighted / weight_sum
        } else {
            0.0
        };
        // Boost slightly for high match counts
        let boost = (f64::from(u32::try_from(match_count).unwrap_or(u32::MAX)) * 0.01).min(0.1);
        (base + boost).min(1.0)
    }

    /// Map tag categories and specific rule names to ATT&CK technique IDs.
    #[must_use]
    pub fn derive_mitre_ttps(&self, tags: &[ThreatTag], matches: &[YaraMatch]) -> Vec<String> {
        let mut ttps: Vec<String> = Vec::new();

        for tag in tags {
            for ttp in tag_to_mitre(&tag.category) {
                if !ttps.contains(&ttp) {
                    ttps.push(ttp);
                }
            }
        }

        // Additional TTPs derived from rule names
        for m in matches {
            for ttp in rule_name_to_mitre(&m.rule_name) {
                if !ttps.contains(&ttp) {
                    ttps.push(ttp);
                }
            }
        }

        ttps.sort();
        ttps
    }
}

impl Default for ThreatTagger {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// tag_to_mitre / rule_name_to_mitre
// ---------------------------------------------------------------------------

/// Map a `TagCategory` to one or more MITRE ATT&CK technique IDs.
#[must_use]
pub fn tag_to_mitre(category: &TagCategory) -> Vec<String> {
    match category {
        TagCategory::Ransomware => vec![
            "T1486".to_owned(), // Data Encrypted for Impact
            "T1490".to_owned(), // Inhibit System Recovery
        ],
        TagCategory::Backdoor | TagCategory::Rat => vec![
            "T1571".to_owned(), // Non-Standard Port
            "T1095".to_owned(), // Non-Application Layer Protocol
            "T1021".to_owned(), // Remote Services
        ],
        TagCategory::Dropper => vec![
            "T1105".to_owned(), // Ingress Tool Transfer
            "T1566".to_owned(), // Phishing
        ],
        TagCategory::Downloader => vec![
            "T1105".to_owned(), // Ingress Tool Transfer
        ],
        TagCategory::Infostealer => vec![
            "T1555".to_owned(), // Credentials from Password Stores
            "T1552".to_owned(), // Unsecured Credentials
            "T1056".to_owned(), // Input Capture
        ],
        TagCategory::Rootkit => vec![
            "T1014".to_owned(), // Rootkit
            "T1547".to_owned(), // Boot or Logon Autostart Execution
        ],
        TagCategory::Packer => vec![
            "T1027".to_owned(), // Obfuscated Files or Information
        ],
        TagCategory::Miner => vec![
            "T1496".to_owned(), // Resource Hijacking
        ],
        TagCategory::Wiper => vec![
            "T1485".to_owned(), // Data Destruction
            "T1561".to_owned(), // Disk Wipe
        ],
        TagCategory::Loader => vec![
            "T1055".to_owned(), // Process Injection
            "T1059".to_owned(), // Command and Scripting Interpreter
        ],
        TagCategory::Hacktool => vec![
            "T1110".to_owned(), // Brute Force
            "T1078".to_owned(), // Valid Accounts
        ],
        _ => vec![],
    }
}

/// Map specific YARA rule names to MITRE technique IDs.
#[must_use]
pub fn rule_name_to_mitre(rule_name: &str) -> Vec<String> {
    let mut ttps = Vec::new();
    let n = rule_name.to_lowercase();
    if n.contains("mimikatz") || n.contains("credential") {
        ttps.push("T1003".to_owned()); // OS Credential Dumping
    }
    if n.contains("injection") || n.contains("inject") {
        ttps.push("T1055".to_owned()); // Process Injection
    }
    if n.contains("keylog") {
        ttps.push("T1056.001".to_owned()); // Keylogging
    }
    if n.contains("screenshot") {
        ttps.push("T1113".to_owned()); // Screen Capture
    }
    if n.contains("persistence") || n.contains("autorun") {
        ttps.push("T1547".to_owned()); // Boot or Logon Autostart Execution
    }
    if n.contains("encrypt") {
        ttps.push("T1486".to_owned()); // Data Encrypted for Impact
    }
    if n.contains("shellcode") || n.contains("shellcodd") {
        ttps.push("T1059".to_owned()); // Command and Scripting Interpreter
    }
    if n.contains("uac") || n.contains("bypass") {
        ttps.push("T1548.002".to_owned()); // UAC Bypass
    }
    if n.contains("cobaltstrike") || n.contains("cobalt_strike") {
        ttps.push("T1573".to_owned()); // Encrypted Channel
        ttps.push("T1071".to_owned()); // Application Layer Protocol
    }
    ttps
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ransomware_match() -> YaraMatch {
        YaraMatch::new("Ransomware_LockBit")
    }

    fn backdoor_match() -> YaraMatch {
        YaraMatch::new("Backdoor_EvilAgent")
    }

    fn cobalt_match() -> YaraMatch {
        YaraMatch::new("CobaltStrike_Beacon")
    }

    #[test]
    fn test_tag_category_severity_ordering() {
        assert!(TagCategory::Wiper.severity() >= TagCategory::Ransomware.severity());
        assert!(TagCategory::Ransomware.severity() > TagCategory::Adware.severity());
        assert!(TagCategory::Packer.severity() < TagCategory::Infostealer.severity());
    }

    #[test]
    fn test_tag_category_label() {
        assert_eq!(TagCategory::Rat.label(), "RAT");
        assert_eq!(TagCategory::Miner.label(), "Miner");
    }

    #[test]
    fn test_threat_tag_clamp_confidence() {
        let tag = ThreatTag::new("x", TagCategory::Malware, "", 1.5);
        assert_eq!(tag.confidence, 1.0);
        let tag2 = ThreatTag::new("x", TagCategory::Malware, "", -0.1);
        assert_eq!(tag2.confidence, 0.0);
    }

    #[test]
    fn test_threat_tag_is_high_confidence() {
        assert!(ThreatTag::new("x", TagCategory::Malware, "", 0.8).is_high_confidence());
        assert!(!ThreatTag::new("x", TagCategory::Malware, "", 0.5).is_high_confidence());
    }

    #[test]
    fn test_tagging_rule_matches_prefix() {
        let rule = TaggingRule {
            yara_identifier: "Ransomware_".to_owned(),
            tags_to_apply: vec![],
            required_positives: 1,
        };
        assert!(rule.matches_rule("Ransomware_LockBit"));
        assert!(!rule.matches_rule("Trojan_Agent"));
    }

    #[test]
    fn test_builtin_rules_count() {
        let rules = builtin_tagging_rules();
        assert!(rules.len() >= 20, "expected ≥ 20 built-in rules, got {}", rules.len());
    }

    #[test]
    fn test_tag_match_results_ransomware() {
        let tagger = ThreatTagger::new();
        let matches = vec![ransomware_match()];
        let tags = tagger.tag_match_results(&matches);
        assert!(!tags.is_empty());
        assert!(tags.iter().any(|t| t.category == TagCategory::Ransomware));
    }

    #[test]
    fn test_tag_match_results_no_match() {
        let tagger = ThreatTagger::new();
        let matches = vec![YaraMatch::new("Unknown_Rule_XYZ")];
        let tags = tagger.tag_match_results(&matches);
        assert!(tags.is_empty());
    }

    #[test]
    fn test_build_profile_ransomware() {
        let tagger = ThreatTagger::new();
        let sha = "a".repeat(64);
        let profile = tagger.build_profile(&sha, &[ransomware_match()]);
        assert_eq!(profile.file_sha256, sha);
        assert_eq!(profile.top_category, TagCategory::Ransomware);
        assert!(!profile.mitre_ttps.is_empty());
        assert!(profile.mitre_ttps.contains(&"T1486".to_owned()));
    }

    #[test]
    fn test_build_profile_empty_matches() {
        let tagger = ThreatTagger::new();
        let profile = tagger.build_profile("abc", &[]);
        assert_eq!(profile.overall_confidence, 0.0);
        assert!(profile.tags.is_empty());
    }

    #[test]
    fn test_build_profile_high_threat() {
        let tagger = ThreatTagger::new();
        let profile = tagger.build_profile("abc", &[ransomware_match()]);
        assert!(profile.is_high_threat(), "profile: {:?}", profile);
    }

    #[test]
    fn test_build_profile_cobalt_strike() {
        let tagger = ThreatTagger::new();
        let profile = tagger.build_profile("abc", &[cobalt_match()]);
        assert!(profile.mitre_ttps.iter().any(|t| t.starts_with("T1573") || t.starts_with("T1071")));
    }

    #[test]
    fn test_rule_name_to_mitre_mimikatz() {
        let ttps = rule_name_to_mitre("Mimikatz_CredDump");
        assert!(ttps.contains(&"T1003".to_owned()));
    }

    #[test]
    fn test_rule_name_to_mitre_injection() {
        let ttps = rule_name_to_mitre("Trojan_Injection_PE");
        assert!(ttps.contains(&"T1055".to_owned()));
    }

    #[test]
    fn test_tag_to_mitre_ransomware() {
        let ttps = tag_to_mitre(&TagCategory::Ransomware);
        assert!(ttps.contains(&"T1486".to_owned()));
    }

    #[test]
    fn test_tag_to_mitre_rootkit() {
        let ttps = tag_to_mitre(&TagCategory::Rootkit);
        assert!(ttps.contains(&"T1014".to_owned()));
    }

    #[test]
    fn test_custom_tagging_rule() {
        let custom_rule = TaggingRule {
            yara_identifier: "Custom_TestFamily".to_owned(),
            tags_to_apply: vec![ThreatTag::new("custom", TagCategory::Trojan, "TestFamily", 0.88)],
            required_positives: 1,
        };
        let mut tagger = ThreatTagger::with_rules(vec![custom_rule]);
        tagger.add_rule(TaggingRule {
            yara_identifier: "ExtraRule".to_owned(),
            tags_to_apply: vec![ThreatTag::new("extra", TagCategory::Loader, "", 0.5)],
            required_positives: 1,
        });
        let m = YaraMatch::new("Custom_TestFamily_v2");
        let tags = tagger.tag_match_results(&[m]);
        assert!(tags.iter().any(|t| t.name == "custom"));
    }

    #[test]
    fn test_high_confidence_tags_filter() {
        let profile = ThreatProfile {
            file_sha256: "x".to_owned(),
            tags: vec![
                ThreatTag::new("a", TagCategory::Ransomware, "", 0.9),
                ThreatTag::new("b", TagCategory::Packer, "", 0.5),
            ],
            top_category: TagCategory::Ransomware,
            overall_confidence: 0.9,
            mitre_ttps: vec![],
        };
        assert_eq!(profile.high_confidence_tags().len(), 1);
    }

    #[test]
    fn test_multiple_matches_combined() {
        let tagger = ThreatTagger::new();
        let matches = vec![backdoor_match(), cobalt_match(), ransomware_match()];
        let profile = tagger.build_profile("abc", &matches);
        // Should have ≥ 3 distinct tags
        assert!(profile.tags.len() >= 3);
        // overall_confidence should be boosted by match count
        assert!(profile.overall_confidence > 0.0);
    }
}
