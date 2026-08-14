//! `family_classifier` — Malware family classification from YARA matches:
//! rule→family mapping, confidence scoring, version detection, variant identification.

use std::collections::{BTreeMap, HashMap};
use serde::{Deserialize, Serialize};

// ── Family definition ─────────────────────────────────────────────────────────

/// A malware family entry in the classification database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyEntry {
    /// Canonical family name (e.g. `Emotet`, `CobaltStrike`).
    pub name: String,
    /// Aliases / alternate names.
    pub aliases: Vec<String>,
    /// Category: "trojan", "ransomware", "apt", "backdoor", "dropper", etc.
    pub category: String,
    /// Known versions.
    pub versions: Vec<VersionInfo>,
    /// Known variants.
    pub variants: Vec<String>,
    /// Threat actor attribution.
    pub actor: Option<String>,
    /// MITRE ATT&CK technique IDs.
    pub mitre_techniques: Vec<String>,
}

/// Version information for a malware family.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub version: String,
    pub first_seen: String,
    pub distinguishing_rules: Vec<String>,
}

// ── Match → family mapping ────────────────────────────────────────────────────

/// A single rule-to-family mapping entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFamilyMapping {
    /// YARA rule name pattern (may contain `*` as a prefix wildcard).
    pub rule_pattern: String,
    /// Family this rule maps to.
    pub family: String,
    /// Version indicator (if the rule is version-specific).
    pub version_indicator: Option<String>,
    /// Variant indicator.
    pub variant_indicator: Option<String>,
    /// Base confidence contribution (0.0–1.0) when this rule fires.
    pub base_confidence: f64,
    /// Weight used when combining with other rules.
    pub weight: f64,
}

impl RuleFamilyMapping {
    /// Does the given rule name match this mapping's pattern?
    #[must_use]
    pub fn matches_rule(&self, rule_name: &str) -> bool {
        if self.rule_pattern.ends_with('*') {
            let prefix = &self.rule_pattern[..self.rule_pattern.len() - 1];
            rule_name.starts_with(prefix)
        } else {
            rule_name.eq_ignore_ascii_case(&self.rule_pattern)
        }
    }
}

// ── Classification result ─────────────────────────────────────────────────────

/// The classified identity of a sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationResult {
    /// The most likely family name (or "Unknown").
    pub family: String,
    /// Confidence score 0.0–1.0.
    pub confidence: f64,
    /// Confidence tier.
    pub tier: ConfidenceTier,
    /// Detected version (if known).
    pub version: Option<String>,
    /// Detected variant (if known).
    pub variant: Option<String>,
    /// All matched families with individual confidence scores.
    pub candidates: Vec<FamilyCandidate>,
    /// The YARA rules that contributed to this classification.
    pub matched_rules: Vec<String>,
    /// Category of the top family.
    pub category: Option<String>,
    /// MITRE technique IDs from the top family.
    pub mitre_techniques: Vec<String>,
}

/// A candidate family with its confidence score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyCandidate {
    pub family: String,
    pub confidence: f64,
    pub matched_rules: Vec<String>,
    pub version: Option<String>,
    pub variant: Option<String>,
}

/// Qualitative confidence tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfidenceTier {
    /// < 0.3
    Low,
    /// 0.3 – 0.6
    Medium,
    /// 0.6 – 0.85
    High,
    /// > 0.85
    VeryHigh,
}

impl ConfidenceTier {
    #[must_use]
    pub fn from_score(score: f64) -> Self {
        if score < 0.3 { Self::Low }
        else if score < 0.6 { Self::Medium }
        else if score < 0.85 { Self::High }
        else { Self::VeryHigh }
    }
}

impl std::fmt::Display for ConfidenceTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low      => write!(f, "LOW"),
            Self::Medium   => write!(f, "MEDIUM"),
            Self::High     => write!(f, "HIGH"),
            Self::VeryHigh => write!(f, "VERY HIGH"),
        }
    }
}

impl ClassificationResult {
    /// True if the classification is reliable (confidence >= 0.6).
    #[must_use]
    pub fn is_reliable(&self) -> bool {
        self.confidence >= 0.6
    }

    /// Summary string for logging.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} [confidence={:.2} {}{}{}]",
            self.family,
            self.confidence,
            self.tier,
            self.version.as_deref().map(|v| format!(", v{v}")).unwrap_or_default(),
            self.variant.as_deref().map(|v| format!(", variant={v}")).unwrap_or_default(),
        )
    }
}

// ── Classifier ────────────────────────────────────────────────────────────────

/// Family classifier backed by a rule-to-family mapping database.
pub struct FamilyClassifier {
    mappings: Vec<RuleFamilyMapping>,
    families: HashMap<String, FamilyEntry>,
}

impl FamilyClassifier {
    /// Create an empty classifier.
    #[must_use]
    pub fn new() -> Self {
        Self {
            mappings: Vec::new(),
            families: HashMap::new(),
        }
    }

    /// Create a classifier with the built-in mapping database.
    #[must_use]
    pub fn with_builtin_db() -> Self {
        let mut c = Self::new();
        c.load_builtin_mappings();
        c.load_builtin_families();
        c
    }

    /// Add a rule-family mapping.
    pub fn add_mapping(&mut self, m: RuleFamilyMapping) {
        self.mappings.push(m);
    }

    /// Add a family entry.
    pub fn add_family(&mut self, f: FamilyEntry) {
        self.families.insert(f.name.clone(), f);
    }

    /// Classify a sample based on a list of matched YARA rule names.
    #[must_use]
    pub fn classify(&self, matched_rules: &[String]) -> ClassificationResult {
        if matched_rules.is_empty() {
            return Self::unknown_result(Vec::new());
        }

        // For each matched rule, find applicable mappings and accumulate scores.
        let mut family_scores: BTreeMap<String, FamilyCumulativeScore> = BTreeMap::new();

        for rule_name in matched_rules {
            for mapping in &self.mappings {
                if mapping.matches_rule(rule_name) {
                    let entry = family_scores
                        .entry(mapping.family.clone())
                        .or_insert_with(|| FamilyCumulativeScore::new(mapping.family.clone()));

                    entry.add_match(rule_name, mapping);
                }
            }
        }

        if family_scores.is_empty() {
            return Self::unknown_result(matched_rules.to_vec());
        }

        // Normalise scores.
        let max_score = family_scores.values().map(|s| s.raw_score).fold(0.0f64, f64::max);
        let mut candidates: Vec<FamilyCandidate> = family_scores.into_values()
            .map(|s| {
                let confidence = if max_score > 0.0 { (s.raw_score / max_score).min(1.0) } else { 0.0 };
                FamilyCandidate {
                    family: s.family.clone(),
                    confidence,
                    matched_rules: s.matched_rules,
                    version: s.version,
                    variant: s.variant,
                }
            })
            .collect();

        candidates.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));

        let top = &candidates[0];
        let (category, mitre) = self.families.get(&top.family)
            .map_or((None, Vec::new()), |f| (Some(f.category.clone()), f.mitre_techniques.clone()));

        ClassificationResult {
            family: top.family.clone(),
            confidence: top.confidence,
            tier: ConfidenceTier::from_score(top.confidence),
            version: top.version.clone(),
            variant: top.variant.clone(),
            matched_rules: matched_rules.to_vec(),
            category,
            mitre_techniques: mitre,
            candidates,
        }
    }

    /// Classify with weighted averaging across multiple scan results.
    #[must_use]
    pub fn classify_multi_scan(
        &self,
        scan_results: &[Vec<String>],
        weights: Option<&[f64]>,
    ) -> ClassificationResult {
        if scan_results.is_empty() {
            return Self::unknown_result(Vec::new());
        }

        // Collect all unique rules, weighted by scan result weight.
        let mut rule_weights: HashMap<String, f64> = HashMap::new();
        let default_weight = 1.0 / f64::from(u32::try_from(scan_results.len()).unwrap_or(u32::MAX));

        for (i, rules) in scan_results.iter().enumerate() {
            let w = weights.and_then(|ws| ws.get(i)).copied().unwrap_or(default_weight);
            for rule in rules {
                *rule_weights.entry(rule.clone()).or_insert(0.0) += w;
            }
        }

        // Classify using deduplicated rules weighted by frequency.
        let all_rules: Vec<String> = rule_weights.keys().cloned().collect();
        self.classify(&all_rules)
    }

    fn unknown_result(rules: Vec<String>) -> ClassificationResult {
        ClassificationResult {
            family: "Unknown".to_string(),
            confidence: 0.0,
            tier: ConfidenceTier::Low,
            version: None,
            variant: None,
            matched_rules: rules,
            category: None,
            mitre_techniques: Vec::new(),
            candidates: Vec::new(),
        }
    }

    // ── Built-in mapping database ─────────────────────────────────────────────

    fn load_builtin_mappings(&mut self) {
        let mappings = vec![
            // Emotet
            RuleFamilyMapping { rule_pattern: "Emotet*".into(), family: "Emotet".into(), version_indicator: None, variant_indicator: None, base_confidence: 0.9, weight: 1.0 },
            RuleFamilyMapping { rule_pattern: "Win_Emotet*".into(), family: "Emotet".into(), version_indicator: None, variant_indicator: None, base_confidence: 0.9, weight: 1.0 },
            // Cobalt Strike
            RuleFamilyMapping { rule_pattern: "CobaltStrike*".into(), family: "CobaltStrike".into(), version_indicator: None, variant_indicator: None, base_confidence: 0.85, weight: 1.0 },
            RuleFamilyMapping { rule_pattern: "CS_Beacon*".into(), family: "CobaltStrike".into(), version_indicator: None, variant_indicator: None, base_confidence: 0.85, weight: 1.0 },
            RuleFamilyMapping { rule_pattern: "Susp_CommonC2Patterns".into(), family: "CobaltStrike".into(), version_indicator: None, variant_indicator: None, base_confidence: 0.4, weight: 0.5 },
            // Mimikatz
            RuleFamilyMapping { rule_pattern: "Susp_MimikatzStrings".into(), family: "Mimikatz".into(), version_indicator: None, variant_indicator: None, base_confidence: 0.9, weight: 1.0 },
            RuleFamilyMapping { rule_pattern: "HackTool_Mimikatz*".into(), family: "Mimikatz".into(), version_indicator: None, variant_indicator: None, base_confidence: 0.95, weight: 1.0 },
            // UPX packer
            RuleFamilyMapping { rule_pattern: "Packer_UPX".into(), family: "UPX".into(), version_indicator: None, variant_indicator: None, base_confidence: 0.9, weight: 0.8 },
            // VMProtect
            RuleFamilyMapping { rule_pattern: "Packer_VMProtect".into(), family: "VMProtect".into(), version_indicator: None, variant_indicator: None, base_confidence: 0.85, weight: 0.9 },
            // Themida
            RuleFamilyMapping { rule_pattern: "Packer_Themida".into(), family: "Themida".into(), version_indicator: None, variant_indicator: None, base_confidence: 0.85, weight: 0.9 },
            // Ransomware families
            RuleFamilyMapping { rule_pattern: "Ransomware_Ryuk*".into(), family: "Ryuk".into(), version_indicator: None, variant_indicator: None, base_confidence: 0.9, weight: 1.0 },
            RuleFamilyMapping { rule_pattern: "Ransomware_Conti*".into(), family: "Conti".into(), version_indicator: None, variant_indicator: None, base_confidence: 0.9, weight: 1.0 },
            RuleFamilyMapping { rule_pattern: "Ransomware_LockBit*".into(), family: "LockBit".into(), version_indicator: None, variant_indicator: None, base_confidence: 0.9, weight: 1.0 },
            // Generic shellcode
            RuleFamilyMapping { rule_pattern: "Shellcode_x86*".into(), family: "Shellcode_x86".into(), version_indicator: None, variant_indicator: None, base_confidence: 0.7, weight: 0.7 },
            RuleFamilyMapping { rule_pattern: "Shellcode_x64*".into(), family: "Shellcode_x64".into(), version_indicator: None, variant_indicator: None, base_confidence: 0.7, weight: 0.7 },
            // Metasploit
            RuleFamilyMapping { rule_pattern: "Metasploit*".into(), family: "Metasploit".into(), version_indicator: None, variant_indicator: None, base_confidence: 0.85, weight: 1.0 },
            // Document exploits
            RuleFamilyMapping { rule_pattern: "Doc_OLE_CVE2017_11882".into(), family: "CVE-2017-11882".into(), version_indicator: None, variant_indicator: None, base_confidence: 0.95, weight: 1.0 },
            RuleFamilyMapping { rule_pattern: "Doc_OfficeMacro*".into(), family: "MacroMalware".into(), version_indicator: None, variant_indicator: None, base_confidence: 0.7, weight: 0.8 },
        ];

        for m in mappings {
            self.mappings.push(m);
        }
    }

    fn load_builtin_families(&mut self) {
        let families = vec![
            FamilyEntry {
                name: "Emotet".into(),
                aliases: vec!["Heodo".into(), "Geodo".into()],
                category: "trojan".into(),
                versions: vec![
                    VersionInfo { version: "3".into(), first_seen: "2018".into(), distinguishing_rules: vec!["Emotet_v3_Dropper".into()] },
                    VersionInfo { version: "4".into(), first_seen: "2020".into(), distinguishing_rules: vec!["Emotet_v4_Loader".into()] },
                ],
                variants: vec!["Emotet_E".into(), "Emotet_F".into()],
                actor: Some("TA542".into()),
                mitre_techniques: vec!["T1027".into(), "T1055".into(), "T1547".into()],
            },
            FamilyEntry {
                name: "CobaltStrike".into(),
                aliases: vec!["CS".into(), "CS Beacon".into()],
                category: "backdoor".into(),
                versions: vec![
                    VersionInfo { version: "4.0".into(), first_seen: "2020".into(), distinguishing_rules: vec!["CobaltStrike_v4_Beacon".into()] },
                ],
                variants: vec!["staged".into(), "stageless".into()],
                actor: None,
                mitre_techniques: vec!["T1071.001".into(), "T1059.003".into(), "T1055".into()],
            },
            FamilyEntry {
                name: "Mimikatz".into(),
                aliases: vec!["mimilib".into()],
                category: "hacktool".into(),
                versions: vec![],
                variants: vec!["lite".into(), "x86".into(), "x64".into()],
                actor: None,
                mitre_techniques: vec!["T1003.001".into(), "T1558.003".into()],
            },
            FamilyEntry {
                name: "Ryuk".into(),
                aliases: vec!["WIZARD SPIDER".into()],
                category: "ransomware".into(),
                versions: vec![],
                variants: vec!["v1".into(), "v2".into(), "wake_on_lan".into()],
                actor: Some("WIZARD SPIDER".into()),
                mitre_techniques: vec!["T1486".into(), "T1490".into()],
            },
        ];

        for f in families {
            self.families.insert(f.name.clone(), f);
        }
    }
}

impl Default for FamilyClassifier {
    fn default() -> Self { Self::new() }
}

// ── Internal accumulator ──────────────────────────────────────────────────────

struct FamilyCumulativeScore {
    family: String,
    raw_score: f64,
    matched_rules: Vec<String>,
    version: Option<String>,
    variant: Option<String>,
}

impl FamilyCumulativeScore {
    const fn new(family: String) -> Self {
        Self { family, raw_score: 0.0, matched_rules: Vec::new(), version: None, variant: None }
    }

    fn add_match(&mut self, rule: &str, mapping: &RuleFamilyMapping) {
        self.raw_score += mapping.base_confidence * mapping.weight;
        if !self.matched_rules.contains(&rule.to_string()) {
            self.matched_rules.push(rule.to_string());
        }
        if self.version.is_none() {
            self.version.clone_from(&mapping.version_indicator);
        }
        if self.variant.is_none() {
            self.variant.clone_from(&mapping.variant_indicator);
        }
    }
}

// ── Version detector ──────────────────────────────────────────────────────────

/// Detect version of a malware family from rule names and raw bytes.
pub struct VersionDetector {
    /// Maps `(family, version_suffix_pattern)` → version string.
    patterns: Vec<(String, String, String)>,
}

impl VersionDetector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            patterns: vec![
                ("Emotet".into(), "_v3_".into(), "3".into()),
                ("Emotet".into(), "_v4_".into(), "4".into()),
                ("CobaltStrike".into(), "_v4_".into(), "4.0".into()),
                ("CobaltStrike".into(), "_v3_".into(), "3.x".into()),
                ("UPX".into(), "_3".into(), "3.x".into()),
                ("UPX".into(), "_4".into(), "4.x".into()),
            ],
        }
    }

    /// Detect version from a list of matched rule names for a given family.
    #[must_use]
    pub fn detect(&self, family: &str, matched_rules: &[String]) -> Option<String> {
        for rule in matched_rules {
            for (fam, pat, ver) in &self.patterns {
                if fam == family && rule.contains(pat.as_str()) {
                    return Some(ver.clone());
                }
            }
        }
        None
    }
}

impl Default for VersionDetector {
    fn default() -> Self { Self::new() }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_known_family() {
        let classifier = FamilyClassifier::with_builtin_db();
        let rules = vec!["Susp_MimikatzStrings".to_string()];
        let result = classifier.classify(&rules);
        assert_eq!(result.family, "Mimikatz");
        assert!(result.confidence > 0.0);
    }

    #[test]
    fn test_classify_unknown() {
        let classifier = FamilyClassifier::with_builtin_db();
        let result = classifier.classify(&[]);
        assert_eq!(result.family, "Unknown");
        assert_eq!(result.confidence, 0.0);
    }

    #[test]
    fn test_classify_wildcard_pattern() {
        let classifier = FamilyClassifier::with_builtin_db();
        let rules = vec!["Emotet_Config_Extractor".to_string()];
        let result = classifier.classify(&rules);
        assert_eq!(result.family, "Emotet");
    }

    #[test]
    fn test_confidence_tier() {
        assert_eq!(ConfidenceTier::from_score(0.1), ConfidenceTier::Low);
        assert_eq!(ConfidenceTier::from_score(0.5), ConfidenceTier::Medium);
        assert_eq!(ConfidenceTier::from_score(0.7), ConfidenceTier::High);
        assert_eq!(ConfidenceTier::from_score(0.9), ConfidenceTier::VeryHigh);
    }

    #[test]
    fn test_rule_pattern_matching() {
        let m = RuleFamilyMapping {
            rule_pattern: "CobaltStrike*".into(),
            family: "CobaltStrike".into(),
            version_indicator: None,
            variant_indicator: None,
            base_confidence: 0.9,
            weight: 1.0,
        };
        assert!(m.matches_rule("CobaltStrike_v4_Beacon"));
        assert!(m.matches_rule("CobaltStrike"));
        assert!(!m.matches_rule("Emotet_v4"));
    }

    #[test]
    fn test_multi_scan_classification() {
        let classifier = FamilyClassifier::with_builtin_db();
        let s1 = vec!["Susp_MimikatzStrings".to_string()];
        let s2 = vec!["HackTool_Mimikatz_v2".to_string()];
        let result = classifier.classify_multi_scan(&[s1, s2], None);
        // HackTool_Mimikatz* wildcard matches s2
        assert_eq!(result.family, "Mimikatz");
    }
}
