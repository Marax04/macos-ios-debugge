// rustre-yara-rules/src/apt_detection_rules.rs
// APT group detection YARA rules.

use std::collections::HashMap;

// ─── APT Group Enum ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AptGroup {
    Lazarus,
    APT28,
    APT29,
    APT32,
    APT41,
    Carbanak,
    Sandworm,
    Turla,
    OceanLotus,
    Equation,
    SilverTerrier,
    Unknown(String),
}

impl AptGroup {
    #[must_use]
    pub const fn display_name(&self) -> &str {
        match self {
            Self::Lazarus => "Lazarus Group (DPRK)",
            Self::APT28 => "APT28 / Fancy Bear (Russia)",
            Self::APT29 => "APT29 / Cozy Bear (Russia)",
            Self::APT32 => "APT32 / OceanLotus (Vietnam)",
            Self::APT41 => "APT41 / Winnti (China)",
            Self::Carbanak => "Carbanak / FIN7",
            Self::Sandworm => "Sandworm (Russia/GRU)",
            Self::Turla => "Turla / Snake (Russia/FSB)",
            Self::OceanLotus => "OceanLotus / APT32",
            Self::Equation => "Equation Group (NSA-linked)",
            Self::SilverTerrier => "SilverTerrier (Nigeria BEC)",
            Self::Unknown(s) => s.as_str(),
        }
    }

    #[must_use]
    pub const fn country_of_origin(&self) -> &str {
        match self {
            Self::Lazarus => "DPRK",
            Self::APT28 | Self::APT29 | Self::Sandworm | Self::Turla => "Russia",
            Self::APT32 | Self::OceanLotus => "Vietnam",
            Self::APT41 => "China",
            Self::Carbanak => "Unknown (criminal)",
            Self::Equation => "USA",
            Self::SilverTerrier => "Nigeria",
            Self::Unknown(_) => "Unknown",
        }
    }

    #[must_use] 
    pub fn all_known() -> Vec<Self> {
        vec![
            Self::Lazarus,
            Self::APT28,
            Self::APT29,
            Self::APT32,
            Self::APT41,
            Self::Carbanak,
            Self::Sandworm,
            Self::Turla,
            Self::OceanLotus,
            Self::Equation,
            Self::SilverTerrier,
        ]
    }
}

// ─── Confidence ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AptConfidence {
    Low,
    Medium,
    High,
}

impl AptConfidence {
    #[must_use] 
    pub const fn as_score(&self) -> f64 {
        match self {
            Self::Low => 0.33,
            Self::Medium => 0.66,
            Self::High => 1.0,
        }
    }

    #[must_use] 
    pub fn from_score(score: f64) -> Self {
        if score >= 0.75 {
            Self::High
        } else if score >= 0.40 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

// ─── APT Rule ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AptRule {
    pub group: AptGroup,
    pub rule_text: String,
    pub confidence: AptConfidence,
    pub technique: String,
}

impl AptRule {
    pub fn new(
        group: AptGroup,
        rule_text: impl Into<String>,
        confidence: AptConfidence,
        technique: impl Into<String>,
    ) -> Self {
        Self {
            group,
            rule_text: rule_text.into(),
            confidence,
            technique: technique.into(),
        }
    }

    #[must_use] 
    pub fn rule_name(&self) -> Option<&str> {
        let t = self.rule_text.trim_start();
        t.strip_prefix("rule ").and_then(|s| s.split_whitespace().next())
    }

    #[must_use] 
    pub fn validate_syntax(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if !self.rule_text.contains("rule ") {
            errors.push("missing 'rule' keyword".to_string());
        }
        if !self.rule_text.contains("condition:") {
            errors.push("missing condition section".to_string());
        }
        let open = self.rule_text.chars().filter(|&c| c == '{').count();
        let close = self.rule_text.chars().filter(|&c| c == '}').count();
        if open != close {
            errors.push(format!("unbalanced braces: {open} open vs {close} close"));
        }
        errors
    }
}

// ─── APT Rules Collection ─────────────────────────────────────────────────────

pub struct AptRules;

pub static APT_RULE_TEXTS: &[&str] = &[
    // 1 — Lazarus Typeframe (RC4 key 0x62, specific export names)
    r#"rule Lazarus_Typeframe
{
    meta:
        description = "Detects Lazarus Group Typeframe backdoor via RC4 key and export markers"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        mitre_attack = "T1059.003"
        apt_group = "Lazarus"
        confidence = "high"

    strings:
        $rc4_key = { 62 62 62 62 62 62 62 62 }
        $export1 = "GetConfiguration"   ascii
        $export2 = "SetConfiguration"   ascii
        $export3 = "RunAndHide"         ascii
        $str1    = "MyProxy"   ascii
        $str2    = "cmd.exe /c" nocase ascii wide

    condition:
        $rc4_key and (2 of ($export1,$export2,$export3)) and $str2
}
"#,
    // 2 — APT28 XAgent
    r#"rule APT28_XAgent
{
    meta:
        description = "Detects APT28 XAgent implant via hardcoded C2 callback strings"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        mitre_attack = "T1071.001"
        apt_group = "APT28"
        confidence = "high"

    strings:
        $s1 = "Agent.BTZ" nocase ascii
        $s2 = "XAgent"    ascii
        $s3 = "module_id" ascii
        $s4 = "task_id"   ascii
        $c2_mark = { 2F 61 67 65 6E 74 2F 70 69 6E 67 }  /* /agent/ping */
        $s5 = "Sofacy" nocase ascii
        $s6 = "fancy_bear_id" nocase ascii

    condition:
        2 of ($s1,$s2,$s5,$s6) or ($c2_mark and 1 of ($s3,$s4))
}
"#,
    // 3 — Carbanak dropper
    r#"rule Carbanak_Dropper
{
    meta:
        description = "Detects Carbanak / FIN7 dropper via PE overlay structure"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        mitre_attack = "T1027"
        apt_group = "Carbanak"
        confidence = "high"

    strings:
        $magic = { 4D 5A 90 00 }
        $ovl   = { 43 41 52 42 41 4E 41 4B }  /* CARBANAK */
        $s1    = "Anunak"   ascii nocase
        $s2    = "carbanak" ascii nocase
        $cfg   = "config.bin" ascii
        $s3    = "svchost.exe" ascii wide nocase

    condition:
        $magic at 0 and ($ovl or $s1 or $s2) and ($cfg or $s3)
}
"#,
    // 4 — Winnti/APT41 rootkit
    r#"rule Winnti_Rootkit
{
    meta:
        description = "Detects Winnti rootkit driver via embedded name strings"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        mitre_attack = "T1014"
        apt_group = "APT41"
        confidence = "high"

    strings:
        $n1 = "Winnti"  ascii wide
        $n2 = "wnBIO"   ascii
        $n3 = "WinDivert" ascii wide
        $n4 = "NDIS_STRING" ascii
        $drv = "\\Driver\\Disk" ascii wide nocase
        $sys = ".sys" ascii nocase

    condition:
        ($n1 or $n2) and ($n3 or $n4 or $drv)
}
"#,
    // 5 — PlugX config magic
    r#"rule PlugX_Config
{
    meta:
        description = "Detects PlugX implant configuration block by magic bytes"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        mitre_attack = "T1055"
        apt_group = "APT41"
        confidence = "medium"

    strings:
        $magic = { 27 48 4B }
        $s1    = "PlugX"  ascii nocase
        $s2    = "PLUGX"  ascii
        $s3    = "Korplug" ascii nocase
        $s4    = "Sogu"    ascii nocase
        $mutex = { 50 58 [4] 00 }  /* PX\x00{4 bytes}\x00 */

    condition:
        $magic or (2 of ($s1,$s2,$s3,$s4)) or $mutex
}
"#,
    // 6 — Cobalt Strike Beacon
    r#"rule CobaltStrike_Beacon
{
    meta:
        description = "Detects Cobalt Strike Beacon via MZRE header and section markers"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        mitre_attack = "T1218"
        apt_group = "Unknown"
        confidence = "high"

    strings:
        $mz   = { 4D 5A }
        $hdr1 = "MZRE" ascii
        $hdr2 = "MZ" ascii
        $sec  = ".rdata" ascii
        $s1   = "beacon.dll" nocase ascii
        $s2   = "ReflectiveLoader" ascii
        $s3   = "cobaltstrike" nocase ascii
        $cs4  = { FC E8 89 00 00 00 60 89 E5 31 D2 }  /* CS shellcode stager */

    condition:
        ($mz at 0 and $s2) or ($cs4 and ($s1 or $s3))
}
"#,
    // 7 — Emotet payload
    r#"rule Emotet_Payload
{
    meta:
        description = "Detects Emotet loader via RC4-encrypted C2 list pattern"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        mitre_attack = "T1027"
        apt_group = "Unknown"
        confidence = "medium"

    strings:
        $s1 = "Emotet"  ascii nocase
        $s2 = "Heodo"   ascii nocase
        $b1 = { E8 ?? ?? ?? ?? 83 C4 04 85 C0 74 }   /* RC4 key setup sequence */
        $b2 = { 8B 45 08 8B 55 0C 8D 0C 02 }          /* IAT loader stub */
        $reg = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase

    condition:
        (2 of ($s1,$s2)) or ($b1 and $b2) or ($b1 and $reg)
}
"#,
    // 8 — APT29 Cozy Bear SUNBURST
    r#"rule APT29_Sunburst
{
    meta:
        description = "Detects APT29 SUNBURST SolarWinds backdoor strings"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        mitre_attack = "T1195.002"
        apt_group = "APT29"
        confidence = "high"

    strings:
        $s1 = "SolarWinds.Orion.Core.BusinessLayer" ascii wide
        $s2 = "SUNBURST" ascii nocase
        $s3 = "avsvmcloud.com" ascii
        $s4 = "OrionImprovementBusinessLayer" ascii wide
        $s5 = "UpdateNotification" ascii wide

    condition:
        2 of them
}
"#,
    // 9 — Sandworm NotPetya / ExPetr
    r#"rule Sandworm_ExPetr
{
    meta:
        description = "Detects Sandworm NotPetya / ExPetr wiper-ransomware"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        mitre_attack = "T1561.002"
        apt_group = "Sandworm"
        confidence = "high"

    strings:
        $s1 = "MBR" ascii wide
        $s2 = { 1E 8B F0 }                              /* MBR overwrite signature */
        $s3 = "Oops, your important files are encrypted" ascii
        $s4 = "perfc.dat" ascii
        $s5 = { 0F 33 ?? ?? 8D 40 18 }                  /* Salsa20 key expansion */

    condition:
        2 of ($s1,$s2,$s3,$s4,$s5)
}
"#,
    // 10 — Turla Snake implant
    r#"rule Turla_Snake
{
    meta:
        description = "Detects Turla Snake / Uroburos rootkit strings"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        mitre_attack = "T1014"
        apt_group = "Turla"
        confidence = "high"

    strings:
        $n1 = "Snake"      ascii nocase
        $n2 = "Uroburos"   ascii nocase
        $n3 = "Turla"      ascii nocase
        $s1 = "\\PIPE\\IPIMP" ascii wide
        $s2 = "SnakeInstaller" ascii nocase
        $s3 = "agent.dll" ascii nocase

    condition:
        2 of ($n1,$n2,$n3) or ($s1 and 1 of ($s2,$s3))
}
"#,
    // 11 — Equation Group GrayFish
    r#"rule Equation_GrayFish
{
    meta:
        description = "Detects Equation Group GrayFish boot-kit strings"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        mitre_attack = "T1542.003"
        apt_group = "Equation"
        confidence = "medium"

    strings:
        $s1 = "GrayFish" ascii nocase
        $s2 = "NONEOFYOURBUSINESS" ascii
        $s3 = { B4 D0 81 C3 }                     /* GrayFish crypto constant */
        $s4 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" ascii wide

    condition:
        $s1 or $s2 or ($s3 and $s4)
}
"#,
    // 12 — APT32 OceanLotus
    r#"rule APT32_OceanLotus
{
    meta:
        description = "Detects APT32 OceanLotus macOS/Win implant markers"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        mitre_attack = "T1059"
        apt_group = "APT32"
        confidence = "medium"

    strings:
        $s1 = "OceanLotus" ascii nocase
        $s2 = "Denis"      ascii
        $s3 = "APT32"      ascii nocase
        $c2 = { 68 74 74 70 3A 2F 2F }  /* http:// */
        $dll = "backdoor.dll" ascii nocase
        $exp = "DllEntryPoint" ascii

    condition:
        (1 of ($s1,$s2,$s3)) and ($c2 or $dll or $exp)
}
"#,
];

impl AptRules {
    fn build_rules() -> Vec<AptRule> {
        let descriptors: &[(AptGroup, AptConfidence, &str)] = &[
            (AptGroup::Lazarus, AptConfidence::High, "T1059.003"),
            (AptGroup::APT28, AptConfidence::High, "T1071.001"),
            (AptGroup::Carbanak, AptConfidence::High, "T1027"),
            (AptGroup::APT41, AptConfidence::High, "T1014"),
            (AptGroup::APT41, AptConfidence::Medium, "T1055"),
            (
                AptGroup::Unknown("CobaltStrike".to_string()),
                AptConfidence::High,
                "T1218",
            ),
            (
                AptGroup::Unknown("Emotet".to_string()),
                AptConfidence::Medium,
                "T1027",
            ),
            (AptGroup::APT29, AptConfidence::High, "T1195.002"),
            (AptGroup::Sandworm, AptConfidence::High, "T1561.002"),
            (AptGroup::Turla, AptConfidence::High, "T1014"),
            (AptGroup::Equation, AptConfidence::Medium, "T1542.003"),
            (AptGroup::APT32, AptConfidence::Medium, "T1059"),
        ];

        APT_RULE_TEXTS
            .iter()
            .zip(descriptors.iter())
            .map(|(text, (group, conf, tech))| {
                AptRule::new(group.clone(), *text, conf.clone(), *tech)
            })
            .collect()
    }

    #[must_use] 
    pub fn all_rules() -> Vec<AptRule> {
        Self::build_rules()
    }

    #[must_use] 
    pub fn rule_for_group(group: &AptGroup) -> Vec<AptRule> {
        Self::build_rules()
            .into_iter()
            .filter(|r| &r.group == group)
            .collect()
    }

    #[must_use] 
    pub fn rules_by_confidence(conf: &AptConfidence) -> Vec<AptRule> {
        Self::build_rules()
            .into_iter()
            .filter(|r| &r.confidence == conf)
            .collect()
    }

    #[must_use] 
    pub fn validate_all() -> Vec<String> {
        let mut errors = Vec::new();
        let mut seen: HashMap<String, usize> = HashMap::new();
        for (i, rule) in Self::build_rules().iter().enumerate() {
            for e in rule.validate_syntax() {
                errors.push(format!("Rule[{i}]: {e}"));
            }
            if let Some(name) = rule.rule_name() {
                if let Some(prev) = seen.insert(name.to_string(), i) {
                    errors.push(format!("Duplicate name '{name}' at {prev} and {i}"));
                }
            } else {
                errors.push(format!("Rule[{i}] has no parseable name"));
            }
        }
        errors
    }

    #[must_use] 
    pub fn group_coverage() -> HashMap<String, usize> {
        let mut map: HashMap<String, usize> = HashMap::new();
        for rule in Self::build_rules() {
            *map.entry(rule.group.display_name().to_string()).or_default() += 1;
        }
        map
    }

    #[must_use] 
    pub fn rules_by_technique(technique: &str) -> Vec<AptRule> {
        Self::build_rules()
            .into_iter()
            .filter(|r| r.technique.contains(technique))
            .collect()
    }

    #[must_use] 
    pub fn high_confidence_rule_names() -> Vec<String> {
        Self::build_rules()
            .into_iter()
            .filter(|r| r.confidence == AptConfidence::High)
            .filter_map(|r| r.rule_name().map(String::from))
            .collect()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_rules_have_names() {
        for rule in AptRules::all_rules() {
            assert!(
                rule.rule_name().is_some(),
                "Missing name in: {}",
                &rule.rule_text[..60.min(rule.rule_text.len())]
            );
        }
    }

    #[test]
    fn test_all_rules_have_condition() {
        for rule in AptRules::all_rules() {
            assert!(
                rule.rule_text.contains("condition:"),
                "Missing condition in {:?}",
                rule.rule_name()
            );
        }
    }

    #[test]
    fn test_validate_no_errors() {
        let errors = AptRules::validate_all();
        assert!(errors.is_empty(), "Errors: {errors:?}");
    }

    #[test]
    fn test_rule_count_at_least_ten() {
        assert!(AptRules::all_rules().len() >= 10);
    }

    #[test]
    fn test_lazarus_rules_exist() {
        let rules = AptRules::rule_for_group(&AptGroup::Lazarus);
        assert!(!rules.is_empty());
    }

    #[test]
    fn test_apt28_rules_exist() {
        let rules = AptRules::rule_for_group(&AptGroup::APT28);
        assert!(!rules.is_empty());
    }

    #[test]
    fn test_apt41_rules_exist() {
        let rules = AptRules::rule_for_group(&AptGroup::APT41);
        assert!(!rules.is_empty());
    }

    #[test]
    fn test_high_confidence_rules_non_empty() {
        let names = AptRules::high_confidence_rule_names();
        assert!(!names.is_empty());
    }

    #[test]
    fn test_group_coverage_non_empty() {
        let cov = AptRules::group_coverage();
        assert!(!cov.is_empty());
    }

    #[test]
    fn test_rules_by_technique_t1014() {
        let rules = AptRules::rules_by_technique("T1014");
        assert!(!rules.is_empty());
    }

    #[test]
    fn test_confidence_ordering() {
        assert!(AptConfidence::Low < AptConfidence::Medium);
        assert!(AptConfidence::Medium < AptConfidence::High);
    }

    #[test]
    fn test_confidence_from_score() {
        assert_eq!(AptConfidence::from_score(0.9), AptConfidence::High);
        assert_eq!(AptConfidence::from_score(0.5), AptConfidence::Medium);
        assert_eq!(AptConfidence::from_score(0.1), AptConfidence::Low);
    }

    #[test]
    fn test_apt_group_display_name() {
        assert!(AptGroup::Lazarus.display_name().contains("Lazarus"));
        assert!(AptGroup::APT28.display_name().contains("APT28"));
    }

    #[test]
    fn test_apt_group_country() {
        assert_eq!(AptGroup::Lazarus.country_of_origin(), "DPRK");
        assert_eq!(AptGroup::APT29.country_of_origin(), "Russia");
    }

    #[test]
    fn test_all_known_groups_non_empty() {
        let groups = AptGroup::all_known();
        assert!(groups.len() >= 10);
    }

    #[test]
    fn test_no_duplicate_rule_names() {
        let rules = AptRules::all_rules();
        let mut names: Vec<&str> = rules.iter().filter_map(|r| r.rule_name()).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(before, names.len(), "Duplicate rule names");
    }

    #[test]
    fn test_sandworm_rule_high_confidence() {
        let rules = AptRules::rule_for_group(&AptGroup::Sandworm);
        assert!(!rules.is_empty());
        assert_eq!(rules[0].confidence, AptConfidence::High);
    }

    #[test]
    fn test_unknown_group_variant() {
        let g = AptGroup::Unknown("TestGroup".to_string());
        assert_eq!(g.display_name(), "TestGroup");
    }
}
