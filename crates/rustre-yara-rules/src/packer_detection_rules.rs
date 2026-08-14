// rustre-yara-rules/src/packer_detection_rules.rs
// Packer detection YARA rules.

use std::collections::HashMap;

// ─── Packer Family ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PackerFamily {
    UPX,
    Themida,
    VMProtect,
    ASPack,
    PECompact,
    MPress,
    NsPack,
    Petite,
    MPRESS,
    Obsidium,
    Enigma,
    BoxedApp,
    Confuser,
    Custom(String),
}

impl PackerFamily {
    #[must_use] 
    pub const fn display_name(&self) -> &str {
        match self {
            Self::UPX => "UPX",
            Self::Themida => "Themida / WinLicense",
            Self::VMProtect => "VMProtect",
            Self::ASPack => "ASPack",
            Self::PECompact => "PECompact",
            Self::MPress => "MPRESS",
            Self::NsPack => "NsPack",
            Self::Petite => "Petite",
            Self::MPRESS => "MPRESS (Alt)",
            Self::Obsidium => "Obsidium",
            Self::Enigma => "Enigma Protector",
            Self::BoxedApp => "BoxedApp Packer",
            Self::Confuser => "ConfuserEx",
            Self::Custom(s) => s.as_str(),
        }
    }

    #[must_use] 
    pub const fn is_protector(&self) -> bool {
        matches!(
            self,
            Self::Themida | Self::VMProtect | Self::Obsidium | Self::Enigma
        )
    }

    #[must_use] 
    pub const fn is_packer(&self) -> bool {
        matches!(
            self,
            Self::UPX | Self::ASPack | Self::PECompact | Self::MPress | Self::NsPack | Self::Petite | Self::MPRESS | Self::BoxedApp
        )
    }

    #[must_use] 
    pub fn all_families() -> Vec<Self> {
        vec![
            Self::UPX,
            Self::Themida,
            Self::VMProtect,
            Self::ASPack,
            Self::PECompact,
            Self::MPress,
            Self::NsPack,
            Self::Petite,
            Self::MPRESS,
            Self::Obsidium,
            Self::Enigma,
            Self::BoxedApp,
            Self::Confuser,
        ]
    }
}

// ─── Packer Rule ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PackerRule {
    pub family: PackerFamily,
    pub rule_text: String,
    pub version_hint: Option<String>,
}

impl PackerRule {
    pub fn new(
        family: PackerFamily,
        rule_text: impl Into<String>,
        version_hint: Option<String>,
    ) -> Self {
        Self {
            family,
            rule_text: rule_text.into(),
            version_hint,
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
        let opens = self.rule_text.chars().filter(|&c| c == '{').count();
        let closes = self.rule_text.chars().filter(|&c| c == '}').count();
        if opens != closes {
            errors.push(format!("unbalanced braces: {opens}/{closes}"));
        }
        errors
    }
}

// ─── YARA Rule Texts ──────────────────────────────────────────────────────────

pub static PACKER_RULE_TEXTS: &[&str] = &[
    // 1 — UPX
    r#"rule UPX_Packed
{
    meta:
        description = "Detects UPX-packed PE files via section names and OEP JMP stub"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        packer = "UPX"

    strings:
        $sec0   = "UPX0" ascii
        $sec1   = "UPX1" ascii
        $sec2   = "UPX2" ascii
        $oep    = { 60 E8 00 00 00 00 5B }   /* pushad; call $+5; pop ebx */
        $oep2   = { 60 BE ?? ?? ?? ?? 8D BE }

    condition:
        ($sec0 and $sec1) or $oep or $oep2
}
"#,
    // 2 — Themida v2
    r#"rule Themida_v2
{
    meta:
        description = "Detects Themida / WinLicense v2 protection"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        packer = "Themida"

    strings:
        $sec1   = ".themida"   ascii
        $sec2   = ".winlicense" ascii
        $sec3   = "WinLicense" ascii nocase
        $sec4   = "Themida"    ascii nocase
        $key1   = { E9 ?? ?? ?? ?? E9 }    /* JMP chain dispatcher */

    condition:
        1 of ($sec1,$sec2,$sec3,$sec4) or $key1
}
"#,
    // 3 — VMProtect v3
    r#"rule VMProtect_v3
{
    meta:
        description = "Detects VMProtect 3.x via .vmp0 section and VM dispatcher"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        packer = "VMProtect"

    strings:
        $sec1 = ".vmp0" ascii
        $sec2 = ".vmp1" ascii
        $s1   = "VMProtect" ascii nocase
        $disp = { 8B 04 24 C2 04 00 }     /* VM entry stub */
        $push = { 68 ?? ?? ?? ?? C3 }     /* push imm32; ret */

    condition:
        ($sec1 and $sec2) or ($s1 and $disp) or ($sec1 and $push)
}
"#,
    // 4 — ASPack
    r#"rule ASPack_Packed
{
    meta:
        description = "Detects ASPack packer via section name and entry point pattern"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        packer = "ASPack"

    strings:
        $sec  = ".aspack" ascii
        $ep1  = { EB 72 }                  /* JMP to unpacker prologue */
        $ep2  = { 60 E8 ?? ?? ?? ?? }      /* pushad; call unpacker */
        $s1   = "ASPack" ascii nocase
        $mark = { 00 60 EB 1A }

    condition:
        $sec or ($ep1 and $ep2) or $s1 or $mark
}
"#,
    // 5 — PECompact
    r#"rule PECompact_Packed
{
    meta:
        description = "Detects PECompact packed PE files"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        packer = "PECompact"

    strings:
        $sec  = "pec2" ascii
        $s1   = "PECompact" ascii nocase
        $mark = { EB 06 68 ?? ?? ?? ?? C3 }
        $ep   = { B8 00 ?? ?? ?? 50 45 00 00 }

    condition:
        $sec or $s1 or $mark or $ep
}
"#,
    // 6 — MPRESS
    r#"rule MPRESS_Packed
{
    meta:
        description = "Detects MPRESS packed PE files"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        packer = "MPRESS"

    strings:
        $sec1 = ".MPRESS1" ascii
        $sec2 = ".MPRESS2" ascii
        $s1   = "MPRESS"   ascii
        $ep   = { 60 E8 00 00 00 00 58 25 }

    condition:
        ($sec1 and $sec2) or $s1 or $ep
}
"#,
    // 7 — NsPack
    r#"rule NsPack_Packed
{
    meta:
        description = "Detects NsPack packed PE files"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        packer = "NsPack"

    strings:
        $sec1 = "nsp0" ascii
        $sec2 = "nsp1" ascii
        $s1   = "NsPack" ascii nocase
        $ep   = { 9C 60 E8 00 00 00 00 }   /* pushfd; pushad; call $+5 */

    condition:
        ($sec1 and $sec2) or $s1 or $ep
}
"#,
    // 8 — Petite
    r#"rule Petite_Packed
{
    meta:
        description = "Detects Petite packer via section name and stub"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        packer = "Petite"

    strings:
        $sec  = ".petite" ascii
        $s1   = "petite"  ascii nocase
        $ep   = { B8 ?? ?? ?? ?? 03 05 }

    condition:
        $sec or $s1 or $ep
}
"#,
    // 9 — Obsidium
    r#"rule Obsidium_Protected
{
    meta:
        description = "Detects Obsidium software protection"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        packer = "Obsidium"

    strings:
        $s1   = "Obsidium" ascii nocase
        $sec  = ".obs"     ascii
        $ep   = { E8 00 00 00 00 8B 1C 24 83 C3 }

    condition:
        $s1 or $sec or $ep
}
"#,
    // 10 — Enigma
    r#"rule Enigma_Protected
{
    meta:
        description = "Detects Enigma Protector via section names"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        packer = "Enigma"

    strings:
        $sec1 = ".enigma1" ascii
        $sec2 = ".enigma2" ascii
        $s1   = "EnigmaProtector" ascii nocase
        $s2   = "Enigma" ascii nocase

    condition:
        ($sec1 and $sec2) or $s1 or ($s2 and $sec1)
}
"#,
    // 11 — BoxedApp
    r#"rule BoxedApp_Packer
{
    meta:
        description = "Detects BoxedApp packer/virtualizer"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        packer = "BoxedApp"

    strings:
        $s1 = "BoxedApp"        ascii nocase
        $s2 = "bxpacker.dll"    ascii nocase
        $s3 = "BoxedAppPackerVersion" ascii

    condition:
        1 of them
}
"#,
    // 12 — ConfuserEx (.NET)
    r#"rule ConfuserEx_Dotnet
{
    meta:
        description = "Detects ConfuserEx obfuscated .NET assemblies"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        packer = "ConfuserEx"

    strings:
        $attr1 = "Confuser.Core.Mark"  ascii wide
        $attr2 = "ConfusedBy"          ascii wide
        $attr3 = "ConfuserEx"          ascii wide
        $mark  = { 43 6F 6E 66 75 73 65 72 45 78 }   /* ConfuserEx */

    condition:
        2 of ($attr1,$attr2,$attr3) or $mark
}
"#,
    // 13 — Generic VM stub
    r#"rule Generic_VM_Dispatcher
{
    meta:
        description = "Detects generic virtual machine dispatcher stubs (protector-agnostic)"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        packer = "GenericVM"

    strings:
        $d1 = { 8B 07 FF E0 }                      /* mov eax,[edi]; jmp eax */
        $d2 = { 8B 06 FF D0 }                      /* mov eax,[esi]; call eax */
        $d3 = { 0F B6 [1-4] FF E4 }               /* movzx ...; jmp esp */

    condition:
        2 of them
}
"#,
    // 14 — PEtite v2.x (alt detection)
    r#"rule Petite_v2x
{
    meta:
        description = "Detects Petite v2.x via specific header pattern"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        packer = "Petite"

    strings:
        $ep2 = { 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 50 }
        $s   = "Petite" ascii nocase

    condition:
        $ep2 at entrypoint or $s
}
"#,
    // 15 — ASProtect
    r#"rule ASProtect_Protected
{
    meta:
        description = "Detects ASProtect software protection"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        packer = "ASProtect"

    strings:
        $s1  = ".aspr"     ascii
        $s2  = "ASProtect" ascii nocase
        $ep  = { 68 01 ?? ?? ?? E8 }

    condition:
        $s1 or $s2 or $ep
}
"#,
];

// ─── Known Packer Strings ─────────────────────────────────────────────────────

#[must_use] 
pub fn known_packer_strings() -> HashMap<&'static str, PackerFamily> {
    let mut m = HashMap::new();
    m.insert("UPX0", PackerFamily::UPX);
    m.insert("UPX1", PackerFamily::UPX);
    m.insert(".themida", PackerFamily::Themida);
    m.insert(".winlicense", PackerFamily::Themida);
    m.insert(".vmp0", PackerFamily::VMProtect);
    m.insert(".vmp1", PackerFamily::VMProtect);
    m.insert(".aspack", PackerFamily::ASPack);
    m.insert(".aspr", PackerFamily::ASPack);
    m.insert("pec2", PackerFamily::PECompact);
    m.insert(".MPRESS1", PackerFamily::MPRESS);
    m.insert(".MPRESS2", PackerFamily::MPRESS);
    m.insert("nsp0", PackerFamily::NsPack);
    m.insert("nsp1", PackerFamily::NsPack);
    m.insert(".petite", PackerFamily::Petite);
    m.insert(".enigma1", PackerFamily::Enigma);
    m.insert(".enigma2", PackerFamily::Enigma);
    m.insert(".obs", PackerFamily::Obsidium);
    m
}

// ─── PackerRules Collection ───────────────────────────────────────────────────

pub struct PackerRules;

impl PackerRules {
    fn build_rules() -> Vec<PackerRule> {
        let descriptors: &[(PackerFamily, Option<&str>)] = &[
            (PackerFamily::UPX, Some("3.x")),
            (PackerFamily::Themida, Some("2.x")),
            (PackerFamily::VMProtect, Some("3.x")),
            (PackerFamily::ASPack, Some("2.x")),
            (PackerFamily::PECompact, None),
            (PackerFamily::MPRESS, None),
            (PackerFamily::NsPack, None),
            (PackerFamily::Petite, None),
            (PackerFamily::Obsidium, None),
            (PackerFamily::Enigma, None),
            (PackerFamily::BoxedApp, None),
            (PackerFamily::Confuser, None),
            (PackerFamily::Custom("GenericVM".to_string()), None),
            (PackerFamily::Petite, Some("2.x")),
            (PackerFamily::Custom("ASProtect".to_string()), None),
        ];

        PACKER_RULE_TEXTS
            .iter()
            .zip(descriptors.iter())
            .map(|(text, (family, ver))| {
                PackerRule::new(family.clone(), *text, ver.map(String::from))
            })
            .collect()
    }

    #[must_use] 
    pub fn all_rules() -> Vec<PackerRule> {
        Self::build_rules()
    }

    #[must_use] 
    pub fn rules_for_family(family: &PackerFamily) -> Vec<PackerRule> {
        Self::build_rules()
            .into_iter()
            .filter(|r| &r.family == family)
            .collect()
    }

    #[must_use] 
    pub fn detect_packer(data: &[u8]) -> Vec<(PackerFamily, f64)> {
        let mut results = Vec::new();
        let packer_strings = known_packer_strings();
        let data_str = String::from_utf8_lossy(data);

        for (marker, family) in &packer_strings {
            if data_str.contains(marker) {
                results.push((family.clone(), 0.9_f64));
            }
        }

        // UPX OEP stub: 60 E8 00 00 00 00 5B
        let upx_stub: &[u8] = &[0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B];
        if data.windows(upx_stub.len()).any(|w| w == upx_stub) {
            results.push((PackerFamily::UPX, 0.95));
        }

        // Deduplicate by family, keeping max score
        let mut map: HashMap<String, (PackerFamily, f64)> = HashMap::new();
        for (fam, score) in results {
            let key = fam.display_name().to_string();
            map.entry(key)
                .and_modify(|v| {
                    if score > v.1 {
                        v.1 = score;
                    }
                })
                .or_insert((fam, score));
        }
        map.into_values().collect()
    }

    #[must_use] 
    pub fn validate_all() -> Vec<String> {
        let mut errors = Vec::new();
        let mut seen: HashMap<String, usize> = HashMap::new();
        for (i, rule) in Self::build_rules().iter().enumerate() {
            for e in rule.validate_syntax() {
                errors.push(format!("Rule[{i}]: {e}"));
            }
            if let Some(name) = rule.rule_name()
                && let Some(prev) = seen.insert(name.to_string(), i) {
                    errors.push(format!("Duplicate name '{name}' at {prev} and {i}"));
                }
        }
        errors
    }

    #[must_use] 
    pub fn families_covered() -> Vec<PackerFamily> {
        let mut seen: Vec<PackerFamily> = Vec::new();
        for rule in Self::build_rules() {
            if !seen.contains(&rule.family) {
                seen.push(rule.family);
            }
        }
        seen
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_count_at_least_fifteen() {
        assert!(PackerRules::all_rules().len() >= 15);
    }

    #[test]
    fn test_all_rules_have_names() {
        for rule in PackerRules::all_rules() {
            assert!(rule.rule_name().is_some(), "Missing name in rule");
        }
    }

    #[test]
    fn test_all_rules_have_condition() {
        for rule in PackerRules::all_rules() {
            assert!(
                rule.rule_text.contains("condition:"),
                "Rule {:?} missing condition",
                rule.rule_name()
            );
        }
    }

    #[test]
    fn test_validate_no_errors() {
        let errors = PackerRules::validate_all();
        assert!(errors.is_empty(), "Errors: {errors:?}");
    }

    #[test]
    fn test_upx_rules_exist() {
        let rules = PackerRules::rules_for_family(&PackerFamily::UPX);
        assert!(!rules.is_empty());
    }

    #[test]
    fn test_themida_rules_exist() {
        let rules = PackerRules::rules_for_family(&PackerFamily::Themida);
        assert!(!rules.is_empty());
    }

    #[test]
    fn test_vmprotect_rules_exist() {
        let rules = PackerRules::rules_for_family(&PackerFamily::VMProtect);
        assert!(!rules.is_empty());
    }

    #[test]
    fn test_detect_packer_with_upx_sections() {
        let data = b"UPX0\x00UPX1\x00some data";
        let detections = PackerRules::detect_packer(data);
        assert!(detections.iter().any(|(f, _)| *f == PackerFamily::UPX));
    }

    #[test]
    fn test_detect_packer_empty_data_no_crash() {
        let detections = PackerRules::detect_packer(&[]);
        let _ = detections;
    }

    #[test]
    fn test_known_packer_strings_non_empty() {
        let map = known_packer_strings();
        assert!(!map.is_empty());
    }

    #[test]
    fn test_packer_family_is_protector() {
        assert!(PackerFamily::Themida.is_protector());
        assert!(!PackerFamily::UPX.is_protector());
    }

    #[test]
    fn test_packer_family_is_packer() {
        assert!(PackerFamily::UPX.is_packer());
        assert!(!PackerFamily::Themida.is_packer());
    }

    #[test]
    fn test_families_covered_non_empty() {
        let fams = PackerRules::families_covered();
        assert!(!fams.is_empty());
    }

    #[test]
    fn test_all_families_list() {
        let all = PackerFamily::all_families();
        assert!(all.len() >= 13);
    }

    #[test]
    fn test_detect_packer_themida() {
        let data = b".themida\x00some content here";
        let detections = PackerRules::detect_packer(data);
        assert!(detections.iter().any(|(f, _)| *f == PackerFamily::Themida));
    }

    #[test]
    fn test_detect_packer_vmprotect() {
        let data = b".vmp0\x00.vmp1\x00PE";
        let detections = PackerRules::detect_packer(data);
        assert!(detections
            .iter()
            .any(|(f, _)| *f == PackerFamily::VMProtect));
    }

    #[test]
    fn test_confuser_rules_exist() {
        let rules = PackerRules::rules_for_family(&PackerFamily::Confuser);
        assert!(!rules.is_empty());
    }

    #[test]
    fn test_rule_version_hints() {
        let rules = PackerRules::all_rules();
        let upx = rules.iter().find(|r| r.family == PackerFamily::UPX);
        assert!(upx.is_some());
        assert!(upx.unwrap().version_hint.is_some());
    }
}
