// rustre-yara-rules/src/ransomware_rules.rs
// YARA rule definitions for ransomware detection.

use std::collections::HashMap;

// ─── Metadata ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RuleMetadata {
    pub description: String,
    pub author: String,
    pub version: String,
    pub date: String,
    pub mitre_ttps: Vec<String>,
    pub severity: u8,
}

impl RuleMetadata {
    pub fn new(
        description: impl Into<String>,
        author: impl Into<String>,
        version: impl Into<String>,
        date: impl Into<String>,
        mitre_ttps: Vec<String>,
        severity: u8,
    ) -> Self {
        Self {
            description: description.into(),
            author: author.into(),
            version: version.into(),
            date: date.into(),
            mitre_ttps,
            severity: severity.min(10),
        }
    }

    #[must_use] 
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.description.is_empty() {
            errors.push("description is empty".to_string());
        }
        if self.author.is_empty() {
            errors.push("author is empty".to_string());
        }
        if self.severity > 10 {
            errors.push(format!("severity {} exceeds 10", self.severity));
        }
        if self.date.is_empty() {
            errors.push("date is empty".to_string());
        }
        errors
    }
}

// ─── Rule Text ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct YaraRuleText {
    pub text: String,
    pub metadata: RuleMetadata,
}

impl YaraRuleText {
    pub fn new(text: impl Into<String>, metadata: RuleMetadata) -> Self {
        Self {
            text: text.into(),
            metadata,
        }
    }

    #[must_use] 
    pub fn rule_name(&self) -> Option<&str> {
        let t = self.text.trim_start();
        t.strip_prefix("rule ").and_then(|s| s.split_whitespace().next())
    }

    #[must_use] 
    pub fn has_condition(&self) -> bool {
        self.text.contains("condition:")
    }

    #[must_use] 
    pub fn has_strings_section(&self) -> bool {
        self.text.contains("strings:")
    }

    #[must_use] 
    pub fn validate_syntax(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if !self.text.contains("rule ") {
            errors.push("missing 'rule' keyword".to_string());
        }
        if !self.text.contains('{') || !self.text.contains('}') {
            errors.push("missing braces".to_string());
        }
        if !self.has_condition() {
            errors.push("missing 'condition:' section".to_string());
        }
        let open = self.text.chars().filter(|&c| c == '{').count();
        let close = self.text.chars().filter(|&c| c == '}').count();
        if open != close {
            errors.push(format!("unbalanced braces: {open} open, {close} close"));
        }
        errors.extend(self.metadata.validate());
        errors
    }
}

// ─── Rule Set ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RuleSet {
    pub name: String,
    pub rules: Vec<YaraRuleText>,
}

impl RuleSet {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            rules: Vec::new(),
        }
    }

    pub fn add(&mut self, rule: YaraRuleText) {
        self.rules.push(rule);
    }

    #[must_use] 
    pub const fn len(&self) -> usize {
        self.rules.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    #[must_use] 
    pub fn by_severity_min(&self, min: u8) -> Vec<&YaraRuleText> {
        self.rules
            .iter()
            .filter(|r| r.metadata.severity >= min)
            .collect()
    }

    #[must_use] 
    pub fn rule_names(&self) -> Vec<&str> {
        self.rules.iter().filter_map(|r| r.rule_name()).collect()
    }

    #[must_use] 
    pub fn combined_text(&self) -> String {
        self.rules
            .iter()
            .map(|r| r.text.as_str())
            .collect::<Vec<_>>()
            .join("\n\n")
    }

    #[must_use] 
    pub fn filter_by_ttp(&self, ttp: &str) -> Vec<&YaraRuleText> {
        self.rules
            .iter()
            .filter(|r| r.metadata.mitre_ttps.iter().any(|t| t == ttp))
            .collect()
    }
}

// ─── Ransomware Rules ─────────────────────────────────────────────────────────

pub struct RansomwareRules;

pub static RANSOMWARE_RULE_TEXTS: &[&str] = &[
    // 1 — File encryption API pattern
    r#"rule FileEncryption_API_Pattern
{
    meta:
        description = "Detects sequential Win32 file API calls typical of ransomware encryption loops"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        mitre_attack = "T1486"
        severity = "9"

    strings:
        $find1   = "FindFirstFileW" ascii wide
        $find2   = "FindNextFileW"  ascii wide
        $create  = "CreateFileW"    ascii wide
        $read    = "ReadFile"       ascii wide
        $write   = "WriteFile"      ascii wide
        $close   = "CloseHandle"    ascii wide
        $encrypt = "CryptEncrypt"   ascii wide nocase

    condition:
        5 of ($find1,$find2,$create,$read,$write,$close,$encrypt)
}
"#,
    // 2 — Ransom note strings
    r#"rule RansomNote_Strings
{
    meta:
        description = "Detects common ransom-note keywords embedded in binaries"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        mitre_attack = "T1486"
        severity = "8"

    strings:
        $s1 = "your files" nocase ascii wide
        $s2 = "decrypt"    nocase ascii wide
        $s3 = "bitcoin"    nocase ascii wide
        $s4 = "wallet"     nocase ascii wide
        $s5 = "unique key" nocase ascii wide
        $s6 = "AES-256"    nocase ascii wide
        $s7 = "RSA-2048"   nocase ascii wide
        $s8 = "Tor browser" nocase ascii wide
        $s9 = "onion"      nocase ascii wide
        $s10 = "payment"   nocase ascii wide

    condition:
        4 of them
}
"#,
    // 3 — Shadow copy deletion
    r#"rule ShadowCopy_Deletion
{
    meta:
        description = "Detects shadow copy / backup deletion commands embedded in binaries"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        mitre_attack = "T1490"
        severity = "9"

    strings:
        $v1 = "vssadmin" nocase ascii wide
        $v2 = "delete shadows" nocase ascii wide
        $v3 = "wbadmin" nocase ascii wide
        $v4 = "delete catalog" nocase ascii wide
        $v5 = "wmic" nocase ascii wide
        $v6 = "shadowcopy" nocase ascii wide
        $v7 = "/all /quiet" nocase ascii wide
        $v8 = "bcdedit" nocase ascii wide
        $v9 = "recoveryenabled no" nocase ascii wide

    condition:
        (($v1 and $v2) or ($v3 and $v4) or ($v5 and $v6)) or
        ($v8 and $v9)
}
"#,
    // 4 — Extension append pattern
    r#"rule Extension_Append_Pattern
{
    meta:
        description = "Detects code patterns that rename files by appending a custom extension (ransomware marker)"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        mitre_attack = "T1486"
        severity = "8"

    strings:
        $rename  = "MoveFileExW"   ascii wide
        $concat  = "lstrcatW"      ascii wide
        $concat2 = "PathAddExtensionW" ascii wide
        $fmt     = { 25 73 2E 00 }   /* "%s." */
        $ext1    = ".locked"  nocase ascii wide
        $ext2    = ".crypt"   nocase ascii wide
        $ext3    = ".enc"     nocase ascii wide
        $ext4    = ".encrypted" nocase ascii wide

    condition:
        ($rename or $concat or $concat2) and (1 of ($ext1,$ext2,$ext3,$ext4,$fmt))
}
"#,
    // 5 — Wiper pattern
    r#"rule Wiper_Pattern
{
    meta:
        description = "Detects wiper-style code: zero/random fill then delete"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        mitre_attack = "T1561"
        severity = "10"

    strings:
        $zero  = { 33 C0 F3 AA }           /* xor eax,eax; rep stosb */
        $rand1 = "CryptGenRandom"   ascii wide
        $rand2 = "RtlGenRandom"     ascii wide
        $del   = "DeleteFileW"      ascii wide
        $del2  = "NtSetInformationFile" ascii wide

    condition:
        ($zero or $rand1 or $rand2) and ($del or $del2)
}
"#,
    // 6 — CryptoAPI pattern
    r#"rule CryptoAPI_Pattern
{
    meta:
        description = "Detects BCrypt/CryptoAPI imports for file encryption"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        mitre_attack = "T1486"
        severity = "7"

    strings:
        $b1 = "BCryptEncrypt"              ascii wide
        $b2 = "BCryptGenerateSymmetricKey" ascii wide
        $b3 = "BCryptOpenAlgorithmProvider" ascii wide
        $b4 = "CryptEncrypt"              ascii wide
        $b5 = "CryptDeriveKey"            ascii wide
        $b6 = "CryptAcquireContextW"      ascii wide

    condition:
        2 of ($b1,$b2,$b3) or 2 of ($b4,$b5,$b6)
}
"#,
    // 7 — Registry persistence + encrypted file drop
    r#"rule RegistryPersistence_Ransom
{
    meta:
        description = "Detects Run key write combined with encrypted file drop pattern"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        mitre_attack = "T1547.001"
        severity = "8"

    strings:
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $reg2 = "RegSetValueExW" ascii wide
        $reg3 = "RegCreateKeyExW" ascii wide
        $drop = "WriteFile" ascii wide
        $temp = "%TEMP%" ascii wide nocase
        $appdata = "AppData" ascii wide nocase

    condition:
        ($reg1 and ($reg2 or $reg3)) and $drop and ($temp or $appdata)
}
"#,
    // 8 — Network C2 for key retrieval
    r#"rule Ransomware_Network_C2
{
    meta:
        description = "Detects ransomware phoning home to retrieve encryption key"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        mitre_attack = "T1486"
        severity = "8"

    strings:
        $http1 = "HttpOpenRequestW" ascii wide
        $http2 = "InternetOpenW"    ascii wide
        $http3 = "WinHttpSendRequest" ascii wide
        $pub   = "public_key"  nocase ascii wide
        $uuid  = "victim_id"   nocase ascii wide
        $tor   = ".onion"      nocase ascii wide

    condition:
        (1 of ($http1,$http2,$http3)) and (1 of ($pub,$uuid,$tor))
}
"#,
    // 9 — Mutex / locker anti-double-run
    r#"rule Ransomware_Mutex
{
    meta:
        description = "Detects ransomware mutex patterns to prevent double execution"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        mitre_attack = "T1480"
        severity = "5"

    strings:
        $m1 = "CreateMutexW"   ascii wide
        $m2 = "OpenMutexW"     ascii wide
        $err = "ERROR_ALREADY_EXISTS" ascii wide
        $guid = { 7B 00 [4-8] 2D 00 [4-8] 2D 00 [4-8] 2D 00 [4-8] 2D 00 [4-8] 7D 00 }

    condition:
        ($m1 or $m2) and ($err or $guid)
}
"#,
    // 10 — Process / service termination before encryption
    r#"rule Ransomware_ProcessKill
{
    meta:
        description = "Detects ransomware killing DB/AV processes before encryption"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        mitre_attack = "T1489"
        severity = "7"

    strings:
        $kill1  = "TerminateProcess" ascii wide
        $kill2  = "taskkill"  nocase ascii wide
        $kill3  = "net stop"  nocase ascii wide
        $db1    = "sqlservr"  nocase ascii wide
        $db2    = "mysqld"    nocase ascii wide
        $av1    = "MsMpEng"   nocase ascii wide

    condition:
        (1 of ($kill1,$kill2,$kill3)) and (1 of ($db1,$db2,$av1))
}
"#,
    // 11 — Wallpaper change for ransom note display
    r#"rule Ransomware_WallpaperChange
{
    meta:
        description = "Detects wallpaper change used to display ransom note image"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        mitre_attack = "T1491"
        severity = "6"

    strings:
        $wp1  = "SystemParametersInfoW" ascii wide
        $wp2  = { 14 00 00 00 }   /* SPI_SETDESKWALLPAPER = 0x14 */
        $bmp  = ".bmp"  nocase ascii wide
        $png  = ".png"  nocase ascii wide
        $note = "README" nocase ascii wide

    condition:
        $wp1 and $wp2 and (1 of ($bmp,$png,$note))
}
"#,
    // 12 — Anti-analysis: sleep / timing
    r#"rule Ransomware_AntiAnalysis_Sleep
{
    meta:
        description = "Detects long Sleep() calls used to evade sandbox analysis"
        author = "RustRE"
        version = "1.0"
        date = "2024-01-01"
        mitre_attack = "T1497.003"
        severity = "5"

    strings:
        $sleep = "Sleep" ascii wide
        $long  = { 68 00 [1-3] 00 00 }   /* push dword >= 0x100 */
        $qpc   = "QueryPerformanceCounter" ascii wide
        $gst   = "GetSystemTime"  ascii wide

    condition:
        ($sleep and $long) or ($qpc and $gst)
}
"#,
];

impl RansomwareRules {
    #[must_use] 
    pub fn generate_ruleset() -> RuleSet {
        let mut rs = RuleSet::new("Ransomware Detection Rules");

        let meta_by_index: &[(&str, &str, u8, &[&str])] = &[
            (
                "FileEncryption_API_Pattern",
                "T1486",
                9,
                &["T1486"],
            ),
            ("RansomNote_Strings", "T1486", 8, &["T1486"]),
            ("ShadowCopy_Deletion", "T1490", 9, &["T1490"]),
            ("Extension_Append_Pattern", "T1486", 8, &["T1486"]),
            ("Wiper_Pattern", "T1561", 10, &["T1561"]),
            ("CryptoAPI_Pattern", "T1486", 7, &["T1486"]),
            (
                "RegistryPersistence_Ransom",
                "T1547.001",
                8,
                &["T1547.001"],
            ),
            ("Ransomware_Network_C2", "T1486", 8, &["T1486", "T1071"]),
            ("Ransomware_Mutex", "T1480", 5, &["T1480"]),
            ("Ransomware_ProcessKill", "T1489", 7, &["T1489"]),
            ("Ransomware_WallpaperChange", "T1491", 6, &["T1491"]),
            (
                "Ransomware_AntiAnalysis_Sleep",
                "T1497.003",
                5,
                &["T1497.003"],
            ),
        ];

        for (i, text) in RANSOMWARE_RULE_TEXTS.iter().enumerate() {
            let (desc, _ttp, sev, ttps) = meta_by_index.get(i).copied().unwrap_or((
                "Ransomware detection rule",
                "T1486",
                7,
                &["T1486"],
            ));
            let meta = RuleMetadata::new(
                desc,
                "RustRE",
                "1.0",
                "2024-01-01",
                ttps.iter().map(std::string::ToString::to_string).collect(),
                sev,
            );
            rs.add(YaraRuleText::new(*text, meta));
        }
        rs
    }

    #[must_use] 
    pub fn validate_all_rules() -> Vec<String> {
        let rs = Self::generate_ruleset();
        let mut errors = Vec::new();
        let mut seen_names: HashMap<String, usize> = HashMap::new();

        for (i, rule) in rs.rules.iter().enumerate() {
            let rule_errors = rule.validate_syntax();
            for e in rule_errors {
                errors.push(format!("Rule[{i}]: {e}"));
            }
            if let Some(name) = rule.rule_name() {
                if let Some(prev) = seen_names.insert(name.to_string(), i) {
                    errors.push(format!(
                        "Duplicate rule name '{name}' at indices {prev} and {i}"
                    ));
                }
            } else {
                errors.push(format!("Rule[{i}]: cannot parse rule name"));
            }
        }
        errors
    }

    #[must_use] 
    pub fn rules_by_ttp(ttp: &str) -> Vec<String> {
        let rs = Self::generate_ruleset();
        rs.filter_by_ttp(ttp)
            .iter()
            .filter_map(|r| r.rule_name().map(String::from))
            .collect()
    }

    #[must_use] 
    pub fn rules_by_severity_min(min: u8) -> Vec<String> {
        let rs = Self::generate_ruleset();
        rs.by_severity_min(min)
            .iter()
            .filter_map(|r| r.rule_name().map(String::from))
            .collect()
    }

    #[must_use] 
    pub fn rule_count() -> usize {
        RANSOMWARE_RULE_TEXTS.len()
    }

    #[must_use] 
    pub fn combined_yara_source() -> String {
        let rs = Self::generate_ruleset();
        rs.combined_text()
    }

    #[must_use] 
    pub fn rule_by_name(name: &str) -> Option<String> {
        let rs = Self::generate_ruleset();
        rs.rules
            .iter()
            .find(|r| r.rule_name() == Some(name))
            .map(|r| r.text.clone())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ruleset_not_empty() {
        let rs = RansomwareRules::generate_ruleset();
        assert!(!rs.is_empty());
        assert!(rs.len() >= 10);
    }

    #[test]
    fn test_all_rules_have_names() {
        let rs = RansomwareRules::generate_ruleset();
        for rule in &rs.rules {
            assert!(
                rule.rule_name().is_some(),
                "Rule missing name: {}",
                &rule.text[..50.min(rule.text.len())]
            );
        }
    }

    #[test]
    fn test_all_rules_have_condition() {
        let rs = RansomwareRules::generate_ruleset();
        for rule in &rs.rules {
            assert!(
                rule.has_condition(),
                "Rule {:?} missing condition",
                rule.rule_name()
            );
        }
    }

    #[test]
    fn test_validate_all_no_errors() {
        let errors = RansomwareRules::validate_all_rules();
        assert!(
            errors.is_empty(),
            "Validation errors: {errors:?}"
        );
    }

    #[test]
    fn test_rule_count_matches_static() {
        assert_eq!(
            RansomwareRules::rule_count(),
            RANSOMWARE_RULE_TEXTS.len()
        );
    }

    #[test]
    fn test_rules_by_ttp_t1486() {
        let names = RansomwareRules::rules_by_ttp("T1486");
        assert!(!names.is_empty(), "Expected T1486 rules");
    }

    #[test]
    fn test_rules_by_ttp_t1490() {
        let names = RansomwareRules::rules_by_ttp("T1490");
        assert!(!names.is_empty());
    }

    #[test]
    fn test_rules_by_severity_min_nine() {
        let names = RansomwareRules::rules_by_severity_min(9);
        assert!(!names.is_empty());
        let rs = RansomwareRules::generate_ruleset();
        for n in &names {
            let rule = rs.rules.iter().find(|r| r.rule_name() == Some(n.as_str()));
            assert!(rule.is_some());
            assert!(rule.unwrap().metadata.severity >= 9);
        }
    }

    #[test]
    fn test_combined_yara_source_non_empty() {
        let src = RansomwareRules::combined_yara_source();
        assert!(src.len() > 100);
    }

    #[test]
    fn test_rule_by_name_found() {
        let text = RansomwareRules::rule_by_name("FileEncryption_API_Pattern");
        assert!(text.is_some());
        assert!(text.unwrap().contains("FileEncryption_API_Pattern"));
    }

    #[test]
    fn test_rule_by_name_not_found() {
        let text = RansomwareRules::rule_by_name("NonExistentRule_XYZ");
        assert!(text.is_none());
    }

    #[test]
    fn test_ruleset_name() {
        let rs = RansomwareRules::generate_ruleset();
        assert_eq!(rs.name, "Ransomware Detection Rules");
    }

    #[test]
    fn test_metadata_severity_clamped() {
        let m = RuleMetadata::new("desc", "author", "1.0", "2024-01-01", vec![], 255);
        assert_eq!(m.severity, 10);
    }

    #[test]
    fn test_metadata_validate_empty_description() {
        let m = RuleMetadata::new("", "author", "1.0", "2024-01-01", vec![], 5);
        let errs = m.validate();
        assert!(errs.iter().any(|e| e.contains("description")));
    }

    #[test]
    fn test_ruleset_filter_by_ttp_empty() {
        let rs = RansomwareRules::generate_ruleset();
        let filtered = rs.filter_by_ttp("T9999");
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_rule_text_has_strings_section() {
        let rs = RansomwareRules::generate_ruleset();
        let ransomware_note = rs
            .rules
            .iter()
            .find(|r| r.rule_name() == Some("RansomNote_Strings"));
        assert!(ransomware_note.is_some());
        assert!(ransomware_note.unwrap().has_strings_section());
    }

    #[test]
    fn test_no_duplicate_rule_names() {
        let rs = RansomwareRules::generate_ruleset();
        let mut names: Vec<&str> = rs.rules.iter().filter_map(|r| r.rule_name()).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(before, names.len(), "Duplicate rule names detected");
    }

    #[test]
    fn test_rule_names_list() {
        let rs = RansomwareRules::generate_ruleset();
        let names = rs.rule_names();
        assert!(names.contains(&"FileEncryption_API_Pattern"));
        assert!(names.contains(&"ShadowCopy_Deletion"));
        assert!(names.contains(&"Wiper_Pattern"));
    }

    #[test]
    fn test_wiper_rule_severity_ten() {
        let rs = RansomwareRules::generate_ruleset();
        let wiper = rs
            .rules
            .iter()
            .find(|r| r.rule_name() == Some("Wiper_Pattern"));
        assert!(wiper.is_some());
        assert_eq!(wiper.unwrap().metadata.severity, 10);
    }
}
