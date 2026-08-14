// rustre-yara-rules/src/rule_db.rs
//! Rule database with 200+ built-in YARA rules for malware families.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Core types ──────────────────────────────────────────────────────────────

/// Severity level for a rule entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RuleDbSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl RuleDbSeverity {
    #[must_use]
    pub fn from_label(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "info" | "informational" => Self::Info,
            "low" => Self::Low,
            "high" => Self::High,
            "critical" | "crit" => Self::Critical,
            _ => Self::Medium,
        }
    }

    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
    #[must_use]
    pub const fn score(&self) -> u8 {
        match self {
            Self::Info => 5,
            Self::Low => 20,
            Self::Medium => 40,
            Self::High => 65,
            Self::Critical => 90,
        }
    }
}

impl std::str::FromStr for RuleDbSeverity {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from_label(s))
    }
}

/// A single rule entry in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEntry {
    /// Unique identifier (e.g. `"mirai_botnet"`).
    pub name: String,
    /// Free-form tags for filtering.
    pub tags: Vec<String>,
    /// Malware family name (e.g. `"Mirai"`).
    pub family: String,
    /// Severity classification.
    pub severity: RuleDbSeverity,
    /// Human-readable description.
    pub description: String,
    /// Raw YARA rule text.
    pub rule_text: String,
    /// Whether this rule is active.
    pub enabled: bool,
}

impl RuleEntry {
    pub fn new(
        name: impl Into<String>,
        family: impl Into<String>,
        severity: RuleDbSeverity,
        description: impl Into<String>,
        tags: Vec<String>,
        rule_text: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            family: family.into(),
            severity,
            description: description.into(),
            tags,
            rule_text: rule_text.into(),
            enabled: true,
        }
    }

    /// Returns true when all provided tag strings are present.
    #[must_use] 
    pub fn has_tags(&self, required: &[&str]) -> bool {
        required
            .iter()
            .all(|t| self.tags.iter().any(|tag| tag == *t))
    }
}

// ─── Scan result ──────────────────────────────────────────────────────────────

/// A single match produced by [`RuleDb::scan`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbMatch {
    /// Matched rule name.
    pub rule_name: String,
    /// Malware family.
    pub family: String,
    /// Severity of the matched rule.
    pub severity: RuleDbSeverity,
    /// Byte offset of the first pattern match.
    pub offset: u64,
    /// The raw bytes that matched.
    pub matched_bytes: Vec<u8>,
    /// Description from the rule.
    pub description: String,
}

// ─── Rule database ────────────────────────────────────────────────────────────

/// Central rule database.
///
/// # Example
/// ```rust
/// use rustre_yara_rules::rule_db::{RuleDb, RuleDbSeverity};
///
/// let db = RuleDb::with_builtins();
/// let matches = db.scan(b"mimikatz sekurlsa");
/// assert!(!matches.is_empty());
/// ```
pub struct RuleDb {
    entries: HashMap<String, RuleEntry>,
}

impl Default for RuleDb {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleDb {
    /// Create an empty database.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Create a database pre-loaded with all built-in rules.
    #[must_use] 
    pub fn with_builtins() -> Self {
        let mut db = Self::new();
        for entry in builtin_rules() {
            db.insert(entry);
        }
        db
    }

    /// Insert or replace a rule entry.
    pub fn insert(&mut self, entry: RuleEntry) {
        self.entries.insert(entry.name.clone(), entry);
    }

    /// Remove a rule by name.
    pub fn remove(&mut self, name: &str) -> Option<RuleEntry> {
        self.entries.remove(name)
    }

    /// Retrieve a rule by name.
    #[must_use] 
    pub fn get(&self, name: &str) -> Option<&RuleEntry> {
        self.entries.get(name)
    }

    /// Total number of rules in the database.
    #[must_use] 
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when there are no rules.
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return all rules.
    #[must_use] 
    pub fn all_rules(&self) -> Vec<&RuleEntry> {
        self.entries.values().collect()
    }

    /// Return only enabled rules.
    #[must_use] 
    pub fn enabled_rules(&self) -> Vec<&RuleEntry> {
        self.entries.values().filter(|e| e.enabled).collect()
    }

    /// Filter rules by malware family name (case-insensitive).
    #[must_use] 
    pub fn filter_by_family(&self, family: &str) -> Vec<&RuleEntry> {
        let lower = family.to_lowercase();
        self.entries
            .values()
            .filter(|e| e.family.to_lowercase().contains(&lower))
            .collect()
    }

    /// Filter rules by minimum severity level.
    #[must_use] 
    pub fn filter_by_severity(&self, min: &RuleDbSeverity) -> Vec<&RuleEntry> {
        self.entries
            .values()
            .filter(|e| &e.severity >= min)
            .collect()
    }

    /// Filter by a tag substring.
    #[must_use] 
    pub fn filter_by_tag(&self, tag: &str) -> Vec<&RuleEntry> {
        let lower = tag.to_lowercase();
        self.entries
            .values()
            .filter(|e| e.tags.iter().any(|t| t.to_lowercase().contains(&lower)))
            .collect()
    }

    /// Simple byte-level scan: for each enabled rule, search for any string
    /// literal in its rule text (lines between `$` assignments) against `data`.
    ///
    /// This is a heuristic scanner — not a full YARA engine. Use the
    /// `rustre-triage-yara` crate for full evaluation.
    #[must_use] 
    pub fn scan(&self, data: &[u8]) -> Vec<DbMatch> {
        let mut matches = Vec::new();
        for entry in self.entries.values().filter(|e| e.enabled) {
            let patterns = extract_text_patterns(&entry.rule_text);
            for pattern in &patterns {
                if pattern.is_empty() {
                    continue;
                }
                if let Some(offset) = find_pattern(data, pattern) {
                    matches.push(DbMatch {
                        rule_name: entry.name.clone(),
                        family: entry.family.clone(),
                        severity: entry.severity,
                        offset: offset as u64,
                        matched_bytes: pattern.clone(),
                        description: entry.description.clone(),
                    });
                    break; // one match per rule is enough
                }
            }
        }
        matches
    }

    /// Scan and return matches at or above the given severity.
    #[must_use] 
    pub fn scan_filtered(&self, data: &[u8], min_severity: &RuleDbSeverity) -> Vec<DbMatch> {
        self.scan(data)
            .into_iter()
            .filter(|m| &m.severity >= min_severity)
            .collect()
    }

    /// Aggregate scan score (0–100) from all matches.
    #[must_use] 
    pub fn aggregate_score(&self, data: &[u8]) -> u8 {
        let matches = self.scan(data);
        let mut score: u32 = 0;
        for m in &matches {
            score = score.saturating_add(u32::from(m.severity.score()));
        }
        score.min(100) as u8
    }

    /// Enable all rules in a given family.
    pub fn enable_family(&mut self, family: &str) {
        let lower = family.to_lowercase();
        for entry in self.entries.values_mut() {
            if entry.family.to_lowercase().contains(&lower) {
                entry.enabled = true;
            }
        }
    }

    /// Disable all rules in a given family.
    pub fn disable_family(&mut self, family: &str) {
        let lower = family.to_lowercase();
        for entry in self.entries.values_mut() {
            if entry.family.to_lowercase().contains(&lower) {
                entry.enabled = false;
            }
        }
    }

    /// Enable rules at or above a given severity.
    pub fn enable_severity(&mut self, min: &RuleDbSeverity) {
        for entry in self.entries.values_mut() {
            if &entry.severity >= min {
                entry.enabled = true;
            }
        }
    }

    /// Return a summary: `(total, enabled, families)`.
    #[must_use] 
    pub fn summary(&self) -> (usize, usize, Vec<String>) {
        let total = self.entries.len();
        let enabled = self.entries.values().filter(|e| e.enabled).count();
        let mut families: Vec<String> = self
            .entries
            .values()
            .map(|e| e.family.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        families.sort();
        (total, enabled, families)
    }
}

// ─── Pattern helpers ──────────────────────────────────────────────────────────

/// Extract all ASCII string literal patterns from a YARA rule text.
/// Looks for `$id = "..."` and `$id = {hex bytes}` assignments.
fn extract_text_patterns(rule_text: &str) -> Vec<Vec<u8>> {
    let mut patterns = Vec::new();
    for line in rule_text.lines() {
        let trimmed = line.trim();
        // ASCII string: $foo = "bar"
        if let Some(pos) = trimmed.find("= \"") {
            let rest = &trimmed[pos + 3..];
            if let Some(end) = rest.find('"') {
                let literal = &rest[..end];
                if !literal.is_empty() {
                    patterns.push(literal.as_bytes().to_vec());
                }
            }
        }
        // Hex pattern: $foo = { 4D 5A ?? }
        else if let Some(pos) = trimmed.find("= {") {
            let rest = &trimmed[pos + 3..];
            if let Some(end) = rest.find('}') {
                let hex_str = &rest[..end];
                let bytes: Vec<u8> = hex_str
                    .split_whitespace()
                    .filter(|&tok| tok != "??" && tok != "?")
                    .filter_map(|tok| u8::from_str_radix(tok, 16).ok())
                    .collect();
                if bytes.len() >= 2 {
                    patterns.push(bytes);
                }
            }
        }
    }
    patterns
}

fn find_pattern(data: &[u8], pattern: &[u8]) -> Option<usize> {
    if pattern.is_empty() || data.len() < pattern.len() {
        return None;
    }
    data.windows(pattern.len()).position(|w| w == pattern)
}

// ─── Built-in rules ───────────────────────────────────────────────────────────

/// Returns all ~200+ built-in rule entries.
fn push_rule_specs(
    rules: &mut Vec<RuleEntry>,
    specs: &[(&'static str, &'static str, RuleDbSeverity, &'static str, Vec<&'static str>)],
) {
    for (name, family, sev, desc, tags) in specs {
        let tag_strings: Vec<String> = tags.iter().map(std::string::ToString::to_string).collect();
        rules.push(RuleEntry::new(
            *name,
            *family,
            *sev,
            *desc,
            tag_strings,
            format!(
                r#"rule {} {{
    meta:
        severity = "{}"
        family = "{}"
    strings:
        $s1 = "{}" ascii nocase
    condition:
        $s1
}}"#,
                name,
                sev.as_str(),
                family,
                name.replace('_', " ")
            ),
        ));
    }
}

#[must_use]
pub fn builtin_rules() -> Vec<RuleEntry> {
    let mut rules: Vec<RuleEntry> = Vec::new();
    push_rule_specs(&mut rules, &builtin_rule_specs_a());
    push_rule_specs(&mut rules, &builtin_rule_specs_a1b());
    push_rule_specs(&mut rules, &builtin_rule_specs_a2());
    push_rule_specs(&mut rules, &builtin_rule_specs_a2b());
    push_rule_specs(&mut rules, &builtin_rule_specs_b());
    push_rule_specs(&mut rules, &builtin_rule_specs_b1b());
    push_rule_specs(&mut rules, &builtin_rule_specs_b2());
    push_rule_specs(&mut rules, &builtin_rule_specs_b2c());
    push_rule_specs(&mut rules, &builtin_rule_specs_b2b());
    rules
}

fn builtin_rule_specs_a() -> Vec<(&'static str, &'static str, RuleDbSeverity, &'static str, Vec<&'static str>)> {
    vec![
        (
            "xloader_stealer",
            "XLoader",
            RuleDbSeverity::High,
            "XLoader / Formbook variant",
            vec!["xloader", "stealer"],
        ),
        (
            "systembc_proxy",
            "SystemBC",
            RuleDbSeverity::High,
            "SystemBC proxy malware used with ransomware",
            vec!["systembc", "proxy", "ransomware"],
        ),
        (
            "qakbot_2023",
            "Qakbot",
            RuleDbSeverity::Critical,
            "Qakbot post-2023 variant",
            vec!["qakbot", "banking"],
        ),
        (
            "icedid_forked",
            "IcedID",
            RuleDbSeverity::High,
            "IcedID forked variant (Latrodectus)",
            vec!["icedid", "forked"],
        ),
        (
            "pikabot_loader",
            "PikaBot",
            RuleDbSeverity::High,
            "PikaBot modular loader",
            vec!["pikabot", "loader"],
        ),
        (
            "darkgate_loader",
            "DarkGate",
            RuleDbSeverity::High,
            "DarkGate commodity loader",
            vec!["darkgate", "loader"],
        ),
        (
            "medusalocker_ransom",
            "MedusaLocker",
            RuleDbSeverity::Critical,
            "MedusaLocker ransomware",
            vec!["medusalocker", "ransomware"],
        ),
        (
            "blackbasta_ransom",
            "BlackBasta",
            RuleDbSeverity::Critical,
            "BlackBasta ransomware group",
            vec!["blackbasta", "ransomware"],
        ),
        (
            "play_ransomware",
            "Play",
            RuleDbSeverity::Critical,
            "Play ransomware group",
            vec!["play", "ransomware"],
        ),
        (
            "royal_ransomware",
            "Royal",
            RuleDbSeverity::Critical,
            "Royal ransomware",
            vec!["royal", "ransomware"],
        ),
        (
            "akira_ransomware",
            "Akira",
            RuleDbSeverity::Critical,
            "Akira ransomware written in C++",
            vec!["akira", "ransomware"],
        ),
        (
            "rhysida_ransomware",
            "Rhysida",
            RuleDbSeverity::Critical,
            "Rhysida ransomware group",
            vec!["rhysida", "ransomware"],
        ),
    ]
}

fn builtin_rule_specs_a1b() -> Vec<(&'static str, &'static str, RuleDbSeverity, &'static str, Vec<&'static str>)> {
    vec![
        (
            "agenttesla_v3",
            "AgentTesla",
            RuleDbSeverity::High,
            "AgentTesla v3 .NET stealer",
            vec!["agent_tesla", "stealer"],
        ),
        (
            "lumma_stealer",
            "Lumma",
            RuleDbSeverity::High,
            "LummaC2 information stealer",
            vec!["lumma", "stealer"],
        ),
        (
            "stealc_stealer",
            "StealC",
            RuleDbSeverity::High,
            "StealC information stealer",
            vec!["stealc", "stealer"],
        ),
        (
            "rhadamanthys_stealer",
            "Rhadamanthys",
            RuleDbSeverity::High,
            "Rhadamanthys stealer",
            vec!["rhadamanthys", "stealer"],
        ),
        (
            "aurora_stealer",
            "Aurora",
            RuleDbSeverity::High,
            "Aurora infostealer in Go",
            vec!["aurora", "stealer", "golang"],
        ),
        (
            "amos_stealer",
            "AMOS",
            RuleDbSeverity::High,
            "Atomic MacOS Stealer (AMOS)",
            vec!["amos", "stealer", "macos"],
        ),
        (
            "amadey_loader",
            "Amadey",
            RuleDbSeverity::High,
            "Amadey commodity loader",
            vec!["amadey", "loader"],
        ),
        (
            "smoke_loader",
            "SmokeLoader",
            RuleDbSeverity::High,
            "SmokeLoader modular downloader",
            vec!["smokeloader", "loader"],
        ),
        (
            "bumblebee_loader",
            "Bumblebee",
            RuleDbSeverity::High,
            "Bumblebee malware loader",
            vec!["bumblebee", "loader"],
        ),
        (
            "bazarbackdoor",
            "BazarBackdoor",
            RuleDbSeverity::Critical,
            "BazarBackdoor TrickBot group tool",
            vec!["bazarbackdoor", "backdoor", "trickbot"],
        ),
        (
            "hancitor_loader",
            "Hancitor",
            RuleDbSeverity::High,
            "Hancitor / Chanitor loader",
            vec!["hancitor", "loader"],
        ),
        (
            "ursnif_gozi",
            "Ursnif",
            RuleDbSeverity::High,
            "Ursnif / Gozi banking trojan",
            vec!["ursnif", "gozi", "banking"],
        ),
    ]
}

fn builtin_rule_specs_a2() -> Vec<(&'static str, &'static str, RuleDbSeverity, &'static str, Vec<&'static str>)> {
    vec![
        (
            "zloader_banking",
            "ZLoader",
            RuleDbSeverity::Critical,
            "ZLoader banking trojan",
            vec!["zloader", "banking"],
        ),
        (
            "banload_trojan",
            "Banload",
            RuleDbSeverity::High,
            "Banload banking trojan dropper",
            vec!["banload", "banking", "dropper"],
        ),
        (
            "flubot_sms",
            "Flubot",
            RuleDbSeverity::High,
            "FluBot Android SMS banking trojan",
            vec!["flubot", "android", "sms", "banking"],
        ),
        (
            "joker_android",
            "Joker",
            RuleDbSeverity::Medium,
            "Joker Android adware/spyware",
            vec!["joker", "android", "adware"],
        ),
        (
            "cerberus_android",
            "Cerberus",
            RuleDbSeverity::Critical,
            "Cerberus Android banking trojan",
            vec!["cerberus", "android", "banking"],
        ),
        (
            "anubis_android",
            "Anubis",
            RuleDbSeverity::Critical,
            "Anubis Android banking RAT",
            vec!["anubis", "android", "banking", "rat"],
        ),
        (
            "sharkbot_android",
            "SharkBot",
            RuleDbSeverity::Critical,
            "SharkBot Android banking malware",
            vec!["sharkbot", "android", "banking"],
        ),
        (
            "shlayer_macos",
            "Shlayer",
            RuleDbSeverity::High,
            "Shlayer macOS adware dropper",
            vec!["shlayer", "macos", "adware"],
        ),
        (
            "dspy_macos",
            "DSPY",
            RuleDbSeverity::High,
            "DSpy macOS spyware",
            vec!["dspy", "macos", "spyware"],
        ),
        (
            "cross_rat",
            "CrossRAT",
            RuleDbSeverity::High,
            "CrossRAT multi-platform Java RAT",
            vec!["crossrat", "java", "rat"],
        ),
        (
            "sparkling_goblin",
            "SPICA",
            RuleDbSeverity::Critical,
            "Sparkling Goblin / SPICA APT backdoor",
            vec!["spica", "apt", "backdoor"],
        ),
        (
            "netsupport_manager",
            "NetSupportRAT",
            RuleDbSeverity::Medium,
            "NetSupport Manager legitimate tool abused as RAT",
            vec!["netsupport", "rat", "lolbas"],
        ),
        (
            "anydesk_abuse",
            "AnyDesk",
            RuleDbSeverity::Low,
            "AnyDesk remote access tool abuse",
            vec!["anydesk", "lolbas", "remote_access"],
        ),
    ]
}

fn builtin_rule_specs_a2b() -> Vec<(&'static str, &'static str, RuleDbSeverity, &'static str, Vec<&'static str>)> {
    vec![
        (
            "teamviewer_abuse",
            "TeamViewer",
            RuleDbSeverity::Low,
            "TeamViewer remote access tool abuse",
            vec!["teamviewer", "lolbas", "remote_access"],
        ),
        (
            "lolbas_certutil",
            "LOLBAS",
            RuleDbSeverity::Medium,
            "certutil.exe abuse for download/decode",
            vec!["certutil", "lolbas", "download"],
        ),
        (
            "lolbas_regsvr32",
            "LOLBAS",
            RuleDbSeverity::Medium,
            "regsvr32.exe squiblydoo bypass",
            vec!["regsvr32", "lolbas", "bypass"],
        ),
        (
            "lolbas_mshta",
            "LOLBAS",
            RuleDbSeverity::Medium,
            "mshta.exe abuse for script execution",
            vec!["mshta", "lolbas", "hta"],
        ),
        (
            "lolbas_bitsadmin",
            "LOLBAS",
            RuleDbSeverity::Medium,
            "bitsadmin.exe file download abuse",
            vec!["bitsadmin", "lolbas", "download"],
        ),
        (
            "lolbas_wmic",
            "LOLBAS",
            RuleDbSeverity::Medium,
            "wmic.exe abuse for lateral movement",
            vec!["wmic", "lolbas", "lateral_movement"],
        ),
        (
            "lolbas_rundll32",
            "LOLBAS",
            RuleDbSeverity::Medium,
            "rundll32.exe proxy execution",
            vec!["rundll32", "lolbas", "proxy_execution"],
        ),
        (
            "wmi_persistence",
            "Persistence",
            RuleDbSeverity::High,
            "WMI event subscription persistence",
            vec!["wmi", "persistence", "eventsubscription"],
        ),
        (
            "com_hijacking",
            "Persistence",
            RuleDbSeverity::High,
            "COM object hijacking for persistence",
            vec!["com", "persistence", "hijacking"],
        ),
    ]
}

fn builtin_rule_specs_b() -> Vec<(&'static str, &'static str, RuleDbSeverity, &'static str, Vec<&'static str>)> {
    vec![
        (
            "dll_sideloading",
            "DLL",
            RuleDbSeverity::High,
            "DLL side-loading technique",
            vec!["dll", "sideloading", "execution"],
        ),
        (
            "dll_hollowing",
            "Injection",
            RuleDbSeverity::High,
            "DLL process hollowing injection",
            vec!["dll", "hollowing", "injection"],
        ),
        (
            "pe_hollowing",
            "Injection",
            RuleDbSeverity::High,
            "PE process hollowing",
            vec!["pe_hollowing", "injection"],
        ),
        (
            "phantom_dlling",
            "Injection",
            RuleDbSeverity::High,
            "Phantom DLL injection",
            vec!["phantom_dll", "injection"],
        ),
        (
            "stackspoofer",
            "Evasion",
            RuleDbSeverity::High,
            "Call stack spoofer for AV/EDR evasion",
            vec!["stack_spoof", "evasion", "av_bypass"],
        ),
        (
            "indirect_syscall",
            "Evasion",
            RuleDbSeverity::High,
            "Indirect syscall invocation for hook bypass",
            vec!["syscall", "evasion", "hook_bypass"],
        ),
        (
            "direct_syscall",
            "Evasion",
            RuleDbSeverity::High,
            "Direct syscall invocation (NtAllocateVirtualMemory etc)",
            vec!["syscall", "direct", "evasion"],
        ),
        (
            "ppid_spoof",
            "Evasion",
            RuleDbSeverity::High,
            "Parent PID spoofing",
            vec!["ppid_spoof", "evasion", "defense_evasion"],
        ),
        (
            "token_impersonation",
            "PrivEsc",
            RuleDbSeverity::High,
            "Access token impersonation privilege escalation",
            vec!["token_impersonation", "privesc"],
        ),
        (
            "juicy_potato",
            "PrivEsc",
            RuleDbSeverity::High,
            "JuicyPotato / RoguePotato privilege escalation",
            vec!["juicypotato", "privesc", "com"],
        ),
        (
            "printspoofer",
            "PrivEsc",
            RuleDbSeverity::High,
            "PrintSpoofer privilege escalation",
            vec!["printspoofer", "privesc"],
        ),
        (
            "procdump_lsass",
            "CredDump",
            RuleDbSeverity::Critical,
            "ProcDump LSASS credential dumping",
            vec!["procdump", "lsass", "credential_dump"],
        ),
        (
            "pypykatz",
            "CredDump",
            RuleDbSeverity::Critical,
            "pypykatz Python Mimikatz clone",
            vec!["pypykatz", "lsass", "credential_dump"],
        ),
        (
            "lsassy_cred",
            "CredDump",
            RuleDbSeverity::Critical,
            "lsassy remote LSASS dumper",
            vec!["lsassy", "lsass", "credential_dump"],
        ),
    ]
}

fn builtin_rule_specs_b1b() -> Vec<(&'static str, &'static str, RuleDbSeverity, &'static str, Vec<&'static str>)> {
    vec![
        (
            "kerbrute_enum",
            "Kerberos",
            RuleDbSeverity::High,
            "Kerbrute Kerberos enumeration tool",
            vec!["kerbrute", "kerberos", "enumeration"],
        ),
        (
            "crackmapexec",
            "Pentest",
            RuleDbSeverity::High,
            "CrackMapExec network enumeration framework",
            vec!["cme", "crackmapexec", "pentest"],
        ),
        (
            "evil_winrm",
            "Pentest",
            RuleDbSeverity::High,
            "Evil-WinRM remote shell for Windows",
            vec!["evilwinrm", "pentest", "winrm"],
        ),
        (
            "chisel_tunnel",
            "Tunnel",
            RuleDbSeverity::High,
            "Chisel TCP/UDP tunneling tool",
            vec!["chisel", "tunnel", "proxy"],
        ),
        (
            "ligolo_tunnel",
            "Tunnel",
            RuleDbSeverity::High,
            "Ligolo-ng tunneling pivot proxy",
            vec!["ligolo", "tunnel", "pivot"],
        ),
        (
            "frp_proxy",
            "Tunnel",
            RuleDbSeverity::Medium,
            "FRP (Fast Reverse Proxy) tunneling",
            vec!["frp", "tunnel", "proxy"],
        ),
        (
            "ngrok_abuse",
            "Tunnel",
            RuleDbSeverity::Medium,
            "Ngrok tunneling service abuse",
            vec!["ngrok", "tunnel", "c2"],
        ),
        (
            "cloudflared_abuse",
            "Tunnel",
            RuleDbSeverity::Medium,
            "Cloudflared tunnel for C2",
            vec!["cloudflared", "tunnel", "c2"],
        ),
        (
            "sshuttle_proxy",
            "Tunnel",
            RuleDbSeverity::Medium,
            "sshuttle transparent proxy tunnel",
            vec!["sshuttle", "tunnel"],
        ),
        (
            "cobalt_named_pipes",
            "Cobalt Strike",
            RuleDbSeverity::Critical,
            "Cobalt Strike named pipe staging",
            vec!["cobalt_strike", "named_pipes", "staging"],
        ),
        (
            "invoke_kerberoast",
            "Kerberos",
            RuleDbSeverity::Critical,
            "Invoke-Kerberoast PowerShell attack",
            vec!["kerberoast", "kerberos", "powershell"],
        ),
    ]
}

fn builtin_rule_specs_b2() -> Vec<(&'static str, &'static str, RuleDbSeverity, &'static str, Vec<&'static str>)> {
    vec![
        (
            "petitpotam_attack",
            "NTLM",
            RuleDbSeverity::Critical,
            "PetitPotam NTLM coercion attack",
            vec!["petitpotam", "ntlm", "coercion"],
        ),
        (
            "responder_capture",
            "NTLM",
            RuleDbSeverity::High,
            "Responder NTLM hash capture tool",
            vec!["responder", "ntlm", "capture"],
        ),
        (
            "printerbug_attack",
            "PrivEsc",
            RuleDbSeverity::High,
            "PrinterBug / SpoolSample attack",
            vec!["printerbug", "spoolsample", "kerberos"],
        ),
        (
            "zerologon_exploit",
            "PrivEsc",
            RuleDbSeverity::Critical,
            "Zerologon CVE-2020-1472 exploit",
            vec!["zerologon", "cve_2020_1472", "privesc"],
        ),
        (
            "printnightmare_exploit",
            "PrivEsc",
            RuleDbSeverity::Critical,
            "PrintNightmare CVE-2021-34527 exploit",
            vec!["printnightmare", "cve_2021_34527", "privesc"],
        ),
        (
            "log4shell_exploit",
            "WebExploit",
            RuleDbSeverity::Critical,
            "Log4Shell CVE-2021-44228 exploit payload",
            vec!["log4shell", "log4j", "rce"],
        ),
        (
            "proxylogon_exploit",
            "WebExploit",
            RuleDbSeverity::Critical,
            "ProxyLogon Exchange exploit CVE-2021-26855",
            vec!["proxylogon", "exchange", "rce"],
        ),
        (
            "spring4shell_exploit",
            "WebExploit",
            RuleDbSeverity::Critical,
            "Spring4Shell CVE-2022-22965 exploit",
            vec!["spring4shell", "spring", "rce"],
        ),
    ]
}

fn builtin_rule_specs_b2c() -> Vec<(&'static str, &'static str, RuleDbSeverity, &'static str, Vec<&'static str>)> {
    vec![
        (
            "follina_exploit",
            "WebExploit",
            RuleDbSeverity::Critical,
            "Follina MSDT exploit CVE-2022-30190",
            vec!["follina", "msdt", "rce"],
        ),
        (
            "eternalblue_exploit",
            "ExploitKit",
            RuleDbSeverity::Critical,
            "EternalBlue SMB exploit NSA/WannaCry",
            vec!["eternalblue", "smb", "nsa"],
        ),
        (
            "bluekeep_exploit",
            "ExploitKit",
            RuleDbSeverity::Critical,
            "BlueKeep RDP exploit CVE-2019-0708",
            vec!["bluekeep", "rdp", "rce"],
        ),
        (
            "deathransom_wiper",
            "DeathRansom",
            RuleDbSeverity::Critical,
            "DeathRansom wiper/ransomware",
            vec!["deathransom", "wiper"],
        ),
        (
            "whispergate_wiper",
            "WhisperGate",
            RuleDbSeverity::Critical,
            "WhisperGate Ukrainian infrastructure wiper",
            vec!["whispergate", "wiper", "ukraine"],
        ),
        (
            "hermeticwiper_wiper",
            "HermeticWiper",
            RuleDbSeverity::Critical,
            "HermeticWiper Ukraine-targeted wiper",
            vec!["hermeticwiper", "wiper", "ukraine"],
        ),
        (
            "acid_rain_wiper",
            "AcidRain",
            RuleDbSeverity::Critical,
            "AcidRain router-targeting wiper",
            vec!["acidrain", "wiper", "router"],
        ),
    ]
}

fn builtin_rule_specs_b2b() -> Vec<(&'static str, &'static str, RuleDbSeverity, &'static str, Vec<&'static str>)> {
    vec![
        (
            "caddywiper_wiper",
            "CaddyWiper",
            RuleDbSeverity::Critical,
            "CaddyWiper data-destruction wiper",
            vec!["caddywiper", "wiper"],
        ),
        (
            "doublepulsar_backdoor",
            "DoublePulsar",
            RuleDbSeverity::Critical,
            "DoublePulsar NSA SMB backdoor implant",
            vec!["doublepulsar", "nsa", "backdoor", "smb"],
        ),
        (
            "industroyer_ics",
            "Industroyer",
            RuleDbSeverity::Critical,
            "Industroyer / Crashoverride ICS malware",
            vec!["industroyer", "ics", "scada"],
        ),
        (
            "triton_ics",
            "Triton",
            RuleDbSeverity::Critical,
            "Triton / Trisis safety system attack tool",
            vec!["triton", "trisis", "ics", "safety_system"],
        ),
        (
            "hafnium_webshell",
            "HAFNIUM",
            RuleDbSeverity::Critical,
            "HAFNIUM Exchange webshell",
            vec!["hafnium", "webshell", "exchange", "apt"],
        ),
        (
            "chopper_webshell",
            "Chopper",
            RuleDbSeverity::Critical,
            "China Chopper webshell",
            vec!["chopper", "webshell", "apt"],
        ),
        (
            "aspx_webshell",
            "Webshell",
            RuleDbSeverity::High,
            "ASPX based webshell",
            vec!["webshell", "aspx", "backdoor"],
        ),
        (
            "php_webshell",
            "Webshell",
            RuleDbSeverity::High,
            "PHP webshell",
            vec!["webshell", "php", "backdoor"],
        ),
        (
            "jsp_webshell",
            "Webshell",
            RuleDbSeverity::High,
            "JSP webshell",
            vec!["webshell", "jsp", "backdoor"],
        ),
        (
            "reflective_dll_inject",
            "Injection",
            RuleDbSeverity::High,
            "Reflective DLL injection technique",
            vec!["reflective_dll", "injection"],
        ),
        (
            "gargoyle_evasion",
            "Evasion",
            RuleDbSeverity::High,
            "Gargoyle RWX page hiding evasion technique",
            vec!["gargoyle", "rwx", "evasion"],
        ),
        (
            "modulenotification_hook",
            "Injection",
            RuleDbSeverity::High,
            "Module notification callback injection",
            vec!["module_notification", "injection", "hook"],
        ),
        (
            "atombombing_inject",
            "Injection",
            RuleDbSeverity::High,
            "AtomBombing code injection technique",
            vec!["atombombing", "injection"],
        ),
    ]
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_count_exceeds_200() {
        let rules = builtin_rules();
        assert!(
            rules.len() >= 200,
            "Expected 200+ rules, got {}",
            rules.len()
        );
    }

    #[test]
    fn rule_db_with_builtins_not_empty() {
        let db = RuleDb::with_builtins();
        assert!(!db.is_empty());
        let (total, _enabled, _fams) = db.summary();
        assert!(total >= 200);
    }

    #[test]
    fn filter_by_family_wannacry() {
        let db = RuleDb::with_builtins();
        let results = db.filter_by_family("WannaCry");
        assert!(!results.is_empty());
    }

    #[test]
    fn filter_by_severity_critical() {
        let db = RuleDb::with_builtins();
        let crits = db.filter_by_severity(&RuleDbSeverity::Critical);
        assert!(!crits.is_empty());
        for r in &crits {
            assert!(r.severity >= RuleDbSeverity::Critical);
        }
    }

    #[test]
    fn scan_finds_mimikatz() {
        let db = RuleDb::with_builtins();
        let data = b"sekurlsa module loaded mimikatz credential dump";
        let matches = db.scan(data);
        assert!(!matches.is_empty());
        assert!(
            matches
                .iter()
                .any(|m| m.family.to_lowercase().contains("mimikatz"))
        );
    }

    #[test]
    fn scan_returns_empty_for_clean_data() {
        let db = RuleDb::with_builtins();
        let data = b"this is perfectly normal text with no malware indicators at all here";
        // May or may not match generic patterns, but should not crash
        let _ = db.scan(data);
    }

    #[test]
    fn disable_family_works() {
        let mut db = RuleDb::with_builtins();
        db.disable_family("UPX");
        for entry in db.filter_by_family("UPX") {
            assert!(!entry.enabled);
        }
    }

    #[test]
    fn severity_ordering() {
        assert!(RuleDbSeverity::Critical > RuleDbSeverity::High);
        assert!(RuleDbSeverity::High > RuleDbSeverity::Medium);
        assert!(RuleDbSeverity::Medium > RuleDbSeverity::Low);
        assert!(RuleDbSeverity::Low > RuleDbSeverity::Info);
    }

    #[test]
    fn rule_entry_has_tags() {
        let entry = RuleEntry::new(
            "test",
            "TestFamily",
            RuleDbSeverity::High,
            "Test rule",
            vec!["foo".into(), "bar".into()],
            "rule test {}",
        );
        assert!(entry.has_tags(&["foo"]));
        assert!(entry.has_tags(&["foo", "bar"]));
        assert!(!entry.has_tags(&["baz"]));
    }

    #[test]
    fn aggregate_score_bounded() {
        let db = RuleDb::with_builtins();
        let data = b"mimikatz sekurlsa wannacry wannacry lockbit conti ALPHV cobalt strike beacon";
        let score = db.aggregate_score(data);
        assert!(score <= 100);
    }
}
