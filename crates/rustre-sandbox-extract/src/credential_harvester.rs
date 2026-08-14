//! `credential_harvester` — Detect and extract credential-harvesting activity
//! from sandbox event streams and API traces.
//!
//! Provides [`CredentialHarvester`] which monitors for common harvesting
//! patterns (DPAPI, LSA secrets, browser credential stores, keylogging,
//! clipboard snooping, network sniffing) and emits structured
//! [`HarvestEvent`] records.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors that can occur in the credential harvester.
#[derive(Debug, Error)]
pub enum HarvesterError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("invalid event: {0}")]
    InvalidEvent(String),
    #[error("unsupported target: {0}")]
    UnsupportedTarget(String),
}

// ─── CredentialTarget ─────────────────────────────────────────────────────────

/// The type of credential store that was targeted.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CredentialTarget {
    /// Windows Credential Manager / DPAPI.
    Dpapi,
    /// Windows LSA secrets / SAM database.
    LsaSecrets,
    /// Windows Security Account Manager.
    Sam,
    /// Chrome / Chromium browser credential store.
    ChromeCredentials,
    /// Firefox credential store (logins.json / key4.db).
    FirefoxCredentials,
    /// Edge browser credential store.
    EdgeCredentials,
    /// Internet Explorer / `WinINet` saved credentials.
    IeCredentials,
    /// Outlook / Exchange email credentials.
    OutlookCredentials,
    /// Generic network credentials (`WNetGetCachedCredential`, etc.).
    NetworkCredentials,
    /// Keyboard input capture.
    Keylogger,
    /// Windows clipboard.
    Clipboard,
    /// Memory scraping of another process.
    ProcessMemory { target_pid: u32 },
    /// Wi-Fi profile passwords.
    WifiProfiles,
    /// SSH private keys.
    SshKeys,
    /// Generic / unclassified credential store.
    Other(String),
}

impl fmt::Display for CredentialTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dpapi => write!(f, "DPAPI"),
            Self::LsaSecrets => write!(f, "LSA_Secrets"),
            Self::Sam => write!(f, "SAM"),
            Self::ChromeCredentials => write!(f, "Chrome"),
            Self::FirefoxCredentials => write!(f, "Firefox"),
            Self::EdgeCredentials => write!(f, "Edge"),
            Self::IeCredentials => write!(f, "IE"),
            Self::OutlookCredentials => write!(f, "Outlook"),
            Self::NetworkCredentials => write!(f, "Network"),
            Self::Keylogger => write!(f, "Keylogger"),
            Self::Clipboard => write!(f, "Clipboard"),
            Self::ProcessMemory { target_pid } => write!(f, "ProcessMemory({target_pid})"),
            Self::WifiProfiles => write!(f, "WiFi"),
            Self::SshKeys => write!(f, "SSH"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

// ─── HarvestTechnique ─────────────────────────────────────────────────────────

/// The specific technique used to harvest credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HarvestTechnique {
    /// Called `CryptUnprotectData` on DPAPI blob.
    DpapiDecrypt,
    /// Opened the SAM hive with write access.
    SamOpen,
    /// Called `LsaRetrievePrivateData` or equivalent.
    LsaRetrieve,
    /// Opened browser `SQLite` database.
    BrowserDbAccess { db_path: String },
    /// Hooked keyboard input API.
    KeyboardHook,
    /// Read from the Windows clipboard.
    ClipboardRead,
    /// Injected into and scraped memory of a target process.
    ProcessScrape { target_pid: u32 },
    /// Called `WNetGetCachedCredential` or `CredRead`.
    CredRead,
    /// Read Wi-Fi profile XML via netsh.
    WifiProfileRead,
    /// Enumerated SSH agent or read ~/.ssh/*.
    SshKeyRead,
    /// Used `MiniDumpWriteDump` on LSASS.
    LsassDump,
    /// Enumerated saved IE passwords via vault API.
    VaultEnumerate,
    /// Other / unclassified.
    Other(String),
}

impl fmt::Display for HarvestTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DpapiDecrypt => write!(f, "DPAPI_Decrypt"),
            Self::SamOpen => write!(f, "SAM_Open"),
            Self::LsaRetrieve => write!(f, "LSA_Retrieve"),
            Self::BrowserDbAccess { db_path } => write!(f, "BrowserDB({db_path})"),
            Self::KeyboardHook => write!(f, "Keyboard_Hook"),
            Self::ClipboardRead => write!(f, "Clipboard_Read"),
            Self::ProcessScrape { target_pid } => write!(f, "ProcessScrape({target_pid})"),
            Self::CredRead => write!(f, "CredRead"),
            Self::WifiProfileRead => write!(f, "WiFi_Profile_Read"),
            Self::SshKeyRead => write!(f, "SSH_Key_Read"),
            Self::LsassDump => write!(f, "LSASS_Dump"),
            Self::VaultEnumerate => write!(f, "Vault_Enumerate"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

// ─── HarvestSeverity ──────────────────────────────────────────────────────────

/// Severity of the harvesting event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HarvestSeverity {
    /// Informational — suspicious but may be benign.
    Low = 1,
    /// Moderate confidence of credential harvesting.
    Medium = 2,
    /// High confidence — credential theft almost certain.
    High = 3,
    /// Critical — LSASS dump, SAM access, or similar.
    Critical = 4,
}

impl fmt::Display for HarvestSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ─── HarvestEvent ─────────────────────────────────────────────────────────────

/// A detected credential-harvesting event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarvestEvent {
    /// Milliseconds since execution start.
    pub ts_ms: u64,
    /// PID of the harvesting process.
    pub pid: u32,
    /// The credential store that was targeted.
    pub target: CredentialTarget,
    /// The specific technique observed.
    pub technique: HarvestTechnique,
    /// Severity classification.
    pub severity: HarvestSeverity,
    /// Human-readable description.
    pub description: String,
    /// The API function that triggered this detection.
    pub trigger_api: String,
    /// Any extracted credential value (may be empty if not recoverable).
    pub extracted_value: Option<String>,
    /// Tags for further triage (e.g. `"lsass"`, `"browser"`, `"dpapi"`).
    pub tags: Vec<String>,
}

impl HarvestEvent {
    /// Create a new harvest event.
    #[must_use]
    pub fn new(
        ts_ms: u64,
        pid: u32,
        target: CredentialTarget,
        technique: HarvestTechnique,
        severity: HarvestSeverity,
        description: impl Into<String>,
        trigger_api: impl Into<String>,
    ) -> Self {
        Self {
            ts_ms,
            pid,
            target,
            technique,
            severity,
            description: description.into(),
            trigger_api: trigger_api.into(),
            extracted_value: None,
            tags: Vec::new(),
        }
    }

    /// Attach an extracted credential value to this event.
    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.extracted_value = Some(value.into());
        self
    }

    /// Add a tag.
    pub fn tag(mut self, t: impl Into<String>) -> Self {
        let s = t.into();
        if !self.tags.contains(&s) {
            self.tags.push(s);
        }
        self
    }

    /// Return `true` if this event has at least the given severity.
    #[must_use]
    pub fn at_least(&self, min: HarvestSeverity) -> bool {
        self.severity >= min
    }
}

impl fmt::Display for HarvestEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{} t+{}ms pid={}] {} via {} ({}): {}",
            self.severity,
            self.ts_ms,
            self.pid,
            self.target,
            self.technique,
            self.trigger_api,
            self.description,
        )
    }
}

// ─── HarvesterRule ────────────────────────────────────────────────────────────

/// A detection rule that maps an API name (substring match) to a harvest event
/// template.
#[derive(Debug, Clone)]
struct HarvesterRule {
    /// Substring to match against the API name (case-insensitive).
    api_fragment: &'static str,
    /// Optional argument index that must contain a non-empty value.
    arg_index: Option<usize>,
    /// The credential target for this rule.
    target: fn() -> CredentialTarget,
    /// The technique for this rule.
    technique: fn(&[String]) -> HarvestTechnique,
    /// Severity.
    severity: HarvestSeverity,
    /// Short description template.
    description: &'static str,
    /// Tag(s) to apply.
    tags: &'static [&'static str],
}

// ─── ApiCall ──────────────────────────────────────────────────────────────────

/// A simplified API call record consumed by the harvester.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCall {
    /// Function name.
    pub name: String,
    /// Return value (as hex string).
    pub retval: String,
    /// Arguments.
    pub args: Vec<String>,
    /// Timestamp in milliseconds.
    pub ts_ms: u64,
    /// PID of caller.
    pub pid: u32,
}

impl ApiCall {
    /// Create a minimal API call record.
    #[must_use]
    pub fn new(name: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            name: name.into(),
            retval: String::new(),
            args,
            ts_ms: 0,
            pid: 0,
        }
    }
}

// ─── CredentialHarvester ──────────────────────────────────────────────────────

/// Detects credential-harvesting behaviour from API call traces.
///
/// Feed API calls via [`CredentialHarvester::process_call`] or bulk-process
/// a trace with [`CredentialHarvester::process_trace`], then retrieve findings
/// with [`CredentialHarvester::events`].
#[derive(Debug)]
pub struct CredentialHarvester {
    rules: Vec<HarvesterRule>,
    events: Vec<HarvestEvent>,
    /// APIs seen so far (for multi-step sequence detection).
    api_sequence: Vec<String>,
    /// PIDs that have already been flagged for LSASS injection.
    flagged_pids: HashSet<u32>,
    /// Threshold: minimum severity to retain.
    min_severity: HarvestSeverity,
}

impl CredentialHarvester {
    /// Build a harvester with the default rule set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: Self::default_rules(),
            events: Vec::new(),
            api_sequence: Vec::new(),
            flagged_pids: HashSet::new(),
            min_severity: HarvestSeverity::Low,
        }
    }

    /// Set the minimum severity level; events below this level are discarded.
    #[must_use] 
    pub const fn with_min_severity(mut self, min: HarvestSeverity) -> Self {
        self.min_severity = min;
        self
    }

    /// Process a single API call and generate harvest events if rules match.
    pub fn process_call(&mut self, call: &ApiCall) {
        let name_lower = call.name.to_ascii_lowercase();
        self.api_sequence.push(name_lower.clone());

        for rule in &self.rules {
            if !name_lower.contains(rule.api_fragment) {
                continue;
            }

            // Check required argument index.
            if let Some(idx) = rule.arg_index
                && call.args.get(idx).is_none_or(std::string::String::is_empty) {
                    continue;
                }

            let target = (rule.target)();
            let technique = (rule.technique)(&call.args);
            let severity = rule.severity;

            if severity < self.min_severity {
                continue;
            }

            let mut ev = HarvestEvent::new(
                call.ts_ms,
                call.pid,
                target,
                technique,
                severity,
                rule.description,
                &call.name,
            );
            for &tag in rule.tags {
                ev = ev.tag(tag);
            }

            self.events.push(ev);
        }

        // Sequence-based detection: LSASS dump pattern.
        self.detect_lsass_dump_sequence(call);
        // Clipboard sequence detection.
        self.detect_clipboard_sequence(call);
        // Browser database access detection.
        self.detect_browser_db(call);
    }

    /// Process a full API trace.
    pub fn process_trace(&mut self, calls: &[ApiCall]) {
        for call in calls {
            self.process_call(call);
        }
    }

    /// Return all detected harvest events.
    #[must_use]
    pub fn events(&self) -> &[HarvestEvent] {
        &self.events
    }

    /// Return events filtered to at least the given severity.
    #[must_use]
    pub fn events_at_least(&self, min: HarvestSeverity) -> Vec<&HarvestEvent> {
        self.events.iter().filter(|e| e.at_least(min)).collect()
    }

    /// Return the highest severity event seen, if any.
    #[must_use]
    pub fn max_severity(&self) -> Option<HarvestSeverity> {
        self.events.iter().map(|e| e.severity).max()
    }

    /// Return `true` if any Critical events were detected.
    #[must_use]
    pub fn has_critical(&self) -> bool {
        self.events
            .iter()
            .any(|e| e.severity == HarvestSeverity::Critical)
    }

    /// Return a deduplicated list of targeted credential stores.
    #[must_use]
    pub fn targeted_stores(&self) -> Vec<&CredentialTarget> {
        let mut seen: HashSet<String> = HashSet::new();
        let mut out = Vec::new();
        for ev in &self.events {
            let key = ev.target.to_string();
            if seen.insert(key) {
                out.push(&ev.target);
            }
        }
        out
    }

    /// Return a summary map: `technique_label → count`.
    #[must_use]
    pub fn technique_counts(&self) -> HashMap<String, usize> {
        let mut map: HashMap<String, usize> = HashMap::new();
        for ev in &self.events {
            *map.entry(ev.technique.to_string()).or_insert(0) += 1;
        }
        map
    }

    /// Generate a human-readable report of all findings.
    #[must_use]
    pub fn report(&self) -> String {
        if self.events.is_empty() {
            return "No credential harvesting activity detected.".to_string();
        }
        let mut lines = vec![format!(
            "=== Credential Harvesting Report ({} events) ===",
            self.events.len()
        )];
        for ev in &self.events {
            lines.push(ev.to_string());
        }
        lines.join("\n")
    }

    // ─── Sequence detectors ───────────────────────────────────────────────────

    /// Detect the classic `OpenProcess(LSASS) → MiniDumpWriteDump` pattern.
    fn detect_lsass_dump_sequence(&mut self, call: &ApiCall) {
        let name_lower = call.name.to_ascii_lowercase();

        // OpenProcess on LSASS PID: mark the PID as suspicious.
        if name_lower.contains("openprocess") {
            // Argument 2 is typically the PID; we flag if it looks like LSASS (pid 4 or 604).
            if let Some(pid_arg) = call.args.get(2)
                && let Ok(pid) = pid_arg.trim().parse::<u32>()
                    && (pid == 4 || pid == 604 || pid == 708) {
                        self.flagged_pids.insert(call.pid);
                    }
        }

        // MiniDumpWriteDump from a previously flagged PID.
        if name_lower.contains("minidumpwritedump") && self.flagged_pids.contains(&call.pid) {
            let ev = HarvestEvent::new(
                call.ts_ms,
                call.pid,
                CredentialTarget::LsaSecrets,
                HarvestTechnique::LsassDump,
                HarvestSeverity::Critical,
                "MiniDumpWriteDump on LSASS process — credential dump",
                &call.name,
            )
            .tag("lsass")
            .tag("memdump");
            self.events.push(ev);
        }
    }

    /// Detect clipboard sniffing: `OpenClipboard → GetClipboardData`.
    fn detect_clipboard_sequence(&mut self, call: &ApiCall) {
        let name_lower = call.name.to_ascii_lowercase();
        if name_lower.contains("getclipboarddata") {
            // Verify we saw OpenClipboard earlier in the sequence.
            let saw_open = self
                .api_sequence
                .iter()
                .any(|s| s.contains("openclipboard"));
            if saw_open {
                if self
                    .events
                    .iter()
                    .any(|e| matches!(e.target, CredentialTarget::Clipboard))
                {
                    return; // already reported
                }
                let ev = HarvestEvent::new(
                    call.ts_ms,
                    call.pid,
                    CredentialTarget::Clipboard,
                    HarvestTechnique::ClipboardRead,
                    HarvestSeverity::Medium,
                    "GetClipboardData after OpenClipboard — potential credential sniff",
                    &call.name,
                )
                .tag("clipboard");
                self.events.push(ev);
            }
        }
    }

    /// Detect browser credential database access (`SQLite` open on known paths).
    fn detect_browser_db(&mut self, call: &ApiCall) {
        let name_lower = call.name.to_ascii_lowercase();
        if !name_lower.contains("createfile") && !name_lower.contains("ntcreatefile") {
            return;
        }
        let path_arg = call.args.first().map(|s| s.to_ascii_lowercase());
        let path = match path_arg.as_deref() {
            Some(p) => p.to_string(),
            None => return,
        };

        let (target, tag) = if path.contains("\\google\\chrome") && path.contains("login data") {
            (CredentialTarget::ChromeCredentials, "chrome")
        } else if path.contains("\\microsoft\\edge") && path.contains("login data") {
            (CredentialTarget::EdgeCredentials, "edge")
        } else if path.contains("\\mozilla\\firefox")
            && (path.contains("logins.json") || path.contains("key4.db"))
        {
            (CredentialTarget::FirefoxCredentials, "firefox")
        } else if path.contains("\\inetexplorer") || path.contains("\\microsoft\\internet explorer") {
            (CredentialTarget::IeCredentials, "ie")
        } else {
            return;
        };

        let db_path = call.args.first().cloned().unwrap_or_default();
        let ev = HarvestEvent::new(
            call.ts_ms,
            call.pid,
            target,
            HarvestTechnique::BrowserDbAccess {
                db_path: db_path.clone(),
            },
            HarvestSeverity::High,
            format!("Browser credential database opened: {db_path}"),
            &call.name,
        )
        .tag(tag)
        .tag("browser");
        self.events.push(ev);
    }

    // ─── Default rules ────────────────────────────────────────────────────────

    #[must_use]
    fn default_rules() -> Vec<HarvesterRule> {
        vec![
            // DPAPI — CryptUnprotectData
            HarvesterRule {
                api_fragment: "cryptunprotectdata",
                arg_index: None,
                target: || CredentialTarget::Dpapi,
                technique: |_| HarvestTechnique::DpapiDecrypt,
                severity: HarvestSeverity::High,
                description: "CryptUnprotectData called — DPAPI blob decryption",
                tags: &["dpapi"],
            },
            // LSA — LsaRetrievePrivateData
            HarvesterRule {
                api_fragment: "lsaretrieveprivatedata",
                arg_index: None,
                target: || CredentialTarget::LsaSecrets,
                technique: |_| HarvestTechnique::LsaRetrieve,
                severity: HarvestSeverity::Critical,
                description: "LsaRetrievePrivateData called — LSA secret extraction",
                tags: &["lsa"],
            },
            // SAM hive open
            HarvesterRule {
                api_fragment: "samopendomain",
                arg_index: None,
                target: || CredentialTarget::Sam,
                technique: |_| HarvestTechnique::SamOpen,
                severity: HarvestSeverity::Critical,
                description: "SamOpenDomain called — SAM database access",
                tags: &["sam"],
            },
            // CredRead / CredEnumerate
            HarvesterRule {
                api_fragment: "credread",
                arg_index: None,
                target: || CredentialTarget::NetworkCredentials,
                technique: |_| HarvestTechnique::CredRead,
                severity: HarvestSeverity::Medium,
                description: "CredRead called — reading stored Windows credentials",
                tags: &["credmanager"],
            },
            HarvesterRule {
                api_fragment: "credenumerate",
                arg_index: None,
                target: || CredentialTarget::NetworkCredentials,
                technique: |_| HarvestTechnique::CredRead,
                severity: HarvestSeverity::Medium,
                description: "CredEnumerate called — enumerating Windows credentials",
                tags: &["credmanager"],
            },
            // Keyboard hooking — SetWindowsHookEx with WH_KEYBOARD_LL (id=13)
            HarvesterRule {
                api_fragment: "setwindowshookex",
                arg_index: Some(0),
                target: || CredentialTarget::Keylogger,
                technique: |_| HarvestTechnique::KeyboardHook,
                severity: HarvestSeverity::High,
                description: "SetWindowsHookEx called — potential keylogger installation",
                tags: &["keylogger"],
            },
            // Vault API
            HarvesterRule {
                api_fragment: "vaultenumerateitems",
                arg_index: None,
                target: || CredentialTarget::IeCredentials,
                technique: |_| HarvestTechnique::VaultEnumerate,
                severity: HarvestSeverity::High,
                description: "VaultEnumerateItems called — IE/Edge vault enumeration",
                tags: &["vault", "ie"],
            },
            // WNetGetCachedCredential
            HarvesterRule {
                api_fragment: "wnetgetcachedcredential",
                arg_index: None,
                target: || CredentialTarget::NetworkCredentials,
                technique: |_| HarvestTechnique::CredRead,
                severity: HarvestSeverity::Medium,
                description: "WNetGetCachedCredential called — network credential read",
                tags: &["network", "credentials"],
            },
            // SSH key read
            HarvesterRule {
                api_fragment: "ssh-agent",
                arg_index: None,
                target: || CredentialTarget::SshKeys,
                technique: |_| HarvestTechnique::SshKeyRead,
                severity: HarvestSeverity::Medium,
                description: "ssh-agent enumeration detected",
                tags: &["ssh"],
            },
        ]
    }
}

impl Default for CredentialHarvester {
    fn default() -> Self {
        Self::new()
    }
}

// ─── HarvesterReport ──────────────────────────────────────────────────────────

/// Structured output of a complete harvester analysis session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarvesterReport {
    /// All detected events.
    pub events: Vec<HarvestEvent>,
    /// Unique targeted credential stores.
    pub targeted_stores: Vec<String>,
    /// Technique to event-count mapping.
    pub technique_counts: HashMap<String, usize>,
    /// Maximum severity observed (None if no events).
    pub max_severity: Option<String>,
    /// Whether any critical events were found.
    pub has_critical: bool,
    /// Total number of harvesting events.
    pub total_events: usize,
}

impl HarvesterReport {
    /// Build a report from a completed [`CredentialHarvester`].
    #[must_use]
    pub fn from_harvester(h: &CredentialHarvester) -> Self {
        let technique_counts = h.technique_counts();
        let targeted_stores: Vec<String> =
            h.targeted_stores().into_iter().map(std::string::ToString::to_string).collect();
        let max_severity = h.max_severity().map(|s| s.to_string());
        Self {
            events: h.events().to_vec(),
            targeted_stores,
            technique_counts,
            max_severity,
            has_critical: h.has_critical(),
            total_events: h.events().len(),
        }
    }
}

impl fmt::Display for HarvesterReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HarvesterReport {{ total={}, critical={}, max_severity={:?}, targets={} }}",
            self.total_events,
            self.has_critical,
            self.max_severity,
            self.targeted_stores.join(", ")
        )
    }
}

// ─── CredentialScanner ────────────────────────────────────────────────────────

/// Scans string blobs (e.g. memory dump extracts) for patterns that look like
/// credentials: passwords in key=value form, Bearer tokens, API keys, etc.
#[derive(Debug, Default)]
pub struct CredentialScanner;

/// A candidate credential found in a string blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateCredential {
    /// The matched raw string.
    pub raw: String,
    /// Heuristic label (e.g. `"password"`, `"api_key"`, `"bearer_token"`).
    pub kind: String,
    /// Byte offset in the input where the match starts.
    pub offset: usize,
    /// Confidence score in [0.0, 1.0].
    pub confidence: f64,
}

impl CredentialScanner {
    /// Create a new scanner.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Scan a string blob for credential patterns.
    #[must_use]
    pub fn scan(&self, input: &str) -> Vec<CandidateCredential> {
        let mut results = Vec::new();
        self.scan_password_fields(input, &mut results);
        self.scan_api_keys(input, &mut results);
        self.scan_bearer_tokens(input, &mut results);
        self.scan_connection_strings(input, &mut results);
        results
    }

    fn scan_password_fields(&self, input: &str, out: &mut Vec<CandidateCredential>) {
        // Match key=value or key: value where key looks like password/pass/pwd/secret.
        for (i, line) in input.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            for kw in &["password", "passwd", "pwd", "secret", "credentials"] {
                if lower.contains(kw) {
                    // Try to extract value after = or :
                    let sep_pos = line
                        .find('=')
                        .or_else(|| line.rfind(':'));
                    let raw = if let Some(pos) = sep_pos {
                        line[pos + 1..].trim().to_string()
                    } else {
                        line.trim().to_string()
                    };
                    if !raw.is_empty() && raw.len() >= 4 {
                        let offset = i * 80; // approximate
                        out.push(CandidateCredential {
                            raw,
                            kind: "password".to_string(),
                            offset,
                            confidence: 0.75,
                        });
                    }
                }
            }
        }
    }

    fn scan_api_keys(&self, input: &str, out: &mut Vec<CandidateCredential>) {
        // API keys are usually 32+ hex chars or base64 strings following "api_key", "apikey", "token".
        for (i, line) in input.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            if lower.contains("api_key") || lower.contains("apikey") || lower.contains("api-key") {
                let sep_pos = line.find('=').or_else(|| line.find(':'));
                if let Some(pos) = sep_pos {
                    let val = line[pos + 1..].trim().to_string();
                    if val.len() >= 20 {
                        out.push(CandidateCredential {
                            raw: val,
                            kind: "api_key".to_string(),
                            offset: i * 80,
                            confidence: 0.80,
                        });
                    }
                }
            }
        }
    }

    fn scan_bearer_tokens(&self, input: &str, out: &mut Vec<CandidateCredential>) {
        // Bearer tokens in HTTP Authorization headers.
        let prefix = "bearer ";
        let mut start = 0;
        let lower = input.to_ascii_lowercase();
        while let Some(pos) = lower[start..].find(prefix) {
            let abs = start + pos + prefix.len();
            let token: String = input[abs..]
                .chars()
                .take_while(|&c| !c.is_whitespace() && c != '\n' && c != '\r' && c != '"')
                .collect();
            if token.len() >= 16 {
                out.push(CandidateCredential {
                    raw: token,
                    kind: "bearer_token".to_string(),
                    offset: abs,
                    confidence: 0.90,
                });
            }
            start = abs;
        }
    }

    fn scan_connection_strings(&self, input: &str, out: &mut Vec<CandidateCredential>) {
        // Connection strings: "Server=...;User Id=...;Password=..."
        for (i, line) in input.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            if lower.contains("password=") && (lower.contains("server=") || lower.contains("data source=")) {
                out.push(CandidateCredential {
                    raw: line.trim().to_string(),
                    kind: "connection_string".to_string(),
                    offset: i * 80,
                    confidence: 0.85,
                });
            }
        }
    }
}

// ─── HarvesterPipeline ────────────────────────────────────────────────────────

/// High-level pipeline that combines API-trace analysis and string scanning.
pub struct HarvesterPipeline {
    harvester: CredentialHarvester,
    scanner: CredentialScanner,
}

impl HarvesterPipeline {
    /// Create a new pipeline with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            harvester: CredentialHarvester::new(),
            scanner: CredentialScanner::new(),
        }
    }

    /// Create a pipeline that only reports High and Critical events.
    #[must_use]
    pub fn high_confidence() -> Self {
        Self {
            harvester: CredentialHarvester::new()
                .with_min_severity(HarvestSeverity::High),
            scanner: CredentialScanner::new(),
        }
    }

    /// Feed API calls into the API-trace harvester.
    pub fn ingest_api_calls(&mut self, calls: &[ApiCall]) {
        self.harvester.process_trace(calls);
    }

    /// Scan string blobs from memory dumps, config files, etc.
    #[must_use]
    pub fn scan_strings(&self, blobs: &[&str]) -> Vec<CandidateCredential> {
        let mut results = Vec::new();
        for blob in blobs {
            results.extend(self.scanner.scan(blob));
        }
        results
    }

    /// Produce a combined [`HarvesterReport`].
    #[must_use]
    pub fn report(&self) -> HarvesterReport {
        HarvesterReport::from_harvester(&self.harvester)
    }

    /// Return all raw harvest events.
    #[must_use]
    pub fn events(&self) -> &[HarvestEvent] {
        self.harvester.events()
    }
}

impl Default for HarvesterPipeline {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_call(name: &str, args: Vec<&str>, pid: u32, ts: u64) -> ApiCall {
        ApiCall {
            name: name.to_string(),
            retval: "0".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            ts_ms: ts,
            pid,
        }
    }

    #[test]
    fn detect_dpapi_decrypt() {
        let mut h = CredentialHarvester::new();
        h.process_call(&make_call("CryptUnprotectData", vec![], 1000, 100));
        assert_eq!(h.events().len(), 1);
        assert_eq!(h.events()[0].severity, HarvestSeverity::High);
        assert!(matches!(h.events()[0].target, CredentialTarget::Dpapi));
    }

    #[test]
    fn detect_lsa_retrieve() {
        let mut h = CredentialHarvester::new();
        h.process_call(&make_call("LsaRetrievePrivateData", vec![], 500, 200));
        assert!(h.has_critical());
        assert!(matches!(
            h.events()[0].target,
            CredentialTarget::LsaSecrets
        ));
    }

    #[test]
    fn detect_cred_enumerate() {
        let mut h = CredentialHarvester::new();
        h.process_call(&make_call("CredEnumerateW", vec![], 123, 50));
        assert_eq!(h.events().len(), 1);
        assert_eq!(h.events()[0].severity, HarvestSeverity::Medium);
    }

    #[test]
    fn detect_clipboard_sequence() {
        let mut h = CredentialHarvester::new();
        h.process_call(&make_call("OpenClipboard", vec!["0"], 200, 10));
        h.process_call(&make_call("GetClipboardData", vec!["1"], 200, 20));
        let clipboard_events: Vec<_> = h
            .events()
            .iter()
            .filter(|e| matches!(e.target, CredentialTarget::Clipboard))
            .collect();
        assert_eq!(clipboard_events.len(), 1);
    }

    #[test]
    fn detect_lsass_dump_sequence() {
        let mut h = CredentialHarvester::new();
        // PID 1000 opens LSASS (pid 604)
        h.process_call(&make_call(
            "OpenProcess",
            vec!["0x1F0FFF", "0", "604"],
            1000,
            100,
        ));
        h.process_call(&make_call("MiniDumpWriteDump", vec![], 1000, 200));
        assert!(h.has_critical());
        let dump_events: Vec<_> = h
            .events()
            .iter()
            .filter(|e| matches!(e.technique, HarvestTechnique::LsassDump))
            .collect();
        assert_eq!(dump_events.len(), 1);
    }

    #[test]
    fn detect_browser_chrome() {
        let mut h = CredentialHarvester::new();
        h.process_call(&make_call(
            "CreateFileW",
            vec![r"C:\Users\user\AppData\Local\Google\Chrome\User Data\Default\Login Data"],
            500,
            300,
        ));
        let browser_events: Vec<_> = h
            .events()
            .iter()
            .filter(|e| matches!(e.target, CredentialTarget::ChromeCredentials))
            .collect();
        assert_eq!(browser_events.len(), 1);
        assert!(browser_events[0].tags.contains(&"chrome".to_string()));
    }

    #[test]
    fn detect_firefox_credentials() {
        let mut h = CredentialHarvester::new();
        h.process_call(&make_call(
            "NtCreateFile",
            vec![r"C:\Users\user\AppData\Roaming\Mozilla\Firefox\Profiles\abc\logins.json"],
            600,
            400,
        ));
        let ev: Vec<_> = h
            .events()
            .iter()
            .filter(|e| matches!(e.target, CredentialTarget::FirefoxCredentials))
            .collect();
        assert_eq!(ev.len(), 1);
    }

    #[test]
    fn min_severity_filter() {
        let mut h = CredentialHarvester::new().with_min_severity(HarvestSeverity::High);
        h.process_call(&make_call("CredReadW", vec![], 100, 10));
        // CredRead is Medium — should be filtered.
        assert_eq!(h.events().len(), 0);
    }

    #[test]
    fn max_severity() {
        let mut h = CredentialHarvester::new();
        h.process_call(&make_call("CryptUnprotectData", vec![], 100, 10));
        h.process_call(&make_call("SamOpenDomain", vec![], 100, 20));
        assert_eq!(h.max_severity(), Some(HarvestSeverity::Critical));
    }

    #[test]
    fn technique_counts() {
        let mut h = CredentialHarvester::new();
        h.process_call(&make_call("CryptUnprotectData", vec![], 1, 1));
        h.process_call(&make_call("CryptUnprotectData", vec![], 2, 2));
        let counts = h.technique_counts();
        assert_eq!(counts.get("DPAPI_Decrypt"), Some(&2));
    }

    #[test]
    fn credential_scanner_password() {
        let scanner = CredentialScanner::new();
        let text = "config: password=S3cr3tP@ss\nother=value";
        let results = scanner.scan(text);
        let pw: Vec<_> = results.iter().filter(|r| r.kind == "password").collect();
        assert!(!pw.is_empty());
    }

    #[test]
    fn credential_scanner_bearer() {
        let scanner = CredentialScanner::new();
        let text = "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig";
        let results = scanner.scan(text);
        let bearer: Vec<_> = results.iter().filter(|r| r.kind == "bearer_token").collect();
        assert!(!bearer.is_empty());
        assert!(bearer[0].raw.starts_with("eyJ"));
    }

    #[test]
    fn credential_scanner_connection_string() {
        let scanner = CredentialScanner::new();
        let text = "Server=myserver;Database=mydb;User Id=sa;Password=mypw;";
        let results = scanner.scan(text);
        let conn: Vec<_> = results
            .iter()
            .filter(|r| r.kind == "connection_string")
            .collect();
        assert!(!conn.is_empty());
    }

    #[test]
    fn harvester_report_structure() {
        let mut h = CredentialHarvester::new();
        h.process_call(&make_call("LsaRetrievePrivateData", vec![], 1, 1));
        let report = HarvesterReport::from_harvester(&h);
        assert_eq!(report.total_events, 1);
        assert!(report.has_critical);
        assert!(!report.targeted_stores.is_empty());
    }

    #[test]
    fn pipeline_combined() {
        let mut pipeline = HarvesterPipeline::new();
        pipeline.ingest_api_calls(&[make_call("CryptUnprotectData", vec![], 1, 10)]);
        let candidates = pipeline.scan_strings(&["password=abc123"]);
        let report = pipeline.report();
        assert_eq!(report.total_events, 1);
        assert!(!candidates.is_empty());
    }

    #[test]
    fn harvest_event_display() {
        let ev = HarvestEvent::new(
            100,
            999,
            CredentialTarget::Dpapi,
            HarvestTechnique::DpapiDecrypt,
            HarvestSeverity::High,
            "test event",
            "CryptUnprotectData",
        );
        let s = ev.to_string();
        assert!(s.contains("HIGH"));
        assert!(s.contains("DPAPI"));
    }

    #[test]
    fn targeted_stores_dedup() {
        let mut h = CredentialHarvester::new();
        h.process_call(&make_call("CryptUnprotectData", vec![], 1, 1));
        h.process_call(&make_call("CryptUnprotectData", vec![], 2, 2));
        // Both hit the same target; only one unique store should be reported.
        let stores = h.targeted_stores();
        assert_eq!(stores.len(), 1);
    }
}
