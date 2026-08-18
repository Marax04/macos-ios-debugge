//! Pattern library for string classification.
//!
//! Classifies decoded strings into semantic categories (URL, IP, e-mail,
//! Windows API calls, crypto keys, SQL, shell commands, …) using hand-written
//! state-machine matchers (no external regex crate required).

use std::collections::HashMap;
use std::fmt;

// ─── PatternCategory ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PatternCategory {
    Url,
    IpAddress,
    EmailAddress,
    FilePathWindows,
    FilePathUnix,
    RegistryKey,
    WindowsApi,
    CryptoKey,
    Base64Data,
    SqlQuery,
    ShellCommand,
    NetworkProtocol,
    ErrorMessage,
    DebugString,
    Pdb,
    VersionInfo,
    Guid,
    MutexName,
    EventName,
    ServiceName,
    ScheduledTask,
}

impl fmt::Display for PatternCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            PatternCategory::Url => "URL",
            PatternCategory::IpAddress => "IP Address",
            PatternCategory::EmailAddress => "Email",
            PatternCategory::FilePathWindows => "Windows Path",
            PatternCategory::FilePathUnix => "Unix Path",
            PatternCategory::RegistryKey => "Registry Key",
            PatternCategory::WindowsApi => "Windows API",
            PatternCategory::CryptoKey => "Crypto Key",
            PatternCategory::Base64Data => "Base64 Data",
            PatternCategory::SqlQuery => "SQL Query",
            PatternCategory::ShellCommand => "Shell Command",
            PatternCategory::NetworkProtocol => "Network Protocol",
            PatternCategory::ErrorMessage => "Error Message",
            PatternCategory::DebugString => "Debug String",
            PatternCategory::Pdb => "PDB Path",
            PatternCategory::VersionInfo => "Version Info",
            PatternCategory::Guid => "GUID",
            PatternCategory::MutexName => "Mutex Name",
            PatternCategory::EventName => "Event Name",
            PatternCategory::ServiceName => "Service Name",
            PatternCategory::ScheduledTask => "Scheduled Task",
        };
        write!(f, "{s}")
    }
}

// ─── PatternMatch ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub category: PatternCategory,
    pub value: String,
    pub confidence: f64,
    pub start: usize,
    pub end: usize,
}

// ─── PatternStats ─────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct PatternStats {
    pub counts: HashMap<PatternCategory, usize>,
    pub total_classified: usize,
    pub total_strings: usize,
}

impl PatternStats {
    pub fn record(&mut self, matches: &[PatternMatch]) {
        if !matches.is_empty() { self.total_classified += 1; }
        for m in matches {
            *self.counts.entry(m.category.clone()).or_insert(0) += 1;
        }
    }
}

// ─── StringPatternLibrary ────────────────────────────────────────────────────

/// Stateless pattern classifier. Call [`classify_string`] for individual
/// strings or [`classify_all`] for a batch.
pub struct StringPatternLibrary;

impl StringPatternLibrary {
    #[must_use]
    pub const fn new() -> Self { Self }

    /// Classify a single string and return all matching [`PatternMatch`]es.
    #[must_use]
    pub fn classify_string(&self, s: &str) -> Vec<PatternMatch> {
        let mut results = Vec::new();
        self.find_urls(s, &mut results);
        self.find_ip_addresses(s, &mut results);
        self.find_emails(s, &mut results);
        self.find_windows_paths(s, &mut results);
        self.find_unix_paths(s, &mut results);
        self.find_registry_keys(s, &mut results);
        self.find_guids(s, &mut results);
        self.find_windows_api(s, &mut results);
        self.find_crypto_keys(s, &mut results);
        self.find_sql(s, &mut results);
        self.find_shell_commands(s, &mut results);
        self.find_network_protocols(s, &mut results);
        self.find_pdb(s, &mut results);
        self.find_version_info(s, &mut results);
        self.find_debug_strings(s, &mut results);
        self.find_error_messages(s, &mut results);
        self.find_mutex_names(s, &mut results);
        self.find_event_names(s, &mut results);
        self.find_service_names(s, &mut results);
        self.find_scheduled_tasks(s, &mut results);
        results
    }

    /// Classify all strings and collect [`PatternStats`].
    #[must_use]
    pub fn classify_all(&self, strings: &[&str]) -> (Vec<Vec<PatternMatch>>, PatternStats) {
        let mut stats = PatternStats { total_strings: strings.len(), ..Default::default() };
        let results: Vec<Vec<PatternMatch>> = strings.iter().map(|s| {
            let m = self.classify_string(s);
            stats.record(&m);
            m
        }).collect();
        (results, stats)
    }

    // ── URL ─────────────────────────────────────────────────────────────────

    fn find_urls(&self, s: &str, out: &mut Vec<PatternMatch>) {
        for scheme in &["http://", "https://", "ftp://", "ftps://"] {
            let mut search_from = 0;
            while let Some(pos) = find_substr_ci(&s[search_from..], scheme) {
                let abs_start = search_from + pos;
                let rest = &s[abs_start..];
                let end_offset = rest.find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '<').unwrap_or(rest.len());
                let url = &rest[..end_offset];
                if url.len() > scheme.len() + 3 {
                    out.push(PatternMatch {
                        category: PatternCategory::Url,
                        value: url.to_owned(),
                        confidence: 0.95,
                        start: abs_start,
                        end: abs_start + end_offset,
                    });
                }
                search_from = abs_start + scheme.len() + 1;
                if search_from >= s.len() { break; }
            }
        }
    }

    // ── IP Address ──────────────────────────────────────────────────────────

    fn find_ip_addresses(&self, s: &str, out: &mut Vec<PatternMatch>) {
        // Scan for `digit . digit . digit . digit` patterns
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i].is_ascii_digit() {
                let start = i;
                if let Some((ip, end)) = try_parse_ipv4(bytes, i) {
                    // Boundary check: must not be preceded/followed by digit or dot
                    let ok_before = start == 0 || (!bytes[start-1].is_ascii_digit() && bytes[start-1] != b'.');
                    let ok_after = end >= bytes.len() || (!bytes[end].is_ascii_digit() && bytes[end] != b'.');
                    if ok_before && ok_after {
                        out.push(PatternMatch {
                            category: PatternCategory::IpAddress,
                            value: ip,
                            confidence: 0.90,
                            start,
                            end,
                        });
                        i = end;
                        continue;
                    }
                }
            }
            i += 1;
        }
    }

    // ── Email ───────────────────────────────────────────────────────────────

    fn find_emails(&self, s: &str, out: &mut Vec<PatternMatch>) {
        let bytes = s.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            if b != b'@' || i == 0 || i + 1 >= bytes.len() { continue; }
            // Scan back for local part
            let local_start = scan_back_email_local(bytes, i);
            // Scan forward for domain
            let domain_end = scan_forward_email_domain(bytes, i + 1);
            if domain_end <= i + 2 { continue; }
            let email = &s[local_start..domain_end];
            if email.len() > 5 && email.contains('.') {
                out.push(PatternMatch {
                    category: PatternCategory::EmailAddress,
                    value: email.to_owned(),
                    confidence: 0.88,
                    start: local_start,
                    end: domain_end,
                });
            }
        }
    }

    // ── Windows Paths ───────────────────────────────────────────────────────

    fn find_windows_paths(&self, s: &str, out: &mut Vec<PatternMatch>) {
        // Drive letter: X:\ or X:/
        for (i, _) in s.char_indices() {
            let Some(slice) = s.get(i..i + 3) else { continue; };
            let ch = slice.chars().next().unwrap_or(' ');
            if ch.is_ascii_alphabetic() && (slice.as_bytes()[1] == b':') && (slice.as_bytes()[2] == b'\\' || slice.as_bytes()[2] == b'/') {
                let end = s[i..].find(|c: char| c.is_whitespace() || c == '"' || c == '\'').map(|e| i + e).unwrap_or(s.len());
                out.push(PatternMatch {
                    category: PatternCategory::FilePathWindows,
                    value: s[i..end].to_owned(),
                    confidence: 0.92,
                    start: i,
                    end,
                });
            }
        }
        // UNC path: \\server\share
        let mut search = 0;
        while let Some(pos) = s[search..].find("\\\\") {
            let abs = search + pos;
            let rest = &s[abs..];
            let end_off = rest.find(|c: char| c.is_whitespace() || c == '"').unwrap_or(rest.len());
            if end_off > 4 {
                out.push(PatternMatch {
                    category: PatternCategory::FilePathWindows,
                    value: rest[..end_off].to_owned(),
                    confidence: 0.88,
                    start: abs,
                    end: abs + end_off,
                });
            }
            search = abs + 2;
            if search >= s.len() { break; }
        }
    }

    // ── Unix Paths ──────────────────────────────────────────────────────────

    fn find_unix_paths(&self, s: &str, out: &mut Vec<PatternMatch>) {
        for prefix in &["/etc/", "/usr/", "/var/", "/tmp/", "/home/", "/root/", "/bin/", "/lib/", "/proc/", "/sys/"] {
            let mut search = 0;
            while let Some(pos) = s[search..].find(prefix) {
                let abs = search + pos;
                let rest = &s[abs..];
                let end_off = rest.find(|c: char| c.is_whitespace() || c == '"' || c == '\'').unwrap_or(rest.len());
                out.push(PatternMatch {
                    category: PatternCategory::FilePathUnix,
                    value: rest[..end_off].to_owned(),
                    confidence: 0.85,
                    start: abs,
                    end: abs + end_off,
                });
                search = abs + prefix.len();
                if search >= s.len() { break; }
            }
        }
    }

    // ── Registry Keys ───────────────────────────────────────────────────────

    fn find_registry_keys(&self, s: &str, out: &mut Vec<PatternMatch>) {
        let prefixes = ["HKLM\\", "HKCU\\", "HKCR\\", "HKU\\", "HKCC\\",
                        "HKEY_LOCAL_MACHINE\\", "HKEY_CURRENT_USER\\",
                        "HKEY_CLASSES_ROOT\\", "HKEY_USERS\\"];
        for prefix in &prefixes {
            let mut search = 0;
            while let Some(pos) = find_substr_ci(&s[search..], prefix) {
                let abs = search + pos;
                let rest = &s[abs..];
                let end_off = rest.find(|c: char| c == '"' || c == '\'' || (c.is_whitespace() && c != ' ')).unwrap_or(rest.len());
                let end_off = end_off.min(256); // cap length
                out.push(PatternMatch {
                    category: PatternCategory::RegistryKey,
                    value: rest[..end_off].to_owned(),
                    confidence: 0.93,
                    start: abs,
                    end: abs + end_off,
                });
                search = abs + prefix.len();
                if search >= s.len() { break; }
            }
        }
    }

    // ── GUID ────────────────────────────────────────────────────────────────

    fn find_guids(&self, s: &str, out: &mut Vec<PatternMatch>) {
        // Pattern: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
        let bytes = s.as_bytes();
        for i in 0..bytes.len() {
            if bytes[i] != b'{' { continue; }
            if i + 38 > bytes.len() { continue; }
            if !s.is_char_boundary(i + 38) { continue; }
            let candidate = &s[i..i + 38];
            if is_guid(candidate) {
                out.push(PatternMatch {
                    category: PatternCategory::Guid,
                    value: candidate.to_owned(),
                    confidence: 0.97,
                    start: i,
                    end: i + 38,
                });
            }
        }
    }

    // ── Windows API ─────────────────────────────────────────────────────────

    fn find_windows_api(&self, s: &str, out: &mut Vec<PatternMatch>) {
        const WINAPI: &[&str] = &[
            "GetProcAddress", "LoadLibrary", "LoadLibraryA", "LoadLibraryW",
            "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
            "WriteProcessMemory", "ReadProcessMemory",
            "CreateRemoteThread", "CreateThread",
            "NtQueryInformationProcess", "ZwQueryInformationProcess",
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "SetUnhandledExceptionFilter", "RtlAddVectoredExceptionHandler",
            "HeapCreate", "HeapAlloc", "RegSetValueEx", "RegOpenKeyEx",
            "InternetOpen", "InternetConnect", "HttpSendRequest",
            "WSAStartup", "connect", "send", "recv", "closesocket",
            "CreateService", "StartService", "OpenSCManager",
            "ShellExecute", "ShellExecuteEx", "CreateProcess", "WinExec",
        ];
        for api in WINAPI {
            if let Some(pos) = s.find(api) {
                out.push(PatternMatch {
                    category: PatternCategory::WindowsApi,
                    value: api.to_string(),
                    confidence: 0.92,
                    start: pos,
                    end: pos + api.len(),
                });
            }
        }
    }

    // ── Crypto Keys ─────────────────────────────────────────────────────────

    fn find_crypto_keys(&self, s: &str, out: &mut Vec<PatternMatch>) {
        const PEM_HEADERS: &[&str] = &[
            "-----BEGIN CERTIFICATE-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN PUBLIC KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "-----BEGIN PGP MESSAGE-----",
            "-----BEGIN PGP PUBLIC KEY BLOCK-----",
        ];
        for hdr in PEM_HEADERS {
            if let Some(pos) = s.find(hdr) {
                out.push(PatternMatch {
                    category: PatternCategory::CryptoKey,
                    value: hdr.to_string(),
                    confidence: 0.99,
                    start: pos,
                    end: pos + hdr.len(),
                });
            }
        }
    }

    // ── SQL ──────────────────────────────────────────────────────────────────

    fn find_sql(&self, s: &str, out: &mut Vec<PatternMatch>) {
        const SQL_KW: &[&str] = &["SELECT ", "INSERT INTO", "UPDATE ", "DELETE FROM",
                                   "DROP TABLE", "CREATE TABLE", "ALTER TABLE", "EXEC ", "EXECUTE "];
        let upper = s.to_ascii_uppercase();
        for kw in SQL_KW {
            if let Some(pos) = upper.find(kw) {
                let end = s[pos..].find(|c: char| c == ';').map(|e| pos + e + 1).unwrap_or(s.len().min(pos + 128));
                out.push(PatternMatch {
                    category: PatternCategory::SqlQuery,
                    value: s[pos..end].to_owned(),
                    confidence: 0.85,
                    start: pos,
                    end,
                });
            }
        }
    }

    // ── Shell Commands ──────────────────────────────────────────────────────

    fn find_shell_commands(&self, s: &str, out: &mut Vec<PatternMatch>) {
        const CMD: &[&str] = &["cmd.exe", "powershell", "powershell.exe", "/bin/sh", "/bin/bash",
                                "bash -c", "sh -c", "wscript", "cscript", "mshta", "rundll32",
                                "regsvr32", "bitsadmin", "certutil", "msiexec"];
        let lower = s.to_ascii_lowercase();
        for cmd in CMD {
            if let Some(pos) = lower.find(cmd) {
                let end = s[pos..].find(|c: char| c == '\n' || c == '\0').map(|e| pos + e).unwrap_or(s.len().min(pos + 256));
                out.push(PatternMatch {
                    category: PatternCategory::ShellCommand,
                    value: s[pos..end].to_owned(),
                    confidence: 0.80,
                    start: pos,
                    end,
                });
            }
        }
    }

    // ── Network Protocols ───────────────────────────────────────────────────

    fn find_network_protocols(&self, s: &str, out: &mut Vec<PatternMatch>) {
        const PROTOS: &[&str] = &["TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS", "SMTP",
                                   "POP3", "IMAP", "FTP", "SSH", "RDP", "SMB", "LDAP",
                                   "TLS", "SSL", "IRC", "XMPP"];
        for proto in PROTOS {
            if s.contains(proto) {
                if let Some(pos) = s.find(proto) {
                    out.push(PatternMatch {
                        category: PatternCategory::NetworkProtocol,
                        value: proto.to_string(),
                        confidence: 0.70,
                        start: pos,
                        end: pos + proto.len(),
                    });
                }
            }
        }
    }

    // ── PDB paths ───────────────────────────────────────────────────────────

    fn find_pdb(&self, s: &str, out: &mut Vec<PatternMatch>) {
        if let Some(pos) = s.to_ascii_lowercase().find(".pdb") {
            let start = s[..pos].rfind(|c: char| c.is_whitespace() || c == '"').map(|p| p + 1).unwrap_or(0);
            out.push(PatternMatch {
                category: PatternCategory::Pdb,
                value: s[start..pos + 4].to_owned(),
                confidence: 0.93,
                start,
                end: pos + 4,
            });
        }
    }

    // ── Version Info ────────────────────────────────────────────────────────

    fn find_version_info(&self, s: &str, out: &mut Vec<PatternMatch>) {
        // Matches patterns like 1.2.3, 1.2.3.4, v1.2
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i].is_ascii_digit() || (bytes[i] == b'v' && i + 1 < bytes.len() && bytes[i+1].is_ascii_digit()) {
                let start = i;
                if bytes[i] == b'v' { i += 1; }
                let mut dots = 0u32;
                while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                    if bytes[i] == b'.' { dots += 1; }
                    i += 1;
                }
                if dots >= 1 && i - start >= 3 {
                    out.push(PatternMatch {
                        category: PatternCategory::VersionInfo,
                        value: s[start..i].to_owned(),
                        confidence: 0.75,
                        start,
                        end: i,
                    });
                }
            } else {
                i += 1;
            }
        }
    }

    // ── Debug Strings ───────────────────────────────────────────────────────

    fn find_debug_strings(&self, s: &str, out: &mut Vec<PatternMatch>) {
        const DEBUG_KW: &[&str] = &["[DEBUG]", "[INFO]", "[WARN]", "[ERROR]", "[TRACE]",
                                     "assert(", "ASSERT(", "printf(", "fprintf(", "__FILE__", "__LINE__",
                                     "TODO:", "FIXME:", "HACK:", "XXX:"];
        for kw in DEBUG_KW {
            if let Some(pos) = s.find(kw) {
                out.push(PatternMatch {
                    category: PatternCategory::DebugString,
                    value: kw.to_string(),
                    confidence: 0.78,
                    start: pos,
                    end: pos + kw.len(),
                });
            }
        }
    }

    // ── Error Messages ──────────────────────────────────────────────────────

    fn find_error_messages(&self, s: &str, out: &mut Vec<PatternMatch>) {
        const ERR_KW: &[&str] = &["error:", "Error:", "ERROR:", "failed", "Failed", "FAILED",
                                   "exception", "Exception", "invalid", "Invalid",
                                   "cannot", "Cannot", "permission denied", "access denied"];
        for kw in ERR_KW {
            if let Some(pos) = s.find(kw) {
                out.push(PatternMatch {
                    category: PatternCategory::ErrorMessage,
                    value: kw.to_string(),
                    confidence: 0.65,
                    start: pos,
                    end: pos + kw.len(),
                });
            }
        }
    }

    // ── Mutex names ─────────────────────────────────────────────────────────

    fn find_mutex_names(&self, s: &str, out: &mut Vec<PatternMatch>) {
        const MUTEX_KW: &[&str] = &["Global\\", "Local\\", "Mutex_", "MTX_", "_mutex", "_Mutex"];
        for kw in MUTEX_KW {
            if let Some(pos) = s.find(kw) {
                let end = s[pos..].find(|c: char| c.is_whitespace() || c == '"').map(|e| pos + e).unwrap_or(s.len().min(pos + 64));
                out.push(PatternMatch {
                    category: PatternCategory::MutexName,
                    value: s[pos..end].to_owned(),
                    confidence: 0.80,
                    start: pos,
                    end,
                });
            }
        }
    }

    // ── Event names ─────────────────────────────────────────────────────────

    fn find_event_names(&self, s: &str, out: &mut Vec<PatternMatch>) {
        const EVENT_KW: &[&str] = &["Event_", "EVT_", "_event", "CreateEvent", "OpenEvent"];
        for kw in EVENT_KW {
            if let Some(pos) = s.find(kw) {
                let end = s[pos..].find(|c: char| c.is_whitespace() || c == '"').map(|e| pos + e).unwrap_or(s.len().min(pos + 64));
                out.push(PatternMatch {
                    category: PatternCategory::EventName,
                    value: s[pos..end].to_owned(),
                    confidence: 0.75,
                    start: pos,
                    end,
                });
            }
        }
    }

    // ── Service names ───────────────────────────────────────────────────────

    fn find_service_names(&self, s: &str, out: &mut Vec<PatternMatch>) {
        const SVC_KW: &[&str] = &["SERVICE_", "Svc", "SVC", "service.exe", "svchost"];
        for kw in SVC_KW {
            if let Some(pos) = s.find(kw) {
                let end = s[pos..].find(|c: char| c.is_whitespace() || c == '"').map(|e| pos + e).unwrap_or(s.len().min(pos + 64));
                out.push(PatternMatch {
                    category: PatternCategory::ServiceName,
                    value: s[pos..end].to_owned(),
                    confidence: 0.72,
                    start: pos,
                    end,
                });
            }
        }
    }

    // ── Scheduled tasks ─────────────────────────────────────────────────────

    fn find_scheduled_tasks(&self, s: &str, out: &mut Vec<PatternMatch>) {
        const TASK_KW: &[&str] = &["\\Microsoft\\Windows\\", "schtasks", "at.exe", "TaskScheduler",
                                    "ITaskScheduler", "SCHTASKS /"];
        for kw in TASK_KW {
            if let Some(pos) = s.find(kw) {
                let end = s[pos..].find(|c: char| c == '\n' || c == '\0').map(|e| pos + e).unwrap_or(s.len().min(pos + 128));
                out.push(PatternMatch {
                    category: PatternCategory::ScheduledTask,
                    value: s[pos..end].to_owned(),
                    confidence: 0.80,
                    start: pos,
                    end,
                });
            }
        }
    }
}

impl Default for StringPatternLibrary {
    fn default() -> Self { Self::new() }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn find_substr_ci(haystack: &str, needle: &str) -> Option<usize> {
    // Use ASCII-only case folding so byte offsets match the original string
    // (Unicode case folding can change byte lengths, e.g. U+212A, U+0130).
    let needle = needle.as_bytes();
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

fn try_parse_ipv4(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let mut pos = start;
    let mut octets = [0u16; 4];
    for i in 0..4 {
        if pos >= bytes.len() || !bytes[pos].is_ascii_digit() { return None; }
        let mut val = 0u16;
        let mut digits = 0;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() && digits < 3 {
            val = val * 10 + u16::from(bytes[pos] - b'0');
            pos += 1;
            digits += 1;
        }
        if val > 255 { return None; }
        octets[i] = val;
        if i < 3 {
            if pos >= bytes.len() || bytes[pos] != b'.' { return None; }
            pos += 1; // skip dot
        }
    }
    let ip = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);
    Some((ip, pos))
}

fn scan_back_email_local(bytes: &[u8], at_pos: usize) -> usize {
    let is_local = |b: u8| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' || b == b'+';
    let mut pos = at_pos;
    while pos > 0 && is_local(bytes[pos - 1]) {
        pos -= 1;
    }
    pos
}

fn scan_forward_email_domain(bytes: &[u8], start: usize) -> usize {
    let is_domain = |b: u8| b.is_ascii_alphanumeric() || b == b'.' || b == b'-';
    let mut pos = start;
    while pos < bytes.len() && is_domain(bytes[pos]) {
        pos += 1;
    }
    pos
}

fn is_guid(s: &str) -> bool {
    if s.len() != 38 { return false; }
    let b = s.as_bytes();
    if b[0] != b'{' || b[37] != b'}' { return false; }
    // {8-4-4-4-12}
    let pattern = [8, 4, 4, 4, 12];
    let mut pos = 1;
    for (i, &len) in pattern.iter().enumerate() {
        for j in 0..len {
            if pos + j >= b.len() { return false; }
            if !b[pos + j].is_ascii_hexdigit() { return false; }
        }
        pos += len;
        if i < 4 {
            if pos >= b.len() || b[pos] != b'-' { return false; }
            pos += 1;
        }
    }
    true
}

// ─── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn lib() -> StringPatternLibrary { StringPatternLibrary::new() }

    fn has_cat(matches: &[PatternMatch], cat: &PatternCategory) -> bool {
        matches.iter().any(|m| &m.category == cat)
    }

    #[test]
    fn test_url_http() {
        let m = lib().classify_string("Visit http://example.com/path for details");
        assert!(has_cat(&m, &PatternCategory::Url));
    }

    #[test]
    fn test_url_https() {
        let m = lib().classify_string("https://malware.example.org/payload.exe");
        assert!(has_cat(&m, &PatternCategory::Url));
    }

    #[test]
    fn test_ip_address() {
        let m = lib().classify_string("Connecting to 192.168.1.1:4444");
        assert!(has_cat(&m, &PatternCategory::IpAddress));
    }

    #[test]
    fn test_ip_address_255() {
        let m = lib().classify_string("255.255.255.0");
        assert!(has_cat(&m, &PatternCategory::IpAddress));
    }

    #[test]
    fn test_email() {
        let m = lib().classify_string("Contact attacker@evil.com for ransom");
        assert!(has_cat(&m, &PatternCategory::EmailAddress));
    }

    #[test]
    fn test_windows_path_drive() {
        let m = lib().classify_string("Dropped to C:\\Windows\\Temp\\malware.exe");
        assert!(has_cat(&m, &PatternCategory::FilePathWindows));
    }

    #[test]
    fn test_unix_path() {
        let m = lib().classify_string("Copied to /tmp/payload");
        assert!(has_cat(&m, &PatternCategory::FilePathUnix));
    }

    #[test]
    fn test_registry_key() {
        let m = lib().classify_string("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
        assert!(has_cat(&m, &PatternCategory::RegistryKey));
    }

    #[test]
    fn test_guid() {
        let m = lib().classify_string("{550e8400-e29b-41d4-a716-446655440000}");
        assert!(has_cat(&m, &PatternCategory::Guid));
    }

    #[test]
    fn test_windows_api() {
        let m = lib().classify_string("Call VirtualAlloc then WriteProcessMemory");
        assert!(has_cat(&m, &PatternCategory::WindowsApi));
    }

    #[test]
    fn test_pem_crypto_key() {
        let m = lib().classify_string("-----BEGIN RSA PRIVATE KEY-----");
        assert!(has_cat(&m, &PatternCategory::CryptoKey));
    }

    #[test]
    fn test_sql_select() {
        let m = lib().classify_string("SELECT * FROM users WHERE id=1");
        assert!(has_cat(&m, &PatternCategory::SqlQuery));
    }

    #[test]
    fn test_shell_powershell() {
        let m = lib().classify_string("powershell -enc aGVsbG8=");
        assert!(has_cat(&m, &PatternCategory::ShellCommand));
    }

    #[test]
    fn test_pdb_path() {
        let m = lib().classify_string("C:\\build\\release\\malware.pdb");
        assert!(has_cat(&m, &PatternCategory::Pdb));
    }

    #[test]
    fn test_version_info() {
        let m = lib().classify_string("version 3.2.1 released");
        assert!(has_cat(&m, &PatternCategory::VersionInfo));
    }

    #[test]
    fn test_mutex_name() {
        let m = lib().classify_string("CreateMutex(NULL, TRUE, \"Global\\\\MyMutex\")");
        assert!(has_cat(&m, &PatternCategory::MutexName));
    }

    #[test]
    fn test_classify_all_stats() {
        let strings = ["http://evil.com", "192.168.0.1", "nothing special here"];
        let lib = StringPatternLibrary::new();
        let (results, stats) = lib.classify_all(&strings);
        assert_eq!(results.len(), 3);
        assert_eq!(stats.total_strings, 3);
        assert!(stats.total_classified >= 2);
    }

    #[test]
    fn test_is_guid_valid() {
        assert!(is_guid("{550e8400-e29b-41d4-a716-446655440000}"));
    }

    #[test]
    fn test_is_guid_invalid_length() {
        assert!(!is_guid("{550e8400-e29b}"));
    }

    #[test]
    fn test_no_false_positive_plain_word() {
        let m = lib().classify_string("hello");
        assert!(m.is_empty());
    }
}
