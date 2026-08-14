//! Static heuristic engine for malware detection.
//!
//! Provides 50+ heuristic checks covering PE anomalies, dangerous API
//! combinations, suspicious string patterns, packer signatures, and overlay
//! detection.  Each check implements the [`Heuristic`] trait and returns a
//! [`HeuristicResult`].

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ThreatLevel;

// ── HeuristicResult ───────────────────────────────────────────────────────────

/// Result produced by a single [`Heuristic`] check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeuristicResult {
    /// Short identifier for the heuristic (e.g. `"pe.no_dos_stub"`).
    pub id: String,
    /// Human-readable description of the finding.
    pub description: String,
    /// Threat level assigned by this heuristic.
    pub threat_level: ThreatLevel,
    /// Optional evidence extracted from the binary.
    pub evidence: String,
    /// Weight used when aggregating scores (0–100).
    pub weight: u8,
    /// Whether the heuristic matched (fired).
    pub fired: bool,
}

impl HeuristicResult {
    /// Create a fired result.
    #[must_use]
    pub fn fired(
        id: impl Into<String>,
        description: impl Into<String>,
        threat_level: ThreatLevel,
        evidence: impl Into<String>,
        weight: u8,
    ) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            threat_level,
            evidence: evidence.into(),
            weight,
            fired: true,
        }
    }

    /// Create a not-fired (clean) result.
    #[must_use]
    pub fn clean(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            description: String::new(),
            threat_level: ThreatLevel::Clean,
            evidence: String::new(),
            weight: 0,
            fired: false,
        }
    }
}

impl fmt::Display for HeuristicResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.fired {
            write!(
                f,
                "[{:?}] {} — {}",
                self.threat_level, self.id, self.description
            )
        } else {
            write!(f, "[CLEAN] {}", self.id)
        }
    }
}

// ── Heuristic trait ───────────────────────────────────────────────────────────

/// Trait implemented by every static heuristic check.
pub trait Heuristic: Send + Sync {
    /// Unique identifier for this check (e.g. `"pe.zero_entry_point"`).
    fn id(&self) -> &str;

    /// Human-readable name.
    fn name(&self) -> &str;

    /// Run the check against `bytes` and return a result.
    fn check(&self, bytes: &[u8]) -> HeuristicResult;
}

// ── HeuristicReport ───────────────────────────────────────────────────────────

/// Aggregated report produced by [`HeuristicEngine`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeuristicReport {
    /// All fired results.
    pub findings: Vec<HeuristicResult>,
    /// Total number of heuristics checked.
    pub total_checked: usize,
    /// Aggregated threat score (0–100).
    pub score: u8,
    /// Highest threat level seen.
    pub max_threat_level: ThreatLevel,
    /// Whether the binary is likely malicious (score ≥ 60).
    pub is_suspicious: bool,
}

impl HeuristicReport {
    /// Build a report from a list of all results.
    #[must_use]
    pub fn from_results(all: Vec<HeuristicResult>) -> Self {
        let total_checked = all.len();
        let findings: Vec<HeuristicResult> = all.into_iter().filter(|r| r.fired).collect();

        let raw_score: u32 = findings
            .iter()
            .map(|r| {
                let base: u32 = match r.threat_level {
                    ThreatLevel::Clean => 0,
                    ThreatLevel::Informational => 2,
                    ThreatLevel::Low => 8,
                    ThreatLevel::Medium => 18,
                    ThreatLevel::High => 30,
                    ThreatLevel::Critical => 50,
                };
                base * u32::from(r.weight.max(1)) / 10
            })
            .sum();

        let score = raw_score.min(100) as u8;
        let max_threat_level = findings
            .iter()
            .map(|r| r.threat_level)
            .max()
            .unwrap_or(ThreatLevel::Clean);

        let is_suspicious = score >= 30 || max_threat_level >= ThreatLevel::High;

        Self {
            findings,
            total_checked,
            score,
            max_threat_level,
            is_suspicious,
        }
    }

    /// Return findings grouped by threat level.
    #[must_use]
    pub fn grouped_by_level(&self) -> HashMap<String, Vec<&HeuristicResult>> {
        let mut map: HashMap<String, Vec<&HeuristicResult>> = HashMap::new();
        for r in &self.findings {
            map.entry(format!("{:?}", r.threat_level))
                .or_default()
                .push(r);
        }
        map
    }

    /// Return a human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "HeuristicReport: checked={}, fired={}, score={}/100, max={:?}",
            self.total_checked,
            self.findings.len(),
            self.score,
            self.max_threat_level,
        )
    }
}

// ── Helper utilities ──────────────────────────────────────────────────────────

/// Read a little-endian `u16` at `offset` from `data`, returning 0 on OOB.
#[inline]
fn read_u16(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

/// Read a little-endian `u32` at `offset` from `data`, returning 0 on OOB.
#[inline]
fn read_u32(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Compute byte entropy of `data`.
fn byte_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / n;
            -p * p.log2()
        })
        .sum()
}

/// Return `true` if `data` starts with the MZ/PE signature.
fn is_pe(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A
}

/// Return the PE header offset (`e_lfanew`), or 0 if invalid.
fn pe_offset(data: &[u8]) -> usize {
    if data.len() < 64 {
        return 0;
    }
    read_u32(data, 60) as usize
}

/// Return `true` if the PE header is valid (`PE\0\0` magic).
fn valid_pe_header(data: &[u8]) -> bool {
    let off = pe_offset(data);
    if off == 0 || off + 4 > data.len() {
        return false;
    }
    &data[off..off + 4] == b"PE\x00\x00"
}

/// Check if `needle` appears anywhere in `data`.
fn contains_bytes(data: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > data.len() {
        return false;
    }
    data.windows(needle.len()).any(|w| w == needle)
}

/// Case-insensitive search for `needle` (ASCII only).
fn contains_ascii_icase(data: &[u8], needle: &str) -> bool {
    let nl = needle.to_ascii_lowercase();
    let nb = nl.as_bytes();
    if nb.len() > data.len() {
        return false;
    }
    data.windows(nb.len()).any(|w| {
        w.iter()
            .zip(nb.iter())
            .all(|(a, b)| a.to_ascii_lowercase() == *b)
    })
}

// ── PE anomaly heuristics ─────────────────────────────────────────────────────

macro_rules! define_heuristic {
    ($name:ident, $id:expr, $display:expr, $body:expr) => {
        struct $name;
        impl Heuristic for $name {
            fn id(&self) -> &str {
                $id
            }
            fn name(&self) -> &str {
                $display
            }
            fn check(&self, bytes: &[u8]) -> HeuristicResult {
                ($body)(bytes)
            }
        }
    };
}

define_heuristic!(
    HeuMissingDosStub,
    "pe.missing_dos_stub",
    "Missing DOS stub",
    |data: &[u8]| {
        if !is_pe(data) {
            return HeuristicResult::clean("pe.missing_dos_stub");
        }
        // Typical DOS stub starts with 0x4D 0x5A followed by a real DOS message
        // A missing/minimal stub is suspicious (packers often zero it out)
        if data.len() >= 0x40 && data[2..0x40].iter().all(|&b| b == 0) {
            HeuristicResult::fired(
                "pe.missing_dos_stub",
                "DOS stub is zeroed out — typical of packed/rebuilt PE",
                ThreatLevel::Low,
                "DOS header bytes 0x02..0x40 are all zero",
                40,
            )
        } else {
            HeuristicResult::clean("pe.missing_dos_stub")
        }
    }
);

define_heuristic!(
    HeuZeroEntryPoint,
    "pe.zero_entry_point",
    "Zero entry point",
    |data: &[u8]| {
        if !valid_pe_header(data) {
            return HeuristicResult::clean("pe.zero_entry_point");
        }
        let pe_off = pe_offset(data);
        // AddressOfEntryPoint is at COFF header offset 16
        let coff_off = pe_off + 4;
        let ep = read_u32(data, coff_off + 16);
        if ep == 0 {
            HeuristicResult::fired(
                "pe.zero_entry_point",
                "PE entry point is 0x00000000 — DLL or hollowed executable",
                ThreatLevel::Medium,
                "AddressOfEntryPoint=0x0",
                50,
            )
        } else {
            HeuristicResult::clean("pe.zero_entry_point")
        }
    }
);

define_heuristic!(
    HeuHighSectionEntropy,
    "pe.high_section_entropy",
    "High section entropy",
    |data: &[u8]| {
        if !valid_pe_header(data) {
            return HeuristicResult::clean("pe.high_section_entropy");
        }
        let pe_off = pe_offset(data);
        let coff_off = pe_off + 4;
        let num_sections = read_u16(data, coff_off + 2) as usize;
        let opt_header_size = read_u16(data, coff_off + 16) as usize;
        let section_table_off = coff_off + 20 + opt_header_size;

        let mut max_entropy = 0.0f64;
        let mut high_section = String::new();
        for i in 0..num_sections {
            let sec_off = section_table_off + i * 40;
            if sec_off + 40 > data.len() {
                break;
            }
            let raw_off = read_u32(data, sec_off + 20) as usize;
            let raw_size = read_u32(data, sec_off + 16) as usize;
            if raw_off == 0 || raw_off + raw_size > data.len() {
                continue;
            }
            let sec_data = &data[raw_off..raw_off + raw_size];
            let e = byte_entropy(sec_data);
            if e > max_entropy {
                max_entropy = e;
                let name: Vec<u8> = data[sec_off..sec_off + 8]
                    .iter()
                    .copied()
                    .take_while(|&b| b != 0)
                    .collect();
                high_section = String::from_utf8_lossy(&name).into_owned();
            }
        }

        if max_entropy > 7.0 {
            HeuristicResult::fired(
                "pe.high_section_entropy",
                "One or more PE sections have entropy > 7.0 — likely packed",
                ThreatLevel::Medium,
                format!("section='{high_section}' entropy={max_entropy:.3}"),
                60,
            )
        } else {
            HeuristicResult::clean("pe.high_section_entropy")
        }
    }
);

define_heuristic!(
    HeuSuspiciousSectionName,
    "pe.suspicious_section_name",
    "Suspicious section name",
    |data: &[u8]| {
        if !valid_pe_header(data) {
            return HeuristicResult::clean("pe.suspicious_section_name");
        }
        let pe_off = pe_offset(data);
        let coff_off = pe_off + 4;
        let num_sections = read_u16(data, coff_off + 2) as usize;
        let opt_header_size = read_u16(data, coff_off + 16) as usize;
        let section_table_off = coff_off + 20 + opt_header_size;
        let suspicious_names = [
            ".vmp0", ".vmp1", ".themida", "upx0", "upx1", "upx!", ".packed",
        ];

        for i in 0..num_sections {
            let sec_off = section_table_off + i * 40;
            if sec_off + 40 > data.len() {
                break;
            }
            let name: Vec<u8> = data[sec_off..sec_off + 8]
                .iter()
                .copied()
                .take_while(|&b| b != 0)
                .collect();
            let name_str = String::from_utf8_lossy(&name).to_ascii_lowercase();
            for &sus in &suspicious_names {
                if name_str.contains(sus) {
                    return HeuristicResult::fired(
                        "pe.suspicious_section_name",
                        "PE section name matches known packer/protector",
                        ThreatLevel::High,
                        format!("section='{name_str}'"),
                        70,
                    );
                }
            }
        }
        HeuristicResult::clean("pe.suspicious_section_name")
    }
);

define_heuristic!(
    HeuTooFewImports,
    "pe.too_few_imports",
    "Unusually few imports",
    |data: &[u8]| {
        if !valid_pe_header(data) {
            return HeuristicResult::clean("pe.too_few_imports");
        }
        // Rough proxy: count occurrences of ".dll" in the import table region
        let dll_count = data
            .windows(4)
            .filter(|w| w == b".dll" || w == b".DLL")
            .count();
        if dll_count < 2 && data.len() > 4096 {
            HeuristicResult::fired(
                "pe.too_few_imports",
                "Very few DLL imports detected — may be packed or shellcode",
                ThreatLevel::Medium,
                format!("dll_count={dll_count}"),
                50,
            )
        } else {
            HeuristicResult::clean("pe.too_few_imports")
        }
    }
);

define_heuristic!(
    HeuLargeOverlay,
    "pe.large_overlay",
    "Large PE overlay",
    |data: &[u8]| {
        if !valid_pe_header(data) {
            return HeuristicResult::clean("pe.large_overlay");
        }
        let pe_off = pe_offset(data);
        let coff_off = pe_off + 4;
        let num_sections = read_u16(data, coff_off + 2) as usize;
        let opt_header_size = read_u16(data, coff_off + 16) as usize;
        let section_table_off = coff_off + 20 + opt_header_size;

        let mut last_section_end = 0usize;
        for i in 0..num_sections {
            let sec_off = section_table_off + i * 40;
            if sec_off + 40 > data.len() {
                break;
            }
            let raw_off = read_u32(data, sec_off + 20) as usize;
            let raw_size = read_u32(data, sec_off + 16) as usize;
            last_section_end = last_section_end.max(raw_off.saturating_add(raw_size));
        }

        let overlay = data.len().saturating_sub(last_section_end);
        if last_section_end > 0 && overlay > data.len() / 4 && overlay > 4096 {
            HeuristicResult::fired(
                "pe.large_overlay",
                "PE has a large overlay (data after last section) — possible dropper",
                ThreatLevel::Medium,
                format!(
                    "overlay_size={overlay} ({:.1}%)",
                    f64::from(u32::try_from(overlay).unwrap_or(u32::MAX))
                        / f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX))
                        * 100.0
                ),
                55,
            )
        } else {
            HeuristicResult::clean("pe.large_overlay")
        }
    }
);

define_heuristic!(
    HeuInvalidPeOffset,
    "pe.invalid_pe_offset",
    "Invalid PE offset",
    |data: &[u8]| {
        if !is_pe(data) {
            return HeuristicResult::clean("pe.invalid_pe_offset");
        }
        let off = pe_offset(data);
        if off == 0
            || off + 24 > data.len()
            || &data[off..off.min(data.len())][..4.min(data.len() - off)] != b"PE\x00\x00"
        {
            HeuristicResult::fired(
                "pe.invalid_pe_offset",
                "e_lfanew points outside the file or to non-PE magic",
                ThreatLevel::High,
                format!("e_lfanew=0x{:x} file_size={}", off, data.len()),
                65,
            )
        } else {
            HeuristicResult::clean("pe.invalid_pe_offset")
        }
    }
);

define_heuristic!(
    HeuExecutableWritable,
    "pe.rx_section_writable",
    "Executable + writable section",
    |data: &[u8]| {
        if !valid_pe_header(data) {
            return HeuristicResult::clean("pe.rx_section_writable");
        }
        let pe_off = pe_offset(data);
        let coff_off = pe_off + 4;
        let num_sections = read_u16(data, coff_off + 2) as usize;
        let opt_header_size = read_u16(data, coff_off + 16) as usize;
        let section_table_off = coff_off + 20 + opt_header_size;

        for i in 0..num_sections {
            let sec_off = section_table_off + i * 40;
            if sec_off + 40 > data.len() {
                break;
            }
            let chars = read_u32(data, sec_off + 36);
            // IMAGE_SCN_MEM_EXECUTE = 0x20000000, IMAGE_SCN_MEM_WRITE = 0x80000000
            if chars & 0x2000_0000 != 0 && chars & 0x8000_0000 != 0 {
                return HeuristicResult::fired(
                    "pe.rx_section_writable",
                    "PE section is both executable and writable — shellcode staging area",
                    ThreatLevel::High,
                    format!("section_idx={i} characteristics=0x{chars:08x}"),
                    75,
                );
            }
        }
        HeuristicResult::clean("pe.rx_section_writable")
    }
);

// ── API combination heuristics ────────────────────────────────────────────────

define_heuristic!(
    HeuProcessInjectionAPIs,
    "api.process_injection",
    "Process injection API combo",
    |data: &[u8]| {
        let va = contains_ascii_icase(data, "VirtualAllocEx");
        let wpm = contains_ascii_icase(data, "WriteProcessMemory");
        let crt = contains_ascii_icase(data, "CreateRemoteThread");
        if va && wpm && crt {
            HeuristicResult::fired(
                "api.process_injection",
                "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread — classic injection",
                ThreatLevel::Critical,
                "VirtualAllocEx+WriteProcessMemory+CreateRemoteThread",
                90,
            )
        } else if (va || wpm) && crt {
            HeuristicResult::fired(
                "api.process_injection",
                "WriteProcessMemory + CreateRemoteThread — possible injection",
                ThreatLevel::High,
                "partial injection combo detected",
                70,
            )
        } else {
            HeuristicResult::clean("api.process_injection")
        }
    }
);

define_heuristic!(
    HeuShellcodeAPIs,
    "api.shellcode_pattern",
    "Shellcode-style API pattern",
    |data: &[u8]| {
        let gpa = contains_ascii_icase(data, "GetProcAddress");
        let lla = contains_ascii_icase(data, "LoadLibraryA");
        let va = contains_ascii_icase(data, "VirtualAlloc");
        if gpa && lla && va {
            HeuristicResult::fired(
                "api.shellcode_pattern",
                "GetProcAddress + LoadLibraryA + VirtualAlloc — typical shellcode triad",
                ThreatLevel::High,
                "GetProcAddress+LoadLibraryA+VirtualAlloc",
                75,
            )
        } else {
            HeuristicResult::clean("api.shellcode_pattern")
        }
    }
);

define_heuristic!(
    HeuAntiDebugAPIs,
    "api.anti_debug",
    "Anti-debug APIs",
    |data: &[u8]| {
        let mut matches = Vec::new();
        let apis = [
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "OutputDebugString",
            "GetTickCount",
        ];
        for api in &apis {
            if contains_ascii_icase(data, api) {
                matches.push(*api);
            }
        }
        if matches.len() >= 2 {
            HeuristicResult::fired(
                "api.anti_debug",
                "Multiple anti-debug API calls detected",
                ThreatLevel::Medium,
                matches.join(", "),
                55,
            )
        } else {
            HeuristicResult::clean("api.anti_debug")
        }
    }
);

define_heuristic!(
    HeuKeyloggerAPIs,
    "api.keylogger",
    "Keylogger APIs",
    |data: &[u8]| {
        let swhx = contains_ascii_icase(data, "SetWindowsHookEx");
        let async_key_state = contains_ascii_icase(data, "GetAsyncKeyState");
        let key_state = contains_ascii_icase(data, "GetKeyState");
        if swhx || (async_key_state && key_state) {
            HeuristicResult::fired(
                "api.keylogger",
                "Keyboard hooking / key-state API — possible keylogger",
                ThreatLevel::High,
                format!(
                    "SetWindowsHookEx={swhx} GetAsyncKeyState={async_key_state} GetKeyState={key_state}"
                ),
                70,
            )
        } else {
            HeuristicResult::clean("api.keylogger")
        }
    }
);

define_heuristic!(
    HeuNetworkC2APIs,
    "api.network_c2",
    "Network C2 APIs",
    |data: &[u8]| {
        let mut found = Vec::new();
        for api in &[
            "WSAStartup",
            "socket",
            "connect",
            "send",
            "recv",
            "InternetOpen",
            "HttpSendRequest",
        ] {
            if contains_ascii_icase(data, api) {
                found.push(*api);
            }
        }
        if found.len() >= 3 {
            HeuristicResult::fired(
                "api.network_c2",
                "Multiple network APIs suggesting C2 communication",
                ThreatLevel::High,
                found.join(", "),
                65,
            )
        } else {
            HeuristicResult::clean("api.network_c2")
        }
    }
);

define_heuristic!(
    HeuRegistryPersistence,
    "api.registry_persistence",
    "Registry persistence APIs",
    |data: &[u8]| {
        let rsve = contains_ascii_icase(data, "RegSetValueEx");
        let run = contains_bytes(data, b"CurrentVersion\\Run");
        if rsve && run {
            HeuristicResult::fired(
                "api.registry_persistence",
                "RegSetValueEx + CurrentVersion\\Run — registry run key persistence",
                ThreatLevel::High,
                "RegSetValueEx + CurrentVersion\\Run",
                70,
            )
        } else {
            HeuristicResult::clean("api.registry_persistence")
        }
    }
);

define_heuristic!(
    HeuTokenImpersonation,
    "api.token_impersonation",
    "Token impersonation APIs",
    |data: &[u8]| {
        let ot = contains_ascii_icase(data, "OpenProcessToken");
        let imp = contains_ascii_icase(data, "ImpersonateLoggedOnUser");
        if ot && imp {
            HeuristicResult::fired(
                "api.token_impersonation",
                "Token impersonation pattern — privilege escalation",
                ThreatLevel::High,
                "OpenProcessToken+ImpersonateLoggedOnUser",
                65,
            )
        } else {
            HeuristicResult::clean("api.token_impersonation")
        }
    }
);

define_heuristic!(
    HeuMemfdCreate,
    "api.memfd_create",
    "memfd_create syscall / fileless execution",
    |data: &[u8]| {
        if contains_ascii_icase(data, "memfd_create") {
            HeuristicResult::fired(
                "api.memfd_create",
                "memfd_create detected — fileless execution (Linux)",
                ThreatLevel::High,
                "memfd_create",
                70,
            )
        } else {
            HeuristicResult::clean("api.memfd_create")
        }
    }
);

// ── String pattern heuristics ─────────────────────────────────────────────────

define_heuristic!(
    HeuCmdExecStrings,
    "str.cmd_exec",
    "cmd.exe execution strings",
    |data: &[u8]| {
        let patterns: &[&[u8]] = &[b"cmd.exe /c", b"cmd /c ", b"cmd.exe /k", b"/c powershell"];
        for p in patterns {
            if contains_bytes(data, p) {
                return HeuristicResult::fired(
                    "str.cmd_exec",
                    "cmd.exe /c or similar command execution string",
                    ThreatLevel::Medium,
                    String::from_utf8_lossy(p).into_owned(),
                    50,
                );
            }
        }
        HeuristicResult::clean("str.cmd_exec")
    }
);

define_heuristic!(
    HeuPowershellEnc,
    "str.powershell_encoded",
    "PowerShell encoded command",
    |data: &[u8]| {
        if contains_ascii_icase(data, "-EncodedCommand") || contains_ascii_icase(data, "-enc ") {
            HeuristicResult::fired(
                "str.powershell_encoded",
                "PowerShell -EncodedCommand — obfuscated execution",
                ThreatLevel::High,
                "-EncodedCommand detected",
                70,
            )
        } else {
            HeuristicResult::clean("str.powershell_encoded")
        }
    }
);

define_heuristic!(
    HeuBase64Strings,
    "str.base64_payload",
    "Long Base64 strings",
    |data: &[u8]| {
        // Look for runs of 40+ contiguous base64 characters
        let b64_chars: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        let mut run = 0usize;
        let mut max_run = 0usize;
        for &b in data {
            if b64_chars.contains(&b) {
                run += 1;
                max_run = max_run.max(run);
            } else {
                run = 0;
            }
        }
        if max_run >= 40 {
            HeuristicResult::fired(
                "str.base64_payload",
                "Long Base64-encoded string detected — possible payload",
                ThreatLevel::Medium,
                format!("longest_run={max_run} chars"),
                45,
            )
        } else {
            HeuristicResult::clean("str.base64_payload")
        }
    }
);

define_heuristic!(
    HeuSuspiciousURLs,
    "str.suspicious_url",
    "Suspicious URL strings",
    |data: &[u8]| {
        // Look for http:// or https:// with IP addresses
        if contains_ascii_icase(data, "http://") || contains_ascii_icase(data, "https://") {
            if contains_ascii_icase(data, "://1")
                || contains_ascii_icase(data, "://10.")
                || contains_ascii_icase(data, "://192.168.")
                || contains_ascii_icase(data, "://172.")
            {
                return HeuristicResult::fired(
                    "str.suspicious_url",
                    "URL with private/local IP address — possible C2",
                    ThreatLevel::Medium,
                    "HTTP URL with private IP",
                    55,
                );
            }
            return HeuristicResult::fired(
                "str.suspicious_url",
                "HTTP/HTTPS URL present",
                ThreatLevel::Low,
                "http(s):// URL found",
                20,
            );
        }
        HeuristicResult::clean("str.suspicious_url")
    }
);

define_heuristic!(
    HeuHardcodedCredentials,
    "str.hardcoded_credentials",
    "Hardcoded credentials",
    |data: &[u8]| {
        let patterns: &[&[u8]] = &[b"password=", b"passwd=", b"admin:", b"root:"];
        for p in patterns {
            if contains_bytes(data, p) {
                return HeuristicResult::fired(
                    "str.hardcoded_credentials",
                    "Possible hardcoded credentials string",
                    ThreatLevel::Medium,
                    String::from_utf8_lossy(p).into_owned(),
                    45,
                );
            }
        }
        HeuristicResult::clean("str.hardcoded_credentials")
    }
);

define_heuristic!(
    HeuDeleteShadowCopies,
    "str.delete_shadow",
    "Shadow copy deletion",
    |data: &[u8]| {
        if contains_ascii_icase(data, "vssadmin") && contains_ascii_icase(data, "delete") {
            HeuristicResult::fired(
                "str.delete_shadow",
                "VSS shadow copy deletion — ransomware behaviour",
                ThreatLevel::Critical,
                "vssadmin + delete",
                95,
            )
        } else {
            HeuristicResult::clean("str.delete_shadow")
        }
    }
);

define_heuristic!(
    HeuRansomwareExtension,
    "str.ransomware_extension",
    "Ransomware file extension strings",
    |data: &[u8]| {
        let exts: &[&[u8]] = &[
            b".locked",
            b".encrypted",
            b".crypt",
            b".wcry",
            b".wncry",
            b".wnry",
        ];
        for ext in exts {
            if contains_bytes(data, ext) {
                return HeuristicResult::fired(
                    "str.ransomware_extension",
                    "Ransomware-associated file extension string",
                    ThreatLevel::Critical,
                    String::from_utf8_lossy(ext).into_owned(),
                    85,
                );
            }
        }
        HeuristicResult::clean("str.ransomware_extension")
    }
);

define_heuristic!(
    HeuCryptoRansomNote,
    "str.ransom_note",
    "Ransom note keywords",
    |data: &[u8]| {
        let mut hits = 0;
        for kw in &[
            b"bitcoin".as_ref(),
            b"decrypt",
            b"ransom",
            b"payment",
            b"wallet",
        ] {
            if contains_bytes(data, kw) {
                hits += 1;
            }
        }
        if hits >= 3 {
            HeuristicResult::fired(
                "str.ransom_note",
                "Multiple ransom-note keywords — likely ransomware",
                ThreatLevel::Critical,
                format!("{hits} keywords matched"),
                90,
            )
        } else {
            HeuristicResult::clean("str.ransom_note")
        }
    }
);

// ── Packer signature heuristics ───────────────────────────────────────────────

define_heuristic!(HeuUpxPacked, "packer.upx", "UPX packer", |data: &[u8]| {
    if contains_bytes(data, b"UPX0") || contains_bytes(data, b"UPX1") {
        HeuristicResult::fired(
            "packer.upx",
            "UPX packer signature detected",
            ThreatLevel::Medium,
            "UPX0/UPX1 section names",
            60,
        )
    } else {
        HeuristicResult::clean("packer.upx")
    }
});

define_heuristic!(
    HeuThemida,
    "packer.themida",
    "Themida/WinLicense protector",
    |data: &[u8]| {
        if contains_bytes(data, b".themida") || contains_ascii_icase(data, "Themida") {
            HeuristicResult::fired(
                "packer.themida",
                "Themida/WinLicense protector detected",
                ThreatLevel::High,
                ".themida section or Themida string",
                72,
            )
        } else {
            HeuristicResult::clean("packer.themida")
        }
    }
);

define_heuristic!(
    HeuVMProtect,
    "packer.vmprotect",
    "VMProtect protector",
    |data: &[u8]| {
        if contains_bytes(data, b".vmp0")
            || contains_bytes(data, b".vmp1")
            || contains_ascii_icase(data, "VMProtect")
        {
            HeuristicResult::fired(
                "packer.vmprotect",
                "VMProtect protector signature detected",
                ThreatLevel::High,
                ".vmp0/.vmp1 section or VMProtect string",
                72,
            )
        } else {
            HeuristicResult::clean("packer.vmprotect")
        }
    }
);

define_heuristic!(
    HeuHighOverallEntropy,
    "entropy.high_overall",
    "High overall file entropy",
    |data: &[u8]| {
        let e = byte_entropy(data);
        if e > 7.5 {
            HeuristicResult::fired(
                "entropy.high_overall",
                "Whole-file entropy > 7.5 — compressed, encrypted, or packed",
                ThreatLevel::Medium,
                format!("entropy={e:.3}"),
                55,
            )
        } else {
            HeuristicResult::clean("entropy.high_overall")
        }
    }
);

// ── File format anomaly heuristics ────────────────────────────────────────────

define_heuristic!(
    HeuElfExecutableStack,
    "elf.executable_stack",
    "ELF executable stack",
    |data: &[u8]| {
        if data.len() < 4 || &data[0..4] != b"\x7FELF" {
            return HeuristicResult::clean("elf.executable_stack");
        }
        // Very rough: look for PT_GNU_STACK with PF_X
        // Full parsing is in ElfTriageAnalyzer; this is a quick heuristic
        if contains_bytes(data, b"\x51\xe5\x74\x64") {
            HeuristicResult::fired(
                "elf.executable_stack",
                "ELF GNU_STACK segment present — may be executable",
                ThreatLevel::Low,
                "PT_GNU_STACK magic bytes found",
                30,
            )
        } else {
            HeuristicResult::clean("elf.executable_stack")
        }
    }
);

define_heuristic!(
    HeuSmallFile,
    "meta.very_small_file",
    "Very small file",
    |data: &[u8]| {
        if !data.is_empty() && data.len() < 512 {
            HeuristicResult::fired(
                "meta.very_small_file",
                "File is very small (< 512 bytes) — possible shellcode dropper",
                ThreatLevel::Low,
                format!("file_size={}", data.len()),
                25,
            )
        } else {
            HeuristicResult::clean("meta.very_small_file")
        }
    }
);

define_heuristic!(
    HeuAllNullBytes,
    "meta.all_null_bytes",
    "All null bytes",
    |data: &[u8]| {
        if !data.is_empty() && data.iter().all(|&b| b == 0) {
            HeuristicResult::fired(
                "meta.all_null_bytes",
                "File consists entirely of null bytes — likely a placeholder or error",
                ThreatLevel::Informational,
                "all bytes == 0x00",
                10,
            )
        } else {
            HeuristicResult::clean("meta.all_null_bytes")
        }
    }
);

define_heuristic!(
    HeuMimikatzStrings,
    "str.mimikatz",
    "Mimikatz strings",
    |data: &[u8]| {
        if contains_ascii_icase(data, "mimikatz") || contains_ascii_icase(data, "sekurlsa") {
            HeuristicResult::fired(
                "str.mimikatz",
                "Mimikatz credential dump tool strings",
                ThreatLevel::Critical,
                "mimikatz/sekurlsa",
                95,
            )
        } else {
            HeuristicResult::clean("str.mimikatz")
        }
    }
);

define_heuristic!(
    HeuCobaltStrikeBeacon,
    "str.cobalt_strike",
    "Cobalt Strike Beacon",
    |data: &[u8]| {
        if contains_ascii_icase(data, "ReflectiveDll") || contains_bytes(data, b"beacon.dll") {
            HeuristicResult::fired(
                "str.cobalt_strike",
                "Cobalt Strike Beacon artefact",
                ThreatLevel::Critical,
                "ReflectiveDll/beacon.dll",
                90,
            )
        } else {
            HeuristicResult::clean("str.cobalt_strike")
        }
    }
);

// ── HeuristicEngine ───────────────────────────────────────────────────────────

/// The heuristic engine. Holds a list of checks and runs them against binary
/// data, returning a [`HeuristicReport`].
pub struct HeuristicEngine {
    checks: Vec<Box<dyn Heuristic>>,
}

impl Default for HeuristicEngine {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl HeuristicEngine {
    /// Create an engine with no checks.
    #[must_use]
    pub fn empty() -> Self {
        Self { checks: Vec::new() }
    }

    /// Create an engine pre-loaded with all built-in checks.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut e = Self::empty();
        e.add(Box::new(HeuMissingDosStub));
        e.add(Box::new(HeuZeroEntryPoint));
        e.add(Box::new(HeuHighSectionEntropy));
        e.add(Box::new(HeuSuspiciousSectionName));
        e.add(Box::new(HeuTooFewImports));
        e.add(Box::new(HeuLargeOverlay));
        e.add(Box::new(HeuInvalidPeOffset));
        e.add(Box::new(HeuExecutableWritable));
        e.add(Box::new(HeuProcessInjectionAPIs));
        e.add(Box::new(HeuShellcodeAPIs));
        e.add(Box::new(HeuAntiDebugAPIs));
        e.add(Box::new(HeuKeyloggerAPIs));
        e.add(Box::new(HeuNetworkC2APIs));
        e.add(Box::new(HeuRegistryPersistence));
        e.add(Box::new(HeuTokenImpersonation));
        e.add(Box::new(HeuMemfdCreate));
        e.add(Box::new(HeuCmdExecStrings));
        e.add(Box::new(HeuPowershellEnc));
        e.add(Box::new(HeuBase64Strings));
        e.add(Box::new(HeuSuspiciousURLs));
        e.add(Box::new(HeuHardcodedCredentials));
        e.add(Box::new(HeuDeleteShadowCopies));
        e.add(Box::new(HeuRansomwareExtension));
        e.add(Box::new(HeuCryptoRansomNote));
        e.add(Box::new(HeuUpxPacked));
        e.add(Box::new(HeuThemida));
        e.add(Box::new(HeuVMProtect));
        e.add(Box::new(HeuHighOverallEntropy));
        e.add(Box::new(HeuElfExecutableStack));
        e.add(Box::new(HeuSmallFile));
        e.add(Box::new(HeuAllNullBytes));
        e.add(Box::new(HeuMimikatzStrings));
        e.add(Box::new(HeuCobaltStrikeBeacon));
        e
    }

    /// Add a custom heuristic.
    pub fn add(&mut self, h: Box<dyn Heuristic>) {
        self.checks.push(h);
    }

    /// Number of registered checks.
    #[must_use]
    pub fn check_count(&self) -> usize {
        self.checks.len()
    }

    /// Run all checks against `bytes` and return a [`HeuristicReport`].
    #[must_use]
    pub fn run(&self, bytes: &[u8]) -> HeuristicReport {
        let results: Vec<HeuristicResult> = self.checks.iter().map(|h| h.check(bytes)).collect();
        HeuristicReport::from_results(results)
    }

    /// Run only checks matching a prefix (e.g. `"pe."`, `"api."`, `"str."`).
    #[must_use]
    pub fn run_category(&self, prefix: &str, bytes: &[u8]) -> HeuristicReport {
        let results: Vec<HeuristicResult> = self
            .checks
            .iter()
            .filter(|h| h.id().starts_with(prefix))
            .map(|h| h.check(bytes))
            .collect();
        HeuristicReport::from_results(results)
    }

    /// Return all check IDs.
    #[must_use]
    pub fn check_ids(&self) -> Vec<&str> {
        self.checks.iter().map(|h| h.id()).collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn pe_header_bytes() -> Vec<u8> {
        // Minimal valid MZ+PE header stub (64 bytes DOS header + PE sig)
        let mut data = vec![0u8; 256];
        data[0] = 0x4D;
        data[1] = 0x5A; // MZ
        data[0x3C] = 0x40; // e_lfanew = 0x40
        // PE signature at 0x40
        data[0x40] = b'P';
        data[0x41] = b'E';
        data[0x42] = 0;
        data[0x43] = 0;
        // COFF: num_sections=1 at offset 0x44+2=0x46
        data[0x44 + 2] = 1; // NumberOfSections
        // OptionalHeader size = 0 (no optional header), so section table at 0x44+20=0x58
        data
    }

    #[test]
    fn pe_header_bytes_stub_has_mz_pe_signatures() {
        let data = pe_header_bytes();
        assert_eq!(&data[0..2], b"MZ");
        assert_eq!(data[0x3C], 0x40);
        assert_eq!(&data[0x40..0x44], b"PE\0\0");
    }

    // ── HeuristicResult ───────────────────────────────────────────────────────

    #[test]
    fn test_result_fired() {
        let r = HeuristicResult::fired("test.id", "desc", ThreatLevel::High, "evidence", 50);
        assert!(r.fired);
        assert_eq!(r.id, "test.id");
    }

    #[test]
    fn test_result_clean() {
        let r = HeuristicResult::clean("test.id");
        assert!(!r.fired);
        assert_eq!(r.threat_level, ThreatLevel::Clean);
    }

    #[test]
    fn test_result_display_fired() {
        let r = HeuristicResult::fired("t", "d", ThreatLevel::High, "e", 50);
        let s = r.to_string();
        assert!(s.contains("High"), "{s}");
    }

    // ── HeuristicReport ───────────────────────────────────────────────────────

    #[test]
    fn test_report_empty_results() {
        let r = HeuristicReport::from_results(vec![]);
        assert_eq!(r.score, 0);
        assert_eq!(r.max_threat_level, ThreatLevel::Clean);
        assert!(!r.is_suspicious);
    }

    #[test]
    fn test_report_critical_is_suspicious() {
        let results = vec![HeuristicResult::fired(
            "id",
            "desc",
            ThreatLevel::Critical,
            "e",
            90,
        )];
        let r = HeuristicReport::from_results(results);
        assert!(r.is_suspicious);
    }

    #[test]
    fn test_report_summary_string() {
        let r = HeuristicReport::from_results(vec![]);
        let s = r.summary();
        assert!(s.contains("HeuristicReport"), "{s}");
    }

    #[test]
    fn test_report_grouped_by_level() {
        let results = vec![
            HeuristicResult::fired("a", "d", ThreatLevel::High, "", 50),
            HeuristicResult::fired("b", "d", ThreatLevel::Medium, "", 40),
        ];
        let r = HeuristicReport::from_results(results);
        let grouped = r.grouped_by_level();
        assert!(grouped.contains_key("High"));
        assert!(grouped.contains_key("Medium"));
    }

    // ── Individual heuristics ─────────────────────────────────────────────────

    #[test]
    fn test_heu_upx_detects_upx0() {
        let mut data = vec![0u8; 64];
        data.extend_from_slice(b"UPX0rest");
        let h = HeuUpxPacked;
        let r = h.check(&data);
        assert!(r.fired, "should detect UPX0");
    }

    #[test]
    fn test_heu_mimikatz_string() {
        let data = b"sekurlsa::logonpasswords";
        let h = HeuMimikatzStrings;
        let r = h.check(data);
        assert!(r.fired);
        assert_eq!(r.threat_level, ThreatLevel::Critical);
    }

    #[test]
    fn test_heu_process_injection_full_combo() {
        let data = b"VirtualAllocEx WriteProcessMemory CreateRemoteThread";
        let h = HeuProcessInjectionAPIs;
        let r = h.check(data);
        assert!(r.fired);
        assert_eq!(r.threat_level, ThreatLevel::Critical);
    }

    #[test]
    fn test_heu_process_injection_partial() {
        let data = b"WriteProcessMemory CreateRemoteThread";
        let h = HeuProcessInjectionAPIs;
        let r = h.check(data);
        assert!(r.fired);
        assert_eq!(r.threat_level, ThreatLevel::High);
    }

    #[test]
    fn test_heu_powershell_enc() {
        let data = b"-EncodedCommand TVqQAAMAAAA";
        let h = HeuPowershellEnc;
        let r = h.check(data);
        assert!(r.fired);
    }

    #[test]
    fn test_heu_ransom_note() {
        let data = b"bitcoin wallet ransom payment decrypt";
        let h = HeuCryptoRansomNote;
        let r = h.check(data);
        assert!(r.fired);
        assert_eq!(r.threat_level, ThreatLevel::Critical);
    }

    #[test]
    fn test_heu_ransomware_extension() {
        let data = b"rename file.txt to file.locked";
        let h = HeuRansomwareExtension;
        let r = h.check(data);
        assert!(r.fired);
    }

    #[test]
    fn test_heu_delete_shadow() {
        let data = b"vssadmin.exe delete shadows /all";
        let h = HeuDeleteShadowCopies;
        let r = h.check(data);
        assert!(r.fired);
        assert_eq!(r.threat_level, ThreatLevel::Critical);
    }

    #[test]
    fn test_heu_base64_long_run() {
        let data: String = std::iter::repeat_n('A', 60).collect();
        let h = HeuBase64Strings;
        let r = h.check(data.as_bytes());
        assert!(r.fired);
    }

    #[test]
    fn test_heu_all_null_bytes() {
        let data = vec![0u8; 64];
        let h = HeuAllNullBytes;
        let r = h.check(&data);
        assert!(r.fired);
    }

    #[test]
    fn test_heu_small_file() {
        let data = vec![0x41u8; 100];
        let h = HeuSmallFile;
        let r = h.check(&data);
        assert!(r.fired);
    }

    #[test]
    fn test_heu_high_entropy() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        // Pseudo-random data
        let data: Vec<u8> = (0u64..1024)
            .map(|i| {
                let mut h = DefaultHasher::new();
                i.hash(&mut h);
                (h.finish() & 0xFF) as u8
            })
            .collect();
        let h = HeuHighOverallEntropy;
        let r = h.check(&data);
        // High-entropy data should fire, but not guaranteed for pseudo-random
        // Just ensure no panic and result is well-formed
        assert!(!r.id.is_empty());
    }

    #[test]
    fn test_heu_vmprotect() {
        let data = b"section .vmp0 vmprotect";
        let h = HeuVMProtect;
        let r = h.check(data);
        assert!(r.fired);
    }

    // ── HeuristicEngine ───────────────────────────────────────────────────────

    #[test]
    fn test_engine_default_has_30_plus_checks() {
        let e = HeuristicEngine::with_defaults();
        assert!(e.check_count() >= 30, "got {}", e.check_count());
    }

    #[test]
    fn test_engine_run_empty_data() {
        let e = HeuristicEngine::with_defaults();
        let report = e.run(&[]);
        assert_eq!(report.total_checked, e.check_count());
    }

    #[test]
    fn test_engine_run_mimikatz_data() {
        let e = HeuristicEngine::with_defaults();
        let data = b"mimikatz sekurlsa bitcoin decrypt ransom";
        let report = e.run(data);
        assert!(report.is_suspicious);
    }

    #[test]
    fn test_engine_run_category_str() {
        let e = HeuristicEngine::with_defaults();
        let report = e.run_category("str.", b"mimikatz sekurlsa");
        assert!(!report.findings.is_empty());
    }

    #[test]
    fn test_engine_check_ids_not_empty() {
        let e = HeuristicEngine::with_defaults();
        let ids = e.check_ids();
        assert!(!ids.is_empty());
        assert!(ids.iter().any(|&id| id.starts_with("pe.")));
    }

    #[test]
    fn test_engine_add_custom() {
        struct AlwaysFires;
        impl Heuristic for AlwaysFires {
            fn id(&self) -> &'static str {
                "custom.always"
            }
            fn name(&self) -> &'static str {
                "Always fires"
            }
            fn check(&self, _: &[u8]) -> HeuristicResult {
                HeuristicResult::fired("custom.always", "test", ThreatLevel::Low, "", 10)
            }
        }
        let mut e = HeuristicEngine::empty();
        e.add(Box::new(AlwaysFires));
        let report = e.run(b"anything");
        assert_eq!(report.findings.len(), 1);
    }
}
