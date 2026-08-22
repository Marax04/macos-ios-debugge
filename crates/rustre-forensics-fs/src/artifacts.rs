//! Forensic artifact detection and classification.
//!
//! Scans file paths and binary data to identify Windows/Linux forensic
//! artifacts: browser databases, prefetch files, LNK files, registry hives,
//! event logs, memory dumps, dropped payloads, and more.

use std::collections::HashMap;

// ─── ArtifactKind ─────────────────────────────────────────────────────────────

/// The category of forensic artifact.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ArtifactKind {
    /// Browser history database (Chrome, Firefox, Edge).
    BrowserHistory,
    /// Windows Recent Files (LNK-backed MRU list).
    RecentFiles,
    /// Windows Prefetch execution trace file.
    PrefetchEntry,
    /// Windows registry hive (SAM, SYSTEM, SOFTWARE, etc.).
    RegistryHive,
    /// Windows Event Log (EVTX format).
    EventLog,
    /// Windows shortcut file (`.lnk`).
    LnkFile,
    /// Windows Jump List (`.automaticDestinations-ms`).
    JumpList,
    /// Windows Amcache hive entry (application compatibility).
    AmcacheEntry,
    /// Full or partial memory dump.
    MemoryDump,
    /// PCAP/PCAPNG network capture.
    NetworkCapture,
    /// Heuristically suspicious file.
    SuspiciousFile,
    /// Payload dropped to a temporary directory.
    DroppedPayload,
    /// Certificate store (PFX, CER, P12, etc.).
    CertificateStore,
    /// Windows Volume Shadow Copy.
    ShadowCopy,
    /// Windows page file (`pagefile.sys`).
    Pagefile,
    /// Windows hibernation file (`hiberfil.sys`).
    Hiberfil,
    /// Windows swap file (`swapfile.sys`).
    SwapFile,
}

impl ArtifactKind {
    /// Human-readable name for reporting.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::BrowserHistory => "BrowserHistory",
            Self::RecentFiles => "RecentFiles",
            Self::PrefetchEntry => "PrefetchEntry",
            Self::RegistryHive => "RegistryHive",
            Self::EventLog => "EventLog",
            Self::LnkFile => "LnkFile",
            Self::JumpList => "JumpList",
            Self::AmcacheEntry => "AmcacheEntry",
            Self::MemoryDump => "MemoryDump",
            Self::NetworkCapture => "NetworkCapture",
            Self::SuspiciousFile => "SuspiciousFile",
            Self::DroppedPayload => "DroppedPayload",
            Self::CertificateStore => "CertificateStore",
            Self::ShadowCopy => "ShadowCopy",
            Self::Pagefile => "Pagefile",
            Self::Hiberfil => "Hiberfil",
            Self::SwapFile => "SwapFile",
        }
    }
}

// ─── IssueSeverity ────────────────────────────────────────────────────────────

/// Severity classification for an artifact finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IssueSeverity {
    /// Low interest; routine artifact.
    Low,
    /// Worth reviewing; may be part of a larger pattern.
    Medium,
    /// Strongly indicative of malicious or anomalous activity.
    High,
    /// Immediate attention required; almost certainly malicious.
    Critical,
}

impl IssueSeverity {
    /// Return the string label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}

// ─── Artifact ─────────────────────────────────────────────────────────────────

/// A single detected forensic artifact.
#[derive(Debug, Clone)]
pub struct Artifact {
    /// Category of artifact.
    pub kind: ArtifactKind,
    /// Path where this artifact was found.
    pub path: String,
    /// Human-readable description of what was detected.
    pub description: String,
    /// Detection confidence 0–100.
    pub confidence: u8,
    /// Severity of this finding.
    pub severity: IssueSeverity,
    /// Arbitrary key-value metadata.
    pub metadata: HashMap<String, String>,
}

impl Artifact {
    /// Create a new artifact with empty metadata.
    #[must_use]
    pub fn new(
        kind: ArtifactKind,
        path: impl Into<String>,
        description: impl Into<String>,
        confidence: u8,
        severity: IssueSeverity,
    ) -> Self {
        Self {
            kind,
            path: path.into(),
            description: description.into(),
            confidence,
            severity,
            metadata: HashMap::new(),
        }
    }

    /// Add a metadata entry.
    #[must_use]
    pub fn with_meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

// ─── ArtifactScanner ─────────────────────────────────────────────────────────

/// Scans files and accumulates detected artifacts.
#[derive(Debug, Default)]
pub struct ArtifactScanner {
    artifacts: Vec<Artifact>,
}

impl ArtifactScanner {
    /// Create a new, empty scanner.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            artifacts: Vec::new(),
        }
    }

    /// Return all detected artifacts.
    #[must_use]
    pub fn artifacts(&self) -> &[Artifact] {
        &self.artifacts
    }

    /// Return artifacts with confidence >= 80.
    #[must_use]
    pub fn high_confidence(&self) -> Vec<&Artifact> {
        self.artifacts
            .iter()
            .filter(|a| a.confidence >= 80)
            .collect()
    }

    /// Scan `path` with optional `data` bytes and route to all detectors.
    pub fn scan_path(&mut self, path: &str, data: &[u8]) {
        if let Some(a) = detect_prefetch(path, data) {
            self.artifacts.push(a);
        }
        if let Some(a) = detect_lnk(path, data) {
            self.artifacts.push(a);
        }
        if let Some(a) = detect_registry_hive(path, data) {
            self.artifacts.push(a);
        }
        if let Some(a) = detect_evtx(path, data) {
            self.artifacts.push(a);
        }
        if let Some(a) = detect_browser_db(path) {
            self.artifacts.push(a);
        }
        if let Some(a) = detect_memory_dump(path, data) {
            self.artifacts.push(a);
        }
        if let Some(a) = detect_dropped_payload(path, data) {
            self.artifacts.push(a);
        }
        if let Some(a) = detect_pagefile(path) {
            self.artifacts.push(a);
        }
        if let Some(a) = detect_certificate_store(path) {
            self.artifacts.push(a);
        }
    }

    /// Produce a summary report.
    #[must_use]
    pub fn report(&self) -> ArtifactReport {
        let mut by_kind: HashMap<String, usize> = HashMap::new();
        let mut critical = 0usize;
        let mut high = 0usize;

        for a in &self.artifacts {
            *by_kind.entry(a.kind.name().to_string()).or_insert(0) += 1;
            match a.severity {
                IssueSeverity::Critical => critical += 1,
                IssueSeverity::High => high += 1,
                _ => {}
            }
        }

        ArtifactReport {
            total: self.artifacts.len(),
            by_kind,
            critical,
            high,
        }
    }
}

// ─── Detectors ────────────────────────────────────────────────────────────────

/// Detect a Windows Prefetch file.
/// Criteria: path ends with `.pf` (case-insensitive) and data starts with `SCCA`.
#[must_use]
pub fn detect_prefetch(path: &str, data: &[u8]) -> Option<Artifact> {
    if !std::path::Path::new(path)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("pf"))
    {
        return None;
    }
    if data.len() < 4 || &data[0..4] != b"SCCA" {
        // Path match alone gives lower confidence
        return Some(
            Artifact::new(
                ArtifactKind::PrefetchEntry,
                path,
                "Windows Prefetch file detected by extension",
                60,
                IssueSeverity::Low,
            )
            .with_meta("detection", "extension-only"),
        );
    }
    Some(
        Artifact::new(
            ArtifactKind::PrefetchEntry,
            path,
            "Windows Prefetch file (SCCA magic + .pf extension)",
            95,
            IssueSeverity::Low,
        )
        .with_meta("magic", "SCCA")
        .with_meta("detection", "magic+extension"),
    )
}

/// Detect a Windows LNK shortcut file.
/// Magic: `4C 00 00 00 01 14 02 00` at offset 0.
#[must_use]
pub fn detect_lnk(path: &str, data: &[u8]) -> Option<Artifact> {
    const LNK_MAGIC: &[u8] = &[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00];
    let by_extension = std::path::Path::new(path)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("lnk"));
    let by_magic = data.len() >= 8 && &data[0..8] == LNK_MAGIC;

    if !by_extension && !by_magic {
        return None;
    }

    let (confidence, description) = if by_magic && by_extension {
        (98, "Windows LNK shortcut (magic + extension)")
    } else if by_magic {
        (90, "Windows LNK shortcut (magic match, unusual extension)")
    } else {
        (55, "Possible Windows LNK shortcut (extension only)")
    };

    Some(
        Artifact::new(
            ArtifactKind::LnkFile,
            path,
            description,
            confidence,
            IssueSeverity::Medium,
        )
        .with_meta("by_magic", by_magic.to_string())
        .with_meta("by_extension", by_extension.to_string()),
    )
}

/// Detect a Windows registry hive.
/// Magic: `regf` (0x72 0x65 0x67 0x66) at offset 0.
#[must_use]
pub fn detect_registry_hive(path: &str, data: &[u8]) -> Option<Artifact> {
    let by_magic = data.len() >= 4 && &data[0..4] == b"regf";
    let lower = path.to_lowercase();
    // Common hive filenames
    let known_names = [
        "sam",
        "system",
        "software",
        "security",
        "ntuser.dat",
        "usrclass.dat",
        "amcache.hve",
        "syscache.hve",
    ];
    let by_name = known_names.iter().any(|n| {
        lower.ends_with(n) || lower.contains(&format!("\\{n}")) || lower.contains(&format!("/{n}"))
    });

    if !by_magic && !by_name {
        return None;
    }

    let (confidence, description) = if by_magic && by_name {
        (99, "Windows Registry hive (regf magic + known filename)")
    } else if by_magic {
        (88, "Windows Registry hive (regf magic)")
    } else {
        (65, "Possible Registry hive (known filename)")
    };

    let severity = if lower.contains("sam") || lower.contains("security") {
        IssueSeverity::High
    } else {
        IssueSeverity::Medium
    };

    Some(
        Artifact::new(
            ArtifactKind::RegistryHive,
            path,
            description,
            confidence,
            severity,
        )
        .with_meta("by_magic", by_magic.to_string())
        .with_meta("by_name", by_name.to_string()),
    )
}

/// Detect a Windows EVTX event log.
/// Magic: `ElfFile\0` (8 bytes) at offset 0.
#[must_use]
pub fn detect_evtx(path: &str, data: &[u8]) -> Option<Artifact> {
    const EVTX_MAGIC: &[u8] = b"ElfFile\0";
    let by_magic = data.len() >= 8 && &data[0..8] == EVTX_MAGIC;
    let by_ext = std::path::Path::new(path)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("evtx"));

    if !by_magic && !by_ext {
        return None;
    }

    let (confidence, description) = if by_magic && by_ext {
        (
            99,
            "Windows EVTX event log (ElfFile magic + .evtx extension)",
        )
    } else if by_magic {
        (90, "Windows EVTX event log (ElfFile magic)")
    } else {
        (60, "Possible EVTX event log (extension only)")
    };

    Some(
        Artifact::new(
            ArtifactKind::EventLog,
            path,
            description,
            confidence,
            IssueSeverity::Low,
        )
        .with_meta("by_magic", by_magic.to_string()),
    )
}

/// Detect a browser history database by filename.
/// Matches: `History` (Chrome), `places.sqlite` (Firefox), `WebCacheV01.dat` (Edge/IE).
#[must_use]
pub fn detect_browser_db(path: &str) -> Option<Artifact> {
    let lower = path.to_lowercase();
    let file_name = lower.split(['/', '\\']).next_back().unwrap_or("");

    let (browser, confidence) =
        if file_name == "history" && (lower.contains("chrome") || lower.contains("google")) {
            ("Chrome", 90u8)
        } else if file_name == "history" {
            ("Unknown/Chrome", 70u8)
        } else if file_name == "places.sqlite" {
            ("Firefox", 92u8)
        } else if file_name == "webcachev01.dat" {
            ("Edge/IE", 88u8)
        } else {
            return None;
        };

    Some(
        Artifact::new(
            ArtifactKind::BrowserHistory,
            path,
            format!("{browser} browser history database"),
            confidence,
            IssueSeverity::Medium,
        )
        .with_meta("browser", browser),
    )
}

/// Detect a memory dump.
/// Path ends with `.dmp` or `.mdmp`, or data starts with `MDMP` or `PAGE`.
#[must_use]
pub fn detect_memory_dump(path: &str, data: &[u8]) -> Option<Artifact> {
    let by_ext = std::path::Path::new(path).extension().is_some_and(|e| {
        e.eq_ignore_ascii_case("dmp") || e.eq_ignore_ascii_case("mdmp")
    });
    let by_magic_mdmp = data.len() >= 4 && &data[0..4] == b"MDMP";
    let by_magic_page = data.len() >= 4 && &data[0..4] == b"PAGE";

    if !by_ext && !by_magic_mdmp && !by_magic_page {
        return None;
    }

    let (confidence, description) = if by_magic_mdmp {
        (97, "Windows minidump (MDMP magic)")
    } else if by_magic_page {
        (85, "Windows full/kernel dump (PAGE magic)")
    } else {
        (70, "Possible memory dump (extension match)")
    };

    Some(
        Artifact::new(
            ArtifactKind::MemoryDump,
            path,
            description,
            confidence,
            IssueSeverity::High,
        )
        .with_meta("by_ext", by_ext.to_string())
        .with_meta("by_magic", (by_magic_mdmp || by_magic_page).to_string()),
    )
}

/// Detect a PE or ELF payload dropped to a temp directory.
/// Criteria: path is in a temp location AND data has PE (`MZ`) or ELF (`\x7fELF`) magic.
#[must_use]
pub fn detect_dropped_payload(path: &str, data: &[u8]) -> Option<Artifact> {
    let lower = path.to_lowercase();
    let in_temp = lower.contains("%temp%")
        || lower.contains("\\temp\\")
        || lower.contains("/tmp/")
        || lower.contains("\\tmp\\")
        || lower.contains("appdata\\local\\temp");

    if !in_temp {
        return None;
    }

    let is_pe = data.len() >= 2 && &data[0..2] == b"MZ";
    let is_elf = data.len() >= 4 && &data[0..4] == b"\x7fELF";

    if !is_pe && !is_elf {
        return None;
    }

    let fmt = if is_pe { "PE (MZ)" } else { "ELF" };

    Some(
        Artifact::new(
            ArtifactKind::DroppedPayload,
            path,
            format!("{fmt} executable dropped in temp directory"),
            95,
            IssueSeverity::Critical,
        )
        .with_meta("format", fmt)
        .with_meta("in_temp", "true"),
    )
}

/// Detect system paging files.
#[must_use]
pub fn detect_pagefile(path: &str) -> Option<Artifact> {
    let lower = path.to_lowercase();
    let file_name = lower.split(['/', '\\']).next_back().unwrap_or("");

    match file_name {
        "pagefile.sys" => Some(Artifact::new(
            ArtifactKind::Pagefile,
            path,
            "Windows page file (pagefile.sys)",
            99,
            IssueSeverity::Medium,
        )),
        "hiberfil.sys" => Some(Artifact::new(
            ArtifactKind::Hiberfil,
            path,
            "Windows hibernation file (hiberfil.sys)",
            99,
            IssueSeverity::High,
        )),
        "swapfile.sys" => Some(Artifact::new(
            ArtifactKind::SwapFile,
            path,
            "Windows swap file (swapfile.sys)",
            99,
            IssueSeverity::Medium,
        )),
        _ => None,
    }
}

/// Detect certificate stores in sensitive directories.
#[must_use]
pub fn detect_certificate_store(path: &str) -> Option<Artifact> {
    let lower = path.to_lowercase();
    let sensitive = lower.contains("\\appdata\\")
        || lower.contains("/home/")
        || lower.contains("\\system32\\")
        || lower.contains("\\certificates\\")
        || lower.contains("/etc/ssl");

    let ext = std::path::Path::new(path).extension();
    let has_cert_ext = ext.is_some_and(|e| {
        e.eq_ignore_ascii_case("cer")
            || e.eq_ignore_ascii_case("pfx")
            || e.eq_ignore_ascii_case("p12")
            || e.eq_ignore_ascii_case("pem")
            || e.eq_ignore_ascii_case("crt")
    });
    let has_private_key =
        ext.is_some_and(|e| e.eq_ignore_ascii_case("pfx") || e.eq_ignore_ascii_case("p12"));

    if !has_cert_ext || !sensitive {
        return None;
    }

    let severity = if has_private_key {
        IssueSeverity::High // private key included
    } else {
        IssueSeverity::Medium
    };

    Some(
        Artifact::new(
            ArtifactKind::CertificateStore,
            path,
            "Certificate file found in sensitive directory",
            85,
            severity,
        )
        .with_meta("has_private_key", has_private_key.to_string()),
    )
}

// ─── ArtifactReport ───────────────────────────────────────────────────────────

/// Summary of all artifacts detected by an [`ArtifactScanner`].
#[derive(Debug, Clone)]
pub struct ArtifactReport {
    /// Total number of artifacts found.
    pub total: usize,
    /// Count of artifacts per kind name.
    pub by_kind: HashMap<String, usize>,
    /// Number of Critical-severity findings.
    pub critical: usize,
    /// Number of High-severity findings.
    pub high: usize,
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── detect_prefetch ───────────────────────────────────────────────────────

    #[test]
    fn prefetch_magic_and_ext() {
        let data = b"SCCAxxx";
        let a = detect_prefetch("C:\\Windows\\Prefetch\\CMD.EXE-AABB1122.pf", data).unwrap();
        assert_eq!(a.confidence, 95);
        assert_eq!(a.kind, ArtifactKind::PrefetchEntry);
    }

    #[test]
    fn prefetch_ext_only() {
        let a = detect_prefetch("C:\\Windows\\Prefetch\\NOTEPAD.EXE.pf", b"garbage").unwrap();
        assert_eq!(a.confidence, 60);
    }

    #[test]
    fn prefetch_no_match() {
        assert!(detect_prefetch("C:\\Windows\\System32\\ntdll.dll", b"MZ").is_none());
    }

    // ── detect_lnk ────────────────────────────────────────────────────────────

    #[test]
    fn lnk_magic_and_ext() {
        let data = &[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0xFF];
        let a = detect_lnk("C:\\Users\\user\\Desktop\\file.lnk", data).unwrap();
        assert_eq!(a.confidence, 98);
    }

    #[test]
    fn lnk_magic_only() {
        let data = &[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00];
        let a = detect_lnk("C:\\weird_file.bin", data).unwrap();
        assert_eq!(a.confidence, 90);
    }

    #[test]
    fn lnk_ext_only() {
        let a = detect_lnk("C:\\link.lnk", b"garbage").unwrap();
        assert_eq!(a.confidence, 55);
    }

    #[test]
    fn lnk_no_match() {
        assert!(detect_lnk("C:\\file.exe", b"MZ").is_none());
    }

    // ── detect_registry_hive ──────────────────────────────────────────────────

    #[test]
    fn registry_hive_regf_and_name() {
        let data = b"regf\x00\x00\x00\x00";
        let a = detect_registry_hive("C:\\Windows\\System32\\config\\SAM", data).unwrap();
        assert_eq!(a.confidence, 99);
        assert_eq!(a.severity, IssueSeverity::High);
    }

    #[test]
    fn registry_hive_regf_only() {
        let data = b"regf\x00\x00\x00\x00";
        let a = detect_registry_hive("C:\\some\\unknown_file", data).unwrap();
        assert_eq!(a.confidence, 88);
    }

    #[test]
    fn registry_hive_name_only() {
        let a = detect_registry_hive("C:\\Windows\\System32\\config\\SYSTEM", b"bad").unwrap();
        assert_eq!(a.confidence, 65);
    }

    #[test]
    fn registry_hive_no_match() {
        assert!(detect_registry_hive("C:\\file.txt", b"hello").is_none());
    }

    // ── detect_evtx ───────────────────────────────────────────────────────────

    #[test]
    fn evtx_magic_and_ext() {
        let data = b"ElfFile\0extra";
        let a = detect_evtx("C:\\Windows\\System32\\winevt\\Logs\\System.evtx", data).unwrap();
        assert_eq!(a.confidence, 99);
    }

    #[test]
    fn evtx_ext_only() {
        let a = detect_evtx("C:\\logs\\Application.evtx", b"junk").unwrap();
        assert_eq!(a.confidence, 60);
    }

    #[test]
    fn evtx_no_match() {
        assert!(detect_evtx("C:\\file.txt", b"hello").is_none());
    }

    // ── detect_browser_db ─────────────────────────────────────────────────────

    #[test]
    fn browser_history_chrome() {
        let a = detect_browser_db(
            "C:\\Users\\user\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History",
        )
        .unwrap();
        assert_eq!(a.kind, ArtifactKind::BrowserHistory);
        assert!(a.confidence >= 90);
    }

    #[test]
    fn browser_history_firefox() {
        let a = detect_browser_db(
            "C:\\Users\\user\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\abc\\places.sqlite",
        )
        .unwrap();
        assert!(a.metadata.get("browser").map(std::string::String::as_str) == Some("Firefox"));
    }

    #[test]
    fn browser_history_edge() {
        let a = detect_browser_db(
            "C:\\Users\\user\\AppData\\Local\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat",
        )
        .unwrap();
        assert!(a.metadata.get("browser").map(std::string::String::as_str) == Some("Edge/IE"));
    }

    #[test]
    fn browser_history_no_match() {
        assert!(detect_browser_db("C:\\file.txt").is_none());
    }

    // ── detect_memory_dump ────────────────────────────────────────────────────

    #[test]
    fn memory_dump_mdmp_magic() {
        let a = detect_memory_dump("C:\\Users\\user\\crash.dmp", b"MDMPxxxx").unwrap();
        assert_eq!(a.confidence, 97);
        assert_eq!(a.severity, IssueSeverity::High);
    }

    #[test]
    fn memory_dump_ext_only() {
        let a = detect_memory_dump("C:\\debug.dmp", b"garbage").unwrap();
        assert_eq!(a.confidence, 70);
    }

    #[test]
    fn memory_dump_no_match() {
        assert!(detect_memory_dump("C:\\file.txt", b"hello").is_none());
    }

    // ── detect_dropped_payload ────────────────────────────────────────────────

    #[test]
    fn dropped_payload_pe_in_temp() {
        let a = detect_dropped_payload("C:\\Windows\\Temp\\update.exe", b"MZ\x90\x00").unwrap();
        assert_eq!(a.kind, ArtifactKind::DroppedPayload);
        assert_eq!(a.severity, IssueSeverity::Critical);
        assert_eq!(a.confidence, 95);
    }

    #[test]
    fn dropped_payload_elf_in_tmp() {
        let a = detect_dropped_payload("/tmp/payload", b"\x7fELF\x02").unwrap();
        assert_eq!(a.severity, IssueSeverity::Critical);
    }

    #[test]
    fn dropped_payload_pe_not_in_temp() {
        assert!(detect_dropped_payload("C:\\Windows\\System32\\ntdll.dll", b"MZ").is_none());
    }

    // ── detect_pagefile ───────────────────────────────────────────────────────

    #[test]
    fn pagefile_sys() {
        let a = detect_pagefile("C:\\pagefile.sys").unwrap();
        assert_eq!(a.kind, ArtifactKind::Pagefile);
    }

    #[test]
    fn hiberfil_sys() {
        let a = detect_pagefile("C:\\hiberfil.sys").unwrap();
        assert_eq!(a.kind, ArtifactKind::Hiberfil);
        assert_eq!(a.severity, IssueSeverity::High);
    }

    #[test]
    fn swapfile_sys() {
        let a = detect_pagefile("C:\\swapfile.sys").unwrap();
        assert_eq!(a.kind, ArtifactKind::SwapFile);
    }

    #[test]
    fn pagefile_no_match() {
        assert!(detect_pagefile("C:\\file.txt").is_none());
    }

    // ── detect_certificate_store ──────────────────────────────────────────────

    #[test]
    fn cert_pfx_sensitive_dir() {
        let a = detect_certificate_store(
            "C:\\Users\\user\\AppData\\Roaming\\Microsoft\\certs\\client.pfx",
        )
        .unwrap();
        assert_eq!(a.kind, ArtifactKind::CertificateStore);
        assert_eq!(a.severity, IssueSeverity::High);
    }

    #[test]
    fn cert_cer_system32() {
        let a =
            detect_certificate_store("C:\\Windows\\System32\\certsrv\\certs\\root.cer").unwrap();
        assert_eq!(a.severity, IssueSeverity::Medium);
    }

    #[test]
    fn cert_no_sensitive_dir() {
        assert!(detect_certificate_store("C:\\Downloads\\cert.pfx").is_none());
    }

    // ── ArtifactScanner ───────────────────────────────────────────────────────

    #[test]
    fn scanner_scan_dropped_payload() {
        let mut scanner = ArtifactScanner::new();
        scanner.scan_path("C:\\Windows\\Temp\\bad.exe", b"MZ\x90\x00");
        assert!(!scanner.artifacts().is_empty());
        assert!(
            scanner
                .artifacts()
                .iter()
                .any(|a| a.kind == ArtifactKind::DroppedPayload)
        );
    }

    #[test]
    fn scanner_high_confidence_filter() {
        let mut scanner = ArtifactScanner::new();
        scanner.scan_path("C:\\Windows\\Prefetch\\CMD.EXE.pf", b"garbage");
        scanner.scan_path("C:\\Windows\\Temp\\shell.exe", b"MZ\x90");
        let hc = scanner.high_confidence();
        // DroppedPayload has confidence=95
        assert!(hc.iter().any(|a| a.kind == ArtifactKind::DroppedPayload));
    }

    #[test]
    fn scanner_report_totals() {
        let mut scanner = ArtifactScanner::new();
        scanner.scan_path("C:\\Windows\\Temp\\evil.exe", b"MZ\x90");
        let report = scanner.report();
        assert!(report.total > 0);
        assert!(report.critical > 0);
    }

    #[test]
    fn artifact_with_meta() {
        let a = Artifact::new(ArtifactKind::LnkFile, "/a", "desc", 80, IssueSeverity::Low)
            .with_meta("k", "v");
        assert_eq!(a.metadata.get("k").map(std::string::String::as_str), Some("v"));
    }

    #[test]
    fn artifact_kind_name() {
        assert_eq!(ArtifactKind::DroppedPayload.name(), "DroppedPayload");
        assert_eq!(ArtifactKind::BrowserHistory.name(), "BrowserHistory");
    }

    #[test]
    fn severity_ordering() {
        assert!(IssueSeverity::Critical > IssueSeverity::High);
        assert!(IssueSeverity::High > IssueSeverity::Medium);
        assert!(IssueSeverity::Medium > IssueSeverity::Low);
    }
}
