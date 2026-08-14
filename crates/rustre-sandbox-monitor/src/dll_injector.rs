//! Windows DLL injection monitor stubs.
//!
//! Provides detection logic for common DLL injection techniques used by malware:
//! classic `CreateRemoteThread` injection, `NtCreateThreadEx`, APC injection,
//! `SetWindowsHookEx`, manual mapping, and reflective DLL loading.
//!
//! On non-Windows platforms all detection logic is available for unit-testing;
//! only the OS-call stubs would differ in a real implementation.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum InjectionError {
    #[error("access denied for PID {0}")]
    AccessDenied(u32),
    #[error("process {0} not found")]
    ProcessNotFound(u32),
    #[error("memory read error at 0x{0:016x}: {1}")]
    MemoryError(u64, String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("scan error: {0}")]
    ScanError(String),
}

// ─── DllInjectionMethod ───────────────────────────────────────────────────────

/// Classification of the injection technique used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DllInjectionMethod {
    /// Classic: `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`.
    CreateRemoteThread,
    /// NT-level: `NtCreateThreadEx` (bypasses some hooks).
    NtCreateThreadEx,
    /// APC queue injection via `QueueUserAPC` / `NtQueueApcThread`.
    Apc,
    /// `SetWindowsHookEx` with a global hook.
    SetWindowsHookEx,
    /// Manual mapping: PE parsed and mapped by the injector without `LoadLibrary`.
    ManualMap,
    /// Reflective DLL: the DLL contains its own loader function.
    Reflective,
    /// `CreateProcess` with a suspended process and hollowed PE.
    ProcessHollowing,
    /// `NtMapViewOfSection` shared section injection.
    SectionInjection,
    /// `AppInit_DLLs` registry key persistence.
    AppInitDll,
    /// Thread hijacking via `SuspendThread` + `SetThreadContext`.
    ThreadHijack,
}

impl fmt::Display for DllInjectionMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::CreateRemoteThread => "CreateRemoteThread",
            Self::NtCreateThreadEx => "NtCreateThreadEx",
            Self::Apc => "APC Injection",
            Self::SetWindowsHookEx => "SetWindowsHookEx",
            Self::ManualMap => "Manual Mapping",
            Self::Reflective => "Reflective DLL",
            Self::ProcessHollowing => "Process Hollowing",
            Self::SectionInjection => "Section Injection",
            Self::AppInitDll => "AppInit_DLLs",
            Self::ThreadHijack => "Thread Hijack",
        };
        write!(f, "{s}")
    }
}

impl DllInjectionMethod {
    /// Suspicion weight (0-100) for scoring.
    #[must_use]
    pub const fn suspicion_weight(self) -> u32 {
        match self {
            Self::CreateRemoteThread => 80,
            Self::NtCreateThreadEx => 90,
            Self::Apc => 75,
            Self::SetWindowsHookEx => 60,
            Self::ManualMap | Self::Reflective | Self::ProcessHollowing => 95,
            Self::SectionInjection | Self::ThreadHijack => 85,
            Self::AppInitDll => 70,
        }
    }
}

// ─── InjectedModule ──────────────────────────────────────────────────────────

/// A DLL module that was found to be injected (not legitimately loaded).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectedModule {
    /// PID of the target process.
    pub target_pid: u32,
    /// Base address of the injected module.
    pub base_address: u64,
    /// Size of the module in memory.
    pub size: u64,
    /// File path if resolvable (empty for manually mapped modules).
    pub path: String,
    /// Module name (basename).
    pub name: String,
    /// Detected injection method, if determinable.
    pub method: Option<DllInjectionMethod>,
    /// Confidence level (0.0 – 1.0).
    pub confidence: f64,
    /// True if this module appears in the PEB module list.
    pub in_peb: bool,
    /// True if the file exists on disk at `path`.
    pub file_on_disk: bool,
    /// Whether the PE header at the base address matches the disk file.
    pub header_matches_disk: bool,
    /// Additional context notes.
    pub notes: Vec<String>,
}

impl InjectedModule {
    #[must_use]
    pub fn new(
        target_pid: u32,
        base_address: u64,
        size: u64,
        name: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        Self {
            target_pid,
            base_address,
            size,
            path: path.into(),
            name: name.into(),
            method: None,
            confidence: 0.0,
            in_peb: true,
            file_on_disk: true,
            header_matches_disk: true,
            notes: Vec::new(),
        }
    }

    /// Returns `true` if this module shows signs of injection.
    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        !self.in_peb || !self.file_on_disk || !self.header_matches_disk || self.confidence > 0.5
    }

    /// Add a note.
    pub fn add_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    /// Quote a value for a CSV row, per RFC 4180.
    ///
    /// The injected module is identified by a name or full path taken from the
    /// target process, so a comma in it is the target's choice, not ours — and
    /// unquoted it shifts every later column, moving the suspicious/clean
    /// verdict onto the wrong module.
    ///
    /// Quoting is minimal: a value containing none of `,` `"` CR LF is returned
    /// untouched, so rows that were already well formed do not change. Same
    /// helper as `csv_field` in `rustre-sysinternals`.
    fn csv_field(value: &str) -> String {
        if value.contains([',', '"', '\r', '\n']) {
            format!("\"{}\"", value.replace('"', "\"\""))
        } else {
            value.to_owned()
        }
    }

    /// CSV row.
    #[must_use]
    pub fn to_csv_row(&self) -> String {
        format!(
            "{},0x{:016x},{},{},{},{:.2}",
            self.target_pid,
            self.base_address,
            Self::csv_field(&self.name),
            self.method.map(|m| m.to_string()).unwrap_or_default(),
            if self.is_suspicious() {
                "suspicious"
            } else {
                "clean"
            },
            self.confidence,
        )
    }
}

// ─── ReflectiveDllSignature ───────────────────────────────────────────────────

/// Byte patterns that identify reflective DLL loaders.
pub struct ReflectiveDllSignature;

impl ReflectiveDllSignature {
    /// Known export names used by reflective DLL loaders.
    pub const REFLECTIVE_EXPORTS: &'static [&'static str] = &[
        "ReflectiveLoader",
        "DllMain", // may indicate self-loading
        "_ReflectiveLoader",
        "reflective_loader",
    ];

    /// Byte signature for the common Metasploit reflective loader prologue.
    /// `55 8B EC 83 E4 F8` (x86) push ebp / mov ebp,esp / and esp,-8
    pub const X86_REFLECTIVE_PROLOGUE: &'static [u8] = &[0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF8];

    /// x64 version: `40 53 48 83 EC 20` push rbx / sub rsp, 0x20
    pub const X64_REFLECTIVE_PROLOGUE: &'static [u8] = &[0x40, 0x53, 0x48, 0x83, 0xEC, 0x20];

    /// A generic heuristic: presence of a call immediately after `call $+5` for
    /// PIC stub: `E8 00 00 00 00 5B` (call $+5; pop rbx).
    pub const PIC_STUB: &'static [u8] = &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B];

    /// Returns `true` if `data` contains any of the known reflective loader byte patterns.
    #[must_use]
    pub fn scan(data: &[u8]) -> bool {
        let patterns: &[&[u8]] = &[
            Self::X86_REFLECTIVE_PROLOGUE,
            Self::X64_REFLECTIVE_PROLOGUE,
            Self::PIC_STUB,
        ];
        for pattern in patterns {
            if contains_bytes(data, pattern) {
                return true;
            }
        }
        false
    }

    /// Returns `true` if `export_name` is a known reflective loader export.
    #[must_use]
    pub fn is_reflective_export(export_name: &str) -> bool {
        Self::REFLECTIVE_EXPORTS
            .iter()
            .any(|&e| export_name.eq_ignore_ascii_case(e))
    }
}

/// Returns `true` if `haystack` contains `needle`.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ─── HollowingDetector ────────────────────────────────────────────────────────

/// Detects process hollowing by comparing in-memory PE headers against
/// the file on disk.
pub struct HollowingDetector;

impl HollowingDetector {
    /// Heuristic: check if the MZ header at `base` looks like it has been
    /// replaced.  In real hollowing the PE optional header will reference a
    /// different entry point than the disk image.
    ///
    /// This stub checks that:
    /// 1. The first two bytes are `MZ`.
    /// 2. The PE signature at offset `[0x3C]` is valid.
    /// 3. The entry-point RVA in the optional header is non-zero.
    #[must_use]
    pub fn check_pe_header(in_memory: &[u8]) -> PeHeaderStatus {
        if in_memory.len() < 0x40 {
            return PeHeaderStatus::TooShort;
        }
        if in_memory[0] != b'M' || in_memory[1] != b'Z' {
            return PeHeaderStatus::InvalidMz;
        }
        let pe_off =
            u32::from_le_bytes(in_memory[0x3C..0x40].try_into().unwrap_or([0; 4])) as usize;
        if pe_off + 4 > in_memory.len() {
            return PeHeaderStatus::InvalidPeOffset;
        }
        if &in_memory[pe_off..pe_off + 4] != b"PE\0\0" {
            return PeHeaderStatus::InvalidPeSignature;
        }
        // Optional header starts at pe_off + 24.
        let opt_off = pe_off + 24;
        if opt_off + 24 > in_memory.len() {
            return PeHeaderStatus::TruncatedOptionalHeader;
        }
        // Entry point RVA at opt_off + 16 (both PE32 and PE32+).
        let ep_rva = u32::from_le_bytes(
            in_memory[opt_off + 16..opt_off + 20]
                .try_into()
                .unwrap_or([0; 4]),
        );
        if ep_rva == 0 {
            return PeHeaderStatus::ZeroEntryPoint;
        }
        PeHeaderStatus::Valid {
            entry_point_rva: ep_rva,
        }
    }

    /// Compare in-memory and on-disk PE headers.
    ///
    /// Returns `true` if the headers differ (potential hollowing).
    #[must_use]
    pub fn headers_differ(in_memory: &[u8], on_disk: &[u8]) -> bool {
        // Compare only the first 0x200 bytes (standard PE header region).
        let len = in_memory.len().min(on_disk.len()).min(0x200);
        if len == 0 {
            return false;
        }
        in_memory[..len] != on_disk[..len]
    }

    /// Analyse a module record for hollowing signs.
    #[must_use]
    pub fn analyse(module: &InjectedModule, in_memory: &[u8]) -> HollowingAnalysis {
        let header_status = Self::check_pe_header(in_memory);
        let is_valid_pe = matches!(header_status, PeHeaderStatus::Valid { .. });
        let suspicious = !is_valid_pe || !module.header_matches_disk;

        HollowingAnalysis {
            pid: module.target_pid,
            base_address: module.base_address,
            header_status,
            header_matches_disk: module.header_matches_disk,
            suspicious,
        }
    }
}

/// Result of a PE header status check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeHeaderStatus {
    /// Valid PE with the given entry-point RVA.
    Valid { entry_point_rva: u32 },
    /// Buffer too short to contain a valid MZ header.
    TooShort,
    /// First two bytes are not `MZ`.
    InvalidMz,
    /// PE offset at `[0x3C]` points outside the buffer.
    InvalidPeOffset,
    /// `PE\0\0` signature not found at the expected offset.
    InvalidPeSignature,
    /// Optional header is truncated.
    TruncatedOptionalHeader,
    /// Entry-point RVA is zero (suspicious for non-DLL images).
    ZeroEntryPoint,
}

impl PeHeaderStatus {
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid { .. })
    }
}

/// Result of a hollowing analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HollowingAnalysis {
    /// Target process PID.
    pub pid: u32,
    /// Module base address.
    pub base_address: u64,
    /// Status of the in-memory PE header.
    pub header_status: PeHeaderStatus,
    /// True if in-memory header matches the disk file.
    pub header_matches_disk: bool,
    /// True if the module shows signs of hollowing.
    pub suspicious: bool,
}

// ─── InjectionDetector ────────────────────────────────────────────────────────

/// Scans a process's module list for injected DLLs.
pub struct InjectionDetector {
    /// Trusted paths — modules from these directories are not flagged.
    trusted_dirs: Vec<String>,
    /// Trusted module names (lowercased).
    trusted_names: Vec<String>,
}

impl InjectionDetector {
    #[must_use]
    pub fn new() -> Self {
        let trusted_dirs = vec![
            r"c:\windows\system32\".to_lowercase(),
            r"c:\windows\syswow64\".to_lowercase(),
            r"c:\windows\".to_lowercase(),
        ];
        let trusted_names = vec![
            "ntdll.dll".into(),
            "kernel32.dll".into(),
            "kernelbase.dll".into(),
            "user32.dll".into(),
            "advapi32.dll".into(),
            "ws2_32.dll".into(),
            "msvcrt.dll".into(),
            "combase.dll".into(),
            "rpcrt4.dll".into(),
            "sechost.dll".into(),
        ];
        Self {
            trusted_dirs,
            trusted_names,
        }
    }

    /// Add a trusted directory.
    pub fn trust_dir(&mut self, dir: impl Into<String>) {
        self.trusted_dirs.push(dir.into().to_lowercase());
    }

    /// Add a trusted module name.
    pub fn trust_name(&mut self, name: impl Into<String>) {
        self.trusted_names.push(name.into().to_lowercase());
    }

    /// Returns `true` if the module at the given path is from a trusted source.
    #[must_use]
    pub fn is_trusted(&self, path: &str, name: &str) -> bool {
        let path_lower = path.to_lowercase();
        let name_lower = name.to_lowercase();
        if self.trusted_names.iter().any(|t| t == &name_lower) {
            return true;
        }
        self.trusted_dirs
            .iter()
            .any(|dir| path_lower.starts_with(dir.as_str()))
    }

    /// Scan a list of loaded modules for injection signs.
    ///
    /// Returns all modules that appear injected or suspicious.
    #[must_use]
    pub fn scan_modules<'a>(&self, modules: &'a [InjectedModule]) -> Vec<&'a InjectedModule> {
        modules
            .iter()
            .filter(|m| !self.is_trusted(&m.path, &m.name) && m.is_suspicious())
            .collect()
    }

    /// Scan for modules present in memory but absent from the PEB module list.
    #[must_use]
    pub fn find_hidden_modules<'a>(
        &self,
        modules: &'a [InjectedModule],
    ) -> Vec<&'a InjectedModule> {
        modules.iter().filter(|m| !m.in_peb).collect()
    }

    /// Scan for modules whose on-disk file cannot be found.
    #[must_use]
    pub fn find_fileless_modules<'a>(
        &self,
        modules: &'a [InjectedModule],
    ) -> Vec<&'a InjectedModule> {
        modules.iter().filter(|m| !m.file_on_disk).collect()
    }

    /// Build a summary report.
    #[must_use]
    pub fn summarise(&self, modules: &[InjectedModule]) -> InjectionSummary {
        let suspicious = self.scan_modules(modules);
        let hidden = self.find_hidden_modules(modules);
        let fileless = self.find_fileless_modules(modules);

        let mut by_method: HashMap<String, usize> = HashMap::new();
        for m in &suspicious {
            let key = m.method.map_or_else(|| "Unknown".into(), |m| m.to_string());
            *by_method.entry(key).or_insert(0) += 1;
        }

        InjectionSummary {
            total_modules: modules.len(),
            suspicious_count: suspicious.len(),
            hidden_count: hidden.len(),
            fileless_count: fileless.len(),
            by_method,
            highest_confidence: suspicious
                .iter()
                .map(|m| m.confidence)
                .fold(0.0f64, f64::max),
        }
    }
}

impl Default for InjectionDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary of an injection scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionSummary {
    pub total_modules: usize,
    pub suspicious_count: usize,
    pub hidden_count: usize,
    pub fileless_count: usize,
    pub by_method: HashMap<String, usize>,
    pub highest_confidence: f64,
}

impl InjectionSummary {
    /// Returns `true` if any suspicious activity was detected.
    #[must_use]
    pub const fn has_findings(&self) -> bool {
        self.suspicious_count > 0 || self.hidden_count > 0 || self.fileless_count > 0
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn clean_module(pid: u32, name: &str, path: &str) -> InjectedModule {
        InjectedModule::new(pid, 0x7FF8_0000_0000, 0x10000, name, path)
    }

    fn injected_module(pid: u32, name: &str) -> InjectedModule {
        let mut m = InjectedModule::new(pid, 0x0001_4000_0000, 0x20000, name, r"C:\Temp\evil.dll");
        m.in_peb = false;
        m.file_on_disk = false;
        m.confidence = 0.9;
        m.method = Some(DllInjectionMethod::Reflective);
        m
    }

    // ── DllInjectionMethod ────────────────────────────────────────────────────

    #[test]
    fn injection_method_display() {
        assert_eq!(
            DllInjectionMethod::CreateRemoteThread.to_string(),
            "CreateRemoteThread"
        );
        assert_eq!(DllInjectionMethod::ManualMap.to_string(), "Manual Mapping");
        assert_eq!(DllInjectionMethod::Reflective.to_string(), "Reflective DLL");
    }

    #[test]
    fn injection_method_weights() {
        assert!(DllInjectionMethod::Reflective.suspicion_weight() > 90);
        assert!(
            DllInjectionMethod::SetWindowsHookEx.suspicion_weight()
                < DllInjectionMethod::ManualMap.suspicion_weight()
        );
    }

    // ── InjectedModule ────────────────────────────────────────────────────────

    #[test]
    fn injected_module_is_suspicious_when_not_in_peb() {
        let mut m = clean_module(1, "test.dll", r"C:\Windows\System32\test.dll");
        assert!(!m.is_suspicious());
        m.in_peb = false;
        assert!(m.is_suspicious());
    }

    #[test]
    fn injected_module_is_suspicious_when_no_disk_file() {
        let mut m = clean_module(1, "x.dll", r"C:\Windows\System32\x.dll");
        m.file_on_disk = false;
        assert!(m.is_suspicious());
    }

    #[test]
    fn injected_module_is_suspicious_high_confidence() {
        let mut m = clean_module(1, "y.dll", r"C:\Windows\y.dll");
        m.confidence = 0.9;
        assert!(m.is_suspicious());
    }

    #[test]
    fn injected_module_add_note() {
        let mut m = clean_module(1, "n.dll", "");
        m.add_note("suspicious export");
        assert_eq!(m.notes.len(), 1);
    }

    #[test]
    fn injected_module_csv_row() {
        let m = injected_module(100, "evil.dll");
        let row = m.to_csv_row();
        assert!(row.contains("100"));
        assert!(row.contains("evil.dll"));
        assert!(row.contains("suspicious"));
    }

    /// The module name comes from the target process, so a comma in it is the
    /// target's choice. Unquoted it shifted every later column, moving the
    /// suspicious/clean verdict onto the wrong module — the one thing this row
    /// exists to report.
    #[test]
    fn injected_module_csv_row_quotes_names_with_delimiters() {
        let m = injected_module(100, "eq,uivocal.dll");
        let row = m.to_csv_row();

        assert!(row.contains("\"eq,uivocal.dll\""), "name was not quoted: {row:?}");
        assert_eq!(row.lines().count(), 1, "row spans several lines: {row:?}");

        // Split the way an RFC 4180 reader does — commas inside quotes are data.
        let mut fields = Vec::new();
        let (mut cur, mut in_quotes) = (String::new(), false);
        for ch in row.chars() {
            match ch {
                '"' => in_quotes = !in_quotes,
                ',' if !in_quotes => fields.push(std::mem::take(&mut cur)),
                c => cur.push(c),
            }
        }
        fields.push(cur);

        assert_eq!(fields.len(), 6, "wrong field count: {fields:?}");
        assert_eq!(fields[2], "eq,uivocal.dll", "name field mangled: {fields:?}");
        assert!(
            fields[4] == "suspicious" || fields[4] == "clean",
            "the verdict is no longer in column 5: {fields:?}"
        );
    }

    // ── ReflectiveDllSignature ────────────────────────────────────────────────

    #[test]
    fn reflective_scan_finds_x86_prologue() {
        let mut data = vec![0u8; 256];
        let prologue = ReflectiveDllSignature::X86_REFLECTIVE_PROLOGUE;
        data[100..100 + prologue.len()].copy_from_slice(prologue);
        assert!(ReflectiveDllSignature::scan(&data));
    }

    #[test]
    fn reflective_scan_finds_x64_prologue() {
        let mut data = vec![0u8; 256];
        let prologue = ReflectiveDllSignature::X64_REFLECTIVE_PROLOGUE;
        data[50..50 + prologue.len()].copy_from_slice(prologue);
        assert!(ReflectiveDllSignature::scan(&data));
    }

    #[test]
    fn reflective_scan_clean_data() {
        let data = vec![0xCC_u8; 256];
        assert!(!ReflectiveDllSignature::scan(&data));
    }

    #[test]
    fn reflective_export_check() {
        assert!(ReflectiveDllSignature::is_reflective_export(
            "ReflectiveLoader"
        ));
        assert!(ReflectiveDllSignature::is_reflective_export(
            "REFLECTIVELOADER"
        ));
        assert!(!ReflectiveDllSignature::is_reflective_export(
            "DllGetClassObject"
        ));
    }

    // ── HollowingDetector ─────────────────────────────────────────────────────

    #[test]
    fn pe_header_valid() {
        let mut pe = vec![0u8; 0x200];
        pe[0] = b'M';
        pe[1] = b'Z';
        // PE offset at 0x3C
        pe[0x3C] = 0x40;
        // PE signature
        pe[0x40] = b'P';
        pe[0x41] = b'E';
        pe[0x42] = 0;
        pe[0x43] = 0;
        // Optional header at 0x40 + 24 = 0x58; entry point RVA at +16 = 0x68
        pe[0x68] = 0x00;
        pe[0x69] = 0x10;
        pe[0x6A] = 0x00;
        pe[0x6B] = 0x00;
        let status = HollowingDetector::check_pe_header(&pe);
        assert!(status.is_valid());
    }

    #[test]
    fn pe_header_invalid_mz() {
        let pe = vec![0u8; 0x200];
        let status = HollowingDetector::check_pe_header(&pe);
        assert_eq!(status, PeHeaderStatus::InvalidMz);
    }

    #[test]
    fn pe_header_too_short() {
        let pe = vec![b'M', b'Z'];
        let status = HollowingDetector::check_pe_header(&pe);
        assert_eq!(status, PeHeaderStatus::TooShort);
    }

    #[test]
    fn hollowing_headers_differ() {
        let mem = vec![0xAA_u8; 0x200];
        let disk = vec![0xBB_u8; 0x200];
        assert!(HollowingDetector::headers_differ(&mem, &disk));
    }

    #[test]
    fn hollowing_headers_match() {
        let data = vec![0x55_u8; 0x200];
        assert!(!HollowingDetector::headers_differ(&data, &data));
    }

    #[test]
    fn hollowing_analyse_suspicious() {
        let mut m = clean_module(1, "x.dll", "");
        m.header_matches_disk = false;
        let analysis = HollowingDetector::analyse(&m, &vec![0u8; 256]);
        assert!(analysis.suspicious);
    }

    // ── InjectionDetector ─────────────────────────────────────────────────────

    #[test]
    fn detector_is_trusted_system32() {
        let det = InjectionDetector::new();
        assert!(det.is_trusted(r"C:\Windows\System32\ntdll.dll", "ntdll.dll"));
    }

    #[test]
    fn detector_is_trusted_by_name() {
        let det = InjectionDetector::new();
        assert!(det.is_trusted("anywhere", "ntdll.dll"));
    }

    #[test]
    fn detector_not_trusted_temp() {
        let det = InjectionDetector::new();
        assert!(!det.is_trusted(r"C:\Temp\evil.dll", "evil.dll"));
    }

    #[test]
    fn detector_scan_finds_injected() {
        let det = InjectionDetector::new();
        let modules = vec![
            clean_module(1, "ntdll.dll", r"C:\Windows\System32\ntdll.dll"),
            injected_module(1, "evil.dll"),
        ];
        let found = det.scan_modules(&modules);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "evil.dll");
    }

    #[test]
    fn detector_find_hidden_modules() {
        let det = InjectionDetector::new();
        let modules = vec![
            injected_module(1, "hidden.dll"),
            clean_module(1, "ntdll.dll", r"C:\Windows\System32\ntdll.dll"),
        ];
        let hidden = det.find_hidden_modules(&modules);
        assert_eq!(hidden.len(), 1);
    }

    #[test]
    fn detector_find_fileless_modules() {
        let det = InjectionDetector::new();
        let modules = vec![injected_module(1, "nofile.dll")];
        let fileless = det.find_fileless_modules(&modules);
        assert_eq!(fileless.len(), 1);
    }

    #[test]
    fn detector_summarise_clean() {
        let det = InjectionDetector::new();
        let modules = vec![clean_module(
            1,
            "ntdll.dll",
            r"C:\Windows\System32\ntdll.dll",
        )];
        let summary = det.summarise(&modules);
        assert!(!summary.has_findings());
    }

    #[test]
    fn detector_summarise_with_injection() {
        let det = InjectionDetector::new();
        let modules = vec![injected_module(1, "bad.dll")];
        let summary = det.summarise(&modules);
        assert!(summary.has_findings());
        assert!(summary.highest_confidence > 0.5);
    }

    #[test]
    fn detector_trust_custom_dir() {
        let mut det = InjectionDetector::new();
        det.trust_dir(r"C:\MyApp\");
        assert!(det.is_trusted(r"C:\MyApp\module.dll", "module.dll"));
    }

    #[test]
    fn contains_bytes_helper() {
        assert!(contains_bytes(b"hello world", b"world"));
        assert!(!contains_bytes(b"hello", b"world"));
        assert!(contains_bytes(b"abc", b"abc"));
        assert!(!contains_bytes(b"", b"x"));
    }

    #[test]
    fn pe_header_status_is_valid() {
        let s = PeHeaderStatus::Valid {
            entry_point_rva: 0x1000,
        };
        assert!(s.is_valid());
        assert!(!PeHeaderStatus::InvalidMz.is_valid());
    }
}
