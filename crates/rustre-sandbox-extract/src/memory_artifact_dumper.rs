//! Memory artifact dumper: captures and analyzes memory regions written by a
//! sandboxed sample, identifying injected shellcode, heap-allocated strings,
//! decrypted payloads, and hollowed process images.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;

/// Lossless helper: `usize` → `f64` (precision may degrade on 64-bit).
const fn usize_as_f64(n: usize) -> f64 { n as f64 }

/// Lossless helper: `u64` → `f64` (precision may degrade above 2^53).
const fn u64_as_f64(n: u64) -> f64 { n as f64 }

/// Lossless helper: `usize` → `u64` (always fits on 64-bit; smaller on 32-bit).
const fn usize_as_u64(n: usize) -> u64 { n as u64 }

// ─────────────────────────────────────────────────────────────────────────────
// MemoryArtifact
// ─────────────────────────────────────────────────────────────────────────────

/// The classification of a memory artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemArtifactKind {
    /// Executable code written at runtime (shellcode / injected PE)
    InjectedCode,
    /// PE image mapped into a foreign process
    HollowedProcess,
    /// String extracted from heap or stack
    HeapString,
    /// Decrypted data block
    DecryptedBlob,
    /// Unpacked PE payload
    UnpackedPe,
    /// Credential material (high-entropy, matches patterns)
    Credential,
    /// Reflectively loaded DLL
    ReflectiveDll,
    /// Configuration block
    Config,
    /// Unknown / unclassified
    Unknown,
}

impl fmt::Display for MemArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::InjectedCode    => "InjectedCode",
            Self::HollowedProcess => "HollowedProcess",
            Self::HeapString      => "HeapString",
            Self::DecryptedBlob   => "DecryptedBlob",
            Self::UnpackedPe      => "UnpackedPe",
            Self::Credential      => "Credential",
            Self::ReflectiveDll   => "ReflectiveDll",
            Self::Config          => "Config",
            Self::Unknown         => "Unknown",
        };
        write!(f, "{s}")
    }
}

/// Metadata for a region of memory captured from a live (simulated) process.
#[derive(Debug, Clone)]
pub struct MemoryArtifact {
    pub kind: MemArtifactKind,
    pub base_address: u64,
    pub size: usize,
    pub pid: u32,
    /// Content bytes (up to the limit in `DumperConfig`).
    pub data: Vec<u8>,
    pub protection: MemProtection,
    pub tags: Vec<String>,
    /// Shannon entropy of the data (0.0–8.0).
    pub entropy: f64,
    /// Detected content type (e.g. `"PE"`, `"shellcode"`, `"text"`).
    pub content_type: String,
    /// Source region description (e.g. `"heap"`, `"stack"`, `"VirtualAlloc"`).
    pub source: String,
}

impl MemoryArtifact {
    #[must_use]
    pub fn new(base_address: u64, data: Vec<u8>, pid: u32, prot: MemProtection) -> Self {
        let entropy = Self::shannon_entropy(&data);
        let content_type = Self::detect_content(&data);
        let size = data.len();
        Self {
            kind: MemArtifactKind::Unknown,
            base_address,
            size,
            pid,
            data,
            protection: prot,
            tags: Vec::new(),
            entropy,
            content_type,
            source: String::new(),
        }
    }

    /// Compute Shannon entropy of the data (bits per byte, 0.0–8.0).
    #[must_use]
    pub fn shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() { return 0.0; }
        let mut counts = [0u64; 256];
        for &b in data { counts[b as usize] += 1; }
        let n = usize_as_f64(data.len());
        let mut h = 0.0f64;
        for &c in &counts {
            if c > 0 {
                let p = u64_as_f64(c) / n;
                h -= p * p.log2();
            }
        }
        h
    }

    /// Heuristically detect the content type from leading bytes.
    #[must_use]
    pub fn detect_content(data: &[u8]) -> String {
        if data.len() < 2 { return "empty".to_string(); }
        if data.starts_with(b"MZ")           { return "PE".to_string(); }
        if data.starts_with(b"\x7fELF")      { return "ELF".to_string(); }
        if data.starts_with(b"PK\x03\x04")   { return "ZIP".to_string(); }
        // Common shellcode prologue: 64-bit: 0x48 0x8b (MOV RSP-based), 32-bit: 0x55 (PUSH EBP)
        if data[0] == 0x55 && data[1] == 0x8b { return "shellcode_x86".to_string(); }
        if data[0] == 0x48 && data[1] == 0x8b { return "shellcode_x64".to_string(); }
        if data[0] == 0xfc && data[1] == 0x48 { return "shellcode_x64_cs".to_string(); } // CobaltStrike beacon
        // All printable ASCII → string data
        if data.iter().take(32).all(|&b| (0x20..0x80).contains(&b)) {
            return "text".to_string();
        }
        // High entropy binary
        let e = Self::shannon_entropy(data);
        if e > 7.5 { return "encrypted_or_compressed".to_string(); }
        "binary".to_string()
    }

    pub fn add_tag(&mut self, t: impl Into<String>) {
        let s = t.into();
        if !self.tags.contains(&s) { self.tags.push(s); }
    }

    #[must_use]
    pub fn is_high_entropy(&self) -> bool { self.entropy > 7.0 }
    #[must_use]
    pub fn is_executable_content(&self) -> bool {
        matches!(self.content_type.as_str(), "PE" | "ELF" | "shellcode_x86" | "shellcode_x64" | "shellcode_x64_cs")
    }

    /// Read a null-terminated string at `offset` within the data.
    #[must_use]
    pub fn read_cstring(&self, offset: usize) -> Option<String> {
        if offset >= self.data.len() { return None; }
        let end = self.data[offset..].iter().position(|&b| b == 0).unwrap_or(self.data.len() - offset);
        String::from_utf8(self.data[offset..offset+end].to_vec()).ok()
    }
}

impl fmt::Display for MemoryArtifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] 0x{:016x} pid={} size={} entropy={:.2} type={}",
            self.kind, self.base_address, self.pid, self.size, self.entropy, self.content_type)
    }
}

/// Memory protection flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemProtection {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl MemProtection {
    pub const RWX: Self = Self { read: true,  write: true,  execute: true };
    pub const RW:  Self = Self { read: true,  write: true,  execute: false };
    pub const RX:  Self = Self { read: true,  write: false, execute: true };
    pub const R:   Self = Self { read: true,  write: false, execute: false };
    pub const NONE: Self = Self { read: false, write: false, execute: false };

    /// Parse from Windows PAGE_* constants.
    #[must_use]
    pub const fn from_windows_protect(p: u32) -> Self {
        match p {
            0x10 | 0x20 => Self::RX,           // PAGE_EXECUTE / PAGE_EXECUTE_READ
            0x40 => Self::RWX,                  // PAGE_EXECUTE_READWRITE
            0x04 => Self::RW,                   // PAGE_READWRITE
            0x02 => Self::R,
            _    => Self::NONE,
        }
    }
}

impl fmt::Display for MemProtection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}{}",
            if self.read    { "r" } else { "-" },
            if self.write   { "w" } else { "-" },
            if self.execute { "x" } else { "-" })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InjectedCode
// ─────────────────────────────────────────────────────────────────────────────

/// Describes a block of code injected into a process.
#[derive(Debug, Clone)]
pub struct InjectedCode {
    pub artifact: MemoryArtifact,
    /// Target PID if cross-process injection, else same as artifact.pid.
    pub target_pid: u32,
    /// Injection technique detected.
    pub technique: InjectionTechnique,
    /// Address of the injected entry point, if found.
    pub entry_point: Option<u64>,
}

/// Known injection techniques.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InjectionTechnique {
    VirtualAllocEx,
    WriteProcessMemory,
    ProcessHollowing,
    ProcessDoppelganging,
    AtomBombing,
    ReflectiveDllInjection,
    ManualMap,
    NtUnmapViewOfSection,
    CreateRemoteThread,
    Unknown,
}

impl fmt::Display for InjectionTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::VirtualAllocEx        => "VirtualAllocEx",
            Self::WriteProcessMemory    => "WriteProcessMemory",
            Self::ProcessHollowing      => "ProcessHollowing",
            Self::ProcessDoppelganging  => "ProcessDoppelganging",
            Self::AtomBombing           => "AtomBombing",
            Self::ReflectiveDllInjection => "ReflectiveDLLInjection",
            Self::ManualMap             => "ManualMap",
            Self::NtUnmapViewOfSection  => "NtUnmapViewOfSection",
            Self::CreateRemoteThread    => "CreateRemoteThread",
            Self::Unknown               => "Unknown",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HeapString
// ─────────────────────────────────────────────────────────────────────────────

/// An interesting string extracted from heap memory.
#[derive(Debug, Clone)]
pub struct HeapString {
    pub value: String,
    pub address: u64,
    pub pid: u32,
    pub encoding: StringEncoding,
    pub context: StringContext,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringEncoding { Ascii, Utf16Le, Utf8 }

impl fmt::Display for StringEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ascii    => write!(f, "ASCII"),
            Self::Utf16Le  => write!(f, "UTF-16LE"),
            Self::Utf8     => write!(f, "UTF-8"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringContext {
    Url, FilePath, RegistryKey, Command, DomainName, IpAddress, ApiName, Config, Unknown
}

impl fmt::Display for StringContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Url         => "URL",
            Self::FilePath    => "FilePath",
            Self::RegistryKey => "RegistryKey",
            Self::Command     => "Command",
            Self::DomainName  => "Domain",
            Self::IpAddress   => "IP",
            Self::ApiName     => "API",
            Self::Config      => "Config",
            Self::Unknown     => "Unknown",
        };
        write!(f, "{s}")
    }
}

impl HeapString {
    #[must_use]
    pub fn classify(s: &str) -> StringContext {
        let low = s.to_ascii_lowercase();
        if low.starts_with("http://") || low.starts_with("https://") || low.starts_with("ftp://") {
            return StringContext::Url;
        }
        if low.starts_with("hkey_") || low.starts_with("software\\") || low.starts_with("system\\") {
            return StringContext::RegistryKey;
        }
        if low.starts_with("c:\\") || low.starts_with("c:/") || low.starts_with("/tmp/") || low.starts_with("/var/") {
            return StringContext::FilePath;
        }
        // Simple IP heuristic
        if s.chars().filter(|c| *c == '.').count() == 3
            && s.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return StringContext::IpAddress;
        }
        // Domain
        if s.contains('.') && !s.contains(' ') && s.len() < 253 {
            let parts: Vec<&str> = s.split('.').collect();
            if parts.len() >= 2 && parts.last().is_some_and(|p| p.len() >= 2) {
                return StringContext::DomainName;
            }
        }
        StringContext::Unknown
    }
}

impl fmt::Display for HeapString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}@{:#016x}] ({}) {:?}", self.context, self.address, self.encoding, self.value)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryDump
// ─────────────────────────────────────────────────────────────────────────────

/// A full or partial process memory dump.
#[derive(Debug, Clone, Default)]
pub struct MemoryDump {
    /// Process ID.
    pub pid: u32,
    /// Process image name.
    pub process_name: String,
    /// All captured memory regions.
    pub regions: Vec<MemoryArtifact>,
    /// Interesting strings extracted from the dump.
    pub strings: Vec<HeapString>,
    /// Injected code sections found.
    pub injected: Vec<InjectedCode>,
    /// High-entropy (encrypted/packed) regions.
    pub high_entropy_regions: Vec<u64>,
    /// Any PE files found embedded in the dump.
    pub embedded_pes: Vec<(u64, usize)>,
}

impl MemoryDump {
    #[must_use]
    pub fn new(pid: u32, process_name: impl Into<String>) -> Self {
        Self { pid, process_name: process_name.into(), ..Default::default() }
    }

    pub fn add_region(&mut self, region: MemoryArtifact) {
        if region.is_high_entropy() {
            self.high_entropy_regions.push(region.base_address);
        }
        if region.content_type == "PE" {
            self.embedded_pes.push((region.base_address, region.size));
        }
        self.regions.push(region);
    }

    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.regions.iter().map(|r| r.size).sum()
    }

    #[must_use]
    pub fn executable_regions(&self) -> Vec<&MemoryArtifact> {
        self.regions.iter().filter(|r| r.protection.execute).collect()
    }
}

impl fmt::Display for MemoryDump {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MemoryDump[pid={}] {} regions {} bytes {} strings {} injected {} PE(s)",
            self.pid, self.regions.len(), self.total_bytes(),
            self.strings.len(), self.injected.len(), self.embedded_pes.len())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DumperConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the memory artifact dumper.
#[derive(Debug, Clone)]
pub struct DumperConfig {
    /// Maximum bytes to store per region.
    pub max_region_bytes: usize,
    /// Minimum size of a region to consider.
    pub min_region_bytes: usize,
    /// Whether to extract strings from all regions.
    pub extract_strings: bool,
    /// Minimum string length to extract.
    pub min_string_len: usize,
    /// Entropy threshold above which a region is flagged as high-entropy.
    pub entropy_threshold: f64,
    /// Whether to detect injection techniques.
    pub detect_injection: bool,
    /// Only capture executable regions.
    pub only_executable: bool,
}

impl Default for DumperConfig {
    fn default() -> Self {
        Self {
            max_region_bytes: 4 * 1024 * 1024,
            min_region_bytes: 64,
            extract_strings: true,
            min_string_len: 6,
            entropy_threshold: 7.0,
            detect_injection: true,
            only_executable: false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryArtifactDumper
// ─────────────────────────────────────────────────────────────────────────────

/// Processes raw memory regions and produces structured `MemoryArtifact` records.
#[derive(Debug)]
pub struct MemoryArtifactDumper {
    config: DumperConfig,
    dumps: HashMap<u32, MemoryDump>,
}

impl MemoryArtifactDumper {
    #[must_use]
    pub fn new(config: DumperConfig) -> Self {
        Self { config, dumps: HashMap::new() }
    }

    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(DumperConfig::default())
    }

    /// Ingest a raw memory region from a process.
    pub fn ingest_region(
        &mut self,
        pid: u32,
        process_name: &str,
        base: u64,
        data: &[u8],
        prot: MemProtection,
        source: impl Into<String>,
    ) {
        if data.len() < self.config.min_region_bytes { return; }
        if self.config.only_executable && !prot.execute { return; }

        let capped: Vec<u8> = data.iter()
            .take(self.config.max_region_bytes)
            .copied()
            .collect();

        let mut artifact = MemoryArtifact::new(base, capped, pid, prot);
        artifact.source = source.into();
        artifact.kind = Self::classify_artifact(&artifact);

        if artifact.is_high_entropy() { artifact.add_tag("high_entropy"); }
        if artifact.is_executable_content() { artifact.add_tag("executable_content"); }
        if prot.execute && prot.write { artifact.add_tag("rwx"); }

        let strings = if self.config.extract_strings {
            self.extract_strings(&artifact)
        } else {
            Vec::new()
        };

        let dump = self.dumps.entry(pid)
            .or_insert_with(|| MemoryDump::new(pid, process_name));

        if self.config.extract_strings {
            dump.strings.extend(strings);
        }

        if self.config.detect_injection && prot.execute && artifact.kind == MemArtifactKind::InjectedCode {
            let inj = InjectedCode {
                target_pid: pid,
                entry_point: Some(base),
                technique: InjectionTechnique::Unknown,
                artifact: artifact.clone(),
            };
            dump.injected.push(inj);
        }

        dump.add_region(artifact);
    }

    fn classify_artifact(a: &MemoryArtifact) -> MemArtifactKind {
        if a.content_type == "PE" {
            if a.protection.execute {
                return MemArtifactKind::HollowedProcess;
            }
            return MemArtifactKind::UnpackedPe;
        }
        if a.is_executable_content() { return MemArtifactKind::InjectedCode; }
        if a.is_high_entropy()       { return MemArtifactKind::DecryptedBlob; }
        if a.content_type == "text"  { return MemArtifactKind::HeapString; }
        MemArtifactKind::Unknown
    }

    /// Extract ASCII and UTF-16LE strings from a memory artifact.
    #[must_use]
    pub fn extract_strings(&self, artifact: &MemoryArtifact) -> Vec<HeapString> {
        let mut result = Vec::new();
        let min = self.config.min_string_len;
        let data = &artifact.data;

        // ASCII extraction
        let mut run_start = 0usize;
        let mut run_len = 0usize;
        for (i, &b) in data.iter().enumerate() {
            if (0x20..0x80).contains(&b) {
                if run_len == 0 { run_start = i; }
                run_len += 1;
            } else {
                if run_len >= min {
                    let s = String::from_utf8_lossy(&data[run_start..run_start+run_len]).to_string();
                    let ctx = HeapString::classify(&s);
                    result.push(HeapString {
                        value: s,
                        address: artifact.base_address + usize_as_u64(run_start),
                        pid: artifact.pid,
                        encoding: StringEncoding::Ascii,
                        context: ctx,
                    });
                }
                run_len = 0;
            }
        }
        if run_len >= min {
            let s = String::from_utf8_lossy(&data[run_start..run_start+run_len]).to_string();
            let ctx = HeapString::classify(&s);
            result.push(HeapString {
                value: s,
                address: artifact.base_address + usize_as_u64(run_start),
                pid: artifact.pid,
                encoding: StringEncoding::Ascii,
                context: ctx,
            });
        }

        // UTF-16LE extraction
        if data.len() >= min * 2 {
            let mut wrun_start = 0usize;
            let mut wchars: Vec<u16> = Vec::new();
            let mut i = 0usize;
            while i + 1 < data.len() {
                let w = u16::from_le_bytes([data[i], data[i+1]]);
                if (0x20..0x80).contains(&w) {
                    if wchars.is_empty() { wrun_start = i; }
                    wchars.push(w);
                } else {
                    if wchars.len() >= min {
                        let s: String = wchars.iter().map(|&c| u8::try_from(c).unwrap_or(b'?') as char).collect();
                        let ctx = HeapString::classify(&s);
                        result.push(HeapString {
                            value: s,
                            address: artifact.base_address + usize_as_u64(wrun_start),
                            pid: artifact.pid,
                            encoding: StringEncoding::Utf16Le,
                            context: ctx,
                        });
                    }
                    wchars.clear();
                }
                i += 2;
            }
        }
        result
    }

    /// Return all collected dumps.
    pub fn dumps(&self) -> impl Iterator<Item = &MemoryDump> {
        self.dumps.values()
    }

    /// Return the dump for a given PID, if any.
    #[must_use]
    pub fn dump_for_pid(&self, pid: u32) -> Option<&MemoryDump> {
        self.dumps.get(&pid)
    }

    /// Return total number of regions ingested across all processes.
    #[must_use]
    pub fn total_regions(&self) -> usize {
        self.dumps.values().map(|d| d.regions.len()).sum()
    }

    /// Build a summary report of all dumps.
    #[must_use]
    pub fn build_summary(&self) -> String {
        let num = self.dumps.len();
        let mut out = String::new();
        let _ = writeln!(out, "MemoryArtifactDumper: {num} process dumps");
        for dump in self.dumps.values() {
            let _ = writeln!(out, "  {dump}");
            for inj in &dump.injected {
                let art = &inj.artifact;
                let tech = &inj.technique;
                let _ = writeln!(out, "    [INJECTION] {art} via {tech}");
            }
            for (addr, size) in &dump.embedded_pes {
                let _ = writeln!(out, "    [PE FOUND] 0x{addr:016x} ({size} bytes)");
            }
        }
        out
    }
}
