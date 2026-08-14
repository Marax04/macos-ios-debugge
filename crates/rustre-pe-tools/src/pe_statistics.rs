//! `pe_statistics` — PE statistical analysis
//!
//! Produces a rich set of metrics about a PE binary:
//!
//! * Entropy distribution per section (min / max / mean / histogram).
//! * API calls categorised by function set (file I/O, networking, process,
//!   cryptography, anti-debug, COM, registry, etc.).
//! * Import diversity score (number of unique DLLs × normalised).
//! * String content analysis: extract printable ASCII / UTF-16 strings and
//!   classify them (file paths, URLs, IP addresses, registry keys).
//! * Size breakdown (headers vs. code vs. data vs. resources vs. overlay).
//! * Packed / obfuscated probability score.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Entropy distribution
// ---------------------------------------------------------------------------

/// Per-section entropy statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionEntropy {
    /// Section name.
    pub name: String,
    /// Minimum byte-level entropy in 256-byte blocks.
    pub min: f64,
    /// Maximum byte-level entropy in 256-byte blocks.
    pub max: f64,
    /// Mean entropy over the whole section.
    pub mean: f64,
    /// Entropy of the whole section as a single block.
    pub whole: f64,
    /// 8-bucket histogram (0.0-1.0, 1.0-2.0, …, 7.0-8.0).
    pub histogram: [u32; 8],
}

impl SectionEntropy {
    /// Returns `true` if the whole-section entropy indicates encryption/packing.
    #[must_use] 
    pub fn is_high_entropy(&self) -> bool { self.whole > 7.0 }
    /// Returns `true` if the section is likely plain code (low-medium entropy).
    #[must_use] 
    pub fn is_code_range(&self) -> bool { self.whole > 3.5 && self.whole < 7.0 }
}

// ---------------------------------------------------------------------------
// API categories
// ---------------------------------------------------------------------------

/// API category names.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiCategory {
    File,
    Network,
    Process,
    Thread,
    Crypto,
    Registry,
    Memory,
    Com,
    AntiDebug,
    Injection,
    Persistence,
    UI,
    Misc,
}

impl std::fmt::Display for ApiCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::File       => "File I/O",
            Self::Network    => "Networking",
            Self::Process    => "Process",
            Self::Thread     => "Threading",
            Self::Crypto     => "Cryptography",
            Self::Registry   => "Registry",
            Self::Memory     => "Memory",
            Self::Com        => "COM",
            Self::AntiDebug  => "Anti-Debug",
            Self::Injection  => "Code Injection",
            Self::Persistence => "Persistence",
            Self::UI         => "User Interface",
            Self::Misc       => "Miscellaneous",
        };
        write!(f, "{s}")
    }
}

/// Classify an imported function name into an API category.
#[must_use] 
pub fn classify_api(fn_name: &str) -> ApiCategory {
    let n = fn_name.to_lowercase();
    // Anti-debug first (specific subset).
    if n.contains("isdebuggerpresent") || n.contains("debugbreak")
        || n.contains("ntqueryin") || n.contains("checkremovedebug")
        || n.contains("outputdebug") || n.contains("findwindow")
    {
        return ApiCategory::AntiDebug;
    }
    // Injection.
    if n.contains("virtualalloc") || n.contains("writeprocessmemory")
        || n.contains("createremotethread") || n.contains("ntmapview")
        || n.contains("setwindowshook")
    {
        return ApiCategory::Injection;
    }
    // Crypto.
    if n.starts_with("crypt") || n.starts_with("bcrypt") || n.starts_with("ncrypt")
        || n.contains("sha") || n.contains("md5") || n.contains("aes")
    {
        return ApiCategory::Crypto;
    }
    // Network.
    if n.starts_with("ws2_") || n.starts_with("wsa") || n.starts_with("inet")
        || n.contains("socket") || n.contains("connect") || n.contains("send")
        || n.contains("recv") || n.contains("http") || n.contains("url")
        || n.contains("winhttp") || n.contains("wininet") || n.contains("internet")
    {
        return ApiCategory::Network;
    }
    // Process.
    if n.contains("process") || n.contains("createproc") || n.contains("openproc")
        || n.contains("exitprocess") || n.contains("shellexec")
    {
        return ApiCategory::Process;
    }
    // Thread.
    if n.contains("thread") || n.contains("createthread") { return ApiCategory::Thread; }
    // Registry.
    if n.starts_with("reg") || n.contains("regopen") || n.contains("regquery")
        || n.contains("regset") || n.contains("regcreate")
    {
        return ApiCategory::Registry;
    }
    // File.
    if n.contains("file") || n.contains("createfile") || n.contains("readfile")
        || n.contains("writefile") || n.contains("deletefile") || n.contains("movefile")
        || n.contains("copyfile") || n.contains("findfile")
    {
        return ApiCategory::File;
    }
    // Memory.
    if n.contains("heap") || n.contains("malloc") || n.contains("free")
        || n.contains("virtual") || n.contains("globalalloc")
    {
        return ApiCategory::Memory;
    }
    // COM.
    if n.starts_with("co") || n.starts_with("ole") || n.contains("createinstance")
        || n.contains("queryinterface")
    {
        return ApiCategory::Com;
    }
    // Persistence.
    if n.contains("scheduledtask") || n.contains("service") || n.contains("autorun") {
        return ApiCategory::Persistence;
    }
    // UI.
    if n.contains("message") || n.contains("window") || n.contains("dialog")
        || n.contains("hwnd")
    {
        return ApiCategory::UI;
    }
    ApiCategory::Misc
}

// ---------------------------------------------------------------------------
// String analysis
// ---------------------------------------------------------------------------

/// Category of an extracted string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StringCategory {
    FilePath,
    Url,
    IpAddress,
    RegistryKey,
    Domain,
    Email,
    Unknown,
}

impl std::fmt::Display for StringCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::FilePath    => "File Path",
            Self::Url         => "URL",
            Self::IpAddress   => "IP Address",
            Self::RegistryKey => "Registry Key",
            Self::Domain      => "Domain",
            Self::Email       => "Email",
            Self::Unknown     => "Unknown",
        };
        write!(f, "{s}")
    }
}

/// A classified string found in the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifiedString {
    pub value: String,
    pub category: StringCategory,
    pub file_offset: usize,
    pub encoding: StringEncoding,
}

/// Encoding of a found string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringEncoding { Ascii, Utf16Le }

/// Classify a printable ASCII string.
#[must_use] 
pub fn classify_string(s: &str) -> StringCategory {
    let lo = s.to_lowercase();
    if lo.starts_with("hk") && lo.contains('\\') {
        return StringCategory::RegistryKey;
    }
    if lo.starts_with("http://") || lo.starts_with("https://") || lo.starts_with("ftp://") {
        return StringCategory::Url;
    }
    if lo.starts_with("c:\\") || lo.starts_with("\\\\") || lo.starts_with('/') {
        return StringCategory::FilePath;
    }
    if lo.contains('@') && lo.contains('.') { return StringCategory::Email; }
    // IPv4: rough heuristic — 4 groups of digits separated by dots.
    if is_ipv4(s) { return StringCategory::IpAddress; }
    // Domain: contains dot, no spaces, all allowed chars.
    if lo.contains('.') && !lo.contains(' ') && lo.len() > 4
        && lo.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return StringCategory::Domain;
    }
    StringCategory::Unknown
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 { return false; }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

/// Extract ASCII strings (min length 4) from `data`.
#[must_use] 
pub fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<ClassifiedString> {
    let mut results = Vec::new();
    let mut start: Option<usize> = None;
    for (i, &b) in data.iter().enumerate() {
        if b.is_ascii_graphic() || b == b' ' || b == b'\t' {
            if start.is_none() { start = Some(i); }
        } else if let Some(s) = start.take() {
            let len = i - s;
            if len >= min_len {
                let value = String::from_utf8_lossy(&data[s..i]).into_owned();
                let category = classify_string(&value);
                results.push(ClassifiedString {
                    value, category, file_offset: s, encoding: StringEncoding::Ascii,
                });
            }
        }
    }
    results
}

/// Extract UTF-16LE strings (min length 4 chars) from `data`.
#[must_use] 
pub fn extract_utf16le_strings(data: &[u8], min_len: usize) -> Vec<ClassifiedString> {
    let mut results = Vec::new();
    if data.len() < 2 { return results; }
    let mut start: Option<usize> = None;
    let mut i = 0;
    while i + 1 < data.len() {
        let word = u16::from_le_bytes([data[i], data[i+1]]);
        let is_printable = (0x20..0x7F).contains(&word);
        if is_printable {
            if start.is_none() { start = Some(i); }
        } else if let Some(s) = start.take() {
            let char_len = (i - s) / 2;
            if char_len >= min_len {
                let words: Vec<u16> = data[s..i]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                if let Ok(value) = String::from_utf16(&words) {
                    let category = classify_string(&value);
                    results.push(ClassifiedString {
                        value, category, file_offset: s, encoding: StringEncoding::Utf16Le,
                    });
                }
            }
        }
        i += 2;
    }
    results
}

// ---------------------------------------------------------------------------
// Size breakdown
// ---------------------------------------------------------------------------

/// PE size breakdown by region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeBreakdown {
    pub total_bytes: usize,
    pub dos_stub_bytes: usize,
    pub headers_bytes: usize,
    pub code_bytes: usize,
    pub initialized_data_bytes: usize,
    pub uninitialized_data_bytes: usize,
    pub resources_bytes: usize,
    pub overlay_bytes: usize,
}

impl SizeBreakdown {
    /// Percentage of file that is code.
    #[must_use] 
    pub fn code_fraction(&self) -> f64 {
        if self.total_bytes == 0 { return 0.0; }
        f64::from(u32::try_from(self.code_bytes).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.total_bytes).unwrap_or(u32::MAX))
    }
    /// Percentage of file that is overlay.
    #[must_use]
    pub fn overlay_fraction(&self) -> f64 {
        if self.total_bytes == 0 { return 0.0; }
        f64::from(u32::try_from(self.overlay_bytes).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.total_bytes).unwrap_or(u32::MAX))
    }
}

// ---------------------------------------------------------------------------
// Full statistics report
// ---------------------------------------------------------------------------

/// Full PE statistics report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeStatistics {
    /// File name (if provided).
    pub file_name: String,
    /// Total file size in bytes.
    pub file_size: usize,
    /// Whole-file Shannon entropy.
    pub file_entropy: f64,
    /// Per-section entropy stats.
    pub section_entropy: Vec<SectionEntropy>,
    /// API calls grouped by category.
    pub api_by_category: HashMap<String, Vec<String>>,
    /// Number of unique DLLs imported.
    pub unique_dlls: usize,
    /// Import diversity score: `unique_dlls` / `max_expected_dlls` (0.0–1.0).
    pub import_diversity_score: f64,
    /// Classified strings found in the binary.
    pub strings: Vec<ClassifiedString>,
    /// File size breakdown.
    pub size_breakdown: SizeBreakdown,
    /// Estimated packed/obfuscated probability (0.0–1.0).
    pub packed_probability: f64,
}

// ---------------------------------------------------------------------------
// PeStatisticsAnalyzer
// ---------------------------------------------------------------------------

/// Generates a full statistics report for a PE file.
pub struct PeStatisticsAnalyzer<'a> {
    data: &'a [u8],
    file_name: String,
    pe_offset: usize,
    is_pe32plus: bool,
}

impl<'a> PeStatisticsAnalyzer<'a> {
    pub fn new(data: &'a [u8], file_name: impl Into<String>) -> Option<Self> {
        let pe_offset = locate_pe(data)?;
        let is_pe32plus = detect_pe32plus(data, pe_offset);
        Some(Self { data, file_name: file_name.into(), pe_offset, is_pe32plus })
    }

    const fn opt(&self) -> usize { self.pe_offset + 24 }

    fn num_sections(&self) -> usize {
        let c = self.pe_offset + 4;
        if c + 4 > self.data.len() { return 0; }
        u16::from_le_bytes(self.data[c+2..c+4].try_into().unwrap()) as usize
    }

    fn opt_size(&self) -> usize {
        let c = self.pe_offset + 4;
        if c + 18 > self.data.len() { return 0; }
        u16::from_le_bytes(self.data[c+16..c+18].try_into().unwrap()) as usize
    }

    fn section_table(&self) -> usize { self.opt() + self.opt_size() }

    fn read_opt_u32(&self, off: usize) -> u32 {
        let o = self.opt() + off;
        if o + 4 > self.data.len() { return 0; }
        u32::from_le_bytes(self.data[o..o+4].try_into().unwrap())
    }

    fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        let coff   = self.pe_offset + 4;
        let n      = u16::from_le_bytes(self.data[coff+2..coff+4].try_into().ok()?) as usize;
        let opsz   = u16::from_le_bytes(self.data[coff+16..coff+18].try_into().ok()?) as usize;
        let sec    = self.pe_offset + 4 + 20 + opsz;
        for i in 0..n {
            let b = sec + i * 40;
            if b + 40 > self.data.len() { break; }
            let va  = u32::from_le_bytes(self.data[b+12..b+16].try_into().ok()?);
            let vsz = u32::from_le_bytes(self.data[b+8..b+12].try_into().ok()?);
            let raw = u32::from_le_bytes(self.data[b+20..b+24].try_into().ok()?) as usize;
            // Checked arithmetic: a wrapping `va + vsz` from a hostile section
            // header would silently skip the section.  Matches the canonical
            // `PeFile::rva_to_offset`.
            if rva >= va && rva < va.saturating_add(vsz) {
                return raw.checked_add((rva - va) as usize);
            }
        }
        None
    }

    // -----------------------------------------------------------------------
    // Section analysis
    // -----------------------------------------------------------------------

    fn section_entropy_stats(&self) -> Vec<SectionEntropy> {
        let n = self.num_sections();
        let st = self.section_table();
        let mut result = Vec::new();
        for i in 0..n {
            let base = st + i * 40;
            if base + 40 > self.data.len() { break; }
            let d = &self.data[base..base+40];
            let mut name_bytes = [0u8; 8];
            name_bytes.copy_from_slice(&d[0..8]);
            let name = {
                let end = name_bytes.iter().position(|&b| b==0).unwrap_or(8);
                String::from_utf8_lossy(&name_bytes[..end]).into_owned()
            };
            let _vsz = u32::from_le_bytes(d[8..12].try_into().unwrap());
            let raw = u32::from_le_bytes(d[16..20].try_into().unwrap()) as usize;
            let ptr = u32::from_le_bytes(d[20..24].try_into().unwrap()) as usize;
            let end = (ptr + raw).min(self.data.len());
            let sec_data = if ptr < self.data.len() { &self.data[ptr..end] } else { &[] };
            let whole = shannon_entropy(sec_data);
            let (min, max, mean, histogram) = block_entropy(sec_data, 256);
            result.push(SectionEntropy { name, min, max, mean, whole, histogram });
        }
        result
    }

    // -----------------------------------------------------------------------
    // Import analysis
    // -----------------------------------------------------------------------

    fn import_api_stats(&self) -> (HashMap<String, Vec<String>>, usize, f64) {
        const MAX_EXPECTED_DLLS: f64 = 20.0;
        let dd_base = {
            let opt = self.opt();
            if self.is_pe32plus { opt + 112 + 8 } else { opt + 96 + 8 }
        };
        if dd_base + 8 > self.data.len() { return (HashMap::new(), 0, 0.0); }
        let import_rva = u32::from_le_bytes(self.data[dd_base..dd_base+4].try_into().unwrap());
        let _import_sz  = u32::from_le_bytes(self.data[dd_base+4..dd_base+8].try_into().unwrap());
        if import_rva == 0 { return (HashMap::new(), 0, 0.0); }
        let Some(mut desc_off) = self.rva_to_offset(import_rva) else {
            return (HashMap::new(), 0, 0.0);
        };

        let mut by_cat: HashMap<String, Vec<String>> = HashMap::new();
        let mut dll_count = 0usize;

        loop {
            if desc_off + 20 > self.data.len() { break; }
            let d = &self.data[desc_off..desc_off+20];
            let name_rva = u32::from_le_bytes(d[12..16].try_into().unwrap());
            let iat_rva  = u32::from_le_bytes(d[16..20].try_into().unwrap());
            if name_rva == 0 && iat_rva == 0 { break; }

            // Read DLL name.
            let _dll_name = self.rva_to_offset(name_rva)
                .and_then(|off| read_cstring(self.data, off))
                .unwrap_or_default();

            // Read INT (OriginalFirstThunk).
            let orig_thunk_rva  = u32::from_le_bytes(d[0..4].try_into().unwrap());
            let thunk_rva = if orig_thunk_rva != 0 { orig_thunk_rva } else { iat_rva };
            if let Some(mut thunk_off) = self.rva_to_offset(thunk_rva) {
                let step = if self.is_pe32plus { 8 } else { 4 };
                loop {
                    if thunk_off + step > self.data.len() { break; }
                    let val: u64 = if self.is_pe32plus {
                        u64::from_le_bytes(self.data[thunk_off..thunk_off+8].try_into().unwrap())
                    } else {
                        u64::from(u32::from_le_bytes(self.data[thunk_off..thunk_off+4].try_into().unwrap()))
                    };
                    if val == 0 { break; }
                    let high_bit: u64 = if self.is_pe32plus { 1 << 63 } else { 1 << 31 };
                    let fn_name = if val & high_bit == 0 {
                        // By name: hint (2 bytes) + name.
                        let hn_rva = u32::try_from(val).unwrap_or(u32::MAX);
                        self.rva_to_offset(hn_rva)
                            .and_then(|off| read_cstring(self.data, off + 2))
                            .unwrap_or_default()
                    } else {
                        format!("#{}", val & 0xFFFF) // ordinal
                    };
                    if !fn_name.is_empty() {
                        let cat = classify_api(&fn_name);
                        by_cat.entry(cat.to_string()).or_default().push(fn_name);
                    }
                    thunk_off += step;
                }
            }
            dll_count += 1;
            desc_off += 20;
        }

        let diversity = (f64::from(u32::try_from(dll_count).unwrap_or(u32::MAX)) / MAX_EXPECTED_DLLS).min(1.0);
        (by_cat, dll_count, diversity)
    }

    // -----------------------------------------------------------------------
    // Size breakdown
    // -----------------------------------------------------------------------

    fn size_breakdown(&self) -> SizeBreakdown {
        let n = self.num_sections();
        let st = self.section_table();
        let soh = self.read_opt_u32(60) as usize;
        let (mut code, mut idata, mut udata, mut rsrc) = (0usize, 0usize, 0usize, 0usize);
        let mut last_end = 0usize;

        // Resource directory RVA/size.
        let rsrc_dd = {
            let opt = self.opt();
            let base = if self.is_pe32plus { opt + 112 + 2*8 } else { opt + 96 + 2*8 };
            if base + 8 <= self.data.len() {
                let r = u32::from_le_bytes(self.data[base..base+4].try_into().unwrap());
                let s = u32::from_le_bytes(self.data[base+4..base+8].try_into().unwrap());
                (r, s)
            } else { (0, 0) }
        };

        for i in 0..n {
            let base = st + i * 40;
            if base + 40 > self.data.len() { break; }
            let d = &self.data[base..base+40];
            let chars = u32::from_le_bytes(d[36..40].try_into().unwrap());
            let raw   = u32::from_le_bytes(d[16..20].try_into().unwrap()) as usize;
            let ptr   = u32::from_le_bytes(d[20..24].try_into().unwrap()) as usize;
            let va    = u32::from_le_bytes(d[12..16].try_into().unwrap());
            let vsz   = u32::from_le_bytes(d[8..12].try_into().unwrap());
            let end   = ptr + raw;
            if end > last_end { last_end = end; }

            if chars & 0x20 != 0 { code  += raw; }
            if chars & 0x40 != 0 {
                // Subtract resource section size from init data.
                if rsrc_dd.0 != 0 && va == rsrc_dd.0 { rsrc += raw; } else { idata += raw; }
            }
            if chars & 0x80 != 0 { udata += vsz as usize; }
        }

        let overlay = self.data.len().saturating_sub(last_end);
        SizeBreakdown {
            total_bytes: self.data.len(),
            dos_stub_bytes: self.pe_offset,
            headers_bytes: soh,
            code_bytes: code,
            initialized_data_bytes: idata,
            uninitialized_data_bytes: udata,
            resources_bytes: rsrc,
            overlay_bytes: overlay,
        }
    }

    // -----------------------------------------------------------------------
    // Packed probability
    // -----------------------------------------------------------------------

    fn packed_probability(&self, sec_entropy: &[SectionEntropy]) -> f64 {
        let high_count = sec_entropy.iter().filter(|s| s.is_high_entropy()).count();
        let total = sec_entropy.len().max(1);
        let frac = f64::from(u32::try_from(high_count).unwrap_or(u32::MAX)) / f64::from(u32::try_from(total).unwrap_or(u32::MAX));
        // Whole-file entropy also contributes.
        let file_ent = shannon_entropy(self.data);
        let file_contrib = (file_ent - 6.5).max(0.0) / 1.5;
        f64::midpoint(frac, file_contrib).min(1.0)
    }

    // -----------------------------------------------------------------------
    // Main entry
    // -----------------------------------------------------------------------

    #[must_use] 
    pub fn analyze(self) -> PeStatistics {
        let file_entropy = shannon_entropy(self.data);
        let section_entropy = self.section_entropy_stats();
        let (api_by_category, unique_dlls, import_diversity_score) = self.import_api_stats();
        let size_breakdown = self.size_breakdown();
        let packed_probability = self.packed_probability(&section_entropy);

        // String extraction — limit to first 4 MB to avoid slowdown on huge files.
        let search_region = &self.data[..self.data.len().min(4 * 1024 * 1024)];
        let mut strings = extract_ascii_strings(search_region, 6);
        strings.extend(extract_utf16le_strings(search_region, 6));
        // Sort by file offset.
        strings.sort_by_key(|s| s.file_offset);

        PeStatistics {
            file_name: self.file_name,
            file_size: self.data.len(),
            file_entropy,
            section_entropy,
            api_by_category,
            unique_dlls,
            import_diversity_score,
            strings,
            size_breakdown,
            packed_probability,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn locate_pe(data: &[u8]) -> Option<usize> {
    if data.len() < 0x40 { return None; }
    if data[0] == b'M' && data[1] == b'Z' {
        let lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().ok()?) as usize;
        if lfanew + 4 <= data.len() && &data[lfanew..lfanew+4] == b"PE\0\0" {
            return Some(lfanew);
        }
    }
    None
}

fn detect_pe32plus(data: &[u8], pe_offset: usize) -> bool {
    let opt = pe_offset + 24;
    if opt + 2 > data.len() { return false; }
    u16::from_le_bytes(data[opt..opt+2].try_into().unwrap()) == 0x020B
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u64; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    counts.iter()
        .filter(|&&c| c > 0)
        .map(|&c| { let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / len; -p * p.log2() })
        .sum()
}

fn block_entropy(data: &[u8], block_size: usize) -> (f64, f64, f64, [u32; 8]) {
    if data.is_empty() { return (0.0, 0.0, 0.0, [0; 8]); }
    let mut min: Option<f64> = None;
    let mut max = 0.0f64;
    let mut sum = 0.0f64;
    let mut count = 0usize;
    let mut histogram = [0u32; 8];
    for chunk in data.chunks(block_size) {
        let e = shannon_entropy(chunk);
        min = Some(min.map_or(e, |m: f64| m.min(e)));
        if e > max { max = e; }
        sum += e;
        count += 1;
        let bucket = if e < 1.0 { 0 } else if e < 2.0 { 1 } else if e < 3.0 { 2 }
            else if e < 4.0 { 3 } else if e < 5.0 { 4 } else if e < 6.0 { 5 }
            else if e < 7.0 { 6 } else { 7 };
        histogram[bucket] += 1;
    }
    let mean = if count > 0 { sum / f64::from(u32::try_from(count).unwrap_or(u32::MAX)) } else { 0.0 };
    (min.unwrap_or(0.0), max, mean, histogram)
}

fn read_cstring(data: &[u8], off: usize) -> Option<String> {
    let end = data[off..].iter().position(|&b| b == 0)? + off;
    String::from_utf8(data[off..end].to_vec()).ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_api_crypto() {
        assert_eq!(classify_api("CryptGenRandom"), ApiCategory::Crypto);
    }

    #[test]
    fn classify_api_network() {
        assert_eq!(classify_api("WSAConnect"), ApiCategory::Network);
    }

    #[test]
    fn classify_api_anti_debug() {
        assert_eq!(classify_api("IsDebuggerPresent"), ApiCategory::AntiDebug);
    }

    #[test]
    fn classify_api_injection() {
        assert_eq!(classify_api("WriteProcessMemory"), ApiCategory::Injection);
    }

    #[test]
    fn classify_string_url() {
        assert_eq!(classify_string("https://example.com/payload"), StringCategory::Url);
    }

    #[test]
    fn classify_string_ip() {
        assert_eq!(classify_string("192.168.1.100"), StringCategory::IpAddress);
    }

    #[test]
    fn classify_string_registry() {
        assert_eq!(
            classify_string(r"HKCU\Software\Microsoft\Windows"),
            StringCategory::RegistryKey
        );
    }

    #[test]
    fn extract_ascii_strings_basic() {
        let data = b"AAAA\x00hello world\x00\x01\x02";
        let strings = extract_ascii_strings(data, 4);
        assert!(strings.iter().any(|s| s.value.contains("AAAA")));
    }

    #[test]
    fn block_entropy_uniform() {
        let data = vec![0xAAu8; 1024];
        let (min, max, mean, _) = block_entropy(&data, 256);
        assert!(min < 0.001 && max < 0.001 && mean < 0.001);
    }
}
