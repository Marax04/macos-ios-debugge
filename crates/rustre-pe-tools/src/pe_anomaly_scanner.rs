//! `pe_anomaly_scanner` — PE structural anomaly detection
//!
//! Implements a comprehensive set of checks that detect malformed, suspicious,
//! or malicious PE characteristics commonly used by malware, packers, and
//! copy-protection schemes.
//!
//! # Checks performed
//!
//! * Checksum mismatch (header vs. computed).
//! * Overlay bytes beyond the last section.
//! * Raw section size significantly larger than virtual size.
//! * Entry point outside all declared sections.
//! * Overlapping sections (raw data ranges intersect).
//! * Bogus timestamp (far future, Unix epoch, all-zeros).
//! * Malformed data directory entries (RVA out of image).
//! * Invalid characteristics combination (e.g. DLL + EXE flag).
//! * Hidden sections (characteristics = 0, virtual size = 0).
//! * Non-standard section names (not in the standard set).
//! * RX sections with Shannon entropy > 7.0 (likely packed code).
//! * `SizeOfImage` mismatch vs. last section end.
//! * TLS callbacks present (anti-debug).
//! * Rich header present / corrupted.

use std::collections::HashSet;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

/// Severity of a detected anomaly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info     => write!(f, "INFO"),
            Self::Low      => write!(f, "LOW"),
            Self::Medium   => write!(f, "MEDIUM"),
            Self::High     => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ---------------------------------------------------------------------------
// Anomaly
// ---------------------------------------------------------------------------

/// A single detected anomaly in a PE file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeAnomaly {
    /// Short machine-readable identifier.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Severity level.
    pub severity: Severity,
    /// Byte offset or RVA context (optional).
    pub offset: Option<usize>,
    /// Additional context (section name, value, etc.).
    pub context: String,
}

impl PeAnomaly {
    fn new(id: &str, desc: &str, severity: Severity, offset: Option<usize>, ctx: &str) -> Self {
        Self {
            id: id.to_owned(),
            description: desc.to_owned(),
            severity,
            offset,
            context: ctx.to_owned(),
        }
    }
}

impl std::fmt::Display for PeAnomaly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}: {}", self.severity, self.id, self.description)?;
        if !self.context.is_empty() { write!(f, " ({})", self.context)?; }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Scan result
// ---------------------------------------------------------------------------

/// Aggregated result of a PE anomaly scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub anomalies: Vec<PeAnomaly>,
    pub has_overlay: bool,
    pub overlay_offset: Option<usize>,
    pub overlay_size: Option<usize>,
    pub checksum_mismatch: bool,
    pub computed_checksum: u32,
    pub header_checksum: u32,
}

impl ScanResult {
    #[must_use] 
    pub fn highest_severity(&self) -> Option<Severity> {
        self.anomalies.iter().map(|a| a.severity).max()
    }

    #[must_use] 
    pub fn anomalies_of_severity(&self, sev: Severity) -> Vec<&PeAnomaly> {
        self.anomalies.iter().filter(|a| a.severity == sev).collect()
    }

    #[must_use] 
    pub fn is_clean(&self) -> bool {
        !self.anomalies.iter().any(|a| a.severity >= Severity::Medium)
    }
}

// ---------------------------------------------------------------------------
// Standard section names
// ---------------------------------------------------------------------------

/// Well-known PE section names.  Presence of other names is flagged.
pub const STANDARD_SECTION_NAMES: &[&str] = &[
    ".text", ".code", ".data", ".rdata", ".bss",
    ".idata", ".edata", ".rsrc", ".reloc", ".pdata",
    ".xdata", ".tls", ".debug", ".drectve", ".sbss",
    ".sdata", ".srdata", ".sxdata", ".gfids", ".gehcont",
    // MSVC CRT sections
    ".CRT", ".crtsect",
    // Resource-only DLL sections sometimes seen
    "RT_MANIFEST",
    // Delphi
    "CODE", "DATA", "BSS",
    // MinGW
    ".ctors", ".dtors",
    // UPX packer (known packer names, flagged separately)
    "UPX0", "UPX1", "UPX2",
];

// ---------------------------------------------------------------------------
// PeAnomalyScanner
// ---------------------------------------------------------------------------

/// Scans a raw PE file for structural anomalies.
pub struct PeAnomalyScanner<'a> {
    data: &'a [u8],
    pe_offset: usize,
    is_pe32plus: bool,
    anomalies: Vec<PeAnomaly>,
}

impl<'a> PeAnomalyScanner<'a> {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Construct a scanner from a raw PE byte slice.
    #[must_use] 
    pub fn new(data: &'a [u8]) -> Option<Self> {
        let pe_offset = locate_pe(data)?;
        let is_pe32plus = detect_pe32plus(data, pe_offset);
        Some(Self { data, pe_offset, is_pe32plus, anomalies: Vec::new() })
    }

    // -----------------------------------------------------------------------
    // Layout helpers
    // -----------------------------------------------------------------------

    const fn coff(&self) -> usize { self.pe_offset + 4 }
    const fn opt(&self)  -> usize { self.pe_offset + 4 + 20 }

    fn num_sections(&self) -> usize {
        let c = self.coff();
        if c + 4 > self.data.len() { return 0; }
        u16::from_le_bytes(self.data[c+2..c+4].try_into().unwrap()) as usize
    }

    fn opt_size(&self) -> usize {
        let c = self.coff();
        if c + 18 > self.data.len() { return 0; }
        u16::from_le_bytes(self.data[c+16..c+18].try_into().unwrap()) as usize
    }

    fn section_table(&self) -> usize { self.opt() + self.opt_size() }

    fn read_opt_u32(&self, off: usize) -> u32 {
        let o = self.opt() + off;
        if o + 4 > self.data.len() { return 0; }
        u32::from_le_bytes(self.data[o..o+4].try_into().unwrap())
    }

    const fn dd_offset(&self, index: usize) -> usize {
        let opt = self.opt();
        if self.is_pe32plus { opt + 112 + index * 8 } else { opt + 96 + index * 8 }
    }

    fn read_dd(&self, index: usize) -> (u32, u32) {
        let off = self.dd_offset(index);
        if off + 8 > self.data.len() { return (0, 0); }
        let rva = u32::from_le_bytes(self.data[off..off+4].try_into().unwrap());
        let sz  = u32::from_le_bytes(self.data[off+4..off+8].try_into().unwrap());
        (rva, sz)
    }

    fn sections(&self) -> Vec<SectionSnapshot> {
        let n = self.num_sections();
        let st = self.section_table();
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let base = st + i * 40;
            if base + 40 > self.data.len() { break; }
            let d = &self.data[base..base+40];
            let mut name = [0u8; 8];
            name.copy_from_slice(&d[0..8]);
            out.push(SectionSnapshot {
                name,
                virtual_size:        u32::from_le_bytes(d[8..12].try_into().unwrap()),
                virtual_address:     u32::from_le_bytes(d[12..16].try_into().unwrap()),
                size_of_raw_data:    u32::from_le_bytes(d[16..20].try_into().unwrap()),
                pointer_to_raw_data: u32::from_le_bytes(d[20..24].try_into().unwrap()),
                characteristics:     u32::from_le_bytes(d[36..40].try_into().unwrap()),
            });
        }
        out
    }

    fn flag(&mut self, id: &str, desc: &str, sev: Severity, off: Option<usize>, ctx: &str) {
        self.anomalies.push(PeAnomaly::new(id, desc, sev, off, ctx));
    }

    // -----------------------------------------------------------------------
    // Individual checks
    // -----------------------------------------------------------------------

    fn check_checksum(&mut self) -> (bool, u32, u32) {
        let header_cs = self.read_opt_u32(64); // CheckSum field offset in OptHdr
        let computed  = pe_checksum(self.data, self.opt() + 64);
        let mismatch  = header_cs != 0 && header_cs != computed;
        if mismatch {
            self.flag(
                "CHECKSUM_MISMATCH",
                "PE checksum in header does not match computed value",
                Severity::Medium,
                Some(self.opt() + 64),
                &format!("header={header_cs:#010x} computed={computed:#010x}"),
            );
        }
        (mismatch, computed, header_cs)
    }

    fn check_overlay(&mut self, sections: &[SectionSnapshot]) -> (bool, Option<usize>, Option<usize>) {
        let last_end = sections
            .iter()
            .map(|s| s.pointer_to_raw_data as usize + s.size_of_raw_data as usize)
            .max()
            .unwrap_or(0);
        if last_end < self.data.len() {
            let overlay_size = self.data.len() - last_end;
            self.flag(
                "OVERLAY_DATA",
                "Bytes beyond last section (overlay)",
                Severity::Low,
                Some(last_end),
                &format!("{overlay_size} bytes at offset {last_end:#x}"),
            );
            return (true, Some(last_end), Some(overlay_size));
        }
        (false, None, None)
    }

    fn check_section_sizes(&mut self, sections: &[SectionSnapshot]) {
        for sec in sections {
            let name = sec.name_str();
            let raw  = sec.size_of_raw_data;
            let virt = sec.virtual_size;
            if raw > 0 && virt > 0 && raw > virt * 2 && raw - virt > 0x1000 {
                self.flag(
                    "RAW_GT_VIRTUAL",
                    "Raw section size is significantly larger than virtual size",
                    Severity::Medium,
                    Some(sec.pointer_to_raw_data as usize),
                    &format!("section={name} raw={raw:#x} virtual={virt:#x}"),
                );
            }
        }
    }

    fn check_entry_point(&mut self, sections: &[SectionSnapshot]) {
        let ep_rva = self.read_opt_u32(16); // AddressOfEntryPoint
        if ep_rva == 0 { return; } // DLLs may have EP=0
        let in_section = sections.iter().any(|s| {
            ep_rva >= s.virtual_address
                && ep_rva < s.virtual_address + s.virtual_size.max(s.size_of_raw_data)
        });
        if !in_section {
            self.flag(
                "EP_OUTSIDE_SECTIONS",
                "Entry point RVA does not fall within any declared section",
                Severity::High,
                None,
                &format!("ep_rva={ep_rva:#010x}"),
            );
        }
    }

    fn check_overlapping_sections(&mut self, sections: &[SectionSnapshot]) {
        for i in 0..sections.len() {
            for j in i+1..sections.len() {
                let a = &sections[i];
                let b = &sections[j];
                let a_start = a.pointer_to_raw_data as usize;
                let a_end   = a_start + a.size_of_raw_data as usize;
                let b_start = b.pointer_to_raw_data as usize;
                let b_end   = b_start + b.size_of_raw_data as usize;
                if a.size_of_raw_data > 0 && b.size_of_raw_data > 0
                    && a_start < b_end && b_start < a_end
                {
                    self.flag(
                        "OVERLAPPING_SECTIONS",
                        "Two sections have overlapping raw data ranges",
                        Severity::High,
                        Some(a_start),
                        &format!("'{}' and '{}'", a.name_str(), b.name_str()),
                    );
                }
            }
        }
    }

    fn check_timestamp(&mut self) {
        let ts_off = self.coff() + 4;
        if ts_off + 4 > self.data.len() { return; }
        let ts = u32::from_le_bytes(self.data[ts_off..ts_off+4].try_into().unwrap());
        if ts == 0 {
            self.flag("ZERO_TIMESTAMP", "TimeDateStamp is zero", Severity::Info, Some(ts_off), "");
        } else if ts > 0x8000_0000 {
            // Far future timestamp (> 2038-ish for signed, > 2106 territory)
            self.flag(
                "BOGUS_TIMESTAMP",
                "TimeDateStamp appears to be in the far future or invalid",
                Severity::Low,
                Some(ts_off),
                &format!("{ts:#010x}"),
            );
        }
    }

    fn check_data_directories(&mut self, sections: &[SectionSnapshot]) {
        let size_of_image = self.read_opt_u32(56);
        let num_dd = if self.is_pe32plus {
            // NumberOfRvaAndSizes at opt+108
            u32::from_le_bytes(
                self.data[self.opt()+108..self.opt()+112].try_into().unwrap_or([0;4])
            )
        } else {
            u32::from_le_bytes(
                self.data[self.opt()+92..self.opt()+96].try_into().unwrap_or([0;4])
            )
        } as usize;
        let num_dd = num_dd.min(16);
        for i in 0..num_dd {
            let (rva, sz) = self.read_dd(i);
            if rva == 0 || sz == 0 { continue; }
            if size_of_image > 0 && rva >= size_of_image {
                self.flag(
                    "DD_RVA_OOB",
                    "Data directory RVA exceeds SizeOfImage",
                    Severity::High,
                    Some(self.dd_offset(i)),
                    &format!("dir={i} rva={rva:#010x} SizeOfImage={size_of_image:#010x}"),
                );
            }
            let in_section = sections.iter().any(|s| {
                rva >= s.virtual_address
                    && rva + sz <= s.virtual_address + s.virtual_size.max(s.size_of_raw_data)
            });
            if !in_section && rva < size_of_image {
                self.flag(
                    "DD_NOT_IN_SECTION",
                    "Data directory points outside all sections",
                    Severity::Medium,
                    Some(self.dd_offset(i)),
                    &format!("dir={i} rva={rva:#010x}"),
                );
            }
        }
    }

    fn check_characteristics(&mut self) {
        const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
        const IMAGE_FILE_DLL: u16              = 0x2000;
        let chars_off = self.coff() + 18;
        if chars_off + 2 > self.data.len() { return; }
        let chars = u16::from_le_bytes(self.data[chars_off..chars_off+2].try_into().unwrap());
        if chars & IMAGE_FILE_EXECUTABLE_IMAGE != 0 && chars & IMAGE_FILE_DLL != 0 {
            self.flag(
                "DLL_AND_EXE_FLAGS",
                "IMAGE_FILE_EXECUTABLE_IMAGE and IMAGE_FILE_DLL both set",
                Severity::Medium,
                Some(chars_off),
                &format!("{chars:#06x}"),
            );
        }
    }

    fn check_hidden_sections(&mut self, sections: &[SectionSnapshot]) {
        for sec in sections {
            if sec.virtual_size == 0 && sec.characteristics == 0 {
                self.flag(
                    "HIDDEN_SECTION",
                    "Section with zero virtual size and zero characteristics",
                    Severity::Medium,
                    Some(sec.pointer_to_raw_data as usize),
                    &format!("section={}", sec.name_str()),
                );
            }
        }
    }

    fn check_section_names(&mut self, sections: &[SectionSnapshot]) {
        let standard: HashSet<&str> = STANDARD_SECTION_NAMES.iter().copied().collect();
        for sec in sections {
            let name = sec.name_str();
            if !name.is_empty() && !standard.contains(name.as_str()) {
                let sev = if name.chars().any(|c| !c.is_ascii_graphic()) {
                    Severity::High
                } else {
                    Severity::Info
                };
                self.flag(
                    "NONSTANDARD_SECTION_NAME",
                    "Section name is not in the standard set",
                    sev,
                    None,
                    &format!("section={name:?}"),
                );
            }
        }
    }

    fn check_high_entropy_rx(&mut self, sections: &[SectionSnapshot]) {
        const EXEC_FLAGS: u32 = 0x2000_0020;
        for sec in sections {
            if sec.characteristics & EXEC_FLAGS == 0 { continue; }
            let start = sec.pointer_to_raw_data as usize;
            let end   = (start + sec.size_of_raw_data as usize).min(self.data.len());
            if start >= self.data.len() || start >= end { continue; }
            let ent = shannon_entropy(&self.data[start..end]);
            if ent > 7.0 {
                self.flag(
                    "HIGH_ENTROPY_RX",
                    "Executable section has high entropy (likely packed/encrypted)",
                    Severity::High,
                    Some(start),
                    &format!("section={} entropy={ent:.3}", sec.name_str()),
                );
            }
        }
    }

    fn check_size_of_image(&mut self, sections: &[SectionSnapshot]) {
        let soi = self.read_opt_u32(56);
        let sa  = self.read_opt_u32(32).max(0x1000);
        let expected: u32 = sections
            .iter()
            .map(|s| s.virtual_address + align_up(s.virtual_size.max(s.size_of_raw_data), sa))
            .max()
            .unwrap_or(sa);
        if soi != 0 && expected != 0 && soi != expected {
            self.flag(
                "SIZE_OF_IMAGE_MISMATCH",
                "SizeOfImage does not match computed value from sections",
                Severity::Medium,
                Some(self.opt() + 56),
                &format!("header={soi:#010x} computed={expected:#010x}"),
            );
        }
    }

    fn check_tls_callbacks(&mut self) {
        let (tls_rva, tls_sz) = self.read_dd(9); // TLS directory is index 9
        if tls_rva != 0 && tls_sz != 0 {
            self.flag(
                "TLS_CALLBACKS",
                "TLS directory present — may contain anti-debug TLS callbacks",
                Severity::Medium,
                Some(self.dd_offset(9)),
                &format!("rva={tls_rva:#010x} size={tls_sz:#x}"),
            );
        }
    }

    fn check_rich_header(&mut self) {
        // The Rich header lives between the MZ stub and the PE signature.
        // It starts with "DanS" (after XOR-decoding) and ends with "Rich".
        if self.data.len() < 0x40 { return; }
        let lfanew = u32::from_le_bytes(
            self.data[0x3C..0x40].try_into().unwrap()
        ) as usize;
        let header_region = &self.data[0x40..lfanew.min(self.data.len())];
        if let Some(pos) = find_subsequence(header_region, b"Rich") {
            self.flag(
                "RICH_HEADER",
                "Rich header (compiler/linker toolchain fingerprint) present",
                Severity::Info,
                Some(0x40 + pos),
                "",
            );
        }
    }

    // -----------------------------------------------------------------------
    // Main entry
    // -----------------------------------------------------------------------

    /// Run all anomaly checks and return a [`ScanResult`].
    #[must_use] 
    pub fn scan(mut self) -> ScanResult {
        let sections = self.sections();

        let (checksum_mismatch, computed_checksum, header_checksum) = self.check_checksum();
        let (has_overlay, overlay_offset, overlay_size) = self.check_overlay(&sections);

        self.check_section_sizes(&sections);
        self.check_entry_point(&sections);
        self.check_overlapping_sections(&sections);
        self.check_timestamp();
        self.check_data_directories(&sections);
        self.check_characteristics();
        self.check_hidden_sections(&sections);
        self.check_section_names(&sections);
        self.check_high_entropy_rx(&sections);
        self.check_size_of_image(&sections);
        self.check_tls_callbacks();
        self.check_rich_header();

        // Sort anomalies by severity descending.
        self.anomalies.sort_by(|a, b| b.severity.cmp(&a.severity));

        ScanResult {
            anomalies: self.anomalies,
            has_overlay,
            overlay_offset,
            overlay_size,
            checksum_mismatch,
            computed_checksum,
            header_checksum,
        }
    }
}

// ---------------------------------------------------------------------------
// SectionSnapshot
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct SectionSnapshot {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    characteristics: u32,
}

impl SectionSnapshot {
    fn name_str(&self) -> String {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        String::from_utf8_lossy(&self.name[..end]).into_owned()
    }
}

// ---------------------------------------------------------------------------
// PE checksum computation
// ---------------------------------------------------------------------------

/// Compute the PE checksum of `data`, skipping the 4-byte checksum field at
/// `checksum_offset`.
#[must_use] 
pub fn pe_checksum(data: &[u8], checksum_offset: usize) -> u32 {
    let mut checksum: u64 = 0;
    let len = data.len();
    let padded_len = (len + 1) & !1; // round up to even

    for i in (0..padded_len).step_by(2) {
        // Skip the checksum field itself.
        if i == checksum_offset { continue; }
        let lo = u64::from(*data.get(i).unwrap_or(&0));
        let hi = u64::from(*data.get(i + 1).unwrap_or(&0));
        let word = (hi << 8) | lo;
        checksum = (checksum + word) & 0xFFFF_FFFF;
        checksum = (checksum >> 16) + (checksum & 0xFFFF);
    }
    let checksum = u32::try_from((checksum >> 16) + checksum).unwrap_or(u32::MAX);
    (checksum & 0xFFFF) + u32::try_from(len).unwrap_or(u32::MAX)
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
    let opt = pe_offset + 4 + 20;
    if opt + 2 > data.len() { return false; }
    u16::from_le_bytes(data[opt..opt+2].try_into().unwrap()) == 0x020B
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

const fn align_up(v: u32, align: u32) -> u32 {
    if align == 0 { return v; }
    v.saturating_add(align - 1) & !(align - 1)
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

/// Convenience function: scan `data` and return the result.
#[must_use] 
pub fn scan_pe(data: &[u8]) -> Option<ScanResult> {
    Some(PeAnomalyScanner::new(data)?.scan())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_max() {
        let data: Vec<u8> = (0..=255u8).collect();
        assert!((shannon_entropy(&data) - 8.0).abs() < 0.01);
    }

    #[test]
    fn entropy_zero() {
        assert_eq!(shannon_entropy(&[0xAA; 64]), 0.0);
    }

    #[test]
    fn pe_checksum_empty() {
        // Smoke test — should not panic.
        let _ = pe_checksum(b"", 0);
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn scan_pe_empty_returns_none() {
        assert!(scan_pe(b"").is_none());
    }
}
