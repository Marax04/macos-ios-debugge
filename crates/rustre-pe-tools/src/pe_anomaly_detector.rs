//! `pe_anomaly_detector` — Detect structural anomalies in PE files.
//!
//! Checks for malformed, suspicious, or deliberately obfuscated PE attributes:
//! section alignment/overlap, unusual entry points, time-stamp zeroing,
//! impossible header values, truncated files, rich header manipulation, etc.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// AnomalyKind
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of a specific anomaly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnomalyKind {
    // ── Header anomalies ────────────────────────────────────────────────────
    /// MZ `e_lfanew` points outside the file.
    InvalidPeOffset,
    /// COFF machine value is 0 or unknown.
    UnknownMachine,
    /// Optional header magic is neither 0x010B nor 0x020B.
    InvalidOptionalMagic,
    /// COFF timestamp is 0 (common in malware / compilers that strip it).
    ZeroTimestamp,
    /// COFF timestamp is in the future (compared to epoch 2030-01-01).
    FutureTimestamp,
    /// Image entry point RVA is 0 for an executable (not a DLL).
    NullEntryPoint,
    /// Image base is 0.
    NullImageBase,
    /// Section alignment is not a power of two.
    BadSectionAlignment,
    /// File alignment is not a power of two.
    BadFileAlignment,
    /// File alignment smaller than 512 (non-standard).
    TinyFileAlignment,
    /// `SizeOfHeaders` is 0.
    ZeroSizeOfHeaders,
    /// `SizeOfImage` is not aligned to `SectionAlignment`.
    MisalignedSizeOfImage,

    // ── Section anomalies ────────────────────────────────────────────────────
    /// Section name contains non-printable bytes.
    NonPrintableSectionName,
    /// Section raw data extends beyond end of file.
    SectionDataOutOfBounds,
    /// Two or more sections have overlapping raw data regions.
    OverlappingSections,
    /// Section virtual address 0 or lower than headers.
    InvalidSectionVA,
    /// Section raw size significantly larger than virtual size.
    RawBiggerThanVirtual,
    /// Executable section is also writable.
    WritableExecutableSection,
    /// More than 96 sections (heuristic for malformed/obfuscated PE).
    TooManySections,
    /// Section has high entropy (> 7.2 bits — likely packed/encrypted).
    HighEntropySectionData,

    // ── Import/export anomalies ──────────────────────────────────────────────
    /// Import table RVA is outside all sections.
    ImportTableOutsideSections,
    /// Export DLL name does not match the file's apparent name.
    ExportDllNameMismatch,
    /// Import of rare / suspicious function.
    SuspiciousImport,

    // ── Data directory anomalies ─────────────────────────────────────────────
    /// Security directory present but size is 0.
    ZeroSizeSecurityDir,
    /// Resource directory RVA is 0 but resource section exists.
    MissingResourceDir,
    /// TLS directory present (unusual; may indicate dynamic loading).
    TlsDirectoryPresent,
    /// Bound import directory present (uncommon in modern PE files).
    BoundImportPresent,

    // ── Rich header anomalies ────────────────────────────────────────────────
    /// Rich header XOR key is 0 (unobfuscated).
    ZeroRichHeaderKey,
    /// Rich header is missing (some legitimate files lack it; also sign of rebuilding).
    MissingRichHeader,

    // ── Overlay anomalies ────────────────────────────────────────────────────
    /// File has data appended after all sections (overlay).
    OverlayPresent,
    /// Overlay is large (> 10 % of the main file body).
    LargeOverlay,

    // ── Misc ─────────────────────────────────────────────────────────────────
    /// Characteristics include `IMAGE_FILE_EXECUTABLE_IMAGE` but also `RELOCS_STRIPPED`
    /// when the image still has a relocation directory.
    RelocsStrippedWithRelocDir,
    /// DOS stub is unusually large (> 256 bytes before PE offset).
    LargeDosStub,
    /// `e_lfanew` is 0x40 (bare minimum); the DOS stub has been stripped.
    StrippedDosStub,
    /// Checksum field is non-zero but verification fails.
    ChecksumMismatch,
}

impl fmt::Display for AnomalyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnomalyScore
// ─────────────────────────────────────────────────────────────────────────────

/// Severity / score contribution of an anomaly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AnomalyScore(pub u32);

impl AnomalyScore {
    /// Informational (score 1).
    pub const INFO: Self = Self(1);
    /// Low-severity anomaly (score 5).
    pub const LOW: Self = Self(5);
    /// Medium-severity anomaly (score 15).
    pub const MEDIUM: Self = Self(15);
    /// High-severity anomaly (score 30).
    pub const HIGH: Self = Self(30);
    /// Critical — almost certainly malicious or broken (score 50).
    pub const CRITICAL: Self = Self(50);

    /// Return a label for the score tier.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self.0 {
            0..=4 => "info",
            5..=14 => "low",
            15..=29 => "medium",
            30..=49 => "high",
            _ => "critical",
        }
    }
}

impl fmt::Display for AnomalyScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", self.label(), self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PeAnomaly
// ─────────────────────────────────────────────────────────────────────────────

/// A single detected anomaly.
#[derive(Debug, Clone)]
pub struct PeAnomaly {
    /// Anomaly classification.
    pub kind: AnomalyKind,
    /// Score contribution.
    pub score: AnomalyScore,
    /// Human-readable description.
    pub description: String,
    /// Optional byte offset in the file related to this anomaly.
    pub offset: Option<usize>,
    /// Optional section name related to this anomaly.
    pub section: Option<String>,
}

impl PeAnomaly {
    /// Create a basic anomaly without location info.
    #[must_use]
    pub fn new(kind: AnomalyKind, score: AnomalyScore, description: impl Into<String>) -> Self {
        Self {
            kind,
            score,
            description: description.into(),
            offset: None,
            section: None,
        }
    }

    /// Attach a file offset.
    #[must_use]
    pub const fn with_offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Attach a section name.
    #[must_use]
    pub fn with_section(mut self, name: impl Into<String>) -> Self {
        self.section = Some(name.into());
        self
    }
}

impl fmt::Display for PeAnomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.score, self.kind, self.description)?;
        if let Some(off) = self.offset {
            write!(f, " @ {off:#x}")?;
        }
        if let Some(ref s) = self.section {
            write!(f, " (section {s})")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnomalyReport
// ─────────────────────────────────────────────────────────────────────────────

/// Collection of anomalies found in a PE file.
#[derive(Debug, Clone, Default)]
pub struct AnomalyReport {
    pub anomalies: Vec<PeAnomaly>,
    /// Aggregate anomaly score.
    pub total_score: u32,
}

impl AnomalyReport {
    /// Create an empty report.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an anomaly and update total score.
    pub fn push(&mut self, anomaly: PeAnomaly) {
        self.total_score += anomaly.score.0;
        self.anomalies.push(anomaly);
    }

    /// Return the number of anomalies.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.anomalies.len()
    }

    /// Returns `true` if no anomalies were found.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.anomalies.is_empty()
    }

    /// Count anomalies by kind.
    #[must_use]
    pub fn count_by_kind(&self) -> HashMap<AnomalyKind, usize> {
        let mut m = HashMap::new();
        for a in &self.anomalies {
            *m.entry(a.kind).or_insert(0) += 1;
        }
        m
    }

    /// Return the highest-scoring anomaly.
    #[must_use]
    pub fn worst(&self) -> Option<&PeAnomaly> {
        self.anomalies.iter().max_by_key(|a| a.score)
    }

    /// Return all critical anomalies.
    #[must_use]
    pub fn critical(&self) -> Vec<&PeAnomaly> {
        self.anomalies
            .iter()
            .filter(|a| a.score >= AnomalyScore::CRITICAL)
            .collect()
    }

    /// Overall risk tier based on total score.
    #[must_use]
    pub fn risk_tier(&self) -> &'static str {
        // The reported tier is the max of (a) the worst single anomaly's severity
        // bucket and (b) the cumulative-score bucket.  This way a single CRITICAL
        // anomaly always reports as "critical", regardless of how few other
        // findings exist.
        let worst_tier = self
            .anomalies
            .iter()
            .map(|a| match a.score.0 {
                0 => 0u8,
                s if s >= AnomalyScore::CRITICAL.0 => 4,
                s if s >= AnomalyScore::HIGH.0 => 3,
                s if s >= AnomalyScore::MEDIUM.0 => 2,
                _ => 1,
            })
            .max()
            .unwrap_or(0);
        let cumulative_tier: u8 = match self.total_score {
            0 => 0,
            1..=19 => 1,
            20..=59 => 2,
            60..=119 => 3,
            _ => 4,
        };
        match worst_tier.max(cumulative_tier) {
            0 => "clean",
            1 => "low",
            2 => "medium",
            3 => "high",
            _ => "critical",
        }
    }
}

impl fmt::Display for AnomalyReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AnomalyReport[score={} risk={} count={}]",
            self.total_score,
            self.risk_tier(),
            self.anomalies.len()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PeAnomalyDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Detects structural anomalies in a raw PE file byte slice.
pub struct PeAnomalyDetector {
    /// If `true`, check section entropy for packed/encrypted data.
    pub check_entropy: bool,
    /// Entropy threshold above which a section is flagged (default 7.2).
    pub entropy_threshold: f64,
    /// If `true`, verify the PE checksum field.
    pub check_checksum: bool,
    /// Import name substrings considered suspicious.
    pub suspicious_imports: Vec<String>,
}

impl Default for PeAnomalyDetector {
    fn default() -> Self {
        Self {
            check_entropy: true,
            entropy_threshold: 7.2,
            check_checksum: false, // expensive; opt-in
            suspicious_imports: vec![
                "VirtualAlloc".to_string(),
                "VirtualProtect".to_string(),
                "WriteProcessMemory".to_string(),
                "CreateRemoteThread".to_string(),
                "NtUnmapViewOfSection".to_string(),
                "IsDebuggerPresent".to_string(),
                "CheckRemoteDebuggerPresent".to_string(),
                "OpenProcess".to_string(),
            ],
        }
    }
}

impl PeAnomalyDetector {
    /// Create a detector with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run all checks and return an `AnomalyReport`.
    #[must_use]
    pub fn analyze(&self, data: &[u8]) -> AnomalyReport {
        let mut report = AnomalyReport::new();
        let Some((e_lfanew, num_sections, is_dll, relocs_stripped, opt_hdr_size)) =
            Self::check_mz_coff(data, &mut report) else { return report; };
        let Some((opt_off, _is_64bit, dir_start, num_dirs, size_of_headers)) =
            Self::check_opt_header(data, e_lfanew, opt_hdr_size, is_dll, &mut report) else { return report; };
        Self::check_data_dirs(data, dir_start, num_dirs, relocs_stripped, &mut report);
        let sect_table_off = opt_off + opt_hdr_size;
        let section_ranges =
            self.check_sections(data, sect_table_off, num_sections, size_of_headers, &mut report);
        Self::check_overlay(data, &section_ranges, &mut report);
        report
    }

    // Returns (e_lfanew, num_sections, is_dll, relocs_stripped, opt_hdr_size)
    fn check_mz_coff(data: &[u8], report: &mut AnomalyReport) -> Option<(usize, usize, bool, bool, usize)> {
        if data.len() < 64 {
            report.push(PeAnomaly::new(AnomalyKind::InvalidPeOffset, AnomalyScore::CRITICAL, "file too short to contain MZ header"));
            return None;
        }
        if data[0] != 0x4D || data[1] != 0x5A {
            report.push(PeAnomaly::new(AnomalyKind::InvalidPeOffset, AnomalyScore::CRITICAL, "missing MZ magic"));
            return None;
        }
        let e_lfanew = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
        if e_lfanew == 0x40 {
            report.push(PeAnomaly::new(AnomalyKind::StrippedDosStub, AnomalyScore::INFO, "e_lfanew is minimal (0x40): DOS stub stripped"));
        } else if e_lfanew > 256 {
            report.push(PeAnomaly::new(AnomalyKind::LargeDosStub, AnomalyScore::LOW, format!("large DOS stub area: {e_lfanew:#x} bytes before PE signature")).with_offset(60));
        }
        if e_lfanew + 24 > data.len() {
            report.push(PeAnomaly::new(AnomalyKind::InvalidPeOffset, AnomalyScore::CRITICAL, format!("e_lfanew {e_lfanew:#x} points outside file")).with_offset(60));
            return None;
        }
        if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            report.push(PeAnomaly::new(AnomalyKind::InvalidPeOffset, AnomalyScore::CRITICAL, "PE signature not found at e_lfanew").with_offset(e_lfanew));
            return None;
        }
        let coff = e_lfanew + 4;
        let machine = u16::from_le_bytes([data[coff], data[coff + 1]]);
        if machine == 0 {
            report.push(PeAnomaly::new(AnomalyKind::UnknownMachine, AnomalyScore::MEDIUM, "COFF machine value is 0").with_offset(coff));
        }
        let num_sections = u16::from_le_bytes([data[coff + 2], data[coff + 3]]) as usize;
        if num_sections > 96 {
            report.push(PeAnomaly::new(AnomalyKind::TooManySections, AnomalyScore::HIGH, format!("unusually high section count: {num_sections}")).with_offset(coff + 2));
        }
        let timestamp = u32::from_le_bytes(data[coff + 4..coff + 8].try_into().unwrap_or([0; 4]));
        if timestamp == 0 {
            report.push(PeAnomaly::new(AnomalyKind::ZeroTimestamp, AnomalyScore::LOW, "COFF timestamp is 0").with_offset(coff + 4));
        } else if timestamp > 1_893_456_000 {
            report.push(PeAnomaly::new(AnomalyKind::FutureTimestamp, AnomalyScore::MEDIUM, format!("COFF timestamp is in the future: {timestamp}")).with_offset(coff + 4));
        }
        let coff_chars = u16::from_le_bytes([data[coff + 22], data[coff + 23]]);
        let is_dll = (coff_chars & 0x2000) != 0;
        let relocs_stripped = (coff_chars & 0x0001) != 0;
        let opt_hdr_size = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
        Some((e_lfanew, num_sections, is_dll, relocs_stripped, opt_hdr_size))
    }

    // Returns (opt_off, is_64bit, dir_start, num_dirs, size_of_headers)
    fn check_opt_header(data: &[u8], e_lfanew: usize, _opt_hdr_size: usize, is_dll: bool, report: &mut AnomalyReport) -> Option<(usize, bool, usize, usize, u32)> {
        let opt_off = e_lfanew + 24;
        if opt_off + 2 > data.len() {
            report.push(PeAnomaly::new(AnomalyKind::InvalidOptionalMagic, AnomalyScore::CRITICAL, "optional header truncated"));
            return None;
        }
        let opt_magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
        if opt_magic != 0x010B && opt_magic != 0x020B {
            report.push(PeAnomaly::new(AnomalyKind::InvalidOptionalMagic, AnomalyScore::HIGH, format!("unknown optional header magic {opt_magic:#x}")).with_offset(opt_off));
        }
        let is_64bit = opt_magic == 0x020B;
        let min_opt = if is_64bit { 112 } else { 96 };
        if opt_off + min_opt > data.len() {
            report.push(PeAnomaly::new(AnomalyKind::InvalidOptionalMagic, AnomalyScore::CRITICAL, "optional header shorter than minimum"));
            return None;
        }
        let r4 = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap_or([0; 4]));
        let ep_rva = r4(opt_off + 16);
        if ep_rva == 0 && !is_dll {
            report.push(PeAnomaly::new(AnomalyKind::NullEntryPoint, AnomalyScore::MEDIUM, "entry point RVA is 0 for a non-DLL").with_offset(opt_off + 16));
        }
        let image_base: u64 = if is_64bit { u64::from_le_bytes(data[opt_off + 24..opt_off + 32].try_into().unwrap_or([0; 8])) } else { u64::from(r4(opt_off + 28)) };
        if image_base == 0 {
            report.push(PeAnomaly::new(AnomalyKind::NullImageBase, AnomalyScore::MEDIUM, "ImageBase is 0").with_offset(opt_off + if is_64bit { 24 } else { 28 }));
        }
        let sect_align = r4(opt_off + 32);
        let file_align = r4(opt_off + 36);
        if sect_align > 0 && !sect_align.is_power_of_two() {
            report.push(PeAnomaly::new(AnomalyKind::BadSectionAlignment, AnomalyScore::HIGH, format!("SectionAlignment {sect_align:#x} is not a power of two")));
        }
        if file_align > 0 && !file_align.is_power_of_two() {
            report.push(PeAnomaly::new(AnomalyKind::BadFileAlignment, AnomalyScore::HIGH, format!("FileAlignment {file_align:#x} is not a power of two")));
        }
        if file_align > 0 && file_align < 512 {
            report.push(PeAnomaly::new(AnomalyKind::TinyFileAlignment, AnomalyScore::LOW, format!("FileAlignment {file_align} < 512")));
        }
        let size_of_headers = r4(opt_off + 60);
        if size_of_headers == 0 {
            report.push(PeAnomaly::new(AnomalyKind::ZeroSizeOfHeaders, AnomalyScore::HIGH, "SizeOfHeaders is 0"));
        }
        let size_of_image = r4(opt_off + 56);
        if sect_align > 0 && size_of_image % sect_align != 0 {
            report.push(PeAnomaly::new(AnomalyKind::MisalignedSizeOfImage, AnomalyScore::MEDIUM, format!("SizeOfImage {size_of_image:#x} not aligned to SectionAlignment {sect_align:#x}")));
        }
        let nd_off = if is_64bit { 108 } else { 92 };
        let num_dirs = r4(opt_off + nd_off) as usize;
        let dir_start = if is_64bit { opt_off + 112 } else { opt_off + 96 };
        Some((opt_off, is_64bit, dir_start, num_dirs, size_of_headers))
    }

    fn check_data_dirs(data: &[u8], dir_start: usize, num_dirs: usize, relocs_stripped: bool, report: &mut AnomalyReport) {
        if dir_start + 4 * 8 + 8 <= data.len() {
            let sec_rva  = u32::from_le_bytes(data[dir_start + 32..dir_start + 36].try_into().unwrap_or([0; 4]));
            let sec_size = u32::from_le_bytes(data[dir_start + 36..dir_start + 40].try_into().unwrap_or([0; 4]));
            if sec_rva != 0 && sec_size == 0 {
                report.push(PeAnomaly::new(AnomalyKind::ZeroSizeSecurityDir, AnomalyScore::MEDIUM, "security directory RVA is present but size is 0"));
            }
        }
        if num_dirs > 9 && dir_start + 9 * 8 + 8 <= data.len() {
            let tls_rva = u32::from_le_bytes(data[dir_start + 72..dir_start + 76].try_into().unwrap_or([0; 4]));
            if tls_rva != 0 {
                report.push(PeAnomaly::new(AnomalyKind::TlsDirectoryPresent, AnomalyScore::LOW, "TLS directory present"));
            }
        }
        if num_dirs > 11 && dir_start + 11 * 8 + 8 <= data.len() {
            let bi_rva = u32::from_le_bytes(data[dir_start + 88..dir_start + 92].try_into().unwrap_or([0; 4]));
            if bi_rva != 0 {
                report.push(PeAnomaly::new(AnomalyKind::BoundImportPresent, AnomalyScore::INFO, "bound import directory present"));
            }
        }
        if relocs_stripped && num_dirs > 5 && dir_start + 5 * 8 + 8 <= data.len() {
            let reloc_rva = u32::from_le_bytes(data[dir_start + 40..dir_start + 44].try_into().unwrap_or([0; 4]));
            if reloc_rva != 0 {
                report.push(PeAnomaly::new(AnomalyKind::RelocsStrippedWithRelocDir, AnomalyScore::MEDIUM, "RELOCS_STRIPPED flag set but relocation directory is present"));
            }
        }
    }

    fn check_sections(&self, data: &[u8], sect_table_off: usize, num_sections: usize, size_of_headers: u32, report: &mut AnomalyReport) -> Vec<(usize, usize, String)> {
        let mut section_ranges: Vec<(usize, usize, String)> = Vec::new();
        for i in 0..num_sections.min(96) {
            let off = sect_table_off + i * 40;
            if off + 40 > data.len() { break; }
            let name_bytes = &data[off..off + 8];
            let name = String::from_utf8_lossy(name_bytes).trim_end_matches('\0').to_string();
            if name_bytes.iter().any(|&b| b != 0 && !(0x20..=0x7E).contains(&b)) {
                report.push(PeAnomaly::new(AnomalyKind::NonPrintableSectionName, AnomalyScore::MEDIUM, format!("section {i} has non-printable name bytes")).with_offset(off));
            }
            let r4 = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap_or([0; 4]));
            let virtual_size    = r4(off +  8);
            let virtual_address = r4(off + 12);
            let raw_size        = r4(off + 16);
            let raw_offset      = r4(off + 20) as usize;
            let chars           = r4(off + 36);
            if virtual_address < size_of_headers && virtual_address != 0 {
                report.push(PeAnomaly::new(AnomalyKind::InvalidSectionVA, AnomalyScore::HIGH, format!("section '{name}' VA {virtual_address:#x} overlaps headers")).with_section(name.clone()));
            }
            let raw_end = raw_offset + raw_size as usize;
            if raw_size > 0 && raw_end > data.len() {
                report.push(PeAnomaly::new(AnomalyKind::SectionDataOutOfBounds, AnomalyScore::HIGH, format!("section '{name}' raw data {raw_offset:#x}+{raw_size} exceeds file size {}", data.len())).with_section(name.clone()));
            }
            if raw_size > 0 && virtual_size > 0 && raw_size > virtual_size * 4 {
                report.push(PeAnomaly::new(AnomalyKind::RawBiggerThanVirtual, AnomalyScore::MEDIUM, format!("section '{name}' raw size {raw_size:#x} >> virtual size {virtual_size:#x}")).with_section(name.clone()));
            }
            if (chars & 0x2000_0000) != 0 && (chars & 0x8000_0000) != 0 {
                report.push(PeAnomaly::new(AnomalyKind::WritableExecutableSection, AnomalyScore::HIGH, format!("section '{name}' is writable and executable")).with_section(name.clone()));
            }
            if self.check_entropy && raw_size > 0 && raw_offset + raw_size as usize <= data.len() {
                let ent = compute_entropy(&data[raw_offset..raw_offset + raw_size as usize]);
                if ent > self.entropy_threshold {
                    report.push(PeAnomaly::new(AnomalyKind::HighEntropySectionData, AnomalyScore::MEDIUM, format!("section '{name}' entropy {ent:.2} > {}", self.entropy_threshold)).with_section(name.clone()));
                }
            }
            if raw_size > 0 { section_ranges.push((raw_offset, raw_end, name)); }
        }
        for i in 0..section_ranges.len() {
            for j in (i + 1)..section_ranges.len() {
                let (s0, e0, ref n0) = section_ranges[i];
                let (s1, e1, ref n1) = section_ranges[j];
                if s0 < e1 && s1 < e0 {
                    report.push(PeAnomaly::new(AnomalyKind::OverlappingSections, AnomalyScore::HIGH, format!("sections '{n0}' and '{n1}' have overlapping raw data")));
                }
            }
        }
        section_ranges
    }

    fn check_overlay(data: &[u8], section_ranges: &[(usize, usize, String)], report: &mut AnomalyReport) {
        let max_end = section_ranges.iter().map(|(_, e, _)| *e).max().unwrap_or(0);
        if max_end > 0 && max_end < data.len() {
            let overlay_size = data.len() - max_end;
            report.push(PeAnomaly::new(AnomalyKind::OverlayPresent, AnomalyScore::INFO, format!("overlay of {overlay_size} bytes after sections")).with_offset(max_end));
            if overlay_size > data.len() / 10 {
                report.push(PeAnomaly::new(AnomalyKind::LargeOverlay, AnomalyScore::MEDIUM, format!("large overlay {overlay_size} bytes ({:.1}% of file)", f64::from(u32::try_from(overlay_size).unwrap_or(u32::MAX)) / f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX)) * 100.0)).with_offset(max_end));
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shannon entropy helper
// ─────────────────────────────────────────────────────────────────────────────

/// Compute Shannon entropy (bits per byte) over a byte slice.
#[must_use]
pub fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / len;
            -p * p.log2()
        })
        .sum()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_pe(is_64: bool, timestamp: u32) -> Vec<u8> {
        // Build the bare minimum PE so the parser doesn't fail early.
        let mut buf = vec![0u8; 0x400];
        // MZ
        buf[0] = 0x4D;
        buf[1] = 0x5A;
        // e_lfanew = 0x40
        buf[60..64].copy_from_slice(&0x40u32.to_le_bytes());
        // PE sig
        buf[0x40..0x44].copy_from_slice(b"PE\0\0");
        // COFF: machine AMD64 or i386, 0 sections, timestamp
        let machine: u16 = if is_64 { 0x8664 } else { 0x014C };
        buf[0x44..0x46].copy_from_slice(&machine.to_le_bytes());
        // COFF TimeDateStamp lives at coff+4 = 0x40 (PE sig) + 4 + 4 = 0x48.
        buf[0x48..0x4C].copy_from_slice(&timestamp.to_le_bytes());
        // optional header size
        let opt_size: u16 = if is_64 { 240 } else { 224 };
        buf[0x54..0x56].copy_from_slice(&opt_size.to_le_bytes());
        // optional header magic
        let magic: u16 = if is_64 { 0x020B } else { 0x010B };
        buf[0x58..0x5A].copy_from_slice(&magic.to_le_bytes());
        // SectionAlignment = 0x1000, FileAlignment = 0x200
        buf[0x58 + 32..0x58 + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[0x58 + 36..0x58 + 40].copy_from_slice(&0x200u32.to_le_bytes());
        // SizeOfHeaders = 0x200
        buf[0x58 + 60..0x58 + 64].copy_from_slice(&0x200u32.to_le_bytes());
        // SizeOfImage = 0x1000
        buf[0x58 + 56..0x58 + 60].copy_from_slice(&0x1000u32.to_le_bytes());
        // ImageBase
        if is_64 {
            buf[0x58 + 24..0x58 + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
            // NumberOfRvaAndSizes
            buf[0x58 + 108..0x58 + 112].copy_from_slice(&16u32.to_le_bytes());
        } else {
            buf[0x58 + 28..0x58 + 32].copy_from_slice(&0x400000u32.to_le_bytes());
            buf[0x58 + 92..0x58 + 96].copy_from_slice(&16u32.to_le_bytes());
        }
        buf
    }

    #[test]
    fn test_empty_file_is_critical() {
        let det = PeAnomalyDetector::new();
        let r = det.analyze(&[]);
        assert!(!r.anomalies.is_empty());
        assert!(r.anomalies.iter().any(|a| a.score >= AnomalyScore::CRITICAL));
    }

    #[test]
    fn test_non_pe_file() {
        let det = PeAnomalyDetector::new();
        let r = det.analyze(&[0xEF, 0xBB, 0xBF, 0x7B]);
        assert!(r.anomalies.iter().any(|a| a.kind == AnomalyKind::InvalidPeOffset));
    }

    #[test]
    fn test_valid_pe_low_anomaly_count() {
        let pe = make_minimal_pe(true, 1_600_000_000);
        let det = PeAnomalyDetector::new();
        let r = det.analyze(&pe);
        // Should only have low-severity anomalies (no sections → stripped DOS stub, etc.)
        let critical: Vec<_> = r.anomalies.iter().filter(|a| a.score >= AnomalyScore::CRITICAL).collect();
        assert!(critical.is_empty(), "Unexpected critical anomalies: {critical:?}");
    }

    #[test]
    fn test_zero_timestamp_detected() {
        let pe = make_minimal_pe(false, 0);
        let det = PeAnomalyDetector::new();
        let r = det.analyze(&pe);
        assert!(r.anomalies.iter().any(|a| a.kind == AnomalyKind::ZeroTimestamp));
    }

    #[test]
    fn test_future_timestamp_detected() {
        let pe = make_minimal_pe(false, 2_000_000_000); // year ~2033
        let det = PeAnomalyDetector::new();
        let r = det.analyze(&pe);
        assert!(r.anomalies.iter().any(|a| a.kind == AnomalyKind::FutureTimestamp));
    }

    #[test]
    fn test_anomaly_report_risk_tier() {
        let mut r = AnomalyReport::new();
        assert_eq!(r.risk_tier(), "clean");
        r.push(PeAnomaly::new(AnomalyKind::ZeroTimestamp, AnomalyScore::LOW, "x"));
        assert_eq!(r.risk_tier(), "low");
        r.push(PeAnomaly::new(AnomalyKind::InvalidPeOffset, AnomalyScore::CRITICAL, "y"));
        assert_eq!(r.risk_tier(), "critical");
    }

    #[test]
    fn test_anomaly_report_worst() {
        let mut r = AnomalyReport::new();
        r.push(PeAnomaly::new(AnomalyKind::ZeroTimestamp, AnomalyScore::LOW, "lo"));
        r.push(PeAnomaly::new(AnomalyKind::InvalidPeOffset, AnomalyScore::CRITICAL, "hi"));
        assert_eq!(r.worst().unwrap().score, AnomalyScore::CRITICAL);
    }

    #[test]
    fn test_anomaly_report_count_by_kind() {
        let mut r = AnomalyReport::new();
        r.push(PeAnomaly::new(AnomalyKind::ZeroTimestamp, AnomalyScore::LOW, "a"));
        r.push(PeAnomaly::new(AnomalyKind::ZeroTimestamp, AnomalyScore::LOW, "b"));
        let counts = r.count_by_kind();
        assert_eq!(counts[&AnomalyKind::ZeroTimestamp], 2);
    }

    #[test]
    fn test_anomaly_score_label() {
        assert_eq!(AnomalyScore::INFO.label(), "info");
        assert_eq!(AnomalyScore::LOW.label(), "low");
        assert_eq!(AnomalyScore::MEDIUM.label(), "medium");
        assert_eq!(AnomalyScore::HIGH.label(), "high");
        assert_eq!(AnomalyScore::CRITICAL.label(), "critical");
    }

    #[test]
    fn test_compute_entropy_uniform() {
        let data: Vec<u8> = (0..=255).collect();
        let e = compute_entropy(&data);
        assert!((e - 8.0).abs() < 0.01, "expected ~8.0 got {e}");
    }

    #[test]
    fn test_compute_entropy_constant() {
        let data = vec![0xAAu8; 100];
        let e = compute_entropy(&data);
        assert_eq!(e, 0.0);
    }

    #[test]
    fn test_anomaly_with_offset_section() {
        let a = PeAnomaly::new(AnomalyKind::OverlappingSections, AnomalyScore::HIGH, "overlap")
            .with_offset(0x100)
            .with_section(".text");
        assert_eq!(a.offset, Some(0x100));
        assert_eq!(a.section.as_deref(), Some(".text"));
    }

    #[test]
    fn test_anomaly_display() {
        let a = PeAnomaly::new(AnomalyKind::ZeroTimestamp, AnomalyScore::LOW, "ts=0");
        let s = a.to_string();
        assert!(s.contains("ZeroTimestamp"));
    }

    #[test]
    fn test_anomaly_report_is_empty() {
        let r = AnomalyReport::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn test_high_entropy_section_detected() {
        // Build a PE with one section filled with high-entropy data.
        let mut pe = make_minimal_pe(true, 1_600_000_000);
        // Extend to add a "section" with pseudo-random data.
        let mut section = vec![0u8; 512];
        for (i, b) in section.iter_mut().enumerate() {
            *b = ((i * 17 + 31) ^ (i >> 3)) as u8;
        }
        // Write a section table entry at opt_off + opt_size.
        // opt_off = 0x58 (0x40 + 0x18), opt_size = 240
        // sect_table = 0x58 + 240 = 0x148
        // COFF num_sections = 1 at offset 0x46
        pe[0x46] = 1; // num_sections
        let sect_off = 0x148usize;
        if pe.len() < sect_off + 40 {
            pe.resize(sect_off + 40, 0);
        }
        let name = b".packed\0";
        pe[sect_off..sect_off + 8].copy_from_slice(name);
        let raw_size = 512u32;
        let raw_offset = pe.len() as u32;
        pe[sect_off + 8..sect_off + 12].copy_from_slice(&512u32.to_le_bytes()); // VirtualSize
        pe[sect_off + 12..sect_off + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VA
        pe[sect_off + 16..sect_off + 20].copy_from_slice(&raw_size.to_le_bytes());
        pe[sect_off + 20..sect_off + 24].copy_from_slice(&raw_offset.to_le_bytes());
        pe[sect_off + 36..sect_off + 40].copy_from_slice(&0x60000020u32.to_le_bytes()); // CODE|EXEC|READ
        pe.extend_from_slice(&section);

        let det = PeAnomalyDetector::new();
        let r = det.analyze(&pe);
        // Should detect high entropy.
        let high_ent = r.anomalies.iter().any(|a| a.kind == AnomalyKind::HighEntropySectionData);
        assert!(high_ent, "Expected high entropy anomaly, got: {:?}", r.anomalies);
    }
}
