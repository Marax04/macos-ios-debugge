// pe_anomaly_detector.rs — PE file anomaly detector for RustRE

// ─── AnomalySeverity ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnomalySeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl AnomalySeverity {
    pub fn score(&self) -> u8 {
        match self {
            AnomalySeverity::Info => 1,
            AnomalySeverity::Low => 5,
            AnomalySeverity::Medium => 15,
            AnomalySeverity::High => 25,
            AnomalySeverity::Critical => 40,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AnomalySeverity::Info => "INFO",
            AnomalySeverity::Low => "LOW",
            AnomalySeverity::Medium => "MEDIUM",
            AnomalySeverity::High => "HIGH",
            AnomalySeverity::Critical => "CRITICAL",
        }
    }
}

// ─── AnomalyType ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum AnomalyType {
    InvalidMagic,
    TruncatedFile,
    OverlappingSection,
    GapBetweenSections,
    SuspiciousEP,
    InvalidImportDescriptor,
    CorruptedExportDir,
    SectionCharacteristicsMismatch,
    ChecksumMismatch,
    TimestampZero,
    TimestampFuture,
    LargeOverlay,
    ManyImports(u32),
    NoImports,
    EPInWritableSection,
    SectionNameNonPrintable,
}

impl AnomalyType {
    pub fn as_str(&self) -> &str {
        match self {
            AnomalyType::InvalidMagic => "InvalidMagic",
            AnomalyType::TruncatedFile => "TruncatedFile",
            AnomalyType::OverlappingSection => "OverlappingSection",
            AnomalyType::GapBetweenSections => "GapBetweenSections",
            AnomalyType::SuspiciousEP => "SuspiciousEP",
            AnomalyType::InvalidImportDescriptor => "InvalidImportDescriptor",
            AnomalyType::CorruptedExportDir => "CorruptedExportDir",
            AnomalyType::SectionCharacteristicsMismatch => "SectionCharacteristicsMismatch",
            AnomalyType::ChecksumMismatch => "ChecksumMismatch",
            AnomalyType::TimestampZero => "TimestampZero",
            AnomalyType::TimestampFuture => "TimestampFuture",
            AnomalyType::LargeOverlay => "LargeOverlay",
            AnomalyType::ManyImports(_) => "ManyImports",
            AnomalyType::NoImports => "NoImports",
            AnomalyType::EPInWritableSection => "EPInWritableSection",
            AnomalyType::SectionNameNonPrintable => "SectionNameNonPrintable",
        }
    }
}

// ─── Anomaly ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Anomaly {
    pub type_: AnomalyType,
    pub severity: AnomalySeverity,
    pub description: String,
    pub offset: Option<u64>,
}

impl Anomaly {
    pub fn new(type_: AnomalyType, severity: AnomalySeverity, description: &str, offset: Option<u64>) -> Self {
        Self {
            type_,
            severity,
            description: description.to_string(),
            offset,
        }
    }
}

// ─── AnomalyReport ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct AnomalyReport {
    pub anomalies: Vec<Anomaly>,
    pub risk_score: u8,
}

impl AnomalyReport {
    pub fn new(anomalies: Vec<Anomaly>) -> Self {
        let score: u32 = anomalies.iter().map(|a| a.severity.score() as u32).sum();
        let risk_score = score.min(100) as u8;
        Self { anomalies, risk_score }
    }

    pub fn count_by_severity(&self, sev: &AnomalySeverity) -> usize {
        self.anomalies.iter().filter(|a| &a.severity == sev).count()
    }

    pub fn is_suspicious(&self) -> bool {
        self.risk_score >= 20
    }

    pub fn is_malicious(&self) -> bool {
        self.risk_score >= 60
    }
}

// ─── PE helpers ───────────────────────────────────────────────────────────────

fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > data.len() { return None; }
    Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > data.len() { return None; }
    Some(u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]))
}

/// Section descriptor parsed from PE header.
#[derive(Debug, Clone)]
struct SectionDesc {
    name: [u8; 8],
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
    characteristics: u32,
}

impl SectionDesc {
    fn name_str(&self) -> String {
        self.name.iter().map_while(|&b| if b == 0 { None } else { Some(b as char) }).collect()
    }

    fn is_writable(&self) -> bool {
        self.characteristics & 0x80000000 != 0
    }

    fn is_executable(&self) -> bool {
        self.characteristics & 0x20000000 != 0
    }
}

// ─── PeAnomalyDetector ───────────────────────────────────────────────────────

pub struct PeAnomalyDetector<'a> {
    data: &'a [u8],
}

impl<'a> PeAnomalyDetector<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn pe_header_offset(&self) -> Option<usize> {
        if self.data.len() < 0x40 { return None; }
        let e_lfanew = read_u32_le(self.data, 0x3C)? as usize;
        if e_lfanew + 4 > self.data.len() { return None; }
        Some(e_lfanew)
    }

    fn optional_header_offset(&self) -> Option<usize> {
        let pe_off = self.pe_header_offset()?;
        Some(pe_off + 24) // PE sig (4) + COFF header (20)
    }

    fn parse_sections(&self) -> Vec<SectionDesc> {
        let pe_off = match self.pe_header_offset() { Some(o) => o, None => return vec![] };
        let num_sections = match read_u16_le(self.data, pe_off + 6) { Some(n) => n as usize, None => return vec![] };
        let opt_header_size = match read_u16_le(self.data, pe_off + 20) { Some(s) => s as usize, None => return vec![] };
        let section_table_off = pe_off + 24 + opt_header_size;

        let mut sections = Vec::new();
        for i in 0..num_sections {
            let base = match section_table_off.checked_add(i.saturating_mul(40)) {
                Some(v) => v,
                None => break,
            };
            if base.saturating_add(40) > self.data.len() { break; }
            let mut name = [0u8; 8];
            name.copy_from_slice(&self.data[base..base + 8]);
            let virtual_size = read_u32_le(self.data, base + 8).unwrap_or(0);
            let virtual_address = read_u32_le(self.data, base + 12).unwrap_or(0);
            let raw_size = read_u32_le(self.data, base + 16).unwrap_or(0);
            let raw_offset = read_u32_le(self.data, base + 20).unwrap_or(0);
            let characteristics = read_u32_le(self.data, base + 36).unwrap_or(0);
            sections.push(SectionDesc { name, virtual_address, virtual_size, raw_offset, raw_size, characteristics });
        }
        sections
    }

    /// Check file magic (MZ).
    pub fn check_magic(&self) -> Option<Anomaly> {
        if self.data.len() < 2 || self.data[0] != 0x4D || self.data[1] != 0x5A {
            return Some(Anomaly::new(
                AnomalyType::InvalidMagic,
                AnomalySeverity::Critical,
                "File does not start with MZ magic",
                Some(0),
            ));
        }
        // Check PE signature
        if let Some(pe_off) = self.pe_header_offset() {
            if pe_off + 4 > self.data.len()
                || self.data[pe_off] != 0x50
                || self.data[pe_off + 1] != 0x45
                || self.data[pe_off + 2] != 0x00
                || self.data[pe_off + 3] != 0x00
            {
                return Some(Anomaly::new(
                    AnomalyType::InvalidMagic,
                    AnomalySeverity::Critical,
                    "PE signature not found at e_lfanew offset",
                    Some(pe_off as u64),
                ));
            }
        }
        None
    }

    /// Check if file appears truncated.
    pub fn check_truncated(&self) -> Option<Anomaly> {
        let sections = self.parse_sections();
        for sec in &sections {
            let end = (sec.raw_offset as usize).saturating_add(sec.raw_size as usize);
            if end > self.data.len() {
                return Some(Anomaly::new(
                    AnomalyType::TruncatedFile,
                    AnomalySeverity::High,
                    &format!("Section '{}' extends beyond file end (offset 0x{:X} + size 0x{:X} > file size 0x{:X})",
                        sec.name_str(), sec.raw_offset, sec.raw_size, self.data.len()),
                    Some(sec.raw_offset as u64),
                ));
            }
        }
        None
    }

    /// Check for overlapping sections.
    pub fn check_section_overlap(&self) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();
        let sections = self.parse_sections();
        for i in 0..sections.len() {
            for j in (i + 1)..sections.len() {
                let a = &sections[i];
                let b = &sections[j];
                if a.raw_size == 0 || b.raw_size == 0 { continue; }
                let a_start = a.raw_offset;
                let a_end = a.raw_offset.saturating_add(a.raw_size);
                let b_start = b.raw_offset;
                let b_end = b.raw_offset.saturating_add(b.raw_size);
                if a_start < b_end && b_start < a_end {
                    anomalies.push(Anomaly::new(
                        AnomalyType::OverlappingSection,
                        AnomalySeverity::High,
                        &format!("Sections '{}' and '{}' overlap in raw data", a.name_str(), b.name_str()),
                        Some(a.raw_offset as u64),
                    ));
                }
            }
        }
        anomalies
    }

    /// Check for gaps between sections.
    pub fn check_section_gaps(&self) -> Vec<Anomaly> {
        let mut sections = self.parse_sections();
        if sections.is_empty() { return vec![]; }
        sections.sort_by_key(|s| s.raw_offset);
        let mut anomalies = Vec::new();
        for i in 1..sections.len() {
            let prev_end = sections[i - 1].raw_offset.saturating_add(sections[i - 1].raw_size);
            let cur_start = sections[i].raw_offset;
            if prev_end < cur_start {
                let gap = cur_start - prev_end;
                if gap > 512 {
                    anomalies.push(Anomaly::new(
                        AnomalyType::GapBetweenSections,
                        AnomalySeverity::Low,
                        &format!("Gap of {} bytes between sections '{}' and '{}'",
                            gap, sections[i-1].name_str(), sections[i].name_str()),
                        Some(prev_end as u64),
                    ));
                }
            }
        }
        anomalies
    }

    /// Check timestamp field.
    pub fn check_timestamps(&self) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();
        let pe_off = match self.pe_header_offset() { Some(o) => o, None => return anomalies };
        let timestamp = match read_u32_le(self.data, pe_off + 8) { Some(t) => t, None => return anomalies };
        if timestamp == 0 {
            anomalies.push(Anomaly::new(
                AnomalyType::TimestampZero,
                AnomalySeverity::Low,
                "PE timestamp is zero (stripped or invalid)",
                Some((pe_off + 8) as u64),
            ));
        }
        // 2030-01-01 = 1893456000 (future)
        if timestamp > 1893456000 {
            anomalies.push(Anomaly::new(
                AnomalyType::TimestampFuture,
                AnomalySeverity::Medium,
                &format!("PE timestamp 0x{:08X} is in the future", timestamp),
                Some((pe_off + 8) as u64),
            ));
        }
        anomalies
    }

    /// Check entry point location.
    pub fn check_ep_location(&self) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();
        let opt_off = match self.optional_header_offset() { Some(o) => o, None => return anomalies };
        // Address of entry point is at offset 16 in optional header
        let ep_rva = match read_u32_le(self.data, opt_off + 16) { Some(e) => e, None => return anomalies };
        let sections = self.parse_sections();
        let mut ep_in_section = false;
        for sec in &sections {
            if ep_rva >= sec.virtual_address && ep_rva < sec.virtual_address + sec.virtual_size.max(sec.raw_size) {
                ep_in_section = true;
                if sec.is_writable() && !sec.is_executable() {
                    anomalies.push(Anomaly::new(
                        AnomalyType::EPInWritableSection,
                        AnomalySeverity::High,
                        &format!("Entry point RVA 0x{:X} is in writable (non-exec) section '{}'",
                            ep_rva, sec.name_str()),
                        Some(ep_rva as u64),
                    ));
                }
                if sec.is_writable() && sec.is_executable() {
                    anomalies.push(Anomaly::new(
                        AnomalyType::SuspiciousEP,
                        AnomalySeverity::Medium,
                        &format!("Entry point in section '{}' with RWX permissions", sec.name_str()),
                        Some(ep_rva as u64),
                    ));
                }
            }
        }
        if !ep_in_section && ep_rva != 0 {
            anomalies.push(Anomaly::new(
                AnomalyType::SuspiciousEP,
                AnomalySeverity::High,
                &format!("Entry point RVA 0x{:X} does not fall within any section", ep_rva),
                Some(ep_rva as u64),
            ));
        }
        anomalies
    }

    /// Check import directory.
    pub fn check_imports(&self) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();
        let opt_off = match self.optional_header_offset() { Some(o) => o, None => return anomalies };
        // Optional header magic: 0x10B = PE32, 0x20B = PE32+
        let magic = match read_u16_le(self.data, opt_off) { Some(m) => m, None => return anomalies };
        let data_dir_off = match magic {
            0x10B => opt_off + 96,  // PE32
            0x20B => opt_off + 112, // PE32+
            _ => return anomalies,
        };
        // Import directory is data dir entry 1 (offset 8 into data directories)
        let import_rva = match read_u32_le(self.data, data_dir_off + 8) { Some(r) => r, None => return anomalies };
        let import_size = match read_u32_le(self.data, data_dir_off + 12) { Some(s) => s, None => return anomalies };
        if import_rva == 0 && import_size == 0 {
            anomalies.push(Anomaly::new(
                AnomalyType::NoImports,
                AnomalySeverity::Medium,
                "No import directory (packed or native binary)",
                None,
            ));
            return anomalies;
        }
        if import_size > 0 && import_size < 20 {
            anomalies.push(Anomaly::new(
                AnomalyType::InvalidImportDescriptor,
                AnomalySeverity::High,
                &format!("Import directory size {} is too small for a valid descriptor", import_size),
                Some(import_rva as u64),
            ));
        }
        // Count import DLL entries (each is 20 bytes)
        let num_imports = import_size / 20;
        if num_imports > 200 {
            anomalies.push(Anomaly::new(
                AnomalyType::ManyImports(num_imports),
                AnomalySeverity::Low,
                &format!("{} import descriptors is unusually high", num_imports),
                Some(import_rva as u64),
            ));
        }
        anomalies
    }

    /// Check section names for non-printable characters.
    pub fn check_section_names(&self) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();
        let sections = self.parse_sections();
        for sec in &sections {
            let has_non_printable = sec.name.iter().any(|&b| b != 0 && (b < 0x20 || b > 0x7E));
            if has_non_printable {
                anomalies.push(Anomaly::new(
                    AnomalyType::SectionNameNonPrintable,
                    AnomalySeverity::Medium,
                    &format!("Section name contains non-printable characters: {:?}", &sec.name),
                    None,
                ));
            }
        }
        anomalies
    }

    /// Check section characteristics for mismatches.
    pub fn check_section_characteristics(&self) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();
        let sections = self.parse_sections();
        for sec in &sections {
            // Writable + executable is suspicious
            if sec.is_writable() && sec.is_executable() {
                anomalies.push(Anomaly::new(
                    AnomalyType::SectionCharacteristicsMismatch,
                    AnomalySeverity::High,
                    &format!("Section '{}' has both WRITE and EXECUTE flags set", sec.name_str()),
                    Some(sec.virtual_address as u64),
                ));
            }
        }
        anomalies
    }

    /// Check for large overlay (data appended after last section).
    pub fn check_overlay(&self) -> Option<Anomaly> {
        let sections = self.parse_sections();
        if sections.is_empty() { return None; }
        let last_end = sections.iter().map(|s| s.raw_offset.saturating_add(s.raw_size)).max().unwrap_or(0) as usize;
        if last_end < self.data.len() {
            let overlay_size = self.data.len() - last_end;
            if overlay_size > 4096 {
                return Some(Anomaly::new(
                    AnomalyType::LargeOverlay,
                    AnomalySeverity::Medium,
                    &format!("Overlay of {} bytes appended after last section", overlay_size),
                    Some(last_end as u64),
                ));
            }
        }
        None
    }

    /// Run all checks and return a report.
    pub fn detect_all(&self) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();
        if let Some(a) = self.check_magic() { anomalies.push(a); }
        if let Some(a) = self.check_truncated() { anomalies.push(a); }
        anomalies.extend(self.check_section_overlap());
        anomalies.extend(self.check_section_gaps());
        anomalies.extend(self.check_timestamps());
        anomalies.extend(self.check_ep_location());
        anomalies.extend(self.check_imports());
        anomalies.extend(self.check_section_names());
        anomalies.extend(self.check_section_characteristics());
        if let Some(a) = self.check_overlay() { anomalies.push(a); }
        anomalies
    }

    pub fn report(&self) -> AnomalyReport {
        AnomalyReport::new(self.detect_all())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_data() -> Vec<u8> { vec![0u8; 512] }

    fn minimal_mz() -> Vec<u8> {
        let mut d = vec![0u8; 512];
        // MZ magic
        d[0] = 0x4D; d[1] = 0x5A;
        // e_lfanew = 0x40
        d[0x3C] = 0x40;
        // PE sig
        d[0x40] = 0x50; d[0x41] = 0x45; d[0x42] = 0x00; d[0x43] = 0x00;
        // Machine (x86)
        d[0x44] = 0x4C; d[0x45] = 0x01;
        // NumberOfSections = 0
        d[0x46] = 0x00; d[0x47] = 0x00;
        // SizeOfOptionalHeader = 0xE0
        d[0x54] = 0xE0; d[0x55] = 0x00;
        // Optional header magic = PE32
        d[0x58] = 0x0B; d[0x59] = 0x01;
        d
    }

    #[test]
    fn test_invalid_magic_empty() {
        let data = empty_data();
        let det = PeAnomalyDetector::new(&data);
        let a = det.check_magic();
        assert!(a.is_some());
        assert_eq!(a.unwrap().type_, AnomalyType::InvalidMagic);
    }

    #[test]
    fn test_valid_magic_no_anomaly() {
        let d = minimal_mz();
        let det = PeAnomalyDetector::new(&d);
        let a = det.check_magic();
        assert!(a.is_none());
    }

    #[test]
    fn test_severity_score_ordering() {
        assert!(AnomalySeverity::Critical.score() > AnomalySeverity::High.score());
        assert!(AnomalySeverity::High.score() > AnomalySeverity::Medium.score());
    }

    #[test]
    fn test_anomaly_report_risk_score_capped() {
        let anomalies: Vec<Anomaly> = (0..10).map(|_| Anomaly::new(
            AnomalyType::OverlappingSection,
            AnomalySeverity::Critical,
            "test",
            None,
        )).collect();
        let report = AnomalyReport::new(anomalies);
        assert!(report.risk_score <= 100);
    }

    #[test]
    fn test_anomaly_type_as_str() {
        assert_eq!(AnomalyType::TruncatedFile.as_str(), "TruncatedFile");
        assert_eq!(AnomalyType::ManyImports(5).as_str(), "ManyImports");
    }

    #[test]
    fn test_check_timestamps_zero() {
        let mut d = minimal_mz();
        // Timestamp at pe+8 = 0x48
        d[0x48] = 0; d[0x49] = 0; d[0x4A] = 0; d[0x4B] = 0;
        let det = PeAnomalyDetector::new(&d);
        let anomalies = det.check_timestamps();
        assert!(anomalies.iter().any(|a| a.type_ == AnomalyType::TimestampZero));
    }

    #[test]
    fn test_check_timestamps_future() {
        let mut d = minimal_mz();
        // Timestamp far in future: 0x90000000
        d[0x48] = 0x00; d[0x49] = 0x00; d[0x4A] = 0x00; d[0x4B] = 0x90;
        let det = PeAnomalyDetector::new(&d);
        let anomalies = det.check_timestamps();
        assert!(anomalies.iter().any(|a| a.type_ == AnomalyType::TimestampFuture));
    }

    #[test]
    fn test_check_section_names_printable() {
        let d = minimal_mz();
        let det = PeAnomalyDetector::new(&d);
        let anomalies = det.check_section_names();
        // No sections → no anomalies
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_detect_all_returns_vec() {
        let d = minimal_mz();
        let det = PeAnomalyDetector::new(&d);
        let all = det.detect_all();
        // Just verify it runs without panic
        let _ = all;
    }

    #[test]
    fn test_report_is_suspicious() {
        let anomalies = vec![
            Anomaly::new(AnomalyType::EPInWritableSection, AnomalySeverity::High, "test", None),
            Anomaly::new(AnomalyType::SuspiciousEP, AnomalySeverity::Medium, "test", None),
        ];
        let report = AnomalyReport::new(anomalies);
        assert!(report.is_suspicious());
    }

    #[test]
    fn test_report_count_by_severity() {
        let anomalies = vec![
            Anomaly::new(AnomalyType::TimestampZero, AnomalySeverity::Low, "t", None),
            Anomaly::new(AnomalyType::TimestampFuture, AnomalySeverity::Medium, "t", None),
            Anomaly::new(AnomalyType::NoImports, AnomalySeverity::Medium, "t", None),
        ];
        let report = AnomalyReport::new(anomalies);
        assert_eq!(report.count_by_severity(&AnomalySeverity::Medium), 2);
        assert_eq!(report.count_by_severity(&AnomalySeverity::Low), 1);
    }

    #[test]
    fn test_no_imports_anomaly() {
        let d = minimal_mz();
        let det = PeAnomalyDetector::new(&d);
        let anomalies = det.check_imports();
        // No import directory in minimal MZ → NoImports
        assert!(anomalies.iter().any(|a| a.type_ == AnomalyType::NoImports));
    }

    #[test]
    fn test_check_overlay_none_for_minimal() {
        let d = minimal_mz();
        let det = PeAnomalyDetector::new(&d);
        let result = det.check_overlay();
        // No sections → no overlay
        assert!(result.is_none());
    }

    #[test]
    fn test_anomaly_severity_ordering() {
        assert!(AnomalySeverity::Critical > AnomalySeverity::Info);
    }

    #[test]
    fn test_report_is_malicious_threshold() {
        let anomalies: Vec<Anomaly> = (0..3).map(|_|
            Anomaly::new(AnomalyType::OverlappingSection, AnomalySeverity::Critical, "t", None)
        ).collect();
        let report = AnomalyReport::new(anomalies);
        assert!(report.is_malicious());
    }

    #[test]
    fn test_invalid_magic_no_mz_in_non_pe() {
        let data = b"ELF\x02\x01\x01\x00\x00".to_vec();
        let det = PeAnomalyDetector::new(&data);
        let a = det.check_magic();
        assert!(a.is_some());
    }
}
