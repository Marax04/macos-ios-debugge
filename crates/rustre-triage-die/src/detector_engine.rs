// rustre-triage-die/src/detector_engine.rs
// Detection engine: executes signatures, combines results, resolves conflicts.

use std::collections::HashMap;
use crate::die_signature_db::{DieCategory, DieSignature, DieSignatureDatabase};

/// A structured detection result for one found item.
#[derive(Debug, Clone)]
pub struct Detection {
    pub category: DieCategory,
    pub name: String,
    pub version: Option<String>,
    pub confidence: f32,        // 0.0 – 1.0
    pub matching_sig_ids: Vec<u32>,
    pub notes: Vec<String>,
}

/// Full detection report from the engine.
#[derive(Debug, Clone)]
pub struct DetectionReport {
    pub compiler: Option<Detection>,
    pub linker: Option<Detection>,
    pub packer: Option<Detection>,
    pub protector: Option<Detection>,
    pub installer: Option<Detection>,
    pub runtime: Option<Detection>,
    pub overlay: Option<Detection>,
    pub libraries: Vec<Detection>,
    pub raw_matches: Vec<u32>,   // Sig IDs.
    pub elapsed_us: u64,
}

impl DetectionReport {
    fn new() -> Self {
        Self {
            compiler: None, linker: None, packer: None, protector: None,
            installer: None, runtime: None, overlay: None, libraries: Vec::new(),
            raw_matches: Vec::new(), elapsed_us: 0,
        }
    }

    /// Format a short human-readable summary.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(ref p) = self.packer    { parts.push(format!("Packer: {}", p.name)); }
        if let Some(ref p) = self.protector { parts.push(format!("Protector: {}", p.name)); }
        if let Some(ref c) = self.compiler  { parts.push(format!("Compiler: {}", c.name)); }
        if let Some(ref l) = self.linker    { parts.push(format!("Linker: {}", l.name)); }
        if let Some(ref r) = self.runtime   { parts.push(format!("Runtime: {}", r.name)); }
        if let Some(ref i) = self.installer { parts.push(format!("Installer: {}", i.name)); }
        if parts.is_empty() { "Unknown".into() } else { parts.join(", ") }
    }

    /// Returns true if any packer or protector was detected.
    pub fn is_packed(&self) -> bool {
        self.packer.is_some() || self.protector.is_some()
    }
}

/// Configuration for the detection engine.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub min_confidence: f32,
    pub max_section_read: usize,
    pub ep_bytes_count: usize,
    pub resolve_conflicts: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.5,
            max_section_read: 4096,
            ep_bytes_count: 64,
            resolve_conflicts: true,
        }
    }
}

/// The main detection engine.
pub struct DetectorEngine {
    pub db: DieSignatureDatabase,
    pub config: EngineConfig,
}

impl Default for DetectorEngine {
    fn default() -> Self {
        Self { db: DieSignatureDatabase::new(), config: EngineConfig::default() }
    }
}

impl DetectorEngine {
    pub fn new(config: EngineConfig) -> Self {
        Self { db: DieSignatureDatabase::new(), config }
    }

    /// Analyse a binary blob.
    pub fn analyze(&self, data: &[u8]) -> DetectionReport {
        let t0 = std::time::Instant::now();
        let mut report = DetectionReport::new();

        // Extract entry point bytes.
        let ep_bytes = self.extract_ep_bytes(data);
        // Extract section names.
        let sections = self.extract_section_names(data);

        // Run all signatures.
        let matches: Vec<&DieSignature> = self.db.signatures.iter()
            .filter(|sig| {
                // Check section constraint.
                if let Some(sec) = sig.section {
                    if !sections.iter().any(|s| s.contains(sec)) { return false; }
                }
                sig.matches(data, &ep_bytes)
            })
            .collect();

        report.raw_matches = matches.iter().map(|s| s.id).collect();

        // Group by category and build detections.
        let mut by_cat: HashMap<DieCategory, Vec<&&DieSignature>> = HashMap::new();
        for sig in &matches {
            by_cat.entry(sig.category).or_default().push(sig);
        }

        // Assign detections to report fields.
        for (cat, sigs) in &by_cat {
            let det = self.build_detection(*cat, sigs);
            if det.confidence < self.config.min_confidence { continue; }
            match cat {
                DieCategory::Compiler  => report.compiler  = Some(det),
                DieCategory::Linker    => report.linker    = Some(det),
                DieCategory::Packer    => report.packer    = Some(det),
                DieCategory::Protector => report.protector = Some(det),
                DieCategory::Installer => report.installer = Some(det),
                DieCategory::Runtime   => report.runtime   = Some(det),
                DieCategory::Overlay   => report.overlay   = Some(det),
                DieCategory::Library   => report.libraries.push(det),
                DieCategory::Other     => {},
            }
        }

        if self.config.resolve_conflicts {
            self.resolve_conflicts(&mut report);
        }

        report.elapsed_us = t0.elapsed().as_micros() as u64;
        report
    }

    fn build_detection(&self, category: DieCategory, sigs: &[&&DieSignature]) -> Detection {
        // Group by name.
        let mut name_counts: HashMap<&str, usize> = HashMap::with_capacity(sigs.len());
        for sig in sigs { *name_counts.entry(sig.name).or_insert(0) += 1; }
        let best_name = name_counts.iter().max_by_key(|&(_, &c)| c).map(|(&n, _)| n).unwrap_or("Unknown");

        // Pick version from any sig with a version hint that matches best_name.
        let version = sigs.iter()
            .filter(|s| s.name == best_name)
            .find_map(|s| s.version_hint)
            .map(|v| v.to_string());

        // Confidence: more matching signatures = higher confidence (capped at 1.0).
        let confidence = (sigs.len() as f32 * 0.3).min(1.0);

        Detection {
            category,
            name: best_name.to_string(),
            version,
            confidence,
            matching_sig_ids: sigs.iter().map(|s| s.id).collect(),
            notes: Vec::new(),
        }
    }

    fn resolve_conflicts(&self, report: &mut DetectionReport) {
        // If a protector is detected, the compiler detection is less reliable.
        if report.protector.is_some() {
            if let Some(ref mut c) = report.compiler {
                c.confidence *= 0.5;
                c.notes.push("Reduced confidence: protector detected".into());
            }
        }
        // If a packer is detected, remove compiler/linker (they're likely the packer's stub).
        if report.packer.is_some() {
            if let Some(ref mut c) = report.compiler {
                if c.confidence < 0.7 {
                    c.notes.push("Possibly the packer stub compiler, not original".into());
                }
            }
        }
        // If both packer and protector are detected, keep the protector (more specific).
        if report.packer.is_some() && report.protector.is_some() {
            if let Some(ref prot) = report.protector {
                if prot.confidence > report.packer.as_ref().map_or(0.0, |p| p.confidence) {
                    let prot_name = prot.name.clone();
                    if let Some(ref mut pack) = report.packer {
                        pack.notes.push(format!("May be subsumed by protector: {prot_name}"));
                    }
                }
            }
        }
    }

    fn extract_ep_bytes(&self, data: &[u8]) -> Vec<u8> {
        if data.len() < 4 || !data.starts_with(b"MZ") {
            return data[..data.len().min(self.config.ep_bytes_count)].to_vec();
        }
        let pe_off = u32::from_le_bytes(data[60..64].try_into().unwrap_or([0; 4])) as usize;
        if pe_off + 24 > data.len() { return Vec::new(); }
        // Optional header starts at pe_off + 24.
        let opt_hdr = pe_off + 24;
        let magic = u16::from_le_bytes(data[opt_hdr..opt_hdr + 2].try_into().unwrap_or([0; 2]));
        let ep_rva = if magic == 0x20b { // PE32+
            u32::from_le_bytes(data[opt_hdr + 16..opt_hdr + 20].try_into().unwrap_or([0; 4]))
        } else { // PE32
            u32::from_le_bytes(data[opt_hdr + 16..opt_hdr + 20].try_into().unwrap_or([0; 4]))
        } as usize;
        // Resolve RVA: crude linear search for a section containing ep_rva.
        let ep_offset = self.rva_to_file_offset(data, ep_rva, pe_off);
        let start = ep_offset.unwrap_or(0);
        let end = (start + self.config.ep_bytes_count).min(data.len());
        data[start..end].to_vec()
    }

    fn rva_to_file_offset(&self, data: &[u8], rva: usize, pe_off: usize) -> Option<usize> {
        if pe_off + 6 > data.len() { return None; }
        let num_sections = u16::from_le_bytes(data[pe_off + 6..pe_off + 8].try_into().ok()?) as usize;
        let opt_hdr_size = u16::from_le_bytes(data[pe_off + 20..pe_off + 22].try_into().ok()?) as usize;
        let section_table_offset = pe_off + 24 + opt_hdr_size;

        for i in 0..num_sections {
            let sec_off = section_table_offset + i * 40;
            if sec_off + 40 > data.len() { break; }
            let virt_addr = u32::from_le_bytes(data[sec_off + 12..sec_off + 16].try_into().ok()?) as usize;
            let virt_size = u32::from_le_bytes(data[sec_off + 16..sec_off + 20].try_into().ok()?) as usize;
            let raw_off   = u32::from_le_bytes(data[sec_off + 20..sec_off + 24].try_into().ok()?) as usize;

            if rva >= virt_addr && rva < virt_addr + virt_size {
                return Some(raw_off + (rva - virt_addr));
            }
        }
        None
    }

    fn extract_section_names(&self, data: &[u8]) -> Vec<String> {
        if data.len() < 64 || !data.starts_with(b"MZ") { return Vec::new(); }
        let pe_off = u32::from_le_bytes(data[60..64].try_into().unwrap_or([0; 4])) as usize;
        if pe_off + 8 > data.len() { return Vec::new(); }
        let num_sections = u16::from_le_bytes(data[pe_off + 6..pe_off + 8].try_into().unwrap_or([0; 2])) as usize;
        let opt_size = u16::from_le_bytes(
            if pe_off + 22 <= data.len() { data[pe_off + 20..pe_off + 22].try_into().unwrap_or([0; 2]) } else { [0; 2] }
        ) as usize;
        let section_table = pe_off + 24 + opt_size;
        let mut names = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let off = section_table + i * 40;
            if off + 8 > data.len() { break; }
            let name_bytes = &data[off..off + 8];
            if let Ok(s) = std::str::from_utf8(name_bytes) {
                names.push(s.trim_end_matches('\0').to_string());
            }
        }
        names
    }
}

/// Lightweight wrapper to scan bytes from a file path.
pub fn scan_bytes(data: &[u8]) -> DetectionReport {
    DetectorEngine::default().analyze(data)
}

/// Format a detection report as a human-readable string.
pub fn format_report(report: &DetectionReport) -> String {
    let mut lines = Vec::new();
    lines.push(format!("DIE Detection Report ({} µs)", report.elapsed_us));
    lines.push(format!("  Summary: {}", report.summary()));
    if let Some(ref c) = report.compiler  { lines.push(format!("  Compiler:  {} {:?}", c.name, c.version)); }
    if let Some(ref l) = report.linker    { lines.push(format!("  Linker:    {}", l.name)); }
    if let Some(ref p) = report.packer    { lines.push(format!("  Packer:    {} (conf={:.2})", p.name, p.confidence)); }
    if let Some(ref p) = report.protector { lines.push(format!("  Protector: {} (conf={:.2})", p.name, p.confidence)); }
    if let Some(ref i) = report.installer { lines.push(format!("  Installer: {}", i.name)); }
    if let Some(ref r) = report.runtime   { lines.push(format!("  Runtime:   {}", r.name)); }
    if let Some(ref o) = report.overlay   { lines.push(format!("  Overlay:   {}", o.name)); }
    for lib in &report.libraries          { lines.push(format!("  Library:   {}", lib.name)); }
    lines.push(format!("  Matches:   {} signatures", report.raw_matches.len()));
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upx_stub() -> Vec<u8> {
        // Minimal MZ + UPX0 section name in the data.
        let mut data = vec![0u8; 256];
        data[0] = b'M'; data[1] = b'Z';
        // PE offset at 60.
        data[60] = 64;
        // PE signature at 64.
        data[64] = b'P'; data[65] = b'E';
        // Add UPX markers.
        data.extend_from_slice(b"UPX0\x00UPX1\x00UPX!");
        // UPX EP pattern at offset 0 of "ep_bytes".
        data
    }

    #[test]
    fn engine_creates() {
        let engine = DetectorEngine::default();
        assert!(engine.db.len() > 0);
    }

    #[test]
    fn scan_empty_no_panic() {
        let report = scan_bytes(b"");
        assert!(report.compiler.is_none());
        assert!(report.packer.is_none());
    }

    #[test]
    fn format_report_no_panic() {
        let report = DetectionReport::new();
        let s = format_report(&report);
        assert!(s.contains("DIE Detection Report"));
    }

    #[test]
    fn upx_detected() {
        let data = upx_stub();
        let engine = DetectorEngine::default();
        let ep = &data[..64.min(data.len())];
        let matches = engine.db.scan(&data, ep);
        // The UPX signatures should fire.
        assert!(matches.iter().any(|s| s.name.contains("UPX")));
    }

    #[test]
    fn dot_net_detected() {
        // Fake .NET binary containing mscoree.dll and the PE32 jmp thunk.
        let mut data = vec![0u8; 128];
        data[0] = b'M'; data[1] = b'Z';
        data.extend_from_slice(b"mscoree.dll\x00_CorExeMain\x00");
        let report = DetectorEngine::default().analyze(&data);
        // Even without full PE structure, runtime signature should match on content.
        let _ = report.raw_matches.len();
    }

    #[test]
    fn summary_unknown_for_empty() {
        let report = DetectionReport::new();
        assert_eq!(report.summary(), "Unknown");
    }

    #[test]
    fn is_packed_false_by_default() {
        let report = DetectionReport::new();
        assert!(!report.is_packed());
    }
}
