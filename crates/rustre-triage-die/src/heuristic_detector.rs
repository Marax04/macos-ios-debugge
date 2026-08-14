//! Heuristic packer detection — detects packed files without specific signatures.
//!
//! [`HeuristicDetector`] inspects PE structure, entropy, imports, TLS callbacks,
//! and overlay data, accumulating evidence into a [`HeuristicScore`].

use crate::{
    DetectKind, Detection, compute_entropy, get_entry_point_bytes, has_overlay as file_has_overlay,
    read_pe_sections,
};
use std::fmt;

// ---------------------------------------------------------------------------
// HeuristicIndicator
// ---------------------------------------------------------------------------

/// A single piece of evidence for or against packing.
#[derive(Debug, Clone)]
pub struct HeuristicIndicator {
    /// Short human-readable name.
    pub name: &'static str,
    /// Longer explanation of what was found.
    pub detail: String,
    /// Score contribution (positive = more packed, negative = less likely).
    pub score: i32,
}

impl fmt::Display for HeuristicIndicator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:+}] {}: {}", self.score, self.name, self.detail)
    }
}

// ---------------------------------------------------------------------------
// HeuristicScore
// ---------------------------------------------------------------------------

/// Aggregated heuristic result.
#[derive(Debug, Clone, Default)]
pub struct HeuristicScore {
    /// All collected indicators.
    pub indicators: Vec<HeuristicIndicator>,
    /// Summed score.
    pub total: i32,
}

impl HeuristicScore {
    /// Push a new indicator and accumulate the score.
    pub fn push(&mut self, ind: HeuristicIndicator) {
        self.total += ind.score;
        self.indicators.push(ind);
    }

    /// Normalize score to a 0–100 confidence value.
    #[must_use]
    pub fn confidence(&self) -> u8 {
        let clamped = self.total.clamp(0, 100);
        clamped as u8
    }

    /// Returns `true` if the score exceeds the default packed threshold (20).
    #[must_use]
    pub const fn is_likely_packed(&self) -> bool {
        self.total >= 20
    }

    /// Returns `true` if the score exceeds a high-confidence threshold (50).
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.total >= 50
    }

    /// All positive (packing-evidence) indicators.
    #[must_use]
    pub fn positive_indicators(&self) -> Vec<&HeuristicIndicator> {
        self.indicators.iter().filter(|i| i.score > 0).collect()
    }

    /// All negative (unpacked-evidence) indicators.
    #[must_use]
    pub fn negative_indicators(&self) -> Vec<&HeuristicIndicator> {
        self.indicators.iter().filter(|i| i.score < 0).collect()
    }
}

impl fmt::Display for HeuristicScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HeuristicScore {{ total: {}, confidence: {}%, packed: {} }}",
            self.total,
            self.confidence(),
            self.is_likely_packed()
        )
    }
}

// ---------------------------------------------------------------------------
// SectionNameFlags
// ---------------------------------------------------------------------------

/// Well-known section names and their packed/unpacked classification.
const PACKER_SECTIONS: &[&str] = &[
    "UPX0",
    "UPX1",
    "UPX2",
    ".MPRESS1",
    ".MPRESS2",
    ".aspack",
    ".adata",
    ".vmp0",
    ".vmp1",
    ".vmp2",
    ".themida",
    ".winlice",
    ".petite",
    ".nsp0",
    ".nsp1",
    ".nsp2",
    ".tmd",
    ".Themida",
    ".enigma1",
    ".enigma2",
    ".obsidium",
    ".perplex",
    ".RLPack",
    ".packed",
    "CODE",
    "DATA", // MEW / simple packers
    ".exect",
];

const NORMAL_SECTIONS: &[&str] = &[
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".reloc", ".rsrc", ".pdata", ".tls",
    ".debug", ".xdata", ".sxdata", ".gfids", ".00cfg", ".voltbl",
];

// ---------------------------------------------------------------------------
// HeuristicDetector
// ---------------------------------------------------------------------------

/// Heuristic PE packer detector.
///
/// # Usage
///
/// ```rust,no_run
/// use rustre_triage_die::heuristic_detector::HeuristicDetector;
/// let data = std::fs::read("sample.exe").unwrap();
/// let (score, detection) = HeuristicDetector::new().analyze(&data);
/// println!("{score}");
/// if let Some(d) = detection { println!("{d}"); }
/// ```
pub struct HeuristicDetector {
    /// Minimum entropy to flag an EP section as high-entropy (default 7.0).
    pub ep_entropy_threshold: f32,
    /// Maximum import count to flag sparse imports (default 5).
    pub sparse_import_threshold: u16,
    /// Score to add when the EP section is high-entropy (default 30).
    pub high_entropy_score: i32,
    /// Score to add for each packer-named section found (default 25).
    pub packer_section_score: i32,
    /// Score added when import count is tiny (default 20).
    pub sparse_import_score: i32,
    /// Score added for overlay data (default 15).
    pub overlay_score: i32,
    /// Score added for TLS callback(s) without .NET (default 10).
    pub tls_callback_score: i32,
    /// Score deducted when many normal sections present (default -10 per extra).
    pub normal_section_deduction: i32,
    /// Score deducted when rich header present (MSVC binary, default -5).
    pub rich_header_deduction: i32,
    /// Score added for checksum mismatch (default 10).
    pub checksum_mismatch_score: i32,
}

impl Default for HeuristicDetector {
    fn default() -> Self {
        Self {
            ep_entropy_threshold: 7.0,
            sparse_import_threshold: 5,
            high_entropy_score: 30,
            packer_section_score: 25,
            sparse_import_score: 20,
            overlay_score: 15,
            tls_callback_score: 10,
            normal_section_deduction: -5,
            rich_header_deduction: -5,
            checksum_mismatch_score: 10,
        }
    }
}

impl HeuristicDetector {
    /// Create a new detector with default thresholds.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Analyze `data` and return `(score, optional_detection)`.
    ///
    /// A [`Detection`] is returned only when the score indicates high confidence.
    #[must_use]
    pub fn analyze(&self, data: &[u8]) -> (HeuristicScore, Option<Detection>) {
        let mut score = HeuristicScore::default();

        self.check_ep_entropy(data, &mut score);
        self.check_section_names(data, &mut score);
        self.check_import_count(data, &mut score);
        self.check_only_kernel32(data, &mut score);
        self.check_overlay(data, &mut score);
        self.check_tls_callbacks(data, &mut score);
        self.check_checksum(data, &mut score);
        self.check_rich_header(data, &mut score);
        self.check_ep_prologue_anomaly(data, &mut score);
        self.check_section_entropy_variance(data, &mut score);
        self.check_section_count(data, &mut score);
        self.check_file_alignment(data, &mut score);

        let detection = if score.is_likely_packed() {
            Some(Detection {
                kind: DetectKind::Packer,
                name: "Unknown Packer (heuristic)".to_string(),
                version: None,
                confidence: score.confidence(),
                description: format!(
                    "Heuristic packing detected: {} indicators, score={}",
                    score.indicators.len(),
                    score.total
                ),
            })
        } else {
            None
        };

        (score, detection)
    }

    // ──────────────────────────────────────────────────────────────────────
    // Individual heuristic checks
    // ──────────────────────────────────────────────────────────────────────

    fn check_ep_entropy(&self, data: &[u8], score: &mut HeuristicScore) {
        let sections = read_pe_sections(data);
        let ep_bytes = get_entry_point_bytes(data);
        if ep_bytes.is_empty() || sections.is_empty() {
            return;
        }

        // Find which section contains the EP.
        if let Some(pe_off) = locate_pe(data) {
            let opt_off = pe_off + 0x18;
            if opt_off + 0x14 > data.len() {
                return;
            }
            let ep_rva = u32::from_le_bytes(
                data[opt_off + 0x10..opt_off + 0x14]
                    .try_into()
                    .unwrap_or([0; 4]),
            );

            let num_sections = u16::from_le_bytes([data[pe_off + 6], data[pe_off + 7]]) as usize;
            let opt_size = u16::from_le_bytes([data[pe_off + 0x14], data[pe_off + 0x15]]) as usize;
            let sec_tbl = opt_off + opt_size;

            for i in 0..num_sections {
                let s = sec_tbl + i * 40;
                if s + 40 > data.len() {
                    break;
                }
                let virt_addr =
                    u32::from_le_bytes(data[s + 12..s + 16].try_into().unwrap_or([0; 4]));
                let virt_size =
                    u32::from_le_bytes(data[s + 8..s + 12].try_into().unwrap_or([0; 4]));
                let raw_off =
                    u32::from_le_bytes(data[s + 20..s + 24].try_into().unwrap_or([0; 4])) as usize;
                let raw_size =
                    u32::from_le_bytes(data[s + 16..s + 20].try_into().unwrap_or([0; 4])) as usize;

                if ep_rva >= virt_addr && ep_rva < virt_addr + virt_size.max(1) {
                    if raw_off + raw_size <= data.len() && raw_size > 0 {
                        let entropy = compute_entropy(&data[raw_off..raw_off + raw_size]);
                        if entropy >= self.ep_entropy_threshold {
                            score.push(HeuristicIndicator {
                                name: "high_ep_entropy",
                                detail: format!(
                                    "EP section entropy = {entropy:.3} >= {}",
                                    self.ep_entropy_threshold
                                ),
                                score: self.high_entropy_score,
                            });
                        }
                    }
                    break;
                }
            }
        }
    }

    fn check_section_names(&self, data: &[u8], score: &mut HeuristicScore) {
        let sections = read_pe_sections(data);
        let mut packer_found = 0u32;
        let mut normal_count = 0u32;

        for (name, _entropy) in &sections {
            if PACKER_SECTIONS
                .iter()
                .any(|&p| name.eq_ignore_ascii_case(p))
            {
                packer_found += 1;
                score.push(HeuristicIndicator {
                    name: "packer_section_name",
                    detail: format!("Section '{name}' is a known packer indicator"),
                    score: self.packer_section_score,
                });
            } else if NORMAL_SECTIONS
                .iter()
                .any(|&n| name.eq_ignore_ascii_case(n))
            {
                normal_count += 1;
            }
        }

        if normal_count >= 4 && packer_found == 0 {
            score.push(HeuristicIndicator {
                name: "normal_section_layout",
                detail: format!("{normal_count} standard sections, no packer names"),
                score: self.normal_section_deduction * normal_count as i32,
            });
        }
    }

    fn check_import_count(&self, data: &[u8], score: &mut HeuristicScore) {
        // Without a PE header at all, "no imports" is not evidence of packing.
        if locate_pe(data).is_none() {
            return;
        }
        let count = count_imports(data);
        if count == 0 {
            score.push(HeuristicIndicator {
                name: "no_imports",
                detail: "Import directory is empty or missing".to_string(),
                score: self.sparse_import_score,
            });
        } else if count < self.sparse_import_threshold {
            score.push(HeuristicIndicator {
                name: "sparse_imports",
                detail: format!(
                    "Only {count} imported functions (< {})",
                    self.sparse_import_threshold
                ),
                score: self.sparse_import_score,
            });
        } else if count > 50 {
            score.push(HeuristicIndicator {
                name: "rich_imports",
                detail: format!("{count} imported functions suggests normal binary"),
                score: -10,
            });
        }
    }

    fn check_only_kernel32(&self, data: &[u8], score: &mut HeuristicScore) {
        // Check if the only DLLs imported are KERNEL32 and/or NTDLL.
        let dll_names = extract_dll_names(data);
        if dll_names.is_empty() {
            return;
        }
        let only_kernel: bool = dll_names.iter().all(|d| {
            let lower = d.to_lowercase();
            lower.contains("kernel32") || lower.contains("ntdll") || lower.contains("msvcrt")
        });
        if only_kernel && dll_names.len() <= 2 {
            score.push(HeuristicIndicator {
                name: "only_kernel32_imports",
                detail: format!("Only imports from: {}", dll_names.join(", ")),
                score: 15,
            });
        }
    }

    fn check_overlay(&self, data: &[u8], score: &mut HeuristicScore) {
        if file_has_overlay(data) {
            let overlay_size = compute_overlay_size(data);
            score.push(HeuristicIndicator {
                name: "overlay_data",
                detail: format!(
                    "Overlay detected: {overlay_size} bytes after last section"
                ),
                score: self.overlay_score,
            });
        }
    }

    fn check_tls_callbacks(&self, data: &[u8], score: &mut HeuristicScore) {
        if has_tls_callbacks(data) && !is_dotnet(data) {
            score.push(HeuristicIndicator {
                name: "tls_callbacks",
                detail:
                    "TLS callback directory present (non-.NET) — common packer anti-debug trick"
                        .to_string(),
                score: self.tls_callback_score,
            });
        }
    }

    fn check_checksum(&self, data: &[u8], score: &mut HeuristicScore) {
        if let Some((stored, computed)) = pe_checksum_check(data)
            && stored != 0 && stored != computed {
                score.push(HeuristicIndicator {
                    name: "checksum_mismatch",
                    detail: format!("Stored checksum {stored:#x} != computed {computed:#x}"),
                    score: self.checksum_mismatch_score,
                });
            }
    }

    fn check_rich_header(&self, data: &[u8], score: &mut HeuristicScore) {
        // "Rich" header is present in MSVC-compiled binaries — negative indicator for packers.
        if data.windows(4).any(|w| w == b"Rich") {
            score.push(HeuristicIndicator {
                name: "rich_header",
                detail: "MSVC Rich header found — likely native compile".to_string(),
                score: self.rich_header_deduction,
            });
        }
    }

    fn check_ep_prologue_anomaly(&self, data: &[u8], score: &mut HeuristicScore) {
        let ep = get_entry_point_bytes(data);
        if ep.len() < 2 {
            return;
        }
        // Packers often start with a PUSHAD (0x60) or PUSH reg (0x50-0x57).
        match ep[0] {
            0x60 => {
                score.push(HeuristicIndicator {
                    name: "ep_pushad",
                    detail: "Entry point starts with PUSHAD (0x60) — classic packer stub"
                        .to_string(),
                    score: 20,
                });
            }
            0xE9 => {
                score.push(HeuristicIndicator {
                    name: "ep_jmp",
                    detail: "Entry point starts with JMP — redirected execution".to_string(),
                    score: 10,
                });
            }
            0xEB => {
                score.push(HeuristicIndicator {
                    name: "ep_short_jmp",
                    detail: "Entry point starts with SHORT JMP — redirected execution".to_string(),
                    score: 8,
                });
            }
            _ => {}
        }
    }

    fn check_section_entropy_variance(&self, data: &[u8], score: &mut HeuristicScore) {
        let sections = read_pe_sections(data);
        if sections.len() < 2 {
            return;
        }
        let max = sections.iter().map(|(_, e)| *e).fold(f32::NEG_INFINITY, f32::max);
        let min = sections.iter().map(|(_, e)| *e).fold(f32::INFINITY, f32::min);
        let variance = max - min;
        if variance > 4.0 {
            score.push(HeuristicIndicator {
                name: "high_entropy_variance",
                detail: format!(
                    "Section entropy range = {min:.2}–{max:.2} (variance {variance:.2})"
                ),
                score: 15,
            });
        }
    }

    fn check_section_count(&self, data: &[u8], score: &mut HeuristicScore) {
        let sections = read_pe_sections(data);
        if sections.len() <= 2 && !sections.is_empty() {
            score.push(HeuristicIndicator {
                name: "few_sections",
                detail: format!(
                    "Only {} section(s) — common in packed executables",
                    sections.len()
                ),
                score: 12,
            });
        }
    }

    fn check_file_alignment(&self, data: &[u8], score: &mut HeuristicScore) {
        if let Some(pe_off) = locate_pe(data) {
            let opt_off = pe_off + 0x18;
            if opt_off + 0x3C > data.len() {
                return;
            }
            // FileAlignment is at opt_off + 0x24 for both PE32 and PE32+
            let fa = u32::from_le_bytes(
                data[opt_off + 0x24..opt_off + 0x28]
                    .try_into()
                    .unwrap_or([0; 4]),
            );
            // Unusual file alignment values (not a power of two, or > 0x10000)
            if fa > 0x10000 || (fa != 0 && (fa & (fa - 1)) != 0) {
                score.push(HeuristicIndicator {
                    name: "unusual_file_alignment",
                    detail: format!("File alignment = {fa:#x} is non-standard"),
                    score: 8,
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PE helper functions (local to this module)
// ---------------------------------------------------------------------------

fn locate_pe(data: &[u8]) -> Option<usize> {
    if data.len() < 0x40 {
        return None;
    }
    if &data[0..2] != b"MZ" {
        return None;
    }
    let pe_off = u32::from_le_bytes(data[0x3c..0x40].try_into().ok()?) as usize;
    if pe_off + 4 > data.len() {
        return None;
    }
    if &data[pe_off..pe_off + 4] != b"PE\0\0" {
        return None;
    }
    Some(pe_off)
}

fn count_imports(data: &[u8]) -> u16 {
    let Some(pe_off) = locate_pe(data) else {
        return 0;
    };
    let opt_off = pe_off + 0x18;
    if opt_off + 2 > data.len() {
        return 0;
    }
    let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
    let dd_off = if magic == 0x020b {
        opt_off + 0x70
    } else {
        opt_off + 0x60
    };
    if dd_off + 16 > data.len() {
        return 0;
    }
    let import_rva = u32::from_le_bytes(data[dd_off + 8..dd_off + 12].try_into().unwrap_or([0; 4]));
    if import_rva == 0 {
        return 0;
    }
    let Some(import_foff) = rva_to_file_offset(data, pe_off, import_rva) else {
        return 0;
    };

    let entry_size: usize = if magic == 0x020b { 8 } else { 4 };
    let mut total: u16 = 0;
    let mut desc_off = import_foff;
    loop {
        if desc_off + 20 > data.len() {
            break;
        }
        let name_rva = u32::from_le_bytes(
            data[desc_off + 12..desc_off + 16]
                .try_into()
                .unwrap_or([0; 4]),
        );
        let ilt_rva = u32::from_le_bytes(data[desc_off..desc_off + 4].try_into().unwrap_or([0; 4]));
        if name_rva == 0 && ilt_rva == 0 {
            break;
        }
        if let Some(ilt_foff) = rva_to_file_offset(data, pe_off, ilt_rva) {
            total = total.saturating_add(count_ilt(data, magic, ilt_foff, entry_size));
        }
        desc_off += 20;
    }
    total
}

fn count_ilt(data: &[u8], _magic: u16, ilt_foff: usize, entry_size: usize) -> u16 {
    let mut count: u16 = 0;
    let mut off = ilt_foff;
    loop {
        if off + entry_size > data.len() {
            break;
        }
        if data[off..off + entry_size].iter().all(|&b| b == 0) {
            break;
        }
        count = count.saturating_add(1);
        off += entry_size;
        if count > 0x7FFF {
            break;
        }
    }
    count
}

fn extract_dll_names(data: &[u8]) -> Vec<String> {
    let Some(pe_off) = locate_pe(data) else {
        return Vec::new();
    };
    let opt_off = pe_off + 0x18;
    if opt_off + 2 > data.len() {
        return Vec::new();
    }
    let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
    let dd_off = if magic == 0x020b {
        opt_off + 0x70
    } else {
        opt_off + 0x60
    };
    if dd_off + 16 > data.len() {
        return Vec::new();
    }
    let import_rva = u32::from_le_bytes(data[dd_off + 8..dd_off + 12].try_into().unwrap_or([0; 4]));
    if import_rva == 0 {
        return Vec::new();
    }
    let Some(import_foff) = rva_to_file_offset(data, pe_off, import_rva) else {
        return Vec::new();
    };

    let mut names = Vec::new();
    let mut desc_off = import_foff;
    loop {
        if desc_off + 20 > data.len() {
            break;
        }
        let name_rva = u32::from_le_bytes(
            data[desc_off + 12..desc_off + 16]
                .try_into()
                .unwrap_or([0; 4]),
        );
        let ilt_rva = u32::from_le_bytes(data[desc_off..desc_off + 4].try_into().unwrap_or([0; 4]));
        if name_rva == 0 && ilt_rva == 0 {
            break;
        }
        if let Some(name_foff) = rva_to_file_offset(data, pe_off, name_rva) {
            let name = read_cstr(data, name_foff);
            if !name.is_empty() {
                names.push(name);
            }
        }
        desc_off += 20;
        if names.len() > 256 {
            break;
        }
    }
    names
}

fn compute_overlay_size(data: &[u8]) -> usize {
    let Some(pe_off) = locate_pe(data) else {
        return 0;
    };
    let num_sections = u16::from_le_bytes([data[pe_off + 6], data[pe_off + 7]]) as usize;
    let opt_size = u16::from_le_bytes([data[pe_off + 0x14], data[pe_off + 0x15]]) as usize;
    let sec_tbl = pe_off + 0x18 + opt_size;
    let mut last_end: usize = 0;
    for i in 0..num_sections {
        let s = sec_tbl + i * 40;
        if s + 40 > data.len() {
            break;
        }
        let raw_off =
            u32::from_le_bytes(data[s + 20..s + 24].try_into().unwrap_or([0; 4])) as usize;
        let raw_size =
            u32::from_le_bytes(data[s + 16..s + 20].try_into().unwrap_or([0; 4])) as usize;
        let end = raw_off + raw_size;
        if end > last_end {
            last_end = end;
        }
    }
    if last_end < data.len() {
        data.len() - last_end
    } else {
        0
    }
}

fn has_tls_callbacks(data: &[u8]) -> bool {
    let Some(pe_off) = locate_pe(data) else {
        return false;
    };
    let opt_off = pe_off + 0x18;
    if opt_off + 2 > data.len() {
        return false;
    }
    let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
    // TLS directory is data directory index 9.
    let dd_off = if magic == 0x020b {
        opt_off + 0x70
    } else {
        opt_off + 0x60
    };
    let tls_dd_off = dd_off + 9 * 8;
    if tls_dd_off + 8 > data.len() {
        return false;
    }
    let rva = u32::from_le_bytes(
        data[tls_dd_off..tls_dd_off + 4]
            .try_into()
            .unwrap_or([0; 4]),
    );
    let size = u32::from_le_bytes(
        data[tls_dd_off + 4..tls_dd_off + 8]
            .try_into()
            .unwrap_or([0; 4]),
    );
    rva != 0 && size != 0
}

fn is_dotnet(data: &[u8]) -> bool {
    let Some(pe_off) = locate_pe(data) else {
        return false;
    };
    let opt_off = pe_off + 0x18;
    if opt_off + 2 > data.len() {
        return false;
    }
    let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
    let dd_off = if magic == 0x020b {
        opt_off + 0x70
    } else {
        opt_off + 0x60
    };
    let clr_dd_off = dd_off + 14 * 8;
    if clr_dd_off + 8 > data.len() {
        return false;
    }
    let rva = u32::from_le_bytes(
        data[clr_dd_off..clr_dd_off + 4]
            .try_into()
            .unwrap_or([0; 4]),
    );
    let size = u32::from_le_bytes(
        data[clr_dd_off + 4..clr_dd_off + 8]
            .try_into()
            .unwrap_or([0; 4]),
    );
    rva != 0 && size != 0
}

/// Simple PE checksum verification.  Returns `(stored, computed)` or `None`.
fn pe_checksum_check(data: &[u8]) -> Option<(u32, u32)> {
    let pe_off = locate_pe(data)?;
    let opt_off = pe_off + 0x18;
    if opt_off + 68 > data.len() {
        return None;
    }
    // Checksum field at opt_off + 0x40
    let cs_off = opt_off + 0x40;
    if cs_off + 4 > data.len() {
        return None;
    }
    let stored = u32::from_le_bytes(data[cs_off..cs_off + 4].try_into().ok()?);

    // Compute checksum (PE spec algorithm).
    let mut checksum: u64 = 0;
    let mut i = 0usize;
    while i + 1 < data.len() {
        if i == cs_off || i == cs_off + 1 || i == cs_off + 2 || i == cs_off + 3 {
            i += 1;
            continue;
        }
        let word = u64::from(u16::from_le_bytes([data[i], data[i + 1]]));
        checksum += word;
        if checksum > 0xFFFF_FFFF {
            checksum = (checksum & 0xFFFF) + (checksum >> 32);
        }
        i += 2;
    }
    if !data.len().is_multiple_of(2) {
        checksum += u64::from(data[data.len() - 1]);
    }
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    checksum += checksum >> 16;
    checksum &= 0xFFFF;
    checksum += data.len() as u64;
    Some((stored, checksum as u32))
}

fn rva_to_file_offset(data: &[u8], pe_off: usize, rva: u32) -> Option<usize> {
    if rva == 0 {
        return None;
    }
    let num_sections = u16::from_le_bytes([data[pe_off + 6], data[pe_off + 7]]) as usize;
    let opt_size = u16::from_le_bytes([data[pe_off + 0x14], data[pe_off + 0x15]]) as usize;
    let sec_tbl = pe_off + 0x18 + opt_size;
    for i in 0..num_sections {
        let s = sec_tbl + i * 40;
        if s + 40 > data.len() {
            break;
        }
        let virt_addr = u32::from_le_bytes(data[s + 12..s + 16].try_into().ok()?);
        let virt_size = u32::from_le_bytes(data[s + 8..s + 12].try_into().ok()?);
        let raw_off = u32::from_le_bytes(data[s + 20..s + 24].try_into().ok()?);
        let raw_size = u32::from_le_bytes(data[s + 16..s + 20].try_into().ok()?);
        let vend = virt_addr + virt_size.max(raw_size);
        if rva >= virt_addr && rva < vend {
            let file_off = raw_off as usize + (rva - virt_addr) as usize;
            if file_off < data.len() {
                return Some(file_off);
            }
        }
    }
    None
}

fn read_cstr(data: &[u8], offset: usize) -> String {
    let slice = &data[offset.min(data.len())..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end.min(256)]).into_owned()
}

/// Check whether the PE `has_overlay` helper (wrapping the crate-level function).
#[must_use] 
pub fn has_overlay(data: &[u8]) -> bool {
    file_has_overlay(data)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pe() -> Vec<u8> {
        let mut v = vec![0u8; 0x400];
        // MZ header
        v[0] = 0x4D;
        v[1] = 0x5A;
        v[0x3c] = 0x40; // e_lfanew = 0x40
        // PE signature
        v[0x40] = 0x50;
        v[0x41] = 0x45; // "PE"
        // Machine = x64
        v[0x44] = 0x64;
        v[0x45] = 0x86;
        // NumberOfSections = 1
        v[0x46] = 0x01;
        // SizeOfOptionalHeader = 0xF0 (PE32+)
        v[0x54] = 0xF0;
        // Optional header magic = PE32+
        v[0x58] = 0x0B;
        v[0x59] = 0x02;
        v
    }

    #[test]
    fn test_detector_new() {
        let d = HeuristicDetector::new();
        assert_eq!(d.ep_entropy_threshold, 7.0);
    }

    #[test]
    fn test_analyze_empty_data() {
        let d = HeuristicDetector::new();
        let (score, det) = d.analyze(&[]);
        assert!(det.is_none());
        // No crash, score may be 0.
        let _ = score;
    }

    #[test]
    fn test_analyze_minimal_pe_no_packing() {
        let d = HeuristicDetector::new();
        let data = minimal_pe();
        let (score, _det) = d.analyze(&data);
        // Minimal PE may have sparse imports → some score, but check it runs.
        let _ = score.total;
    }

    #[test]
    fn test_upx_section_names_score_high() {
        let d = HeuristicDetector::new();
        let mut data = minimal_pe();
        // Patch in UPX0 section name at section table offset 0x40 + 0x18 + 0xF0 = 0x148
        let sec_off = 0x40 + 0x18 + 0xF0;
        data[sec_off..sec_off + 4].copy_from_slice(b"UPX0");
        let (score, _) = d.analyze(&data);
        assert!(score.total > 0);
    }

    #[test]
    fn test_overlay_indicator() {
        // We can't easily fake an overlay in a minimal PE without full section table.
        // Just check the overlay_score field.
        let d = HeuristicDetector::new();
        assert_eq!(d.overlay_score, 15);
    }

    #[test]
    fn test_score_is_likely_packed() {
        let mut score = HeuristicScore::default();
        score.push(HeuristicIndicator {
            name: "test",
            detail: "x".into(),
            score: 30,
        });
        assert!(score.is_likely_packed());
    }

    #[test]
    fn test_score_not_packed_zero() {
        let score = HeuristicScore::default();
        assert!(!score.is_likely_packed());
    }

    #[test]
    fn test_score_high_confidence() {
        let mut score = HeuristicScore::default();
        score.push(HeuristicIndicator {
            name: "a",
            detail: String::new(),
            score: 60,
        });
        assert!(score.is_high_confidence());
    }

    #[test]
    fn test_score_confidence_clamped() {
        let mut score = HeuristicScore::default();
        score.push(HeuristicIndicator {
            name: "x",
            detail: String::new(),
            score: 200,
        });
        assert_eq!(score.confidence(), 100);
    }

    #[test]
    fn test_positive_negative_indicators() {
        let mut score = HeuristicScore::default();
        score.push(HeuristicIndicator {
            name: "pos",
            detail: String::new(),
            score: 20,
        });
        score.push(HeuristicIndicator {
            name: "neg",
            detail: String::new(),
            score: -5,
        });
        assert_eq!(score.positive_indicators().len(), 1);
        assert_eq!(score.negative_indicators().len(), 1);
    }

    #[test]
    fn test_rich_header_deduction() {
        let d = HeuristicDetector::new();
        let mut data = minimal_pe();
        data.extend_from_slice(b"Rich");
        let (score, _) = d.analyze(&data);
        assert!(score.indicators.iter().any(|i| i.name == "rich_header"));
    }

    #[test]
    fn test_pushad_ep_score() {
        let d = HeuristicDetector::new();
        // We can't easily set EP bytes without a full PE, but we can test the
        // check_ep_prologue_anomaly function doesn't panic on empty EP.
        let data = minimal_pe();
        let (score, _) = d.analyze(&data);
        // Just check no panic.
        let _ = score;
    }

    #[test]
    fn test_heuristic_indicator_display() {
        let ind = HeuristicIndicator {
            name: "test",
            detail: "some detail".to_string(),
            score: 10,
        };
        let s = ind.to_string();
        assert!(s.contains("test"));
        assert!(s.contains("some detail"));
    }

    #[test]
    fn test_heuristic_score_display() {
        let mut score = HeuristicScore::default();
        score.push(HeuristicIndicator {
            name: "a",
            detail: "b".into(),
            score: 25,
        });
        let s = score.to_string();
        assert!(s.contains("25"));
    }

    #[test]
    fn test_sparse_import_threshold_default() {
        let d = HeuristicDetector::new();
        assert_eq!(d.sparse_import_threshold, 5);
    }

    #[test]
    fn test_count_imports_empty() {
        assert_eq!(count_imports(&[]), 0);
    }

    #[test]
    fn test_compute_overlay_size_zero_on_minimal() {
        let data = minimal_pe();
        // No sections, so overlay = all data after header (but there's no last section end).
        let _ = compute_overlay_size(&data);
    }

    #[test]
    fn test_is_dotnet_false_on_plain_pe() {
        let data = minimal_pe();
        assert!(!is_dotnet(&data));
    }

    #[test]
    fn test_has_tls_callbacks_false_on_plain_pe() {
        let data = minimal_pe();
        assert!(!has_tls_callbacks(&data));
    }

    #[test]
    fn test_extract_dll_names_empty() {
        let data = minimal_pe();
        let names = extract_dll_names(&data);
        // No import table in minimal PE
        assert!(names.is_empty());
    }

    #[test]
    fn test_read_cstr_basic() {
        let data = b"hello\0world";
        assert_eq!(read_cstr(data, 0), "hello");
    }

    #[test]
    fn test_locate_pe_non_pe() {
        assert!(locate_pe(&[0u8; 100]).is_none());
    }

    #[test]
    fn test_locate_pe_valid() {
        let data = minimal_pe();
        assert!(locate_pe(&data).is_some());
    }

    #[test]
    fn test_pe_checksum_minimal() {
        let data = minimal_pe();
        // checksum check may or may not succeed; just check no panic.
        let _ = pe_checksum_check(&data);
    }

    #[test]
    fn test_score_total_accumulates() {
        let mut score = HeuristicScore::default();
        score.push(HeuristicIndicator {
            name: "a",
            detail: String::new(),
            score: 10,
        });
        score.push(HeuristicIndicator {
            name: "b",
            detail: String::new(),
            score: 15,
        });
        assert_eq!(score.total, 25);
    }
}
