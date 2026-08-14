//! `dex_optimizer_detector` — Detects ART/DEX optimisation and obfuscation artefacts.
//!
//! Analyses DEX bytecode for:
//! - Quick/optimised opcodes (ART `invoke-virtual-quick`, etc.)
//! - VDEX quickening info presence
//! - NOP sled padding (common in deobfuscated DEX)
//! - Suspicious string-pool characteristics (entropy, packing)
//! - Known packer signatures (`DexGuard`, Bangcle, etc.)
//! - Dead-code injection and string encryption artefacts

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{DexHeader, read_string_table, is_dex};

// ─── OptimizerDetectorError ───────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum OptimizerDetectorError {
    #[error("not a DEX file")]
    NotDex,
    #[error("truncated DEX data")]
    Truncated,
    #[error("parse error: {0}")]
    ParseError(String),
}

// ─── DalvikOpcode constants ───────────────────────────────────────────────────

/// First-byte opcodes in standard DEX bytecode.
pub const OP_NOP: u8 = 0x00;
pub const OP_RETURN_VOID: u8 = 0x0E;
pub const OP_INVOKE_VIRTUAL: u8 = 0x6E;
pub const OP_INVOKE_SUPER: u8 = 0x6F;
pub const OP_INVOKE_DIRECT: u8 = 0x70;
pub const OP_INVOKE_STATIC: u8 = 0x71;
pub const OP_INVOKE_INTERFACE: u8 = 0x72;
pub const OP_INVOKE_VIRTUAL_RANGE: u8 = 0x74;
pub const OP_THROW: u8 = 0x27;
pub const OP_GOTO: u8 = 0x28;
pub const OP_GOTO_16: u8 = 0x29;
pub const OP_CONST_STRING: u8 = 0x1A;
pub const OP_CONST_STRING_JUMBO: u8 = 0x1B;

/// ART-specific "quick" opcodes — present only in ODEX/OAT-patched DEX.
pub const OP_INVOKE_VIRTUAL_QUICK: u8 = 0xE6;
pub const OP_INVOKE_VIRTUAL_QUICK_RANGE: u8 = 0xEB;
pub const OP_IGET_QUICK: u8 = 0xE3;
pub const OP_IPUT_QUICK: u8 = 0xE4;
pub const OP_IGET_WIDE_QUICK: u8 = 0xE4;
pub const OP_INVOKE_SUPER_QUICK: u8 = 0xE7;

/// ODEX 1.0 quick opcodes (Dalvik era).
pub const OP_INVOKE_VIRTUAL_QUICK_LEGACY: u8 = 0xF4;

// ─── OptimizationKind ────────────────────────────────────────────────────────

/// A kind of optimisation or obfuscation artefact detected in a DEX file.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OptimizationKind {
    /// ART quick-invoke opcodes present.
    QuickOpcodes,
    /// VDEX quickening table detected.
    VdexQuickening,
    /// Large NOP sleds (≥ 4 consecutive NOP instructions).
    NopSleds,
    /// Unusually high string-pool entropy (possible encryption/obfuscation).
    HighStringEntropy,
    /// Very low string-pool entropy (constant/trivial strings only).
    LowStringEntropy,
    /// Known DEX packer signature matched.
    KnownPacker(String),
    /// Dead code detected (unreachable return-void sequences).
    DeadCode,
    /// Suspicious opcode distribution (many jumps / gotos).
    JumpHeavy,
    /// String decryption artefacts (xor sequences near const-string).
    StringDecryptionArtefacts,
    /// Abnormally large number of classes with identical names.
    ClassNameCollisions,
    /// ODEX header detected (pre-ART optimised DEX).
    OdexHeader,
    /// `ProGuard` / R8 name obfuscation (single-letter class/method names).
    ProGuardObfuscation,
}

impl fmt::Display for OptimizationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QuickOpcodes => write!(f, "quick_opcodes"),
            Self::VdexQuickening => write!(f, "vdex_quickening"),
            Self::NopSleds => write!(f, "nop_sleds"),
            Self::HighStringEntropy => write!(f, "high_string_entropy"),
            Self::LowStringEntropy => write!(f, "low_string_entropy"),
            Self::KnownPacker(n) => write!(f, "known_packer:{n}"),
            Self::DeadCode => write!(f, "dead_code"),
            Self::JumpHeavy => write!(f, "jump_heavy"),
            Self::StringDecryptionArtefacts => write!(f, "string_decryption_artefacts"),
            Self::ClassNameCollisions => write!(f, "class_name_collisions"),
            Self::OdexHeader => write!(f, "odex_header"),
            Self::ProGuardObfuscation => write!(f, "proguard_obfuscation"),
        }
    }
}

// ─── DetectionResult ─────────────────────────────────────────────────────────

/// A single detection finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionFinding {
    pub kind: OptimizationKind,
    pub description: String,
    pub severity: FindingSeverity,
    /// Byte offset in the DEX file where the artefact was first observed.
    pub first_offset: Option<u32>,
    /// Count of occurrences.
    pub count: u32,
    /// Evidence strings.
    pub evidence: Vec<String>,
}

impl DetectionFinding {
    #[must_use]
    pub fn new(
        kind: OptimizationKind,
        desc: impl Into<String>,
        severity: FindingSeverity,
    ) -> Self {
        Self {
            kind,
            description: desc.into(),
            severity,
            first_offset: None,
            count: 1,
            evidence: Vec::new(),
        }
    }

    #[must_use]
    pub const fn with_offset(mut self, off: u32) -> Self {
        self.first_offset = Some(off);
        self
    }

    #[must_use]
    pub const fn with_count(mut self, n: u32) -> Self {
        self.count = n;
        self
    }

    #[must_use]
    pub fn with_evidence(mut self, ev: impl Into<String>) -> Self {
        self.evidence.push(ev.into());
        self
    }
}

/// Severity of a detection finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
}

impl fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
        }
    }
}

// ─── DexOptimizerReport ───────────────────────────────────────────────────────

/// Full report from the DEX optimizer/obfuscation detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexOptimizerReport {
    /// List of detected findings.
    pub findings: Vec<DetectionFinding>,
    /// Total bytecode bytes scanned.
    pub bytecode_bytes_scanned: usize,
    /// Total string-pool bytes scanned.
    pub string_pool_bytes: usize,
    /// Number of classes in the DEX.
    pub class_count: usize,
    /// Number of methods in the DEX.
    pub method_count: usize,
    /// Shannon entropy of the string pool (0.0–8.0 bits).
    pub string_pool_entropy: f64,
    /// Fraction of bytecode that is NOP instructions.
    pub nop_density: f64,
    /// Fraction of bytecode that is jump/goto instructions.
    pub jump_density: f64,
    /// Whether any ART quick opcodes were found.
    pub has_quick_opcodes: bool,
}

impl DexOptimizerReport {
    /// Returns findings of at least `severity`.
    #[must_use]
    pub fn findings_at_least(&self, sev: FindingSeverity) -> Vec<&DetectionFinding> {
        self.findings.iter().filter(|f| f.severity >= sev).collect()
    }

    /// Returns `true` if any packer was detected.
    #[must_use]
    pub fn is_packed(&self) -> bool {
        self.findings
            .iter()
            .any(|f| matches!(&f.kind, OptimizationKind::KnownPacker(_)))
    }

    /// Summarise the report as a single-line string.
    #[must_use]
    pub fn summary(&self) -> String {
        let highs = self.findings_at_least(FindingSeverity::High).len();
        let mediums = self.findings_at_least(FindingSeverity::Medium).len() - highs;
        format!(
            "findings={} high={highs} medium={mediums} nop_density={:.2} packed={}",
            self.findings.len(),
            self.nop_density,
            self.is_packed(),
        )
    }

    /// Return all unique `OptimizationKind` values found.
    #[must_use]
    pub fn unique_kinds(&self) -> Vec<&OptimizationKind> {
        let mut seen: HashSet<String> = HashSet::new();
        let mut out = Vec::new();
        for f in &self.findings {
            let key = f.kind.to_string();
            if seen.insert(key) {
                out.push(&f.kind);
            }
        }
        out
    }

    /// Tally findings by [`OptimizationKind`], returning a histogram suitable
    /// for sorting and reporting.
    #[must_use]
    pub fn kind_histogram(&self) -> HashMap<String, usize> {
        let mut hist: HashMap<String, usize> = HashMap::new();
        for f in &self.findings {
            *hist.entry(f.kind.to_string()).or_insert(0) += 1;
        }
        hist
    }
}

// ─── Shannon entropy ─────────────────────────────────────────────────────────

/// Compute Shannon entropy (bits per byte) of `data`.
#[must_use]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n;
            -p * p.log2()
        })
        .sum()
}

// ─── Packer signatures ───────────────────────────────────────────────────────

/// Known packer/protector byte signatures (`(name, magic_bytes_as_hex_in_string_pool)`).
const PACKER_SIGNATURES: &[(&str, &[u8])] = &[
    ("DexGuard", b"com/saikoa/dexguard"),
    ("Bangcle", b"com/bangcle"),
    ("Jiagu", b"com/qihoo360/jiagu"),
    ("Tencent Shield", b"com/tencent/tp"),
    ("SecNeo", b"com/secneo"),
    ("ApkProtect", b"com/apkprotect"),
    ("ArmorOn", b"com/armoron"),
    ("Allatori", b"com/allatori"),
];

fn detect_packer(data: &[u8]) -> Option<&'static str> {
    for (name, sig) in PACKER_SIGNATURES {
        if data.windows(sig.len()).any(|w| w == *sig) {
            return Some(name);
        }
    }
    None
}

// ─── DexOptimizerDetector ────────────────────────────────────────────────────

/// Analyses a DEX file for optimisation and obfuscation artefacts.
#[derive(Debug, Clone, Default)]
pub struct DexOptimizerDetector;

impl DexOptimizerDetector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Analyse `dex_data` and return a full `DexOptimizerReport`.
    ///
    /// # Errors
    /// Returns `OptimizerDetectorError::NotDex` if the data is not DEX.
    /// Returns `OptimizerDetectorError::Truncated` if the header can't be parsed.
    pub fn analyze(&self, dex_data: &[u8]) -> Result<DexOptimizerReport, OptimizerDetectorError> {
        if !is_dex(dex_data) {
            return Err(OptimizerDetectorError::NotDex);
        }

        let hdr = DexHeader::parse(dex_data)
            .map_err(|_| OptimizerDetectorError::Truncated)?;

        let strings = read_string_table(dex_data, &hdr);
        let class_count = hdr.class_defs_size as usize;
        let method_count = hdr.method_ids_size as usize;

        let mut findings: Vec<DetectionFinding> = Vec::new();

        // String pool bytes
        let string_pool_start = hdr.string_ids_off as usize;
        let string_pool_end = (hdr.string_ids_off as usize + hdr.string_ids_size as usize * 4)
            .min(dex_data.len());
        let string_pool_bytes = string_pool_end.saturating_sub(string_pool_start);
        let string_pool_data = &dex_data[string_pool_start..string_pool_end];
        let string_pool_entropy = shannon_entropy(string_pool_data);

        // Check string entropy
        if string_pool_entropy > 5.5 {
            findings.push(
                DetectionFinding::new(
                    OptimizationKind::HighStringEntropy,
                    format!("String pool entropy {string_pool_entropy:.2} bits — possible encryption"),
                    FindingSeverity::High,
                )
                .with_evidence(format!("entropy={string_pool_entropy:.4}")),
            );
        } else if string_pool_entropy < 1.5 && !strings.is_empty() {
            findings.push(
                DetectionFinding::new(
                    OptimizationKind::LowStringEntropy,
                    format!("String pool entropy {string_pool_entropy:.2} bits — very few unique strings"),
                    FindingSeverity::Info,
                ),
            );
        }

        // Packer detection via string pool
        if let Some(packer) = detect_packer(dex_data) {
            findings.push(
                DetectionFinding::new(
                    OptimizationKind::KnownPacker(packer.to_owned()),
                    format!("Known DEX packer signature found: {packer}"),
                    FindingSeverity::High,
                )
                .with_evidence(packer.to_owned()),
            );
        }

        // ODEX magic
        if dex_data.len() >= 8 && &dex_data[0..4] == b"dey\n" {
            findings.push(DetectionFinding::new(
                OptimizationKind::OdexHeader,
                "ODEX (Dalvik optimised DEX) header detected",
                FindingSeverity::Medium,
            ));
        }

        // ProGuard heuristic: many single-letter class names
        let short_names = strings
            .iter()
            .filter(|s| {
                (s.len() == 1 || (s.len() == 3 && s.starts_with('L') && s.ends_with(';')))
                    && s.chars().all(|c| c.is_ascii_lowercase() || c == 'L' || c == ';')
            })
            .count();
        if short_names > 5 && class_count > 0 {
            let ratio = short_names as f64 / class_count as f64;
            if ratio > 0.3 {
                findings.push(
                    DetectionFinding::new(
                        OptimizationKind::ProGuardObfuscation,
                        format!("{short_names} single-letter names ({:.0}% of classes) — ProGuard/R8 obfuscation",
                            ratio * 100.0),
                        FindingSeverity::Medium,
                    )
                    .with_count(short_names as u32),
                );
            }
        }

        // Scan bytecode
        let (quick_count, nop_count, jump_count, sled_count, dead_count, xor_count, total_insns) =
            self.scan_bytecode(dex_data, &hdr);

        let nop_density = if total_insns > 0 {
            f64::from(nop_count) / total_insns as f64
        } else {
            0.0
        };
        let jump_density = if total_insns > 0 {
            f64::from(jump_count) / total_insns as f64
        } else {
            0.0
        };
        let has_quick_opcodes = quick_count > 0;

        if has_quick_opcodes {
            findings.push(
                DetectionFinding::new(
                    OptimizationKind::QuickOpcodes,
                    format!("{quick_count} ART quick-invoke opcodes found"),
                    FindingSeverity::Medium,
                )
                .with_count(quick_count),
            );
        }
        if sled_count > 0 {
            findings.push(
                DetectionFinding::new(
                    OptimizationKind::NopSleds,
                    format!("{sled_count} NOP sled(s) of ≥ 4 consecutive NOPs found"),
                    FindingSeverity::Low,
                )
                .with_count(sled_count),
            );
        }
        if jump_density > 0.15 {
            findings.push(
                DetectionFinding::new(
                    OptimizationKind::JumpHeavy,
                    format!("High jump/goto density {jump_density:.2} ({jump_count} jumps)"),
                    FindingSeverity::Medium,
                )
                .with_count(jump_count),
            );
        }
        if dead_count > 0 {
            findings.push(
                DetectionFinding::new(
                    OptimizationKind::DeadCode,
                    format!("{dead_count} dead-code return-void sequence(s) detected"),
                    FindingSeverity::Low,
                )
                .with_count(dead_count),
            );
        }
        if xor_count > 0 {
            findings.push(
                DetectionFinding::new(
                    OptimizationKind::StringDecryptionArtefacts,
                    format!("{xor_count} XOR-near-const-string pattern(s) — possible string decryption"),
                    FindingSeverity::High,
                )
                .with_count(xor_count),
            );
        }

        Ok(DexOptimizerReport {
            findings,
            bytecode_bytes_scanned: total_insns * 2,
            string_pool_bytes,
            class_count,
            method_count,
            string_pool_entropy,
            nop_density,
            jump_density,
            has_quick_opcodes,
        })
    }

    /// Scan all bytecode in `dex_data` and return counters.
    /// Returns `(quick, nop, jump, sled, dead, xor, total)` counts.
    fn scan_bytecode(&self, dex_data: &[u8], hdr: &DexHeader) -> (u32, u32, u32, u32, u32, u32, usize) {
        let mut quick = 0u32;
        let mut nop = 0u32;
        let mut jump = 0u32;
        let mut sled = 0u32;
        let mut dead = 0u32;
        let mut xor = 0u32;
        let mut total = 0usize;

        let class_defs = crate::read_class_defs(dex_data, hdr);
        for def in &class_defs {
            if def.class_data_off == 0 {
                continue;
            }
            let methods = crate::parse_encoded_methods(dex_data, def.class_data_off);
            for m in methods {
                if m.code_off == 0 {
                    continue;
                }
                if let Some(ci) = crate::CodeItem::parse(dex_data, m.code_off as usize) {
                    total += ci.insns.len();
                    let insn_bytes: Vec<u8> = ci
                        .insns
                        .iter()
                        .flat_map(|&u| u.to_le_bytes())
                        .collect();
                    // Count opcode types
                    let mut consecutive_nops = 0u32;
                    let mut prev_was_const_string = false;
                    for i in 0..insn_bytes.len() {
                        let op = insn_bytes[i];
                        // Count NOPs
                        if op == OP_NOP && i % 2 == 0 {
                            nop += 1;
                            consecutive_nops += 1;
                        } else {
                            if consecutive_nops >= 4 {
                                sled += 1;
                            }
                            consecutive_nops = 0;
                        }
                        // Quick opcodes
                        if op == OP_INVOKE_VIRTUAL_QUICK
                            || op == OP_INVOKE_VIRTUAL_QUICK_RANGE
                            || op == OP_IGET_QUICK
                            || op == OP_INVOKE_SUPER_QUICK
                        {
                            quick += 1;
                        }
                        // Jumps / gotos
                        if (op == OP_GOTO || op == OP_GOTO_16) && i % 2 == 0 {
                            jump += 1;
                        }
                        // Dead code: return-void after return-void
                        if op == OP_RETURN_VOID && i + 2 < insn_bytes.len() && insn_bytes[i + 2] == OP_RETURN_VOID && i % 2 == 0 {
                            dead += 1;
                        }
                        // XOR near const-string
                        if prev_was_const_string && op == 0xB2 /* xor-int/2addr */ {
                            xor += 1;
                        }
                        prev_was_const_string = op == OP_CONST_STRING || op == OP_CONST_STRING_JUMBO;
                    }
                    if consecutive_nops >= 4 {
                        sled += 1;
                    }
                }
            }
        }
        (quick, nop, jump, sled, dead, xor, total)
    }
}

// ─── DexStringAnalyzer ────────────────────────────────────────────────────────

/// Analyses the string pool of a DEX file for obfuscation patterns.
#[derive(Debug, Clone, Default)]
pub struct DexStringAnalyzer;

impl DexStringAnalyzer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Analyse the string pool and return statistics.
    #[must_use] 
    pub fn analyze(&self, dex_data: &[u8]) -> StringPoolStats {
        if !is_dex(dex_data) {
            return StringPoolStats::default();
        }
        let hdr = match DexHeader::parse(dex_data) {
            Ok(h) => h,
            Err(_) => return StringPoolStats::default(),
        };
        let strings = read_string_table(dex_data, &hdr);
        let total = strings.len();
        if total == 0 {
            return StringPoolStats::default();
        }

        let total_len: usize = strings.iter().map(std::string::String::len).sum();
        let avg_len = total_len as f64 / total as f64;
        let empty_count = strings.iter().filter(|s| s.is_empty()).count();
        let single_char_count = strings.iter().filter(|s| s.len() == 1).count();
        let non_ascii_count = strings
            .iter()
            .filter(|s| !s.is_ascii())
            .count();

        // Compute length variance
        let variance: f64 = if total > 1 {
            strings
                .iter()
                .map(|s| {
                    let diff = s.len() as f64 - avg_len;
                    diff * diff
                })
                .sum::<f64>()
                / (total as f64 - 1.0)
        } else {
            0.0
        };

        let high_entropy_strings = strings
            .iter()
            .filter(|s| s.len() >= 8 && shannon_entropy(s.as_bytes()) > 4.5)
            .count();

        StringPoolStats {
            total_strings: total,
            avg_length: avg_len,
            empty_count,
            single_char_count,
            non_ascii_count,
            high_entropy_strings,
            length_variance: variance,
        }
    }
}

/// Statistics about a DEX string pool.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StringPoolStats {
    pub total_strings: usize,
    pub avg_length: f64,
    pub empty_count: usize,
    pub single_char_count: usize,
    pub non_ascii_count: usize,
    pub high_entropy_strings: usize,
    pub length_variance: f64,
}

impl StringPoolStats {
    /// Returns `true` if this looks like a heavily obfuscated string pool.
    #[must_use]
    pub fn looks_obfuscated(&self) -> bool {
        (self.single_char_count as f64 / self.total_strings.max(1) as f64) > 0.3
            || self.high_entropy_strings > 5
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_dex() -> Vec<u8> {
        // Minimal valid DEX file (112-byte header with no content)
        let mut data = vec![0u8; 112];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..8].copy_from_slice(b"035\0");
        // file_size at offset 32
        let size = 112u32;
        data[32..36].copy_from_slice(&size.to_le_bytes());
        // header_size at offset 36
        data[36..40].copy_from_slice(&112u32.to_le_bytes());
        // endian_tag at offset 40
        data[40..44].copy_from_slice(&0x12345678u32.to_le_bytes());
        data
    }

    #[test]
    fn detect_not_dex() {
        let err = DexOptimizerDetector::new().analyze(b"notadex").unwrap_err();
        assert!(matches!(err, OptimizerDetectorError::NotDex));
    }

    #[test]
    fn detect_minimal_dex_ok() {
        let dex = minimal_dex();
        let report = DexOptimizerDetector::new().analyze(&dex).unwrap();
        assert_eq!(report.class_count, 0);
        assert_eq!(report.method_count, 0);
    }

    #[test]
    fn shannon_entropy_uniform() {
        let data: Vec<u8> = (0..=255).collect();
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 0.01);
    }

    #[test]
    fn shannon_entropy_constant() {
        let data = vec![0u8; 100];
        let e = shannon_entropy(&data);
        assert_eq!(e, 0.0);
    }

    #[test]
    fn shannon_entropy_empty() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn finding_severity_ord() {
        assert!(FindingSeverity::High > FindingSeverity::Medium);
        assert!(FindingSeverity::Medium > FindingSeverity::Low);
        assert!(FindingSeverity::Low > FindingSeverity::Info);
    }

    #[test]
    fn detection_finding_new() {
        let f = DetectionFinding::new(
            OptimizationKind::NopSleds,
            "desc",
            FindingSeverity::Low,
        );
        assert_eq!(f.count, 1);
        assert!(f.first_offset.is_none());
    }

    #[test]
    fn detection_finding_with_offset() {
        let f = DetectionFinding::new(OptimizationKind::QuickOpcodes, "desc", FindingSeverity::Medium)
            .with_offset(0x100);
        assert_eq!(f.first_offset, Some(0x100));
    }

    #[test]
    fn dex_optimizer_report_is_packed_false() {
        let dex = minimal_dex();
        let report = DexOptimizerDetector::new().analyze(&dex).unwrap();
        assert!(!report.is_packed());
    }

    #[test]
    fn dex_optimizer_report_unique_kinds() {
        let dex = minimal_dex();
        let report = DexOptimizerDetector::new().analyze(&dex).unwrap();
        // Each kind should appear at most once in unique list
        let kinds = report.unique_kinds();
        let mut set = std::collections::HashSet::new();
        for k in &kinds {
            assert!(set.insert(k.to_string()));
        }
    }

    #[test]
    fn string_pool_stats_default() {
        let stats = StringPoolStats::default();
        assert_eq!(stats.total_strings, 0);
        assert!(!stats.looks_obfuscated());
    }

    #[test]
    fn dex_string_analyzer_minimal() {
        let dex = minimal_dex();
        let stats = DexStringAnalyzer::new().analyze(&dex);
        assert_eq!(stats.total_strings, 0);
    }

    #[test]
    fn dex_string_analyzer_not_dex() {
        let stats = DexStringAnalyzer::new().analyze(b"garbage");
        assert_eq!(stats.total_strings, 0);
    }

    #[test]
    fn detect_packer_no_match() {
        let data = b"hello world nothing to see here";
        assert!(detect_packer(data).is_none());
    }

    #[test]
    fn detect_packer_bangcle() {
        let data = b"com/bangcle/main";
        assert_eq!(detect_packer(data), Some("Bangcle"));
    }

    #[test]
    fn detect_packer_dexguard() {
        let data = b"com/saikoa/dexguard/protect";
        assert_eq!(detect_packer(data), Some("DexGuard"));
    }

    #[test]
    fn optimization_kind_display_quick() {
        assert_eq!(OptimizationKind::QuickOpcodes.to_string(), "quick_opcodes");
    }

    #[test]
    fn optimization_kind_display_packer() {
        assert_eq!(
            OptimizationKind::KnownPacker("DexGuard".to_owned()).to_string(),
            "known_packer:DexGuard"
        );
    }

    #[test]
    fn report_findings_at_least_empty_when_minimal() {
        let dex = minimal_dex();
        let report = DexOptimizerDetector::new().analyze(&dex).unwrap();
        let high = report.findings_at_least(FindingSeverity::High);
        // no high findings in a trivial DEX
        assert!(high.is_empty());
    }

    #[test]
    fn report_summary_format() {
        let dex = minimal_dex();
        let report = DexOptimizerDetector::new().analyze(&dex).unwrap();
        let s = report.summary();
        assert!(s.contains("findings="));
        assert!(s.contains("packed="));
    }

    #[test]
    fn nop_density_zero_for_minimal() {
        let dex = minimal_dex();
        let report = DexOptimizerDetector::new().analyze(&dex).unwrap();
        assert_eq!(report.nop_density, 0.0);
    }

    #[test]
    fn finding_severity_display() {
        assert_eq!(FindingSeverity::High.to_string(), "high");
        assert_eq!(FindingSeverity::Info.to_string(), "info");
    }
}
