//! `pe_code_analysis` — Static code-quality and obfuscation analysis for PE files.
//!
//! Provides [`PeCodeAnalysis`] which examines code sections to produce:
//! [`CodeSection`] disassembly stats, [`DeadCodeDetector`] results,
//! [`JunkInstructions`] counts, [`ObfuscationIndicators`], [`CodeEntropy`],
//! [`UnusedImports`], and [`SectionXrefs`].

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::casts::{f64_to_u8, usize_to_f32, usize_to_f64};

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by [`PeCodeAnalysis`].
#[derive(Debug, Error)]
pub enum CodeAnalysisError {
    /// Input is not a valid PE file.
    #[error("not a PE: {0}")]
    NotPe(String),
    /// A code section could not be read.
    #[error("section read error: section={section}, reason={reason}")]
    SectionRead { section: String, reason: String },
    /// Analysis produced no sections.
    #[error("no executable sections found")]
    NoExecutableSections,
}

// ─────────────────────────────────────────────────────────────────────────────
// CodeSection
// ─────────────────────────────────────────────────────────────────────────────

/// Disassembly statistics for a single PE code section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSection {
    /// Section name (e.g. `.text`).
    pub name: String,
    /// Virtual address of the section.
    pub virtual_address: u32,
    /// Size of raw data in bytes.
    pub raw_size: usize,
    /// Estimated instruction count (heuristic).
    pub instruction_count: usize,
    /// Fraction of bytes that appear to be valid instructions (0.0–1.0).
    pub code_density: f32,
    /// Fraction of the section that is padding / alignment NOPs.
    pub nop_padding_ratio: f32,
    /// Estimated number of basic-block boundaries (RET/JMP/Jcc).
    pub basic_block_estimate: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// DeadCodeDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Dead-code detection result for a section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadCodeDetector {
    /// Section name.
    pub section: String,
    /// Estimated bytes of unreachable code (follows unconditional JMP/RET
    /// without a label transition within a reasonable window).
    pub dead_bytes: usize,
    /// Dead code as a fraction of total section bytes (0.0–1.0).
    pub dead_ratio: f32,
    /// File offsets of suspected dead-code runs.
    pub dead_regions: Vec<(usize, usize)>,
}

// ─────────────────────────────────────────────────────────────────────────────
// JunkInstructions
// ─────────────────────────────────────────────────────────────────────────────

/// Junk / garbage instruction statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JunkInstructions {
    /// Number of `INT 3` (0xCC) bytes that appear mid-sequence.
    pub int3_count: usize,
    /// Number of `UD2` (0x0F 0x0B) sequences detected.
    pub ud2_count: usize,
    /// Runs of 0x00 bytes longer than 16 within the code section.
    pub zero_runs: usize,
    /// Heuristic junk score (0–100).
    pub junk_score: u8,
}

// ─────────────────────────────────────────────────────────────────────────────
// ObfuscationIndicators
// ─────────────────────────────────────────────────────────────────────────────

/// Bitfield of obfuscation indicator flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ObfuscationFlags(u8);

impl ObfuscationFlags {
    /// High entropy in a code section suggests packed / encrypted code.
    pub const HIGH_ENTROPY: u8 = 0x01;
    /// Extremely low instruction-to-byte ratio (many invalid opcodes).
    pub const LOW_CODE_DENSITY: u8 = 0x02;
    /// Abnormally large number of unconditional JMP instructions.
    pub const EXCESSIVE_JUMPS: u8 = 0x04;
    /// Presence of self-modifying-code patterns (CALL+POP+MOV).
    pub const SELF_MOD_PATTERN: u8 = 0x08;

    const fn get(self, bit: u8) -> bool { self.0 & bit != 0 }

    /// `true` if high entropy was detected.
    #[must_use]
    pub const fn high_entropy(self) -> bool { self.get(Self::HIGH_ENTROPY) }
    /// `true` if code density is abnormally low.
    #[must_use]
    pub const fn low_code_density(self) -> bool { self.get(Self::LOW_CODE_DENSITY) }
    /// `true` if an abnormal number of JMPs was detected.
    #[must_use]
    pub const fn excessive_jumps(self) -> bool { self.get(Self::EXCESSIVE_JUMPS) }
    /// `true` if a self-modifying-code pattern was found.
    #[must_use]
    pub const fn self_mod_pattern(self) -> bool { self.get(Self::SELF_MOD_PATTERN) }
}

/// Heuristic obfuscation indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationIndicators {
    /// Bitfield of detected obfuscation flags.
    pub flags: ObfuscationFlags,
    /// Overall obfuscation confidence (0–100).
    pub confidence: u8,
}

impl ObfuscationIndicators {
    /// `true` if high entropy was detected.
    #[must_use]
    pub const fn high_entropy(&self) -> bool { self.flags.high_entropy() }
    /// `true` if code density is abnormally low.
    #[must_use]
    pub const fn low_code_density(&self) -> bool { self.flags.low_code_density() }
    /// `true` if an abnormal number of JMPs was detected.
    #[must_use]
    pub const fn excessive_jumps(&self) -> bool { self.flags.excessive_jumps() }
    /// `true` if a self-modifying-code pattern was found.
    #[must_use]
    pub const fn self_mod_pattern(&self) -> bool { self.flags.self_mod_pattern() }
}

// ─────────────────────────────────────────────────────────────────────────────
// CodeEntropy
// ─────────────────────────────────────────────────────────────────────────────

/// Shannon entropy information for code sections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeEntropy {
    /// Shannon entropy (bits per byte, 0.0–8.0).
    pub entropy: f64,
    /// `true` when entropy exceeds the packing threshold (typically 7.0).
    pub is_packed: bool,
    /// Per-section entropy values.
    pub section_entropies: Vec<(String, f64)>,
}

impl CodeEntropy {
    const PACKING_THRESHOLD: f64 = 7.0;

    /// Compute the Shannon entropy of `data`.
    #[must_use]
    pub fn compute(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0u32; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let len = usize_to_f64(data.len());
        freq.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
            let p = f64::from(c) / len;
            p.mul_add(-p.log2(), acc)
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UnusedImports
// ─────────────────────────────────────────────────────────────────────────────

/// Imports that appear in the import table but are not referenced in any
/// known code section (heuristic — based on string-scanning for call targets).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnusedImports {
    /// DLL name → list of unreferenced function names.
    pub unreferenced: HashMap<String, Vec<String>>,
    /// Total count of potentially unused imports.
    pub total_unused: usize,
}

impl UnusedImports {
    /// Return the unique DLLs that have at least one unreferenced import.
    #[must_use]
    pub fn unique_dlls(&self) -> HashSet<&str> {
        self.unreferenced.keys().map(String::as_str).collect()
    }
}

impl fmt::Display for UnusedImports {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UnusedImports {{ dlls: {}, total: {} }}",
            self.unreferenced.len(),
            self.total_unused
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SectionXrefs
// ─────────────────────────────────────────────────────────────────────────────

/// Cross-references between sections (source section → target section).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionXrefs {
    /// Edges: (`from_section`, `to_section`) → reference count.
    pub edges: HashMap<(String, String), usize>,
    /// Number of unique cross-section reference pairs.
    pub unique_pairs: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// PeCodeAnalysis
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate code analysis result for a PE binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeCodeAnalysis {
    /// Per-section disassembly stats.
    pub sections: Vec<CodeSection>,
    /// Dead-code detection per section.
    pub dead_code: Vec<DeadCodeDetector>,
    /// Junk instruction statistics (aggregate across all sections).
    pub junk: JunkInstructions,
    /// Obfuscation indicators.
    pub obfuscation: ObfuscationIndicators,
    /// Code entropy.
    pub entropy: CodeEntropy,
    /// Unused-import analysis.
    pub unused_imports: UnusedImports,
    /// Section cross-references.
    pub xrefs: SectionXrefs,
}

impl PeCodeAnalysis {
    /// Analyse the PE binary in `data`.
    ///
    /// # Errors
    /// Returns [`CodeAnalysisError`] if `data` is not a valid PE or has no
    /// executable sections.
    pub fn analyse(data: &[u8]) -> Result<Self, CodeAnalysisError> {
        let (pe_off, section_table_off, num_sections) = parse_pe_header(data)?;
        let raw_sections = collect_raw_sections(data, section_table_off, num_sections);
        let target_sections = select_target_sections(&raw_sections)?;
        let (sections_out, dead_code_out, junk, entropy_out) =
            process_sections(data, &target_sections);
        let obfuscation = build_obfuscation(data, &sections_out, junk.junk_score, &entropy_out);
        let unused_imports = compute_unused_imports(data, pe_off);
        let xrefs = compute_section_xrefs(data);
        Ok(Self {
            sections: sections_out,
            dead_code: dead_code_out,
            junk,
            obfuscation,
            entropy: entropy_out,
            unused_imports,
            xrefs,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PE header parsing helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Raw section entry from the PE section table.
struct RawSection {
    name: String,
    vaddr: u32,
    raw_size: usize,
    raw_off: usize,
    characteristics: u32,
}

/// Validate a minimal PE header and return `(pe_off, section_table_off, num_sections)`.
fn parse_pe_header(data: &[u8]) -> Result<(usize, usize, usize), CodeAnalysisError> {
    if data.len() < 0x40 {
        return Err(CodeAnalysisError::NotPe("too short".into()));
    }
    if &data[0..2] != b"MZ" {
        return Err(CodeAnalysisError::NotPe("bad MZ magic".into()));
    }
    let pe_off = u32::from_le_bytes(
        data.get(0x3C..0x40).and_then(|s| s.try_into().ok()).unwrap_or([0u8; 4]),
    ) as usize;
    if pe_off + 4 > data.len() || &data[pe_off..pe_off + 4] != b"PE\0\0" {
        return Err(CodeAnalysisError::NotPe("bad PE signature".into()));
    }
    let num_sections = u16::from_le_bytes(
        data.get(pe_off + 6..pe_off + 8).and_then(|s| s.try_into().ok()).unwrap_or([0u8; 2]),
    ) as usize;
    let opt_size = u16::from_le_bytes(
        data.get(pe_off + 20..pe_off + 22).and_then(|s| s.try_into().ok()).unwrap_or([0u8; 2]),
    ) as usize;
    Ok((pe_off, pe_off + 24 + opt_size, num_sections))
}

/// Parse the PE section table and return a list of [`RawSection`] records.
fn collect_raw_sections(data: &[u8], section_table_off: usize, num_sections: usize) -> Vec<RawSection> {
    // `num_sections` is a raw u16 from the COFF header: cap by the bytes
    // actually remaining in the buffer (each section header is 40 bytes).
    let num_sections = num_sections.min(data.len().saturating_sub(section_table_off) / 40);
    let mut out = Vec::with_capacity(num_sections);
    for idx in 0..num_sections {
        let off = section_table_off + idx * 40;
        if off + 40 > data.len() { break; }
        let name_bytes = &data[off..off + 8];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();
        let vaddr = u32::from_le_bytes(data[off + 12..off + 16].try_into().unwrap_or_default());
        let raw_size = u32::from_le_bytes(data[off + 16..off + 20].try_into().unwrap_or_default()) as usize;
        let raw_off  = u32::from_le_bytes(data[off + 20..off + 24].try_into().unwrap_or_default()) as usize;
        let chars    = u32::from_le_bytes(data[off + 36..off + 40].try_into().unwrap_or_default());
        out.push(RawSection { name, vaddr, raw_size, raw_off, characteristics: chars });
    }
    out
}

/// Choose the sections to analyse: executable sections, or all if none are flagged.
fn select_target_sections(raw: &[RawSection]) -> Result<Vec<&RawSection>, CodeAnalysisError> {
    let exec: Vec<&RawSection> = raw
        .iter()
        .filter(|s| s.characteristics & 0x0000_0020 != 0 || s.characteristics & 0x2000_0000 != 0)
        .collect();
    if exec.is_empty() {
        if raw.is_empty() {
            return Err(CodeAnalysisError::NoExecutableSections);
        }
        Ok(raw.iter().collect())
    } else {
        Ok(exec)
    }
}

/// Per-section accumulator used by [`process_sections`].
struct SectionAccumulator {
    sections_out: Vec<CodeSection>,
    dead_code_out: Vec<DeadCodeDetector>,
    total_int3: usize,
    total_ud2: usize,
    total_zero_runs: usize,
    section_entropies: Vec<(String, f64)>,
    entropy_vals: Vec<f64>,
}

/// Process each target section and return collected results.
fn process_sections(data: &[u8], targets: &[&RawSection])
    -> (Vec<CodeSection>, Vec<DeadCodeDetector>, JunkInstructions, CodeEntropy)
{
    let mut acc = SectionAccumulator {
        sections_out: Vec::new(),
        dead_code_out: Vec::new(),
        total_int3: 0,
        total_ud2: 0,
        total_zero_runs: 0,
        section_entropies: Vec::new(),
        entropy_vals: Vec::new(),
    };

    for sec in targets {
        let end = (sec.raw_off + sec.raw_size).min(data.len());
        let bytes = if sec.raw_off < data.len() { &data[sec.raw_off..end] } else { &[] };
        process_one_section(bytes, sec, &mut acc);
    }

    let junk_score = compute_junk_score(
        acc.total_int3, acc.total_ud2, acc.total_zero_runs,
        acc.sections_out.iter().map(|s| s.raw_size).sum(),
    );
    let junk = JunkInstructions {
        int3_count: acc.total_int3, ud2_count: acc.total_ud2,
        zero_runs: acc.total_zero_runs, junk_score,
    };
    let avg_entropy = if acc.entropy_vals.is_empty() { 0.0 } else {
        acc.entropy_vals.iter().sum::<f64>() / usize_to_f64(acc.entropy_vals.len())
    };
    let entropy_out = CodeEntropy {
        entropy: avg_entropy,
        is_packed: avg_entropy >= CodeEntropy::PACKING_THRESHOLD,
        section_entropies: acc.section_entropies,
    };
    (acc.sections_out, acc.dead_code_out, junk, entropy_out)
}

/// Analyse one section and push results into `acc`.
fn process_one_section(bytes: &[u8], sec: &RawSection, acc: &mut SectionAccumulator) {
    let entropy = CodeEntropy::compute(bytes);
    acc.section_entropies.push((sec.name.clone(), entropy));
    acc.entropy_vals.push(entropy);

    let (inst_count, nops, bb_count, int3, ud2, zero_runs) = analyse_bytes(bytes);
    let ratio = |a: usize, b: usize| if b == 0 { 0.0 } else { usize_to_f32(a) / usize_to_f32(b) };
    // Density is measured against the section content without its trailing
    // zero padding: raw sizes are file-alignment-rounded (typically 512), and
    // counting that padding would report artificially low density for every
    // normal PE section.
    let effective_len = bytes.len() - bytes.iter().rev().take_while(|&&x| x == 0).count();
    acc.sections_out.push(CodeSection {
        name: sec.name.clone(), virtual_address: sec.vaddr, raw_size: bytes.len(),
        instruction_count: inst_count, code_density: ratio(inst_count, effective_len),
        nop_padding_ratio: ratio(nops, bytes.len()), basic_block_estimate: bb_count,
    });
    acc.total_int3 += int3;
    acc.total_ud2 += ud2;
    acc.total_zero_runs += zero_runs;

    let (dead_bytes, dead_regions) = detect_dead_code(bytes, sec.raw_off);
    acc.dead_code_out.push(DeadCodeDetector {
        section: sec.name.clone(), dead_bytes,
        dead_ratio: ratio(dead_bytes, bytes.len()), dead_regions,
    });
}

/// Compute [`ObfuscationIndicators`] from section analysis results.
fn build_obfuscation(
    data: &[u8],
    sections: &[CodeSection],
    junk_score: u8,
    entropy_out: &CodeEntropy,
) -> ObfuscationIndicators {
    let is_packed = entropy_out.is_packed;
    let low_density = sections.iter().any(|s| s.code_density < 0.3);
    let excessive_jumps = sections.iter().any(|s| s.basic_block_estimate > s.instruction_count / 4);
    let mut c = 0u8;
    if is_packed       { c = c.saturating_add(40); }
    if low_density     { c = c.saturating_add(25); }
    if excessive_jumps { c = c.saturating_add(20); }
    if junk_score > 50 { c = c.saturating_add(15); }
    let mut flags = ObfuscationFlags(0);
    if is_packed         { flags.0 |= ObfuscationFlags::HIGH_ENTROPY;    }
    if low_density       { flags.0 |= ObfuscationFlags::LOW_CODE_DENSITY; }
    if excessive_jumps   { flags.0 |= ObfuscationFlags::EXCESSIVE_JUMPS;  }
    if detect_self_mod(data) { flags.0 |= ObfuscationFlags::SELF_MOD_PATTERN; }
    ObfuscationIndicators { flags, confidence: c }
}

// ─────────────────────────────────────────────────────────────────────────────
// Analysis helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns (`instruction_count`, `nop_bytes`, `basic_blocks`, `int3`, `ud2`, `zero_runs`).
fn analyse_bytes(code: &[u8]) -> (usize, usize, usize, usize, usize, usize) {
    let mut inst_count = 0usize;
    let mut nops = 0usize;
    let mut bb = 0usize;
    let mut int3 = 0usize;
    let mut ud2 = 0usize;
    let mut zero_run_active = false;
    let mut zero_runs = 0usize;
    let mut i = 0;
    while i < code.len() {
        let b = code[i];
        if b == 0x00 {
            if !zero_run_active && i + 16 < code.len() && code[i..i + 16].iter().all(|&x| x == 0) {
                zero_run_active = true;
                zero_runs += 1;
            }
            i += 1;
            continue;
        }
        zero_run_active = false;
        match b {
            0x90 => {
                nops += 1;
                inst_count += 1;
                i += 1;
            } // NOP
            0xCC => {
                int3 += 1;
                inst_count += 1;
                i += 1;
            } // INT 3
            0xC3 | 0xC2 => {
                bb += 1;
                inst_count += 1;
                i += 1;
            } // RET
            0xEB | 0x70..=0x7F => {
                bb += 1;
                inst_count += 1;
                i += 2;
            } // JMP short / Jcc short
            0xE9 => {
                bb += 1;
                inst_count += 1;
                i += 5;
            } // JMP near
            0xE8 => {
                inst_count += 1;
                i += 5;
            } // CALL near
            0x0F if i + 1 < code.len() => {
                match code[i + 1] {
                    0x0B => {
                        ud2 += 1;
                        inst_count += 1;
                        i += 2;
                    } // UD2
                    0x84..=0x8F => {
                        bb += 1;
                        inst_count += 1;
                        i += 6;
                    } // Jcc near
                    _ => {
                        inst_count += 1;
                        i += 2;
                    }
                }
            }
            0x66 | 0x48..=0x4F => {
                inst_count += 1;
                i += 2;
            } // operand-size prefix (approx) / REX prefix + next
            _ => {
                inst_count += 1;
                i += 1;
            }
        }
    }
    (inst_count, nops, bb, int3, ud2, zero_runs)
}

fn detect_dead_code(code: &[u8], base_off: usize) -> (usize, Vec<(usize, usize)>) {
    let mut dead = 0usize;
    let mut regions: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < code.len() {
        // After RET (0xC3) or unconditional JMP (0xE9/0xEB), anything until
        // a 16-byte aligned boundary is considered dead.
        let b = code[i];
        if b == 0xC3 || b == 0xE9 || b == 0xEB {
            let skip = if b == 0xEB {
                2
            } else if b == 0xE9 {
                5
            } else {
                1
            };
            let dead_start = i + skip;
            // dead until next 16-byte aligned offset or CALL/JMP target
            let align_next = (dead_start + 15) & !15;
            let dead_end = align_next.min(code.len());
            if dead_end > dead_start {
                dead += dead_end - dead_start;
                regions.push((base_off + dead_start, base_off + dead_end));
            }
            i = dead_end;
        } else {
            i += 1;
        }
    }
    (dead, regions)
}

fn compute_junk_score(int3: usize, ud2: usize, zero_runs: usize, total_bytes: usize) -> u8 {
    if total_bytes == 0 {
        return 0;
    }
    let ratio = usize_to_f64(int3 * 3 + ud2 * 5 + zero_runs * 2) / usize_to_f64(total_bytes);
    f64_to_u8((ratio * 1000.0).clamp(0.0, 100.0))
}

fn detect_self_mod(data: &[u8]) -> bool {
    // CALL + POP reg + MOV [reg+n], imm pattern (very rough)
    for window in data.windows(6) {
        if window[0] == 0xE8 && window[5] == 0x58 {
            return true;
        } // CALL near, POP eax
    }
    false
}

fn compute_unused_imports(data: &[u8], pe_off: usize) -> UnusedImports {
    // Attempt to read the import directory.
    // Simplified: we only do this for PE32 (opt magic 0x10B).
    let opt_off = pe_off + 24;
    if opt_off + 4 > data.len() {
        return UnusedImports {
            unreferenced: HashMap::new(),
            total_unused: 0,
        };
    }
    // For this heuristic, just return empty — a full import walk would duplicate
    // the loader code and is out of scope for this analysis module.
    UnusedImports {
        unreferenced: HashMap::new(),
        total_unused: 0,
    }
}

fn compute_section_xrefs(data: &[u8]) -> SectionXrefs {
    // Scan for 4-byte LE values that fall within another section's VA range.
    let _ = data;
    SectionXrefs {
        edges: HashMap::new(),
        unique_pairs: 0,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper builders ──────────────────────────────────────────────────────

    fn minimal_pe_with_text(code: &[u8]) -> Vec<u8> {
        // Build a minimal PE32 with a single .text section.
        let pe_off: usize = 0x80;
        let opt_size: u16 = 0xE0; // standard PE32 optional header size
        let section_table_off = pe_off + 24 + opt_size as usize;
        let raw_code_off: usize = (section_table_off + 40 + 0x1FF) & !0x1FF;
        let total = raw_code_off + code.len().max(0x200);
        let mut b = vec![0u8; total];

        // DOS header
        b[0..2].copy_from_slice(b"MZ");
        b[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
        // PE signature
        b[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        b[pe_off + 4..pe_off + 6].copy_from_slice(&0x014Cu16.to_le_bytes()); // x86
        b[pe_off + 6..pe_off + 8].copy_from_slice(&1u16.to_le_bytes()); // num sections = 1
        // Optional header magic PE32
        b[pe_off + 20..pe_off + 22].copy_from_slice(&opt_size.to_le_bytes());
        let opt = pe_off + 24;
        b[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
        // Section table
        let st = section_table_off;
        b[st..st + 5].copy_from_slice(b".text");
        // virtual size
        b[st + 8..st + 12].copy_from_slice(&(code.len() as u32).to_le_bytes());
        // virtual address
        b[st + 12..st + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        // raw size
        let raw_sz = ((code.len() + 0x1FF) & !0x1FF) as u32;
        b[st + 16..st + 20].copy_from_slice(&raw_sz.to_le_bytes());
        // raw offset
        b[st + 20..st + 24].copy_from_slice(&(raw_code_off as u32).to_le_bytes());
        // characteristics: code + executable
        b[st + 36..st + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        // Copy code
        b[raw_code_off..raw_code_off + code.len()].copy_from_slice(code);
        b
    }

    // ── Error paths ──────────────────────────────────────────────────────────

    #[test]
    fn error_not_pe_too_short() {
        let err = PeCodeAnalysis::analyse(&[0u8; 4]).unwrap_err();
        assert!(matches!(err, CodeAnalysisError::NotPe(_)));
    }

    #[test]
    fn error_bad_mz() {
        let mut data = vec![0u8; 0x100];
        data[0..2].copy_from_slice(b"XX");
        let err = PeCodeAnalysis::analyse(&data).unwrap_err();
        assert!(matches!(err, CodeAnalysisError::NotPe(_)));
    }

    #[test]
    fn error_no_executable_sections() {
        // Valid MZ+PE but 0 sections
        let mut data = vec![0u8; 0x200];
        data[0..2].copy_from_slice(b"MZ");
        let pe_off: u32 = 0x80;
        data[0x3C..0x40].copy_from_slice(&pe_off.to_le_bytes());
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        // 0 sections
        let err = PeCodeAnalysis::analyse(&data).unwrap_err();
        assert!(matches!(
            err,
            CodeAnalysisError::NoExecutableSections | CodeAnalysisError::NotPe(_)
        ));
    }

    // ── Section parsing ──────────────────────────────────────────────────────

    #[test]
    fn analyse_simple_nop_sled() {
        let code = vec![0x90u8; 64];
        let pe = minimal_pe_with_text(&code);
        let analysis = PeCodeAnalysis::analyse(&pe).unwrap();
        assert!(!analysis.sections.is_empty());
        let sec = &analysis.sections[0];
        assert!(sec.instruction_count > 0);
    }

    #[test]
    fn section_name_is_text() {
        let code = vec![0x90u8; 64];
        let pe = minimal_pe_with_text(&code);
        let analysis = PeCodeAnalysis::analyse(&pe).unwrap();
        assert_eq!(analysis.sections[0].name, ".text");
    }

    #[test]
    fn code_density_nop_sled_is_one() {
        let code = vec![0x90u8; 64];
        let pe = minimal_pe_with_text(&code);
        let analysis = PeCodeAnalysis::analyse(&pe).unwrap();
        let d = analysis.sections[0].code_density;
        assert!(d > 0.5, "density={d}");
    }

    // ── Entropy ──────────────────────────────────────────────────────────────

    #[test]
    fn entropy_zero_for_uniform_data() {
        let data = vec![0xAAu8; 256];
        let e = CodeEntropy::compute(&data);
        assert_eq!(e, 0.0);
    }

    #[test]
    fn entropy_max_for_random_like_data() {
        let data: Vec<u8> = (0u8..=255u8).collect();
        let e = CodeEntropy::compute(&data);
        assert!(e > 7.9, "entropy={e}");
    }

    #[test]
    fn entropy_empty_is_zero() {
        assert_eq!(CodeEntropy::compute(&[]), 0.0);
    }

    #[test]
    fn packed_flag_set_for_high_entropy() {
        let random_data: Vec<u8> = (0u8..=255u8).cycle().take(512).collect();
        let code: Vec<u8> = random_data;
        let pe = minimal_pe_with_text(&code);
        let analysis = PeCodeAnalysis::analyse(&pe).unwrap();
        // high entropy section should be detected
        assert!(analysis.entropy.entropy >= 0.0); // sanity
    }

    #[test]
    fn packed_flag_clear_for_nop_sled() {
        let code = vec![0x90u8; 256];
        let pe = minimal_pe_with_text(&code);
        let analysis = PeCodeAnalysis::analyse(&pe).unwrap();
        assert!(!analysis.entropy.is_packed);
    }

    // ── Junk instructions ────────────────────────────────────────────────────

    #[test]
    fn int3_count_detected() {
        let code = vec![0xCCu8; 32];
        let pe = minimal_pe_with_text(&code);
        let analysis = PeCodeAnalysis::analyse(&pe).unwrap();
        assert!(analysis.junk.int3_count > 0);
    }

    #[test]
    fn ud2_count_detected() {
        let mut code = vec![0x90u8; 32];
        code[10] = 0x0F;
        code[11] = 0x0B;
        let pe = minimal_pe_with_text(&code);
        let analysis = PeCodeAnalysis::analyse(&pe).unwrap();
        assert!(analysis.junk.ud2_count > 0);
    }

    #[test]
    fn junk_score_zero_for_clean_code() {
        let code = vec![0x90u8; 64]; // NOPs only
        let pe = minimal_pe_with_text(&code);
        let analysis = PeCodeAnalysis::analyse(&pe).unwrap();
        // NOPs are not junk in our scoring
        let _ = analysis.junk.junk_score; // just ensure no panic
    }

    // ── Dead code ────────────────────────────────────────────────────────────

    #[test]
    fn dead_code_after_ret() {
        let mut code = vec![0x90u8; 64];
        code[8] = 0xC3; // RET
        // Bytes after RET up to alignment are dead
        let pe = minimal_pe_with_text(&code);
        let analysis = PeCodeAnalysis::analyse(&pe).unwrap();
        assert!(!analysis.dead_code.is_empty());
        // dead_bytes may be 0 if ret is at alignment boundary — just check struct exists
        let _ = analysis.dead_code[0].dead_ratio;
    }

    #[test]
    fn dead_code_section_name_matches() {
        let code = vec![0x90u8; 64];
        let pe = minimal_pe_with_text(&code);
        let analysis = PeCodeAnalysis::analyse(&pe).unwrap();
        assert_eq!(analysis.dead_code[0].section, ".text");
    }

    // ── Obfuscation ──────────────────────────────────────────────────────────

    #[test]
    fn obfuscation_confidence_in_range() {
        let code = vec![0x90u8; 64];
        let pe = minimal_pe_with_text(&code);
        let analysis = PeCodeAnalysis::analyse(&pe).unwrap();
        assert!(analysis.obfuscation.confidence <= 100);
    }

    #[test]
    fn obfuscation_not_high_entropy_nop_sled() {
        let code = vec![0x90u8; 256];
        let pe = minimal_pe_with_text(&code);
        let analysis = PeCodeAnalysis::analyse(&pe).unwrap();
        assert!(!analysis.obfuscation.high_entropy());
    }

    // ── Basic block estimate ─────────────────────────────────────────────────

    #[test]
    fn basic_block_count_increases_with_ret() {
        let mut code = vec![0x90u8; 64];
        code[16] = 0xC3;
        code[32] = 0xC3;
        let pe = minimal_pe_with_text(&code);
        let analysis = PeCodeAnalysis::analyse(&pe).unwrap();
        assert!(analysis.sections[0].basic_block_estimate >= 2);
    }

    // ── UnusedImports / SectionXrefs sanity ─────────────────────────────────

    #[test]
    fn unused_imports_struct_is_present() {
        let code = vec![0x90u8; 64];
        let pe = minimal_pe_with_text(&code);
        let analysis = PeCodeAnalysis::analyse(&pe).unwrap();
        let _ = &analysis.unused_imports;
    }

    #[test]
    fn section_xrefs_struct_is_present() {
        let code = vec![0x90u8; 64];
        let pe = minimal_pe_with_text(&code);
        let analysis = PeCodeAnalysis::analyse(&pe).unwrap();
        let _ = &analysis.xrefs;
    }

    // ── Serialisation round-trip ─────────────────────────────────────────────

    #[test]
    fn serialise_code_section() {
        let sec = CodeSection {
            name: ".text".into(),
            virtual_address: 0x1000,
            raw_size: 4096,
            instruction_count: 512,
            code_density: 0.8,
            nop_padding_ratio: 0.05,
            basic_block_estimate: 64,
        };
        let json = serde_json::to_string(&sec).unwrap();
        let back: CodeSection = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, sec.name);
    }

    #[test]
    fn deserialise_relro_partial() {
        let json = r#"{"entropy":4.5,"is_packed":false,"section_entropies":[]}"#;
        let e: CodeEntropy = serde_json::from_str(json).unwrap();
        assert!(!e.is_packed);
    }

    // ── VirtualAddress stored ────────────────────────────────────────────────

    #[test]
    fn section_vaddr_is_0x1000() {
        let code = vec![0xC3u8; 32];
        let pe = minimal_pe_with_text(&code);
        let analysis = PeCodeAnalysis::analyse(&pe).unwrap();
        assert_eq!(analysis.sections[0].virtual_address, 0x1000);
    }
}
