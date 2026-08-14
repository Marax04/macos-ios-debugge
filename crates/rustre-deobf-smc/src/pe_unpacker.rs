//! `pe_unpacker` — Generic PE unpacker with OEP detection and IAT reconstruction.
//!
//! Detects the Original Entry Point via heuristics (ret-to-OEP, hardware BP
//! simulation on IAT access), dumps memory at OEP, reconstructs the IAT from
//! memory, fixes relocations, and produces a Scylla-style dump.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// IatEntry
// ─────────────────────────────────────────────────────────────────────────────

/// One resolved IAT entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IatEntry {
    /// Virtual address of the IAT slot.
    pub slot_va: u64,
    /// Resolved function virtual address.
    pub func_va: u64,
    /// Module name (best-effort, may be empty).
    pub module: String,
    /// Function name or ordinal string.
    pub symbol: String,
    /// Whether the entry was resolved by name (false = ordinal only).
    pub by_name: bool,
}

impl IatEntry {
    /// Formatted display string for the entry.
    #[must_use]
    pub fn display(&self) -> String {
        if self.by_name {
            format!("{}!{} @ {:#010x}", self.module, self.symbol, self.func_va)
        } else {
            format!("{}#{} @ {:#010x}", self.module, self.symbol, self.func_va)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OepCandidate
// ─────────────────────────────────────────────────────────────────────────────

/// A candidate Original Entry Point discovered by the unpacker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OepCandidate {
    /// Virtual address of the candidate OEP.
    pub va: u64,
    /// Score (higher = more likely to be the real OEP).
    pub score: f32,
    /// Detection method that produced this candidate.
    pub method: OepDetectionMethod,
    /// Whether this candidate falls inside the original PE section (not in the
    /// unpacker stub).
    pub in_original_section: bool,
}

/// Method used to locate the OEP candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OepDetectionMethod {
    /// Control flow returned to the suspected OEP after the unpack stub.
    ReturnHeuristic,
    /// Hardware breakpoint (simulated) triggered on IAT slot access.
    IatAccessBreakpoint,
    /// `jmp eax` / `jmp [eax]` / `call eax` trampoline at end of stub.
    JmpTrampolineHeuristic,
    /// OEP inferred from PE header after section permissions settled.
    SectionPermissionHeuristic,
    /// OEP matched a known unpacker signature (e.g. UPX tail).
    KnownPackerSignature,
    /// OEP found via emulation watching for low-entropy code.
    EntropyHeuristic,
}

impl OepDetectionMethod {
    /// Base confidence weight for each detection method.
    #[must_use]
    pub const fn base_score(self) -> f32 {
        match self {
            Self::IatAccessBreakpoint => 0.95,
            Self::KnownPackerSignature => 0.90,
            Self::JmpTrampolineHeuristic => 0.80,
            Self::ReturnHeuristic => 0.75,
            Self::SectionPermissionHeuristic => 0.65,
            Self::EntropyHeuristic => 0.60,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RelocationEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A single base-relocation entry that needs to be applied / fixed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelocationEntry {
    /// Virtual address of the pointer to fix.
    pub va: u64,
    /// Type (0=ABSOLUTE, 3=HIGHLOW, 10=DIR64 etc.).
    pub reloc_type: u16,
    /// Delta to add (`new_image_base` − `old_image_base`).
    pub delta: i64,
}

// ─────────────────────────────────────────────────────────────────────────────
// PeSection
// ─────────────────────────────────────────────────────────────────────────────

/// Simplified PE section descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeSection {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_offset: u64,
    pub raw_size: u64,
    pub characteristics: u32,
}

impl PeSection {
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
    const _IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;

    /// Whether the section is executable.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.characteristics & Self::IMAGE_SCN_MEM_EXECUTE != 0
    }

    /// Whether the section is writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.characteristics & Self::IMAGE_SCN_MEM_WRITE != 0
    }

    /// Whether the address `va` falls within this section.
    #[must_use]
    pub const fn contains(&self, va: u64) -> bool {
        va >= self.virtual_address && va < self.virtual_address + self.virtual_size
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UnpackerConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the PE unpacker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnpackerConfig {
    /// Maximum emulation steps before giving up.
    pub max_steps: u64,
    /// Whether to fix the relocation table after dumping.
    pub fix_relocations: bool,
    /// Whether to attempt IAT reconstruction.
    pub reconstruct_iat: bool,
    /// Minimum score for an OEP candidate to be selected.
    pub min_oep_score: f32,
    /// Image base assumed for the dump.
    pub dump_image_base: u64,
}

impl Default for UnpackerConfig {
    fn default() -> Self {
        Self {
            max_steps: 5_000_000,
            fix_relocations: true,
            reconstruct_iat: true,
            min_oep_score: 0.60,
            dump_image_base: 0x0040_0000,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IatScanner
// ─────────────────────────────────────────────────────────────────────────────

/// Scans memory for IAT entries and attempts to resolve them.
pub struct IatScanner {
    /// Base VA of the IAT region to scan.
    pub iat_base: u64,
    /// Size of the IAT region in bytes.
    pub iat_size: u64,
    /// Map from `func_va` → (module, symbol) for all known exports.
    known_exports: HashMap<u64, (String, String)>,
}

impl IatScanner {
    /// Create a new scanner for the given IAT range.
    #[must_use]
    pub fn new(iat_base: u64, iat_size: u64) -> Self {
        Self {
            iat_base,
            iat_size,
            known_exports: HashMap::new(),
        }
    }

    /// Register a known export for symbol resolution.
    pub fn register_export(&mut self, func_va: u64, module: impl Into<String>, symbol: impl Into<String>) {
        self.known_exports.insert(func_va, (module.into(), symbol.into()));
    }

    /// Scan `memory` (mapped at `iat_base`) for 32-bit or 64-bit pointers
    /// that resolve to known exports, returning resolved [`IatEntry`]s.
    ///
    /// # Arguments
    /// * `memory` — bytes of the IAT region
    /// * `is_64bit` — whether to read 8-byte pointers (true) or 4-byte (false)
    #[must_use]
    pub fn scan(&self, memory: &[u8], is_64bit: bool) -> Vec<IatEntry> {
        let ptr_size = if is_64bit { 8usize } else { 4 };
        let mut entries = Vec::new();

        let mut offset = 0usize;
        while offset + ptr_size <= memory.len() {
            let func_va = if is_64bit {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&memory[offset..offset + 8]);
                u64::from_le_bytes(arr)
            } else {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(&memory[offset..offset + 4]);
                u64::from(u32::from_le_bytes(arr))
            };

            let slot_va = self.iat_base + u64::try_from(offset).unwrap_or(u64::MAX);

            if func_va == 0 {
                offset += ptr_size;
                continue; // null terminator
            }

            if let Some((module, symbol)) = self.known_exports.get(&func_va) {
                entries.push(IatEntry {
                    slot_va,
                    func_va,
                    module: module.clone(),
                    symbol: symbol.clone(),
                    by_name: !symbol.starts_with('#'),
                });
            } else if func_va > 0x7000_0000 {
                // Plausible kernel/user space pointer, record as unresolved
                entries.push(IatEntry {
                    slot_va,
                    func_va,
                    module: String::new(),
                    symbol: format!("sub_{func_va:x}"),
                    by_name: false,
                });
            }

            offset += ptr_size;
        }

        entries
    }

    /// Attempt to auto-detect the IAT boundaries from a memory dump.
    ///
    /// Returns `(base, size)` of the largest candidate IAT region.
    #[must_use]
    pub fn auto_detect_bounds(memory: &[u8], image_base: u64, is_64bit: bool) -> (u64, u64) {
        let ptr_size = if is_64bit { 8usize } else { 4usize };
        let mut best_base = image_base;
        let mut best_size = 0u64;
        let mut current_start = 0usize;
        let mut current_count = 0usize;

        let mut offset = 0usize;
        while offset + ptr_size <= memory.len() {
            let val = if is_64bit {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&memory[offset..offset + 8]);
                u64::from_le_bytes(arr)
            } else {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(&memory[offset..offset + 4]);
                u64::from(u32::from_le_bytes(arr))
            };

            // Heuristic: plausible user-space API address
            let plausible = (0x6000_0000..=0x8000_0000_0000u64).contains(&val) || val == 0;
            if plausible {
                if current_count == 0 {
                    current_start = offset;
                }
                current_count += 1;
            } else {
                if current_count > usize::try_from(best_size).unwrap_or(usize::MAX).wrapping_div(ptr_size) {
                    best_base = image_base.saturating_add(u64::try_from(current_start).unwrap_or(u64::MAX));
                    best_size = u64::try_from(current_count.saturating_mul(ptr_size)).unwrap_or(u64::MAX);
                }
                current_count = 0;
            }
            offset += ptr_size;
        }
        (best_base, best_size)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OepDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Heuristic OEP detector.
pub struct OepDetector {
    config: UnpackerConfig,
    sections: Vec<PeSection>,
    candidates: Vec<OepCandidate>,
}

impl OepDetector {
    /// Create with the given PE sections.
    #[must_use]
    pub const fn new(config: UnpackerConfig, sections: Vec<PeSection>) -> Self {
        Self {
            config,
            sections,
            candidates: Vec::new(),
        }
    }

    /// Submit a candidate OEP for scoring.
    pub fn submit_candidate(&mut self, va: u64, method: OepDetectionMethod) {
        let in_orig = self.sections.iter().any(|s| {
            s.contains(va) && !s.name.contains(".pack") && !s.name.contains("UPX")
        });

        let mut score = method.base_score();
        if in_orig {
            score += 0.10;
        }
        // Bonus if the VA is on a 0x10 or 0x100 alignment (common for OEP)
        if va.trailing_zeros() >= 4 {
            score += 0.03;
        }
        score = score.min(1.0);

        self.candidates.push(OepCandidate {
            va,
            score,
            method,
            in_original_section: in_orig,
        });
    }

    /// Return the best OEP candidate, or `None` if no candidate meets the threshold.
    ///
    /// # Panics
    /// Panics if a score is NaN (scores are expected to be finite floats in `[0.0, 1.0]`).
    #[must_use]
    pub fn best(&self) -> Option<&OepCandidate> {
        self.candidates
            .iter()
            .filter(|c| c.score >= self.config.min_oep_score)
            .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap())
    }

    /// Apply UPX tail signature heuristic to raw bytes.
    ///
    /// UPX stub ends with `61 8d 74 26 00 ff e0` (popad + jmp eax) or similar.
    pub fn check_upx_tail(&mut self, data: &[u8], image_base: u64) {
        // UPX 3.x: popad (61) followed by jmp eax (ff e0) or jmp [eax] (ff 20)
        let patterns: &[&[u8]] = &[
            &[0x61, 0xff, 0xe0],     // popad; jmp eax
            &[0x61, 0xff, 0x20],     // popad; jmp [eax]
            &[0x61, 0x8d, 0x74, 0x26, 0x00, 0xff, 0xe0], // UPX 3.x full tail
        ];
        for pat in patterns {
            if let Some(pos) = data.windows(pat.len()).position(|w| w == *pat) {
                // OEP is the first instruction after the jmp — the jmp target
                // is read from eax register which we can't know statically, but
                // the instruction *after* the tail is typically a push 0 or nop
                let candidate_va = image_base + u64::try_from(pos).unwrap_or(u64::MAX) + u64::try_from(pat.len()).unwrap_or(u64::MAX);
                self.submit_candidate(candidate_va, OepDetectionMethod::KnownPackerSignature);
            }
        }
    }

    /// All scored candidates (sorted by score descending).
    ///
    /// # Panics
    /// Panics if a score is NaN (scores are expected to be finite floats in `[0.0, 1.0]`).
    #[must_use]
    pub fn all_candidates(&self) -> Vec<&OepCandidate> {
        let mut v: Vec<&OepCandidate> = self.candidates.iter().collect();
        v.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        v
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RelocationFixer
// ─────────────────────────────────────────────────────────────────────────────

/// Applies base relocations to a memory dump.
pub struct RelocationFixer {
    old_base: u64,
    new_base: u64,
}

impl RelocationFixer {
    /// Create a fixer that shifts pointers from `old_base` to `new_base`.
    #[must_use]
    pub const fn new(old_base: u64, new_base: u64) -> Self {
        Self { old_base, new_base }
    }

    /// Delta applied to each pointer.
    #[must_use]
    pub const fn delta(&self) -> i64 {
        self.new_base.cast_signed() - self.old_base.cast_signed()
    }

    /// Apply a single relocation entry to `memory`.
    ///
    /// `memory` is mapped at `self.new_base`; `entry.va` is relative to image base.
    pub fn apply(&self, memory: &mut [u8], entry: &RelocationEntry) -> bool {
        // If entry.va < self.new_base the subtraction underflows; reject such entries.
        let Some(raw_offset) = entry.va.checked_sub(self.new_base) else { return false };
        let Ok(offset) = usize::try_from(raw_offset) else { return false };
        match entry.reloc_type {
            3 => {
                // IMAGE_REL_BASED_HIGHLOW (32-bit)
                if offset.checked_add(4).is_none_or(|e| e > memory.len()) {
                    return false;
                }
                let mut arr = [0u8; 4];
                arr.copy_from_slice(&memory[offset..offset + 4]);
                let val = u32::from_le_bytes(arr);
                let fixed = u32::try_from((i64::from(val) + entry.delta) & 0xFFFF_FFFF).unwrap_or(u32::MAX);
                memory[offset..offset + 4].copy_from_slice(&fixed.to_le_bytes());
                true
            }
            10 => {
                // IMAGE_REL_BASED_DIR64 (64-bit)
                if offset.checked_add(8).is_none_or(|e| e > memory.len()) {
                    return false;
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&memory[offset..offset + 8]);
                let val = u64::from_le_bytes(arr);
                let fixed = (val.cast_signed() + entry.delta).cast_unsigned();
                memory[offset..offset + 8].copy_from_slice(&fixed.to_le_bytes());
                true
            }
            0 => true, // ABSOLUTE — skip
            _ => false,
        }
    }

    /// Apply a full list of relocation entries, returning count of successes.
    pub fn apply_all(&self, memory: &mut [u8], entries: &[RelocationEntry]) -> usize {
        entries.iter().filter(|e| self.apply(memory, e)).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PeDump
// ─────────────────────────────────────────────────────────────────────────────

/// A reconstructed PE dump produced by the unpacker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeDump {
    /// The raw memory dump bytes.
    pub bytes: Vec<u8>,
    /// Image base used for this dump.
    pub image_base: u64,
    /// OEP (relative to image base).
    pub oep_rva: u64,
    /// Resolved IAT entries.
    pub iat: Vec<IatEntry>,
    /// Number of relocations applied.
    pub relocations_fixed: usize,
    /// Whether the dump looks like a valid PE (MZ header present).
    pub has_mz_header: bool,
}

impl PeDump {
    /// Whether the dump is likely valid.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.has_mz_header && self.oep_rva > 0
    }

    /// Human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "PeDump: base={:#x} oep_rva={:#x} iat={} entries relocations_fixed={} valid={}",
            self.image_base,
            self.oep_rva,
            self.iat.len(),
            self.relocations_fixed,
            self.is_valid()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PeUnpacker
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level PE unpacker orchestrator.
///
/// Usage:
/// 1. Feed packed bytes via [`Self::load`].
/// 2. Call [`Self::detect_oep`] (with emulation or static heuristics).
/// 3. Call [`Self::dump`] to produce a [`PeDump`].
pub struct PeUnpacker {
    config: UnpackerConfig,
    packed_bytes: Vec<u8>,
    sections: Vec<PeSection>,
    oep_detector: OepDetector,
    iat_scanner: IatScanner,
    reloc_fixer: RelocationFixer,
}

impl PeUnpacker {
    /// Construct a new unpacker.
    #[must_use] 
    pub fn new(
        config: UnpackerConfig,
        packed_bytes: Vec<u8>,
        sections: Vec<PeSection>,
        old_base: u64,
    ) -> Self {
        let oep_detector = OepDetector::new(config.clone(), sections.clone());
        let iat_scanner = IatScanner::new(0, 0); // bounds auto-detected at dump time
        let reloc_fixer = RelocationFixer::new(old_base, config.dump_image_base);
        Self {
            config,
            packed_bytes,
            sections,
            oep_detector,
            iat_scanner,
            reloc_fixer,
        }
    }

    /// Static heuristic OEP detection pass (no emulation required).
    pub fn detect_oep_static(&mut self) {
        // UPX tail check
        self.oep_detector
            .check_upx_tail(&self.packed_bytes, self.config.dump_image_base);

        // Section-permission heuristic: first executable section's VA
        if let Some(sec) = self.sections.iter().find(|s| s.is_executable() && !s.is_writable()) {
            self.oep_detector.submit_candidate(
                sec.virtual_address,
                OepDetectionMethod::SectionPermissionHeuristic,
            );
        }
    }

    /// Submit an OEP candidate discovered externally (e.g. from emulation callback).
    pub fn submit_oep_candidate(&mut self, va: u64, method: OepDetectionMethod) {
        self.oep_detector.submit_candidate(va, method);
    }

    /// Perform the actual dump at the best detected OEP.
    ///
    /// Returns `None` if no valid OEP candidate was found.
    #[must_use]
    pub fn dump(&mut self) -> Option<PeDump> {
        let oep = self.oep_detector.best()?.clone();
        let oep_rva = oep.va.wrapping_sub(self.config.dump_image_base);

        let mut bytes = self.packed_bytes.clone();

        // Fix relocations
        let relocs = Self::collect_relocation_entries();
        let relocations_fixed = self.reloc_fixer.apply_all(&mut bytes, &relocs);

        // Reconstruct IAT
        let (iat_base, iat_size) =
            IatScanner::auto_detect_bounds(&bytes, self.config.dump_image_base, true);
        self.iat_scanner.iat_base = iat_base;
        self.iat_scanner.iat_size = iat_size;
        let iat_offset = iat_base
            .checked_sub(self.config.dump_image_base)
            .and_then(|o| usize::try_from(o).ok())
            .unwrap_or_default();
        let iat_end = iat_offset
            .saturating_add(usize::try_from(iat_size).unwrap_or(0))
            .min(bytes.len());
        let iat = if iat_end > iat_offset {
            self.iat_scanner.scan(&bytes[iat_offset..iat_end], true)
        } else {
            vec![]
        };

        let has_mz = bytes.starts_with(b"MZ");

        Some(PeDump {
            bytes,
            image_base: self.config.dump_image_base,
            oep_rva,
            iat,
            relocations_fixed,
            has_mz_header: has_mz,
        })
    }

    /// Collect relocation entries from the packed binary (stub implementation).
    ///
    /// In a real implementation this parses the PE relocation directory.
    const fn collect_relocation_entries() -> Vec<RelocationEntry> {
        // Stub: return empty — a real integration hooks into rustre-loader-pe
        vec![]
    }

    /// Access the OEP detector for custom queries.
    #[must_use]
    pub const fn oep_detector(&self) -> &OepDetector {
        &self.oep_detector
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PackerSignatureDb
// ─────────────────────────────────────────────────────────────────────────────

/// Database of known packer byte signatures and their names.
pub struct PackerSignatureDb {
    entries: Vec<PackerSignature>,
}

/// One packer signature entry.
pub struct PackerSignature {
    pub name: &'static str,
    pub pattern: Vec<u8>,
    pub mask: Vec<u8>, // 0xFF = exact match, 0x00 = wildcard
    pub oep_offset: i64, // offset from pattern match to OEP estimate
}

impl PackerSignatureDb {
    /// Build the default signature database.
    #[must_use]
    pub fn default_db() -> Self {
        let mut db = Self { entries: vec![] };
        // UPX 3.x (x86)
        db.entries.push(PackerSignature {
            name: "UPX3-x86",
            pattern: vec![0x60, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x8D, 0xBE],
            mask: vec![0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF],
            oep_offset: 0,
        });
        // MPRESS
        db.entries.push(PackerSignature {
            name: "MPRESS",
            pattern: vec![0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x83, 0xC0, 0x0E],
            mask: vec![0xFF; 10],
            oep_offset: 0,
        });
        db
    }

    /// Scan `data` for all matching packer signatures.
    #[must_use]
    pub fn scan(&self, data: &[u8], image_base: u64) -> Vec<(String, u64)> {
        let mut results = Vec::new();
        for sig in &self.entries {
            let pat_len = sig.pattern.len();
            if pat_len == 0 || pat_len > data.len() {
                continue;
            }
            for (i, window) in data.windows(pat_len).enumerate() {
                let matched = window
                    .iter()
                    .zip(sig.pattern.iter())
                    .zip(sig.mask.iter())
                    .all(|((b, p), m)| (*m == 0) || (b & m == p & m));
                if matched {
                    // Compute OEP VA with saturating arithmetic to avoid wrapping.
                    let base_plus_i = image_base.saturating_add(u64::try_from(i).unwrap_or(u64::MAX));
                    let oep_va = if sig.oep_offset >= 0 {
                        base_plus_i.saturating_add(u64::try_from(sig.oep_offset).unwrap_or(u64::MAX))
                    } else {
                        base_plus_i.saturating_sub(sig.oep_offset.unsigned_abs())
                    };
                    results.push((sig.name.to_string(), oep_va));
                }
            }
        }
        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iat_scanner_resolves_known_exports() {
        let mut scanner = IatScanner::new(0x1000, 8);
        scanner.register_export(0x7FF00001u64, "kernel32", "GetProcAddress");
        let memory = 0x7FF00001u64.to_le_bytes().to_vec();
        let entries = scanner.scan(&memory, true);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].symbol, "GetProcAddress");
    }

    #[test]
    fn test_relocation_highlow() {
        let fixer = RelocationFixer::new(0x0040_0000, 0x0050_0000);
        let mut memory = vec![0u8; 8];
        let original_ptr: u32 = 0x0041_0000;
        memory[0..4].copy_from_slice(&original_ptr.to_le_bytes());
        let entry = RelocationEntry {
            va: 0x0050_0000, // maps to offset 0
            reloc_type: 3,
            delta: fixer.delta(),
        };
        assert!(fixer.apply(&mut memory, &entry));
        let result = u32::from_le_bytes(memory[0..4].try_into().unwrap());
        assert_eq!(result, 0x0051_0000);
    }

    #[test]
    fn test_oep_detector_upx() {
        let config = UnpackerConfig::default();
        let sections = vec![PeSection {
            name: ".text".into(),
            virtual_address: 0x1000,
            virtual_size: 0x5000,
            raw_offset: 0x400,
            raw_size: 0x5000,
            characteristics: 0x6000_0020,
        }];
        let mut detector = OepDetector::new(config, sections);
        let mut data = vec![0u8; 64];
        // Inject UPX tail at offset 10
        data[10..13].copy_from_slice(&[0x61, 0xff, 0xe0]);
        detector.check_upx_tail(&data, 0x0040_0000);
        assert!(!detector.all_candidates().is_empty());
    }
}
