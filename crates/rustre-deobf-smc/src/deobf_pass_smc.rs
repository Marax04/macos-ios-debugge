//! `deobf_pass_smc` — Deobfuscation pass that eliminates self-modifying code.
//!
//! Integrates with the analysis pipeline: runs the decryption loops inside an
//! emulator, collects all written bytes via the [`WriteMonitor`], reconstructs
//! the final (decrypted) binary layout, and produces a patched image with all
//! SMC stubs replaced by their plaintext equivalents.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::write_monitor::{KeyCandidate, WriteMonitor, WriteMonitorConfig};
use crate::smc_extractor::{LayerDecryption, LayerId, SmcAnalysis, SmcExtractor};

// ─────────────────────────────────────────────────────────────────────────────
// EmulatedWrite
// ─────────────────────────────────────────────────────────────────────────────

/// A single write produced during controlled emulation of a decryption stub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulatedWrite {
    /// Destination virtual address.
    pub dest_va: u64,
    /// Bytes written.
    pub bytes: Vec<u8>,
    /// Emulator instruction counter at the time of write.
    pub tick: u64,
    /// Source PC of the writing instruction.
    pub writer_pc: u64,
}

impl EmulatedWrite {
    /// Construct a new emulated write.
    #[must_use] 
    pub const fn new(dest_va: u64, bytes: Vec<u8>, tick: u64, writer_pc: u64) -> Self {
        Self { dest_va, bytes, tick, writer_pc }
    }

    /// Total bytes written.
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if no bytes were written.
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Display for EmulatedWrite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EmulatedWrite dest={:#x} len={} tick={} pc={:#x}",
            self.dest_va,
            self.bytes.len(),
            self.tick,
            self.writer_pc
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReconstructedBinary
// ─────────────────────────────────────────────────────────────────────────────

/// A patch applied to the binary image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmcPatch {
    /// File offset (raw binary offset, not VA).
    pub file_offset: u64,
    /// New bytes to write at that offset.
    pub new_bytes: Vec<u8>,
    /// Original bytes that existed there before decryption.
    pub old_bytes: Vec<u8>,
    /// Virtual address corresponding to `file_offset`.
    pub va: u64,
    /// Layer that produced this patch.
    pub source_layer: LayerId,
}

impl SmcPatch {
    /// Construct a new patch.
    #[must_use] 
    pub const fn new(
        file_offset: u64,
        va: u64,
        old_bytes: Vec<u8>,
        new_bytes: Vec<u8>,
        source_layer: LayerId,
    ) -> Self {
        Self { file_offset, new_bytes, old_bytes, va, source_layer }
    }

    /// Size of the patch in bytes.
    #[must_use] 
    pub const fn size(&self) -> usize {
        self.new_bytes.len()
    }

    /// Number of bytes that actually differ from the original.
    #[must_use] 
    pub fn changed_bytes(&self) -> usize {
        self.old_bytes.iter().zip(&self.new_bytes).filter(|(a, b)| a != b).count()
    }
}

impl fmt::Display for SmcPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SmcPatch va={:#x} off={:#x} size={} changed={}",
            self.va,
            self.file_offset,
            self.size(),
            self.changed_bytes()
        )
    }
}

/// The fully reconstructed binary after all SMC patches have been applied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructedBinary {
    /// Original binary bytes.
    pub original: Vec<u8>,
    /// Patched binary bytes (same length as `original`).
    pub patched: Vec<u8>,
    /// All patches applied.
    pub patches: Vec<SmcPatch>,
    /// Virtual address base used for VA→offset translation.
    pub image_base: u64,
    /// Number of decryption layers that were resolved.
    pub layers_resolved: u32,
}

impl ReconstructedBinary {
    /// Create a new reconstruction from the original binary image.
    #[must_use] 
    pub fn new(original: Vec<u8>, image_base: u64) -> Self {
        let patched = original.clone();
        Self {
            original,
            patched,
            patches: Vec::new(),
            image_base,
            layers_resolved: 0,
        }
    }

    /// Translate a virtual address to a file offset.
    ///
    /// For a flat image, `file_offset = va - image_base`.
    #[must_use] 
    pub const fn va_to_offset(&self, va: u64) -> Option<u64> {
        if va < self.image_base {
            return None;
        }
        let off = va - self.image_base;
        if off >= self.original.len() as u64 {
            return None;
        }
        Some(off)
    }

    /// Apply a single patch to the in-memory image.
    pub fn apply_patch(&mut self, patch: SmcPatch) -> bool {
        let off = usize::try_from(patch.file_offset).unwrap_or(usize::MAX);
        if off + patch.new_bytes.len() > self.patched.len() {
            return false;
        }
        self.patched[off..off + patch.new_bytes.len()].copy_from_slice(&patch.new_bytes);
        self.patches.push(patch);
        true
    }

    /// Build and apply a patch from a VA range and the decrypted bytes.
    pub fn patch_from_va(&mut self, va: u64, decrypted: &[u8], layer: LayerId) -> bool {
        let Some(off) = self.va_to_offset(va) else { return false };
        let Ok(off_usize) = usize::try_from(off) else { return false };
        let end = off_usize + decrypted.len();
        if end > self.original.len() {
            return false;
        }
        let old = self.original[off_usize..end].to_vec();
        let patch = SmcPatch::new(off, va, old, decrypted.to_vec(), layer);
        self.apply_patch(patch)
    }

    /// Total bytes changed relative to the original.
    #[must_use] 
    pub fn total_changed_bytes(&self) -> usize {
        self.patches.iter().map(SmcPatch::changed_bytes).sum()
    }

    /// Return a slice of the patched binary.
    #[must_use] 
    pub fn as_bytes(&self) -> &[u8] {
        &self.patched
    }

    /// Number of patches applied.
    #[must_use] 
    pub const fn patch_count(&self) -> usize {
        self.patches.len()
    }
}

impl fmt::Display for ReconstructedBinary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ReconstructedBinary base={:#x} size={} patches={} changed={}",
            self.image_base,
            self.original.len(),
            self.patch_count(),
            self.total_changed_bytes()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PassResult
// ─────────────────────────────────────────────────────────────────────────────

/// Error types returned by the SMC deobfuscation pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SmcPassError {
    /// Emulation failed at the given VA.
    EmulationFailed(u64, String),
    /// No decryption loops were found.
    NoLoopsFound,
    /// Binary is too large to reconstruct.
    BinaryTooLarge(usize),
    /// A patch could not be applied (e.g. out-of-range).
    PatchFailed(u64),
}

impl fmt::Display for SmcPassError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmulationFailed(va, msg) => {
                write!(f, "emulation failed at {va:#x}: {msg}")
            }
            Self::NoLoopsFound => write!(f, "no decryption loops found"),
            Self::BinaryTooLarge(sz) => write!(f, "binary too large: {sz} bytes"),
            Self::PatchFailed(va) => write!(f, "patch failed at {va:#x}"),
        }
    }
}

/// Summary of a completed SMC deobfuscation pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassResult {
    /// Whether the pass succeeded.
    pub success: bool,
    /// Errors encountered (non-fatal ones are collected here).
    pub errors: Vec<SmcPassError>,
    /// Number of loops processed.
    pub loops_processed: u32,
    /// Number of layers fully decrypted.
    pub layers_decrypted: u32,
    /// Number of patches applied to the binary.
    pub patches_applied: u32,
    /// Total bytes changed in the output image.
    pub bytes_changed: usize,
    /// Extracted code analysis result.
    pub analysis: SmcAnalysis,
}

impl PassResult {
    const fn _success_result(
        loops_processed: u32,
        layers_decrypted: u32,
        patches_applied: u32,
        bytes_changed: usize,
        analysis: SmcAnalysis,
    ) -> Self {
        Self {
            success: true,
            errors: Vec::new(),
            loops_processed,
            layers_decrypted,
            patches_applied,
            bytes_changed,
            analysis,
        }
    }

    fn failure(error: SmcPassError) -> Self {
        Self {
            success: false,
            errors: vec![error],
            loops_processed: 0,
            layers_decrypted: 0,
            patches_applied: 0,
            bytes_changed: 0,
            analysis: SmcAnalysis::new(),
        }
    }
}

impl fmt::Display for PassResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PassResult ok={} loops={} layers={} patches={} changed={}",
            self.success,
            self.loops_processed,
            self.layers_decrypted,
            self.patches_applied,
            self.bytes_changed
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcDeobfPass
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the SMC deobfuscation pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmcDeobfPassConfig {
    /// Maximum number of emulator ticks per loop execution.
    pub max_ticks_per_loop: u64,
    /// Maximum number of bytes that may be rewritten by a single loop.
    pub max_write_bytes: usize,
    /// If `true`, also patch the decryptor stub itself with NOPs.
    pub nop_out_decryptor: bool,
    /// If `true`, abort on the first emulation error.
    pub abort_on_error: bool,
    /// Maximum number of SMC layers to process (prevents infinite loop).
    pub max_layers: u32,
}

impl Default for SmcDeobfPassConfig {
    fn default() -> Self {
        Self {
            max_ticks_per_loop: 1_000_000,
            max_write_bytes: 1 << 20, // 1 MiB
            nop_out_decryptor: true,
            abort_on_error: false,
            max_layers: 16,
        }
    }
}

/// The main SMC deobfuscation pass.
///
/// Workflow:
/// 1. Feed the binary and known decryption regions via `add_region`.
/// 2. For each region, call `emulate_region` with a series of [`EmulatedWrite`]
///    events collected by the caller's emulator.
/// 3. Call `run` to produce a [`ReconstructedBinary`] and [`PassResult`].
pub struct SmcDeobfPass {
    /// Pass configuration.
    pub config: SmcDeobfPassConfig,
    /// Registered regions: VA → (size, `decryptor_entry`).
    regions: Vec<(u64, usize, u64)>,
    /// Emulated writes per region, keyed by region base VA.
    emulated_writes: HashMap<u64, Vec<EmulatedWrite>>,
    /// Write monitor (for loop detection and key extraction).
    monitor: WriteMonitor,
    /// SMC extractor.
    extractor: SmcExtractor,
    /// Accumulated key candidates (`region_va` → list).
    key_candidates: HashMap<u64, Vec<KeyCandidate>>,
}

impl SmcDeobfPass {
    /// Create a new pass with default configuration.
    #[must_use] 
    pub fn new() -> Self {
        Self::with_config(SmcDeobfPassConfig::default())
    }

    /// Create a pass with explicit configuration.
    #[must_use] 
    pub fn with_config(config: SmcDeobfPassConfig) -> Self {
        let monitor_cfg = WriteMonitorConfig {
            ring_capacity: 65536,
            smc_write_threshold: 4,
            loop_window: 32,
            track_all_writes: false,
        };
        Self {
            config,
            regions: Vec::new(),
            emulated_writes: HashMap::new(),
            monitor: WriteMonitor::with_config(monitor_cfg),
            extractor: SmcExtractor::new(),
            key_candidates: HashMap::new(),
        }
    }

    /// Register an encrypted code region at `[base_va, base_va + size)` with a
    /// known decryptor entry point.
    pub fn add_region(&mut self, base_va: u64, size: usize, decryptor_entry: u64) {
        self.regions.push((base_va, size, decryptor_entry));
        self.monitor.add_exec_region(base_va, base_va + size as u64);
    }

    /// Feed a batch of emulated writes collected during emulation of the
    /// decryptor at `region_va`.
    pub fn feed_writes(&mut self, region_va: u64, writes: Vec<EmulatedWrite>) {
        for w in &writes {
            self.monitor.on_write(w.dest_va, &w.bytes, w.writer_pc, w.tick);
        }
        self.emulated_writes.entry(region_va).or_default().extend(writes);
    }

    /// Feed a single emulated write.
    pub fn feed_write(&mut self, region_va: u64, write: EmulatedWrite) {
        self.monitor.on_write(write.dest_va, &write.bytes, write.writer_pc, write.tick);
        self.emulated_writes.entry(region_va).or_default().push(write);
    }

    /// Add a key candidate for the given region.
    pub fn add_key_candidate(&mut self, region_va: u64, candidate: KeyCandidate) {
        self.key_candidates.entry(region_va).or_default().push(candidate);
    }

    /// Build the decrypted byte map for a region from accumulated emulated writes.
    fn reconstruct_region_bytes(&self, base_va: u64, size: usize) -> Vec<u8> {
        let mut out = vec![0u8; size];
        if let Some(writes) = self.emulated_writes.get(&base_va) {
            for w in writes {
                let offset = usize::try_from(w.dest_va.saturating_sub(base_va)).unwrap_or(usize::MAX);
                for (i, &b) in w.bytes.iter().enumerate() {
                    let idx = offset + i;
                    if idx < out.len() {
                        out[idx] = b;
                    }
                }
            }
        }
        out
    }

    /// Execute the deobfuscation pass against `binary_image`.
    ///
    /// Returns the reconstructed binary and a pass result.
    pub fn run(
        &mut self,
        binary_image: Vec<u8>,
        image_base: u64,
    ) -> (ReconstructedBinary, PassResult) {
        if binary_image.len() > (1 << 30) {
            let err = SmcPassError::BinaryTooLarge(binary_image.len());
            let rb = ReconstructedBinary::new(binary_image, image_base);
            return (rb, PassResult::failure(err));
        }

        if self.regions.is_empty() {
            let err = SmcPassError::NoLoopsFound;
            let rb = ReconstructedBinary::new(binary_image, image_base);
            return (rb, PassResult::failure(err));
        }

        let mut rb = ReconstructedBinary::new(binary_image, image_base);
        let mut errors: Vec<SmcPassError> = Vec::new();
        let mut layers_decrypted = 0u32;

        let regions = self.regions.clone();
        for (base_va, size, decryptor_entry) in &regions {
            // Check max layers.
            if layers_decrypted >= self.config.max_layers {
                break;
            }

            // Fetch original encrypted bytes from the image.
            let enc_bytes = if let Some(off) = rb.va_to_offset(*base_va)
                && let Ok(off_usize) = usize::try_from(off)
            {
                // `off_usize + size` would wrap in release builds (overflow-checks
                // off), letting an out-of-range region pass the bound check below.
                let Some(end) = off_usize.checked_add(*size) else {
                    errors.push(SmcPassError::PatchFailed(*base_va));
                    if self.config.abort_on_error {
                        break;
                    }
                    continue;
                };
                if end > rb.original.len() {
                    errors.push(SmcPassError::PatchFailed(*base_va));
                    if self.config.abort_on_error {
                        break;
                    }
                    continue;
                }
                rb.original[off_usize..end].to_vec()
            } else {
                errors.push(SmcPassError::PatchFailed(*base_va));
                if self.config.abort_on_error {
                    break;
                }
                continue;
            };

            // Register layer in extractor.
            let layer_id = self.extractor.begin_layer(*base_va, enc_bytes, *decryptor_entry);

            // Reconstruct decrypted bytes from emulated writes.
            let decrypted = self.reconstruct_region_bytes(*base_va, *size);

            // Check if we actually got any writes.
            let has_writes =
                self.emulated_writes.get(base_va).is_some_and(|v| !v.is_empty());
            if !has_writes {
                errors.push(SmcPassError::EmulationFailed(
                    *base_va,
                    "no writes observed".into(),
                ));
                if self.config.abort_on_error {
                    break;
                }
            }

            // Finalize layer in extractor (runs linear sweep disassembly).
            self.extractor.finalize_layer(*base_va, layer_id, &decrypted);

            // Record decryption metadata.
            let key_bytes: Vec<u8> = self
                .key_candidates
                .get(base_va)
                .and_then(|kcs| kcs.first())
                .map(|kc| kc.value.to_le_bytes().to_vec())
                .unwrap_or_default();
            let dec_record =
                LayerDecryption::new(layer_id, "emulated", key_bytes, 0).mark_complete();
            self.extractor.record_decryption(dec_record);

            // Apply patch to the binary.
            let patched = rb.patch_from_va(*base_va, &decrypted, layer_id);
            if !patched {
                errors.push(SmcPassError::PatchFailed(*base_va));
            }

            // Optionally NOP out the decryptor.
            if self.config.nop_out_decryptor {
                // Estimate decryptor size as 32 bytes (placeholder).
                let nop_bytes = vec![0x90u8; 32];
                rb.patch_from_va(*decryptor_entry, &nop_bytes, layer_id);
            }

            layers_decrypted += 1;
        }

        self.extractor.finish();
        let analysis = self.extractor.analysis.clone();

        let result = PassResult {
            success: errors.is_empty() || layers_decrypted > 0,
            errors,
            loops_processed: u32::try_from(self.monitor.decryption_loops.len()).unwrap_or(u32::MAX),
            layers_decrypted,
            patches_applied: u32::try_from(rb.patch_count()).unwrap_or(u32::MAX),
            bytes_changed: rb.total_changed_bytes(),
            analysis,
        };

        (rb, result)
    }

    /// Return all key candidates grouped by region VA.
    #[must_use] 
    pub const fn all_key_candidates(&self) -> &HashMap<u64, Vec<KeyCandidate>> {
        &self.key_candidates
    }

    /// Return a reference to the write monitor for inspection.
    #[must_use] 
    pub const fn monitor(&self) -> &WriteMonitor {
        &self.monitor
    }

    /// Clear accumulated emulated writes for a specific region.
    pub fn clear_region_writes(&mut self, region_va: u64) {
        self.emulated_writes.remove(&region_va);
    }

    /// Reset the entire pass state, keeping configuration.
    pub fn reset(&mut self) {
        self.regions.clear();
        self.emulated_writes.clear();
        self.monitor.reset();
        self.extractor = SmcExtractor::new();
        self.key_candidates.clear();
    }

    /// Return all emulated writes for a given region.
    #[must_use] 
    pub fn writes_for_region(&self, region_va: u64) -> &[EmulatedWrite] {
        self.emulated_writes.get(&region_va).map_or(&[], std::vec::Vec::as_slice)
    }

    /// Total number of emulated writes across all regions.
    #[must_use] 
    pub fn total_emulated_writes(&self) -> usize {
        self.emulated_writes.values().map(std::vec::Vec::len).sum()
    }
}

impl Default for SmcDeobfPass {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SmcDeobfPass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SmcDeobfPass [regions={} writes={} key_candidates={}]",
            self.regions.len(),
            self.total_emulated_writes(),
            self.key_candidates.values().map(std::vec::Vec::len).sum::<usize>()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_binary(size: usize, fill: u8) -> Vec<u8> {
        vec![fill; size]
    }

    #[test]
    fn test_pass_no_regions_returns_failure() {
        let mut pass = SmcDeobfPass::new();
        let binary = make_binary(0x1000, 0xcc);
        let (_, result) = pass.run(binary, 0x0040_0000);
        assert!(!result.success);
    }

    #[test]
    fn test_pass_with_region_and_writes() {
        let mut pass = SmcDeobfPass::new();
        // Binary: 0x1000 bytes at base 0x400000.
        let binary = make_binary(0x1000, 0xaa);
        // Encrypted region at offset 0x100 (VA = 0x400100), size 0x10.
        pass.add_region(0x0040_0100, 0x10, 0x0040_0050);

        // Simulate 16 emulated writes (one per byte).
        for i in 0..16u64 {
            let w = EmulatedWrite::new(0x0040_0100 + i, vec![0x90], i + 1, 0x0040_0050 + i * 2);
            pass.feed_write(0x0040_0100, w);
        }

        let (rb, result) = pass.run(binary, 0x0040_0000);
        assert!(result.layers_decrypted > 0);
        // Patched bytes at offset 0x100 should be 0x90 (NOP).
        assert_eq!(rb.patched[0x100], 0x90);
    }

    #[test]
    fn test_reconstructed_binary_va_to_offset() {
        let rb = ReconstructedBinary::new(vec![0u8; 0x1000], 0x0040_0000);
        assert_eq!(rb.va_to_offset(0x0040_0000), Some(0));
        assert_eq!(rb.va_to_offset(0x0040_0100), Some(0x100));
        assert_eq!(rb.va_to_offset(0x003f_ffff), None);
    }

    #[test]
    fn test_smc_patch_changed_bytes() {
        let old = vec![0xaa; 4];
        let new = vec![0xaa, 0xbb, 0xaa, 0xcc];
        let patch = SmcPatch::new(0, 0x1000, old, new, LayerId(0));
        assert_eq!(patch.changed_bytes(), 2);
    }

    #[test]
    fn test_emulated_write_len() {
        let w = EmulatedWrite::new(0x1000, vec![0x01, 0x02, 0x03], 5, 0x200);
        assert_eq!(w.len(), 3);
        assert!(!w.is_empty());
    }

    #[test]
    fn test_pass_reset() {
        let mut pass = SmcDeobfPass::new();
        pass.add_region(0x1000, 0x100, 0x500);
        pass.reset();
        assert_eq!(pass.regions.len(), 0);
        assert_eq!(pass.total_emulated_writes(), 0);
    }

    #[test]
    fn test_pass_result_display() {
        let pr = PassResult::_success_result(2, 2, 4, 128, SmcAnalysis::new());
        let s = format!("{pr}");
        assert!(s.contains("ok=true"));
    }

    #[test]
    fn test_key_candidate_stored_in_pass() {
        let mut pass = SmcDeobfPass::new();
        pass.add_region(0x2000, 0x40, 0x1000);
        let kc = KeyCandidate::xor(0xde, 8, 0x1010, 0.95);
        pass.add_key_candidate(0x2000, kc);
        assert_eq!(pass.key_candidates[&0x2000].len(), 1);
    }
}
