//! `smc_reconstructor` — Self-Modifying Code reconstruction engine.
//!
//! Emulates the decrypt loop, captures memory snapshots after each write,
//! assembles final revealed code from fragments, and handles multi-layer SMC
//! (decrypt → execute → re-encrypt).

use crate::{SmcAlgorithm, SmcKey, SmcRegion};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

// ─────────────────────────────────────────────────────────────────────────────
// MemorySnapshot
// ─────────────────────────────────────────────────────────────────────────────

/// A point-in-time snapshot of a memory region captured during emulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySnapshot {
    /// Emulation clock tick at which this snapshot was taken.
    pub tick: u64,
    /// Virtual address of the region base.
    pub base_addr: u64,
    /// Raw bytes captured from the region.
    pub bytes: Vec<u8>,
    /// Fraction of bytes that differ from the previous snapshot (0.0–1.0).
    pub delta_ratio: f32,
    /// Whether this snapshot appears to contain valid x86/x64 preamble bytes.
    pub looks_executable: bool,
}

impl MemorySnapshot {
    /// Compute byte-level diff count against a previous snapshot.
    #[must_use]
    pub fn diff_bytes(&self, prev: &Self) -> usize {
        if prev.bytes.len() != self.bytes.len() {
            return self.bytes.len();
        }
        self.bytes
            .iter()
            .zip(prev.bytes.iter())
            .filter(|(a, b)| a != b)
            .count()
    }

    /// Heuristic: does the snapshot start with a common function prologue?
    #[must_use]
    pub fn has_function_prologue(&self) -> bool {
        if self.bytes.len() < 4 {
            return false;
        }
        // push rbp / mov rbp, rsp  (0x55 0x48 0x89 0xe5)
        if self.bytes.starts_with(&[0x55, 0x48, 0x89, 0xe5]) {
            return true;
        }
        // push ebp / mov ebp, esp  (0x55 0x89 0xe5)
        if self.bytes.starts_with(&[0x55, 0x89, 0xe5]) {
            return true;
        }
        // sub rsp, N  (0x48 0x83 0xec)
        if self.bytes.starts_with(&[0x48, 0x83, 0xec]) {
            return true;
        }
        false
    }

    /// Shannon entropy of the snapshot bytes (0.0–8.0 bits/byte).
    #[must_use]
    pub fn entropy(&self) -> f64 {
        if self.bytes.is_empty() {
            return 0.0;
        }
        let mut freq = [0u64; 256];
        for &b in &self.bytes {
            freq[usize::from(b)] += 1;
        }
        let n = f64::from(u32::try_from(self.bytes.len()).unwrap_or(u32::MAX));
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / n;
                -p * p.log2()
            })
            .sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CodeFragment
// ─────────────────────────────────────────────────────────────────────────────

/// A contiguous slice of recovered code assembled from snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeFragment {
    /// Virtual start address.
    pub start_addr: u64,
    /// Recovered bytes.
    pub bytes: Vec<u8>,
    /// Snapshot tick from which this fragment was extracted.
    pub source_tick: u64,
    /// Layer number (0 = first decrypt stage).
    pub layer: u32,
    /// Confidence that this fragment represents genuine code (0.0–1.0).
    pub confidence: f32,
}

impl CodeFragment {
    /// Merge two adjacent fragments into one.
    ///
    /// # Panics
    /// Panics if `self` and `other` are not adjacent in memory.
    #[must_use]
    pub fn merge(mut self, other: &Self) -> Self {
        assert_eq!(
            self.start_addr + u64::try_from(self.bytes.len()).unwrap_or(u64::MAX),
            other.start_addr,
            "CodeFragment::merge: fragments are not adjacent"
        );
        self.bytes.extend_from_slice(&other.bytes);
        self.confidence = self.confidence.min(other.confidence);
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcLayer
// ─────────────────────────────────────────────────────────────────────────────

/// One layer in a multi-layer SMC scheme.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmcLayer {
    /// Zero-based layer index (0 = outermost decrypt, last = innermost payload).
    pub index: u32,
    /// Algorithm used to decrypt this layer.
    pub algorithm: SmcAlgorithm,
    /// Key material for this layer.
    pub key: SmcKey,
    /// Address range of the encrypted/decrypted region.
    pub region: SmcRegion,
    /// Plaintext bytes revealed after this layer is peeled off.
    pub revealed_bytes: Vec<u8>,
    /// Whether the original bytes were re-encrypted after execution (re-encrypt pattern).
    pub re_encrypted: bool,
}

impl SmcLayer {
    /// Estimate the real payload by applying the inverse transform locally.
    #[must_use]
    pub fn apply_inverse(&self, ciphertext: &[u8]) -> Vec<u8> {
        match (&self.algorithm, &self.key) {
            (SmcAlgorithm::Xor, SmcKey::Constant(k)) => {
                let kb = u8::try_from(*k & 0xFF).unwrap_or(0);
                ciphertext.iter().map(|b| b ^ kb).collect()
            }
            (SmcAlgorithm::Add, SmcKey::Constant(k)) => {
                let kb = u8::try_from(*k & 0xFF).unwrap_or(0);
                ciphertext.iter().map(|b| b.wrapping_sub(kb)).collect()
            }
            (SmcAlgorithm::Sub, SmcKey::Constant(k)) => {
                let kb = u8::try_from(*k & 0xFF).unwrap_or(0);
                ciphertext.iter().map(|b| b.wrapping_add(kb)).collect()
            }
            (SmcAlgorithm::Rol, SmcKey::Constant(k)) => {
                let bits = u32::try_from(*k & 7).unwrap_or(0);
                ciphertext.iter().map(|b| b.rotate_right(bits)).collect()
            }
            (SmcAlgorithm::Ror, SmcKey::Constant(k)) => {
                let bits = u32::try_from(*k & 7).unwrap_or(0);
                ciphertext.iter().map(|b| b.rotate_left(bits)).collect()
            }
            (SmcAlgorithm::XorRolling, SmcKey::Constant(k)) => {
                let mut key = u8::try_from(*k & 0xFF).unwrap_or(0);
                let mut out = Vec::with_capacity(ciphertext.len());
                for &b in ciphertext {
                    let plain = b ^ key;
                    key = b; // rolling: next key is ciphertext byte
                    out.push(plain);
                }
                out
            }
            _ => ciphertext.to_vec(), // unknown / derived — return as-is
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReconstructionConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the SMC reconstruction engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructionConfig {
    /// Maximum number of decrypt layers to peel.
    pub max_layers: u32,
    /// Maximum emulation steps per layer.
    pub max_steps: u64,
    /// Minimum entropy drop that signals a successful decrypt (bits/byte).
    pub entropy_drop_threshold: f64,
    /// Whether to record every write individually (expensive but precise).
    pub record_all_writes: bool,
    /// Minimum number of bytes changed per snapshot to keep it.
    pub min_delta_bytes: usize,
    /// If true, attempt re-encryption detection (exec→re-encrypt pattern).
    pub detect_re_encrypt: bool,
}

impl Default for ReconstructionConfig {
    fn default() -> Self {
        Self {
            max_layers: 4,
            max_steps: 2_000_000,
            entropy_drop_threshold: 1.5,
            record_all_writes: false,
            min_delta_bytes: 4,
            detect_re_encrypt: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WriteEvent
// ─────────────────────────────────────────────────────────────────────────────

/// A single memory-write event observed during emulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteEvent {
    /// Emulation tick.
    pub tick: u64,
    /// Program counter at the time of the write.
    pub pc: u64,
    /// Destination virtual address.
    pub dest: u64,
    /// Bytes written.
    pub bytes: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcReconstructor
// ─────────────────────────────────────────────────────────────────────────────

/// Engine that drives multi-layer SMC reconstruction.
///
/// The reconstructor works in simulation: it applies the detected algorithm
/// iteratively to the encrypted region and records snapshots at each stage.
pub struct SmcReconstructor {
    config: ReconstructionConfig,
    /// All write events captured (gated by `record_all_writes`).
    write_log: Vec<WriteEvent>,
    /// Snapshots indexed by tick.
    snapshots: BTreeMap<u64, MemorySnapshot>,
    /// Layers peeled so far.
    layers: Vec<SmcLayer>,
    /// Current (working) state of the target region bytes.
    region_state: Vec<u8>,
    /// Virtual base address of the working region.
    region_base: u64,
}

impl SmcReconstructor {
    /// Create a new reconstructor for the given initial (encrypted) bytes.
    #[must_use]
    pub const fn new(config: ReconstructionConfig, base_addr: u64, encrypted: Vec<u8>) -> Self {
        Self {
            config,
            write_log: Vec::new(),
            snapshots: BTreeMap::new(),
            layers: Vec::new(),
            region_state: encrypted,
            region_base: base_addr,
        }
    }

    /// Default constructor using [`ReconstructionConfig::default`].
    #[must_use]
    pub fn with_defaults(base_addr: u64, encrypted: Vec<u8>) -> Self {
        Self::new(ReconstructionConfig::default(), base_addr, encrypted)
    }

    // ── Snapshot helpers ────────────────────────────────────────────────────

    fn take_snapshot(&self, tick: u64) -> MemorySnapshot {
        let prev_entropy = if let Some((_, prev)) = self.snapshots.iter().next_back() {
            // rough delta ratio
            let diff = prev
                .bytes
                .iter()
                .zip(self.region_state.iter())
                .filter(|(a, b)| a != b)
                .count();
            f32::from(u16::try_from(diff).unwrap_or(u16::MAX)) / f32::from(u16::try_from(prev.bytes.len().max(1)).unwrap_or(u16::MAX))
        } else {
            1.0
        };

        
        MemorySnapshot {
            tick,
            base_addr: self.region_base,
            bytes: self.region_state.clone(),
            delta_ratio: prev_entropy,
            looks_executable: self.looks_executable(),
        }
    }

    fn looks_executable(&self) -> bool {
        if self.region_state.len() < 4 {
            return false;
        }
        // Basic heuristic: low entropy (<6) + common prologue bytes
        let e = {
            let mut freq = [0u64; 256];
            for &b in &self.region_state {
                freq[usize::from(b)] += 1;
            }
            let n = f64::from(u32::try_from(self.region_state.len()).unwrap_or(u32::MAX));
            freq.iter()
                .filter(|&&c| c > 0)
                .map(|&c| {
                    let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / n;
                    -p * p.log2()
                })
                .sum::<f64>()
        };
        e < 6.5
    }

    /// Record a write event from the emulation layer.
    pub fn record_write(&mut self, event: WriteEvent) {
        let offset = usize::try_from(event.dest.wrapping_sub(self.region_base)).unwrap_or(usize::MAX);
        if offset < self.region_state.len() {
            let end = (offset + event.bytes.len()).min(self.region_state.len());
            let len = end - offset;
            self.region_state[offset..end].copy_from_slice(&event.bytes[..len]);
        }
        if self.config.record_all_writes {
            self.write_log.push(event);
        }
    }

    /// Commit a snapshot at the given tick (call after a batch of writes).
    pub fn commit_snapshot(&mut self, tick: u64) {
        let snap = self.take_snapshot(tick);
        self.snapshots.insert(tick, snap);
    }

    // ── Layer peeling ───────────────────────────────────────────────────────

    /// Apply one decryption layer statically using the provided algorithm + key.
    ///
    /// Returns `true` if the entropy dropped by at least `config.entropy_drop_threshold`.
    pub fn peel_layer(&mut self, algorithm: SmcAlgorithm, key: SmcKey, region: SmcRegion) -> bool {
        let before_entropy = self.snapshot_entropy();
        let layer_idx = u32::try_from(self.layers.len()).unwrap_or(u32::MAX);

        let candidate = {
            let layer = SmcLayer {
                index: layer_idx,
                algorithm: algorithm.clone(),
                key: key.clone(),
                region: region.clone(),
                revealed_bytes: vec![],
                re_encrypted: false,
            };
            layer.apply_inverse(&self.region_state)
        };

        let after_entropy = {
            let mut freq = [0u64; 256];
            for &b in &candidate {
                freq[usize::from(b)] += 1;
            }
            let n = f64::from(u32::try_from(candidate.len()).unwrap_or(u32::MAX));
            freq.iter()
                .filter(|&&c| c > 0)
                .map(|&c| {
                    let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / n;
                    -p * p.log2()
                })
                .sum::<f64>()
        };

        let drop = before_entropy - after_entropy;
        if drop >= self.config.entropy_drop_threshold || after_entropy < 5.5 {
            let layer = SmcLayer {
                index: layer_idx,
                algorithm,
                key,
                region,
                revealed_bytes: candidate.clone(),
                re_encrypted: false,
            };
            self.layers.push(layer);
            self.region_state = candidate;
            true
        } else {
            false
        }
    }

    fn snapshot_entropy(&self) -> f64 {
        if self.region_state.is_empty() {
            return 0.0;
        }
        let mut freq = [0u64; 256];
        for &b in &self.region_state {
            freq[usize::from(b)] += 1;
        }
        let n = f64::from(u32::try_from(self.region_state.len()).unwrap_or(u32::MAX));
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / n;
                -p * p.log2()
            })
            .sum()
    }

    // ── Re-encryption detection ─────────────────────────────────────────────

    /// Detect whether the code was re-encrypted after execution.
    ///
    /// Strategy: compare the first snapshot with the last snapshot; if
    /// the last snapshot entropy is *higher* than the first, re-encryption
    /// is suspected.
    #[must_use]
    pub fn detect_re_encryption(&self) -> bool {
        if !self.config.detect_re_encrypt {
            return false;
        }
        let mut iter = self.snapshots.values();
        let first = match iter.next() {
            Some(s) => s.entropy(),
            None => return false,
        };
        let last = match self.snapshots.values().last() {
            Some(s) => s.entropy(),
            None => return false,
        };
        last > first + 1.0
    }

    // ── Fragment assembly ───────────────────────────────────────────────────

    /// Assemble final code from all revealed layer bytes and snapshot deltas.
    ///
    /// Produces a list of [`CodeFragment`]s, one per recovered contiguous region.
    #[must_use]
    pub fn assemble_fragments(&self) -> Vec<CodeFragment> {
        if self.layers.is_empty() {
            // Fall back: take the current state as a single fragment
            return vec![CodeFragment {
                start_addr: self.region_base,
                bytes: self.region_state.clone(),
                source_tick: 0,
                layer: 0,
                confidence: 0.5,
            }];
        }

        let mut fragments = Vec::new();
        for layer in &self.layers {
            if layer.revealed_bytes.is_empty() {
                continue;
            }
            fragments.push(CodeFragment {
                start_addr: layer.region.start,
                bytes: layer.revealed_bytes.clone(),
                source_tick: 0,
                layer: layer.index,
                confidence: if layer.re_encrypted { 0.7 } else { 0.9 },
            });
        }

        // Merge adjacent fragments from the same layer.
        fragments.sort_by_key(|f| (f.layer, f.start_addr));
        let mut merged: Vec<CodeFragment> = Vec::new();
        for frag in fragments {
            if let Some(last) = merged.last_mut()
                && last.layer == frag.layer
                    && last.start_addr + u64::try_from(last.bytes.len()).unwrap_or(u64::MAX) == frag.start_addr
                {
                    last.bytes.extend_from_slice(&frag.bytes);
                    last.confidence = last.confidence.min(frag.confidence);
                    continue;
                }
            merged.push(frag);
        }
        merged
    }

    // ── Reconstruction report ───────────────────────────────────────────────

    /// Return a full reconstruction report.
    #[must_use]
    pub fn report(&self) -> ReconstructionReport {
        ReconstructionReport {
            layers_peeled: u32::try_from(self.layers.len()).unwrap_or(u32::MAX),
            total_writes: self.write_log.len(),
            snapshot_count: self.snapshots.len(),
            re_encryption_detected: self.detect_re_encryption(),
            fragments: self.assemble_fragments(),
            layers: self.layers.clone(),
            final_entropy: self.snapshot_entropy(),
        }
    }

    /// Convenience: access the current (possibly decrypted) bytes.
    #[must_use]
    pub fn current_bytes(&self) -> &[u8] {
        &self.region_state
    }

    /// Access the write log (only populated when `record_all_writes` is set).
    #[must_use]
    pub fn write_log(&self) -> &[WriteEvent] {
        &self.write_log
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReconstructionReport
// ─────────────────────────────────────────────────────────────────────────────

/// Summary of a complete SMC reconstruction run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructionReport {
    /// Total number of decrypt layers peeled.
    pub layers_peeled: u32,
    /// Total number of individual write events logged.
    pub total_writes: usize,
    /// Number of memory snapshots taken during emulation.
    pub snapshot_count: usize,
    /// Whether re-encryption was detected.
    pub re_encryption_detected: bool,
    /// Final assembled code fragments.
    pub fragments: Vec<CodeFragment>,
    /// Detailed per-layer information.
    pub layers: Vec<SmcLayer>,
    /// Shannon entropy of the final recovered bytes.
    pub final_entropy: f64,
}

impl ReconstructionReport {
    /// Whether the reconstruction appears complete (all layers peeled, low entropy).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.final_entropy < 6.0 && self.layers_peeled > 0
    }

    /// Total bytes recovered across all fragments.
    #[must_use]
    pub fn total_bytes_recovered(&self) -> usize {
        self.fragments.iter().map(|f| f.bytes.len()).sum()
    }

    /// Human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "SMC Reconstruction: {} layer(s) peeled, {} fragment(s) recovered \
             ({} bytes total), final entropy {:.2} bits/byte, re-encrypt={}",
            self.layers_peeled,
            self.fragments.len(),
            self.total_bytes_recovered(),
            self.final_entropy,
            self.re_encryption_detected
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopBoundAnalysis
// ─────────────────────────────────────────────────────────────────────────────

/// Analyzes a suspected decrypt loop to estimate iteration count and stride.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopBoundAnalysis {
    /// Estimated number of iterations.
    pub iterations: u64,
    /// Memory stride per iteration (bytes advanced per loop body execution).
    pub stride: u64,
    /// Detected loop counter register name, if any.
    pub counter_register: Option<String>,
    /// Whether the bound is statically determined.
    pub is_static: bool,
    /// Upper bound for emulation steps needed.
    pub emulation_budget: u64,
}

impl LoopBoundAnalysis {
    /// Create from a region size and detected stride.
    #[must_use]
    pub fn from_region(region_size: u64, stride: u64) -> Self {
        let stride = stride.max(1);
        let iterations = region_size.div_ceil(stride);
        Self {
            iterations,
            stride,
            counter_register: None,
            is_static: true,
            emulation_budget: iterations.saturating_mul(8), // ~8 insns/iteration
        }
    }

    /// Mark the loop bound as dynamically determined.
    #[must_use]
    pub const fn dynamic(mut self) -> Self {
        self.is_static = false;
        self.emulation_budget = self.emulation_budget.saturating_mul(4);
        self
    }

    /// Attach a counter register name.
    #[must_use]
    pub fn with_register(mut self, reg: impl Into<String>) -> Self {
        self.counter_register = Some(reg.into());
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TaintTracker
// ─────────────────────────────────────────────────────────────────────────────

/// Simple write-taint tracker for .text / executable regions.
///
/// Records which addresses in a code segment have been written by the SMC
/// decryptor, allowing the reconstructor to know exactly which bytes changed.
#[derive(Debug, Default)]
pub struct TaintTracker {
    /// Set of virtual addresses that have been written by SMC code.
    tainted: HashMap<u64, u8>,
}

impl TaintTracker {
    /// Mark a range as tainted with the given byte values.
    pub fn taint_range(&mut self, base: u64, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            self.tainted.insert(base + u64::try_from(i).unwrap_or(u64::MAX), b);
        }
    }

    /// Return `true` if the address has been written at least once.
    #[must_use]
    pub fn is_tainted(&self, addr: u64) -> bool {
        self.tainted.contains_key(&addr)
    }

    /// Number of unique tainted addresses.
    #[must_use]
    pub fn tainted_count(&self) -> usize {
        self.tainted.len()
    }

    /// Collect tainted ranges as contiguous slices `(base, bytes)`.
    #[must_use]
    pub fn contiguous_ranges(&self) -> Vec<(u64, Vec<u8>)> {
        if self.tainted.is_empty() {
            return vec![];
        }
        let mut sorted: Vec<(u64, u8)> = self.tainted.iter().map(|(&a, &b)| (a, b)).collect();
        sorted.sort_by_key(|(a, _)| *a);

        let mut ranges: Vec<(u64, Vec<u8>)> = Vec::new();
        for (addr, byte) in sorted {
            if let Some(last) = ranges.last_mut()
                && last.0 + u64::try_from(last.1.len()).unwrap_or(u64::MAX) == addr {
                    last.1.push(byte);
                    continue;
                }
            ranges.push((addr, vec![byte]));
        }
        ranges
    }

    /// Clear all taint state.
    pub fn clear(&mut self) {
        self.tainted.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_inverse() {
        let key = SmcKey::Constant(0x42);
        let algo = SmcAlgorithm::Xor;
        let region = SmcRegion {
            start: 0x1000,
            end: 0x1004,
            decryptor_addr: 0,
            algorithm: SmcAlgorithm::Xor,
            key: SmcKey::Constant(0x42),
        };
        let layer = SmcLayer {
            index: 0,
            algorithm: algo,
            key,
            region,
            revealed_bytes: vec![],
            re_encrypted: false,
        };
        let ct = vec![0x42u8, 0x00, 0xFF, 0xAB];
        let pt = layer.apply_inverse(&ct);
        // XOR is self-inverse
        assert_eq!(pt, vec![0x00, 0x42, 0xBD, 0xE9]);
    }

    #[test]
    fn test_taint_tracker_ranges() {
        let mut t = TaintTracker::default();
        t.taint_range(0x1000, &[0xAA, 0xBB, 0xCC]);
        t.taint_range(0x1003, &[0xDD]);
        let ranges = t.contiguous_ranges();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].1, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_loop_bound_analysis() {
        let lba = LoopBoundAnalysis::from_region(1024, 1);
        assert_eq!(lba.iterations, 1024);
        assert_eq!(lba.emulation_budget, 8192);
    }

    #[test]
    fn test_reconstructor_peel_xor() {
        let plaintext = b"Hello, World!!! ";
        let key = 0x5Eu8;
        let ciphertext: Vec<u8> = plaintext.iter().map(|b| b ^ key).collect();

        let mut rec = SmcReconstructor::with_defaults(0x0040_1000, ciphertext);
        let region = SmcRegion {
            start: 0x0040_1000,
            end: 0x0040_1000 + u64::try_from(plaintext.len()).unwrap_or(u64::MAX),
            decryptor_addr: 0,
            algorithm: SmcAlgorithm::Xor,
            key: SmcKey::Constant(u64::from(key)),
        };
        let peeled = rec.peel_layer(SmcAlgorithm::Xor, SmcKey::Constant(u64::from(key)), region);
        assert!(peeled, "XOR peel should succeed (entropy should drop)");
        assert_eq!(rec.current_bytes(), plaintext.as_ref());
    }
}
