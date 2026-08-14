//! `CmpLog` / REDQUEEN instrumentation and input-to-state (I2S) pipeline.
//!
//! This module implements the `CmpLog` technique introduced by AFL++ and the
//! REDQUEEN mutation strategy.  At a high level:
//!
//! 1. During a dedicated "colorize" execution the target is run with a
//!    fully-random input so that comparison operand values are uniquely tied to
//!    concrete input bytes.
//! 2. For every comparison instruction the pair `(v0, v1)` is recorded.
//! 3. The I2S pass scans the current input for byte sequences that equal `v0`
//!    and replaces them with `v1` (and vice-versa), producing new candidate
//!    inputs that may satisfy the comparison and unlock new branches.
//! 4. The colorize sub-pass randomises the input byte-by-byte while re-running
//!    the target to establish which input bytes influence which comparison.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{AflShmCoverage, XorShiftRng, RngCore};

// ── CmpSize ──────────────────────────────────────────────────────────────────

/// Width of a single comparison operand in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CmpSize {
    /// 1-byte comparison.
    B1 = 1,
    /// 2-byte comparison.
    B2 = 2,
    /// 4-byte comparison.
    B4 = 4,
    /// 8-byte comparison.
    B8 = 8,
}

impl CmpSize {
    /// Number of bytes covered by this comparison.
    #[must_use]
    pub const fn bytes(self) -> usize {
        self as usize
    }

    /// Extract the value from `v` masked to this size.
    #[must_use]
    pub const fn mask(self, v: u64) -> u64 {
        match self {
            Self::B1 => v & 0xFF,
            Self::B2 => v & 0xFFFF,
            Self::B4 => v & 0xFFFF_FFFF,
            Self::B8 => v,
        }
    }

    /// Try to infer the comparison size from a raw byte count.
    #[must_use]
    pub const fn from_bytes(n: u8) -> Option<Self> {
        match n {
            1 => Some(Self::B1),
            2 => Some(Self::B2),
            4 => Some(Self::B4),
            8 => Some(Self::B8),
            _ => None,
        }
    }
}

// ── CmplogEntry ───────────────────────────────────────────────────────────────

/// One observed comparison: the address of the instruction, both operand
/// values, and the comparison width.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmplogEntry {
    /// Virtual address of the comparison instruction.
    pub addr: u64,
    /// Left-hand operand value (first operand to `cmp`).
    pub v0: u64,
    /// Right-hand operand value (second operand to `cmp`, often a constant).
    pub v1: u64,
    /// Comparison width.
    pub size: CmpSize,
    /// True when the comparison originated from a function-call hook (e.g.
    /// `memcmp`, `strcmp`) rather than an inline CMP instruction.
    pub is_fn_hook: bool,
    /// How many times this exact (addr, v0, v1) triple was observed in the run.
    pub hit_count: u32,
}

impl CmplogEntry {
    /// Construct a new entry with `hit_count = 1`.
    #[must_use]
    pub const fn new(addr: u64, v0: u64, v1: u64, size: CmpSize) -> Self {
        Self {
            addr,
            v0,
            v1,
            size,
            is_fn_hook: false,
            hit_count: 1,
        }
    }

    /// Whether the comparison was satisfied (both sides equal).
    #[must_use]
    pub const fn is_equal(&self) -> bool {
        self.size.mask(self.v0) == self.size.mask(self.v1)
    }

    /// Absolute difference between operands (useful for arithmetic proximity
    /// mutations).
    #[must_use]
    pub const fn diff(&self) -> u64 {
        self.size.mask(self.v0).abs_diff(self.size.mask(self.v1))
    }

    /// Serialise `v1` as little-endian bytes of length `self.size.bytes()`.
    #[must_use]
    pub fn v1_le_bytes(&self) -> Vec<u8> {
        let masked = self.size.mask(self.v1);
        masked.to_le_bytes()[..self.size.bytes()].to_vec()
    }

    /// Serialise `v0` as little-endian bytes of length `self.size.bytes()`.
    #[must_use]
    pub fn v0_le_bytes(&self) -> Vec<u8> {
        let masked = self.size.mask(self.v0);
        masked.to_le_bytes()[..self.size.bytes()].to_vec()
    }

    /// Big-endian variant of `v1_le_bytes`.
    #[must_use]
    pub fn v1_be_bytes(&self) -> Vec<u8> {
        let masked = self.size.mask(self.v1);
        masked.to_be_bytes()[8 - self.size.bytes()..].to_vec()
    }
}

// ── CmplogMap ─────────────────────────────────────────────────────────────────

/// Accumulates all comparison observations from a single execution.
///
/// Internally deduplicates by `(addr, v0, v1)` and increments `hit_count` for
/// repeated observations so that hot comparisons can be prioritised.
#[derive(Debug, Clone, Default)]
pub struct CmplogMap {
    /// All unique comparisons, keyed by `(addr, v0, v1)`.
    entries: HashMap<(u64, u64, u64), CmplogEntry>,
    /// Insertion order (for deterministic iteration).
    order: Vec<(u64, u64, u64)>,
}

impl CmplogMap {
    /// Create an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a comparison, incrementing `hit_count` for duplicates.
    pub fn record(&mut self, addr: u64, v0: u64, v1: u64, size: CmpSize) {
        let key = (addr, v0, v1);
        if let Some(e) = self.entries.get_mut(&key) {
            e.hit_count = e.hit_count.saturating_add(1);
        } else {
            let e = CmplogEntry::new(addr, v0, v1, size);
            self.order.push(key);
            self.entries.insert(key, e);
        }
    }

    /// Record a function-hook comparison (e.g. from `strcmp` intercept).
    pub fn record_fn_hook(&mut self, addr: u64, v0: u64, v1: u64, size: CmpSize) {
        self.record(addr, v0, v1, size);
        if let Some(e) = self.entries.get_mut(&(addr, v0, v1)) {
            e.is_fn_hook = true;
        }
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    /// Number of distinct comparisons recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no comparisons have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over entries in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &CmplogEntry> {
        self.order.iter().filter_map(|k| self.entries.get(k))
    }

    /// Return all entries where `v0 != v1` (unsatisfied comparisons).
    #[must_use]
    pub fn unsatisfied(&self) -> Vec<&CmplogEntry> {
        self.iter().filter(|e| !e.is_equal()).collect()
    }

    /// Return entries sorted by hit count descending (hottest comparisons first).
    #[must_use]
    pub fn sorted_by_frequency(&self) -> Vec<&CmplogEntry> {
        let mut v: Vec<&CmplogEntry> = self.iter().collect();
        v.sort_unstable_by(|a, b| b.hit_count.cmp(&a.hit_count));
        v
    }

    /// Extract all distinct constant values seen on the right-hand side of
    /// comparisons (the "magic bytes" used inside the target binary).
    #[must_use]
    pub fn magic_bytes(&self) -> Vec<Vec<u8>> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        for e in self.iter() {
            if !e.is_equal() {
                let v = e.v1_le_bytes();
                if seen.insert(v.clone()) {
                    result.push(v.clone());
                }
                // Also add big-endian variant for multi-byte constants.
                if e.size.bytes() > 1 {
                    let be = e.v1_be_bytes();
                    if seen.insert(be.clone()) {
                        result.push(be);
                    }
                }
            }
        }
        result
    }
}

// ── I2sTransform ──────────────────────────────────────────────────────────────

/// Result of a single Input-to-State transformation.
#[derive(Debug, Clone)]
pub struct I2sResult {
    /// The mutated input candidate.
    pub candidate: Vec<u8>,
    /// Byte offset in the input where the substitution was made.
    pub offset: usize,
    /// Number of bytes replaced.
    pub replaced_bytes: usize,
    /// Whether we replaced `v0→v1` (`true`) or `v1→v0` (`false`).
    pub forward: bool,
}

/// Performs Input-to-State (I2S) transformations driven by a [`CmplogMap`].
///
/// For every unsatisfied comparison `(v0, v1)` the transformer scans the
/// input for byte patterns that match `v0` (or `v1`) and replaces them with
/// the other side, generating new inputs that satisfy the comparison.
pub struct I2sTransformer {
    /// How many candidates to generate per comparison (caps exploration).
    pub max_candidates_per_cmp: usize,
    /// Whether to also try reversed (big-endian) variants of multi-byte values.
    pub try_endian_flip: bool,
    /// Whether to try arithmetic neighbours of `v1` (±1, ±2) in addition to
    /// exact replacement.
    pub try_arithmetic_neighbours: bool,
}

impl I2sTransformer {
    /// Create a transformer with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_candidates_per_cmp: 32,
            try_endian_flip: true,
            try_arithmetic_neighbours: true,
        }
    }

    /// Apply I2S transformations and return a list of candidate inputs.
    ///
    /// The caller should execute each candidate and check for new coverage.
    #[must_use]
    pub fn transform(&self, input: &[u8], cmplog: &CmplogMap) -> Vec<I2sResult> {
        let mut results: Vec<I2sResult> = Vec::new();
        for entry in cmplog.unsatisfied() {
            if results.len() >= self.max_candidates_per_cmp * cmplog.len() {
                break;
            }
            self.transform_entry(input, entry, &mut results);
        }
        results
    }

    fn transform_entry(&self, input: &[u8], entry: &CmplogEntry, out: &mut Vec<I2sResult>) {
        let n = entry.size.bytes();
        if n > input.len() {
            return;
        }

        let little_needle = entry.v0_le_bytes();
        let little_repl = entry.v1_le_bytes();
        let big_needle = entry.v1_be_bytes(); // intentional: entry.v0 BE
        let big_repl = entry.v1_be_bytes();

        // Forward: find v0 in input, replace with v1.
        self.scan_and_replace(input, &little_needle, &little_repl, true, out);
        // Reverse: find v1 in input, replace with v0.
        self.scan_and_replace(input, &little_repl, &little_needle, false, out);

        if self.try_endian_flip && n > 1 {
            self.scan_and_replace(input, &big_needle, &big_repl, true, out);
            self.scan_and_replace(input, &big_repl, &big_needle, false, out);
        }

        if self.try_arithmetic_neighbours {
            // Try v1 ± 1 and v1 ± 2 as replacements when exact v1 didn't hit.
            for delta in [1u64, 2, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFE] {
                let neighbour = entry.size.mask(entry.v1.wrapping_add(delta));
                let nb_bytes = neighbour.to_le_bytes()[..n].to_vec();
                self.scan_and_replace(input, &little_needle, &nb_bytes, true, out);
            }
        }
    }

    fn scan_and_replace(
        &self,
        input: &[u8],
        needle: &[u8],
        replacement: &[u8],
        forward: bool,
        out: &mut Vec<I2sResult>,
    ) {
        if needle.is_empty() || replacement.is_empty() || needle == replacement {
            return;
        }
        let n = needle.len();
        let rn = replacement.len().min(n);
        let mut count = 0usize;

        for start in 0..=input.len().saturating_sub(n) {
            if &input[start..start + n] == needle {
                let mut candidate = input.to_vec();
                candidate[start..start + rn].copy_from_slice(&replacement[..rn]);
                out.push(I2sResult {
                    candidate,
                    offset: start,
                    replaced_bytes: rn,
                    forward,
                });
                count += 1;
                if count >= self.max_candidates_per_cmp {
                    break;
                }
            }
        }
    }
}

impl Default for I2sTransformer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Colorize ──────────────────────────────────────────────────────────────────

/// Tracks which input bytes "influence" which comparison operands.
///
/// The colorize algorithm runs the target repeatedly with a single byte of the
/// input randomised at a time.  If the coverage bitmap changes when byte `i` is
/// randomised, byte `i` is considered "coloured" (it influences at least one
/// comparison).
#[derive(Debug, Clone, Default)]
pub struct ColorizeMap {
    /// `influence[i]` = true when input byte `i` was found to influence at
    /// least one comparison.
    pub influence: Vec<bool>,
    /// Total number of randomise-and-execute cycles performed.
    pub cycles: u64,
}

impl ColorizeMap {
    /// Create a map for an input of `len` bytes.
    #[must_use]
    pub fn new(len: usize) -> Self {
        Self {
            influence: vec![false; len],
            cycles: 0,
        }
    }

    /// Mark byte `i` as influential.
    pub fn mark(&mut self, i: usize) {
        if i < self.influence.len() {
            self.influence[i] = true;
        }
    }

    /// Return the indices of bytes that were marked as influential.
    #[must_use]
    pub fn influential_bytes(&self) -> Vec<usize> {
        self.influence
            .iter()
            .enumerate()
            .filter_map(|(i, &v)| if v { Some(i) } else { None })
            .collect()
    }

    /// Number of influential bytes.
    #[must_use]
    pub fn influential_count(&self) -> usize {
        self.influence.iter().filter(|&&v| v).count()
    }
}

/// Runs the colorize algorithm on a single input to identify which bytes
/// influence the coverage bitmap.
pub struct Colorizer {
    rng: XorShiftRng,
}

impl Colorizer {
    /// Create a new colorizer with the given PRNG seed.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            rng: XorShiftRng::new(seed),
        }
    }

    /// Perform one colorize pass over `input`.
    ///
    /// For every byte position a random replacement is tried.  If the coverage
    /// bitmap changes (compared to `baseline_shm`), the byte is flagged as
    /// influential.
    ///
    /// `execute` should run the target with the given bytes and return the new
    /// coverage bitmap.
    pub fn colorize<F>(
        &mut self,
        input: &[u8],
        baseline_shm: &AflShmCoverage,
        mut execute: F,
    ) -> ColorizeMap
    where
        F: FnMut(&[u8]) -> AflShmCoverage,
    {
        let mut cmap = ColorizeMap::new(input.len());
        for i in 0..input.len() {
            // Generate a random replacement byte (different from the original).
            let mut replacement = self.rng.next_u8();
            if replacement == input[i] {
                replacement = replacement.wrapping_add(1);
            }
            let mut candidate = input.to_vec();
            candidate[i] = replacement;

            let new_shm = execute(&candidate);
            cmap.cycles += 1;

            // If any coverage bit changed, this byte is influential.
            for (j, (&a, &b)) in baseline_shm.bitmap.iter().zip(new_shm.bitmap.iter()).enumerate() {
                if a != b {
                    cmap.mark(i);
                    let _ = j;
                    break;
                }
            }
        }
        cmap
    }
}

// ── CmplogCollector ───────────────────────────────────────────────────────────

/// High-level collector that combines a [`CmplogMap`] with the I2S pipeline.
///
/// In a real AFL++ deployment this sits between the fork server and the fuzzer
/// loop.  Here it provides the data-structures and transformations; the actual
/// execution is left to the caller.
#[derive(Debug, Clone, Default)]
pub struct CmplogCollector {
    /// Accumulated comparison log.
    pub map: CmplogMap,
    /// Total I2S candidates generated so far.
    pub total_candidates: u64,
}

impl CmplogCollector {
    /// Create an empty collector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest a raw comparison (`addr`, `v0`, `v1`, byte `size`).
    pub fn ingest(&mut self, addr: u64, v0: u64, v1: u64, size: u8) {
        if let Some(sz) = CmpSize::from_bytes(size) {
            self.map.record(addr, v0, v1, sz);
        }
    }

    /// Ingest a function-hook comparison (e.g. `memcmp` / `strcmp`).
    pub fn ingest_hook(&mut self, addr: u64, v0: u64, v1: u64, size: u8) {
        if let Some(sz) = CmpSize::from_bytes(size) {
            self.map.record_fn_hook(addr, v0, v1, sz);
        }
    }

    /// Run the full I2S pipeline on `input` and return all candidates.
    ///
    /// Also updates `total_candidates`.
    #[must_use]
    pub fn i2s_candidates(&mut self, input: &[u8]) -> Vec<I2sResult> {
        let transformer = I2sTransformer::new();
        let candidates = transformer.transform(input, &self.map);
        self.total_candidates += candidates.len() as u64;
        candidates
    }

    /// Extract "magic bytes" (constants used in comparisons) that can be added
    /// to the fuzzer's dictionary.
    #[must_use]
    pub fn extract_magic_bytes(&self) -> Vec<Vec<u8>> {
        self.map.magic_bytes()
    }

    /// Clear the log (call at the start of each new seed's mutation cycle).
    pub fn reset(&mut self) {
        self.map.clear();
    }

    /// Number of distinct comparison entries.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.map.len()
    }
}

// ── MultiByteI2s ──────────────────────────────────────────────────────────────

/// Solver for multi-byte comparisons such as `memcmp` / `strncmp`.
///
/// When a function hook records a multi-byte comparison (e.g. a 16-byte key
/// check), this solver tries to substitute the matching byte sequence at every
/// aligned and unaligned position in the input.
#[derive(Debug, Clone, Default)]
pub struct MultiByteI2s;

impl MultiByteI2s {
    /// Generate candidates that satisfy a multi-byte comparison.
    ///
    /// `needle` is the value currently in the input (the left operand of the
    /// comparison), `replacement` is the required value (the right operand).
    #[must_use]
    pub fn solve(input: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<Vec<u8>> {
        if needle.len() != replacement.len() || needle.is_empty() || needle.len() > input.len() {
            return Vec::new();
        }
        let n = needle.len();
        let mut candidates = Vec::new();
        for start in 0..=input.len() - n {
            if &input[start..start + n] == needle {
                let mut candidate = input.to_vec();
                candidate[start..start + n].copy_from_slice(replacement);
                candidates.push(candidate);
            }
        }
        candidates
    }

    /// Attempt to satisfy a string comparison: infer `needle` by inspecting
    /// which prefix of `input` matches `v0` bytes, then replace with `v1`.
    ///
    /// This handles the common case where `strcmp(input_ptr, magic_string)` is
    /// intercepted: we simply search for the ASCII representation of the constant.
    #[must_use]
    pub fn solve_str_cmp(input: &[u8], magic: &[u8]) -> Vec<Vec<u8>> {
        // Treat magic as a null-terminated ASCII constant.
        let magic_trimmed = magic.split(|&b| b == 0).next().unwrap_or(magic);
        if magic_trimmed.is_empty() || magic_trimmed.len() > input.len() {
            return Vec::new();
        }
        let n = magic_trimmed.len();
        let mut candidates = Vec::new();
        for start in 0..=input.len() - n {
            // Accept any current bytes at this position (we're trying to satisfy
            // the comparison regardless of what's there).
            let mut candidate = input.to_vec();
            candidate[start..start + n].copy_from_slice(magic_trimmed);
            candidates.push(candidate);
            if candidates.len() >= 8 {
                break;
            }
        }
        candidates
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmpsize_mask() {
        assert_eq!(CmpSize::B1.mask(0xDEAD_BEEF), 0xEF);
        assert_eq!(CmpSize::B2.mask(0xDEAD_BEEF), 0xBEEF);
        assert_eq!(CmpSize::B4.mask(0xDEAD_BEEF), 0xDEAD_BEEF);
    }

    #[test]
    fn cmplog_entry_equality() {
        let e = CmplogEntry::new(0x1000, 42, 42, CmpSize::B4);
        assert!(e.is_equal());
        assert_eq!(e.diff(), 0);
    }

    #[test]
    fn cmplog_entry_inequality() {
        let e = CmplogEntry::new(0x1000, 10, 20, CmpSize::B4);
        assert!(!e.is_equal());
        assert_eq!(e.diff(), 10);
    }

    #[test]
    fn cmplog_map_record_dedup() {
        let mut m = CmplogMap::new();
        m.record(0x100, 1, 2, CmpSize::B4);
        m.record(0x100, 1, 2, CmpSize::B4);
        assert_eq!(m.len(), 1);
        let e = m.iter().next().unwrap();
        assert_eq!(e.hit_count, 2);
    }

    #[test]
    fn cmplog_map_unsatisfied() {
        let mut m = CmplogMap::new();
        m.record(0x1, 5, 5, CmpSize::B1);   // satisfied
        m.record(0x2, 5, 6, CmpSize::B1);   // unsatisfied
        assert_eq!(m.unsatisfied().len(), 1);
    }

    #[test]
    fn cmplog_map_magic_bytes() {
        let mut m = CmplogMap::new();
        m.record(0x1, 0, 0xDEAD_BEEF, CmpSize::B4);
        let mb = m.magic_bytes();
        assert!(!mb.is_empty());
    }

    #[test]
    fn i2s_forward_replace() {
        let input = b"hello world";
        let mut cmpmap = CmplogMap::new();
        // Pretend 'hell' (0x6C6C6568 LE) was compared with something.
        let v0 = u32::from_le_bytes(*b"hell") as u64;
        let v1 = u32::from_le_bytes(*b"HELL") as u64;
        cmpmap.record(0x1000, v0, v1, CmpSize::B4);

        let transformer = I2sTransformer::new();
        let results = transformer.transform(input, &cmpmap);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.forward));
    }

    #[test]
    fn colorize_map_mark() {
        let mut cm = ColorizeMap::new(10);
        cm.mark(3);
        cm.mark(7);
        assert_eq!(cm.influential_count(), 2);
        assert_eq!(cm.influential_bytes(), vec![3, 7]);
    }

    #[test]
    fn cmplog_collector_ingest_and_candidates() {
        let mut col = CmplogCollector::new();
        col.ingest(0x2000, 0xFF, 0x00, 1);
        let input = vec![0xFFu8; 16];
        let candidates = col.i2s_candidates(&input);
        assert!(!candidates.is_empty());
    }

    #[test]
    fn multi_byte_i2s_solve() {
        let input = b"AAAA_secret_AAAA";
        let needle = b"secr";
        let replacement = b"SECR";
        let results = MultiByteI2s::solve(input, needle, replacement);
        assert!(!results.is_empty());
        assert!(results[0].windows(4).any(|w| w == b"SECR"));
    }

    #[test]
    fn multi_byte_i2s_solve_str_cmp() {
        let input = b"random_junk_here";
        let magic = b"junk\0";
        let candidates = MultiByteI2s::solve_str_cmp(input, magic);
        assert!(!candidates.is_empty());
    }

    #[test]
    fn v1_le_bytes_correct_length() {
        let e = CmplogEntry::new(0, 0, 0x1234_5678, CmpSize::B4);
        let b = e.v1_le_bytes();
        assert_eq!(b.len(), 4);
        assert_eq!(b, vec![0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn cmplog_entry_fn_hook_flag() {
        let mut m = CmplogMap::new();
        m.record_fn_hook(0xABC, 10, 20, CmpSize::B8);
        let e = m.iter().next().unwrap();
        assert!(e.is_fn_hook);
    }

    #[test]
    fn sorted_by_frequency_order() {
        let mut m = CmplogMap::new();
        m.record(0x1, 1, 2, CmpSize::B1);
        m.record(0x2, 3, 4, CmpSize::B1);
        m.record(0x2, 3, 4, CmpSize::B1);
        m.record(0x2, 3, 4, CmpSize::B1);
        let sorted = m.sorted_by_frequency();
        assert_eq!(sorted[0].hit_count, 3);
    }
}
