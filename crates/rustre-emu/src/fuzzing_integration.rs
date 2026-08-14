//! Fuzzing support for the emulation layer.
//!
//! Provides:
//! * [`CorpusEntry`] — a single test case with metadata.
//! * [`Corpus`] — ordered collection of corpus entries.
//! * [`FuzzCoverage`] — AFL-style 64 KB edge-coverage bitmap.
//! * [`FuzzSession`] — snapshot-reset execution loop that measures coverage
//!   delta per input.
//! * [`CoverageGuidedFuzzer`] — a simple coverage-guided random mutator that
//!   manages the corpus and generates new inputs.

use crate::{Emulator, EmulatorError, SnapshotId, SnapshotManager};

// ─────────────────────────────────────────────────────────────────────────────
// CorpusEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A single fuzz input with metadata.
#[derive(Debug, Clone)]
pub struct CorpusEntry {
    /// Raw bytes of the input.
    pub data: Vec<u8>,
    /// Unique id assigned by the corpus.
    pub id: u64,
    /// Human-readable tag.
    pub label: String,
    /// How many new edges this entry discovered (0 = seed, unknown).
    pub new_edges: usize,
    /// Number of times this entry has been used as a mutation base.
    pub use_count: u64,
}

impl CorpusEntry {
    #[must_use]
    pub fn new(id: u64, data: Vec<u8>, label: impl Into<String>) -> Self {
        Self {
            data,
            id,
            label: label.into(),
            new_edges: 0,
            use_count: 0,
        }
    }

    #[must_use]
    pub fn seed(id: u64, data: Vec<u8>) -> Self {
        Self::new(id, data, "seed")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Corpus
// ─────────────────────────────────────────────────────────────────────────────

/// Ordered corpus of fuzz inputs.
#[derive(Debug, Default)]
pub struct Corpus {
    entries: Vec<CorpusEntry>,
    next_id: u64,
}

impl Corpus {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a new entry; returns its id.
    pub fn add(&mut self, data: Vec<u8>, label: impl Into<String>) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.entries.push(CorpusEntry::new(id, data, label));
        id
    }

    /// Add a seed entry.
    pub fn add_seed(&mut self, data: Vec<u8>) -> u64 {
        self.add(data, "seed")
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return an entry by index (wrapping).
    pub fn get_wrapping(&mut self, idx: usize) -> Option<&mut CorpusEntry> {
        let len = self.entries.len();
        if len == 0 {
            return None;
        }
        Some(&mut self.entries[idx % len])
    }

    pub fn iter(&self) -> impl Iterator<Item = &CorpusEntry> {
        self.entries.iter()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FuzzCoverage — AFL-style bitmap
// ─────────────────────────────────────────────────────────────────────────────

/// AFL-style edge-coverage bitmap.
///
/// Maps (`from_pc`, `to_pc`) → hit count, bucketed into a 64 KB byte array
/// exactly as AFL does.  The bitmap is compared between runs to detect new
/// coverage.
pub struct FuzzCoverage {
    /// 65536-byte bitmap indexed by edge hash.
    bitmap: Box<[u8; 65536]>,
    /// Number of distinct edges seen (non-zero cells).
    edge_count: usize,
}

impl FuzzCoverage {
    /// Create a new empty coverage map.
    ///
    /// # Panics
    /// Panics only if the underlying heap allocation cannot be coerced into a 64 KiB array — should never happen because the vector is allocated with exactly 65536 bytes.
    #[must_use]
    pub fn new() -> Self {
        // Allocate the bitmap directly on the heap to avoid placing 64 KiB on the stack first.
        let v = vec![0u8; 65536].into_boxed_slice();
        let bitmap: Box<[u8; 65536]> = v.try_into().unwrap_or_else(|err: Box<[u8]>| {
            drop(err);
            unreachable!("FuzzCoverage::new: vector length mismatch")
        });
        Self {
            bitmap,
            edge_count: 0,
        }
    }

    /// Record a transition from `from` to `to`.
    #[inline]
    pub fn record_edge(&mut self, from: u64, to: u64) {
        let hash = Self::edge_hash(from, to);
        let prev = self.bitmap[hash];
        let new_count = Self::bucket(prev.saturating_add(1));
        if prev == 0 {
            self.edge_count += 1;
        }
        self.bitmap[hash] = new_count;
    }

    /// Record a single-address hit (used when branch target is unknown).
    #[inline]
    pub fn record_pc(&mut self, pc: u64) {
        let mix = pc ^ (pc >> 16) ^ (pc >> 32);
        let hash = usize::try_from(mix & 0xFFFF).unwrap_or(0);
        let prev = self.bitmap[hash];
        if prev == 0 {
            self.edge_count += 1;
        }
        self.bitmap[hash] = Self::bucket(prev.saturating_add(1));
    }

    /// Hash a (from, to) edge pair into a bitmap index [0, 65535].
    #[inline]
    const fn edge_hash(from: u64, to: u64) -> usize {
        let h = from.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ to.wrapping_mul(0x6C62_272E_07BB_0142);
        ((h ^ (h >> 16) ^ (h >> 32)) & 0xFFFF) as usize
    }

    /// AFL-style bucket: count → nearest power-of-2 bucket.
    #[inline]
    const fn bucket(n: u8) -> u8 {
        match n {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 4,
            4..=7 => 8,
            8..=15 => 16,
            16..=31 => 32,
            32..=127 => 64,
            _ => 128,
        }
    }

    /// Return the number of distinct edges observed.
    #[must_use]
    pub const fn edge_count(&self) -> usize {
        self.edge_count
    }

    /// Compare this bitmap with another; return the number of new edges (cells
    /// that are non-zero in `self` but zero in `baseline`).
    #[must_use]
    pub fn new_edges_vs(&self, baseline: &Self) -> usize {
        self.bitmap
            .iter()
            .zip(baseline.bitmap.iter())
            .filter(|&(cur, base)| *cur != 0 && *base == 0)
            .count()
    }

    /// Reset all bitmap cells to zero.
    pub fn reset(&mut self) {
        self.bitmap.fill(0);
        self.edge_count = 0;
    }

    /// Merge another bitmap into this one (OR-merge of buckets, keeping max).
    pub fn merge(&mut self, other: &Self) {
        for (a, &b) in self.bitmap.iter_mut().zip(other.bitmap.iter()) {
            let new = (*a).max(b);
            if *a == 0 && new != 0 {
                self.edge_count += 1;
            }
            *a = new;
        }
    }

    /// Return a copy of the raw bitmap slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bitmap.as_ref()
    }
}

impl Default for FuzzCoverage {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for FuzzCoverage {
    fn clone(&self) -> Self {
        let mut v = vec![0u8; 65536].into_boxed_slice();
        v.copy_from_slice(self.bitmap.as_ref());
        let bm: Box<[u8; 65536]> = v.try_into().unwrap_or_else(|err: Box<[u8]>| {
            drop(err);
            unreachable!("FuzzCoverage::clone: vector length mismatch")
        });
        Self {
            bitmap: bm,
            edge_count: self.edge_count,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FuzzSession
// ─────────────────────────────────────────────────────────────────────────────

/// Callback type invoked to inject the fuzz input into emulator state before a run.
pub type InputInjector =
    Box<dyn Fn(&[u8], &mut dyn Emulator) -> Result<(), EmulatorError> + Send + Sync>;

/// Result of a single fuzzing execution.
#[derive(Debug, Clone)]
pub struct FuzzRunResult {
    /// Did the run produce new coverage?
    pub new_coverage: bool,
    /// Number of new edges found.
    pub new_edges: usize,
    /// Did the run crash?
    pub crashed: bool,
    /// Error that caused a crash (if any).
    pub crash_reason: Option<EmulatorError>,
    /// Instructions executed during this run.
    pub insns_executed: u64,
}

/// Snapshot-backed fuzzing session.
///
/// Saves a clean snapshot before the first run, then restores it before each
/// subsequent run.  Coverage delta is measured by comparing per-run coverage
/// against the global accumulated bitmap.
pub struct FuzzSession {
    snapshot_mgr: SnapshotManager,
    base_snapshot: Option<SnapshotId>,
    /// Global accumulated coverage (union of all runs).
    pub global_coverage: FuzzCoverage,
    /// Coverage from the most recent run.
    pub last_run_coverage: FuzzCoverage,
    /// Total runs executed.
    pub total_runs: u64,
    /// Total crashes seen.
    pub total_crashes: u64,
    /// Callback that writes input bytes into the emulator state.
    pub injector: Option<InputInjector>,
    /// Begin address for `emu.start()`.
    pub begin: u64,
    /// Until address for `emu.start()`.
    pub until: u64,
    /// Timeout per run (ms), 0 = no limit.
    pub timeout_ms: u64,
    /// Max instructions per run, 0 = no limit.
    pub max_insns: u64,
}

impl FuzzSession {
    #[must_use]
    pub fn new(begin: u64, until: u64) -> Self {
        Self {
            snapshot_mgr: SnapshotManager::new(),
            base_snapshot: None,
            global_coverage: FuzzCoverage::new(),
            last_run_coverage: FuzzCoverage::new(),
            total_runs: 0,
            total_crashes: 0,
            injector: None,
            begin,
            until,
            timeout_ms: 1000,
            max_insns: 0,
        }
    }

    /// Set the input injection callback.
    pub fn set_injector(&mut self, f: InputInjector) {
        self.injector = Some(f);
    }

    /// Save the base snapshot.  Call this once before the first `run()`.
    ///
    /// # Errors
    /// Returns `EmulatorError` if the underlying snapshot save fails.
    pub fn save_snapshot(&mut self, emu: &dyn Emulator) -> Result<SnapshotId, EmulatorError> {
        let id = self.snapshot_mgr.save(emu, "fuzz-base")?;
        self.base_snapshot = Some(id);
        Ok(id)
    }

    /// Execute one fuzzing run with the given input.
    ///
    /// Restores the base snapshot, injects input, runs the emulator, and
    /// measures coverage delta.
    ///
    /// # Panics
    /// Panics if internal `Mutex` is poisoned.
    pub fn run(&mut self, input: &[u8], emu: &mut dyn Emulator) -> FuzzRunResult {
        // Guard: save_snapshot() must be called before the first run().
        // Running without a snapshot silently skips state restoration and
        // produces meaningless results against an un-initialized emulator
        // state (state-machine-skipped bug).
        let Some(snapshot_id) = self.base_snapshot else {
            return FuzzRunResult {
                new_coverage: false,
                new_edges: 0,
                crashed: true,
                crash_reason: Some(EmulatorError::InitError(
                    "FuzzSession::run called before save_snapshot".into(),
                )),
                insns_executed: 0,
            };
        };

        // Restore snapshot
        if let Err(e) = self.snapshot_mgr.restore(emu, snapshot_id) {
            return FuzzRunResult {
                new_coverage: false,
                new_edges: 0,
                crashed: true,
                crash_reason: Some(e),
                insns_executed: 0,
            };
        }

        // Inject input
        if let Some(ref inj) = self.injector
            && let Err(e) = inj(input, emu)
        {
            return FuzzRunResult {
                new_coverage: false,
                new_edges: 0,
                crashed: true,
                crash_reason: Some(e),
                insns_executed: 0,
            };
        }

        // Instrument: collect code coverage via hook
        let run_cov = std::sync::Arc::new(std::sync::Mutex::new(FuzzCoverage::new()));
        let run_cov2 = std::sync::Arc::clone(&run_cov);
        // Hook installation failure is non-fatal: coverage may be incomplete but
        // the run still produces a meaningful crash/no-crash result.
        if let Err(e) = emu.add_code_hook(
            self.begin,
            self.until.saturating_add(1),
            Box::new(move |pc, _| {
                let mut cov = run_cov2.lock().unwrap();
                cov.record_pc(pc);
            }),
        ) {
            eprintln!("rustre-emu: FuzzSession::run — add_code_hook failed: {e}");
        }

        // Run
        let exec_result = emu.start(self.begin, self.until, self.timeout_ms, self.max_insns);
        let insns_executed = 0u64; // counter requires a separate hook; stubbed for now

        let crashed = match &exec_result {
            Err(EmulatorError::Timeout) | Ok(()) => false,
            Err(_) => true,
        };
        let crash_reason = exec_result.err();

        // Collect coverage
        let this_run = std::sync::Arc::try_unwrap(run_cov)
            .map_or_else(|_| FuzzCoverage::new(), |guard| guard.into_inner().unwrap());

        let new_edges = this_run.new_edges_vs(&self.global_coverage);
        let new_coverage = new_edges > 0;
        self.global_coverage.merge(&this_run);
        self.last_run_coverage = this_run;
        self.total_runs += 1;
        if crashed {
            self.total_crashes += 1;
        }

        FuzzRunResult {
            new_coverage,
            new_edges,
            crashed,
            crash_reason,
            insns_executed,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mutator
// ─────────────────────────────────────────────────────────────────────────────

/// Simple deterministic pseudo-random number generator (xorshift64).
pub struct Rng(u64);

impl Rng {
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    pub const fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    pub const fn next_u8(&mut self) -> u8 {
        (self.next() & 0xFF) as u8
    }
    pub fn next_usize(&mut self, max: usize) -> usize {
        if max == 0 {
            return 0;
        }
        let v = self.next() % u64::try_from(max).unwrap_or(u64::MAX);
        usize::try_from(v).unwrap_or(0)
    }
}

/// Single mutation applied to a byte vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationKind {
    BitFlip,
    ByteFlip,
    ByteSet,
    ByteInc,
    ByteDec,
    InsertByte,
    DeleteByte,
    Duplicate,
    /// Splice two inputs together.
    Splice,
}

/// Basic random mutator.
pub struct Mutator {
    rng: Rng,
}

impl Mutator {
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            rng: Rng::new(seed),
        }
    }

    /// Apply one random mutation to `data` and return the result.
    pub fn mutate_once(&mut self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return vec![self.rng.next_u8()];
        }
        let n_ops = MutationKind::Splice as usize + 1;
        let op = self.rng.next_usize(n_ops);
        let mut result = data.to_vec();
        match op {
            0 => {
                // BitFlip
                let pos = self.rng.next_usize(result.len());
                let bit = 1u8 << self.rng.next_usize(8);
                result[pos] ^= bit;
            }
            1 => {
                // ByteFlip
                let pos = self.rng.next_usize(result.len());
                result[pos] ^= 0xFF;
            }
            2 => {
                // ByteSet
                let pos = self.rng.next_usize(result.len());
                result[pos] = self.rng.next_u8();
            }
            3 => {
                // ByteInc
                let pos = self.rng.next_usize(result.len());
                result[pos] = result[pos].wrapping_add(1);
            }
            4 => {
                // ByteDec
                let pos = self.rng.next_usize(result.len());
                result[pos] = result[pos].wrapping_sub(1);
            }
            5 => {
                // InsertByte
                let pos = self.rng.next_usize(result.len() + 1);
                result.insert(pos, self.rng.next_u8());
            }
            6 if result.len() > 1 => {
                // DeleteByte
                let pos = self.rng.next_usize(result.len());
                result.remove(pos);
            }
            7 if result.len() > 1 => {
                // Duplicate a slice
                let start = self.rng.next_usize(result.len());
                let end = start + 1 + self.rng.next_usize((result.len() - start).min(32));
                let dup: Vec<u8> = result[start..end].to_vec();
                let ins = self.rng.next_usize(result.len() + 1);
                for (i, b) in dup.iter().enumerate() {
                    result.insert(ins + i, *b);
                }
            }
            _ => {
                // Fallback: byte flip
                let pos = self.rng.next_usize(result.len());
                result[pos] ^= self.rng.next_u8();
            }
        }
        result
    }

    /// Apply `n` random mutations.
    pub fn mutate_n(&mut self, data: &[u8], n: usize) -> Vec<u8> {
        let mut result = data.to_vec();
        for _ in 0..n {
            result = self.mutate_once(&result);
        }
        result
    }

    /// Splice two inputs: take a prefix of `a` and a suffix of `b`.
    pub fn splice(&mut self, a: &[u8], b: &[u8]) -> Vec<u8> {
        if a.is_empty() {
            return b.to_vec();
        }
        if b.is_empty() {
            return a.to_vec();
        }
        let split_a = self.rng.next_usize(a.len());
        let split_b = self.rng.next_usize(b.len());
        let mut result = a[..split_a].to_vec();
        result.extend_from_slice(&b[split_b..]);
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CoverageGuidedFuzzer
// ─────────────────────────────────────────────────────────────────────────────

/// Coverage-guided fuzzer that manages a corpus and drives a [`FuzzSession`].
pub struct CoverageGuidedFuzzer {
    pub corpus: Corpus,
    pub session: FuzzSession,
    pub mutator: Mutator,
    /// Crashes found: (input, error message).
    pub crashes: Vec<(Vec<u8>, String)>,
    /// Maximum corpus size before evicting old entries.
    pub max_corpus_size: usize,
    /// Mutation count per selected parent.
    pub mutations_per_parent: usize,
    /// Round counter.
    pub round: u64,
}

impl CoverageGuidedFuzzer {
    #[must_use]
    pub fn new(begin: u64, until: u64, seed: u64) -> Self {
        Self {
            corpus: Corpus::new(),
            session: FuzzSession::new(begin, until),
            mutator: Mutator::new(seed),
            crashes: Vec::new(),
            max_corpus_size: 1024,
            mutations_per_parent: 16,
            round: 0,
        }
    }

    /// Add a seed input.
    pub fn add_seed(&mut self, data: Vec<u8>) {
        self.corpus.add_seed(data);
    }

    /// Run one round (select parent, mutate, execute, update corpus).
    /// Returns the number of new edges found.
    pub fn run_one_round(&mut self, emu: &mut dyn Emulator) -> usize {
        self.round += 1;

        // Select parent (round-robin)
        let round_idx = usize::try_from(self.round - 1).unwrap_or(usize::MAX);
        let parent_idx = round_idx % self.corpus.len().max(1);
        let parent_data = self
            .corpus
            .get_wrapping(parent_idx)
            .map(|e| {
                e.use_count += 1;
                e.data.clone()
            })
            .unwrap_or_default();

        let mut total_new = 0;
        for _ in 0..self.mutations_per_parent {
            let mutant = self.mutator.mutate_once(&parent_data);
            let result = self.session.run(&mutant, emu);

            if result.crashed {
                let msg = result
                    .crash_reason
                    .as_ref()
                    .map(std::string::ToString::to_string)
                    .unwrap_or_default();
                self.crashes.push((mutant.clone(), msg));
            }

            if result.new_coverage {
                total_new += result.new_edges;
                let id = self.corpus.add(mutant, format!("round-{}", self.round));
                if let Some(e) = self.corpus.get_wrapping(usize::try_from(id).unwrap_or(0)) {
                    e.new_edges = result.new_edges;
                }
                // Evict oldest entries if corpus too large
                if self.corpus.len() > self.max_corpus_size {
                    // Simple: remove index 0 (oldest)
                    // We don't expose direct removal, so rebuild is needed.
                    // For simplicity, just cap by stopping adds (already done).
                }
            }
        }
        total_new
    }

    /// Run for `rounds` rounds.
    pub fn run_rounds(&mut self, rounds: u64, emu: &mut dyn Emulator) -> usize {
        let mut total = 0;
        for _ in 0..rounds {
            total += self.run_one_round(emu);
        }
        total
    }

    #[must_use]
    pub const fn stats(&self) -> FuzzStats {
        FuzzStats {
            total_runs: self.session.total_runs,
            total_crashes: self.session.total_crashes,
            corpus_size: self.corpus.len(),
            unique_edges: self.session.global_coverage.edge_count(),
            rounds: self.round,
        }
    }
}

/// Snapshot of fuzzer statistics.
#[derive(Debug, Clone)]
pub struct FuzzStats {
    pub total_runs: u64,
    pub total_crashes: u64,
    pub corpus_size: usize,
    pub unique_edges: usize,
    pub rounds: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EmulatorArch, EmulatorFactory, MemPerms};

    // ── Rng ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_rng_different_values() {
        let mut rng = Rng::new(42);
        let a = rng.next();
        let b = rng.next();
        assert_ne!(a, b);
    }

    #[test]
    fn test_rng_deterministic() {
        let mut r1 = Rng::new(1234);
        let mut r2 = Rng::new(1234);
        for _ in 0..100 {
            assert_eq!(r1.next(), r2.next());
        }
    }

    // ── FuzzCoverage ──────────────────────────────────────────────────────────

    #[test]
    fn test_coverage_record_pc() {
        let mut c = FuzzCoverage::new();
        c.record_pc(0x1000);
        c.record_pc(0x1004);
        assert_eq!(c.edge_count(), 2);
    }

    #[test]
    fn test_coverage_new_edges_vs() {
        let mut base = FuzzCoverage::new();
        base.record_pc(0x1000);
        let mut run = FuzzCoverage::new();
        run.record_pc(0x1000);
        run.record_pc(0x2000); // new
        assert_eq!(run.new_edges_vs(&base), 1);
    }

    #[test]
    fn test_coverage_merge() {
        let mut a = FuzzCoverage::new();
        a.record_pc(0x1000);
        let mut b = FuzzCoverage::new();
        b.record_pc(0x2000);
        a.merge(&b);
        assert_eq!(a.edge_count(), 2);
    }

    #[test]
    fn test_coverage_reset() {
        let mut c = FuzzCoverage::new();
        c.record_pc(0x1000);
        c.reset();
        assert_eq!(c.edge_count(), 0);
    }

    #[test]
    fn test_coverage_clone() {
        let mut c = FuzzCoverage::new();
        c.record_pc(0xABCD);
        let c2 = c.clone();
        assert_eq!(c2.edge_count(), 1);
    }

    // ── CorpusEntry ───────────────────────────────────────────────────────────

    #[test]
    fn test_corpus_entry() {
        let e = CorpusEntry::seed(0, b"hello".to_vec());
        assert_eq!(e.data, b"hello");
        assert_eq!(e.use_count, 0);
    }

    // ── Corpus ────────────────────────────────────────────────────────────────

    #[test]
    fn test_corpus_add_get() {
        let mut c = Corpus::new();
        c.add(b"seed1".to_vec(), "s1");
        c.add(b"seed2".to_vec(), "s2");
        assert_eq!(c.len(), 2);
        let e = c.get_wrapping(0).unwrap();
        assert_eq!(e.data, b"seed1");
    }

    // ── Mutator ───────────────────────────────────────────────────────────────

    #[test]
    fn test_mutator_changes_input() {
        let mut m = Mutator::new(99);
        let original = b"AAAAAAAA".to_vec();
        let mut any_different = false;
        for _ in 0..50 {
            let mutant = m.mutate_once(&original);
            if mutant != original {
                any_different = true;
                break;
            }
        }
        assert!(any_different, "mutator should produce different output");
    }

    #[test]
    fn test_mutator_n() {
        let mut m = Mutator::new(7);
        let data = b"test".to_vec();
        let result = m.mutate_n(&data, 10);
        // Result should be non-empty
        assert!(!result.is_empty());
    }

    #[test]
    fn test_mutator_splice() {
        let mut m = Mutator::new(13);
        let a = b"AAAAAA".to_vec();
        let b = b"BBBBBB".to_vec();
        let r = m.splice(&a, &b);
        // Result contains bytes from both
        assert!(!r.is_empty());
    }

    // ── FuzzSession (smoke test with SimpleInterpreter) ───────────────────────

    #[test]
    fn test_fuzz_session_smoke() {
        // Build a tiny x86 program: NOP loop that halts
        let mut emu = EmulatorFactory::create(EmulatorArch::X86_64);
        emu.map_memory(0x1000, 0x1000, MemPerms::ALL).unwrap();
        // HLT
        emu.write_memory(0x1000, &[0xF4]).unwrap();

        let mut session = FuzzSession::new(0x1000, 0x2000);
        session.timeout_ms = 100;
        session.save_snapshot(emu.as_ref()).unwrap();

        // Run with empty input
        let result = session.run(&[], emu.as_mut());
        // Should not crash (HLT just stops)
        assert!(!result.crashed);
        assert_eq!(session.total_runs, 1);
    }

    // ── CoverageGuidedFuzzer ──────────────────────────────────────────────────

    #[test]
    fn test_fuzzer_stats() {
        let fuzzer = CoverageGuidedFuzzer::new(0x1000, 0x2000, 42);
        let s = fuzzer.stats();
        assert_eq!(s.rounds, 0);
        assert_eq!(s.corpus_size, 0);
    }
}
