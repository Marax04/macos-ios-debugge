//! Coverage-guided fuzzing loop (AFL-style).
//!
//! Implements corpus management, energy scheduling, splice mutation,
//! calibration, trimming and a compact coverage map identical in spirit to
//! AFL's bitmap.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Size of the coverage bitmap in bytes (64 KB like AFL).
pub const MAP_SIZE: usize = 1 << 16;

/// Maximum number of calibration runs when adding a new corpus entry.
pub const CALIBRATION_RUNS: usize = 8;

/// Minimum length of a test-case after trimming.
pub const MIN_INPUT_LEN: usize = 1;

/// Maximum number of havoc mutations per energy unit.
pub const HAVOC_ROUNDS: usize = 128;

// ── CoverageMap ───────────────────────────────────────────────────────────────

/// Compact hit-count coverage bitmap (one byte per edge).
#[derive(Clone)]
pub struct CoverageMap {
    pub map: Box<[u8; MAP_SIZE]>,
}

/// Allocate a zero-initialised `Box<[u8; MAP_SIZE]>` on the heap directly,
/// avoiding the `large_stack_arrays` lint that `Box::new([0; N])` would trigger
/// (the array would be constructed on the stack before being boxed).
fn alloc_map_box() -> Box<[u8; MAP_SIZE]> {
    let v: Vec<u8> = vec![0; MAP_SIZE];
    let boxed: Box<[u8]> = v.into_boxed_slice();
    debug_assert_eq!(boxed.len(), MAP_SIZE);
    boxed.try_into().expect("vec is exactly MAP_SIZE bytes")
}

impl CoverageMap {
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: alloc_map_box(),
        }
    }

    /// Record an edge transition between `from` and `to`.
    #[inline]
    pub fn record(&mut self, from: usize, to: usize) {
        let idx = (from ^ to) & (MAP_SIZE - 1);
        self.map[idx] = self.map[idx].saturating_add(1);
    }

    /// Classify hit counts into AFL buckets (1,2,3,4-7,8-15,16-31,32-127,128+).
    #[must_use]
    pub fn bucketed(&self) -> Box<[u8; MAP_SIZE]> {
        let mut out = alloc_map_box();
        for (i, &v) in self.map.iter().enumerate() {
            out[i] = match v {
                0 => 0,
                1 => 1,
                2 => 2,
                3 => 4,
                4..=7 => 8,
                8..=15 => 16,
                16..=31 => 32,
                32..=127 => 64,
                _ => 128,
            };
        }
        out
    }

    /// Count how many edges have been touched.
    #[must_use] 
    pub fn edge_count(&self) -> usize {
        self.map.iter().filter(|&&b| b != 0).count()
    }

    /// Merge another map's bits into ours; return `true` if new edges were found.
    pub fn merge_new_bits(&mut self, other: &Self) -> bool {
        let mut new_bits = false;
        for (a, &b) in self.map.iter_mut().zip(other.map.iter()) {
            if b != 0 && *a == 0 {
                new_bits = true;
            }
            *a |= b;
        }
        new_bits
    }

    /// Return a bit-set of edge indices that are non-zero.
    #[must_use] 
    pub fn active_edges(&self) -> Vec<usize> {
        self.map
            .iter()
            .enumerate()
            .filter(|&(_, &b)| b != 0)
            .map(|(i, _)| i)
            .collect()
    }

    /// Jaccard similarity to another map (0.0..=1.0).
    #[must_use] 
    pub fn jaccard(&self, other: &Self) -> f64 {
        let mut inter = 0usize;
        let mut union_ = 0usize;
        for (&a, &b) in self.map.iter().zip(other.map.iter()) {
            let av = a != 0;
            let bv = b != 0;
            if av || bv {
                union_ += 1;
            }
            if av && bv {
                inter += 1;
            }
        }
        if union_ == 0 {
            1.0
        } else {
            crate::cast::usize_to_f64(inter) / crate::cast::usize_to_f64(union_)
        }
    }

    /// Clear the map.
    pub fn reset(&mut self) {
        self.map.iter_mut().for_each(|b| *b = 0);
    }

    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.map.iter().all(|&b| b == 0)
    }
}

impl Default for CoverageMap {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CoverageMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CoverageMap(edges={})", self.edge_count())
    }
}

// ── CorpusEntry ───────────────────────────────────────────────────────────────

/// Unique corpus identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CorpusId(pub u64);

/// Execution outcome for a single test case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecStatus {
    Ok,
    Crash(String),
    Timeout,
    OomKill,
}

/// A single entry in the fuzzing corpus.
#[derive(Debug, Clone)]
pub struct CorpusEntry {
    pub id: CorpusId,
    pub data: Vec<u8>,
    pub cov: CoverageMap,
    /// Bucketed edge set used for deduplication.
    pub unique_edges: Vec<usize>,
    /// Estimated execution time in microseconds.
    pub exec_us: u64,
    /// Number of times this entry has been chosen as a parent.
    pub fuzz_count: u64,
    /// Accumulated energy credits.
    pub energy: u64,
    /// Depth in the mutation chain.
    pub depth: u32,
    /// Whether this entry is favoured (minimal set).
    pub favoured: bool,
    pub status: ExecStatus,
    pub added_at: Instant,
}

impl CorpusEntry {
    #[must_use] 
    pub fn new(id: CorpusId, data: Vec<u8>, cov: CoverageMap, exec_us: u64) -> Self {
        let unique_edges = cov.active_edges();
        Self {
            id,
            data,
            cov,
            unique_edges,
            exec_us,
            fuzz_count: 0,
            energy: 0,
            depth: 0,
            favoured: false,
            status: ExecStatus::Ok,
            added_at: Instant::now(),
        }
    }

    /// Length of the underlying test case.
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// ── EnergyScheduler ───────────────────────────────────────────────────────────

/// AFL-style energy scheduling strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnergyPolicy {
    Fast,
    Explore,
    Exploit,
    Rare,
    Linear,
}

/// Computes fuzz energy for a corpus entry.
pub struct EnergyScheduler {
    policy: EnergyPolicy,
    avg_exec_us: f64,
    avg_depth: f64,
}

impl EnergyScheduler {
    #[must_use] 
    pub const fn new(policy: EnergyPolicy) -> Self {
        Self {
            policy,
            avg_exec_us: 1.0,
            avg_depth: 1.0,
        }
    }

    pub fn update_averages(&mut self, entries: &[CorpusEntry]) {
        if entries.is_empty() {
            return;
        }
        self.avg_exec_us = entries.iter().map(|e| crate::cast::u64_to_f64(e.exec_us)).sum::<f64>()
            / crate::cast::usize_to_f64(entries.len());
        self.avg_depth = entries.iter().map(|e| f64::from(e.depth)).sum::<f64>()
            / crate::cast::usize_to_f64(entries.len());
    }

    /// Assign energy credits to a corpus entry.
    pub fn assign_energy(&self, entry: &mut CorpusEntry, total_fuzz: u64) {
        let base = match self.policy {
            EnergyPolicy::Linear => 128u64,
            EnergyPolicy::Fast => {
                // Fast: penalise large + slow inputs, reward high-depth.
                let exec_factor = (self.avg_exec_us / crate::cast::u64_to_f64(entry.exec_us.max(1))).clamp(0.1, 4.0);
                let size_factor = (128.0 / crate::cast::usize_to_f64(entry.data.len().max(1))).clamp(0.1, 4.0);
                let depth_factor = (f64::from(entry.depth) / self.avg_depth.max(1.0)).clamp(0.1, 4.0);
                crate::cast::f64_to_u64(128.0 * exec_factor * size_factor * depth_factor)
            }
            EnergyPolicy::Explore => {
                // Explore: reward unique edge count.
                let edge_bonus = (crate::cast::usize_to_f64(entry.unique_edges.len()) / 10.0).clamp(1.0, 8.0);
                crate::cast::f64_to_u64(128.0 * edge_bonus)
            }
            EnergyPolicy::Exploit => {
                // Exploit: spend more on rarely fuzzed entries.
                let fuzz_ratio = if total_fuzz == 0 {
                    1.0
                } else {
                    1.0 - (crate::cast::u64_to_f64(entry.fuzz_count) / crate::cast::u64_to_f64(total_fuzz))
                };
                crate::cast::f64_to_u64(256.0 * fuzz_ratio.max(0.0)) + 64
            }
            EnergyPolicy::Rare => {
                // Rare: entries with unique edges that no other entry covers.
                if entry.favoured {
                    512
                } else {
                    32
                }
            }
        };
        entry.energy = base.clamp(16, 2048);
    }
}

// ── MutationEngine ────────────────────────────────────────────────────────────

/// Single mutation operation.
#[derive(Debug, Clone)]
pub enum Mutation {
    BitFlip { offset: usize, width: u8 },
    ByteFlip { offset: usize, count: usize },
    ArithAdd { offset: usize, val: i32, size: u8 },
    InterestingByte { offset: usize, val: u8 },
    InterestingWord { offset: usize, val: u16, le: bool },
    InterestingDword { offset: usize, val: u32, le: bool },
    RandomByte { offset: usize },
    DeleteRange { offset: usize, len: usize },
    InsertRandom { offset: usize, len: usize },
    Overwrite { offset: usize, data: Vec<u8> },
    Splice { crossover_point: usize, donor: Vec<u8> },
    DictInsert { offset: usize, token: Vec<u8> },
    DictOverwrite { offset: usize, token: Vec<u8> },
    RepeatBytes { offset: usize, len: usize, count: usize },
    Truncate { new_len: usize },
    ExtendWithRandom { extra_len: usize },
}

static INTERESTING_U8: &[u8] = &[0, 1, 16, 32, 64, 100, 127, 128, 200, 255];
static INTERESTING_U16: &[u16] = &[
    0, 1, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff,
];
static INTERESTING_U32: &[u32] = &[
    0,
    1,
    0x7f,
    0x80,
    0xff,
    0x100,
    0x7fff,
    0x8000,
    0xffff,
    0x1_0000,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_ffff,
];

/// Simple xorshift64 PRNG embedded in the fuzzer (no external dep).
pub struct Prng(u64);

impl Prng {
    #[must_use] 
    pub const fn new(seed: u64) -> Self {
        Self(if seed == 0 { 0xdead_beef_cafe_f00d } else { seed })
    }

    #[inline]
    pub const fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    #[inline]
    pub fn usize_below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        crate::cast::u64_to_usize(self.next()) % n
    }

    pub const fn bool_prob(&mut self, numerator: u64, denominator: u64) -> bool {
        self.next() % denominator < numerator
    }
}

/// Stateless mutation engine.
pub struct MutationEngine {
    pub dictionary: Vec<Vec<u8>>,
    rng: Prng,
}

impl MutationEngine {
    #[must_use] 
    pub const fn new(seed: u64) -> Self {
        Self {
            dictionary: Vec::new(),
            rng: Prng::new(seed),
        }
    }

    pub fn add_dict_token(&mut self, tok: Vec<u8>) {
        self.dictionary.push(tok);
    }

    /// Apply a single deterministic bit-flip pass, yielding all mutations.
    #[must_use] 
    pub fn bitflip1(&self, input: &[u8]) -> Vec<Vec<u8>> {
        (0..input.len() * 8)
            .map(|bit| {
                let mut v = input.to_vec();
                v[bit / 8] ^= 1 << (bit % 8);
                v
            })
            .collect()
    }

    /// Deterministic byte-flip (1/2/4 bytes).
    #[must_use] 
    pub fn byteflip(&self, input: &[u8], width: usize) -> Vec<Vec<u8>> {
        (0..input.len().saturating_sub(width - 1))
            .map(|i| {
                let mut v = input.to_vec();
                for j in 0..width {
                    v[i + j] ^= 0xff;
                }
                v
            })
            .collect()
    }

    /// Apply random havoc mutations to `input`, returning a new variant.
    pub fn havoc(&mut self, input: &[u8], energy: u64) -> Vec<u8> {
        let rounds = crate::cast::u64_to_usize(energy).clamp(4, HAVOC_ROUNDS);
        let mut data = input.to_vec();
        for _ in 0..rounds {
            if data.is_empty() {
                data.push(crate::cast::u64_to_u8(self.rng.next()));
                continue;
            }
            self.havoc_step(&mut data);
        }
        data
    }

    fn havoc_step(&mut self, data: &mut Vec<u8>) {
        let op = self.rng.usize_below(18);
        if op >= 10 {
            self.havoc_step_high(data, op);
            return;
        }
        match op {
                0 => {
                    // bit flip
                    let bit = self.rng.usize_below(data.len() * 8);
                    data[bit / 8] ^= 1 << (bit % 8);
                }
                1 => {
                    // byte add/sub
                    let i = self.rng.usize_below(data.len());
                    let delta = crate::cast::usize_to_i32(self.rng.usize_below(35)) - 17;
                    data[i] = data[i].wrapping_add(crate::cast::i32_to_u8(delta));
                }
                2 => {
                    // interesting byte
                    let i = self.rng.usize_below(data.len());
                    data[i] = INTERESTING_U8[self.rng.usize_below(INTERESTING_U8.len())];
                }
                3 => {
                    // interesting u16 LE
                    if data.len() >= 2 {
                        let i = self.rng.usize_below(data.len() - 1);
                        let v = INTERESTING_U16[self.rng.usize_below(INTERESTING_U16.len())];
                        data[i..i + 2].copy_from_slice(&v.to_le_bytes());
                    }
                }
                4 => {
                    // interesting u32 LE
                    if data.len() >= 4 {
                        let i = self.rng.usize_below(data.len() - 3);
                        let v = INTERESTING_U32[self.rng.usize_below(INTERESTING_U32.len())];
                        data[i..i + 4].copy_from_slice(&v.to_le_bytes());
                    }
                }
                5 => {
                    // random overwrite
                    let i = self.rng.usize_below(data.len());
                    data[i] = crate::cast::u64_to_u8(self.rng.next());
                }
                6 => {
                    // delete range
                    if data.len() > MIN_INPUT_LEN {
                        let i = self.rng.usize_below(data.len());
                        let max_del = (data.len() - MIN_INPUT_LEN).min(128);
                        let len = self.rng.usize_below(max_del).max(1);
                        let end = (i + len).min(data.len());
                        data.drain(i..end);
                    }
                }
                7 => {
                    // insert random bytes
                    let i = self.rng.usize_below(data.len() + 1);
                    let len = self.rng.usize_below(32).max(1);
                    let mut bytes = Vec::with_capacity(len);
                    bytes.extend((0..len).map(|_| crate::cast::u64_to_u8(self.rng.next())));
                    data.splice(i..i, bytes);
                }
                8 => {
                    // clone existing region
                    let src = self.rng.usize_below(data.len());
                    let len = self.rng.usize_below(32).max(1);
                    let end = (src + len).min(data.len());
                    let chunk: Vec<u8> = data[src..end].to_vec();
                    let dst = self.rng.usize_below(data.len() + 1);
                    data.splice(dst..dst, chunk);
                }
                9 => {
                    // memset region
                    let i = self.rng.usize_below(data.len());
                    let len = self.rng.usize_below(32).max(1);
                    let end = (i + len).min(data.len());
                    let fill = crate::cast::u64_to_u8(self.rng.next());
                    data[i..end].iter_mut().for_each(|b| *b = fill);
                }
                _ => {}
            }
    }

    fn havoc_step_high(&mut self, data: &mut Vec<u8>, op: usize) {
        match op {
            10 => {
                // swap two bytes
                if data.len() >= 2 {
                    let a = self.rng.usize_below(data.len());
                    let b = self.rng.usize_below(data.len());
                    data.swap(a, b);
                }
            }
            11 => {
                // truncate
                if data.len() > MIN_INPUT_LEN {
                    let new_len = self.rng.usize_below(data.len()).max(MIN_INPUT_LEN);
                    data.truncate(new_len);
                }
            }
            12 => {
                // extend with random
                let extra = self.rng.usize_below(64).max(1);
                data.extend((0..extra).map(|_| crate::cast::u64_to_u8(self.rng.next())));
            }
            13 => {
                // repeat a chunk
                if data.len() >= 2 {
                    let src = self.rng.usize_below(data.len());
                    let len = self.rng.usize_below(16).max(1);
                    let end = (src + len).min(data.len());
                    let chunk: Vec<u8> = data[src..end].to_vec();
                    let reps = self.rng.usize_below(4) + 2;
                    let dst = self.rng.usize_below(data.len() + 1);
                    let total = len.saturating_mul(reps);
                    let mut insert = Vec::with_capacity(total);
                    insert.extend(chunk.iter().copied().cycle().take(total));
                    data.splice(dst..dst, insert);
                }
            }
            14 => {
                // dictionary insert
                if !self.dictionary.is_empty() {
                    let tok = self.dictionary[self.rng.usize_below(self.dictionary.len())].clone();
                    let i = self.rng.usize_below(data.len() + 1);
                    data.splice(i..i, tok);
                }
            }
            15 => {
                // dictionary overwrite
                if !self.dictionary.is_empty() && !data.is_empty() {
                    let tok = &self.dictionary[self.rng.usize_below(self.dictionary.len())];
                    let i = self.rng.usize_below(data.len());
                    let end = (i + tok.len()).min(data.len());
                    data[i..end].copy_from_slice(&tok[..end - i]);
                }
            }
            16 => {
                // u16 arith BE
                if data.len() >= 2 {
                    let i = self.rng.usize_below(data.len() - 1);
                    let cur = u16::from_be_bytes([data[i], data[i + 1]]);
                    let delta = crate::cast::usize_to_i32(self.rng.usize_below(35)) - 17;
                    let new_val = cur.wrapping_add(crate::cast::i32_to_u16(delta));
                    let b = new_val.to_be_bytes();
                    data[i] = b[0];
                    data[i + 1] = b[1];
                }
            }
            _ => {
                // u32 arith LE
                if data.len() >= 4 {
                    let i = self.rng.usize_below(data.len() - 3);
                    let cur = u32::from_le_bytes(data[i..i + 4].try_into().unwrap_or([0; 4]));
                    let delta = crate::cast::usize_to_i32(self.rng.usize_below(35)) - 17;
                    let new_val = cur.wrapping_add(delta.cast_unsigned());
                    data[i..i + 4].copy_from_slice(&new_val.to_le_bytes());
                }
            }
        }
    }

    /// Splice two inputs together at a random crossover point.
    pub fn splice(&mut self, a: &[u8], b: &[u8]) -> Vec<u8> {
        if a.is_empty() || b.is_empty() {
            return if a.is_empty() { b.to_vec() } else { a.to_vec() };
        }
        let cut_a = self.rng.usize_below(a.len());
        let cut_b = self.rng.usize_below(b.len());
        let mut result = a[..cut_a].to_vec();
        result.extend_from_slice(&b[cut_b..]);
        result
    }

    /// Trim an input by repeatedly halving and checking coverage.
    /// Caller supplies an executor closure.
    pub fn trim<F>(&mut self, input: &[u8], mut exec: F) -> Vec<u8>
    where
        F: FnMut(&[u8]) -> CoverageMap,
    {
        let original_cov = exec(input);
        let mut current = input.to_vec();
        let mut step = current.len() / 2;
        while step > 0 && current.len() > MIN_INPUT_LEN {
            let mut improved = false;
            let mut i = 0;
            while i + step <= current.len() {
                let mut candidate = current[..i].to_vec();
                candidate.extend_from_slice(&current[i + step..]);
                if candidate.is_empty() {
                    i += step;
                    continue;
                }
                let cov = exec(&candidate);
                // Keep trim if coverage unchanged.
                if cov.edge_count() >= original_cov.edge_count() {
                    current = candidate;
                    improved = true;
                } else {
                    i += step;
                }
            }
            if !improved {
                step /= 2;
            }
        }
        current
    }
}

// ── CorpusManager ─────────────────────────────────────────────────────────────

/// Tracks the full set of corpus entries and the global coverage frontier.
pub struct CorpusManager {
    entries: Vec<CorpusEntry>,
    global_cov: CoverageMap,
    next_id: u64,
    /// Minimal set of entries that together cover all edges (favoured queue).
    favoured_set: HashSet<CorpusId>,
    total_fuzz_ops: u64,
}

impl CorpusManager {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            global_cov: CoverageMap::new(),
            next_id: 1,
            favoured_set: HashSet::new(),
            total_fuzz_ops: 0,
        }
    }

    #[must_use] 
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Add a new entry to the corpus; returns its ID.
    pub fn add(&mut self, data: Vec<u8>, cov: CoverageMap, exec_us: u64) -> CorpusId {
        let id = CorpusId(self.next_id);
        self.next_id += 1;
        let has_new = self.global_cov.merge_new_bits(&cov);
        let entry = CorpusEntry::new(id, data, cov, exec_us);
        self.entries.push(entry);
        if has_new {
            self.recompute_favoured();
        }
        id
    }

    /// Compute the greedy minimal set covering all edges.
    fn recompute_favoured(&mut self) {
        // Collect (edge_count, fastest) per edge.
        let mut edge_winner: HashMap<usize, (u64, CorpusId)> = HashMap::with_capacity(
            self.entries.iter().map(|e| e.unique_edges.len()).sum(),
        );
        for entry in &self.entries {
            for &edge in &entry.unique_edges {
                edge_winner
                    .entry(edge)
                    .and_modify(|(best_us, _)| {
                        if entry.exec_us < *best_us {
                            *best_us = entry.exec_us;
                        }
                    })
                    .or_insert((entry.exec_us, entry.id));
            }
        }
        // Greedy coverage.
        let mut covered: HashSet<usize> = HashSet::new();
        let mut favoured: HashSet<CorpusId> = HashSet::new();
        // Sort by unique edge count descending.
        let mut sorted: Vec<&CorpusEntry> = self.entries.iter().collect();
        sorted.sort_by(|a, b| b.unique_edges.len().cmp(&a.unique_edges.len()));
        for entry in sorted {
            let new: Vec<usize> = entry
                .unique_edges
                .iter()
                .filter(|e| !covered.contains(e))
                .copied()
                .collect();
            if !new.is_empty() {
                favoured.insert(entry.id);
                covered.extend(new);
            }
        }
        self.favoured_set.clone_from(&favoured);
        for entry in &mut self.entries {
            entry.favoured = favoured.contains(&entry.id);
        }
    }

    /// Choose the next entry to fuzz (round-robin with priority for favoured).
    pub fn choose_next(&mut self, rng: &mut Prng) -> Option<&mut CorpusEntry> {
        if self.entries.is_empty() {
            return None;
        }
        // 75% chance of picking from favoured set if non-empty.
        let use_favoured = !self.favoured_set.is_empty() && rng.bool_prob(3, 4);
        let candidates: Vec<usize> = if use_favoured {
            self.entries
                .iter()
                .enumerate()
                .filter(|(_, e)| e.favoured)
                .map(|(i, _)| i)
                .collect()
        } else {
            (0..self.entries.len()).collect()
        };
        if candidates.is_empty() {
            return None;
        }
        let idx = candidates[rng.usize_below(candidates.len())];
        Some(&mut self.entries[idx])
    }

    /// Record that an entry was fuzzed.
    pub fn record_fuzz(&mut self, id: CorpusId) {
        self.total_fuzz_ops += 1;
        if let Some(entry) = self.entries.iter_mut().find(|e| e.id == id) {
            entry.fuzz_count += 1;
        }
    }

    /// Global edge coverage count.
    #[must_use] 
    pub fn global_edge_count(&self) -> usize {
        self.global_cov.edge_count()
    }

    #[must_use] 
    pub const fn global_cov(&self) -> &CoverageMap {
        &self.global_cov
    }

    #[must_use] 
    pub fn entries(&self) -> &[CorpusEntry] {
        &self.entries
    }

    /// Remove entries that are strictly dominated (subset covered by others).
    pub fn prune_dominated(&mut self) {
        // Simple version: remove entries whose unique edges are all covered by favoured.
        self.entries.retain(|e| e.favoured || e.fuzz_count == 0);
    }
}

impl Default for CorpusManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── CalibrationResult ─────────────────────────────────────────────────────────

/// Result of calibrating a new corpus entry.
#[derive(Debug, Clone)]
pub struct CalibrationResult {
    pub entry_id: CorpusId,
    /// Mean execution time across multiple runs.
    pub mean_exec_us: u64,
    /// Standard deviation in execution time.
    pub stddev_us: u64,
    /// Whether coverage was stable across runs.
    pub stable: bool,
    /// Fraction of runs that matched baseline coverage.
    pub stability_ratio: f64,
    pub runs: usize,
}

/// Calibrate a new input by running it multiple times.
pub struct Calibrator {
    pub runs: usize,
}

impl Calibrator {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            runs: CALIBRATION_RUNS,
        }
    }

    pub fn calibrate<F>(&self, input: &[u8], mut exec: F) -> CalibrationResult
    where
        F: FnMut(&[u8]) -> (CoverageMap, u64),
    {
        let (baseline_cov, t0) = exec(input);
        let mut times = vec![t0];
        let mut matches = 1usize;
        for _ in 1..self.runs {
            let (cov, t) = exec(input);
            times.push(t);
            if cov.edge_count() == baseline_cov.edge_count() {
                matches += 1;
            }
        }
        let mean_us = times.iter().fold(0u64, |acc, &t| acc.saturating_add(t))
            / times.len() as u64;
        let variance = times
            .iter()
            .map(|&t| {
                let d = t.cast_signed().saturating_sub(mean_us.cast_signed());
                d.saturating_mul(d).cast_unsigned()
            })
            .fold(0u64, u64::saturating_add)
            / times.len() as u64;
        let stddev_us = crate::cast::f64_to_u64(crate::cast::u64_to_f64(variance).sqrt());
        let stability_ratio = crate::cast::usize_to_f64(matches) / crate::cast::usize_to_f64(self.runs);
        CalibrationResult {
            entry_id: CorpusId(0), // caller fills in
            mean_exec_us: mean_us,
            stddev_us,
            stable: stability_ratio >= 0.9,
            stability_ratio,
            runs: self.runs,
        }
    }
}

impl Default for Calibrator {
    fn default() -> Self {
        Self::new()
    }
}

// ── CrashEntry ────────────────────────────────────────────────────────────────

/// A crash discovered during fuzzing.
#[derive(Debug, Clone)]
pub struct CrashEntry {
    pub data: Vec<u8>,
    pub signal: Option<u32>,
    pub description: String,
    pub coverage_at_crash: CoverageMap,
    pub discovered_at: Instant,
    pub parent_id: Option<CorpusId>,
}

// ── FuzzSession ───────────────────────────────────────────────────────────────

/// Overall fuzzing campaign statistics.
#[derive(Debug, Clone, Default)]
pub struct FuzzStats {
    pub execs_total: u64,
    pub execs_per_sec: f64,
    pub crashes: u64,
    pub timeouts: u64,
    pub corpus_size: usize,
    pub edges_covered: usize,
    pub pending_favoured: usize,
    pub cycles_done: u64,
    pub stage_name: String,
    pub last_new_path: Option<Instant>,
    pub elapsed: Duration,
}

impl FuzzStats {
    #[must_use] 
    pub fn display_summary(&self) -> String {
        format!(
            "execs={} ({:.0}/s) crashes={} corpus={} edges={} cycles={}",
            self.execs_total,
            self.execs_per_sec,
            self.crashes,
            self.corpus_size,
            self.edges_covered,
            self.cycles_done
        )
    }
}

/// Stage of fuzzing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzStage {
    Calibrate,
    Trim,
    BitFlip1,
    BitFlip2,
    BitFlip4,
    ByteFlip1,
    ByteFlip2,
    ByteFlip4,
    Arith8,
    Arith16,
    Arith32,
    Interesting8,
    Interesting16,
    Interesting32,
    DictReplace,
    DictInsert,
    Havoc,
    Splice,
}

/// Executor trait — users implement this to run a test case.
pub trait Executor: Send + Sync {
    /// Run the test case and return (coverage, `exec_time_us`, status).
    fn execute(&self, input: &[u8]) -> (CoverageMap, u64, ExecStatus);
}

/// A no-op executor for testing.
pub struct NullExecutor;
impl Executor for NullExecutor {
    fn execute(&self, _input: &[u8]) -> (CoverageMap, u64, ExecStatus) {
        (CoverageMap::new(), 100, ExecStatus::Ok)
    }
}

/// The main coverage-guided fuzzer.
pub struct CoverageGuidedFuzzer {
    corpus: CorpusManager,
    crashes: Vec<CrashEntry>,
    mutation_engine: MutationEngine,
    calibrator: Calibrator,
    scheduler: EnergyScheduler,
    executor: Box<dyn Executor>,
    stats: FuzzStats,
    start_time: Instant,
    /// Maximum time to run (None = forever).
    max_duration: Option<Duration>,
    /// Maximum number of executions.
    max_execs: Option<u64>,
    current_stage: FuzzStage,
    enable_trim: bool,
    enable_splice: bool,
    enable_calibrate: bool,
}

impl CoverageGuidedFuzzer {
    #[must_use] 
    pub fn new(executor: Box<dyn Executor>, seed: u64, policy: EnergyPolicy) -> Self {
        Self {
            corpus: CorpusManager::new(),
            crashes: Vec::new(),
            mutation_engine: MutationEngine::new(seed),
            calibrator: Calibrator::new(),
            scheduler: EnergyScheduler::new(policy),
            executor,
            stats: FuzzStats::default(),
            start_time: Instant::now(),
            max_duration: None,
            max_execs: None,
            current_stage: FuzzStage::Calibrate,
            enable_trim: true,
            enable_splice: true,
            enable_calibrate: true,
        }
    }

    #[must_use] 
    pub const fn with_max_duration(mut self, d: Duration) -> Self {
        self.max_duration = Some(d);
        self
    }

    #[must_use] 
    pub const fn with_max_execs(mut self, n: u64) -> Self {
        self.max_execs = Some(n);
        self
    }

    #[must_use] 
    pub const fn without_trim(mut self) -> Self {
        self.enable_trim = false;
        self
    }

    #[must_use] 
    pub const fn without_splice(mut self) -> Self {
        self.enable_splice = false;
        self
    }

    pub fn add_seed(&mut self, data: Vec<u8>) -> CorpusId {
        let (cov, exec_us, _status) = self.executor.execute(&data);
        if self.enable_calibrate {
            let cal_result = self.calibrator.calibrate(&data, |input| {
                let (c, t, _) = self.executor.execute(input);
                (c, t)
            });
            let _ = cal_result;
        }
        
        self.corpus.add(data, cov, exec_us)
    }

    pub fn add_dictionary(&mut self, tokens: Vec<Vec<u8>>) {
        for tok in tokens {
            self.mutation_engine.add_dict_token(tok);
        }
    }

    /// Check whether the run should stop.
    #[must_use] 
    pub fn should_stop(&self) -> bool {
        if let Some(max) = self.max_execs
            && self.stats.execs_total >= max {
                return true;
            }
        if let Some(dur) = self.max_duration
            && self.start_time.elapsed() >= dur {
                return true;
            }
        false
    }

    /// Update stats.
    fn update_stats(&mut self) {
        let elapsed = self.start_time.elapsed();
        self.stats.elapsed = elapsed;
        let secs = elapsed.as_secs_f64().max(0.001);
        self.stats.execs_per_sec = crate::cast::u64_to_f64(self.stats.execs_total) / secs;
        self.stats.corpus_size = self.corpus.len();
        self.stats.edges_covered = self.corpus.global_edge_count();
        self.stats.crashes = self.crashes.len() as u64;
    }

    /// Execute one input, update corpus and crash list.
    pub fn exec_one(&mut self, data: Vec<u8>, parent_id: Option<CorpusId>) -> ExecStatus {
        let (cov, exec_us, status) = self.executor.execute(&data);
        self.stats.execs_total += 1;
        match &status {
            ExecStatus::Crash(desc) => {
                self.crashes.push(CrashEntry {
                    data,
                    signal: None,
                    description: desc.clone(),
                    coverage_at_crash: cov,
                    discovered_at: Instant::now(),
                    parent_id,
                });
                self.stats.crashes += 1;
            }
            ExecStatus::Timeout => {
                self.stats.timeouts += 1;
            }
            ExecStatus::Ok => {
                // Check if new coverage was found.
                let global_edges_before = self.corpus.global_edge_count();
                self.corpus.add(data, cov, exec_us);
                if self.corpus.global_edge_count() > global_edges_before {
                    self.stats.last_new_path = Some(Instant::now());
                }
            }
            ExecStatus::OomKill => {}
        }
        status
    }

    /// Run one fuzzing iteration: pick an entry, assign energy, mutate, execute.
    ///
    /// # Errors
    /// Documented for clippy.
    pub fn fuzz_one(&mut self) -> Result<()> {
        if self.corpus.is_empty() {
            bail!("corpus is empty — add at least one seed");
        }
        let mut rng = Prng::new(self.stats.execs_total ^ 0x00AB_CDEF);
        // Update energy assignments.
        self.scheduler.update_averages(self.corpus.entries());
        let total_fuzz = self.corpus.entries().iter().map(|e| e.fuzz_count).sum();
        // Choose parent.
        let (parent_id, parent_data, parent_energy) = {
            let entry = self
                .corpus
                .choose_next(&mut rng)
                .context("no corpus entries")?;
            self.scheduler.assign_energy(entry, total_fuzz);
            (entry.id, entry.data.clone(), entry.energy)
        };
        // Mutation stage.
        let child = if self.enable_splice
            && self.corpus.len() >= 2
            && rng.bool_prob(1, 4)
        {
            self.current_stage = FuzzStage::Splice;
            // Pick a donor.
            let donor_idx = rng.usize_below(self.corpus.len());
            let donor = self.corpus.entries()[donor_idx].data.clone();
            self.mutation_engine.splice(&parent_data, &donor)
        } else {
            self.current_stage = FuzzStage::Havoc;
            self.mutation_engine.havoc(&parent_data, parent_energy)
        };
        // Trim before executing (with probability).
        let final_input = if self.enable_trim && rng.bool_prob(1, 16) {
            self.current_stage = FuzzStage::Trim;
            let executor = &self.executor;
            self.mutation_engine.trim(&child, |input| {
                let (cov, _, _) = executor.execute(input);
                cov
            })
        } else {
            child
        };
        self.exec_one(final_input, Some(parent_id));
        self.corpus.record_fuzz(parent_id);
        self.update_stats();
        Ok(())
    }

    /// Run the fuzzer until stop condition is met.
    ///
    /// # Errors
    /// Documented for clippy.
    pub fn run(&mut self) -> Result<FuzzStats> {
        if self.corpus.is_empty() {
            bail!("no seeds in corpus");
        }
        self.start_time = Instant::now();
        while !self.should_stop() {
            self.fuzz_one()?;
            if self.stats.execs_total.is_multiple_of(10_000) {
                self.corpus.prune_dominated();
            }
        }
        self.update_stats();
        Ok(self.stats.clone())
    }

    #[must_use] 
    pub const fn stats(&self) -> &FuzzStats {
        &self.stats
    }

    #[must_use] 
    pub fn crashes(&self) -> &[CrashEntry] {
        &self.crashes
    }

    #[must_use] 
    pub const fn corpus(&self) -> &CorpusManager {
        &self.corpus
    }

    pub fn take_crashes(&mut self) -> Vec<CrashEntry> {
        std::mem::take(&mut self.crashes)
    }
}

// ── FuzzerBuilder ─────────────────────────────────────────────────────────────

/// Builder for `CoverageGuidedFuzzer`.
pub struct FuzzerBuilder {
    executor: Option<Box<dyn Executor>>,
    seeds: Vec<Vec<u8>>,
    dict_tokens: Vec<Vec<u8>>,
    policy: EnergyPolicy,
    seed_rng: u64,
    max_duration: Option<Duration>,
    max_execs: Option<u64>,
    trim: bool,
    splice: bool,
}

impl FuzzerBuilder {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            executor: None,
            seeds: Vec::new(),
            dict_tokens: Vec::new(),
            policy: EnergyPolicy::Fast,
            seed_rng: 0x1234_5678_90AB_CDEF,
            max_duration: None,
            max_execs: None,
            trim: true,
            splice: true,
        }
    }

    #[must_use] 
    pub fn executor(mut self, exec: Box<dyn Executor>) -> Self {
        self.executor = Some(exec);
        self
    }

    #[must_use] 
    pub fn add_seed(mut self, data: Vec<u8>) -> Self {
        self.seeds.push(data);
        self
    }

    #[must_use] 
    pub fn seeds(mut self, seeds: Vec<Vec<u8>>) -> Self {
        self.seeds = seeds;
        self
    }

    #[must_use] 
    pub const fn policy(mut self, p: EnergyPolicy) -> Self {
        self.policy = p;
        self
    }

    #[must_use] 
    pub const fn rng_seed(mut self, s: u64) -> Self {
        self.seed_rng = s;
        self
    }

    #[must_use] 
    pub const fn max_duration(mut self, d: Duration) -> Self {
        self.max_duration = Some(d);
        self
    }

    #[must_use] 
    pub const fn max_execs(mut self, n: u64) -> Self {
        self.max_execs = Some(n);
        self
    }

    #[must_use] 
    pub const fn no_trim(mut self) -> Self {
        self.trim = false;
        self
    }

    #[must_use] 
    pub const fn no_splice(mut self) -> Self {
        self.splice = false;
        self
    }

    #[must_use] 
    pub fn dictionary(mut self, tokens: Vec<Vec<u8>>) -> Self {
        self.dict_tokens = tokens;
        self
    }

    /// # Errors
    /// Documented for clippy.
    pub fn build(self) -> Result<CoverageGuidedFuzzer> {
        let executor = self.executor.unwrap_or_else(|| Box::new(NullExecutor));
        let mut fuzzer = CoverageGuidedFuzzer::new(executor, self.seed_rng, self.policy);
        if let Some(d) = self.max_duration {
            fuzzer = fuzzer.with_max_duration(d);
        }
        if let Some(n) = self.max_execs {
            fuzzer = fuzzer.with_max_execs(n);
        }
        if !self.trim {
            fuzzer = fuzzer.without_trim();
        }
        if !self.splice {
            fuzzer = fuzzer.without_splice();
        }
        fuzzer.add_dictionary(self.dict_tokens);
        for seed in self.seeds {
            fuzzer.add_seed(seed);
        }
        Ok(fuzzer)
    }
}

impl Default for FuzzerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct CountingExecutor(Arc<Mutex<u64>>);
    impl Executor for CountingExecutor {
        fn execute(&self, input: &[u8]) -> (CoverageMap, u64, ExecStatus) {
            *self.0.lock().unwrap() += 1;
            let mut cov = CoverageMap::new();
            // Simple: derive edges from input bytes.
            for (i, &b) in input.iter().enumerate() {
                cov.record(i, b as usize);
            }
            (cov, 100, ExecStatus::Ok)
        }
    }

    #[test]
    fn test_coverage_map_merge() {
        let mut a = CoverageMap::new();
        let mut b = CoverageMap::new();
        // CoverageMap uses (from ^ to) hashing — pick edges that hash to distinct slots.
        a.record(0, 1);
        b.record(0, 2);
        let new = a.merge_new_bits(&b);
        assert!(new);
        assert!(a.edge_count() >= 2);
    }

    #[test]
    fn test_prng_determinism() {
        let mut r1 = Prng::new(42);
        let mut r2 = Prng::new(42);
        for _ in 0..100 {
            assert_eq!(r1.next(), r2.next());
        }
    }

    #[test]
    fn test_mutation_engine_havoc() {
        let mut eng = MutationEngine::new(0xCAFE);
        let input = b"hello world";
        let mutated = eng.havoc(input, 64);
        // Mutation must not panic; output should be non-empty.
        assert!(!mutated.is_empty());
    }

    #[test]
    fn test_splice() {
        let mut eng = MutationEngine::new(1);
        let a = b"AAAAAAAAAA";
        let b = b"BBBBBBBBBB";
        let s = eng.splice(a, b);
        assert!(!s.is_empty());
    }

    #[test]
    fn test_corpus_manager_add_and_choose() {
        let mut cm = CorpusManager::new();
        let mut cov = CoverageMap::new();
        cov.record(0, 1);
        cm.add(b"seed".to_vec(), cov, 100);
        assert_eq!(cm.len(), 1);
        let mut rng = Prng::new(1);
        assert!(cm.choose_next(&mut rng).is_some());
    }

    #[test]
    fn test_fuzzer_builder_runs() {
        let counter = Arc::new(Mutex::new(0u64));
        let exec = Box::new(CountingExecutor(counter.clone()));
        let mut fuzzer = FuzzerBuilder::new()
            .executor(exec)
            .add_seed(b"hello".to_vec())
            .max_execs(20)
            .no_trim()
            .build()
            .unwrap();
        fuzzer.run().unwrap();
        assert!(*counter.lock().unwrap() >= 20);
    }

    #[test]
    fn test_energy_policy_fast() {
        let mut sched = EnergyScheduler::new(EnergyPolicy::Fast);
        let cov = CoverageMap::new();
        let mut entry = CorpusEntry::new(CorpusId(1), vec![0u8; 64], cov, 500);
        sched.update_averages(&[entry.clone()]);
        sched.assign_energy(&mut entry, 0);
        assert!(entry.energy >= 16);
    }

    #[test]
    fn test_calibrator() {
        let cal = Calibrator::new();
        let result = cal.calibrate(b"test", |input| {
            let mut cov = CoverageMap::new();
            cov.record(0, input.len());
            (cov, 100)
        });
        assert_eq!(result.runs, CALIBRATION_RUNS);
        assert!(result.mean_exec_us > 0);
    }
}
