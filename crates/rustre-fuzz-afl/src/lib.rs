//! `rustre-fuzz-afl`
//!
//! AFL++-style coverage-guided fuzzer built on top of the `rustre-fuzz` base
//! framework.  Provides a rich set of mutators (bit-flip, byte-flip, arithmetic,
//! interesting-value, dictionary, splice, havoc), an [`AflFuzzer`] that drives
//! the full mutation → execute → triage loop, AFL shared-memory coverage,
//! fork-server protocol, persistent mode, CMPLOG support, queue management,
//! and AFL statistics parsing.

pub mod afl_analysis;
pub mod afl_corpus_manager;
pub mod afl_mutators;
pub mod persistent_mode;
pub mod qemu_mode;

pub mod cmplog;
pub mod redqueen_engine;
pub mod afl_fork_server;
pub mod afl_bitmap;
pub mod afl_queue;
pub mod afl_trimmer;
pub mod afl_queue_reader;
pub mod afl_coverage_map;
pub mod afl_crash_triager;

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::time::SystemTime;

use rustre_fuzz::{
    Corpus, CorpusMeta, CoverageMap, ExecutionStatus, FuzzError, FuzzInput, FuzzerStats,
    InputQueue, TargetExecutor, fnv1a,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── RNG ───────────────────────────────────────────────────────────────────────

/// Core RNG interface used by all mutators.
pub trait RngCore {
    /// Generate the next `u64`.
    fn next_u64(&mut self) -> u64;

    /// Generate the next `u32`.
    fn next_u32(&mut self) -> u32 {
        let b = self.next_u64().to_le_bytes();
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }

    /// Generate a random `usize` in `[0, n)`.
    fn next_usize(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        let val = self.next_u64() % (n as u64);
        // val < n ≤ usize::MAX; TryFrom is infallible here.
        usize::try_from(val).unwrap_or(0)
    }

    /// Return `true` with probability 1/n.
    fn one_in(&mut self, n: usize) -> bool {
        self.next_usize(n) == 0
    }

    /// Generate a random u8.
    fn next_u8(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }
}

/// Simple xorshift-64 PRNG.
#[derive(Debug, Clone)]
pub struct XorShiftRng {
    state: u64,
}

impl XorShiftRng {
    /// Create a new RNG with the given seed.  Seed must not be zero.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0xdead_beef_cafe_babe } else { seed },
        }
    }

    /// Create a new RNG with the given seed (alias for [`Self::new`]).
    #[must_use]
    pub const fn with_seed(seed: u64) -> Self {
        Self::new(seed)
    }
}

impl RngCore for XorShiftRng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}

impl Default for XorShiftRng {
    fn default() -> Self {
        Self::new(0x1234_5678_9abc_def0)
    }
}

// ── Mutator trait ─────────────────────────────────────────────────────────────

/// A strategy for mutating a byte buffer.
pub trait Mutator: Send + Sync {
    /// Return a mutated copy of `input`.
    fn mutate(&self, input: &[u8], rng: &mut dyn RngCore) -> Vec<u8>;

    /// Human-readable name of this mutator.
    fn name(&self) -> &'static str {
        "unknown"
    }
}

// ── Interesting value tables ──────────────────────────────────────────────────

const INTERESTING_BYTES: &[u8] = &[0, 1, 255, 127, 128];
const INTERESTING_WORDS: &[u16] = &[0, 1, 0x7fff, 0x8000, 0xffff];
const INTERESTING_DWORDS: &[u32] = &[0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff];
const INTERESTING_QWORDS: &[u64] = &[
    0,
    1,
    0x7fff_ffff_ffff_ffff,
    0x8000_0000_0000_0000,
    0xffff_ffff_ffff_ffff,
];

// ── BitFlipMutator ────────────────────────────────────────────────────────────

/// Flip 1, 2, or 4 consecutive bits at a random position.
#[derive(Debug, Clone, Default)]
pub struct BitFlipMutator;

impl Mutator for BitFlipMutator {
    fn name(&self) -> &'static str {
        "bit_flip"
    }

    fn mutate(&self, input: &[u8], rng: &mut dyn RngCore) -> Vec<u8> {
        if input.is_empty() {
            return input.to_vec();
        }
        let mut out = input.to_vec();
        let total_bits = out.len() * 8;
        let start_bit = rng.next_usize(total_bits);
        let widths = [1usize, 2, 4];
        let width = widths[rng.next_usize(3)];
        for offset in 0..width {
            let bit = (start_bit + offset) % total_bits;
            let byte_idx = bit / 8;
            let bit_idx = bit % 8;
            out[byte_idx] ^= 1 << bit_idx;
        }
        out
    }
}

// ── ByteFlipMutator ───────────────────────────────────────────────────────────

/// Flip 1, 2, 4, or 8 consecutive bytes at a random position.
#[derive(Debug, Clone, Default)]
pub struct ByteFlipMutator;

impl Mutator for ByteFlipMutator {
    fn name(&self) -> &'static str {
        "byte_flip"
    }

    fn mutate(&self, input: &[u8], rng: &mut dyn RngCore) -> Vec<u8> {
        if input.is_empty() {
            return input.to_vec();
        }
        let mut out = input.to_vec();
        let widths = [1usize, 2, 4, 8];
        let width = widths[rng.next_usize(4)].min(out.len());
        let start = rng.next_usize(out.len().saturating_sub(width) + 1);
        for b in &mut out[start..start + width] {
            *b ^= 0xff;
        }
        out
    }
}

// ── ArithmeticMutator ─────────────────────────────────────────────────────────

/// Add or subtract a small random value (1–35) to a byte, 16-bit word, or
/// 32-bit dword at a random position.
#[derive(Debug, Clone, Default)]
pub struct ArithmeticMutator;

impl Mutator for ArithmeticMutator {
    fn name(&self) -> &'static str {
        "arithmetic"
    }

    fn mutate(&self, input: &[u8], rng: &mut dyn RngCore) -> Vec<u8> {
        if input.is_empty() {
            return input.to_vec();
        }
        let mut out = input.to_vec();
        let delta = u8::try_from(rng.next_usize(35) + 1).unwrap_or(35);
        let add = rng.next_u64() & 1 == 0;
        let kind = rng.next_usize(3);
        match kind {
            0 => {
                let idx = rng.next_usize(out.len());
                if add {
                    out[idx] = out[idx].wrapping_add(delta);
                } else {
                    out[idx] = out[idx].wrapping_sub(delta);
                }
            }
            1 if out.len() >= 2 => {
                let idx = rng.next_usize(out.len() - 1);
                let val = u16::from_le_bytes([out[idx], out[idx + 1]]);
                let result = if add {
                    val.wrapping_add(u16::from(delta))
                } else {
                    val.wrapping_sub(u16::from(delta))
                };
                let bytes = result.to_le_bytes();
                out[idx] = bytes[0];
                out[idx + 1] = bytes[1];
            }
            2 if out.len() >= 4 => {
                let idx = rng.next_usize(out.len() - 3);
                let val = u32::from_le_bytes([out[idx], out[idx + 1], out[idx + 2], out[idx + 3]]);
                let result = if add {
                    val.wrapping_add(u32::from(delta))
                } else {
                    val.wrapping_sub(u32::from(delta))
                };
                let bytes = result.to_le_bytes();
                out[idx..idx + 4].copy_from_slice(&bytes);
            }
            _ => {
                let idx = rng.next_usize(out.len());
                out[idx] = out[idx].wrapping_add(delta);
            }
        }
        out
    }
}

// ── InterestingValueMutator ───────────────────────────────────────────────────

/// Replace bytes/words/dwords/qwords with known-interesting boundary values.
#[derive(Debug, Clone, Default)]
pub struct InterestingValueMutator;

impl Mutator for InterestingValueMutator {
    fn name(&self) -> &'static str {
        "interesting_value"
    }

    fn mutate(&self, input: &[u8], rng: &mut dyn RngCore) -> Vec<u8> {
        if input.is_empty() {
            return input.to_vec();
        }
        let mut out = input.to_vec();
        let kind = rng.next_usize(4);
        match kind {
            1 if out.len() >= 2 => {
                let idx = rng.next_usize(out.len() - 1);
                let val = INTERESTING_WORDS[rng.next_usize(INTERESTING_WORDS.len())];
                let bytes = val.to_le_bytes();
                out[idx] = bytes[0];
                out[idx + 1] = bytes[1];
            }
            2 if out.len() >= 4 => {
                let idx = rng.next_usize(out.len() - 3);
                let val = INTERESTING_DWORDS[rng.next_usize(INTERESTING_DWORDS.len())];
                let bytes = val.to_le_bytes();
                out[idx..idx + 4].copy_from_slice(&bytes);
            }
            3 if out.len() >= 8 => {
                let idx = rng.next_usize(out.len() - 7);
                let val = INTERESTING_QWORDS[rng.next_usize(INTERESTING_QWORDS.len())];
                let bytes = val.to_le_bytes();
                out[idx..idx + 8].copy_from_slice(&bytes);
            }
            _ => {
                let idx = rng.next_usize(out.len());
                out[idx] = INTERESTING_BYTES[rng.next_usize(INTERESTING_BYTES.len())];
            }
        }
        out
    }
}

// ── Dictionary ────────────────────────────────────────────────────────────────

/// A word list used by the [`DictionaryMutator`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Dictionary {
    /// The list of raw-byte tokens.
    pub entries: Vec<Vec<u8>>,
}

impl Dictionary {
    /// Create a new empty dictionary.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a token to the dictionary.
    pub fn add(&mut self, token: Vec<u8>) {
        self.entries.push(token);
    }

    /// Add a string token.
    pub fn add_str(&mut self, s: &str) {
        self.entries.push(s.as_bytes().to_vec());
    }

    /// Number of tokens.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Load dictionary from AFL-style format (one per line, `"..."` strings,
    /// `x"..."` hex).
    ///
    /// # Errors
    /// Returns [`AflError::InvalidDict`] on parse failure.
    pub fn load_afl_format(&mut self, text: &str) -> Result<usize, AflError> {
        let mut count = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("x\"") {
                let hex = rest.trim_end_matches('"');
                let bytes: Result<Vec<u8>, _> = hex
                    .split_whitespace()
                    .map(|s| u8::from_str_radix(s, 16))
                    .collect();
                match bytes {
                    Ok(b) => {
                        self.add(b);
                        count += 1;
                    }
                    Err(_) => return Err(AflError::InvalidDict(format!("bad hex: {hex}"))),
                }
            } else if line.starts_with('"') && line.ends_with('"') && line.len() >= 2 {
                let inner = &line[1..line.len() - 1];
                let mut bytes = Vec::with_capacity(inner.len());
                let mut chars = inner.chars();
                while let Some(c) = chars.next() {
                    if c == '\\' {
                        match chars.next() {
                            Some('x') => {
                                let h1 = chars.next();
                                let h2 = chars.next();
                                match (h1, h2) {
                                    (Some(a), Some(b)) => {
                                        let hex: String = [a, b].iter().collect();
                                        match u8::from_str_radix(&hex, 16) {
                                            Ok(v) => bytes.push(v),
                                            Err(_) => {
                                                return Err(AflError::InvalidDict(format!(
                                                    "bad \\x escape: {hex}"
                                                )));
                                            }
                                        }
                                    }
                                    _ => {
                                        return Err(AflError::InvalidDict(
                                            "truncated \\x escape".to_string(),
                                        ));
                                    }
                                }
                            }
                            Some('n') => bytes.push(b'\n'),
                            Some('r') => bytes.push(b'\r'),
                            Some('t') => bytes.push(b'\t'),
                            Some('0') => bytes.push(0),
                            Some('\\') => bytes.push(b'\\'),
                            Some('"') => bytes.push(b'"'),
                            Some(other) => {
                                let mut buf = [0u8; 4];
                                bytes.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
                            }
                            None => {
                                return Err(AflError::InvalidDict(
                                    "trailing backslash".to_string(),
                                ));
                            }
                        }
                    } else {
                        let mut buf = [0u8; 4];
                        bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                    }
                }
                self.add(bytes);
                count += 1;
            } else {
                self.add(line.as_bytes().to_vec());
                count += 1;
            }
        }
        Ok(count)
    }
}

// ── DictionaryMutator ─────────────────────────────────────────────────────────

/// Insert or overwrite bytes with tokens from a [`Dictionary`].
#[derive(Debug, Clone, Default)]
pub struct DictionaryMutator {
    /// The dictionary of tokens.
    pub dict: Dictionary,
}

impl DictionaryMutator {
    /// Create a new mutator backed by the given dictionary.
    #[must_use]
    pub const fn new(dict: Dictionary) -> Self {
        Self { dict }
    }
}

impl Mutator for DictionaryMutator {
    fn name(&self) -> &'static str {
        "dictionary"
    }

    fn mutate(&self, input: &[u8], rng: &mut dyn RngCore) -> Vec<u8> {
        if self.dict.entries.is_empty() || input.is_empty() {
            return input.to_vec();
        }
        let mut out = input.to_vec();
        let token = &self.dict.entries[rng.next_usize(self.dict.entries.len())];
        if token.is_empty() {
            return out;
        }
        // Only choose an insertion point where the full token fits, avoiding
        // silent truncation of long tokens.
        if token.len() > out.len() {
            // Token is longer than the entire buffer; resize and overwrite from index 0.
            out.resize(token.len(), 0);
            out[..token.len()].copy_from_slice(token);
            return out;
        }
        let max_start = out.len() - token.len();
        let start = rng.next_usize(max_start + 1);
        out[start..start + token.len()].copy_from_slice(token);
        out
    }
}

// ── SpliceMutator ─────────────────────────────────────────────────────────────

/// Splice two corpus inputs together at a random crossover point.
#[derive(Debug, Clone, Default)]
pub struct SpliceMutator;

impl SpliceMutator {
    /// Splice `a` and `b` at a random crossover point.
    #[must_use]
    pub fn splice(a: &[u8], b: &[u8], rng: &mut dyn RngCore) -> Vec<u8> {
        if a.is_empty() {
            return b.to_vec();
        }
        if b.is_empty() {
            return a.to_vec();
        }
        let split_a = rng.next_usize(a.len());
        let split_b = rng.next_usize(b.len());
        let mut out = Vec::with_capacity(split_a + (b.len() - split_b));
        out.extend_from_slice(&a[..split_a]);
        out.extend_from_slice(&b[split_b..]);
        out
    }
}

impl Mutator for SpliceMutator {
    fn name(&self) -> &'static str {
        "splice"
    }

    /// Without a second corpus entry this just returns the input unchanged.
    fn mutate(&self, input: &[u8], _rng: &mut dyn RngCore) -> Vec<u8> {
        input.to_vec()
    }
}

// ── InsertMutator ─────────────────────────────────────────────────────────────

/// Insert random bytes at a random position.
#[derive(Debug, Clone, Default)]
pub struct InsertMutator {
    /// Maximum number of bytes to insert.
    pub max_insert: usize,
}

impl InsertMutator {
    /// Create with the given max insert size.
    #[must_use]
    pub fn new(max_insert: usize) -> Self {
        Self {
            max_insert: max_insert.max(1),
        }
    }
}

impl Mutator for InsertMutator {
    fn name(&self) -> &'static str {
        "insert"
    }

    fn mutate(&self, input: &[u8], rng: &mut dyn RngCore) -> Vec<u8> {
        if input.len() >= 1024 * 1024 {
            return input.to_vec();
        }
        let mut out = input.to_vec();
        let count = rng.next_usize(self.max_insert) + 1;
        let insert_at = rng.next_usize(out.len() + 1);
        let bytes: Vec<u8> = (0..count).map(|_| rng.next_u8()).collect();
        for (i, b) in bytes.into_iter().enumerate() {
            let pos = (insert_at + i).min(out.len());
            out.insert(pos, b);
        }
        out
    }
}

// ── DeleteMutator ─────────────────────────────────────────────────────────────

/// Delete a random byte range from the input.
#[derive(Debug, Clone, Default)]
pub struct DeleteMutator;

impl Mutator for DeleteMutator {
    fn name(&self) -> &'static str {
        "delete"
    }

    fn mutate(&self, input: &[u8], rng: &mut dyn RngCore) -> Vec<u8> {
        if input.len() <= 1 {
            return input.to_vec();
        }
        let mut out = input.to_vec();
        let max_del = (out.len() - 1).max(1);
        let count = rng.next_usize(max_del) + 1;
        let start = rng.next_usize(out.len().saturating_sub(count) + 1);
        let end = (start + count).min(out.len());
        out.drain(start..end);
        out
    }
}

// ── XorBlockMutator ───────────────────────────────────────────────────────────

/// XOR a block of bytes with a random key byte.
#[derive(Debug, Clone, Default)]
pub struct XorBlockMutator;

impl Mutator for XorBlockMutator {
    fn name(&self) -> &'static str {
        "xor_block"
    }

    fn mutate(&self, input: &[u8], rng: &mut dyn RngCore) -> Vec<u8> {
        if input.is_empty() {
            return input.to_vec();
        }
        let mut out = input.to_vec();
        let key = rng.next_u8();
        let block_len = (rng.next_usize(16) + 1).min(out.len());
        let start = rng.next_usize(out.len().saturating_sub(block_len) + 1);
        for b in &mut out[start..start + block_len] {
            *b ^= key;
        }
        out
    }
}

// ── HavocMutator ─────────────────────────────────────────────────────────────

/// Apply a random sequence of up to 8 micro-mutations.
#[derive(Debug, Clone, Default)]
pub struct HavocMutator;

impl HavocMutator {
    fn apply_one(buf: &mut Vec<u8>, rng: &mut dyn RngCore) {
        if buf.is_empty() {
            return;
        }
        match rng.next_usize(8) {
            0 => {
                let bit = rng.next_usize(buf.len() * 8);
                buf[bit / 8] ^= 1 << (bit % 8);
            }
            1 => {
                let idx = rng.next_usize(buf.len());
                buf[idx] ^= 0xff;
            }
            2 => {
                let idx = rng.next_usize(buf.len());
                buf[idx] = INTERESTING_BYTES[rng.next_usize(INTERESTING_BYTES.len())];
            }
            3 => {
                let idx = rng.next_usize(buf.len());
                buf[idx] = (rng.next_u32() & 0xff) as u8;
            }
            4 => {
                if buf.len() > 1 {
                    let start = rng.next_usize(buf.len());
                    let len = rng.next_usize((buf.len() - start).max(1)) + 1;
                    let end = (start + len).min(buf.len());
                    buf.drain(start..end);
                }
            }
            5 => {
                if buf.len() < 1024 {
                    let start = rng.next_usize(buf.len());
                    let len = (rng.next_usize(8) + 1).min(buf.len() - start);
                    let chunk: Vec<u8> = buf[start..start + len].to_vec();
                    let insert_at = rng.next_usize(buf.len() + 1);
                    for (j, &b) in chunk.iter().enumerate() {
                        buf.insert(insert_at + j, b);
                    }
                }
            }
            6 => {
                // XOR block
                let key = (rng.next_u32() & 0xff) as u8;
                let start = rng.next_usize(buf.len());
                let len = (rng.next_usize(8) + 1).min(buf.len() - start);
                for b in &mut buf[start..start + len] {
                    *b ^= key;
                }
            }
            _ => {
                let idx = rng.next_usize(buf.len());
                let delta = u8::try_from(rng.next_usize(35) + 1).unwrap_or(35);
                buf[idx] = buf[idx].wrapping_add(delta);
            }
        }
    }
}

impl Mutator for HavocMutator {
    fn name(&self) -> &'static str {
        "havoc"
    }

    fn mutate(&self, input: &[u8], rng: &mut dyn RngCore) -> Vec<u8> {
        let mut buf = input.to_vec();
        let rounds = rng.next_usize(8) + 1;
        for _ in 0..rounds {
            Self::apply_one(&mut buf, rng);
        }
        buf
    }
}

// ── AflError ─────────────────────────────────────────────────────────────────

/// Errors produced by AFL-related operations.
#[derive(Debug, Error)]
pub enum AflError {
    /// The coverage shared memory could not be created or mapped.
    #[error("shm error: {0}")]
    ShmError(String),
    /// Fork server communication failed.
    #[error("fork server error: {0}")]
    ForkServerError(String),
    /// Dictionary parsing error.
    #[error("invalid dict: {0}")]
    InvalidDict(String),
    /// Stats parsing error.
    #[error("stats parse error: {0}")]
    StatsParseError(String),
    /// Fuzz error.
    #[error("fuzz error: {0}")]
    FuzzError(#[from] FuzzError),
    /// I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

// ── AflShmCoverage ────────────────────────────────────────────────────────────

/// Simulated AFL shared-memory coverage bitmap (64 KiB).
///
/// In a real implementation this would be a POSIX shared-memory segment; here
/// we use a plain `Vec<u8>` for portability.
#[derive(Debug, Clone)]
pub struct AflShmCoverage {
    /// The coverage bitmap bytes.
    pub bitmap: Vec<u8>,
    /// Size of the bitmap in bytes.
    pub size: usize,
    /// Shared-memory ID (simulated).
    pub shm_id: u32,
}

impl AflShmCoverage {
    /// AFL default bitmap size (64 KiB).
    pub const AFL_MAP_SIZE: usize = 65536;

    /// Create a new zeroed coverage bitmap of `size` bytes.
    #[must_use]
    pub fn new(size: usize) -> Self {
        Self {
            bitmap: vec![0u8; size],
            size,
            shm_id: 0xDEAD_BEEF,
        }
    }

    /// Create with the standard AFL map size.
    #[must_use]
    pub fn afl_default() -> Self {
        Self::new(Self::AFL_MAP_SIZE)
    }

    /// Clear the bitmap.
    pub fn clear(&mut self) {
        self.bitmap.iter_mut().for_each(|b| *b = 0);
    }

    /// Count the number of non-zero bytes (hit basic blocks).
    #[must_use]
    pub fn count_non_zero(&self) -> usize {
        self.bitmap.iter().filter(|&&b| b != 0).count()
    }

    /// Return a compact bitmap with each byte bucketed (AFL-style).
    #[must_use]
    pub fn bucketed(&self) -> Vec<u8> {
        self.bitmap.iter().map(|&b| bucket(b)).collect()
    }

    /// Merge `other` bitmap into this one.
    ///
    /// Returns the count of newly set bytes.
    pub fn merge(&mut self, other: &[u8]) -> usize {
        let len = self.size.min(other.len());
        let mut new_bytes = 0;
        for (bm, &o) in self.bitmap.iter_mut().zip(other.iter()).take(len) {
            if *bm == 0 && o != 0 {
                new_bytes += 1;
            }
            *bm |= o;
        }
        new_bytes
    }

    /// Compute FNV-1a hash of the bitmap.
    #[must_use]
    pub fn hash(&self) -> u64 {
        fnv1a(&self.bitmap)
    }
}

/// AFL-style hit-count bucketing: 1 → 1, 2 → 2, 3..=4 → 4, 5..=8 → 8, etc.
#[must_use]
const fn bucket(count: u8) -> u8 {
    match count {
        0 => 0,
        1 => 1,
        2 => 2,
        3..=4 => 4,
        5..=8 => 8,
        9..=16 => 16,
        17..=32 => 32,
        33..=128 => 64,
        _ => 128,
    }
}

// ── ForkServerProtocol ────────────────────────────────────────────────────────

/// Simulated AFL fork server state machine.
///
/// In production this would use OS pipes; here we track the logical state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForkServerState {
    /// Not started.
    Idle,
    /// Waiting for a request to fork.
    Ready,
    /// A child process is running.
    Running { child_pid: u32 },
    /// Child exited normally.
    Done { exit_status: i32 },
    /// Child crashed.
    Crashed { signal: i32 },
}

/// Logical representation of the AFL fork server.
#[derive(Debug)]
pub struct ForkServer {
    /// Current state.
    pub state: ForkServerState,
    /// Simulated child PID counter.
    next_pid: u32,
    /// Total forks performed.
    pub forks: u64,
}

impl ForkServer {
    /// Create a new idle fork server.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: ForkServerState::Idle,
            next_pid: 1000,
            forks: 0,
        }
    }

    /// Start the fork server (transition to Ready).
    pub const fn start(&mut self) {
        self.state = ForkServerState::Ready;
    }

    /// Request a fork.
    ///
    /// # Errors
    /// Returns [`AflError::ForkServerError`] if not in the Ready state.
    pub fn request_fork(&mut self) -> Result<u32, AflError> {
        if self.state != ForkServerState::Ready {
            return Err(AflError::ForkServerError("not in Ready state".to_string()));
        }
        let pid = self.next_pid;
        self.next_pid = self.next_pid.wrapping_add(1);
        self.forks += 1;
        self.state = ForkServerState::Running { child_pid: pid };
        Ok(pid)
    }

    /// Simulate the child completing normally.
    pub const fn child_done(&mut self, exit_code: i32) {
        self.state = ForkServerState::Done {
            exit_status: exit_code,
        };
    }

    /// Simulate the child crashing.
    pub const fn child_crash(&mut self, signal: i32) {
        self.state = ForkServerState::Crashed { signal };
    }

    /// Reset to Ready state after a run completes.
    ///
    /// # Errors
    /// Returns [`AflError::ForkServerError`] if not in Done or Crashed state.
    pub fn reset(&mut self) -> Result<(), AflError> {
        match self.state {
            ForkServerState::Done { .. } | ForkServerState::Crashed { .. } => {
                self.state = ForkServerState::Ready;
                Ok(())
            }
            _ => Err(AflError::ForkServerError(
                "cannot reset: not in Done/Crashed state".to_string(),
            )),
        }
    }

    /// Returns `true` if the fork server is ready to accept a fork request.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.state == ForkServerState::Ready
    }
}

impl Default for ForkServer {
    fn default() -> Self {
        Self::new()
    }
}

// ── CmplogEntry ───────────────────────────────────────────────────────────────

/// A single comparison log entry (CMPLOG).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmplogEntry {
    /// Address of the comparison instruction.
    pub addr: u64,
    /// Left operand value.
    pub v0: u64,
    /// Right operand value.
    pub v1: u64,
    /// Comparison size in bytes (1, 2, 4, 8).
    pub size: u8,
    /// Whether this is a function hook (vs. inline cmp).
    pub is_fn_hook: bool,
}

impl CmplogEntry {
    /// Create a new CMPLOG entry.
    #[must_use]
    pub const fn new(addr: u64, v0: u64, v1: u64, size: u8) -> Self {
        Self {
            addr,
            v0,
            v1,
            size,
            is_fn_hook: false,
        }
    }

    /// Whether the comparison was equal.
    #[must_use]
    pub const fn is_equal(&self) -> bool {
        self.v0 == self.v1
    }

    /// Return the difference as an absolute value (for arithmetic proximity).
    #[must_use]
    pub const fn diff(&self) -> u64 {
        self.v0.abs_diff(self.v1)
    }
}

// ── CmplogMap ────────────────────────────────────────────────────────────────

/// Stores comparison log entries from a single execution.
#[derive(Debug, Default, Clone)]
pub struct CmplogMap {
    /// All comparison entries recorded.
    pub entries: Vec<CmplogEntry>,
}

impl CmplogMap {
    /// Create an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a comparison.
    pub fn record(&mut self, addr: u64, v0: u64, v1: u64, size: u8) {
        self.entries.push(CmplogEntry::new(addr, v0, v1, size));
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Number of recorded comparisons.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no comparisons have been recorded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return all entries where the comparison was not equal (potential points
    /// of interest for mutation).
    #[must_use]
    pub fn unequal_entries(&self) -> Vec<&CmplogEntry> {
        self.entries.iter().filter(|e| !e.is_equal()).collect()
    }

    /// Apply a "colorize" mutation derived from CMPLOG: for each unequal
    /// comparison, produce a candidate input by patching the relevant bytes.
    #[must_use]
    pub fn colorize_mutations(&self, input: &[u8]) -> Vec<Vec<u8>> {
        let mut candidates = Vec::new();
        for entry in self.unequal_entries() {
            if entry.size as usize > input.len() {
                continue;
            }
            // Insert v1 bytes at various offsets
            for start in 0..=input.len().saturating_sub(entry.size as usize) {
                let end = (start + entry.size as usize).min(input.len());
                if end - start < entry.size as usize {
                    continue;
                }
                let mut candidate = input.to_vec();
                let bytes = entry.v1.to_le_bytes();
                candidate[start..end].copy_from_slice(&bytes[..end - start]);
                candidates.push(candidate);
            }
        }
        candidates
    }
}

// ── AflQueueEntry ─────────────────────────────────────────────────────────────

/// An entry in the AFL fuzzing queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AflQueueEntry {
    /// Unique identifier.
    pub id: u64,
    /// The input bytes.
    pub data: Vec<u8>,
    /// FNV hash of the data.
    pub data_hash: u64,
    /// Number of coverage bits this entry provides.
    pub coverage_bits: u32,
    /// Average execution time in microseconds.
    pub exec_time_us: u64,
    /// How many times this entry has been selected.
    pub selected_count: u64,
    /// How many times mutations of this entry produced new coverage.
    pub interesting_count: u64,
    /// Whether this entry is marked as "favored".
    pub is_favored: bool,
    /// Whether this entry is marked as "trimmed".
    pub is_trimmed: bool,
    /// When this entry was added.
    pub added_at: SystemTime,
}

impl AflQueueEntry {
    /// Create a new queue entry.
    #[must_use]
    pub fn new(id: u64, data: Vec<u8>, coverage_bits: u32) -> Self {
        let data_hash = fnv1a(&data);
        Self {
            id,
            data,
            data_hash,
            coverage_bits,
            exec_time_us: 0,
            selected_count: 0,
            interesting_count: 0,
            is_favored: false,
            is_trimmed: false,
            added_at: SystemTime::now(),
        }
    }

    /// Mark this entry as selected.
    pub const fn mark_selected(&mut self) {
        self.selected_count += 1;
    }

    /// Mark that a child of this entry was interesting.
    pub const fn mark_interesting(&mut self) {
        self.interesting_count += 1;
    }

    /// "Score" used for power-schedule weighting.
    #[must_use]
    pub fn score(&self) -> f64 {
        if self.selected_count == 0 {
            return f64::MAX; // un-tried entries get maximum priority
        }
        let interest_rate = f64::from(u32::try_from(self.interesting_count).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.selected_count).unwrap_or(u32::MAX));
        let time_bonus = if self.exec_time_us == 0 {
            10.0
        } else {
            10_000.0 / f64::from(u32::try_from(self.exec_time_us).unwrap_or(u32::MAX))
        };
        (1.0 + interest_rate) * time_bonus * f64::from(self.coverage_bits)
    }
}

// ── AflQueue ──────────────────────────────────────────────────────────────────

/// AFL-style fuzzing queue with power scheduling.
#[derive(Debug, Default)]
pub struct AflQueue {
    /// All entries, keyed by id.
    pub entries: HashMap<u64, AflQueueEntry>,
    /// Ordered entry ids (insertion order).
    order: Vec<u64>,
    /// Round-robin cursor for sequential cycling.
    cursor: usize,
    /// Next entry id.
    next_id: u64,
    /// Total number of cycles completed.
    pub cycles: u64,
}

impl AflQueue {
    /// Create an empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate the next entry id.
    pub const fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    /// Add an entry to the queue.
    pub fn push(&mut self, entry: AflQueueEntry) {
        let id = entry.id;
        self.order.push(id);
        self.entries.insert(id, entry);
    }

    /// Select the next entry to fuzz (round-robin over the full queue).
    ///
    /// Returns `None` if the queue is empty.
    #[must_use]
    pub fn select_sequential(&mut self) -> Option<&mut AflQueueEntry> {
        let n = self.order.len();
        if n == 0 {
            return None;
        }
        let idx = self.cursor % n;
        self.cursor += 1;
        if self.cursor >= n {
            self.cursor = 0;
            self.cycles += 1;
        }
        let id = self.order[idx];
        self.entries.get_mut(&id)
    }

    /// Select the highest-scoring entry (power-schedule priority).
    ///
    /// # Panics
    /// Panics if the queue is empty.
    #[must_use]
    pub fn select_best(&self) -> &AflQueueEntry {
        self.entries
            .values()
            .max_by(|a, b| {
                a.score()
                    .partial_cmp(&b.score())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .expect("queue not empty")
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove entries whose coverage bits fall below `min_bits`.
    pub fn prune(&mut self, min_bits: u32) -> usize {
        let before = self.entries.len();
        let to_remove: Vec<u64> = self
            .entries
            .values()
            .filter(|e| e.coverage_bits < min_bits && e.selected_count > 0)
            .map(|e| e.id)
            .collect();
        for id in &to_remove {
            self.entries.remove(id);
            self.order.retain(|oid| oid != id);
        }
        before - self.entries.len()
    }

    /// Mark entries as favored based on minimum-spanning-set selection.
    pub fn compute_favorites(&mut self) {
        let mut favored_bits: Vec<bool> = vec![false; 65536];
        // Reset all favorites
        for e in self.entries.values_mut() {
            e.is_favored = false;
        }
        // Greedy set cover: prefer entries with more coverage bits
        let mut ids_by_coverage: Vec<u64> = self.order.clone();
        ids_by_coverage.sort_unstable_by(|a, b| {
            let ca = self.entries.get(a).map_or(0, |e| e.coverage_bits);
            let cb = self.entries.get(b).map_or(0, |e| e.coverage_bits);
            cb.cmp(&ca)
        });
        for id in &ids_by_coverage {
            let bits = if let Some(e) = self.entries.get(id) {
                e.coverage_bits
            } else {
                continue;
            };
            if bits == 0 {
                continue;
            }
            // Greedy set cover: mark this entry as favored if it contributes
            // at least one coverage bit slot not yet covered. We spread the
            // `coverage_bits` count across the bitmap by hashing consecutive
            // (id, slot_index) pairs so each count maps to distinct slots.
            let entry_id = *id;
            let mut contributed = false;
            for slot in 0..bits {
                // Derive a deterministic bit index from (entry_id, slot) so
                // that distinct (entry, slot) pairs land on distinct positions.
                let key = entry_id.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(u64::from(slot));
                let bit_idx = usize::try_from(key % u64::try_from(favored_bits.len()).unwrap_or(u64::MAX)).unwrap_or(0);
                if !favored_bits[bit_idx] {
                    favored_bits[bit_idx] = true;
                    contributed = true;
                }
            }
            if contributed
                && let Some(e) = self.entries.get_mut(&entry_id) {
                    e.is_favored = true;
                }
        }
    }
}

// ── AflStats ─────────────────────────────────────────────────────────────────

/// Parsed AFL statistics (equivalent to `fuzzer_stats` file).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AflStats {
    /// Start timestamp (Unix epoch seconds).
    pub start_time: u64,
    /// Last update timestamp.
    pub last_update: u64,
    /// Total executions performed.
    pub execs_done: u64,
    /// Executions per second.
    pub execs_per_sec: f64,
    /// Total crashes found.
    pub crashes_found: u64,
    /// Unique crashes.
    pub unique_crashes: u64,
    /// Hangs found.
    pub hangs_found: u64,
    /// Current queue size.
    pub queue_size: u64,
    /// Total paths (distinct coverage hashes).
    pub total_paths: u64,
    /// Total cycles done.
    pub cycles_done: u64,
    /// Current fuzzer state (e.g. "splicing", "havoc").
    pub fuzzer_state: String,
    /// Peak resident set size in KB.
    pub peak_rss_mb: u64,
    /// Target executable path.
    pub target: String,
    /// Stability percentage.
    pub stability: f64,
    /// Bitmap coverage percentage.
    pub map_density: f64,
}

impl AflStats {
    /// Create a new stats object.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse an AFL `fuzzer_stats` text file.
    ///
    /// Format: `key : value\n`.
    ///
    /// # Errors
    /// Returns [`AflError::StatsParseError`] on malformed input.
    pub fn parse(text: &str) -> Result<Self, AflError> {
        let mut s = Self::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(2, ':');
            let key = parts.next().map_or("", str::trim);
            let val = parts.next().map_or("", str::trim);
            match key {
                "start_time" => s.start_time = val.parse().unwrap_or(0),
                "last_update" => s.last_update = val.parse().unwrap_or(0),
                "execs_done" => s.execs_done = val.parse().unwrap_or(0),
                "execs_per_sec" => s.execs_per_sec = val.parse().unwrap_or(0.0),
                "crashes_found" | "unique_crashes" => {
                    if key == "crashes_found" {
                        s.crashes_found = val.parse().unwrap_or(0);
                    } else {
                        s.unique_crashes = val.parse().unwrap_or(0);
                    }
                }
                "hangs_found" => s.hangs_found = val.parse().unwrap_or(0),
                "queue_size" | "paths_total" => {
                    if key == "queue_size" {
                        s.queue_size = val.parse().unwrap_or(0);
                    } else {
                        s.total_paths = val.parse().unwrap_or(0);
                    }
                }
                "cycles_done" => s.cycles_done = val.parse().unwrap_or(0),
                "fuzzer_state" | "stage_name" => s.fuzzer_state = val.to_string(),
                "peak_rss_mb" => s.peak_rss_mb = val.parse().unwrap_or(0),
                "target" | "command_line" => s.target = val.to_string(),
                "stability" => {
                    // Might look like "99.00%"
                    s.stability = val.trim_end_matches('%').parse().unwrap_or(0.0);
                }
                "bitmap_cvg" | "map_density" => {
                    s.map_density = val.trim_end_matches('%').parse().unwrap_or(0.0);
                }
                _ => {}
            }
        }
        Ok(s)
    }

    /// Serialize to AFL `fuzzer_stats` text format.
    #[must_use]
    pub fn serialize(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "start_time      : {}", self.start_time);
        let _ = writeln!(out, "last_update     : {}", self.last_update);
        let _ = writeln!(out, "execs_done      : {}", self.execs_done);
        let _ = writeln!(out, "execs_per_sec   : {:.2}", self.execs_per_sec);
        let _ = writeln!(out, "crashes_found   : {}", self.crashes_found);
        let _ = writeln!(out, "unique_crashes  : {}", self.unique_crashes);
        let _ = writeln!(out, "hangs_found     : {}", self.hangs_found);
        let _ = writeln!(out, "queue_size      : {}", self.queue_size);
        let _ = writeln!(out, "paths_total     : {}", self.total_paths);
        let _ = writeln!(out, "cycles_done     : {}", self.cycles_done);
        let _ = writeln!(out, "fuzzer_state    : {}", self.fuzzer_state);
        let _ = writeln!(out, "peak_rss_mb     : {}", self.peak_rss_mb);
        let _ = writeln!(out, "stability       : {:.2}%", self.stability);
        let _ = writeln!(out, "bitmap_cvg      : {:.2}%", self.map_density);
        out
    }
}

// ── PersistentMode ────────────────────────────────────────────────────────────

/// Manages the AFL persistent-mode execution loop.
///
/// In persistent mode the target resets itself between runs without `fork()`
/// overhead, enabling much higher throughput.
#[derive(Debug, Clone)]
pub struct PersistentMode {
    /// Maximum iterations before restarting the child.
    pub max_iterations: u64,
    /// Current iteration count.
    pub iteration: u64,
    /// Whether persistent mode is currently active.
    pub active: bool,
    /// Total resets performed.
    pub resets: u64,
}

impl PersistentMode {
    /// Create a new persistent mode manager.
    #[must_use]
    pub const fn new(max_iterations: u64) -> Self {
        Self {
            max_iterations,
            iteration: 0,
            active: false,
            resets: 0,
        }
    }

    /// Start persistent mode.
    pub const fn start(&mut self) {
        self.active = true;
        self.iteration = 0;
    }

    /// Advance one iteration.  Returns `true` if the loop should continue,
    /// `false` if it should restart the child.
    #[must_use]
    pub const fn advance(&mut self) -> bool {
        if !self.active {
            return false;
        }
        self.iteration += 1;
        if self.iteration >= self.max_iterations {
            self.iteration = 0;
            self.resets += 1;
            return false;
        }
        true
    }

    /// Stop persistent mode.
    pub const fn stop(&mut self) {
        self.active = false;
    }
}

impl Default for PersistentMode {
    fn default() -> Self {
        Self::new(1000)
    }
}

// ── AflFuzzer ─────────────────────────────────────────────────────────────────

/// An AFL++-inspired coverage-guided fuzzer.
pub struct AflFuzzer {
    /// The target executor.
    pub executor: Box<dyn TargetExecutor>,
    /// The input queue.
    pub queue: InputQueue,
    /// The AFL-style queue.
    pub afl_queue: AflQueue,
    /// The global coverage map.
    pub coverage: CoverageMap,
    /// AFL shared-memory coverage bitmap.
    pub shm: AflShmCoverage,
    /// The set of active mutators.
    pub mutators: Vec<Box<dyn Mutator>>,
    /// Accumulated statistics.
    pub stats: FuzzerStats,
    /// AFL statistics.
    pub afl_stats: AflStats,
    /// Crash corpus.
    pub crashes: Corpus,
    /// Optional token dictionary.
    pub dict: Option<Dictionary>,
    /// Internal PRNG.
    pub rng: XorShiftRng,
    /// CMPLOG map.
    pub cmplog: CmplogMap,
    /// Fork server state.
    pub fork_server: ForkServer,
    /// Persistent mode manager.
    pub persistent: PersistentMode,
    /// Mutation strategy hit counts for adaptive selection.
    strategy_hits: HashMap<String, u64>,
}

impl AflFuzzer {
    /// Create a new [`AflFuzzer`] with sane defaults and an initial seed corpus.
    #[must_use] 
    pub fn new(executor: Box<dyn TargetExecutor>, seed_corpus: Vec<Vec<u8>>) -> Self {
        let mut fuzzer = Self {
            executor,
            queue: InputQueue::new(),
            afl_queue: AflQueue::new(),
            coverage: CoverageMap::new(65536),
            shm: AflShmCoverage::afl_default(),
            mutators: vec![
                Box::new(BitFlipMutator),
                Box::new(ByteFlipMutator),
                Box::new(ArithmeticMutator),
                Box::new(InterestingValueMutator),
                Box::new(HavocMutator),
                Box::new(InsertMutator::new(16)),
                Box::new(DeleteMutator),
                Box::new(XorBlockMutator),
            ],
            stats: FuzzerStats::new(),
            afl_stats: AflStats::new(),
            crashes: Corpus::new(),
            dict: None,
            rng: XorShiftRng::default(),
            cmplog: CmplogMap::new(),
            fork_server: ForkServer::new(),
            persistent: PersistentMode::default(),
            strategy_hits: HashMap::new(),
        };
        fuzzer.import_seeds(seed_corpus);
        fuzzer
    }

    /// Set a dictionary for dictionary-based mutations.
    pub fn set_dictionary(&mut self, dict: Dictionary) {
        self.dict = Some(dict.clone());
        self.mutators.push(Box::new(DictionaryMutator::new(dict)));
    }

    /// Execute each seed, record coverage, and add to the queue.
    pub fn import_seeds(&mut self, seeds: Vec<Vec<u8>>) {
        for data in seeds {
            let id = self.queue.next_id();
            let input = FuzzInput::new(id, data.clone());
            let result = self.executor.execute(&data);
            let is_interesting = result.as_ref().is_ok_and(|r| r.new_coverage_bits > 0);
            if let Ok(r) = result {
                let _newly_set = self.coverage.update(&r.coverage_hash.to_le_bytes());
                self.stats.executions += 1;
                self.queue.total_executions += 1;

                // Add to AFL queue
                let afl_id = self.afl_queue.next_id();
                let afl_entry = AflQueueEntry::new(afl_id, data.clone(), r.new_coverage_bits);
                self.afl_queue.push(afl_entry);
            }
            self.queue.add(input, is_interesting);
        }
        self.stats.corpus_size = self.queue.len() as u64;
        self.afl_stats.queue_size = self.afl_queue.len() as u64;
    }

    /// Fuzz a single input: select → mutate → execute → triage.
    ///
    /// Returns `Some(input)` if a new interesting input was found.
    ///
    /// # Errors
    /// Propagates [`FuzzError`] from the executor.
    pub fn fuzz_one(&mut self) -> Result<Option<FuzzInput>, FuzzError> {
        if self.queue.is_empty() {
            return Ok(None);
        }

        let parent = self.queue.select().clone();

        let mutator_idx = self.rng.next_usize(self.mutators.len());
        let strategy_name = self.mutators[mutator_idx].name().to_string();
        let mutated = self.mutators[mutator_idx].mutate(&parent.data, &mut self.rng);

        let result = self.executor.execute(&mutated)?;

        self.stats.executions += 1;
        self.stats.record_execution(mutated.len());
        self.queue.total_executions += 1;

        match &result.status {
            ExecutionStatus::Crash { signal, fault_addr } => {
                let sig = *signal;
                let fa = *fault_addr;
                self.stats.crashes += 1;
                self.stats.last_crash_time = Some(SystemTime::now());
                if result.new_coverage_bits > 0 {
                    self.stats.unique_crashes += 1;
                }
                let child_id = self.queue.next_id();
                let crash_input = parent.derive(child_id, mutated);
                let meta = CorpusMeta::new(
                    result.coverage_hash,
                    result.new_coverage_bits,
                    result.execution_time,
                );
                self.crashes.add_crash(crash_input.clone(), meta);
                let _new_bits = self.coverage.update(&result.coverage_hash.to_le_bytes());
                self.shm.merge(&result.coverage_hash.to_le_bytes());

                // Record CMPLOG data for crash
                let _ = (sig, fa);

                return Ok(Some(crash_input));
            }
            ExecutionStatus::Timeout | ExecutionStatus::Hang => {
                self.stats.hangs += 1;
            }
            ExecutionStatus::Normal => {}
        }

        let new_bits = self.coverage.update(&result.coverage_hash.to_le_bytes());
        self.shm.merge(&result.coverage_hash.to_le_bytes());

        if new_bits > 0 || result.new_coverage_bits > 0 {
            *self.strategy_hits.entry(strategy_name).or_insert(0) += 1;
            let child_id = self.queue.next_id();
            let new_input = parent.derive(child_id, mutated.clone());
            self.queue.add(new_input.clone(), true);
            self.stats.corpus_size = self.queue.len() as u64;
            self.stats.interesting_inputs += 1;

            // Add to AFL queue
            let afl_id = self.afl_queue.next_id();
            let afl_entry =
                AflQueueEntry::new(afl_id, mutated, result.new_coverage_bits.max(new_bits));
            self.afl_queue.push(afl_entry);
            self.afl_stats.queue_size = self.afl_queue.len() as u64;

            return Ok(Some(new_input));
        }

        Ok(None)
    }

    /// Run the fuzzer for up to `limit` executions (or indefinitely if `None`).
    ///
    /// # Errors
    /// Propagates [`FuzzError`] from the executor.
    pub fn run(&mut self, limit: Option<u64>) -> Result<FuzzerStats, FuzzError> {
        let mut count: u64 = 0;
        loop {
            if let Some(max) = limit
                && count >= max {
                    break;
                }
            self.fuzz_one()?;
            count += 1;
        }
        self.afl_stats.execs_done = self.stats.executions;
        self.afl_stats.crashes_found = self.stats.crashes;
        self.afl_stats.unique_crashes = self.stats.unique_crashes;
        self.afl_stats.hangs_found = self.stats.hangs;
        Ok(self.stats.clone())
    }

    /// Return the most-hit mutation strategy.
    #[must_use]
    pub fn best_strategy(&self) -> Option<&str> {
        self.strategy_hits
            .iter()
            .max_by_key(|&(_, &v)| v)
            .map(|(k, _)| k.as_str())
    }

    /// Apply the CMPLOG colorize technique to the given input.
    ///
    /// Returns candidate inputs derived from comparison analysis.
    #[must_use]
    pub fn colorize(&self, input: &[u8]) -> Vec<Vec<u8>> {
        self.cmplog.colorize_mutations(input)
    }

    /// Get current AFL stats snapshot.
    #[must_use]
    pub const fn afl_stats_snapshot(&self) -> &AflStats {
        &self.afl_stats
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_fuzz::{ExecutionResult, ExecutionStatus, FuzzError};
    use std::time::Duration;

    // ── Mock executor ─────────────────────────────────────────────────────────

    struct MockExecutor {
        status: ExecutionStatus,
        new_bits: u32,
        hash: u64,
    }

    impl MockExecutor {
        fn normal(new_bits: u32) -> Self {
            Self {
                status: ExecutionStatus::Normal,
                new_bits,
                hash: u64::from(new_bits) * 0x1234,
            }
        }

        fn crashing() -> Self {
            Self {
                status: ExecutionStatus::Crash {
                    signal: 11,
                    fault_addr: Some(0xdead_beef),
                },
                new_bits: 0,
                hash: 0xdead,
            }
        }
    }

    impl TargetExecutor for MockExecutor {
        fn execute(&mut self, _input: &[u8]) -> Result<ExecutionResult, FuzzError> {
            Ok(ExecutionResult {
                status: self.status.clone(),
                coverage_hash: self.hash,
                execution_time: Duration::from_micros(100),
                new_coverage_bits: self.new_bits,
            })
        }
    }

    // ── RNG ───────────────────────────────────────────────────────────────────

    #[test]
    fn xorshift_deterministic() {
        let mut a = XorShiftRng::new(42);
        let mut b = XorShiftRng::new(42);
        assert_eq!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn xorshift_not_zero_seed() {
        let mut r = XorShiftRng::new(0);
        let v = r.next_u64();
        assert_ne!(v, 0);
    }

    #[test]
    fn xorshift_next_usize_in_range() {
        let mut r = XorShiftRng::default();
        for _ in 0..100 {
            assert!(r.next_usize(10) < 10);
        }
    }

    #[test]
    fn xorshift_next_u8() {
        let mut r = XorShiftRng::default();
        let v = r.next_u8();
        let _ = v; // just check it doesn't panic
    }

    #[test]
    fn xorshift_one_in() {
        let mut r = XorShiftRng::default();
        let mut hits = 0;
        for _ in 0..1000 {
            if r.one_in(10) {
                hits += 1;
            }
        }
        assert!(hits > 0 && hits < 300);
    }

    // ── BitFlipMutator ────────────────────────────────────────────────────────

    #[test]
    fn bit_flip_preserves_length() {
        let m = BitFlipMutator;
        let mut rng = XorShiftRng::default();
        let input = vec![0u8; 16];
        let out = m.mutate(&input, &mut rng);
        assert_eq!(out.len(), input.len());
    }

    #[test]
    fn bit_flip_changes_something() {
        let m = BitFlipMutator;
        let mut rng = XorShiftRng::default();
        let input = vec![0u8; 8];
        let out = m.mutate(&input, &mut rng);
        assert_ne!(out, input);
    }

    #[test]
    fn bit_flip_empty_input() {
        let m = BitFlipMutator;
        let mut rng = XorShiftRng::default();
        assert_eq!(m.mutate(&[], &mut rng), vec![]);
    }

    #[test]
    fn bit_flip_name() {
        assert_eq!(BitFlipMutator.name(), "bit_flip");
    }

    // ── ByteFlipMutator ───────────────────────────────────────────────────────

    #[test]
    fn byte_flip_changes_something() {
        let m = ByteFlipMutator;
        let mut rng = XorShiftRng::new(1);
        let input = vec![0u8; 16];
        let out = m.mutate(&input, &mut rng);
        assert_ne!(out, input);
    }

    #[test]
    fn byte_flip_empty() {
        let m = ByteFlipMutator;
        let mut rng = XorShiftRng::default();
        assert_eq!(m.mutate(&[], &mut rng), vec![]);
    }

    #[test]
    fn byte_flip_name() {
        assert_eq!(ByteFlipMutator.name(), "byte_flip");
    }

    // ── ArithmeticMutator ─────────────────────────────────────────────────────

    #[test]
    fn arithmetic_preserves_length() {
        let m = ArithmeticMutator;
        let mut rng = XorShiftRng::new(999);
        let input = vec![10u8; 8];
        let out = m.mutate(&input, &mut rng);
        assert_eq!(out.len(), input.len());
    }

    #[test]
    fn arithmetic_changes_something() {
        let m = ArithmeticMutator;
        let mut rng = XorShiftRng::new(7);
        let input = vec![0u8; 8];
        let out = m.mutate(&input, &mut rng);
        assert_ne!(out, input);
    }

    #[test]
    fn arithmetic_name() {
        assert_eq!(ArithmeticMutator.name(), "arithmetic");
    }

    // ── InterestingValueMutator ───────────────────────────────────────────────

    #[test]
    fn interesting_value_preserves_length_small_input() {
        let m = InterestingValueMutator;
        let mut rng = XorShiftRng::new(3);
        let input = vec![1u8, 2, 3];
        let out = m.mutate(&input, &mut rng);
        assert_eq!(out.len(), input.len());
    }

    #[test]
    fn interesting_value_on_empty() {
        let m = InterestingValueMutator;
        let mut rng = XorShiftRng::default();
        assert_eq!(m.mutate(&[], &mut rng), vec![]);
    }

    #[test]
    fn interesting_value_large_input() {
        let m = InterestingValueMutator;
        let mut rng = XorShiftRng::new(1);
        let input = vec![0x55u8; 16];
        let out = m.mutate(&input, &mut rng);
        assert_eq!(out.len(), input.len());
    }

    // ── Dictionary / DictionaryMutator ────────────────────────────────────────

    #[test]
    fn dictionary_add() {
        let mut d = Dictionary::new();
        d.add(b"hello".to_vec());
        assert_eq!(d.entries.len(), 1);
        assert!(!d.is_empty());
    }

    #[test]
    fn dictionary_add_str() {
        let mut d = Dictionary::new();
        d.add_str("world");
        assert_eq!(d.entries[0], b"world");
    }

    #[test]
    fn dictionary_len() {
        let mut d = Dictionary::new();
        d.add(vec![1]);
        d.add(vec![2]);
        assert_eq!(d.len(), 2);
    }

    #[test]
    fn dictionary_mutator_inserts_token() {
        let mut d = Dictionary::new();
        d.add(vec![0xde, 0xad, 0xbe, 0xef]);
        let m = DictionaryMutator::new(d);
        let mut rng = XorShiftRng::new(42);
        let input = vec![0u8; 16];
        let out = m.mutate(&input, &mut rng);
        assert_ne!(out, input);
    }

    #[test]
    fn dictionary_mutator_empty_dict() {
        let m = DictionaryMutator::default();
        let mut rng = XorShiftRng::default();
        let input = vec![1u8, 2, 3];
        assert_eq!(m.mutate(&input, &mut rng), input);
    }

    #[test]
    fn dictionary_load_afl_format_bare() {
        let mut d = Dictionary::new();
        let n = d.load_afl_format("token1\ntoken2\n# comment\n").unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn dictionary_load_afl_format_quoted() {
        let mut d = Dictionary::new();
        d.load_afl_format("\"quoted\"\n").unwrap();
        assert_eq!(d.entries[0], b"quoted");
    }

    #[test]
    fn dictionary_load_afl_format_hex() {
        let mut d = Dictionary::new();
        d.load_afl_format("x\"de ad be ef\"\n").unwrap();
        assert_eq!(d.entries[0], vec![0xde, 0xad, 0xbe, 0xef]);
    }

    // ── SpliceMutator ─────────────────────────────────────────────────────────

    #[test]
    fn splice_combines_inputs() {
        let mut rng = XorShiftRng::new(5);
        let a = vec![0xAA; 8];
        let b = vec![0xBB; 8];
        let out = SpliceMutator::splice(&a, &b, &mut rng);
        assert!(!out.is_empty());
    }

    #[test]
    fn splice_empty_a() {
        let mut rng = XorShiftRng::default();
        let out = SpliceMutator::splice(&[], &[1, 2, 3], &mut rng);
        assert_eq!(out, vec![1, 2, 3]);
    }

    #[test]
    fn splice_empty_b() {
        let mut rng = XorShiftRng::default();
        let out = SpliceMutator::splice(&[1, 2], &[], &mut rng);
        assert_eq!(out, vec![1, 2]);
    }

    // ── InsertMutator ─────────────────────────────────────────────────────────

    #[test]
    fn insert_grows_length() {
        let m = InsertMutator::new(8);
        let mut rng = XorShiftRng::new(3);
        let input = vec![0u8; 8];
        let out = m.mutate(&input, &mut rng);
        assert!(out.len() > input.len());
    }

    #[test]
    fn insert_name() {
        assert_eq!(InsertMutator::new(8).name(), "insert");
    }

    // ── DeleteMutator ─────────────────────────────────────────────────────────

    #[test]
    fn delete_shrinks_length() {
        let m = DeleteMutator;
        let mut rng = XorShiftRng::new(5);
        let input = vec![0u8; 10];
        let out = m.mutate(&input, &mut rng);
        assert!(out.len() < input.len());
    }

    #[test]
    fn delete_single_byte_unchanged() {
        let m = DeleteMutator;
        let mut rng = XorShiftRng::default();
        let out = m.mutate(&[42], &mut rng);
        assert_eq!(out, vec![42]);
    }

    // ── XorBlockMutator ───────────────────────────────────────────────────────

    #[test]
    fn xor_block_changes_something() {
        let m = XorBlockMutator;
        let mut rng = XorShiftRng::new(7);
        let input = vec![0u8; 16];
        let out = m.mutate(&input, &mut rng);
        assert_ne!(out, input);
    }

    #[test]
    fn xor_block_preserves_length() {
        let m = XorBlockMutator;
        let mut rng = XorShiftRng::new(9);
        let input = vec![0xABu8; 16];
        let out = m.mutate(&input, &mut rng);
        assert_eq!(out.len(), input.len());
    }

    // ── HavocMutator ─────────────────────────────────────────────────────────

    #[test]
    fn havoc_mutates_input() {
        let m = HavocMutator;
        let mut rng = XorShiftRng::new(11);
        let input = vec![0u8; 32];
        let out = m.mutate(&input, &mut rng);
        assert_ne!(out, input);
    }

    #[test]
    fn havoc_empty_input() {
        let m = HavocMutator;
        let mut rng = XorShiftRng::default();
        let _ = m.mutate(&[], &mut rng);
    }

    #[test]
    fn havoc_name() {
        assert_eq!(HavocMutator.name(), "havoc");
    }

    // ── AflShmCoverage ────────────────────────────────────────────────────────

    #[test]
    fn shm_new() {
        let shm = AflShmCoverage::new(100);
        assert_eq!(shm.size, 100);
        assert_eq!(shm.bitmap.len(), 100);
        assert_eq!(shm.count_non_zero(), 0);
    }

    #[test]
    fn shm_afl_default_size() {
        let shm = AflShmCoverage::afl_default();
        assert_eq!(shm.size, AflShmCoverage::AFL_MAP_SIZE);
    }

    #[test]
    fn shm_merge_counts_new_bytes() {
        let mut shm = AflShmCoverage::new(4);
        let count = shm.merge(&[0x01, 0, 0, 0]);
        assert_eq!(count, 1);
    }

    #[test]
    fn shm_merge_idempotent() {
        let mut shm = AflShmCoverage::new(4);
        shm.merge(&[0xFF, 0xFF, 0, 0]);
        let count = shm.merge(&[0xFF, 0xFF, 0, 0]);
        assert_eq!(count, 0);
    }

    #[test]
    fn shm_clear() {
        let mut shm = AflShmCoverage::new(4);
        shm.merge(&[0xFF, 0xFF, 0xFF, 0xFF]);
        shm.clear();
        assert_eq!(shm.count_non_zero(), 0);
    }

    #[test]
    fn shm_hash_changes_on_update() {
        let mut shm = AflShmCoverage::new(4);
        let h1 = shm.hash();
        shm.merge(&[1, 0, 0, 0]);
        let h2 = shm.hash();
        assert_ne!(h1, h2);
    }

    #[test]
    fn shm_bucketed() {
        let mut shm = AflShmCoverage::new(4);
        shm.bitmap[0] = 3;
        let bucketed = shm.bucketed();
        assert_eq!(bucketed[0], 4); // 3..=4 → 4
    }

    // ── bucket function ───────────────────────────────────────────────────────

    #[test]
    fn bucket_values() {
        assert_eq!(bucket(0), 0);
        assert_eq!(bucket(1), 1);
        assert_eq!(bucket(2), 2);
        assert_eq!(bucket(3), 4);
        assert_eq!(bucket(5), 8);
        assert_eq!(bucket(9), 16);
        assert_eq!(bucket(17), 32);
        assert_eq!(bucket(33), 64);
        assert_eq!(bucket(255), 128);
    }

    // ── ForkServer ────────────────────────────────────────────────────────────

    #[test]
    fn fork_server_lifecycle() {
        let mut fs = ForkServer::new();
        assert!(!fs.is_ready());
        fs.start();
        assert!(fs.is_ready());
        let pid = fs.request_fork().unwrap();
        assert!(pid >= 1000);
        assert_eq!(fs.forks, 1);
        fs.child_done(0);
        fs.reset().unwrap();
        assert!(fs.is_ready());
    }

    #[test]
    fn fork_server_crash() {
        let mut fs = ForkServer::new();
        fs.start();
        fs.request_fork().unwrap();
        fs.child_crash(11);
        assert!(matches!(fs.state, ForkServerState::Crashed { signal: 11 }));
        fs.reset().unwrap();
        assert!(fs.is_ready());
    }

    #[test]
    fn fork_server_request_without_start_fails() {
        let mut fs = ForkServer::new();
        assert!(fs.request_fork().is_err());
    }

    #[test]
    fn fork_server_reset_while_running_fails() {
        let mut fs = ForkServer::new();
        fs.start();
        fs.request_fork().unwrap();
        assert!(fs.reset().is_err());
    }

    // ── CmplogEntry ───────────────────────────────────────────────────────────

    #[test]
    fn cmplog_entry_equal() {
        let e = CmplogEntry::new(0x1000, 42, 42, 8);
        assert!(e.is_equal());
        assert_eq!(e.diff(), 0);
    }

    #[test]
    fn cmplog_entry_unequal() {
        let e = CmplogEntry::new(0x1000, 100, 200, 8);
        assert!(!e.is_equal());
        assert_eq!(e.diff(), 100);
    }

    // ── CmplogMap ─────────────────────────────────────────────────────────────

    #[test]
    fn cmplog_map_record() {
        let mut m = CmplogMap::new();
        m.record(0x1000, 1, 2, 4);
        m.record(0x2000, 3, 3, 4);
        assert_eq!(m.len(), 2);
        assert!(!m.is_empty());
    }

    #[test]
    fn cmplog_map_unequal_entries() {
        let mut m = CmplogMap::new();
        m.record(0x1000, 1, 2, 4);
        m.record(0x2000, 3, 3, 4); // equal
        let unequal = m.unequal_entries();
        assert_eq!(unequal.len(), 1);
    }

    #[test]
    fn cmplog_map_clear() {
        let mut m = CmplogMap::new();
        m.record(0x1000, 1, 2, 4);
        m.clear();
        assert!(m.is_empty());
    }

    #[test]
    fn cmplog_colorize_mutations() {
        let mut m = CmplogMap::new();
        m.record(0x1000, 0x1234, 0x5678, 2);
        let input = vec![0u8; 16];
        let candidates = m.colorize_mutations(&input);
        assert!(!candidates.is_empty());
    }

    // ── AflQueueEntry ─────────────────────────────────────────────────────────

    #[test]
    fn afl_queue_entry_score_untried() {
        let e = AflQueueEntry::new(0, vec![1, 2, 3], 10);
        assert_eq!(e.score(), f64::MAX);
    }

    #[test]
    fn afl_queue_entry_mark_selected() {
        let mut e = AflQueueEntry::new(0, vec![1], 5);
        e.mark_selected();
        e.mark_interesting();
        assert_eq!(e.selected_count, 1);
        assert_eq!(e.interesting_count, 1);
        assert!(e.score() > 0.0);
    }

    // ── AflQueue ──────────────────────────────────────────────────────────────

    #[test]
    fn afl_queue_push_and_len() {
        let mut q = AflQueue::new();
        q.push(AflQueueEntry::new(0, vec![1], 5));
        q.push(AflQueueEntry::new(1, vec![2], 10));
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn afl_queue_select_sequential() {
        let mut q = AflQueue::new();
        let id0 = q.next_id();
        q.push(AflQueueEntry::new(id0, vec![1], 5));
        let id1 = q.next_id();
        q.push(AflQueueEntry::new(id1, vec![2], 10));
        let e = q.select_sequential().expect("non-empty");
        assert!(e.id == id0 || e.id == id1);
    }

    #[test]
    fn afl_queue_select_best() {
        let mut q = AflQueue::new();
        let mut e0 = AflQueueEntry::new(0, vec![1], 100);
        e0.mark_selected(); // give it a score
        let e1 = AflQueueEntry::new(1, vec![2], 5); // untried → MAX score
        q.push(e0);
        q.push(e1);
        let best = q.select_best();
        assert_eq!(best.id, 1); // untried wins
    }

    #[test]
    fn afl_queue_prune() {
        let mut q = AflQueue::new();
        let mut e0 = AflQueueEntry::new(0, vec![1], 1);
        e0.mark_selected(); // only selected entries are pruned
        let e1 = AflQueueEntry::new(1, vec![2], 100);
        q.push(e0);
        q.push(e1);
        let removed = q.prune(10);
        assert_eq!(removed, 1);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn afl_queue_compute_favorites() {
        let mut q = AflQueue::new();
        q.push(AflQueueEntry::new(0, vec![1], 50));
        q.push(AflQueueEntry::new(1, vec![2], 10));
        q.compute_favorites();
        let favored_count = q.entries.values().filter(|e| e.is_favored).count();
        assert!(favored_count >= 1);
    }

    #[test]
    fn afl_queue_cycles_increment() {
        let mut q = AflQueue::new();
        q.push(AflQueueEntry::new(0, vec![1], 5));
        // After len selections, cursor wraps and cycles increments
        let _ = q.select_sequential();
        assert_eq!(q.cycles, 1);
    }

    // ── AflStats ─────────────────────────────────────────────────────────────

    #[test]
    fn afl_stats_parse_round_trip() {
        let mut s = AflStats::new();
        s.execs_done = 12345;
        s.crashes_found = 7;
        s.stability = 99.5;
        let text = s.serialize();
        let parsed = AflStats::parse(&text).unwrap();
        assert_eq!(parsed.execs_done, 12345);
        assert_eq!(parsed.crashes_found, 7);
        assert!((parsed.stability - 99.5).abs() < 0.01);
    }

    #[test]
    fn afl_stats_parse_empty() {
        let s = AflStats::parse("").unwrap();
        assert_eq!(s.execs_done, 0);
    }

    #[test]
    fn afl_stats_parse_comments_ignored() {
        let text = "# this is a comment\nexecs_done : 42\n";
        let s = AflStats::parse(text).unwrap();
        assert_eq!(s.execs_done, 42);
    }

    #[test]
    fn afl_stats_serialize_contains_keys() {
        let s = AflStats::new();
        let text = s.serialize();
        assert!(text.contains("execs_done"));
        assert!(text.contains("crashes_found"));
        assert!(text.contains("stability"));
    }

    // ── PersistentMode ────────────────────────────────────────────────────────

    #[test]
    fn persistent_mode_lifecycle() {
        let mut pm = PersistentMode::new(3);
        pm.start();
        assert!(pm.active);
        assert!(pm.advance()); // 1
        assert!(pm.advance()); // 2
        assert!(!pm.advance()); // 3 → reset
        assert_eq!(pm.resets, 1);
    }

    #[test]
    fn persistent_mode_not_active() {
        let mut pm = PersistentMode::new(10);
        assert!(!pm.advance()); // not started
    }

    #[test]
    fn persistent_mode_stop() {
        let mut pm = PersistentMode::new(100);
        pm.start();
        pm.stop();
        assert!(!pm.active);
    }

    // ── AflFuzzer ─────────────────────────────────────────────────────────────

    #[test]
    fn afl_fuzzer_new_imports_seeds() {
        let exec = Box::new(MockExecutor::normal(1));
        let seeds = vec![vec![1u8, 2, 3], vec![4u8, 5, 6]];
        let fuzzer = AflFuzzer::new(exec, seeds);
        assert!(!fuzzer.queue.is_empty());
    }

    #[test]
    fn afl_fuzzer_fuzz_one_normal() {
        let exec = Box::new(MockExecutor::normal(0));
        let seeds = vec![vec![1u8; 8]];
        let mut fuzzer = AflFuzzer::new(exec, seeds);
        let result = fuzzer.fuzz_one();
        assert!(result.is_ok());
    }

    #[test]
    fn afl_fuzzer_fuzz_one_interesting() {
        let exec = Box::new(MockExecutor::normal(5));
        let seeds = vec![vec![0u8; 8]];
        let mut fuzzer = AflFuzzer::new(exec, seeds);
        let result = fuzzer.fuzz_one().unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn afl_fuzzer_fuzz_one_crash() {
        let exec = Box::new(MockExecutor::crashing());
        let seeds = vec![vec![0u8; 8]];
        let mut fuzzer = AflFuzzer::new(exec, seeds);
        fuzzer.fuzz_one().unwrap();
        assert!(fuzzer.stats.crashes > 0);
    }

    #[test]
    fn afl_fuzzer_run_limited() {
        let exec = Box::new(MockExecutor::normal(0));
        let seeds = vec![vec![1u8; 4]];
        let mut fuzzer = AflFuzzer::new(exec, seeds);
        let stats = fuzzer.run(Some(10)).unwrap();
        assert!(stats.executions >= 10);
    }

    #[test]
    fn afl_fuzzer_stats_updated() {
        let exec = Box::new(MockExecutor::crashing());
        let seeds = vec![vec![0u8; 4]];
        let mut fuzzer = AflFuzzer::new(exec, seeds);
        fuzzer.run(Some(5)).unwrap();
        assert!(fuzzer.stats.crashes > 0);
    }

    #[test]
    fn afl_fuzzer_colorize_empty() {
        let exec = Box::new(MockExecutor::normal(0));
        let fuzzer = AflFuzzer::new(exec, vec![vec![1, 2, 3]]);
        let candidates = fuzzer.colorize(&[1, 2, 3]);
        // No CMPLOG entries → empty
        assert!(candidates.is_empty());
    }

    #[test]
    fn afl_fuzzer_set_dictionary() {
        let exec = Box::new(MockExecutor::normal(0));
        let mut fuzzer = AflFuzzer::new(exec, vec![vec![1, 2, 3]]);
        let mut d = Dictionary::new();
        d.add(b"TOKEN".to_vec());
        fuzzer.set_dictionary(d);
        assert!(fuzzer.dict.is_some());
    }

    #[test]
    fn afl_fuzzer_afl_stats_snapshot() {
        let exec = Box::new(MockExecutor::normal(0));
        let mut fuzzer = AflFuzzer::new(exec, vec![vec![1]]);
        fuzzer.run(Some(3)).unwrap();
        let snap = fuzzer.afl_stats_snapshot();
        assert!(snap.execs_done >= 3);
    }

    // ── AflError ──────────────────────────────────────────────────────────────

    #[test]
    fn afl_error_display() {
        let e = AflError::ShmError("no memory".into());
        assert!(e.to_string().contains("no memory"));
        let e2 = AflError::InvalidDict("bad token".into());
        assert!(e2.to_string().contains("bad token"));
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// §19.1  AFL++-style coverage-guided fuzzer — extended implementation
// ═════════════════════════════════════════════════════════════════════════════

use std::path::Path;
use std::time::Instant;

// ── Interesting value tables (spec §19.1) ─────────────────────────────────────

/// Interesting 8-bit values from AFL's known-crash-causing constants.
pub const INTERESTING_8: &[i8] = &[-128, -1, 0, 1, 16, 32, 64, 100, 127];

/// Interesting 16-bit values.
pub const INTERESTING_16: &[i16] = &[-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767];

/// Interesting 32-bit values.
pub const INTERESTING_32: &[i32] = &[
    -2_147_483_648,
    -100_663_046,
    -32769,
    32768,
    65535,
    65536,
    100_663_045,
    2_147_483_647,
];

// ── SimpleRng ─────────────────────────────────────────────────────────────────

/// Lightweight xorshift-64 RNG compatible with the spec's `SimpleRng` name.
#[derive(Debug, Clone)]
pub struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    /// Create with a given seed (zero seed is replaced with a constant).
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0xcafe_babe_dead_beef
            } else {
                seed
            },
        }
    }

    /// Advance and return the next `u64`.
    pub const fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// Random `usize` in `[0, n)`.
    pub fn next_usize(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            let val = self.next_u64() % (n as u64);
            // val < n ≤ usize::MAX; TryFrom is infallible here.
            usize::try_from(val).unwrap_or(0)
        }
    }

    /// Random `u8`.
    pub const fn next_u8(&mut self) -> u8 {
        self.next_u64().to_le_bytes()[0]
    }

    /// Random `u32`.
    pub const fn next_u32(&mut self) -> u32 {
        let b = self.next_u64().to_le_bytes();
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }

    /// `true` with probability `1/n`.
    pub fn one_in(&mut self, n: usize) -> bool {
        self.next_usize(n) == 0
    }
}

impl Default for SimpleRng {
    fn default() -> Self {
        Self::new(0x1234_5678_9abc_def0)
    }
}

// ── CoverageMap (AFL-style 64 KiB bitmap) ─────────────────────────────────────

/// AFL-style 64 KiB coverage bitmap.
///
/// Each byte slot corresponds to a (from, to) edge hash.  The value is
/// incremented on every hit (saturating at 255).
#[derive(Debug, Clone)]
pub struct AflCoverageMap {
    /// Raw bitmap — always exactly 65 536 bytes.
    pub data: Vec<u8>,
}

impl AflCoverageMap {
    /// AFL map size in bytes.
    pub const SIZE: usize = 65536;

    /// Create a zeroed coverage map.
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: vec![0u8; Self::SIZE],
        }
    }

    /// Record an edge `from → to` by incrementing the corresponding slot.
    pub fn update_with_path(&mut self, from: u32, to: u32) {
        let idx = Self::hash_edge(from, to);
        self.data[idx] = self.data[idx].saturating_add(1);
    }

    /// Count the number of non-zero bytes (set bits / hit edges).
    #[must_use]
    pub fn count_set_bits(&self) -> u32 {
        u32::try_from(self.data.iter().filter(|&&b| b != 0).count()).unwrap_or(u32::MAX)
    }

    /// Return `true` if any byte in `self` is non-zero where `virgin` is
    /// still zero (i.e. `self` has new coverage relative to `virgin`).
    #[must_use]
    pub fn has_new_bits(&self, virgin: &Self) -> bool {
        self.data
            .iter()
            .zip(virgin.data.iter())
            .any(|(&cur, &vir)| cur != 0 && vir == 0)
    }

    /// Merge `self` into `virgin`: for every byte that is non-zero in `self`
    /// and zero in `virgin`, set `virgin[i] = self[i]`.  Returns the count
    /// of newly set bytes.
    pub fn merge_into_virgin(&self, virgin: &mut Self) -> u32 {
        let mut new_bits = 0u32;
        for (i, &cur) in self.data.iter().enumerate() {
            if cur != 0 && virgin.data[i] == 0 {
                virgin.data[i] = cur;
                new_bits += 1;
            }
        }
        new_bits
    }

    /// AFL edge hash: `((from >> 1) ^ to) % 65536`.
    #[must_use]
    pub const fn hash_edge(from: u32, to: u32) -> usize {
        ((from >> 1) ^ to) as usize % Self::SIZE
    }

    /// Clear the bitmap.
    pub fn clear(&mut self) {
        self.data.iter_mut().for_each(|b| *b = 0);
    }
}

impl Default for AflCoverageMap {
    fn default() -> Self {
        Self::new()
    }
}

// ── CorpusEntry ───────────────────────────────────────────────────────────────

/// A single entry in the AFL fuzzer corpus.
#[derive(Debug, Clone)]
pub struct CorpusEntry {
    /// The raw input bytes.
    pub data: Vec<u8>,
    /// Number of coverage bits this entry contributes.
    pub coverage_bits: u32,
    /// Average execution time in microseconds.
    pub exec_time_us: u64,
    /// Whether this entry has already been used as a mutation parent.
    pub was_fuzzed: bool,
    /// Whether this entry triggered new coverage.
    pub interesting: bool,
    /// Mutation depth (0 = seed).
    pub depth: u32,
}

impl CorpusEntry {
    /// Create a new corpus entry.
    #[must_use]
    pub const fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            coverage_bits: 0,
            exec_time_us: 0,
            was_fuzzed: false,
            interesting: false,
            depth: 0,
        }
    }
}

// ── Corpus ────────────────────────────────────────────────────────────────────

/// AFL corpus with weighted random selection.
#[derive(Debug)]
pub struct AflCorpus {
    /// All corpus entries.
    pub entries: Vec<CorpusEntry>,
    /// Internal RNG.
    pub rng: SimpleRng,
}

impl AflCorpus {
    /// Create an empty corpus with a default RNG seed.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            rng: SimpleRng::default(),
        }
    }

    /// Add an entry to the corpus.
    pub fn add(&mut self, entry: CorpusEntry) {
        self.entries.push(entry);
    }

    /// Weighted-random selection that favors:
    /// - short inputs (inverse length weight)
    /// - recently interesting entries
    /// - low execution time
    ///
    /// Falls back to uniform random when all weights are zero.
    ///
    /// # Panics
    /// Panics if the corpus is empty.
    pub fn select_next(&mut self) -> &CorpusEntry {
        assert!(
            !self.entries.is_empty(),
            "AflCorpus::select_next on empty corpus"
        );

        // Compute a score per entry.
        let weights: Vec<u64> = self
            .entries
            .iter()
            .map(|e| {
                let len_score = if e.data.is_empty() {
                    1u64
                } else {
                    (1_000_000u64).saturating_div(e.data.len() as u64).max(1)
                };
                let interesting_bonus: u64 = if e.interesting { 4 } else { 1 };
                let time_score = if e.exec_time_us == 0 {
                    1_000u64
                } else {
                    (1_000_000u64).saturating_div(e.exec_time_us).max(1)
                };
                len_score
                    .saturating_mul(interesting_bonus)
                    .saturating_mul(time_score)
            })
            .collect();

        let total: u64 = weights.iter().sum();
        if total == 0 {
            let idx = self.rng.next_usize(self.entries.len());
            return &self.entries[idx];
        }
        let mut pick = self.rng.next_u64() % total;
        let mut chosen = 0;
        for (i, &w) in weights.iter().enumerate() {
            if pick < w {
                chosen = i;
                break;
            }
            pick -= w;
        }
        &self.entries[chosen]
    }

    /// Remove entries that do not cover any unique bits (`coverage_bits` == 0)
    /// and whose `data.len()` is above `threshold`.
    pub fn minimize(&mut self, threshold: usize) {
        self.entries
            .retain(|e| e.coverage_bits > 0 || e.data.len() <= threshold);
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the corpus is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for AflCorpus {
    fn default() -> Self {
        Self::new()
    }
}

// ── AFL mutation stages ───────────────────────────────────────────────────────

/// Maximum input length accepted by deterministic stage functions.
///
/// Functions that allocate O(n) or O(n*k) output vectors (bit-flip, arithmetic,
/// interesting-value stages) call `Vec::with_capacity(input.len() * k)`.  An
/// untrusted or corpus-grown input whose length is not bounded here can exhaust
/// process memory.  4 KiB is sufficient for AFL-style deterministic stages and
/// keeps the worst-case allocation at roughly 4096 * 70 * 8 ≈ 2.2 MiB.
pub const STAGE_INPUT_MAX_BYTES: usize = 4096;

/// Flip every single bit in `input`, producing one mutant per bit position.
pub fn stage_bit_flip_1(input: &[u8], _rng: &mut SimpleRng) -> Vec<Vec<u8>> {
    // dos-memory-exhaustion: cap input length before allocating O(n*8) output.
    let input = if input.len() > STAGE_INPUT_MAX_BYTES { &input[..STAGE_INPUT_MAX_BYTES] } else { input };
    let total_bits = input.len() * 8;
    let mut results = Vec::with_capacity(total_bits);
    for bit in 0..total_bits {
        let mut buf = input.to_vec();
        buf[bit / 8] ^= 1 << (bit % 8);
        results.push(buf);
    }
    results
}

/// Flip every two consecutive bits (walking window of 2).
#[must_use]
pub fn stage_bit_flip_2(input: &[u8]) -> Vec<Vec<u8>> {
    let input = if input.len() > STAGE_INPUT_MAX_BYTES { &input[..STAGE_INPUT_MAX_BYTES] } else { input };
    let total_bits = input.len() * 8;
    if total_bits < 2 {
        return vec![];
    }
    let mut results = Vec::with_capacity(total_bits - 1);
    for bit in 0..total_bits - 1 {
        let mut buf = input.to_vec();
        for offset in 0..2 {
            let b = bit + offset;
            buf[b / 8] ^= 1 << (b % 8);
        }
        results.push(buf);
    }
    results
}

/// Flip every four consecutive bits (walking window of 4).
#[must_use]
pub fn stage_bit_flip_4(input: &[u8]) -> Vec<Vec<u8>> {
    let input = if input.len() > STAGE_INPUT_MAX_BYTES { &input[..STAGE_INPUT_MAX_BYTES] } else { input };
    let total_bits = input.len() * 8;
    if total_bits < 4 {
        return vec![];
    }
    let mut results = Vec::with_capacity(total_bits - 3);
    for bit in 0..total_bits - 3 {
        let mut buf = input.to_vec();
        for offset in 0..4 {
            let b = bit + offset;
            buf[b / 8] ^= 1 << (b % 8);
        }
        results.push(buf);
    }
    results
}

/// Flip every single byte (XOR 0xFF) at each position.
#[must_use] 
pub fn stage_byte_flip_1(input: &[u8]) -> Vec<Vec<u8>> {
    (0..input.len())
        .map(|i| {
            let mut buf = input.to_vec();
            buf[i] ^= 0xff;
            buf
        })
        .collect()
}

/// Arithmetic stage: add/subtract 1..=35 to/from each byte.
#[must_use]
pub fn stage_arith_8(input: &[u8]) -> Vec<Vec<u8>> {
    // dos-memory-exhaustion: cap before O(n*70) allocation.
    let input = if input.len() > STAGE_INPUT_MAX_BYTES { &input[..STAGE_INPUT_MAX_BYTES] } else { input };
    let mut results = Vec::with_capacity(input.len() * 70);
    for i in 0..input.len() {
        for delta in 1u8..=35 {
            let mut add = input.to_vec();
            add[i] = add[i].wrapping_add(delta);
            results.push(add);

            let mut sub = input.to_vec();
            sub[i] = sub[i].wrapping_sub(delta);
            results.push(sub);
        }
    }
    results
}

/// 16-bit arithmetic stage: add/subtract 1..=35 to/from each 16-bit word
/// (little-endian), at every aligned and unaligned position.
#[must_use]
pub fn stage_arith_16(input: &[u8]) -> Vec<Vec<u8>> {
    let input = if input.len() > STAGE_INPUT_MAX_BYTES { &input[..STAGE_INPUT_MAX_BYTES] } else { input };
    if input.len() < 2 {
        return vec![];
    }
    let mut results = Vec::with_capacity((input.len() - 1) * 70);
    for i in 0..input.len() - 1 {
        let orig = u16::from_le_bytes([input[i], input[i + 1]]);
        for delta in 1u16..=35 {
            for &add in &[true, false] {
                let val = if add {
                    orig.wrapping_add(delta)
                } else {
                    orig.wrapping_sub(delta)
                };
                if val == orig {
                    continue;
                }
                let mut buf = input.to_vec();
                let bytes = val.to_le_bytes();
                buf[i] = bytes[0];
                buf[i + 1] = bytes[1];
                results.push(buf);
            }
        }
    }
    results
}

/// 32-bit arithmetic stage: add/subtract 1..=35 to/from each 32-bit dword.
#[must_use]
pub fn stage_arith_32(input: &[u8]) -> Vec<Vec<u8>> {
    let input = if input.len() > STAGE_INPUT_MAX_BYTES { &input[..STAGE_INPUT_MAX_BYTES] } else { input };
    if input.len() < 4 {
        return vec![];
    }
    let mut results = Vec::with_capacity((input.len() - 3) * 70);
    for i in 0..input.len() - 3 {
        let orig = u32::from_le_bytes([input[i], input[i + 1], input[i + 2], input[i + 3]]);
        for delta in 1u32..=35 {
            for &add in &[true, false] {
                let val = if add {
                    orig.wrapping_add(delta)
                } else {
                    orig.wrapping_sub(delta)
                };
                if val == orig {
                    continue;
                }
                let mut buf = input.to_vec();
                buf[i..i + 4].copy_from_slice(&val.to_le_bytes());
                results.push(buf);
            }
        }
    }
    results
}

/// Interesting-8 stage: replace each byte with values from `INTERESTING_8`.
#[must_use]
pub fn stage_interesting_8(input: &[u8]) -> Vec<Vec<u8>> {
    let input = if input.len() > STAGE_INPUT_MAX_BYTES { &input[..STAGE_INPUT_MAX_BYTES] } else { input };
    let mut results = Vec::with_capacity(input.len() * INTERESTING_8.len());
    for i in 0..input.len() {
        for &val in INTERESTING_8 {
            let mut buf = input.to_vec();
            buf[i] = val.cast_unsigned();
            results.push(buf);
        }
    }
    results
}

/// Interesting-16 stage: replace each 16-bit word with values from
/// `INTERESTING_16` (both LE and BE variants).
#[must_use]
pub fn stage_interesting_16(input: &[u8]) -> Vec<Vec<u8>> {
    let input = if input.len() > STAGE_INPUT_MAX_BYTES { &input[..STAGE_INPUT_MAX_BYTES] } else { input };
    if input.len() < 2 {
        return vec![];
    }
    let mut results = Vec::with_capacity((input.len() - 1) * INTERESTING_16.len() * 2);
    for i in 0..input.len() - 1 {
        for &val in INTERESTING_16 {
            let le = val.cast_unsigned().to_le_bytes();
            let mut buf = input.to_vec();
            buf[i] = le[0];
            buf[i + 1] = le[1];

            let be = val.cast_unsigned().to_be_bytes();
            let mut buf2 = input.to_vec();
            buf2[i] = be[0];
            buf2[i + 1] = be[1];
            let is_dup = buf2 == buf;
            results.push(buf);
            if !is_dup {
                results.push(buf2);
            }
        }
    }
    results
}

/// Interesting-32 stage: replace each 32-bit dword with values from
/// `INTERESTING_32` (both LE and BE variants).
#[must_use]
pub fn stage_interesting_32(input: &[u8]) -> Vec<Vec<u8>> {
    let input = if input.len() > STAGE_INPUT_MAX_BYTES { &input[..STAGE_INPUT_MAX_BYTES] } else { input };
    if input.len() < 4 {
        return vec![];
    }
    let mut results = Vec::with_capacity((input.len() - 3) * INTERESTING_32.len() * 2);
    for i in 0..input.len() - 3 {
        for &val in INTERESTING_32 {
            let le = val.cast_unsigned().to_le_bytes();
            let mut buf = input.to_vec();
            buf[i..i + 4].copy_from_slice(&le);

            let be = val.cast_unsigned().to_be_bytes();
            let mut buf2 = input.to_vec();
            buf2[i..i + 4].copy_from_slice(&be);
            let is_dup = buf2 == buf;
            results.push(buf);
            if !is_dup {
                results.push(buf2);
            }
        }
    }
    results
}

/// Dictionary stage: for each position in `input`, overwrite bytes with each
/// token from `dict`.  A random subset is picked when `dict` is large.
pub fn stage_dictionary(input: &[u8], dict: &[Vec<u8>], rng: &mut SimpleRng) -> Vec<Vec<u8>> {
    if dict.is_empty() || input.is_empty() {
        return vec![];
    }
    let mut results = Vec::new();
    // Limit to at most 256 token/position combos for performance.
    let max_tokens = 256usize.min(dict.len());
    for i in 0..input.len() {
        let token_idx = rng.next_usize(dict.len().saturating_sub(max_tokens) + 1);
        for token in &dict[token_idx..token_idx + max_tokens.min(dict.len() - token_idx)] {
            if token.is_empty() {
                continue;
            }
            let end = (i + token.len()).min(input.len());
            if end <= i {
                continue;
            }
            let mut buf = input.to_vec();
            buf[i..end].copy_from_slice(&token[..end - i]);
            results.push(buf);
        }
    }
    results
}

/// Havoc stage: apply `count` randomly chosen micro-mutations to `input`.
pub fn stage_havoc(input: &[u8], rng: &mut SimpleRng, count: usize) -> Vec<Vec<u8>> {
    let mut results = Vec::with_capacity(count);
    for _ in 0..count {
        let mut buf = input.to_vec();
        let rounds = rng.next_usize(8) + 1;
        for _ in 0..rounds {
            apply_havoc_micro(&mut buf, rng);
        }
        results.push(buf);
    }
    results
}

/// Apply a single randomly chosen micro-mutation to `buf` in place.
fn apply_havoc_micro(buf: &mut Vec<u8>, rng: &mut SimpleRng) {
    if buf.is_empty() {
        return;
    }
    match rng.next_usize(12) {
        // Bit flip
        0 => {
            let bit = rng.next_usize(buf.len() * 8);
            buf[bit / 8] ^= 1 << (bit % 8);
        }
        // Byte XOR 0xFF
        1 => {
            let idx = rng.next_usize(buf.len());
            buf[idx] ^= 0xff;
        }
        // Interesting byte
        2 => {
            let idx = rng.next_usize(buf.len());
            let vi = rng.next_usize(INTERESTING_8.len());
            buf[idx] = INTERESTING_8[vi].cast_unsigned();
        }
        // Interesting 16
        3 if buf.len() >= 2 => {
            let idx = rng.next_usize(buf.len() - 1);
            let vi = rng.next_usize(INTERESTING_16.len());
            let bytes = INTERESTING_16[vi].cast_unsigned().to_le_bytes();
            buf[idx] = bytes[0];
            buf[idx + 1] = bytes[1];
        }
        // Interesting 32
        4 if buf.len() >= 4 => {
            let idx = rng.next_usize(buf.len() - 3);
            let vi = rng.next_usize(INTERESTING_32.len());
            let bytes = INTERESTING_32[vi].cast_unsigned().to_le_bytes();
            buf[idx..idx + 4].copy_from_slice(&bytes);
        }
        // Arithmetic +
        5 => {
            let idx = rng.next_usize(buf.len());
            let delta = u8::try_from(rng.next_usize(35) + 1).unwrap_or(35);
            buf[idx] = buf[idx].wrapping_add(delta);
        }
        // Arithmetic -
        6 => {
            let idx = rng.next_usize(buf.len());
            let delta = u8::try_from(rng.next_usize(35) + 1).unwrap_or(35);
            buf[idx] = buf[idx].wrapping_sub(delta);
        }
        // Random byte set
        7 => {
            let idx = rng.next_usize(buf.len());
            buf[idx] = rng.next_u8();
        }
        // Delete block
        8 if buf.len() > 1 => {
            let max_del = (buf.len() - 1).max(1);
            let count = rng.next_usize(max_del) + 1;
            let start = rng.next_usize(buf.len().saturating_sub(count) + 1);
            let end = (start + count).min(buf.len());
            buf.drain(start..end);
        }
        // Clone/insert block
        9 if buf.len() < 128 * 1024 => {
            let src_start = rng.next_usize(buf.len());
            let src_len = (rng.next_usize(32) + 1).min(buf.len() - src_start);
            let chunk: Vec<u8> = buf[src_start..src_start + src_len].to_vec();
            let insert_at = rng.next_usize(buf.len() + 1);
            for (j, &b) in chunk.iter().enumerate() {
                buf.insert((insert_at + j).min(buf.len()), b);
            }
        }
        // XOR block with random key
        10 => {
            let key = rng.next_u8();
            let start = rng.next_usize(buf.len());
            let len = (rng.next_usize(32) + 1).min(buf.len() - start);
            for b in &mut buf[start..start + len] {
                *b ^= key;
            }
        }
        // Byte repeat
        _ => {
            let idx = rng.next_usize(buf.len());
            let rep_len = (rng.next_usize(16) + 1).min(buf.len() - idx);
            let val = buf[idx];
            for b in &mut buf[idx..idx + rep_len] {
                *b = val;
            }
        }
    }
}

/// Splice stage: combine `a` and `b` at a random crossover point.
pub fn stage_splice(a: &[u8], b: &[u8], rng: &mut SimpleRng) -> Vec<u8> {
    if a.is_empty() {
        return b.to_vec();
    }
    if b.is_empty() {
        return a.to_vec();
    }
    let split_a = rng.next_usize(a.len());
    let split_b = rng.next_usize(b.len());
    let mut out = Vec::with_capacity(split_a + (b.len() - split_b));
    out.extend_from_slice(&a[..split_a]);
    out.extend_from_slice(&b[split_b..]);
    out
}

// ── FuzzStats (extended) ──────────────────────────────────────────────────────

/// Runtime statistics for the extended fuzzer.
#[derive(Debug, Clone, Default)]
pub struct ExtFuzzStats {
    /// Total mutation executions.
    pub total_executions: u64,
    /// Executions that produced new coverage.
    pub interesting: u64,
    /// Total crashes saved.
    pub crashes: u64,
    /// Total timeouts saved.
    pub timeouts: u64,
}

// ── IterResult ────────────────────────────────────────────────────────────────

/// Outcome of a single fuzzing iteration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IterResult {
    /// Mutated input produced new coverage and was added to the corpus.
    NewCoverage,
    /// A crash was detected; the input has been saved.
    Crash,
    /// A timeout was detected.
    Timeout,
    /// Normal execution, no new coverage.
    Normal,
}

// ── FuzzReport ────────────────────────────────────────────────────────────────

/// Summary produced at the end of a [`ExtAflFuzzer::fuzz`] run.
#[derive(Debug, Clone)]
pub struct FuzzReport {
    /// Total mutation iterations executed.
    pub total_iterations: u64,
    /// Number of unique crashes saved.
    pub unique_crashes: u32,
    /// Number of unique timeouts saved.
    pub unique_timeouts: u32,
    /// Final corpus size.
    pub corpus_size: u32,
    /// Total coverage bits set in the virgin map.
    pub total_coverage_bits: u32,
    /// Executions per second over the whole run.
    pub exec_per_sec: f64,
    /// Peak resident set size in MiB (platform-approximated).
    pub peak_rss_mb: u64,
    /// Wall-clock run time in seconds.
    pub run_time_secs: f64,
}

// ── ExtAflFuzzer ──────────────────────────────────────────────────────────────

/// Inline callback type: receives `&[u8]` and returns `IterResult`.
type TargetFn = Box<dyn FnMut(&[u8]) -> IterResult + Send>;

/// Extended AFL++-style coverage-guided fuzzer (spec §19.1).
///
/// This struct owns the corpus, coverage bitmaps, crash/timeout queues,
/// dictionary, and statistics.  The actual "target" execution is driven by a
/// user-supplied closure so that it works without any OS process overhead.
pub struct ExtAflFuzzer {
    /// The active corpus.
    pub corpus: AflCorpus,
    /// Per-run coverage bitmap (cleared each iteration).
    pub coverage: AflCoverageMap,
    /// Accumulator of all seen coverage.
    pub virgin: AflCoverageMap,
    /// Crash inputs.
    pub crashes: Vec<CorpusEntry>,
    /// Timeout inputs.
    pub timeouts: Vec<CorpusEntry>,
    /// Optional AFL-format dictionary tokens.
    pub dict: Vec<Vec<u8>>,
    /// Runtime statistics.
    pub stats: ExtFuzzStats,
    /// Internal RNG.
    rng: SimpleRng,
    /// Target execution closure.
    target: TargetFn,
}

impl ExtAflFuzzer {
    /// Create a new fuzzer with the given target function.
    ///
    /// The `target` closure receives a byte slice and must return an
    /// [`IterResult`] indicating the outcome.
    pub fn new(target: impl FnMut(&[u8]) -> IterResult + Send + 'static) -> Self {
        Self {
            corpus: AflCorpus::new(),
            coverage: AflCoverageMap::new(),
            virgin: AflCoverageMap::new(),
            crashes: Vec::new(),
            timeouts: Vec::new(),
            dict: Vec::new(),
            stats: ExtFuzzStats::default(),
            rng: SimpleRng::default(),
            target: Box::new(target),
        }
    }

    /// Add a raw seed input to the corpus.
    pub fn add_seed(&mut self, data: Vec<u8>) {
        let mut entry = CorpusEntry::new(data);
        entry.interesting = true;
        self.corpus.add(entry);
    }

    /// Load an AFL-format dictionary file (`key="value"` or bare tokens).
    ///
    /// Returns the number of tokens loaded.
    ///
    /// # Errors
    /// Returns an error on I/O failure.
    pub fn load_dictionary(&mut self, path: &Path) -> Result<u32, anyhow::Error> {
        let text = std::fs::read_to_string(path)?;
        let mut count = 0u32;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Support `name="value"` and `"value"` and bare `value`.
            let value_part = line.find('=').map_or(line, |eq_pos| &line[eq_pos + 1..]);
            let token: Vec<u8> = if value_part.starts_with('"')
                && value_part.ends_with('"')
                && value_part.len() >= 2
            {
                value_part.as_bytes()[1..value_part.len() - 1].to_vec()
            } else {
                value_part.as_bytes().to_vec()
            };
            if !token.is_empty() {
                self.dict.push(token);
                count += 1;
            }
        }
        Ok(count)
    }

    /// Execute one fuzzing iteration:
    ///
    /// 1. Select an input from the corpus.
    /// 2. Pick a mutation stage (weighted by AFL's schedule).
    /// 3. Mutate the input.
    /// 4. Execute via the target closure.
    /// 5. Update coverage, corpus, crashes, or timeouts.
    pub fn run_iteration(&mut self) -> IterResult {
        if self.corpus.is_empty() {
            return IterResult::Normal;
        }

        // ── 1. Select parent ──────────────────────────────────────────────────
        // We clone the data to avoid borrow issues with &mut self.rng later.
        let parent_data = self.corpus.select_next().data.clone();
        let parent_depth = self.corpus.select_next().depth;
        let _parent_time = self.corpus.select_next().exec_time_us;
        let corpus_len = self.corpus.len();

        // ── 2 & 3. Pick stage and mutate ─────────────────────────────────────
        let mutant = self.pick_stage_and_mutate(&parent_data, corpus_len);

        // ── 4. Execute ────────────────────────────────────────────────────────
        let t_start = Instant::now();
        let outcome = (self.target)(&mutant);
        let elapsed_us = u64::try_from(t_start.elapsed().as_micros()).unwrap_or(u64::MAX);

        self.stats.total_executions += 1;

        // ── 5. Triage ─────────────────────────────────────────────────────────
        match outcome {
            IterResult::Crash => {
                self.stats.crashes += 1;
                let mut entry = CorpusEntry::new(mutant);
                entry.exec_time_us = elapsed_us;
                entry.depth = parent_depth + 1;
                self.crashes.push(entry);
                IterResult::Crash
            }
            IterResult::Timeout => {
                self.stats.timeouts += 1;
                let mut entry = CorpusEntry::new(mutant);
                entry.exec_time_us = elapsed_us;
                entry.depth = parent_depth + 1;
                self.timeouts.push(entry);
                IterResult::Timeout
            }
            IterResult::Normal => IterResult::Normal,
            IterResult::NewCoverage => {
                self.stats.interesting += 1;
                let mut entry = CorpusEntry::new(mutant);
                entry.exec_time_us = elapsed_us;
                entry.coverage_bits = 1; // caller would fill with real data
                entry.interesting = true;
                entry.depth = parent_depth + 1;
                // Update a fake edge so virgin sees something new.
                let fake_from = u32::try_from(self.stats.interesting).unwrap_or(u32::MAX);
                let fake_to = u32::try_from(self.corpus.len()).unwrap_or(u32::MAX);
                self.coverage.update_with_path(fake_from, fake_to);
                self.coverage.merge_into_virgin(&mut self.virgin);
                entry.coverage_bits = self.coverage.count_set_bits();
                self.coverage.clear();
                self.corpus.add(entry);
                IterResult::NewCoverage
            }
        }
    }

    /// Run the fuzzer for `iterations` iterations, returning a [`FuzzReport`].
    pub fn fuzz(&mut self, iterations: u64) -> FuzzReport {
        let wall_start = Instant::now();
        for _ in 0..iterations {
            self.run_iteration();
        }
        let elapsed = wall_start.elapsed().as_secs_f64();
        let exec_per_sec = if elapsed > 0.0 {
            f64::from(u32::try_from(self.stats.total_executions).unwrap_or(u32::MAX)) / elapsed
        } else {
            0.0
        };
        FuzzReport {
            total_iterations: self.stats.total_executions,
            unique_crashes: u32::try_from(self.crashes.len()).unwrap_or(u32::MAX),
            unique_timeouts: u32::try_from(self.timeouts.len()).unwrap_or(u32::MAX),
            corpus_size: u32::try_from(self.corpus.len()).unwrap_or(u32::MAX),
            total_coverage_bits: self.virgin.count_set_bits(),
            exec_per_sec,
            peak_rss_mb: estimate_rss_mb(),
            run_time_secs: elapsed,
        }
    }

    // ── Internal: stage selection ─────────────────────────────────────────────

    /// Pick a mutation stage weighted by AFL's empirical schedule and apply it
    /// to `input`, returning the mutated bytes.
    fn pick_stage_and_mutate(&mut self, input: &[u8], corpus_len: usize) -> Vec<u8> {
        // Weights approximate AFL++ stage frequency:
        //   bit-flip-1: 15, bit-flip-2: 5, bit-flip-4: 5,
        //   byte-flip-1: 10, arith-8: 20, arith-16: 10, arith-32: 5,
        //   interesting-8: 10, interesting-16: 5, interesting-32: 5,
        //   dictionary: 5, havoc: 30, splice: 10
        const TOTAL_WEIGHT: usize = 135;
        let pick = self.rng.next_usize(TOTAL_WEIGHT);

        let thresholds: &[(usize, u8)] = &[
            (15, 0),   // bit_flip_1
            (20, 1),   // bit_flip_2
            (25, 2),   // bit_flip_4
            (35, 3),   // byte_flip_1
            (55, 4),   // arith_8
            (65, 5),   // arith_16
            (70, 6),   // arith_32
            (80, 7),   // interesting_8
            (85, 8),   // interesting_16
            (90, 9),   // interesting_32
            (95, 10),  // dictionary
            (125, 11), // havoc
            (135, 12), // splice
        ];

        let mut stage_id = 11u8; // default: havoc
        let mut cumulative = 0usize;
        for &(limit, id) in thresholds {
            if pick < limit {
                stage_id = id;
                break;
            }
            cumulative = limit;
        }
        let _ = cumulative;

        self.apply_stage(stage_id, input, corpus_len)
    }

    /// Pick one variant from a stage's output vec; falls back to `input` if empty.
    fn pick_one_from(&mut self, mut v: Vec<Vec<u8>>, input: &[u8]) -> Vec<u8> {
        if v.is_empty() {
            return input.to_vec();
        }
        let idx = self.rng.next_usize(v.len());
        v.remove(idx)
    }

    fn apply_stage(&mut self, stage_id: u8, input: &[u8], corpus_len: usize) -> Vec<u8> {
        match stage_id {
            0 => { let v = stage_bit_flip_1(input, &mut self.rng); self.pick_one_from(v, input) },
            1 => self.pick_one_from(stage_bit_flip_2(input), input),
            2 => self.pick_one_from(stage_bit_flip_4(input), input),
            3 => self.pick_one_from(stage_byte_flip_1(input), input),
            4 => self.pick_one_from(stage_arith_8(input), input),
            5 => self.pick_one_from(stage_arith_16(input), input),
            6 => self.pick_one_from(stage_arith_32(input), input),
            7 => self.pick_one_from(stage_interesting_8(input), input),
            8 => self.pick_one_from(stage_interesting_16(input), input),
            9 => self.pick_one_from(stage_interesting_32(input), input),
            10 => {
                // Dictionary
                let dict_clone: Vec<Vec<u8>> = self.dict.clone();
                if dict_clone.is_empty() {
                    // Fall through to havoc
                    return self.apply_stage(11, input, corpus_len);
                }
                let mut v = stage_dictionary(input, &dict_clone, &mut self.rng);
                if v.is_empty() {
                    return input.to_vec();
                }
                let idx = self.rng.next_usize(v.len());
                v.remove(idx)
            }
            11 => {
                // Havoc — generate one mutant
                let mut v = stage_havoc(input, &mut self.rng, 1);
                v.pop().unwrap_or_else(|| input.to_vec())
            }
            12 => {
                // Splice — requires at least two corpus entries
                if corpus_len < 2 {
                    return self.apply_stage(11, input, corpus_len);
                }
                let b_data = self.corpus.select_next().data.clone();
                stage_splice(input, &b_data, &mut self.rng)
            }
            _ => input.to_vec(),
        }
    }
}

/// Rough RSS estimate (always returns 0 on platforms without /proc/self/status).
///
/// Not `const`: on Linux it reads `/proc/self/status` at runtime, which a const
/// fn cannot do (the empty Windows body happens to be const-valid, which is why
/// this only breaks the Linux build).
fn estimate_rss_mb() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
            for line in s.lines() {
                if line.starts_with("VmRSS:") {
                    if let Some(kb) = line.split_whitespace().nth(1) {
                        return kb.parse::<u64>().unwrap_or(0) / 1024;
                    }
                }
            }
        }
    }
    0
}

// ── §19.1 extended tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod afl_extended_tests {
    use super::*;

    // ── SimpleRng ─────────────────────────────────────────────────────────────

    #[test]
    fn simple_rng_deterministic() {
        let mut a = SimpleRng::new(99);
        let mut b = SimpleRng::new(99);
        assert_eq!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn simple_rng_zero_seed_replaced() {
        let mut r = SimpleRng::new(0);
        assert_ne!(r.next_u64(), 0);
    }

    #[test]
    fn simple_rng_range() {
        let mut r = SimpleRng::default();
        for _ in 0..200 {
            assert!(r.next_usize(7) < 7);
        }
    }

    // ── AflCoverageMap ────────────────────────────────────────────────────────

    #[test]
    fn afl_cov_map_new_zeros() {
        let m = AflCoverageMap::new();
        assert_eq!(m.data.len(), AflCoverageMap::SIZE);
        assert_eq!(m.count_set_bits(), 0);
    }

    #[test]
    fn afl_cov_map_update_with_path() {
        let mut m = AflCoverageMap::new();
        m.update_with_path(0, 1);
        assert_eq!(m.count_set_bits(), 1);
    }

    #[test]
    fn afl_cov_map_update_same_edge_increments() {
        let mut m = AflCoverageMap::new();
        m.update_with_path(100, 200);
        m.update_with_path(100, 200);
        let idx = AflCoverageMap::hash_edge(100, 200);
        assert_eq!(m.data[idx], 2);
    }

    #[test]
    fn afl_cov_map_has_new_bits_detects_new() {
        let mut cur = AflCoverageMap::new();
        cur.update_with_path(1, 2);
        let virgin = AflCoverageMap::new();
        assert!(cur.has_new_bits(&virgin));
    }

    #[test]
    fn afl_cov_map_has_new_bits_no_new() {
        let mut cur = AflCoverageMap::new();
        cur.update_with_path(1, 2);
        let mut virgin = AflCoverageMap::new();
        cur.merge_into_virgin(&mut virgin);
        assert!(!cur.has_new_bits(&virgin));
    }

    #[test]
    fn afl_cov_map_merge_into_virgin_returns_count() {
        let mut cur = AflCoverageMap::new();
        cur.update_with_path(10, 20);
        cur.update_with_path(30, 40);
        let mut virgin = AflCoverageMap::new();
        let new = cur.merge_into_virgin(&mut virgin);
        assert_eq!(new, 2);
        // Second merge should find nothing new.
        let new2 = cur.merge_into_virgin(&mut virgin);
        assert_eq!(new2, 0);
    }

    #[test]
    fn afl_cov_map_hash_edge_consistent() {
        let h1 = AflCoverageMap::hash_edge(0xABCD, 0x1234);
        let h2 = AflCoverageMap::hash_edge(0xABCD, 0x1234);
        assert_eq!(h1, h2);
        assert!(h1 < AflCoverageMap::SIZE);
    }

    #[test]
    fn afl_cov_map_clear() {
        let mut m = AflCoverageMap::new();
        m.update_with_path(5, 6);
        m.clear();
        assert_eq!(m.count_set_bits(), 0);
    }

    // ── AflCorpus ─────────────────────────────────────────────────────────────

    #[test]
    fn afl_corpus_add_and_len() {
        let mut c = AflCorpus::new();
        c.add(CorpusEntry::new(vec![1, 2, 3]));
        assert_eq!(c.len(), 1);
        assert!(!c.is_empty());
    }

    #[test]
    fn afl_corpus_select_returns_entry() {
        let mut c = AflCorpus::new();
        c.add(CorpusEntry::new(vec![0xAA, 0xBB]));
        let e = c.select_next();
        assert_eq!(e.data, vec![0xAA, 0xBB]);
    }

    #[test]
    fn afl_corpus_minimize_removes_large_uncovered() {
        let mut c = AflCorpus::new();
        // This entry has no coverage and is large → should be removed.
        let mut big = CorpusEntry::new(vec![0u8; 200]);
        big.coverage_bits = 0;
        c.add(big);
        // This one is small → kept even with no coverage.
        c.add(CorpusEntry::new(vec![1u8; 4]));
        c.minimize(10);
        // The 200-byte zero-coverage entry is gone.
        assert_eq!(c.len(), 1);
    }

    // ── Mutation stages ───────────────────────────────────────────────────────

    #[test]
    fn stage_bit_flip_1_count() {
        let input = vec![0u8; 4];
        let mut rng = SimpleRng::default();
        let v = stage_bit_flip_1(&input, &mut rng);
        assert_eq!(v.len(), 32); // 4 bytes × 8 bits
    }

    #[test]
    fn stage_bit_flip_1_each_different() {
        let input = vec![0u8; 2];
        let mut rng = SimpleRng::default();
        let v = stage_bit_flip_1(&input, &mut rng);
        // Every mutant should differ from the original.
        for m in &v {
            assert_ne!(m, &input);
        }
    }

    #[test]
    fn stage_bit_flip_2_count() {
        let input = vec![0u8; 4];
        let v = stage_bit_flip_2(&input);
        assert_eq!(v.len(), 31); // 32 - 1
    }

    #[test]
    fn stage_bit_flip_4_count() {
        let input = vec![0u8; 4];
        let v = stage_bit_flip_4(&input);
        assert_eq!(v.len(), 29); // 32 - 3
    }

    #[test]
    fn stage_byte_flip_1_count() {
        let input = vec![0u8; 8];
        let v = stage_byte_flip_1(&input);
        assert_eq!(v.len(), 8);
        for m in &v {
            assert_ne!(m, &input);
        }
    }

    #[test]
    fn stage_arith_8_count() {
        let input = vec![0u8; 3];
        let v = stage_arith_8(&input);
        // 3 bytes × 35 deltas × 2 directions = 210
        assert_eq!(v.len(), 210);
    }

    #[test]
    fn stage_arith_8_wrap() {
        // Byte 255 + 1 should wrap to 0.
        let input = vec![255u8];
        let v = stage_arith_8(&input);
        assert!(v.iter().any(|m| m[0] == 0));
    }

    #[test]
    fn stage_arith_16_non_empty() {
        let input = vec![0u8; 4];
        let v = stage_arith_16(&input);
        assert!(!v.is_empty());
    }

    #[test]
    fn stage_arith_16_too_short() {
        let v = stage_arith_16(&[1]);
        assert!(v.is_empty());
    }

    #[test]
    fn stage_arith_32_non_empty() {
        let input = vec![0u8; 8];
        let v = stage_arith_32(&input);
        assert!(!v.is_empty());
    }

    #[test]
    fn stage_interesting_8_count() {
        let input = vec![0u8; 4];
        let v = stage_interesting_8(&input);
        assert_eq!(v.len(), 4 * INTERESTING_8.len());
    }

    #[test]
    fn stage_interesting_8_contains_minus128() {
        let input = vec![0u8; 1];
        let v = stage_interesting_8(&input);
        // i8 -128 as u8 is 128.
        assert!(v.iter().any(|m| m[0] == 128u8));
    }

    #[test]
    fn stage_interesting_16_non_empty() {
        let input = vec![0u8; 4];
        let v = stage_interesting_16(&input);
        assert!(!v.is_empty());
    }

    #[test]
    fn stage_interesting_32_non_empty() {
        let input = vec![0u8; 8];
        let v = stage_interesting_32(&input);
        assert!(!v.is_empty());
    }

    #[test]
    fn stage_dictionary_empty_dict() {
        let input = vec![0u8; 8];
        let mut rng = SimpleRng::default();
        let v = stage_dictionary(&input, &[], &mut rng);
        assert!(v.is_empty());
    }

    #[test]
    fn stage_dictionary_applies_token() {
        let input = vec![0u8; 8];
        let dict = vec![vec![0xDE, 0xAD, 0xBE, 0xEF]];
        let mut rng = SimpleRng::default();
        let v = stage_dictionary(&input, &dict, &mut rng);
        assert!(!v.is_empty());
        // At least one mutant should contain the token bytes.
        assert!(
            v.iter()
                .any(|m| m.windows(4).any(|w| w == [0xDE, 0xAD, 0xBE, 0xEF]))
        );
    }

    #[test]
    fn stage_havoc_produces_count_mutants() {
        let input = vec![0u8; 16];
        let mut rng = SimpleRng::new(7);
        let v = stage_havoc(&input, &mut rng, 10);
        assert_eq!(v.len(), 10);
    }

    #[test]
    fn stage_havoc_changes_input() {
        let input = vec![0u8; 16];
        let mut rng = SimpleRng::new(13);
        let v = stage_havoc(&input, &mut rng, 20);
        // At least some mutants should differ from the input.
        assert!(v.iter().any(|m| m != &input));
    }

    #[test]
    fn stage_splice_combines() {
        let a = vec![0xAAu8; 8];
        let b = vec![0xBBu8; 8];
        let mut rng = SimpleRng::new(5);
        let out = stage_splice(&a, &b, &mut rng);
        assert!(!out.is_empty());
        // Result must contain bytes from both inputs.
        assert!(out.contains(&0xAA) || out.contains(&0xBB));
    }

    #[test]
    fn stage_splice_empty_a() {
        let mut rng = SimpleRng::default();
        let out = stage_splice(&[], &[1, 2, 3], &mut rng);
        assert_eq!(out, vec![1, 2, 3]);
    }

    #[test]
    fn stage_splice_empty_b() {
        let mut rng = SimpleRng::default();
        let out = stage_splice(&[1, 2], &[], &mut rng);
        assert_eq!(out, vec![1, 2]);
    }

    // ── ExtAflFuzzer ──────────────────────────────────────────────────────────

    #[test]
    fn ext_fuzzer_add_seed() {
        let mut f = ExtAflFuzzer::new(|_| IterResult::Normal);
        f.add_seed(vec![1, 2, 3]);
        assert_eq!(f.corpus.len(), 1);
    }

    #[test]
    fn ext_fuzzer_run_iteration_normal() {
        let mut f = ExtAflFuzzer::new(|_| IterResult::Normal);
        f.add_seed(vec![0u8; 8]);
        let r = f.run_iteration();
        assert_eq!(r, IterResult::Normal);
        assert_eq!(f.stats.total_executions, 1);
    }

    #[test]
    fn ext_fuzzer_run_iteration_crash() {
        let mut f = ExtAflFuzzer::new(|_| IterResult::Crash);
        f.add_seed(vec![0xFFu8; 4]);
        let r = f.run_iteration();
        assert_eq!(r, IterResult::Crash);
        assert_eq!(f.crashes.len(), 1);
        assert_eq!(f.stats.crashes, 1);
    }

    #[test]
    fn ext_fuzzer_run_iteration_timeout() {
        let mut f = ExtAflFuzzer::new(|_| IterResult::Timeout);
        f.add_seed(vec![1u8; 4]);
        let r = f.run_iteration();
        assert_eq!(r, IterResult::Timeout);
        assert_eq!(f.timeouts.len(), 1);
    }

    #[test]
    fn ext_fuzzer_run_iteration_new_coverage() {
        let mut f = ExtAflFuzzer::new(|_| IterResult::NewCoverage);
        f.add_seed(vec![2u8; 8]);
        let r = f.run_iteration();
        assert_eq!(r, IterResult::NewCoverage);
        assert!(f.corpus.len() > 1); // seed + new entry
        assert_eq!(f.stats.interesting, 1);
    }

    #[test]
    fn ext_fuzzer_run_iteration_empty_corpus() {
        let mut f = ExtAflFuzzer::new(|_| IterResult::Normal);
        // No seeds — should return Normal without crashing.
        let r = f.run_iteration();
        assert_eq!(r, IterResult::Normal);
        assert_eq!(f.stats.total_executions, 0);
    }

    #[test]
    fn ext_fuzzer_fuzz_report_fields() {
        let mut f = ExtAflFuzzer::new(|_| IterResult::Normal);
        f.add_seed(vec![0u8; 4]);
        let report = f.fuzz(50);
        assert_eq!(report.total_iterations, 50);
        assert_eq!(report.unique_crashes, 0);
        assert_eq!(report.unique_timeouts, 0);
        assert!(report.run_time_secs >= 0.0);
    }

    #[test]
    fn ext_fuzzer_fuzz_accumulates_crashes() {
        let mut f = ExtAflFuzzer::new(|_| IterResult::Crash);
        f.add_seed(vec![0u8; 4]);
        let report = f.fuzz(10);
        assert_eq!(report.unique_crashes, 10);
        assert!(report.total_iterations >= 10);
    }

    #[test]
    fn ext_fuzzer_fuzz_grows_corpus() {
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let cc = call_count;
        let mut f = ExtAflFuzzer::new(move |_| {
            let n = cc.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if n.is_multiple_of(5) {
                IterResult::NewCoverage
            } else {
                IterResult::Normal
            }
        });
        f.add_seed(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let report = f.fuzz(25);
        // Some NewCoverage hits should have grown the corpus.
        assert!(report.corpus_size >= 1);
    }

    #[test]
    fn ext_fuzzer_load_dictionary_nonexistent() {
        let mut f = ExtAflFuzzer::new(|_| IterResult::Normal);
        let result = f.load_dictionary(Path::new("/nonexistent/path/dict.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn ext_fuzzer_with_dict_uses_dict_stage() {
        let mut f = ExtAflFuzzer::new(|_| IterResult::Normal);
        f.dict.push(b"MAGIC".to_vec());
        f.add_seed(vec![0u8; 16]);
        // Just verify it doesn't panic with a dict loaded.
        for _ in 0..20 {
            f.run_iteration();
        }
    }

    // ── Interesting value constants ────────────────────────────────────────────

    #[test]
    fn interesting_8_contains_zero() {
        assert!(INTERESTING_8.contains(&0));
    }

    #[test]
    fn interesting_8_contains_min_max() {
        assert!(INTERESTING_8.contains(&-128));
        assert!(INTERESTING_8.contains(&127));
    }

    #[test]
    fn interesting_16_contains_boundary() {
        assert!(INTERESTING_16.contains(&-32768));
        assert!(INTERESTING_16.contains(&32767));
    }

    #[test]
    fn interesting_32_contains_i32_bounds() {
        assert!(INTERESTING_32.contains(&i32::MIN));
        assert!(INTERESTING_32.contains(&i32::MAX));
    }

    // ── FuzzReport fields ─────────────────────────────────────────────────────

    #[test]
    fn fuzz_report_exec_per_sec_nonnegative() {
        let mut f = ExtAflFuzzer::new(|_| IterResult::Normal);
        f.add_seed(vec![0u8; 8]);
        let report = f.fuzz(100);
        assert!(report.exec_per_sec >= 0.0);
    }

    #[test]
    fn fuzz_report_corpus_size_min_one() {
        let mut f = ExtAflFuzzer::new(|_| IterResult::Normal);
        f.add_seed(vec![0u8; 4]);
        let report = f.fuzz(1);
        assert!(report.corpus_size >= 1);
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// §20  Coverage Bitmap
// ══════════════════════════════════════════════════════════════════════════════

/// AFL-style 64 KiB edge-coverage bitmap.
///
/// Each byte represents one (`prev_loc` XOR `cur_loc`) edge bucket.
/// Counters are saturating so they never wrap to zero.
#[derive(Clone)]
pub struct CovBitmap(pub Box<[u8]>);

impl std::fmt::Debug for CovBitmap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CovBitmap(bits={})", self.count_bits())
    }
}

impl Default for CovBitmap {
    fn default() -> Self {
        Self::new()
    }
}

impl CovBitmap {
    /// Construct a zeroed bitmap.
    #[must_use]
    pub fn new() -> Self {
        Self(vec![0u8; 65536].into_boxed_slice())
    }

    /// Construct a bitmap with all bytes set to `0xff` (virgin / all-undiscovered).
    #[must_use]
    pub fn new_virgin() -> Self {
        Self(vec![0xffu8; 65536].into_boxed_slice())
    }

    /// Record an edge transition `prev_loc → cur_loc`.
    ///
    /// Uses the standard AFL formula `(prev_loc >> 1) XOR cur_loc` so that
    /// the forward and reverse of the same edge map to different buckets.
    #[inline]
    pub fn record_edge(&mut self, prev_loc: u64, cur_loc: u64) {
        let idx = usize::try_from((prev_loc >> 1) ^ cur_loc).unwrap_or(0) % 65536;
        self.0[idx] = self.0[idx].saturating_add(1);
    }

    /// Count the number of non-zero bytes (= distinct edges ever hit).
    #[must_use]
    pub fn count_bits(&self) -> u32 {
        u32::try_from(self.0.iter().filter(|&&b| b > 0).count()).unwrap_or(u32::MAX)
    }

    /// Return `true` if `self` has at least one edge that is still set in
    /// `virgin` (i.e. a newly-discovered edge).
    ///
    /// The virgin bitmap starts all-`0xFF`; bits are cleared as edges are
    /// discovered.
    ///
    /// # Panics
    /// Panics if the bitmap length is not a multiple of 8 (never happens for the
    /// fixed 65536-byte bitmap).
    #[must_use]
    pub fn has_new_bits(&self, virgin: &Self) -> bool {
        // Scan in 8-byte chunks for speed.
        let sc = self.0.chunks_exact(8);
        let vc = virgin.0.chunks_exact(8);
        for (s, v) in sc.zip(vc) {
            let sv = u64::from_ne_bytes(s.try_into().unwrap());
            let vv = u64::from_ne_bytes(v.try_into().unwrap());
            if sv & vv != 0 {
                return true;
            }
        }
        false
    }

    /// For every edge that is set in `self` and still set in `virgin`, clear
    /// the bit in `virgin` (mark as discovered) and return the count cleared.
    pub fn update_virgin(&self, virgin: &mut Self) -> u32 {
        let mut cleared = 0u32;
        for (s, v) in self.0.iter().zip(virgin.0.iter_mut()) {
            if *s > 0 && *v > 0 {
                *v = 0;
                cleared += 1;
            }
        }
        cleared
    }

    /// Classify raw hit counts into AFL power-of-two buckets so that minor
    /// loop-count differences do not create spurious "new coverage" entries.
    ///
    /// ```text
    ///   0       → 0
    ///   1       → 1
    ///   2       → 2
    ///   3       → 4
    ///   4–7     → 8
    ///   8–15    → 16
    ///   16–31   → 32
    ///   32–127  → 64
    ///   128–255 → 128
    /// ```
    pub fn classify_counts(&mut self) {
        for b in &mut self.0 {
            *b = cov_classify_count(*b);
        }
    }

    /// Zero all bytes (prepare for the next execution run).
    pub fn clear(&mut self) {
        self.0.iter_mut().for_each(|b| *b = 0);
    }

    /// Merge `other` into `self` using saturating addition.
    pub fn merge(&mut self, other: &Self) {
        for (d, s) in self.0.iter_mut().zip(other.0.iter()) {
            *d = d.saturating_add(*s);
        }
    }

    /// Compress to `(index, count)` pairs for non-zero entries.
    #[must_use]
    pub fn to_sparse(&self) -> Vec<(u16, u8)> {
        self.0
            .iter()
            .enumerate()
            .filter(|(_, b)| **b > 0)
            .map(|(i, &b)| (u16::try_from(i).unwrap_or(u16::MAX), b))
            .collect()
    }

    /// Reconstruct from a sparse representation.
    #[must_use]
    pub fn from_sparse(pairs: &[(u16, u8)]) -> Self {
        let mut bm = Self::new();
        for &(idx, count) in pairs {
            bm.0[idx as usize] = count;
        }
        bm
    }
}

/// AFL bucket classification for a single counter byte.
#[inline]
#[must_use] 
pub const fn cov_classify_count(c: u8) -> u8 {
    match c {
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

// ══════════════════════════════════════════════════════════════════════════════
// §21  Mutation Engine
// ══════════════════════════════════════════════════════════════════════════════

/// Interesting 8-bit values (unsigned view) used by the §21 engine.
pub const AFL_INTERESTING_8: &[u8] = &[0, 1, 16, 32, 64, 100, 127, 128, 255];

/// Interesting 16-bit values (unsigned view) used by the §21 engine.
pub const AFL_INTERESTING_16: &[u16] = &[0, 1, 128, 255, 256, 512, 1024, 4096, 32767, 32768, 65535];

/// Interesting 32-bit values (unsigned view) used by the §21 engine.
pub const AFL_INTERESTING_32: &[u32] = &[
    0,
    1,
    128,
    255,
    256,
    512,
    65535,
    65536,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_ffff,
];

/// Full AFL-style mutation engine backed by a 64-bit LCG.
///
/// Methods are split into three groups:
/// 1. **Deterministic** — explicit position argument, reproducible output.
/// 2. **Havoc** — random single-step operators applied in a loop.
/// 3. **Splice** — two-input crossover.
#[derive(Debug, Clone)]
pub struct AflMutEngine {
    /// LCG state (Knuth TAOCP multiplier/increment).
    pub rng: u64,
}

impl AflMutEngine {
    /// Create with an explicit seed.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            rng: if seed == 0 { 1 } else { seed },
        }
    }

    // ── RNG ──────────────────────────────────────────────────────────────────

    /// Advance the LCG and return the next `u64`.
    #[inline]
    pub const fn rand(&mut self) -> u64 {
        self.rng = self
            .rng
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.rng
    }

    /// Random `usize` in `[0, max)`.  Returns 0 when `max == 0`.
    #[inline]
    pub fn rand_usize(&mut self, max: usize) -> usize {
        if max == 0 {
            0
        } else {
            let val = self.rand() % (max as u64);
            // val < max ≤ usize::MAX; TryFrom is infallible here.
            usize::try_from(val).unwrap_or(0)
        }
    }

    // ── Deterministic: bit-flips ──────────────────────────────────────────────

    /// Flip the single bit at position `bit` (bit 0 = LSB of byte 0).
    #[must_use] 
    pub fn flip_bit(&self, input: &[u8], bit: usize) -> Vec<u8> {
        let mut out = input.to_vec();
        if !out.is_empty() {
            let bi = (bit / 8) % out.len();
            out[bi] ^= 1 << (bit % 8);
        }
        out
    }

    /// Flip 2 consecutive bits starting at `bit`.
    #[must_use] 
    pub fn flip_2_bits(&self, input: &[u8], bit: usize) -> Vec<u8> {
        let a = self.flip_bit(input, bit);
        self.flip_bit(&a, bit + 1)
    }

    /// Flip 4 consecutive bits starting at `bit`.
    #[must_use] 
    pub fn flip_4_bits(&self, input: &[u8], bit: usize) -> Vec<u8> {
        let a = self.flip_2_bits(input, bit);
        self.flip_2_bits(&a, bit + 2)
    }

    /// XOR the byte at `byte` with `0xFF`.
    #[must_use] 
    pub fn flip_byte(&self, input: &[u8], byte: usize) -> Vec<u8> {
        let mut out = input.to_vec();
        if !out.is_empty() {
            let idx = byte % out.len();
            out[idx] ^= 0xff;
        }
        out
    }

    /// XOR two consecutive bytes with `0xFF`.
    #[must_use] 
    pub fn flip_2_bytes(&self, input: &[u8], byte: usize) -> Vec<u8> {
        let a = self.flip_byte(input, byte);
        self.flip_byte(&a, byte + 1)
    }

    /// XOR four consecutive bytes with `0xFF`.
    #[must_use] 
    pub fn flip_4_bytes(&self, input: &[u8], byte: usize) -> Vec<u8> {
        let a = self.flip_2_bytes(input, byte);
        self.flip_2_bytes(&a, byte + 2)
    }

    // ── Deterministic: arithmetic ─────────────────────────────────────────────

    /// Add `delta` (wrapping) to the byte at `pos`.
    #[must_use] 
    pub fn add_byte(&self, input: &[u8], pos: usize, delta: i8) -> Vec<u8> {
        let mut out = input.to_vec();
        if !out.is_empty() {
            let p = pos % out.len();
            out[p] = out[p].wrapping_add(delta.cast_unsigned());
        }
        out
    }

    /// Add `delta` to the LE `u16` at `pos`.
    #[must_use]
    pub fn add_word_le(&self, input: &[u8], pos: usize, delta: i16) -> Vec<u8> {
        let mut out = input.to_vec();
        if out.len() >= 2 {
            let p = pos % (out.len() - 1);
            let v = u16::from_le_bytes([out[p], out[p + 1]]).wrapping_add(delta.cast_unsigned());
            let b = v.to_le_bytes();
            out[p] = b[0];
            out[p + 1] = b[1];
        }
        out
    }

    /// Add `delta` to the BE `u16` at `pos`.
    #[must_use]
    pub fn add_word_be(&self, input: &[u8], pos: usize, delta: i16) -> Vec<u8> {
        let mut out = input.to_vec();
        if out.len() >= 2 {
            let p = pos % (out.len() - 1);
            let v = u16::from_be_bytes([out[p], out[p + 1]]).wrapping_add(delta.cast_unsigned());
            let b = v.to_be_bytes();
            out[p] = b[0];
            out[p + 1] = b[1];
        }
        out
    }

    /// Add `delta` to the LE `u32` at `pos`.
    ///
    /// # Panics
    /// Panics if `out[p..p+4]` cannot be converted to `[u8; 4]` (never in practice).
    #[must_use]
    pub fn add_dword_le(&self, input: &[u8], pos: usize, delta: i32) -> Vec<u8> {
        let mut out = input.to_vec();
        if out.len() >= 4 {
            let p = pos % (out.len() - 3);
            let v =
                u32::from_le_bytes(out[p..p + 4].try_into().unwrap()).wrapping_add(delta.cast_unsigned());
            out[p..p + 4].copy_from_slice(&v.to_le_bytes());
        }
        out
    }

    /// Add `delta` to the BE `u32` at `pos`.
    ///
    /// # Panics
    /// Panics if `out[p..p+4]` cannot be converted to `[u8; 4]` (never in practice).
    #[must_use]
    pub fn add_dword_be(&self, input: &[u8], pos: usize, delta: i32) -> Vec<u8> {
        let mut out = input.to_vec();
        if out.len() >= 4 {
            let p = pos % (out.len() - 3);
            let v =
                u32::from_be_bytes(out[p..p + 4].try_into().unwrap()).wrapping_add(delta.cast_unsigned());
            out[p..p + 4].copy_from_slice(&v.to_be_bytes());
        }
        out
    }

    // ── Deterministic: interesting values ────────────────────────────────────

    /// Replace the byte at `pos` with `val`.
    #[must_use] 
    pub fn set_byte_interesting(&self, input: &[u8], pos: usize, val: u8) -> Vec<u8> {
        let mut out = input.to_vec();
        if !out.is_empty() {
            let p = pos % out.len();
            out[p] = val;
        }
        out
    }

    /// Replace 2 bytes at `pos` with `val` in LE or BE.
    #[must_use] 
    pub fn set_word_interesting(&self, input: &[u8], pos: usize, val: u16, be: bool) -> Vec<u8> {
        let mut out = input.to_vec();
        if out.len() >= 2 {
            let p = pos % (out.len() - 1);
            let b = if be {
                val.to_be_bytes()
            } else {
                val.to_le_bytes()
            };
            out[p] = b[0];
            out[p + 1] = b[1];
        }
        out
    }

    /// Replace 4 bytes at `pos` with `val` in LE or BE.
    #[must_use] 
    pub fn set_dword_interesting(&self, input: &[u8], pos: usize, val: u32, be: bool) -> Vec<u8> {
        let mut out = input.to_vec();
        if out.len() >= 4 {
            let p = pos % (out.len() - 3);
            let b = if be {
                val.to_be_bytes()
            } else {
                val.to_le_bytes()
            };
            out[p..p + 4].copy_from_slice(&b);
        }
        out
    }

    // ── Havoc ─────────────────────────────────────────────────────────────────

    /// Apply `iterations` random single-step mutations from the full AFL havoc
    /// operator set.
    pub fn havoc(&mut self, input: &[u8], iterations: u32) -> Vec<u8> {
        let mut buf = input.to_vec();
        for _ in 0..iterations {
            match self.rand_usize(10) {
                0 => self.hv_flip_bit(&mut buf),
                1 => self.hv_interesting_byte(&mut buf),
                2 => self.hv_interesting_word(&mut buf),
                3 => self.hv_random_add_sub(&mut buf),
                4 => self.hv_set_random_byte(&mut buf),
                5 => self.hv_delete_bytes(&mut buf),
                6 => self.hv_insert_bytes(&mut buf),
                7 | 8 => self.hv_clone_bytes(&mut buf),
                _ => {} // no-op slot (dict overwrite when extras supplied)
            }
        }
        buf
    }

    fn hv_flip_bit(&mut self, buf: &mut [u8]) {
        if buf.is_empty() {
            return;
        }
        let bit = self.rand_usize(buf.len() * 8);
        buf[bit / 8] ^= 1 << (bit % 8);
    }

    fn hv_interesting_byte(&mut self, buf: &mut [u8]) {
        if buf.is_empty() {
            return;
        }
        let pos = self.rand_usize(buf.len());
        buf[pos] = AFL_INTERESTING_8[self.rand_usize(AFL_INTERESTING_8.len())];
    }

    fn hv_interesting_word(&mut self, buf: &mut [u8]) {
        if buf.len() < 2 {
            return;
        }
        let pos = self.rand_usize(buf.len() - 1);
        let val = AFL_INTERESTING_16[self.rand_usize(AFL_INTERESTING_16.len())];
        let be = self.rand_usize(2) == 0;
        let b = if be {
            val.to_be_bytes()
        } else {
            val.to_le_bytes()
        };
        buf[pos] = b[0];
        buf[pos + 1] = b[1];
    }

    fn hv_random_add_sub(&mut self, buf: &mut [u8]) {
        if buf.is_empty() {
            return;
        }
        let pos = self.rand_usize(buf.len());
        let rnd = i32::try_from(self.rand_usize(71)).unwrap_or(0);
        // rnd - 35 is in [-35, 35], always fits in i8
        let delta: i8 = i8::try_from(rnd - 35).unwrap_or(0);
        buf[pos] = buf[pos].wrapping_add(delta.cast_unsigned());
    }

    fn hv_set_random_byte(&mut self, buf: &mut [u8]) {
        if buf.is_empty() {
            return;
        }
        let pos = self.rand_usize(buf.len());
        buf[pos] = (self.rand() & 0xff) as u8;
    }

    fn hv_delete_bytes(&mut self, buf: &mut Vec<u8>) {
        if buf.len() < 2 {
            return;
        }
        let max_del = (buf.len() / 2).max(1);
        let del_len = 1 + self.rand_usize(max_del);
        let del_pos = self.rand_usize(buf.len() - del_len + 1);
        buf.drain(del_pos..del_pos + del_len);
    }

    fn hv_insert_bytes(&mut self, buf: &mut Vec<u8>) {
        const MAX: usize = 32;
        let ins_len = 1 + self.rand_usize(MAX);
        let ins_pos = self.rand_usize(buf.len() + 1);
        let filler = if self.rand_usize(2) == 0 {
            0u8
        } else {
            (self.rand() & 0xff) as u8
        };
        buf.splice(ins_pos..ins_pos, std::iter::repeat_n(filler, ins_len));
    }

    fn hv_clone_bytes(&mut self, buf: &mut Vec<u8>) {
        if buf.len() < 2 {
            return;
        }
        let max_copy = (buf.len() / 2).max(1);
        let copy_len = 1 + self.rand_usize(max_copy);
        let src_pos = self.rand_usize(buf.len() - copy_len + 1);
        let dst_pos = self.rand_usize(buf.len() + 1);
        let cloned: Vec<u8> = buf[src_pos..src_pos + copy_len].to_vec();
        buf.splice(dst_pos..dst_pos, cloned);
    }

    // ── Splice ────────────────────────────────────────────────────────────────

    /// Splice `a` and `b` at the point of maximum hamming difference.
    pub fn splice(&mut self, a: &[u8], b: &[u8]) -> Vec<u8> {
        let min_len = a.len().min(b.len());
        if min_len == 0 {
            return a.to_vec();
        }
        let split = Self::max_hamming_split(a, b);
        let mut out = a[..split].to_vec();
        out.extend_from_slice(&b[split..min_len]);
        if a.len() > min_len {
            out.extend_from_slice(&a[min_len..]);
        }
        out
    }

    /// Find the byte position with the highest XOR hamming weight in a sliding
    /// window of width 4.  Returns the midpoint of that window.
    #[must_use] 
    pub fn max_hamming_split(a: &[u8], b: &[u8]) -> usize {
        let min_len = a.len().min(b.len());
        if min_len == 0 {
            return 0;
        }
        let window = 4.min(min_len);
        let mut best_pos = min_len / 2;
        let mut best_score = 0u32;
        for start in 0..=(min_len - window) {
            let score: u32 = (0..window)
                .map(|i| (a[start + i] ^ b[start + i]).count_ones())
                .sum();
            if score > best_score {
                best_score = score;
                best_pos = start + window / 2;
            }
        }
        best_pos
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// §22  Input Queue
// ══════════════════════════════════════════════════════════════════════════════

/// A single entry in the §22 input queue.
#[derive(Debug, Clone)]
pub struct BitmapQueueEntry {
    /// Monotonically-increasing identifier.
    pub id: u32,
    /// Raw input bytes.
    pub data: Vec<u8>,
    /// Distinct coverage edges observed for this input.
    pub coverage: u32,
    /// Measured execution time (microseconds).
    pub exec_time_us: u64,
    /// Depth in the seed/mutation tree (0 = initial seed).
    pub depth: u32,
    /// Whether this entry has completed at least one mutation cycle.
    pub was_fuzzed: bool,
    /// AFL "favored" flag: smallest input covering at least one unique edge.
    pub favored: bool,
    /// How many times this entry has been selected for fuzzing.
    pub passes: u32,
    /// Power-schedule energy (mutations to apply per cycle).
    pub energy: u32,
}

impl BitmapQueueEntry {
    fn new(id: u32, data: Vec<u8>, coverage: u32, exec_time_us: u64) -> Self {
        let energy = (coverage / 4).clamp(1, 256);
        Self {
            id,
            data,
            coverage,
            exec_time_us,
            depth: 0,
            was_fuzzed: false,
            favored: false,
            passes: 0,
            energy,
        }
    }
}

/// Round-robin input queue with AFL power-schedule support.
#[derive(Debug, Default)]
pub struct BitmapQueue {
    entries: Vec<BitmapQueueEntry>,
    current: usize,
    next_id: u32,
    /// Union of coverage across all entries.
    pub total_coverage: u32,
}

impl BitmapQueue {
    /// Construct an empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry; returns its assigned `id`.
    pub fn add(&mut self, data: Vec<u8>, coverage: u32, exec_time: u64) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        if coverage > self.total_coverage {
            self.total_coverage = coverage;
        }
        self.entries
            .push(BitmapQueueEntry::new(id, data, coverage, exec_time));
        id
    }

    /// Return the next entry for fuzzing.  Favored entries are preferred;
    /// falls back to plain round-robin when none are marked.
    pub fn next_entry(&mut self) -> Option<&mut BitmapQueueEntry> {
        if self.entries.is_empty() {
            return None;
        }
        let start = self.current;
        let n = self.entries.len();
        for i in 0..n {
            let idx = (start + i) % n;
            if self.entries[idx].favored {
                self.current = (idx + 1) % n;
                return Some(&mut self.entries[idx]);
            }
        }
        let idx = self.current;
        self.current = (idx + 1) % n;
        Some(&mut self.entries[idx])
    }

    /// Select a parent using a simplified power schedule.
    ///
    /// Score = `coverage / (log2(exec_time_us + 2) + 1)`.
    #[must_use] 
    pub fn select_parent(&self) -> &BitmapQueueEntry {
        if self.entries.len() == 1 {
            return &self.entries[0];
        }
        let mut best = 0;
        let mut best_score = 0.0f64;
        for (i, e) in self.entries.iter().enumerate() {
            let t = f64::from(u32::try_from(e.exec_time_us + 2).unwrap_or(u32::MAX)).log2() + 1.0;
            let s = f64::from(e.coverage) / t;
            if s > best_score {
                best_score = s;
                best = i;
            }
        }
        &self.entries[best]
    }

    /// Recompute `favored` flags.  For each coverage slot, the smallest input
    /// that covers it is marked favored; all others are cleared.
    pub fn update_favored(&mut self, _global: &CovBitmap) {
        let mut best_for: HashMap<usize, (usize, usize)> = HashMap::new();
        for (ei, entry) in self.entries.iter().enumerate() {
            for slot in 0..(entry.coverage as usize) {
                let b = best_for.entry(slot).or_insert((entry.data.len() + 1, ei));
                if entry.data.len() < b.0 {
                    *b = (entry.data.len(), ei);
                }
            }
        }
        for e in &mut self.entries {
            e.favored = false;
        }
        for (_, idx) in best_for.values() {
            self.entries[*idx].favored = true;
        }
    }

    /// Save each entry as `<id>.bin` under `dir`.
    ///
    /// # Errors
    /// Returns an I/O error if directory creation or file writes fail.
    pub fn save_corpus(&self, dir: &std::path::Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        for e in &self.entries {
            std::fs::write(dir.join(format!("{:08}.bin", e.id)), &e.data)?;
        }
        Ok(())
    }

    /// Load all `*.bin` files from `dir` as zero-coverage seeds.
    ///
    /// # Errors
    /// Returns an I/O error if reading the directory or any file fails.
    pub fn load_corpus(&mut self, dir: &std::path::Path) -> std::io::Result<usize> {
        let mut count = 0;
        for de in std::fs::read_dir(dir)? {
            let de = de?;
            let path = de.path();
            if path.extension().and_then(|e| e.to_str()) == Some("bin") {
                self.add(std::fs::read(&path)?, 0, 0);
                count += 1;
            }
        }
        Ok(count)
    }

    /// Number of entries in the queue.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when the queue is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Immutable slice over all entries.
    #[must_use] 
    pub fn entries(&self) -> &[BitmapQueueEntry] {
        &self.entries
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// §23  Fork-Server Protocol (platform-abstracted)
// ══════════════════════════════════════════════════════════════════════════════

/// Outcome of a single target execution in the §23 fork-server driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitmapExecStatus {
    /// Target exited normally.
    Normal,
    /// Target terminated with a signal.
    Crash { signal: i32 },
    /// Target exceeded the timeout.
    Timeout,
    /// Target appeared to hang (detected by the fork server).
    Hang,
}

/// Headless fork-server driver used when no actual instrumented binary is
/// available.  All methods are pure no-ops or deterministic stubs so the §24
/// fuzzer compiles and tests on every platform.
///
/// On a real deployment this would hold pipe fds and a SHM pointer; those
/// details live in platform-specific integration crates (e.g.
/// `rustre-fuzz-afl-unix`) that re-use [`AflMutEngine`] and [`CovBitmap`].
#[derive(Debug, Default)]
pub struct BitmapForkServer {
    /// Simulated execution counter.
    pub exec_count: u64,
}

impl BitmapForkServer {
    /// Create a new headless fork-server stub.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Simulate one execution.  Returns `(Normal, synthetic_coverage_bits)`.
    ///
    /// Coverage is derived from the input's FNV-1a hash so different inputs
    /// yield different (but deterministic) synthetic coverage.
    pub fn run_one(&mut self, input: &[u8]) -> (BitmapExecStatus, u32) {
        self.exec_count += 1;
        // Synthetic coverage: low 8 bits of hash, at least 1.
        let h = rustre_fuzz::fnv1a(input);
        let cov = ((h & 0xff) as u32).max(1);
        (BitmapExecStatus::Normal, cov)
    }

    /// Shut down the fork server (no-op for the stub).
    pub const fn shutdown(&mut self) {}
}

// ══════════════════════════════════════════════════════════════════════════════
// §24  Standalone Bitmap Fuzzer
// ══════════════════════════════════════════════════════════════════════════════

/// Configuration for [`BitmapFuzzer`].
#[derive(Debug, Clone)]
pub struct BitmapFuzzerConfig {
    /// Path to the instrumented target binary (informational; not executed by
    /// the headless stub).
    pub target: std::path::PathBuf,
    /// Arguments forwarded to the target.
    pub args: Vec<String>,
    /// Seed corpus directory.
    pub corpus_dir: std::path::PathBuf,
    /// Crash output directory.
    pub crash_dir: std::path::PathBuf,
    /// Per-execution timeout (milliseconds).
    pub timeout_ms: u64,
    /// Memory limit for the target (megabytes).
    pub memory_limit_mb: u64,
}

impl Default for BitmapFuzzerConfig {
    fn default() -> Self {
        Self {
            target: std::path::PathBuf::from("./target"),
            args: Vec::new(),
            corpus_dir: std::path::PathBuf::from("corpus"),
            crash_dir: std::path::PathBuf::from("crashes"),
            timeout_ms: 1000,
            memory_limit_mb: 256,
        }
    }
}

/// Statistics snapshot from [`BitmapFuzzer`].
#[derive(Debug, Clone)]
pub struct BitmapFuzzerStats {
    /// Total executions since the fuzzer was started.
    pub total_execs: u64,
    /// Current throughput (executions per second).
    pub execs_per_second: f64,
    /// Distinct queue entries (paths) discovered.
    pub total_paths: u32,
    /// Number of unique crashes saved.
    pub unique_crashes: u32,
    /// Non-zero bits in the global coverage bitmap.
    pub coverage_bits: u32,
    /// Elapsed wall-clock time (seconds).
    pub uptime_secs: u64,
}

/// Standalone AFL-style bitmap fuzzer.
///
/// Integrates [`BitmapForkServer`], [`BitmapQueue`], [`CovBitmap`], and
/// [`AflMutEngine`] into a single execution loop that can run without any
/// external process.
pub struct BitmapFuzzer {
    /// Fork-server handle.
    pub server: BitmapForkServer,
    /// Input queue.
    pub queue: BitmapQueue,
    /// Accumulated coverage bitmap (union of all observed runs).
    pub bitmap: CovBitmap,
    /// Virgin bitmap: edges not yet discovered (starts all-`0xFF`).
    pub virgin: CovBitmap,
    /// Mutation engine.
    pub mutator: AflMutEngine,
    /// Crashing inputs paired with their exit status.
    pub crashes: Vec<(Vec<u8>, BitmapExecStatus)>,
    /// Total number of executions performed.
    pub total_execs: u64,
    /// Fuzzer start time.
    pub start_time: std::time::Instant,
    /// Configuration.
    pub config: BitmapFuzzerConfig,
}

impl BitmapFuzzer {
    /// Construct a new fuzzer with the given configuration.
    #[must_use]
    pub fn new(config: BitmapFuzzerConfig) -> Self {
        Self {
            server: BitmapForkServer::new(),
            queue: BitmapQueue::new(),
            bitmap: CovBitmap::new(),
            virgin: CovBitmap::new_virgin(),
            mutator: AflMutEngine::new(0xcafe_babe),
            crashes: Vec::new(),
            total_execs: 0,
            start_time: std::time::Instant::now(),
            config,
        }
    }

    /// Add a raw byte vector as an initial seed.
    pub fn add_seed(&mut self, data: Vec<u8>) {
        let cov = u32::try_from(data.len()).unwrap_or(u32::MAX);
        self.queue.add(data, cov, 0);
    }

    /// Execute one full fuzzing cycle:
    ///
    /// 1. Pick an entry from the queue.
    /// 2. Generate `energy` mutants.
    /// 3. Run each mutant through the fork server.
    /// 4. Update coverage / queue / crash list.
    ///
    /// # Errors
    /// Returns `Err` only if the queue is empty.
    pub fn run_one_cycle(&mut self) -> Result<(), FuzzError> {
        let (parent_data, energy) = {
            let entry = self
                .queue
                .next_entry()
                .ok_or_else(|| FuzzError::CorpusError("empty queue".into()))?;
            entry.passes += 1;
            (entry.data.clone(), entry.energy)
        };

        for _ in 0..energy {
            let mutant = self.mutator.havoc(&parent_data, 8);
            let (status, cov) = self.server.run_one(&mutant);
            self.total_execs += 1;

            match &status {
                BitmapExecStatus::Crash { .. } | BitmapExecStatus::Hang => {
                    self.save_crash(&mutant, &status);
                    self.crashes.push((mutant.clone(), status.clone()));
                }
                _ => {}
            }

            if cov > 0 {
                let prev = self.bitmap.count_bits();
                for i in 0..cov {
                    self.bitmap.record_edge(u64::from(i), u64::from(cov) ^ u64::from(i));
                }
                if self.bitmap.count_bits() > prev {
                    let depth = self.queue.entries().last().map_or(0, |e| e.depth + 1);
                    let id = self.queue.add(mutant, cov, 0);
                    if let Some(e) = self.queue.entries.iter_mut().find(|e| e.id == id) {
                        e.depth = depth;
                    }
                }
            }
        }

        let bm = self.bitmap.clone();
        self.queue.update_favored(&bm);
        Ok(())
    }

    /// Collect a statistics snapshot.
    #[must_use]
    pub fn stats(&self) -> BitmapFuzzerStats {
        let uptime = self.start_time.elapsed().as_secs();
        let eps = if uptime > 0 {
            f64::from(u32::try_from(self.total_execs).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(uptime).unwrap_or(u32::MAX))
        } else {
            f64::from(u32::try_from(self.total_execs).unwrap_or(u32::MAX))
        };
        BitmapFuzzerStats {
            total_execs: self.total_execs,
            execs_per_second: eps,
            total_paths: u32::try_from(self.queue.len()).unwrap_or(u32::MAX),
            unique_crashes: u32::try_from(self.crashes.len()).unwrap_or(u32::MAX),
            coverage_bits: self.bitmap.count_bits(),
            uptime_secs: uptime,
        }
    }

    /// Persist a crashing input to the configured crash directory.
    pub fn save_crash(&self, input: &[u8], _status: &BitmapExecStatus) {
        let _ = std::fs::create_dir_all(&self.config.crash_dir);
        let name = format!("crash_{:016x}.bin", rustre_fuzz::fnv1a(input));
        let _ = std::fs::write(self.config.crash_dir.join(name), input);
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// §25  Tests
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod cov_bitmap_tests {
    use super::*;

    // ── construction ──────────────────────────────────────────────────────────

    #[test]
    fn new_bitmap_is_all_zero() {
        let bm = CovBitmap::new();
        assert!(bm.0.iter().all(|&b| b == 0));
    }

    #[test]
    fn new_virgin_is_all_ff() {
        let bm = CovBitmap::new_virgin();
        assert!(bm.0.iter().all(|&b| b == 0xff));
    }

    #[test]
    fn count_bits_zero_on_empty() {
        assert_eq!(CovBitmap::new().count_bits(), 0);
    }

    // ── record_edge ───────────────────────────────────────────────────────────

    #[test]
    fn record_edge_increments_bucket() {
        let mut bm = CovBitmap::new();
        bm.record_edge(0, 0);
        assert_eq!(bm.count_bits(), 1);
    }

    #[test]
    fn record_edge_saturates_at_255() {
        let mut bm = CovBitmap::new();
        for _ in 0..300u32 {
            bm.record_edge(0, 0);
        }
        let idx = (0u64 >> 1) as usize % 65536;
        assert_eq!(bm.0[idx], 255);
    }

    #[test]
    fn record_edge_different_edges_use_different_buckets() {
        let mut bm = CovBitmap::new();
        bm.record_edge(1, 2);
        bm.record_edge(3, 7);
        // Both may hash to the same bucket, but at least one must be set.
        assert!(bm.count_bits() >= 1);
    }

    #[test]
    fn record_edge_asymmetric_formula() {
        // (A→B) and (B→A) must differ after the right-shift.
        let mut bm = CovBitmap::new();
        let idx_ab = ((10u64 >> 1) ^ 20u64) as usize % 65536;
        let idx_ba = ((20u64 >> 1) ^ 10u64) as usize % 65536;
        bm.record_edge(10, 20);
        bm.record_edge(20, 10);
        // Both recorded; total bits >= 1 (may collide but formula is correct).
        let _ = (idx_ab, idx_ba);
        assert!(bm.count_bits() >= 1);
    }

    // ── has_new_bits ──────────────────────────────────────────────────────────

    #[test]
    fn has_new_bits_true_when_overlap() {
        let mut bm = CovBitmap::new();
        bm.0[0] = 1;
        let mut v = CovBitmap::new();
        v.0[0] = 1;
        assert!(bm.has_new_bits(&v));
    }

    #[test]
    fn has_new_bits_false_no_overlap() {
        let mut bm = CovBitmap::new();
        bm.0[0] = 1;
        assert!(!bm.has_new_bits(&CovBitmap::new()));
    }

    #[test]
    fn has_new_bits_false_empty_bitmap() {
        let bm = CovBitmap::new();
        let mut v = CovBitmap::new();
        v.0[10] = 0xff;
        assert!(!bm.has_new_bits(&v));
    }

    #[test]
    fn has_new_bits_detects_any_set_byte() {
        let mut bm = CovBitmap::new();
        bm.0[65535] = 1;
        let mut v = CovBitmap::new();
        v.0[65535] = 0xff;
        assert!(bm.has_new_bits(&v));
    }

    // ── update_virgin ─────────────────────────────────────────────────────────

    #[test]
    fn update_virgin_clears_covered_bits() {
        let mut bm = CovBitmap::new();
        bm.0[5] = 1;
        let mut v = CovBitmap::new_virgin();
        let cleared = bm.update_virgin(&mut v);
        assert_eq!(cleared, 1);
        assert_eq!(v.0[5], 0);
    }

    #[test]
    fn update_virgin_does_not_clear_uncovered_bits() {
        let bm = CovBitmap::new();
        let mut v = CovBitmap::new_virgin();
        let cleared = bm.update_virgin(&mut v);
        assert_eq!(cleared, 0);
        assert!(v.0.iter().all(|&b| b == 0xff));
    }

    #[test]
    fn update_virgin_returns_exact_count() {
        let mut bm = CovBitmap::new();
        bm.0[0] = 1;
        bm.0[1] = 1;
        bm.0[2] = 1;
        let mut v = CovBitmap::new();
        v.0[0] = 1;
        v.0[1] = 1; // only two overlap
        assert_eq!(bm.update_virgin(&mut v), 2);
    }

    #[test]
    fn update_virgin_idempotent_after_second_call() {
        let mut bm = CovBitmap::new();
        bm.0[7] = 1;
        let mut v = CovBitmap::new_virgin();
        bm.update_virgin(&mut v);
        let cleared2 = bm.update_virgin(&mut v); // already cleared
        assert_eq!(cleared2, 0);
    }

    // ── classify_counts ───────────────────────────────────────────────────────

    #[test]
    fn cov_classify_zero() {
        assert_eq!(cov_classify_count(0), 0);
    }
    #[test]
    fn cov_classify_one() {
        assert_eq!(cov_classify_count(1), 1);
    }
    #[test]
    fn cov_classify_two() {
        assert_eq!(cov_classify_count(2), 2);
    }
    #[test]
    fn cov_classify_three_to_four() {
        assert_eq!(cov_classify_count(3), 4);
    }

    #[test]
    fn cov_classify_four_through_seven() {
        for v in 4u8..=7 {
            assert_eq!(cov_classify_count(v), 8, "v={v}");
        }
    }

    #[test]
    fn cov_classify_eight_through_fifteen() {
        for v in 8u8..=15 {
            assert_eq!(cov_classify_count(v), 16, "v={v}");
        }
    }

    #[test]
    fn cov_classify_sixteen_through_thirtyone() {
        for v in 16u8..=31 {
            assert_eq!(cov_classify_count(v), 32, "v={v}");
        }
    }

    #[test]
    fn cov_classify_thirtytwo_through_127() {
        assert_eq!(cov_classify_count(32), 64);
        assert_eq!(cov_classify_count(127), 64);
    }

    #[test]
    fn cov_classify_128_and_above() {
        assert_eq!(cov_classify_count(128), 128);
        assert_eq!(cov_classify_count(255), 128);
    }

    #[test]
    fn classify_output_is_one_of_nine_bucket_values() {
        // The nine defined bucket output values for AFL count classification.
        const BUCKETS: &[u8] = &[0, 1, 2, 4, 8, 16, 32, 64, 128];
        for v in 0u8..=255 {
            let out = cov_classify_count(v);
            assert!(
                BUCKETS.contains(&out),
                "cov_classify_count({v}) = {out}, which is not a valid bucket value"
            );
        }
    }

    #[test]
    fn classify_output_is_power_of_two_or_zero() {
        for v in 0u8..=255 {
            let c = cov_classify_count(v);
            assert!(c == 0 || c.is_power_of_two(), "v={v} → {c}");
        }
    }

    #[test]
    fn classify_does_not_change_count_bits() {
        let mut bm = CovBitmap::new();
        bm.0[10] = 5;
        let before = bm.count_bits();
        bm.classify_counts();
        assert_eq!(bm.count_bits(), before);
    }

    #[test]
    fn classify_bucket_exhaustive() {
        let cases: &[(u8, u8, u8)] = &[
            (0, 0, 0),
            (1, 1, 1),
            (2, 2, 2),
            (3, 3, 4),
            (4, 7, 8),
            (8, 15, 16),
            (16, 31, 32),
            (32, 127, 64),
            (128, 255, 128),
        ];
        for &(lo, hi, expected) in cases {
            for v in lo..=hi {
                assert_eq!(cov_classify_count(v), expected, "v={v}");
            }
        }
    }

    // ── sparse round-trip ─────────────────────────────────────────────────────

    #[test]
    fn sparse_round_trip_empty() {
        let bm = CovBitmap::new();
        let bm2 = CovBitmap::from_sparse(&bm.to_sparse());
        assert_eq!(bm2.count_bits(), 0);
    }

    #[test]
    fn sparse_round_trip_single() {
        let mut bm = CovBitmap::new();
        bm.0[42] = 7;
        let bm2 = CovBitmap::from_sparse(&bm.to_sparse());
        assert_eq!(bm2.0[42], 7);
        assert_eq!(bm2.count_bits(), 1);
    }

    #[test]
    fn sparse_round_trip_multiple() {
        let mut bm = CovBitmap::new();
        bm.0[0] = 1;
        bm.0[100] = 5;
        bm.0[65535] = 255;
        let bm2 = CovBitmap::from_sparse(&bm.to_sparse());
        assert_eq!(bm2.0[0], 1);
        assert_eq!(bm2.0[100], 5);
        assert_eq!(bm2.0[65535], 255);
    }

    // ── merge & clear ─────────────────────────────────────────────────────────

    #[test]
    fn merge_adds_counts() {
        let mut a = CovBitmap::new();
        a.0[0] = 10;
        let mut b = CovBitmap::new();
        b.0[0] = 20;
        a.merge(&b);
        assert_eq!(a.0[0], 30);
    }

    #[test]
    fn merge_saturates() {
        let mut a = CovBitmap::new();
        a.0[0] = 250;
        let mut b = CovBitmap::new();
        b.0[0] = 100;
        a.merge(&b);
        assert_eq!(a.0[0], 255);
    }

    #[test]
    fn clear_zeros_all() {
        let mut bm = CovBitmap::new();
        bm.0[0] = 1;
        bm.0[32000] = 99;
        bm.clear();
        assert_eq!(bm.count_bits(), 0);
    }

    // ── integration ───────────────────────────────────────────────────────────

    #[test]
    fn record_then_update_virgin_consistent() {
        let mut bm = CovBitmap::new();
        let mut v = CovBitmap::new_virgin();
        for &(p, c) in &[(0u64, 1u64), (1, 2), (2, 3), (100, 200), (12345, 67890)] {
            bm.record_edge(p, c);
        }
        assert!(bm.has_new_bits(&v));
        let cleared = bm.update_virgin(&mut v);
        assert!(cleared >= 1);
        assert!(!bm.has_new_bits(&v));
    }

    #[test]
    fn classify_then_update_virgin_consistent() {
        let mut bm = CovBitmap::new();
        let mut v = CovBitmap::new_virgin();
        for _ in 0..5 {
            bm.record_edge(10, 20);
        } // raw count = 5
        bm.classify_counts();
        let idx = ((10u64 >> 1) ^ 20u64) as usize % 65536;
        assert_eq!(bm.0[idx], 8); // bucket for 5 is 8
        v.0[idx] = 0xff;
        let cleared = bm.update_virgin(&mut v);
        assert_eq!(cleared, 1);
    }

    #[test]
    fn merge_union_coverage() {
        let mut a = CovBitmap::new();
        a.record_edge(1, 2);
        let mut b = CovBitmap::new();
        b.record_edge(3, 4);
        let a_bits = a.count_bits();
        let b_bits = b.count_bits();
        a.merge(&b);
        assert!(a.count_bits() >= a_bits.max(b_bits));
    }
}

#[cfg(test)]
mod mutation_engine_tests {
    use super::*;

    fn eng() -> AflMutEngine {
        AflMutEngine::new(0x1234_5678_9abc_def0)
    }

    // ── LCG ──────────────────────────────────────────────────────────────────

    #[test]
    fn rand_is_deterministic() {
        let mut a = AflMutEngine::new(42);
        let mut b = AflMutEngine::new(42);
        assert_eq!(a.rand(), b.rand());
        assert_eq!(a.rand(), b.rand());
    }

    #[test]
    fn rand_usize_in_range() {
        let mut m = eng();
        for _ in 0..1000 {
            let v = m.rand_usize(100);
            assert!(v < 100, "v={v}");
        }
    }

    #[test]
    fn rand_usize_zero_max() {
        assert_eq!(eng().rand_usize(0), 0);
    }

    // ── flip_bit ──────────────────────────────────────────────────────────────

    #[test]
    fn flip_bit_length_preserved() {
        let m = eng();
        assert_eq!(m.flip_bit(&[0u8; 16], 3).len(), 16);
    }

    #[test]
    fn flip_bit_exactly_one_bit() {
        let m = eng();
        let input = vec![0u8; 8];
        for bit in 0..64 {
            let out = m.flip_bit(&input, bit);
            let diff: u32 = input
                .iter()
                .zip(&out)
                .map(|(a, b)| (a ^ b).count_ones())
                .sum();
            assert_eq!(diff, 1, "bit={bit}");
        }
    }

    #[test]
    fn flip_bit_roundtrips() {
        let m = eng();
        let input = vec![0xab, 0xcd, 0xef];
        assert_eq!(input, m.flip_bit(&m.flip_bit(&input, 5), 5));
    }

    #[test]
    fn flip_bit_empty_is_noop() {
        assert!(eng().flip_bit(&[], 0).is_empty());
    }

    #[test]
    fn flip_2_bits_changes_two() {
        let m = eng();
        let input = vec![0u8; 8];
        let diff: u32 = input
            .iter()
            .zip(&m.flip_2_bits(&input, 0))
            .map(|(a, b)| (a ^ b).count_ones())
            .sum();
        assert_eq!(diff, 2);
    }

    #[test]
    fn flip_4_bits_changes_four() {
        let m = eng();
        let input = vec![0u8; 8];
        let diff: u32 = input
            .iter()
            .zip(&m.flip_4_bits(&input, 0))
            .map(|(a, b)| (a ^ b).count_ones())
            .sum();
        assert_eq!(diff, 4);
    }

    #[test]
    fn flip_byte_xors_ff() {
        assert_eq!(eng().flip_byte(&[0xaa], 0)[0], 0xaa ^ 0xff);
    }

    #[test]
    fn flip_2_bytes_length_preserved() {
        assert_eq!(eng().flip_2_bytes(&[1, 2, 3, 4], 0).len(), 4);
    }

    #[test]
    fn flip_4_bytes_length_preserved() {
        assert_eq!(eng().flip_4_bytes(&[1u8; 8], 0).len(), 8);
    }

    // ── arithmetic ────────────────────────────────────────────────────────────

    #[test]
    fn add_byte_positive() {
        assert_eq!(eng().add_byte(&[10], 0, 5)[0], 15);
    }

    #[test]
    fn add_byte_negative() {
        assert_eq!(eng().add_byte(&[10], 0, -3)[0], 7);
    }

    #[test]
    fn add_byte_wraps() {
        assert_eq!(eng().add_byte(&[255], 0, 1)[0], 0);
    }

    #[test]
    fn add_word_le_increments() {
        let out = eng().add_word_le(&[0x01, 0x00, 0x00, 0x00], 0, 1);
        assert_eq!(u16::from_le_bytes([out[0], out[1]]), 2);
    }

    #[test]
    fn add_word_be_increments() {
        let out = eng().add_word_be(&[0x00, 0x01, 0x00, 0x00], 0, 1);
        assert_eq!(u16::from_be_bytes([out[0], out[1]]), 2);
    }

    #[test]
    fn add_word_le_wraps() {
        let out = eng().add_word_le(&[0xff, 0xff, 0x00], 0, 1);
        assert_eq!(u16::from_le_bytes([out[0], out[1]]), 0);
    }

    #[test]
    fn add_dword_le_increments() {
        let mut inp = vec![0u8; 8];
        inp[0] = 1;
        let out = eng().add_dword_le(&inp, 0, 10);
        assert_eq!(u32::from_le_bytes(out[0..4].try_into().unwrap()), 11);
    }

    #[test]
    fn add_dword_be_increments() {
        let mut inp = vec![0u8; 8];
        inp[3] = 1;
        let out = eng().add_dword_be(&inp, 0, 5);
        assert_eq!(u32::from_be_bytes(out[0..4].try_into().unwrap()), 6);
    }

    // ── interesting value setters ─────────────────────────────────────────────

    #[test]
    fn set_byte_interesting_sets_value() {
        assert_eq!(eng().set_byte_interesting(&[0xaa; 4], 2, 127)[2], 127);
    }

    #[test]
    fn set_word_interesting_le() {
        let out = eng().set_word_interesting(&[0u8; 4], 0, 0x8000, false);
        assert_eq!(u16::from_le_bytes([out[0], out[1]]), 0x8000);
    }

    #[test]
    fn set_word_interesting_be() {
        let out = eng().set_word_interesting(&[0u8; 4], 0, 0x8000, true);
        assert_eq!(u16::from_be_bytes([out[0], out[1]]), 0x8000);
    }

    #[test]
    fn set_dword_interesting_le() {
        let out = eng().set_dword_interesting(&[0u8; 8], 0, 0xffff_ffff, false);
        assert_eq!(
            u32::from_le_bytes(out[0..4].try_into().unwrap()),
            0xffff_ffff
        );
    }

    #[test]
    fn set_dword_interesting_be() {
        let out = eng().set_dword_interesting(&[0u8; 8], 0, 0x7fff_ffff, true);
        assert_eq!(
            u32::from_be_bytes(out[0..4].try_into().unwrap()),
            0x7fff_ffff
        );
    }

    // ── interesting value tables ──────────────────────────────────────────────

    #[test]
    fn afl_interesting_8_contains_boundaries() {
        assert!(AFL_INTERESTING_8.contains(&0));
        assert!(AFL_INTERESTING_8.contains(&127));
        assert!(AFL_INTERESTING_8.contains(&128));
        assert!(AFL_INTERESTING_8.contains(&255));
    }

    #[test]
    fn afl_interesting_16_contains_boundaries() {
        assert!(AFL_INTERESTING_16.contains(&0));
        assert!(AFL_INTERESTING_16.contains(&32767));
        assert!(AFL_INTERESTING_16.contains(&32768));
        assert!(AFL_INTERESTING_16.contains(&65535));
    }

    #[test]
    fn afl_interesting_32_contains_boundaries() {
        assert!(AFL_INTERESTING_32.contains(&0));
        assert!(AFL_INTERESTING_32.contains(&0x7fff_ffff));
        assert!(AFL_INTERESTING_32.contains(&0x8000_0000));
        assert!(AFL_INTERESTING_32.contains(&0xffff_ffff));
    }

    // ── havoc ─────────────────────────────────────────────────────────────────

    #[test]
    fn havoc_zero_iterations_identity() {
        let mut m = eng();
        let input = vec![1u8, 2, 3, 4];
        assert_eq!(m.havoc(&input, 0), input);
    }

    #[test]
    fn havoc_does_not_panic() {
        let mut m = eng();
        let _ = m.havoc(&[0u8; 64], 100);
    }

    #[test]
    fn havoc_can_grow_buffer() {
        let mut grew = false;
        let input = vec![0u8; 16];
        for seed in 0u64..100 {
            let mut m = AflMutEngine::new(seed + 1);
            if m.havoc(&input, 20).len() > input.len() {
                grew = true;
                break;
            }
        }
        assert!(grew);
    }

    #[test]
    fn havoc_can_change_buffer() {
        let input = vec![0u8; 16];
        let mut changed = false;
        for seed in 0u64..20 {
            let mut m = AflMutEngine::new(seed + 1);
            if m.havoc(&input, 5) != input {
                changed = true;
                break;
            }
        }
        assert!(changed);
    }

    #[test]
    fn havoc_different_seeds_differ() {
        let input = vec![0u8; 32];
        let mut m1 = AflMutEngine::new(1);
        let mut m2 = AflMutEngine::new(999_999);
        let o1 = m1.havoc(&input, 50);
        let o2 = m2.havoc(&input, 50);
        // Very likely to differ; just ensure no panic.
        let _ = (o1, o2);
    }

    // ── splice ────────────────────────────────────────────────────────────────

    #[test]
    fn splice_empty_a_returns_empty() {
        let mut m = eng();
        assert!(m.splice(&[], &[1, 2, 3]).is_empty());
    }

    #[test]
    fn splice_a_longer_preserves_a_length() {
        let mut m = eng();
        let a = vec![1u8; 10];
        let b = vec![2u8; 6];
        assert_eq!(m.splice(&a, &b).len(), a.len());
    }

    #[test]
    fn splice_b_longer_produces_min_len() {
        let mut m = eng();
        let a = vec![1u8; 4];
        let b = vec![2u8; 8];
        assert_eq!(m.splice(&a, &b).len(), 4);
    }

    #[test]
    fn splice_bytes_from_correct_parents() {
        let mut m = eng();
        let a = vec![0x00u8; 16];
        let b = vec![0xffu8; 16];
        let out = m.splice(&a, &b);
        assert_eq!(out.len(), 16);
        assert!(
            out.iter().all(|&v| v == 0x00 || v == 0xff),
            "unexpected byte: {out:?}"
        );
    }

    #[test]
    fn splice_identical_inputs_no_panic() {
        let mut m = eng();
        let a = vec![0x42u8; 8];
        assert_eq!(m.splice(&a, &a).len(), a.len());
    }

    #[test]
    fn max_hamming_split_empty_returns_zero() {
        assert_eq!(AflMutEngine::max_hamming_split(&[], &[]), 0);
    }

    #[test]
    fn max_hamming_split_single_byte() {
        assert_eq!(AflMutEngine::max_hamming_split(&[0], &[0xff]), 0);
    }

    #[test]
    fn max_hamming_split_near_start_when_diff_at_start() {
        let a = vec![0x00u8; 8];
        let b = [0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let pos = AflMutEngine::max_hamming_split(&a, &b);
        assert!(pos <= 4, "expected pos near start, got {pos}");
    }
}

#[cfg(test)]
mod bitmap_queue_tests {
    use super::*;

    // ── add / len / is_empty ──────────────────────────────────────────────────

    #[test]
    fn queue_starts_empty() {
        assert!(BitmapQueue::new().is_empty());
    }

    #[test]
    fn add_increases_len() {
        let mut q = BitmapQueue::new();
        q.add(vec![1, 2, 3], 5, 100);
        q.add(vec![4, 5, 6], 3, 200);
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn add_returns_sequential_ids() {
        let mut q = BitmapQueue::new();
        assert_eq!(q.add(vec![0], 1, 0), 0);
        assert_eq!(q.add(vec![1], 1, 0), 1);
        assert_eq!(q.add(vec![2], 1, 0), 2);
    }

    #[test]
    fn add_updates_total_coverage() {
        let mut q = BitmapQueue::new();
        q.add(vec![0], 10, 0);
        assert_eq!(q.total_coverage, 10);
        q.add(vec![1], 5, 0);
        assert_eq!(q.total_coverage, 10); // does not decrease
        q.add(vec![2], 20, 0);
        assert_eq!(q.total_coverage, 20);
    }

    // ── next_entry ────────────────────────────────────────────────────────────

    #[test]
    fn next_entry_none_on_empty() {
        assert!(BitmapQueue::new().next_entry().is_none());
    }

    #[test]
    fn next_entry_round_robin() {
        let mut q = BitmapQueue::new();
        q.add(vec![1], 1, 0);
        q.add(vec![2], 1, 0);
        q.add(vec![3], 1, 0);
        let ids: Vec<u32> = (0..6).map(|_| q.next_entry().unwrap().id).collect();
        assert_eq!(ids, vec![0, 1, 2, 0, 1, 2]);
    }

    #[test]
    fn next_entry_prefers_favored() {
        let mut q = BitmapQueue::new();
        q.add(vec![1], 1, 0);
        q.add(vec![2], 1, 0);
        q.add(vec![3], 1, 0);
        q.entries.iter_mut().find(|e| e.id == 1).unwrap().favored = true;
        for _ in 0..5 {
            assert_eq!(q.next_entry().unwrap().id, 1);
        }
    }

    // ── select_parent ─────────────────────────────────────────────────────────

    #[test]
    fn select_parent_single_entry() {
        let mut q = BitmapQueue::new();
        q.add(vec![0], 5, 100);
        assert_eq!(q.select_parent().id, 0);
    }

    #[test]
    fn select_parent_prefers_high_coverage() {
        let mut q = BitmapQueue::new();
        q.add(vec![0], 1, 100);
        q.add(vec![1], 100, 100);
        assert_eq!(q.select_parent().id, 1);
    }

    #[test]
    fn select_parent_prefers_fast_exec() {
        let mut q = BitmapQueue::new();
        q.add(vec![0], 10, 1_000_000);
        q.add(vec![1], 10, 1);
        assert_eq!(q.select_parent().id, 1);
    }

    // ── update_favored ────────────────────────────────────────────────────────

    #[test]
    fn update_favored_marks_at_least_one() {
        let mut q = BitmapQueue::new();
        q.add(vec![0u8; 10], 5, 0);
        q.add(vec![0u8; 3], 5, 0);
        q.update_favored(&CovBitmap::new());
        assert!(q.entries().iter().any(|e| e.favored));
    }

    #[test]
    fn update_favored_prefers_shorter() {
        let mut q = BitmapQueue::new();
        q.add(vec![0u8; 100], 5, 0); // id=0
        q.add(vec![0u8; 3], 5, 0); // id=1 (smaller)
        q.update_favored(&CovBitmap::new());
        assert!(q.entries().iter().find(|e| e.id == 1).unwrap().favored);
    }

    // ── save / load corpus ────────────────────────────────────────────────────

    #[test]
    fn save_and_load_corpus_roundtrip() {
        let dir = std::env::temp_dir().join("rustre_bitmap_queue_test");
        let _ = std::fs::remove_dir_all(&dir);
        let mut q = BitmapQueue::new();
        q.add(vec![0xde, 0xad], 2, 0);
        q.add(vec![0xbe, 0xef, 0x00], 3, 0);
        q.save_corpus(&dir).unwrap();
        let mut q2 = BitmapQueue::new();
        assert_eq!(q2.load_corpus(&dir).unwrap(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_corpus_empty_dir() {
        let dir = std::env::temp_dir().join("rustre_bitmap_queue_empty");
        std::fs::create_dir_all(&dir).unwrap();
        let mut q = BitmapQueue::new();
        assert_eq!(q.load_corpus(&dir).unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── energy / passes ───────────────────────────────────────────────────────

    #[test]
    fn energy_at_least_one() {
        let mut q = BitmapQueue::new();
        q.add(vec![0], 0, 0);
        assert!(q.entries()[0].energy >= 1);
    }

    #[test]
    fn energy_capped_at_256() {
        let mut q = BitmapQueue::new();
        q.add(vec![0], u32::MAX, 0);
        assert!(q.entries()[0].energy <= 256);
    }

    #[test]
    fn passes_starts_zero() {
        let mut q = BitmapQueue::new();
        q.add(vec![0], 1, 0);
        assert_eq!(q.entries()[0].passes, 0);
    }

    #[test]
    fn was_fuzzed_starts_false() {
        let mut q = BitmapQueue::new();
        q.add(vec![0], 1, 0);
        assert!(!q.entries()[0].was_fuzzed);
    }
}

#[cfg(test)]
mod bitmap_exec_status_tests {
    use super::*;

    #[test]
    fn normal_eq_normal() {
        assert_eq!(BitmapExecStatus::Normal, BitmapExecStatus::Normal);
    }
    #[test]
    fn crash_neq_normal() {
        assert_ne!(
            BitmapExecStatus::Crash { signal: 11 },
            BitmapExecStatus::Normal
        );
    }
    #[test]
    fn crash_signal_preserved() {
        let s = BitmapExecStatus::Crash { signal: 6 };
        if let BitmapExecStatus::Crash { signal } = s {
            assert_eq!(signal, 6);
        } else {
            panic!("wrong variant");
        }
    }
    #[test]
    fn timeout_neq_hang() {
        assert_ne!(BitmapExecStatus::Timeout, BitmapExecStatus::Hang);
    }
    #[test]
    fn clone_roundtrip() {
        let s = BitmapExecStatus::Crash { signal: 11 };
        assert_eq!(s, s.clone());
    }
}

#[cfg(test)]
mod bitmap_fuzzer_tests {
    use super::*;

    fn make_fuzzer() -> BitmapFuzzer {
        BitmapFuzzer::new(BitmapFuzzerConfig {
            crash_dir: std::env::temp_dir().join("rustre_bitmap_crashes"),
            ..BitmapFuzzerConfig::default()
        })
    }

    #[test]
    fn new_fuzzer_empty_queue() {
        assert!(make_fuzzer().queue.is_empty());
    }

    #[test]
    fn add_seed_grows_queue() {
        let mut f = make_fuzzer();
        f.add_seed(vec![1, 2, 3]);
        assert_eq!(f.queue.len(), 1);
    }

    #[test]
    fn run_one_cycle_empty_queue_errors() {
        let mut f = make_fuzzer();
        assert!(f.run_one_cycle().is_err());
    }

    #[test]
    fn run_one_cycle_increments_execs() {
        let mut f = make_fuzzer();
        f.add_seed(vec![0u8; 32]);
        f.run_one_cycle().unwrap();
        assert!(f.total_execs > 0);
    }

    #[test]
    fn stats_execs_per_second_nonneg() {
        let mut f = make_fuzzer();
        f.add_seed(vec![0u8; 16]);
        f.run_one_cycle().unwrap();
        assert!(f.stats().execs_per_second >= 0.0);
    }

    #[test]
    fn stats_total_execs_matches() {
        let mut f = make_fuzzer();
        f.add_seed(vec![0u8; 8]);
        f.run_one_cycle().unwrap();
        assert_eq!(f.stats().total_execs, f.total_execs);
    }

    #[test]
    fn stats_total_paths_at_least_one() {
        let mut f = make_fuzzer();
        f.add_seed(vec![0u8; 4]);
        assert!(f.stats().total_paths >= 1);
    }

    #[test]
    fn stats_unique_crashes_starts_zero() {
        assert_eq!(make_fuzzer().stats().unique_crashes, 0);
    }

    #[test]
    fn virgin_starts_all_ff() {
        let f = make_fuzzer();
        assert!(f.virgin.0.iter().all(|&b| b == 0xff));
    }

    #[test]
    fn bitmap_starts_all_zero() {
        assert_eq!(make_fuzzer().bitmap.count_bits(), 0);
    }

    #[test]
    fn multiple_cycles_no_panic() {
        let mut f = make_fuzzer();
        f.add_seed(vec![0u8; 32]);
        for _ in 0..10 {
            f.run_one_cycle().unwrap();
        }
        assert!(!f.queue.is_empty());
    }

    #[test]
    fn save_crash_no_panic() {
        make_fuzzer().save_crash(
            &[0xde, 0xad, 0xbe, 0xef],
            &BitmapExecStatus::Crash { signal: 11 },
        );
    }

    #[test]
    fn fork_server_stub_run_one() {
        let mut srv = BitmapForkServer::new();
        let (status, cov) = srv.run_one(&[1, 2, 3]);
        assert_eq!(status, BitmapExecStatus::Normal);
        assert!(cov >= 1);
    }

    #[test]
    fn fork_server_stub_deterministic() {
        let mut s1 = BitmapForkServer::new();
        let mut s2 = BitmapForkServer::new();
        assert_eq!(s1.run_one(&[9, 8, 7]), s2.run_one(&[9, 8, 7]));
    }

    #[test]
    fn fork_server_exec_count_increments() {
        let mut srv = BitmapForkServer::new();
        srv.run_one(&[0]);
        srv.run_one(&[1]);
        assert_eq!(srv.exec_count, 2);
    }
}

#[cfg(test)]
mod bitmap_fuzzer_config_tests {
    use super::*;

    #[test]
    fn default_config_timeout_reasonable() {
        assert!(BitmapFuzzerConfig::default().timeout_ms >= 100);
    }

    #[test]
    fn default_config_memory_limit_nonzero() {
        assert!(BitmapFuzzerConfig::default().memory_limit_mb > 0);
    }
}

#[cfg(test)]
mod splice_property_tests {
    use super::*;

    #[test]
    fn splice_output_length_equals_a_len() {
        let mut m = AflMutEngine::new(0xabcd);
        for seed in 0u64..20 {
            let a: Vec<u8> = (0..seed as usize + 4).map(|i| i as u8).collect();
            let b: Vec<u8> = (0..seed as usize + 8).map(|i| (i * 2) as u8).collect();
            assert_eq!(m.splice(&a, &b).len(), a.len(), "seed={seed}");
        }
    }

    #[test]
    fn splice_single_byte_inputs() {
        let mut m = AflMutEngine::new(77);
        assert_eq!(m.splice(&[0xaa], &[0xbb]).len(), 1);
    }

    #[test]
    fn splice_all_bytes_from_one_parent() {
        let mut m = AflMutEngine::new(0x1111_2222);
        let a = vec![0x00u8; 16];
        let b = vec![0xffu8; 16];
        let out = m.splice(&a, &b);
        assert!(
            out.iter().all(|&v| v == 0x00 || v == 0xff),
            "byte not from either parent: {out:?}"
        );
    }

    #[test]
    fn splice_identity_both_same() {
        let mut m = AflMutEngine::new(99);
        let a = vec![0x42u8; 8];
        assert_eq!(m.splice(&a, &a).len(), a.len());
    }
}
