//! Custom mutator layer for in-process libFuzzer-style fuzzing.
//!
//! Provides:
//! * [`MutatorPlugin`] trait — custom mutate + crossover.
//! * [`MutationStrategy`] enum — `ByteFlip`, `BitFlip`, Insert, Delete, Splice,
//!   `DictEntry`.
//! * [`DictionaryEntry`] — a dictionary token with weight and hit count.
//! * [`MutatorChain`] — composes multiple plugins into a priority-weighted chain.
//! * Standard plugin implementations: [`ByteFlipMutator`], [`BitFlipMutator`],
//!   [`InsertMutator`], [`DeleteMutator`], [`SpliceMutator`],
//!   [`DictEntryMutator`], [`ArithmeticMutator`].

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── MutatorError ─────────────────────────────────────────────────────────────

/// Errors produced by the mutator layer.
#[derive(Debug, Error)]
pub enum MutatorError {
    /// Input is empty and the mutator requires at least one byte.
    #[error("empty input")]
    EmptyInput,
    /// The mutator could not produce a valid output.
    #[error("mutation failed: {0}")]
    MutationFailed(String),
    /// A required dictionary is empty.
    #[error("empty dictionary")]
    EmptyDictionary,
    /// Input exceeds the configured maximum size.
    #[error("input too large: {actual} > {limit}")]
    TooLarge { actual: usize, limit: usize },
}

// ─── MutatorPlugin trait ──────────────────────────────────────────────────────

/// Interface for a custom mutator plugin.
pub trait MutatorPlugin: Send + Sync + fmt::Debug {
    /// Produce one mutated variant of `input`.
    ///
    /// `seed` drives the internal PRNG.  `max_size` is the upper bound on the
    /// returned length (0 = unlimited).
    ///
    /// # Errors
    ///
    /// Returns [`MutatorError`] if mutation fails.
    fn custom_mutate(
        &self,
        input: &[u8],
        seed: u64,
        max_size: usize,
    ) -> Result<Vec<u8>, MutatorError>;

    /// Produce a child by crossing over `parent_a` and `parent_b`.
    ///
    /// The default implementation takes the first half of `a` and the second
    /// half of `b`.
    ///
    /// # Errors
    ///
    /// Returns [`MutatorError`] if crossover fails.
    fn custom_crossover(
        &self,
        parent_a: &[u8],
        parent_b: &[u8],
        seed: u64,
    ) -> Result<Vec<u8>, MutatorError> {
        let mut rng = Rng::new(seed);
        if parent_a.is_empty() {
            return Ok(parent_b.to_vec());
        }
        let split = (rng.range(parent_a.len() as u64)) as usize;
        let mut out = Vec::with_capacity(split + parent_b.len());
        out.extend_from_slice(&parent_a[..split]);
        out.extend_from_slice(parent_b);
        Ok(out)
    }

    /// Short name of this plugin.
    fn name(&self) -> &str;

    /// Suggested relative weight for use in [`MutatorChain`].
    fn weight(&self) -> u32 {
        1
    }
}

// ─── MutationStrategy ─────────────────────────────────────────────────────────

/// Enumeration of available mutation strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MutationStrategy {
    /// Flip one or more bytes (XOR with 0xFF).
    ByteFlip,
    /// Flip a single bit.
    BitFlip,
    /// Insert random bytes.
    Insert,
    /// Delete a chunk of bytes.
    Delete,
    /// Splice two inputs at a random point.
    Splice,
    /// Replace a chunk with a dictionary token.
    DictEntry,
    /// Arithmetic addition/subtraction on a word or dword.
    Arithmetic,
    /// Replace a chunk with an interesting value (boundary integers).
    InterestingValue,
    /// Duplicate a chunk within the input.
    ChunkCopy,
}

impl MutationStrategy {
    /// Return all available strategies.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::ByteFlip,
            Self::BitFlip,
            Self::Insert,
            Self::Delete,
            Self::Splice,
            Self::DictEntry,
            Self::Arithmetic,
            Self::InterestingValue,
            Self::ChunkCopy,
        ]
    }
}

impl fmt::Display for MutationStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::ByteFlip => "byte_flip",
            Self::BitFlip => "bit_flip",
            Self::Insert => "insert",
            Self::Delete => "delete",
            Self::Splice => "splice",
            Self::DictEntry => "dict_entry",
            Self::Arithmetic => "arithmetic",
            Self::InterestingValue => "interesting_value",
            Self::ChunkCopy => "chunk_copy",
        };
        write!(f, "{s}")
    }
}

// ─── DictionaryEntry ──────────────────────────────────────────────────────────

/// A single token in the mutator dictionary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DictionaryEntry {
    /// Token bytes.
    pub token: Vec<u8>,
    /// Human-readable label.
    pub label: String,
    /// Selection weight (higher = more frequently selected).
    pub weight: u32,
    /// Number of times this entry has been selected.
    pub hit_count: u64,
}

impl DictionaryEntry {
    /// Create a new entry with default weight 1.
    #[must_use]
    pub fn new(token: Vec<u8>, label: impl Into<String>) -> Self {
        Self {
            token,
            label: label.into(),
            weight: 1,
            hit_count: 0,
        }
    }

    /// Create with an explicit weight.
    #[must_use]
    pub fn with_weight(token: Vec<u8>, label: impl Into<String>, weight: u32) -> Self {
        Self {
            token,
            label: label.into(),
            weight,
            hit_count: 0,
        }
    }

    /// Record a selection.
    pub const fn record_hit(&mut self) {
        self.hit_count += 1;
    }
}

impl fmt::Display for DictionaryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} ({}x, weight={})",
            self.token, self.hit_count, self.weight
        )
    }
}

// ─── Rng (local) ──────────────────────────────────────────────────────────────

/// Minimal xorshift64 PRNG (independent of other crate state).
pub struct Rng {
    s: u64,
}

impl Rng {
    #[must_use] 
    pub const fn new(seed: u64) -> Self {
        Self {
            s: if seed == 0 { 0xbad_c0de } else { seed },
        }
    }

    pub const fn next(&mut self) -> u64 {
        let mut x = self.s;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.s = x;
        x
    }

    pub const fn range(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }

    pub const fn bool(&mut self) -> bool {
        self.next() & 1 == 0
    }
}

// ─── Interesting values ───────────────────────────────────────────────────────

const INTERESTING_U8: &[u8] = &[0, 1, 127, 128, 255];
const INTERESTING_U16: &[u16] = &[0, 1, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff];
const INTERESTING_U32: &[u32] = &[
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

// ─── Standard plugin implementations ─────────────────────────────────────────

/// Mutator that flips one or more bytes (XOR with 0xFF).
#[derive(Debug, Clone, Default)]
pub struct ByteFlipMutator;

impl MutatorPlugin for ByteFlipMutator {
    fn custom_mutate(
        &self,
        input: &[u8],
        seed: u64,
        _max_size: usize,
    ) -> Result<Vec<u8>, MutatorError> {
        if input.is_empty() {
            return Err(MutatorError::EmptyInput);
        }
        let mut rng = Rng::new(seed);
        let mut out = input.to_vec();
        let count = (rng.range(4) + 1) as usize;
        let pos = (rng.range(out.len() as u64)) as usize;
        let end = (pos + count).min(out.len());
        for b in &mut out[pos..end] {
            *b ^= 0xFF;
        }
        Ok(out)
    }
    fn name(&self) -> &'static str {
        "byte_flip"
    }
    fn weight(&self) -> u32 {
        3
    }
}

/// Mutator that flips a single bit.
#[derive(Debug, Clone, Default)]
pub struct BitFlipMutator;

impl MutatorPlugin for BitFlipMutator {
    fn custom_mutate(
        &self,
        input: &[u8],
        seed: u64,
        _max_size: usize,
    ) -> Result<Vec<u8>, MutatorError> {
        if input.is_empty() {
            return Err(MutatorError::EmptyInput);
        }
        let mut rng = Rng::new(seed);
        let mut out = input.to_vec();
        let byte_pos = (rng.range(out.len() as u64)) as usize;
        let bit_pos = (rng.range(8)) as u8;
        out[byte_pos] ^= 1 << bit_pos;
        Ok(out)
    }
    fn name(&self) -> &'static str {
        "bit_flip"
    }
    fn weight(&self) -> u32 {
        2
    }
}

/// Mutator that inserts random bytes at a random position.
#[derive(Debug, Clone, Default)]
pub struct InsertMutator;

impl MutatorPlugin for InsertMutator {
    fn custom_mutate(
        &self,
        input: &[u8],
        seed: u64,
        max_size: usize,
    ) -> Result<Vec<u8>, MutatorError> {
        let mut rng = Rng::new(seed);
        let count = (rng.range(32) + 1) as usize;
        let pos = (rng.range((input.len() + 1) as u64)) as usize;
        let mut out = Vec::with_capacity(input.len() + count);
        out.extend_from_slice(&input[..pos]);
        for _ in 0..count {
            out.push(rng.next() as u8);
        }
        out.extend_from_slice(&input[pos..]);
        if max_size > 0 && out.len() > max_size {
            out.truncate(max_size);
        }
        Ok(out)
    }
    fn name(&self) -> &'static str {
        "insert"
    }
    fn weight(&self) -> u32 {
        2
    }
}

/// Mutator that deletes a chunk of bytes.
#[derive(Debug, Clone, Default)]
pub struct DeleteMutator;

impl MutatorPlugin for DeleteMutator {
    fn custom_mutate(
        &self,
        input: &[u8],
        seed: u64,
        _max_size: usize,
    ) -> Result<Vec<u8>, MutatorError> {
        if input.len() <= 1 {
            return Ok(input.to_vec());
        }
        let mut rng = Rng::new(seed);
        let count = (rng.range(32) + 1) as usize;
        let count = count.min(input.len() - 1);
        let pos = (rng.range((input.len() - count) as u64)) as usize;
        let mut out = Vec::with_capacity(input.len() - count);
        out.extend_from_slice(&input[..pos]);
        out.extend_from_slice(&input[pos + count..]);
        Ok(out)
    }
    fn name(&self) -> &'static str {
        "delete"
    }
    fn weight(&self) -> u32 {
        2
    }
}

/// Mutator that splices two inputs: first `[0..split]` from self, rest from other.
#[derive(Debug, Clone, Default)]
pub struct SpliceMutator {
    /// Secondary corpus for splicing.
    secondary: Vec<Vec<u8>>,
}

impl SpliceMutator {
    /// Create a splicer with a secondary corpus.
    #[must_use]
    pub const fn new(secondary: Vec<Vec<u8>>) -> Self {
        Self { secondary }
    }

    /// Add an entry to the secondary corpus.
    pub fn add_secondary(&mut self, entry: Vec<u8>) {
        self.secondary.push(entry);
    }
}

impl MutatorPlugin for SpliceMutator {
    fn custom_mutate(
        &self,
        input: &[u8],
        seed: u64,
        max_size: usize,
    ) -> Result<Vec<u8>, MutatorError> {
        if self.secondary.is_empty() {
            return ByteFlipMutator.custom_mutate(input, seed, max_size);
        }
        let mut rng = Rng::new(seed);
        let other = &self.secondary[rng.range(self.secondary.len() as u64) as usize];
        if input.is_empty() {
            return Ok(other.clone());
        }
        if other.is_empty() {
            return Ok(input.to_vec());
        }
        let split_a = (rng.range(input.len() as u64)) as usize;
        let split_b = (rng.range(other.len() as u64)) as usize;
        let mut out = Vec::with_capacity(split_a + other.len() - split_b);
        out.extend_from_slice(&input[..split_a]);
        out.extend_from_slice(&other[split_b..]);
        if max_size > 0 && out.len() > max_size {
            out.truncate(max_size);
        }
        Ok(out)
    }
    fn name(&self) -> &'static str {
        "splice"
    }
    fn weight(&self) -> u32 {
        2
    }
}

/// Mutator that replaces a random chunk with a dictionary token.
///
/// Note: an explicit `impl fmt::Debug for DictEntryMutator` is provided below,
/// so we intentionally disable the `derive(Debug)` here to avoid a duplicate
/// implementation (kept via a never-true `cfg_attr` guard rather than removing
/// the original attribute).
#[cfg_attr(any(), derive(Debug))]
pub struct DictEntryMutator {
    /// Dictionary entries.
    pub entries: Vec<DictionaryEntry>,
}

impl DictEntryMutator {
    /// Create a mutator from a list of tokens.
    #[must_use]
    pub const fn new(entries: Vec<DictionaryEntry>) -> Self {
        Self { entries }
    }

    /// Create from raw token byte-slices.
    #[must_use]
    pub fn from_tokens(tokens: &[&[u8]]) -> Self {
        let entries = tokens
            .iter()
            .enumerate()
            .map(|(i, t)| DictionaryEntry::new(t.to_vec(), format!("tok_{i}")))
            .collect();
        Self { entries }
    }

    /// Total weight of all entries.
    fn total_weight(&self) -> u64 {
        self.entries.iter().map(|e| u64::from(e.weight)).sum()
    }

    /// Select an entry by weighted random choice.
    fn select(&self, rng: &mut Rng) -> Option<&DictionaryEntry> {
        let total = self.total_weight();
        if total == 0 {
            return None;
        }
        let mut pick = rng.range(total);
        for entry in &self.entries {
            if pick < u64::from(entry.weight) {
                return Some(entry);
            }
            pick -= u64::from(entry.weight);
        }
        self.entries.last()
    }
}

impl MutatorPlugin for DictEntryMutator {
    fn custom_mutate(
        &self,
        input: &[u8],
        seed: u64,
        max_size: usize,
    ) -> Result<Vec<u8>, MutatorError> {
        if self.entries.is_empty() {
            return Err(MutatorError::EmptyDictionary);
        }
        let mut rng = Rng::new(seed);
        let entry = self.select(&mut rng).ok_or(MutatorError::EmptyDictionary)?;
        let token = &entry.token;

        if token.is_empty() {
            return Ok(input.to_vec());
        }
        let pos = if input.is_empty() {
            0
        } else {
            (rng.range(input.len() as u64)) as usize
        };
        let end = (pos + token.len()).min(if max_size > 0 { max_size } else { usize::MAX });
        let mut out = input.to_vec();
        let fill_end = end.min(out.len());
        let copy_len = fill_end - pos;
        out[pos..pos + copy_len].copy_from_slice(&token[..copy_len]);
        Ok(out)
    }
    fn name(&self) -> &'static str {
        "dict_entry"
    }
    fn weight(&self) -> u32 {
        3
    }

    fn custom_crossover(
        &self,
        parent_a: &[u8],
        parent_b: &[u8],
        seed: u64,
    ) -> Result<Vec<u8>, MutatorError> {
        // Inject a dictionary token between the two parents.
        if self.entries.is_empty() || parent_a.is_empty() {
            return Ok(parent_b.to_vec());
        }
        let mut rng = Rng::new(seed);
        let entry = self.select(&mut rng).ok_or(MutatorError::EmptyDictionary)?;
        let mut out = parent_a.to_vec();
        out.extend_from_slice(&entry.token);
        out.extend_from_slice(parent_b);
        Ok(out)
    }
}

impl fmt::Debug for DictEntryMutator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DictEntryMutator({} entries)", self.entries.len())
    }
}

/// Mutator that performs arithmetic addition/subtraction on a word or dword.
#[derive(Debug, Clone, Default)]
pub struct ArithmeticMutator;

impl MutatorPlugin for ArithmeticMutator {
    fn custom_mutate(
        &self,
        input: &[u8],
        seed: u64,
        _max_size: usize,
    ) -> Result<Vec<u8>, MutatorError> {
        if input.is_empty() {
            return Err(MutatorError::EmptyInput);
        }
        let mut rng = Rng::new(seed);
        let mut out = input.to_vec();
        let delta = rng.range(35).cast_signed() - 17; // [-17, 17]
        match rng.range(3) {
            0 => {
                let pos = (rng.range(out.len() as u64)) as usize;
                out[pos] = out[pos].wrapping_add(delta as u8);
            }
            1 if out.len() >= 2 => {
                let pos = (rng.range((out.len() - 1) as u64)) as usize;
                let v = u16::from_le_bytes([out[pos], out[pos + 1]]).wrapping_add(delta as u16);
                let b = v.to_le_bytes();
                out[pos] = b[0];
                out[pos + 1] = b[1];
            }
            _ if out.len() >= 4 => {
                let pos = (rng.range((out.len() - 3) as u64)) as usize;
                let v = u32::from_le_bytes([out[pos], out[pos + 1], out[pos + 2], out[pos + 3]])
                    .wrapping_add(delta as u32);
                let b = v.to_le_bytes();
                out[pos..pos + 4].copy_from_slice(&b);
            }
            _ => {
                let pos = (rng.range(out.len() as u64)) as usize;
                out[pos] = out[pos].wrapping_add(delta as u8);
            }
        }
        Ok(out)
    }
    fn name(&self) -> &'static str {
        "arithmetic"
    }
    fn weight(&self) -> u32 {
        2
    }
}

/// Mutator that replaces a position with an "interesting" boundary value.
#[derive(Debug, Clone, Default)]
pub struct InterestingValueMutator;

impl MutatorPlugin for InterestingValueMutator {
    fn custom_mutate(
        &self,
        input: &[u8],
        seed: u64,
        _max_size: usize,
    ) -> Result<Vec<u8>, MutatorError> {
        if input.is_empty() {
            return Err(MutatorError::EmptyInput);
        }
        let mut rng = Rng::new(seed);
        let mut out = input.to_vec();
        match rng.range(3) {
            0 => {
                let pos = (rng.range(out.len() as u64)) as usize;
                let idx = (rng.range(INTERESTING_U8.len() as u64)) as usize;
                out[pos] = INTERESTING_U8[idx];
            }
            1 if out.len() >= 2 => {
                let pos = (rng.range((out.len() - 1) as u64)) as usize;
                let idx = (rng.range(INTERESTING_U16.len() as u64)) as usize;
                let b = INTERESTING_U16[idx].to_le_bytes();
                out[pos] = b[0];
                out[pos + 1] = b[1];
            }
            _ if out.len() >= 4 => {
                let pos = crate::cast::u64_to_usize(rng.range((out.len() - 3) as u64));
                let idx = crate::cast::u64_to_usize(rng.range(INTERESTING_U32.len() as u64));
                let b = INTERESTING_U32[idx].to_le_bytes();
                out[pos..pos + 4].copy_from_slice(&b);
            }
            _ => {
                let pos = crate::cast::u64_to_usize(rng.range(out.len() as u64));
                let idx = crate::cast::u64_to_usize(rng.range(INTERESTING_U8.len() as u64));
                out[pos] = INTERESTING_U8[idx];
            }
        }
        Ok(out)
    }
    fn name(&self) -> &'static str {
        "interesting_value"
    }
    fn weight(&self) -> u32 {
        2
    }
}

/// Mutator that copies a chunk within the input.
#[derive(Debug, Clone, Default)]
pub struct ChunkCopyMutator;

impl MutatorPlugin for ChunkCopyMutator {
    fn custom_mutate(
        &self,
        input: &[u8],
        seed: u64,
        _max_size: usize,
    ) -> Result<Vec<u8>, MutatorError> {
        if input.len() < 2 {
            return Ok(input.to_vec());
        }
        let mut rng = Rng::new(seed);
        let src = crate::cast::u64_to_usize(rng.range(input.len() as u64));
        let max_len = (input.len() - src).min(32);
        if max_len == 0 {
            return Ok(input.to_vec());
        }
        let chunk_len = crate::cast::u64_to_usize(rng.range(max_len as u64) + 1);
        let dst = crate::cast::u64_to_usize(rng.range(input.len() as u64));
        let mut out = input.to_vec();
        let end_dst = (dst + chunk_len).min(out.len());
        let copy_count = end_dst - dst;
        let src_end = (src + copy_count).min(input.len());
        let chunk: Vec<u8> = input[src..src_end].to_vec();
        let actual = chunk.len().min(copy_count);
        out[dst..dst + actual].copy_from_slice(&chunk[..actual]);
        Ok(out)
    }
    fn name(&self) -> &'static str {
        "chunk_copy"
    }
    fn weight(&self) -> u32 {
        1
    }
}

// ─── MutatorChain ─────────────────────────────────────────────────────────────

/// Composes multiple [`MutatorPlugin`] instances into a weighted chain.
///
/// On each call the chain picks a plugin proportionally to its weight and
/// delegates the mutation.
pub struct MutatorChain {
    plugins: Vec<Box<dyn MutatorPlugin>>,
    /// Per-plugin invocation statistics.
    stats: HashMap<String, u64>,
}

impl MutatorChain {
    /// Create an empty chain.
    #[must_use]
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
            stats: HashMap::new(),
        }
    }

    /// Create a chain with all standard plugins.
    #[must_use]
    pub fn standard() -> Self {
        let mut c = Self::new();
        c.add(Box::new(ByteFlipMutator));
        c.add(Box::new(BitFlipMutator));
        c.add(Box::new(InsertMutator));
        c.add(Box::new(DeleteMutator));
        c.add(Box::new(ArithmeticMutator));
        c.add(Box::new(InterestingValueMutator));
        c.add(Box::new(ChunkCopyMutator));
        c
    }

    /// Add a plugin to the chain.
    pub fn add(&mut self, plugin: Box<dyn MutatorPlugin>) {
        self.stats.insert(plugin.name().to_string(), 0);
        self.plugins.push(plugin);
    }

    /// Total weight of all plugins in the chain.
    fn total_weight(&self) -> u64 {
        self.plugins.iter().map(|p| u64::from(p.weight())).sum()
    }

    /// Select a plugin by weighted random choice.
    fn select_plugin(&self, rng: &mut Rng) -> Option<&dyn MutatorPlugin> {
        let total = self.total_weight();
        if total == 0 {
            return self.plugins.first().map(std::convert::AsRef::as_ref);
        }
        let mut pick = rng.range(total);
        for plugin in &self.plugins {
            if pick < u64::from(plugin.weight()) {
                return Some(plugin.as_ref());
            }
            pick -= u64::from(plugin.weight());
        }
        self.plugins.last().map(std::convert::AsRef::as_ref)
    }

    /// Mutate `input` using a randomly selected plugin from the chain.
    ///
    /// # Errors
    ///
    /// Returns [`MutatorError`] if the selected plugin fails.
    pub fn mutate(
        &mut self,
        input: &[u8],
        seed: u64,
        max_size: usize,
    ) -> Result<Vec<u8>, MutatorError> {
        let mut rng = Rng::new(seed);
        let plugin = self
            .select_plugin(&mut rng)
            .ok_or(MutatorError::MutationFailed("no plugins".into()))?;
        let name = plugin.name().to_string();
        let result = plugin.custom_mutate(input, rng.next(), max_size)?;
        *self.stats.entry(name).or_insert(0) += 1;
        Ok(result)
    }

    /// Perform crossover using a randomly selected plugin.
    ///
    /// # Errors
    ///
    /// Returns [`MutatorError`] if the selected plugin fails.
    pub fn crossover(&mut self, a: &[u8], b: &[u8], seed: u64) -> Result<Vec<u8>, MutatorError> {
        let mut rng = Rng::new(seed);
        let plugin = self
            .select_plugin(&mut rng)
            .ok_or(MutatorError::MutationFailed("no plugins".into()))?;
        plugin.custom_crossover(a, b, rng.next())
    }

    /// Return a snapshot of per-plugin invocation counts.
    #[must_use]
    pub const fn stats(&self) -> &HashMap<String, u64> {
        &self.stats
    }

    /// Number of plugins in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Return `true` if the chain is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Run `count` mutations of `input` and return all results.
    ///
    /// # Errors
    ///
    /// Returns [`MutatorError`] if any mutation fails.
    pub fn batch_mutate(
        &mut self,
        input: &[u8],
        count: usize,
        base_seed: u64,
        max_size: usize,
    ) -> Result<Vec<Vec<u8>>, MutatorError> {
        let mut rng = Rng::new(base_seed);
        let mut results = Vec::with_capacity(count);
        for _ in 0..count {
            results.push(self.mutate(input, rng.next(), max_size)?);
        }
        Ok(results)
    }
}

impl Default for MutatorChain {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for MutatorChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MutatorChain")
            .field("plugins", &self.plugins.len())
            .finish_non_exhaustive()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: u64 = 0xdead_beef;
    const INPUT: &[u8] = b"Hello, fuzzer!";

    #[test]
    fn byte_flip_changes_bytes() {
        let out = ByteFlipMutator.custom_mutate(INPUT, SEED, 0).expect("ok");
        assert_eq!(out.len(), INPUT.len());
        assert_ne!(out, INPUT);
    }

    #[test]
    fn byte_flip_empty_fails() {
        let err = ByteFlipMutator.custom_mutate(&[], SEED, 0);
        assert!(matches!(err, Err(MutatorError::EmptyInput)));
    }

    #[test]
    fn bit_flip_changes_one_bit() {
        let out = BitFlipMutator.custom_mutate(INPUT, SEED, 0).expect("ok");
        assert_eq!(out.len(), INPUT.len());
        // Exactly one bit should differ.
        let diffs: Vec<u8> = INPUT
            .iter()
            .zip(out.iter())
            .map(|(a, b)| a ^ b)
            .filter(|&d| d != 0)
            .collect();
        assert_eq!(diffs.len(), 1);
        assert!(diffs[0].is_power_of_two());
    }

    #[test]
    fn insert_increases_length() {
        let out = InsertMutator.custom_mutate(INPUT, SEED, 0).expect("ok");
        assert!(out.len() > INPUT.len());
    }

    #[test]
    fn insert_respects_max_size() {
        let out = InsertMutator
            .custom_mutate(INPUT, SEED, INPUT.len())
            .expect("ok");
        assert!(out.len() <= INPUT.len());
    }

    #[test]
    fn delete_decreases_length() {
        let long_input = vec![0u8; 64];
        let out = DeleteMutator
            .custom_mutate(&long_input, SEED, 0)
            .expect("ok");
        assert!(out.len() < long_input.len());
    }

    #[test]
    fn delete_single_byte_ok() {
        let out = DeleteMutator.custom_mutate(&[42u8], SEED, 0).expect("ok");
        assert_eq!(out, &[42u8]); // can't delete only byte
    }

    #[test]
    fn splice_with_secondary() {
        let m = SpliceMutator::new(vec![b"world!".to_vec()]);
        let out = m.custom_mutate(b"hello ", SEED, 0).expect("ok");
        assert!(!out.is_empty());
    }

    #[test]
    fn splice_empty_secondary_falls_back() {
        let m = SpliceMutator::new(vec![]);
        let out = m.custom_mutate(INPUT, SEED, 0).expect("ok");
        // Falls back to ByteFlipMutator, so length unchanged.
        assert_eq!(out.len(), INPUT.len());
    }

    #[test]
    fn dict_entry_replaces_chunk() {
        let tokens: &[&[u8]] = &[b"AAAA", b"\x00\x00", b"\xff\xff"];
        let m = DictEntryMutator::from_tokens(tokens);
        let out = m.custom_mutate(INPUT, SEED, 0).expect("ok");
        // Length should stay the same (replace, not insert).
        assert_eq!(out.len(), INPUT.len());
    }

    #[test]
    fn dict_entry_empty_fails() {
        let m = DictEntryMutator::new(vec![]);
        let err = m.custom_mutate(INPUT, SEED, 0);
        assert!(matches!(err, Err(MutatorError::EmptyDictionary)));
    }

    #[test]
    fn dict_entry_crossover_inserts_token() {
        let tokens: &[&[u8]] = &[b"--DELIM--"];
        let m = DictEntryMutator::from_tokens(tokens);
        let out = m.custom_crossover(b"hello", b"world", SEED).expect("ok");
        assert!(out.len() > 5); // at least "hello" + token
    }

    #[test]
    fn arithmetic_mutator_changes_value() {
        let out = ArithmeticMutator.custom_mutate(INPUT, SEED, 0).expect("ok");
        assert_ne!(out, INPUT);
    }

    #[test]
    fn interesting_value_mutator_ok() {
        let out = InterestingValueMutator
            .custom_mutate(INPUT, SEED, 0)
            .expect("ok");
        assert!(!out.is_empty());
    }

    #[test]
    fn chunk_copy_mutator_ok() {
        let out = ChunkCopyMutator.custom_mutate(INPUT, SEED, 0).expect("ok");
        assert_eq!(out.len(), INPUT.len());
    }

    #[test]
    fn mutator_chain_standard_mutate() {
        let mut chain = MutatorChain::standard();
        assert!(!chain.is_empty());
        let out = chain.mutate(INPUT, SEED, 0).expect("ok");
        assert!(!out.is_empty());
    }

    #[test]
    fn mutator_chain_batch_mutate() {
        let mut chain = MutatorChain::standard();
        let results = chain.batch_mutate(INPUT, 10, SEED, 0).expect("ok");
        assert_eq!(results.len(), 10);
    }

    #[test]
    fn mutator_chain_crossover() {
        let mut chain = MutatorChain::standard();
        let out = chain.crossover(b"AAAA", b"BBBB", SEED).expect("ok");
        assert!(!out.is_empty());
    }

    #[test]
    fn mutator_chain_stats_tracked() {
        let mut chain = MutatorChain::standard();
        for i in 0..100 {
            let _ = chain.mutate(INPUT, i, 0);
        }
        let total: u64 = chain.stats().values().sum();
        assert_eq!(total, 100);
    }

    #[test]
    fn mutation_strategy_all() {
        let all = MutationStrategy::all();
        assert!(all.len() >= 5);
    }

    #[test]
    fn mutation_strategy_display() {
        assert_eq!(MutationStrategy::ByteFlip.to_string(), "byte_flip");
        assert_eq!(MutationStrategy::DictEntry.to_string(), "dict_entry");
    }

    #[test]
    fn dictionary_entry_hit_count() {
        let mut e = DictionaryEntry::new(b"token".to_vec(), "t");
        assert_eq!(e.hit_count, 0);
        e.record_hit();
        assert_eq!(e.hit_count, 1);
    }

    #[test]
    fn custom_crossover_default_impl() {
        let m = ByteFlipMutator;
        let out = m.custom_crossover(b"hello", b"world", SEED).expect("ok");
        assert!(!out.is_empty());
    }
}
