//! Advanced mutation strategies: crossover (splicing), structure-aware mutation,
//! dictionary-guided mutation, AFL++ RedQueen-style comparisons, and havoc mode.
//!
//! Types: [`MutationStrategy`], [`Crossover`], [`StructureMutation`],
//! [`DictionaryEntry`], [`HavocConfig`].

use std::collections::HashMap;
use std::fmt;

// ─── Simple PRNG ─────────────────────────────────────────────────────────────

/// A minimal xorshift64 PRNG.
#[derive(Debug, Clone)]
pub struct Rng {
    state: u64,
}

impl Rng {
    /// Create a new RNG with the given seed (0 is replaced with a default).
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0xdead_beef_cafe_babe } else { seed },
        }
    }

    /// Advance and return the next u64.
    #[inline]
    pub const fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// Return a value in `[0, max)`, or 0 when `max == 0`.
    #[inline]
    pub const fn next_range(&mut self, max: u64) -> u64 {
        if max == 0 { 0 } else { self.next_u64() % max }
    }

    /// Return a float in [0.0, 1.0).
    #[inline]
    pub fn next_f64(&mut self) -> f64 {
        ((self.next_u64() >> 11) as f64) / ((1u64 << 53) as f64)
    }
}

// ─── MutationStrategy ────────────────────────────────────────────────────────

/// High-level mutation strategy selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MutationStrategy {
    /// Simple single-bit flip.
    BitFlip,
    /// Single-byte flip.
    ByteFlip,
    /// Arithmetic add/subtract on a 1/2/4-byte field.
    Arithmetic,
    /// Replace a byte/word/dword with an "interesting" boundary value.
    InterestingValue,
    /// Splice two corpus entries together.
    Crossover,
    /// Structure-aware mutation (field boundary detection).
    StructureAware,
    /// Dictionary token substitution.
    Dictionary,
    /// `RedQueen` comparison-guided (cmp operand substitution).
    RedQueen,
    /// Havoc: apply multiple random mutations in sequence.
    Havoc,
    /// Insert a random block.
    BlockInsert,
    /// Delete a random block.
    BlockDelete,
    /// Overwrite with a random block copied from another position.
    BlockCopy,
}

impl MutationStrategy {
    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BitFlip => "bit_flip",
            Self::ByteFlip => "byte_flip",
            Self::Arithmetic => "arithmetic",
            Self::InterestingValue => "interesting_value",
            Self::Crossover => "crossover",
            Self::StructureAware => "structure_aware",
            Self::Dictionary => "dictionary",
            Self::RedQueen => "red_queen",
            Self::Havoc => "havoc",
            Self::BlockInsert => "block_insert",
            Self::BlockDelete => "block_delete",
            Self::BlockCopy => "block_copy",
        }
    }

    /// All available strategies as a fixed array.
    #[must_use]
    pub const fn all() -> [Self; 12] {
        [
            Self::BitFlip,
            Self::ByteFlip,
            Self::Arithmetic,
            Self::InterestingValue,
            Self::Crossover,
            Self::StructureAware,
            Self::Dictionary,
            Self::RedQueen,
            Self::Havoc,
            Self::BlockInsert,
            Self::BlockDelete,
            Self::BlockCopy,
        ]
    }
}

impl fmt::Display for MutationStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─── Interesting values ───────────────────────────────────────────────────────

const INTERESTING_U8: &[u8] = &[0, 1, 0x7f, 0x80, 0xfe, 0xff];
const INTERESTING_U16: &[u16] = &[
    0x0000, 0x0001, 0x007f, 0x0080, 0x00ff, 0x0100,
    0x7fff, 0x8000, 0xfffe, 0xffff,
];
const INTERESTING_U32: &[u32] = &[
    0x0000_0000, 0x0000_0001, 0x0000_007f, 0x0000_0080,
    0x0000_00ff, 0x0000_0100, 0x0000_7fff, 0x0000_8000,
    0x0000_ffff, 0x0001_0000, 0x7fff_ffff, 0x8000_0000,
    0xffff_fffe, 0xffff_ffff,
];

// ─── DictionaryEntry ─────────────────────────────────────────────────────────

/// A dictionary token used by the dictionary-guided mutator.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DictionaryEntry {
    /// The token bytes.
    pub token: Vec<u8>,
    /// Optional human-readable label.
    pub label: Option<String>,
    /// Weight: higher = more likely to be selected.
    pub weight: u32,
}

impl DictionaryEntry {
    /// Create a new entry with weight 1.
    #[must_use]
    pub const fn new(token: Vec<u8>) -> Self {
        Self {
            token,
            label: None,
            weight: 1,
        }
    }

    /// Create a labelled entry.
    #[must_use]
    pub fn labelled(token: Vec<u8>, label: impl Into<String>) -> Self {
        Self {
            token,
            label: Some(label.into()),
            weight: 1,
        }
    }

    /// Create an entry with a custom weight.
    #[must_use]
    pub fn weighted(token: Vec<u8>, weight: u32) -> Self {
        Self {
            token,
            label: None,
            weight: weight.max(1),
        }
    }
}

impl fmt::Display for DictionaryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref label) = self.label {
            write!(f, "{label}={:02x?}", self.token)
        } else {
            write!(f, "{:02x?}", self.token)
        }
    }
}

// ─── Dictionary ──────────────────────────────────────────────────────────────

/// A weighted collection of dictionary tokens.
#[derive(Debug, Default)]
pub struct Dictionary {
    entries: Vec<DictionaryEntry>,
    total_weight: u64,
}

impl Dictionary {
    /// Create an empty dictionary.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry.
    pub fn add(&mut self, entry: DictionaryEntry) {
        self.total_weight += u64::from(entry.weight);
        self.entries.push(entry);
    }

    /// Add a raw byte token with weight 1.
    pub fn add_bytes(&mut self, token: Vec<u8>) {
        self.add(DictionaryEntry::new(token));
    }

    /// Add a string literal as a token.
    pub fn add_str(&mut self, s: &str) {
        self.add_bytes(s.as_bytes().to_vec());
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the dictionary is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Pick a weighted-random entry.
    ///
    /// Returns `None` if the dictionary is empty.
    #[must_use]
    pub fn pick(&self, rng: &mut Rng) -> Option<&DictionaryEntry> {
        if self.entries.is_empty() {
            return None;
        }
        let r = rng.next_range(self.total_weight);
        let mut cumulative = 0u64;
        for entry in &self.entries {
            cumulative += u64::from(entry.weight);
            if r < cumulative {
                return Some(entry);
            }
        }
        self.entries.last()
    }
}

// ─── FieldBoundary ────────────────────────────────────────────────────────────

/// A detected field boundary within an input.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldBoundary {
    /// Byte offset of the field start.
    pub offset: usize,
    /// Length of the field in bytes.
    pub length: usize,
    /// Confidence in this boundary (0.0–1.0).
    pub confidence: f64,
    /// Detected field kind.
    pub kind: FieldKind,
}

/// Inferred type of a detected field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// Little-endian length prefix followed by a payload.
    LengthPrefixedLE,
    /// Big-endian length prefix followed by a payload.
    LengthPrefixedBE,
    /// Null-terminated string.
    CString,
    /// Fixed-size chunk (no prefix detected).
    FixedChunk,
    /// Magic number / signature bytes.
    Magic,
}

impl fmt::Display for FieldKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── StructureMutation ───────────────────────────────────────────────────────

/// Structure-aware mutation: detects field boundaries and respects them.
#[derive(Debug, Default)]
pub struct StructureMutation;

impl StructureMutation {
    /// Detect field boundaries in `data`.
    ///
    /// Heuristics applied (in order):
    /// 1. Null-terminated string regions.
    /// 2. 2-byte LE length prefix followed by the indicated payload.
    /// 3. 4-byte LE length prefix followed by the indicated payload.
    #[must_use]
    pub fn detect_fields(data: &[u8]) -> Vec<FieldBoundary> {
        let mut fields = Vec::new();

        // ── C-string detection ────────────────────────────────────────────────
        let mut start = 0usize;
        for (i, &b) in data.iter().enumerate() {
            if b == 0 && i > start {
                fields.push(FieldBoundary {
                    offset: start,
                    length: i - start + 1, // include null terminator
                    confidence: 0.7,
                    kind: FieldKind::CString,
                });
                start = i + 1;
            }
        }

        // ── 2-byte LE length prefix ───────────────────────────────────────────
        let mut pos = 0;
        while pos + 2 < data.len() {
            let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
            if len > 0 && pos + 2 + len <= data.len() && len <= 4096 {
                fields.push(FieldBoundary {
                    offset: pos,
                    length: 2 + len,
                    confidence: 0.85,
                    kind: FieldKind::LengthPrefixedLE,
                });
                pos += 2 + len;
            } else {
                pos += 1;
            }
        }

        // ── 4-byte LE length prefix ───────────────────────────────────────────
        pos = 0;
        while pos + 4 < data.len() {
            let len = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
            if len > 0 && pos + 4 + len <= data.len() && len <= 65536 {
                fields.push(FieldBoundary {
                    offset: pos,
                    length: 4 + len,
                    confidence: 0.80,
                    kind: FieldKind::LengthPrefixedBE,
                });
                pos += 4 + len;
            } else {
                pos += 1;
            }
        }

        fields.sort_by_key(|f| f.offset);
        fields
    }

    /// Perform a structure-aware mutation: mutate only within detected fields.
    #[must_use]
    pub fn mutate(data: &[u8], rng: &mut Rng) -> Vec<u8> {
        let fields = Self::detect_fields(data);
        if fields.is_empty() || data.is_empty() {
            // Fall back to a simple byte flip.
            let mut out = data.to_vec();
            if !out.is_empty() {
                let pos = (rng.next_range(out.len() as u64)) as usize;
                out[pos] ^= (rng.next_u64() as u8) | 1;
            }
            return out;
        }

        // Pick a random field.
        let fi = (rng.next_range(fields.len() as u64)) as usize;
        let field = &fields[fi];
        let mut out = data.to_vec();

        // Mutate randomly within the field payload (skip length prefix bytes).
        let skip = match field.kind {
            FieldKind::LengthPrefixedLE => 2,
            FieldKind::LengthPrefixedBE => 4,
            _ => 0,
        };
        let payload_start = field.offset + skip;
        let payload_end = (field.offset + field.length).min(out.len());
        if payload_start >= payload_end {
            return out;
        }
        let rel_pos = (rng.next_range((payload_end - payload_start) as u64)) as usize;
        let abs_pos = payload_start + rel_pos;
        out[abs_pos] = rng.next_u64() as u8;
        out
    }

    /// Mutate a length field to a new random value within bounds.
    #[must_use]
    pub fn corrupt_length_field(data: &[u8], rng: &mut Rng) -> Vec<u8> {
        let mut out = data.to_vec();
        if out.len() < 2 {
            return out;
        }
        let pos = (rng.next_range((out.len() - 1) as u64)) as usize;
        // Write a new 2-byte LE length: either 0, max, or random.
        let new_len: u16 = match rng.next_range(4) {
            0 => 0,
            1 => u16::MAX,
            2 => u16::MAX / 2,
            _ => rng.next_u64() as u16,
        };
        let bytes = new_len.to_le_bytes();
        out[pos] = bytes[0];
        if pos + 1 < out.len() {
            out[pos + 1] = bytes[1];
        }
        out
    }
}

// ─── Crossover ───────────────────────────────────────────────────────────────

/// Splicing / crossover mutation between two corpus entries.
#[derive(Debug, Default)]
pub struct Crossover;

/// Configuration for crossover mutations.
#[derive(Debug, Clone)]
pub struct CrossoverConfig {
    /// Whether to use two split points (uniform crossover).
    pub two_point: bool,
    /// Minimum contribution in bytes from each parent.
    pub min_contribution: usize,
    /// Maximum output size (0 = unlimited).
    pub max_output_size: usize,
}

impl Default for CrossoverConfig {
    fn default() -> Self {
        Self {
            two_point: false,
            min_contribution: 1,
            max_output_size: 0,
        }
    }
}

impl Crossover {
    /// Single-point crossover: first `split_a` bytes from `a`, then `b[split_b..]`.
    #[must_use]
    pub fn single_point(a: &[u8], b: &[u8], rng: &mut Rng) -> Vec<u8> {
        if a.is_empty() {
            return b.to_vec();
        }
        if b.is_empty() {
            return a.to_vec();
        }
        let split_a = (rng.next_range(a.len() as u64)) as usize;
        let split_b = (rng.next_range(b.len() as u64)) as usize;
        let mut out = Vec::with_capacity(split_a + (b.len() - split_b));
        out.extend_from_slice(&a[..split_a]);
        out.extend_from_slice(&b[split_b..]);
        out
    }

    /// Two-point crossover: take `a[0..p1]`, then `b[p1..p2]`, then `a[p2..]`.
    #[must_use]
    pub fn two_point(a: &[u8], b: &[u8], rng: &mut Rng) -> Vec<u8> {
        if a.is_empty() || b.is_empty() {
            return Self::single_point(a, b, rng);
        }
        let min_len = a.len().min(b.len());
        if min_len < 2 {
            return Self::single_point(a, b, rng);
        }
        let p1 = (rng.next_range(min_len as u64)) as usize;
        let p2 = p1 + (rng.next_range((min_len - p1) as u64) as usize);
        let p2 = p2.min(min_len);
        let mut out = Vec::with_capacity(a.len());
        out.extend_from_slice(&a[..p1]);
        out.extend_from_slice(&b[p1..p2]);
        if p2 < a.len() {
            out.extend_from_slice(&a[p2..]);
        }
        out
    }

    /// Uniform crossover: for each byte, randomly take from `a` or `b`.
    #[must_use]
    pub fn uniform(a: &[u8], b: &[u8], rng: &mut Rng) -> Vec<u8> {
        let max_len = a.len().max(b.len());
        let mut out = Vec::with_capacity(max_len);
        for i in 0..max_len {
            let byte = if rng.next_u64() & 1 == 0 {
                if i < a.len() { a[i] } else { b[i] }
            } else if i < b.len() {
                b[i]
            } else {
                a[i]
            };
            out.push(byte);
        }
        out
    }

    /// Perform crossover with the given `config`.
    #[must_use]
    pub fn crossover_with_config(
        a: &[u8],
        b: &[u8],
        rng: &mut Rng,
        config: &CrossoverConfig,
    ) -> Vec<u8> {
        let mut out = if config.two_point {
            Self::two_point(a, b, rng)
        } else {
            Self::single_point(a, b, rng)
        };
        if config.max_output_size > 0 && out.len() > config.max_output_size {
            out.truncate(config.max_output_size);
        }
        out
    }
}

// ─── RedQueenComparison ───────────────────────────────────────────────────────

/// A comparison operand captured for RedQueen-style mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedQueenComparison {
    /// Byte offset in the input where the compared value appears.
    pub input_offset: usize,
    /// The value in the input (lhs operand of the comparison).
    pub input_value: Vec<u8>,
    /// The value the program compares against (rhs operand).
    pub compare_value: Vec<u8>,
    /// Type of comparison instruction.
    pub cmp_type: CmpType,
}

/// Type of comparison (inferred from context).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpType {
    /// Integer equality (==).
    Eq,
    /// Integer less-than (<).
    Lt,
    /// Integer less-than-or-equal (<=).
    Le,
    /// String equality (strcmp-like).
    StrEq,
    /// Memory equality (memcmp-like).
    MemEq,
}

impl RedQueenComparison {
    /// Generate a set of mutations that try to satisfy this comparison.
    #[must_use]
    pub fn generate_mutations(&self, input: &[u8], rng: &mut Rng) -> Vec<Vec<u8>> {
        let mut results = Vec::new();
        let off = self.input_offset;
        let cmp_len = self.compare_value.len();

        if off + cmp_len > input.len() {
            return results;
        }

        // Direct substitution: replace input[off..off+cmp_len] with compare_value.
        {
            let mut out = input.to_vec();
            out[off..off + cmp_len].copy_from_slice(&self.compare_value);
            results.push(out);
        }

        // Off-by-one variants.
        for delta in [1i8, -1, 2, -2] {
            let mut out = input.to_vec();
            let mut val = self.compare_value.clone();
            if !val.is_empty() {
                val[0] = val[0].wrapping_add(delta.cast_unsigned());
            }
            let limit = cmp_len.min(out.len() - off);
            out[off..off + limit].copy_from_slice(&val[..limit]);
            results.push(out);
        }

        // Endian-swapped (for 2- and 4-byte values).
        if cmp_len == 2 {
            let mut out = input.to_vec();
            out[off] = self.compare_value[1];
            out[off + 1] = self.compare_value[0];
            results.push(out);
        } else if cmp_len == 4 {
            let mut out = input.to_vec();
            for i in 0..4 {
                out[off + i] = self.compare_value[3 - i];
            }
            results.push(out);
        }

        // Random noise near the comparison site.
        {
            let mut out = input.to_vec();
            let noise_pos = (rng.next_range(cmp_len as u64)) as usize;
            out[off + noise_pos] ^= 1;
            results.push(out);
        }

        results
    }
}

// ─── RedQueenEngine ───────────────────────────────────────────────────────────

/// Engine that collects `RedQueen` comparisons and applies them.
#[derive(Debug, Default)]
pub struct RedQueenEngine {
    comparisons: Vec<RedQueenComparison>,
}

impl RedQueenEngine {
    /// Create a new engine.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a captured comparison.
    pub fn add_comparison(&mut self, cmp: RedQueenComparison) {
        self.comparisons.push(cmp);
    }

    /// Clear all captured comparisons.
    pub fn clear(&mut self) {
        self.comparisons.clear();
    }

    /// Number of recorded comparisons.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.comparisons.len()
    }

    /// True if no comparisons are recorded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.comparisons.is_empty()
    }

    /// Apply a randomly chosen comparison mutation to `input`.
    #[must_use]
    pub fn apply_one(&self, input: &[u8], rng: &mut Rng) -> Option<Vec<u8>> {
        if self.comparisons.is_empty() {
            return None;
        }
        let idx = (rng.next_range(self.comparisons.len() as u64)) as usize;
        let mutations = self.comparisons[idx].generate_mutations(input, rng);
        if mutations.is_empty() {
            return None;
        }
        let m_idx = (rng.next_range(mutations.len() as u64)) as usize;
        Some(mutations[m_idx].clone())
    }

    /// Apply all comparison mutations to `input`, returning all variants.
    #[must_use]
    pub fn apply_all(&self, input: &[u8], rng: &mut Rng) -> Vec<Vec<u8>> {
        self.comparisons
            .iter()
            .flat_map(|c| c.generate_mutations(input, rng))
            .collect()
    }
}

// ─── HavocConfig ─────────────────────────────────────────────────────────────

/// Configuration for the havoc mutator.
#[derive(Debug, Clone)]
pub struct HavocConfig {
    /// Minimum number of mutations per havoc pass.
    pub min_mutations: usize,
    /// Maximum number of mutations per havoc pass.
    pub max_mutations: usize,
    /// Strategies to include in the havoc pool.
    pub strategies: Vec<MutationStrategy>,
    /// Maximum output size in bytes (0 = unlimited).
    pub max_size: usize,
}

impl Default for HavocConfig {
    fn default() -> Self {
        Self {
            min_mutations: 2,
            max_mutations: 32,
            strategies: vec![
                MutationStrategy::BitFlip,
                MutationStrategy::ByteFlip,
                MutationStrategy::Arithmetic,
                MutationStrategy::InterestingValue,
                MutationStrategy::BlockInsert,
                MutationStrategy::BlockDelete,
                MutationStrategy::BlockCopy,
            ],
            max_size: 1024 * 1024,
        }
    }
}

// ─── BaseMutator ─────────────────────────────────────────────────────────────

/// The core mutation engine implementing all primitive strategies.
#[derive(Debug, Default)]
pub struct BaseMutator;

impl BaseMutator {
    /// Create a new mutator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    // ── Primitives ────────────────────────────────────────────────────────────

    /// Flip a random single bit.
    #[must_use]
    pub fn bit_flip(&self, data: &[u8], rng: &mut Rng) -> Vec<u8> {
        if data.is_empty() {
            return vec![rng.next_u64() as u8];
        }
        let mut out = data.to_vec();
        let pos = (rng.next_range(out.len() as u64)) as usize;
        let bit = (rng.next_range(8)) as u8;
        out[pos] ^= 1 << bit;
        out
    }

    /// Flip one or more consecutive bytes.
    #[must_use]
    pub fn byte_flip(&self, data: &[u8], rng: &mut Rng) -> Vec<u8> {
        if data.is_empty() {
            return vec![0xff];
        }
        let mut out = data.to_vec();
        let count = (rng.next_range(8) + 1) as usize;
        let pos = (rng.next_range(out.len() as u64)) as usize;
        let end = (pos + count).min(out.len());
        for b in &mut out[pos..end] {
            *b ^= 0xff;
        }
        out
    }

    /// Arithmetic: add/subtract a small delta from a 1/2/4-byte field.
    #[must_use]
    pub fn arithmetic(&self, data: &[u8], rng: &mut Rng) -> Vec<u8> {
        if data.is_empty() {
            return vec![1];
        }
        let mut out = data.to_vec();
        let delta = rng.next_range(35).cast_signed() - 17; // [-17, 17]
        match rng.next_range(3) {
            0 => {
                let pos = (rng.next_range(out.len() as u64)) as usize;
                out[pos] = out[pos].wrapping_add(delta as u8);
            }
            1 if out.len() >= 2 => {
                let pos = (rng.next_range((out.len() - 1) as u64)) as usize;
                let v = u16::from_le_bytes([out[pos], out[pos + 1]]).wrapping_add(delta as u16);
                let b = v.to_le_bytes();
                out[pos] = b[0];
                out[pos + 1] = b[1];
            }
            _ if out.len() >= 4 => {
                let pos = crate::cast::u64_to_usize(rng.next_range((out.len() - 3) as u64));
                let v = u32::from_le_bytes([out[pos], out[pos + 1], out[pos + 2], out[pos + 3]])
                    .wrapping_add(delta as u32);
                let b = v.to_le_bytes();
                out[pos..pos + 4].copy_from_slice(&b);
            }
            _ => {
                let pos = crate::cast::u64_to_usize(rng.next_range(out.len() as u64));
                out[pos] = out[pos].wrapping_add(delta as u8);
            }
        }
        out
    }

    /// Replace a byte/word/dword with an interesting boundary value.
    #[must_use]
    pub fn interesting_value(&self, data: &[u8], rng: &mut Rng) -> Vec<u8> {
        if data.is_empty() {
            return vec![0];
        }
        let mut out = data.to_vec();
        match rng.next_range(3) {
            0 => {
                let pos = crate::cast::u64_to_usize(rng.next_range(out.len() as u64));
                out[pos] = INTERESTING_U8[rng.next_range(INTERESTING_U8.len() as u64) as usize];
            }
            1 if out.len() >= 2 => {
                let pos = crate::cast::u64_to_usize(rng.next_range((out.len() - 1) as u64));
                let v = INTERESTING_U16[rng.next_range(INTERESTING_U16.len() as u64) as usize];
                let b = v.to_le_bytes();
                out[pos] = b[0];
                out[pos + 1] = b[1];
            }
            _ if out.len() >= 4 => {
                let pos = crate::cast::u64_to_usize(rng.next_range((out.len() - 3) as u64));
                let v = INTERESTING_U32[rng.next_range(INTERESTING_U32.len() as u64) as usize];
                let b = v.to_le_bytes();
                out[pos..pos + 4].copy_from_slice(&b);
            }
            _ => {
                let pos = crate::cast::u64_to_usize(rng.next_range(out.len() as u64));
                out[pos] = INTERESTING_U8[rng.next_range(INTERESTING_U8.len() as u64) as usize];
            }
        }
        out
    }

    /// Insert a random block of bytes.
    #[must_use]
    pub fn block_insert(&self, data: &[u8], rng: &mut Rng) -> Vec<u8> {
        let count = crate::cast::u64_to_usize(rng.next_range(64) + 1);
        let pos = if data.is_empty() {
            0
        } else {
            crate::cast::u64_to_usize(rng.next_range((data.len() + 1) as u64))
        };
        let mut out = Vec::with_capacity(data.len() + count);
        out.extend_from_slice(&data[..pos]);
        for _ in 0..count {
            out.push(rng.next_u64() as u8);
        }
        out.extend_from_slice(&data[pos..]);
        out
    }

    /// Delete a random block of bytes.
    #[must_use]
    pub fn block_delete(&self, data: &[u8], rng: &mut Rng) -> Vec<u8> {
        if data.len() <= 1 {
            return data.to_vec();
        }
        let count = crate::cast::u64_to_usize(rng.next_range(data.len().min(64) as u64) + 1);
        let pos = crate::cast::u64_to_usize(rng.next_range((data.len() - count + 1) as u64));
        let mut out = Vec::with_capacity(data.len() - count);
        out.extend_from_slice(&data[..pos]);
        out.extend_from_slice(&data[pos + count..]);
        out
    }

    /// Copy a chunk from one position to another.
    #[must_use]
    pub fn block_copy(&self, data: &[u8], rng: &mut Rng) -> Vec<u8> {
        if data.len() < 2 {
            return data.to_vec();
        }
        let src = crate::cast::u64_to_usize(rng.next_range(data.len() as u64));
        let max_chunk = (data.len() - src).min(64);
        let chunk_len = crate::cast::u64_to_usize(rng.next_range(max_chunk as u64) + 1);
        let dst = crate::cast::u64_to_usize(rng.next_range(data.len() as u64));
        let mut out = data.to_vec();
        let chunk: Vec<u8> = data[src..src + chunk_len].to_vec();
        let end = (dst + chunk_len).min(out.len());
        let copy_len = end - dst;
        out[dst..end].copy_from_slice(&chunk[..copy_len]);
        out
    }

    // ── Dictionary ────────────────────────────────────────────────────────────

    /// Insert or overwrite a dictionary token at a random position.
    #[must_use]
    pub fn dictionary_mutate(
        &self,
        data: &[u8],
        dict: &Dictionary,
        rng: &mut Rng,
    ) -> Vec<u8> {
        let Some(entry) = dict.pick(rng) else { return data.to_vec() };
        let token = &entry.token;
        if token.is_empty() {
            return data.to_vec();
        }
        if data.is_empty() {
            return token.clone();
        }

        let insert = rng.next_u64() & 1 == 0;
        if insert {
            // Insert the token at a random position.
            let pos = crate::cast::u64_to_usize(rng.next_range((data.len() + 1) as u64));
            let mut out = Vec::with_capacity(data.len() + token.len());
            out.extend_from_slice(&data[..pos]);
            out.extend_from_slice(token);
            out.extend_from_slice(&data[pos..]);
            out
        } else if data.len() >= token.len() {
            // Overwrite at a random position.
            let max_pos = data.len() - token.len();
            let pos = crate::cast::u64_to_usize(rng.next_range((max_pos + 1) as u64));
            let mut out = data.to_vec();
            out[pos..pos + token.len()].copy_from_slice(token);
            out
        } else {
            // Data shorter than token: prepend.
            let mut out = token.clone();
            out.extend_from_slice(data);
            out
        }
    }

    // ── Havoc ─────────────────────────────────────────────────────────────────

    /// Apply multiple random mutations in sequence (havoc mode).
    #[must_use]
    pub fn havoc(
        &self,
        data: &[u8],
        rng: &mut Rng,
        config: &HavocConfig,
        dict: Option<&Dictionary>,
        corpus: Option<&[Vec<u8>]>,
    ) -> Vec<u8> {
        let count = config.min_mutations
            + crate::cast::u64_to_usize(rng.next_range((config.max_mutations - config.min_mutations + 1) as u64));

        let strategies = &config.strategies;
        if strategies.is_empty() {
            return data.to_vec();
        }

        let mut out = data.to_vec();
        for _ in 0..count {
            let idx = crate::cast::u64_to_usize(rng.next_range(strategies.len() as u64));
            out = match strategies[idx] {
                MutationStrategy::ByteFlip => self.byte_flip(&out, rng),
                MutationStrategy::Arithmetic => self.arithmetic(&out, rng),
                MutationStrategy::InterestingValue => self.interesting_value(&out, rng),
                MutationStrategy::BlockInsert => self.block_insert(&out, rng),
                MutationStrategy::BlockDelete => self.block_delete(&out, rng),
                MutationStrategy::BlockCopy => self.block_copy(&out, rng),
                MutationStrategy::Dictionary => {
                    if let Some(d) = dict {
                        self.dictionary_mutate(&out, d, rng)
                    } else {
                        self.bit_flip(&out, rng)
                    }
                }
                MutationStrategy::Crossover => {
                    corpus.map_or_else(|| out.clone(), |c| if c.is_empty() {
                            out.clone()
                        } else {
                            let ci = crate::cast::u64_to_usize(rng.next_range(c.len() as u64));
                            Crossover::single_point(&out, &c[ci], rng)
                        })
                }
                MutationStrategy::StructureAware => StructureMutation::mutate(&out, rng),
                _ => self.bit_flip(&out, rng),
            };

            // Enforce size cap.
            if config.max_size > 0 && out.len() > config.max_size {
                out.truncate(config.max_size);
            }
        }
        out
    }
}

// ─── MutationStats ────────────────────────────────────────────────────────────

/// Per-strategy mutation statistics.
#[derive(Debug, Default, Clone)]
pub struct MutationStats {
    /// How many times each strategy was applied.
    pub strategy_counts: HashMap<String, u64>,
    /// How many of those led to new coverage.
    pub interesting_counts: HashMap<String, u64>,
    /// Total mutations applied.
    pub total_mutations: u64,
}

impl MutationStats {
    /// Create empty stats.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a mutation with the given strategy.
    pub fn record(&mut self, strategy: MutationStrategy, interesting: bool) {
        let key = strategy.name().to_string();
        *self.strategy_counts.entry(key.clone()).or_insert(0) += 1;
        if interesting {
            *self.interesting_counts.entry(key).or_insert(0) += 1;
        }
        self.total_mutations += 1;
    }

    /// Effectiveness ratio for a strategy: interesting / applied.
    #[must_use]
    pub fn effectiveness(&self, strategy: MutationStrategy) -> f64 {
        let key = strategy.name();
        let applied = self.strategy_counts.get(key).copied().unwrap_or(0);
        let interesting = self.interesting_counts.get(key).copied().unwrap_or(0);
        if applied == 0 {
            0.0
        } else {
            (interesting as f64) / (applied as f64)
        }
    }

    /// Reset all counters.
    pub fn reset(&mut self) {
        self.strategy_counts.clear();
        self.interesting_counts.clear();
        self.total_mutations = 0;
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn rng() -> Rng {
        Rng::new(0x1234_5678_abcd_ef01)
    }

    #[test]
    fn rng_nonzero() {
        let mut r = rng();
        for _ in 0..100 {
            assert_ne!(r.next_u64(), 0, "xorshift must not produce 0 repeatedly");
        }
    }

    #[test]
    fn mutation_strategy_names() {
        assert_eq!(MutationStrategy::BitFlip.name(), "bit_flip");
        assert_eq!(MutationStrategy::Havoc.name(), "havoc");
    }

    #[test]
    fn mutation_strategy_all_count() {
        assert_eq!(MutationStrategy::all().len(), 12);
    }

    #[test]
    fn base_bit_flip_changes_data() {
        let m = BaseMutator::new();
        let mut r = rng();
        let orig = vec![0u8; 16];
        let out = m.bit_flip(&orig, &mut r);
        assert_ne!(orig, out);
        assert_eq!(out.len(), 16);
    }

    #[test]
    fn base_block_insert_grows() {
        let m = BaseMutator::new();
        let mut r = rng();
        let orig = vec![1u8; 8];
        let out = m.block_insert(&orig, &mut r);
        assert!(out.len() > orig.len());
    }

    #[test]
    fn base_block_delete_shrinks() {
        let m = BaseMutator::new();
        let mut r = rng();
        let orig = vec![1u8; 32];
        let out = m.block_delete(&orig, &mut r);
        assert!(out.len() < orig.len());
    }

    #[test]
    fn base_arithmetic_same_length() {
        let m = BaseMutator::new();
        let mut r = rng();
        let orig = vec![0u8; 8];
        let out = m.arithmetic(&orig, &mut r);
        assert_eq!(out.len(), orig.len());
    }

    #[test]
    fn crossover_single_point_length() {
        let mut r = rng();
        let a = vec![0u8; 10];
        let b = vec![1u8; 10];
        let out = Crossover::single_point(&a, &b, &mut r);
        assert!(!out.is_empty());
    }

    #[test]
    fn crossover_two_point_same_len() {
        let mut r = rng();
        let a = vec![0u8; 16];
        let b = vec![0xffu8; 16];
        let out = Crossover::two_point(&a, &b, &mut r);
        assert_eq!(out.len(), 16);
    }

    #[test]
    fn crossover_uniform_max_len() {
        let mut r = rng();
        let a = vec![0u8; 5];
        let b = vec![0u8; 10];
        let out = Crossover::uniform(&a, &b, &mut r);
        assert_eq!(out.len(), 10);
    }

    #[test]
    fn dictionary_pick_returns_entry() {
        let mut dict = Dictionary::new();
        dict.add_bytes(b"magic".to_vec());
        let mut r = rng();
        let picked = dict.pick(&mut r);
        assert!(picked.is_some());
        assert_eq!(picked.unwrap().token, b"magic");
    }

    #[test]
    fn dictionary_mutate_inserts_token() {
        let m = BaseMutator::new();
        let mut r = rng();
        let mut dict = Dictionary::new();
        dict.add_bytes(b"TOKEN".to_vec());
        let orig = b"hello world".to_vec();
        let out = m.dictionary_mutate(&orig, &dict, &mut r);
        // Output must contain the token bytes somewhere.
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("TOKEN") || out.windows(5).any(|w| w == b"TOKEN"), "token missing");
    }

    #[test]
    fn structure_detect_cstring() {
        let data = b"hello\0world\0".to_vec();
        let fields = StructureMutation::detect_fields(&data);
        assert!(!fields.is_empty());
        assert!(fields.iter().any(|f| f.kind == FieldKind::CString));
    }

    #[test]
    fn structure_mutate_returns_same_length_ish() {
        let mut r = rng();
        let data = b"hello\0world\0extra_bytes".to_vec();
        let out = StructureMutation::mutate(&data, &mut r);
        assert!(!out.is_empty());
    }

    #[test]
    fn redqueen_direct_substitution() {
        let cmp = RedQueenComparison {
            input_offset: 0,
            input_value: b"AAAA".to_vec(),
            compare_value: b"PASS".to_vec(),
            cmp_type: CmpType::StrEq,
        };
        let input = b"AAAA_other_data".to_vec();
        let mut r = rng();
        let mutations = cmp.generate_mutations(&input, &mut r);
        assert!(!mutations.is_empty());
        // First mutation should have "PASS" at offset 0.
        assert_eq!(&mutations[0][..4], b"PASS");
    }

    #[test]
    fn havoc_produces_output() {
        let m = BaseMutator::new();
        let mut r = rng();
        let config = HavocConfig::default();
        let orig = b"fuzz_target_data".to_vec();
        let out = m.havoc(&orig, &mut r, &config, None, None);
        assert!(!out.is_empty());
    }

    #[test]
    fn havoc_max_size_respected() {
        let m = BaseMutator::new();
        let mut r = rng();
        let mut config = HavocConfig::default();
        config.max_size = 4;
        let orig = vec![0u8; 100];
        let out = m.havoc(&orig, &mut r, &config, None, None);
        assert!(out.len() <= 4);
    }

    #[test]
    fn mutation_stats_record() {
        let mut stats = MutationStats::new();
        stats.record(MutationStrategy::BitFlip, true);
        stats.record(MutationStrategy::BitFlip, false);
        assert_eq!(stats.total_mutations, 2);
        assert!((stats.effectiveness(MutationStrategy::BitFlip) - 0.5).abs() < 1e-9);
    }

    #[test]
    fn dictionary_entry_display() {
        let e = DictionaryEntry::labelled(b"ok".to_vec(), "ok_token");
        assert!(e.to_string().contains("ok_token"));
    }

    #[test]
    fn redqueen_engine_apply_one() {
        let mut engine = RedQueenEngine::new();
        engine.add_comparison(RedQueenComparison {
            input_offset: 0,
            input_value: b"AA".to_vec(),
            compare_value: b"OK".to_vec(),
            cmp_type: CmpType::StrEq,
        });
        let input = b"AA_data".to_vec();
        let mut r = rng();
        let result = engine.apply_one(&input, &mut r);
        assert!(result.is_some());
    }
}
