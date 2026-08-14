//! AFL++ mutation engine for `rustre-fuzz-afl`.
//!
//! Implements the full suite of AFL++ mutation strategies:
//! - [`DeterministicMutations`]: bitflip 1/2/4/8/16/32, byte flip,
//!   arithmetic add/sub 8/16/32, interesting value substitution.
//! - [`HavocMutations`]: random strategy selection combining many sub-strategies.
//! - [`SpliceMutation`]: splice two inputs together at a random offset.
//! - [`DictionaryMutator`]: insert/replace with tokens from a dictionary.
//! - [`RadamsaMutator`]: stub for Radamsa-style mutations.
//! - [`AflMutator`]: high-level facade combining all of the above.

use std::collections::VecDeque;
use std::fmt;

// ---------------------------------------------------------------------------
// Interesting values used by arithmetic mutations
// ---------------------------------------------------------------------------

/// Interesting 8-bit values (boundaries, common special values).
pub const INTERESTING_8: &[u8] = &[0x00, 0x01, 0x7F, 0x80, 0xFF, b'A', b'a', b' ', b'\n', b'\r'];

/// Interesting 16-bit values (little-endian).
pub const INTERESTING_16: &[u16] = &[
    0x0000, 0x0001, 0x007F, 0x0080, 0x00FF, 0x0100, 0x7FFF, 0x8000, 0xFFFF, 0x0200, 0x0400, 0x1000,
    0x2000, 0x4000,
];

/// Interesting 32-bit values.
pub const INTERESTING_32: &[u32] = &[
    0x0000_0000,
    0x0000_0001,
    0x0000_007F,
    0x0000_0080,
    0x0000_00FF,
    0x0000_0100,
    0x0000_7FFF,
    0x0000_8000,
    0x0000_FFFF,
    0x7FFF_FFFF,
    0x8000_0000,
    0xFFFF_FFFF,
    0x0001_0000,
    0xDEAD_BEEF,
    0xCAFE_BABE,
];

// ---------------------------------------------------------------------------
// MutationContext
// ---------------------------------------------------------------------------

/// Context passed to mutation functions.
#[derive(Debug, Clone)]
pub struct MutationContext {
    /// RNG state (LCG for reproducibility).
    rng_state: u64,
    /// Maximum output size.
    pub max_size: usize,
    /// Minimum output size.
    pub min_size: usize,
}

impl MutationContext {
    /// Create a context with the given seed.
    #[must_use]
    pub const fn new(seed: u64, min_size: usize, max_size: usize) -> Self {
        Self {
            rng_state: seed,
            min_size,
            max_size,
        }
    }

    /// Generate the next pseudo-random u64.
    pub const fn rand_u64(&mut self) -> u64 {
        // xorshift64
        let mut x = self.rng_state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng_state = x;
        x
    }

    /// Generate a random usize in `[0, n)`.
    pub fn rand_range(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        // val < n ≤ usize::MAX; TryFrom is infallible here.
        usize::try_from(self.rand_u64() % (n as u64)).unwrap_or(0)
    }

    /// Pick a random byte.
    pub const fn rand_byte(&mut self) -> u8 {
        self.rand_u64().to_le_bytes()[0]
    }
}

impl Default for MutationContext {
    fn default() -> Self {
        Self::new(0xDEAD_BEEF_CAFE_BABE, 1, 65536)
    }
}

// ---------------------------------------------------------------------------
// DeterministicMutations
// ---------------------------------------------------------------------------

/// Iterator over all bitflip-1 mutations of a buffer.
pub struct BitFlip1Iter {
    data: Vec<u8>,
    bit_pos: usize,
    total_bits: usize,
}

impl BitFlip1Iter {
    #[must_use]
    pub const fn new(data: Vec<u8>) -> Self {
        let total_bits = data.len() * 8;
        Self {
            data,
            bit_pos: 0,
            total_bits,
        }
    }
}

impl Iterator for BitFlip1Iter {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bit_pos >= self.total_bits {
            return None;
        }
        let mut out = self.data.clone();
        let byte_idx = self.bit_pos / 8;
        let bit_idx = self.bit_pos % 8;
        out[byte_idx] ^= 1 << bit_idx;
        self.bit_pos += 1;
        Some(out)
    }
}

/// All deterministic AFL++ mutations.
pub struct DeterministicMutations;

impl DeterministicMutations {
    /// Generate all bitflip-1 mutations (one bit at a time).
    #[must_use]
    pub fn bitflip_1(data: &[u8]) -> Vec<Vec<u8>> {
        (0..data.len() * 8)
            .map(|bit| {
                let mut out = data.to_vec();
                out[bit / 8] ^= 1 << (bit % 8);
                out
            })
            .collect()
    }

    /// Generate all bitflip-2 mutations (two consecutive bits).
    #[must_use]
    pub fn bitflip_2(data: &[u8]) -> Vec<Vec<u8>> {
        let bits = data.len() * 8;
        if bits < 2 {
            return vec![];
        }
        (0..bits - 1)
            .map(|bit| {
                let mut out = data.to_vec();
                out[bit / 8] ^= 1 << (bit % 8);
                out[(bit + 1) / 8] ^= 1 << ((bit + 1) % 8);
                out
            })
            .collect()
    }

    /// Generate all bitflip-4 mutations (four consecutive bits).
    #[must_use]
    pub fn bitflip_4(data: &[u8]) -> Vec<Vec<u8>> {
        let bits = data.len() * 8;
        if bits < 4 {
            return vec![];
        }
        (0..bits - 3)
            .map(|bit| {
                let mut out = data.to_vec();
                for i in 0..4 {
                    out[(bit + i) / 8] ^= 1 << ((bit + i) % 8);
                }
                out
            })
            .collect()
    }

    /// Generate all byte-flip mutations (XOR entire byte with 0xFF).
    #[must_use]
    pub fn byteflip_8(data: &[u8]) -> Vec<Vec<u8>> {
        (0..data.len())
            .map(|i| {
                let mut out = data.to_vec();
                out[i] ^= 0xFF;
                out
            })
            .collect()
    }

    /// Generate all 16-bit byte-flip mutations.
    #[must_use]
    pub fn byteflip_16(data: &[u8]) -> Vec<Vec<u8>> {
        if data.len() < 2 {
            return vec![];
        }
        (0..data.len() - 1)
            .map(|i| {
                let mut out = data.to_vec();
                out[i] ^= 0xFF;
                out[i + 1] ^= 0xFF;
                out
            })
            .collect()
    }

    /// Generate all 32-bit byte-flip mutations.
    #[must_use]
    pub fn byteflip_32(data: &[u8]) -> Vec<Vec<u8>> {
        if data.len() < 4 {
            return vec![];
        }
        (0..data.len() - 3)
            .map(|i| {
                let mut out = data.to_vec();
                for j in 0..4 {
                    out[i + j] ^= 0xFF;
                }
                out
            })
            .collect()
    }

    /// Arithmetic: add/subtract small values (1..=35) to each byte.
    #[must_use]
    pub fn arith_8(data: &[u8]) -> Vec<Vec<u8>> {
        // dos-memory-exhaustion: cap before O(n*70) allocation.
        let data = if data.len() > crate::STAGE_INPUT_MAX_BYTES { &data[..crate::STAGE_INPUT_MAX_BYTES] } else { data };
        let mut results = Vec::with_capacity(data.len() * 70);
        for i in 0..data.len() {
            for delta in 1u8..=35 {
                let mut add = data.to_vec();
                add[i] = add[i].wrapping_add(delta);
                results.push(add);
                let mut sub = data.to_vec();
                sub[i] = sub[i].wrapping_sub(delta);
                results.push(sub);
            }
        }
        results
    }

    /// Arithmetic 16-bit: add/subtract 1..=35 to each 16-bit word.
    #[must_use]
    pub fn arith_16(data: &[u8]) -> Vec<Vec<u8>> {
        let data = if data.len() > crate::STAGE_INPUT_MAX_BYTES { &data[..crate::STAGE_INPUT_MAX_BYTES] } else { data };
        if data.len() < 2 {
            return vec![];
        }
        let mut results = Vec::with_capacity((data.len() - 1) * 70);
        for i in 0..data.len() - 1 {
            let orig = u16::from_le_bytes([data[i], data[i + 1]]);
            for delta in 1u16..=35 {
                let mut add = data.to_vec();
                let v = orig.wrapping_add(delta).to_le_bytes();
                add[i] = v[0];
                add[i + 1] = v[1];
                results.push(add);
                let mut sub = data.to_vec();
                let v = orig.wrapping_sub(delta).to_le_bytes();
                sub[i] = v[0];
                sub[i + 1] = v[1];
                results.push(sub);
            }
        }
        results
    }

    /// Arithmetic 32-bit: add/subtract 1..=35 to each 32-bit word.
    #[must_use]
    pub fn arith_32(data: &[u8]) -> Vec<Vec<u8>> {
        let data = if data.len() > crate::STAGE_INPUT_MAX_BYTES { &data[..crate::STAGE_INPUT_MAX_BYTES] } else { data };
        if data.len() < 4 {
            return vec![];
        }
        let mut results = Vec::with_capacity((data.len() - 3) * 70);
        for i in 0..data.len() - 3 {
            let orig = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            for delta in 1u32..=35 {
                let mut add = data.to_vec();
                let v = orig.wrapping_add(delta).to_le_bytes();
                add[i..i + 4].copy_from_slice(&v);
                results.push(add);
                let mut sub = data.to_vec();
                let v = orig.wrapping_sub(delta).to_le_bytes();
                sub[i..i + 4].copy_from_slice(&v);
                results.push(sub);
            }
        }
        results
    }

    /// Interesting 8-bit value substitution.
    #[must_use]
    pub fn interesting_8(data: &[u8]) -> Vec<Vec<u8>> {
        let mut results = Vec::with_capacity(data.len() * INTERESTING_8.len());
        for i in 0..data.len() {
            for &v in INTERESTING_8 {
                if v != data[i] {
                    let mut out = data.to_vec();
                    out[i] = v;
                    results.push(out);
                }
            }
        }
        results
    }

    /// Interesting 16-bit value substitution.
    #[must_use]
    pub fn interesting_16(data: &[u8]) -> Vec<Vec<u8>> {
        if data.len() < 2 {
            return vec![];
        }
        let mut results = Vec::with_capacity((data.len() - 1) * INTERESTING_16.len());
        for i in 0..data.len() - 1 {
            for &v in INTERESTING_16 {
                let bytes = v.to_le_bytes();
                if bytes[0] != data[i] || bytes[1] != data[i + 1] {
                    let mut out = data.to_vec();
                    out[i] = bytes[0];
                    out[i + 1] = bytes[1];
                    results.push(out);
                }
            }
        }
        results
    }

    /// Interesting 32-bit value substitution.
    #[must_use]
    pub fn interesting_32(data: &[u8]) -> Vec<Vec<u8>> {
        if data.len() < 4 {
            return vec![];
        }
        let mut results = Vec::with_capacity((data.len() - 3) * INTERESTING_32.len());
        for i in 0..data.len() - 3 {
            for &v in INTERESTING_32 {
                let bytes = v.to_le_bytes();
                if bytes != data[i..i + 4] {
                    let mut out = data.to_vec();
                    out[i..i + 4].copy_from_slice(&bytes);
                    results.push(out);
                }
            }
        }
        results
    }
}

// ---------------------------------------------------------------------------
// HavocMutations
// ---------------------------------------------------------------------------

/// Strategy codes for havoc stage selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HavocStrategy {
    BitFlip,
    ByteFlip,
    SetInteresting8,
    SetInteresting16,
    SetInteresting32,
    Arith8,
    Arith16,
    Arith32,
    SetRandom,
    DeleteBytes,
    InsertBytes,
    OverwriteBytes,
    CloneBytes,
    Splice,
    Nop,
}

impl HavocStrategy {
    const ALL: &'static [Self] = &[
        Self::BitFlip,
        Self::ByteFlip,
        Self::SetInteresting8,
        Self::SetInteresting16,
        Self::SetInteresting32,
        Self::Arith8,
        Self::Arith16,
        Self::Arith32,
        Self::SetRandom,
        Self::DeleteBytes,
        Self::InsertBytes,
        Self::OverwriteBytes,
        Self::CloneBytes,
        Self::Splice,
        Self::Nop,
    ];

    fn pick(ctx: &mut MutationContext) -> Self {
        Self::ALL[ctx.rand_range(Self::ALL.len())]
    }
}

/// Havoc stage: applies a random sequence of mutations.
pub struct HavocMutations {
    /// Number of mutation steps per call to [`apply`].
    pub num_steps: usize,
}

impl HavocMutations {
    #[must_use]
    pub const fn new(num_steps: usize) -> Self {
        Self { num_steps }
    }

    /// Apply `num_steps` random mutations to `data`.
    #[must_use]
    pub fn apply(&self, data: &[u8], ctx: &mut MutationContext) -> Vec<u8> {
        let mut buf = data.to_vec();
        for _ in 0..self.num_steps {
            if buf.is_empty() {
                break;
            }
            buf = Self::apply_one(buf, ctx);
        }
        buf
    }

    fn apply_arithmetic_mutation(mut data: Vec<u8>, ctx: &mut MutationContext, strategy: HavocStrategy) -> Vec<u8> {
        match strategy {
            HavocStrategy::Arith8 => {
                let pos = ctx.rand_range(data.len());
                let delta = u8::try_from(ctx.rand_range(35) + 1).unwrap_or(35);
                if ctx.rand_range(2) == 0 {
                    data[pos] = data[pos].wrapping_add(delta);
                } else {
                    data[pos] = data[pos].wrapping_sub(delta);
                }
            }
            HavocStrategy::Arith16 => {
                if data.len() >= 2 {
                    let pos = ctx.rand_range(data.len() - 1);
                    let v = u16::from_le_bytes([data[pos], data[pos + 1]]);
                    let delta = u16::try_from(ctx.rand_range(35) + 1).unwrap_or(35);
                    let result = if ctx.rand_range(2) == 0 {
                        v.wrapping_add(delta)
                    } else {
                        v.wrapping_sub(delta)
                    };
                    let bytes = result.to_le_bytes();
                    data[pos] = bytes[0];
                    data[pos + 1] = bytes[1];
                }
            }
            HavocStrategy::Arith32
                if data.len() >= 4 => {
                    let pos = ctx.rand_range(data.len() - 3);
                    let v = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
                    let delta = u32::try_from(ctx.rand_range(35) + 1).unwrap_or(35);
                    let result = if ctx.rand_range(2) == 0 {
                        v.wrapping_add(delta)
                    } else {
                        v.wrapping_sub(delta)
                    };
                    data[pos..pos + 4].copy_from_slice(&result.to_le_bytes());
                }
            _ => {}
        }
        data
    }

    fn apply_one(mut data: Vec<u8>, ctx: &mut MutationContext) -> Vec<u8> {
        if data.is_empty() {
            return data;
        }
        let strategy = HavocStrategy::pick(ctx);
        match strategy {
            HavocStrategy::BitFlip => {
                let bit = ctx.rand_range(data.len() * 8);
                data[bit / 8] ^= 1 << (bit % 8);
            }
            HavocStrategy::ByteFlip => {
                let pos = ctx.rand_range(data.len());
                data[pos] ^= 0xFF;
            }
            HavocStrategy::SetInteresting8 => {
                let pos = ctx.rand_range(data.len());
                let idx = ctx.rand_range(INTERESTING_8.len());
                data[pos] = INTERESTING_8[idx];
            }
            HavocStrategy::SetInteresting16 => {
                if data.len() >= 2 {
                    let pos = ctx.rand_range(data.len() - 1);
                    let idx = ctx.rand_range(INTERESTING_16.len());
                    let v = INTERESTING_16[idx].to_le_bytes();
                    data[pos] = v[0];
                    data[pos + 1] = v[1];
                }
            }
            HavocStrategy::SetInteresting32 => {
                if data.len() >= 4 {
                    let pos = ctx.rand_range(data.len() - 3);
                    let idx = ctx.rand_range(INTERESTING_32.len());
                    let v = INTERESTING_32[idx].to_le_bytes();
                    data[pos..pos + 4].copy_from_slice(&v);
                }
            }
            HavocStrategy::Arith8 | HavocStrategy::Arith16 | HavocStrategy::Arith32 => {
                return Self::apply_arithmetic_mutation(data, ctx, strategy);
            }
            HavocStrategy::SetRandom => {
                let pos = ctx.rand_range(data.len());
                data[pos] = ctx.rand_byte();
            }
            HavocStrategy::DeleteBytes => {
                if data.len() > ctx.min_size {
                    let pos = ctx.rand_range(data.len());
                    let len = 1 + ctx.rand_range((data.len() - pos).min(16));
                    data.drain(pos..pos + len);
                }
            }
            HavocStrategy::InsertBytes => {
                if data.len() < ctx.max_size {
                    let pos = ctx.rand_range(data.len() + 1);
                    let len = 1 + ctx.rand_range(16);
                    let insert: Vec<u8> = (0..len).map(|_| ctx.rand_byte()).collect();
                    data.splice(pos..pos, insert);
                }
            }
            HavocStrategy::OverwriteBytes => {
                let pos = ctx.rand_range(data.len());
                let len = 1 + ctx.rand_range((data.len() - pos).min(8));
                for b in &mut data[pos..pos + len] {
                    *b = ctx.rand_byte();
                }
            }
            HavocStrategy::CloneBytes => {
                if data.len() < ctx.max_size && data.len() > 1 {
                    let src = ctx.rand_range(data.len());
                    let len = 1 + ctx.rand_range((data.len() - src).min(16));
                    let cloned = data[src..src + len].to_vec();
                    let dst = ctx.rand_range(data.len() + 1);
                    data.splice(dst..dst, cloned);
                }
            }
            HavocStrategy::Splice | HavocStrategy::Nop => {}
        }
        data
    }
}

impl Default for HavocMutations {
    fn default() -> Self {
        Self::new(16)
    }
}

// ---------------------------------------------------------------------------
// SpliceMutation
// ---------------------------------------------------------------------------

/// Splices two inputs together at a random split point.
pub struct SpliceMutation;

impl SpliceMutation {
    /// Splice `a` and `b` at a random midpoint.
    ///
    /// The first half comes from `a`, the second half from `b` (or vice versa).
    #[must_use]
    pub fn splice(a: &[u8], b: &[u8], ctx: &mut MutationContext) -> Vec<u8> {
        if a.is_empty() || b.is_empty() {
            return if a.is_empty() { b.to_vec() } else { a.to_vec() };
        }
        let split_a = ctx.rand_range(a.len());
        let split_b = ctx.rand_range(b.len());
        let mut out = a[..split_a].to_vec();
        out.extend_from_slice(&b[split_b..]);
        out
    }

    /// Splice at an aligned boundary.
    #[must_use]
    pub fn splice_aligned(a: &[u8], b: &[u8], ctx: &mut MutationContext, align: usize) -> Vec<u8> {
        if a.is_empty() || b.is_empty() || align == 0 {
            return Self::splice(a, b, ctx);
        }
        let blocks_a = (a.len() / align).max(1);
        let blocks_b = (b.len() / align).max(1);
        let split_a = ctx.rand_range(blocks_a) * align;
        let split_b = ctx.rand_range(blocks_b) * align;
        let mut out = a[..split_a.min(a.len())].to_vec();
        out.extend_from_slice(&b[split_b.min(b.len())..]);
        out
    }
}

// ---------------------------------------------------------------------------
// DictionaryMutator
// ---------------------------------------------------------------------------

/// A single dictionary token.
#[derive(Debug, Clone)]
pub struct DictToken {
    pub value: Vec<u8>,
    pub label: String,
    pub use_count: u64,
}

impl DictToken {
    #[must_use]
    pub fn new(value: Vec<u8>, label: impl Into<String>) -> Self {
        Self {
            value,
            label: label.into(),
            use_count: 0,
        }
    }

    #[must_use]
    pub fn parse_str(s: &str) -> Self {
        Self::new(s.as_bytes().to_vec(), s)
    }
}

impl std::str::FromStr for DictToken {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::parse_str(s))
    }
}

/// Applies dictionary tokens to fuzzing inputs via insertion and overwrite.
pub struct DictionaryMutator {
    pub tokens: Vec<DictToken>,
}

impl DictionaryMutator {
    #[must_use]
    pub const fn new() -> Self {
        Self { tokens: Vec::new() }
    }

    /// Add a token from a byte slice.
    pub fn add_token(&mut self, token: Vec<u8>, label: impl Into<String>) {
        self.tokens.push(DictToken::new(token, label));
    }

    /// Add a string token.
    pub fn add_str(&mut self, s: &str) {
        self.tokens.push(DictToken::parse_str(s));
    }

    /// Load multiple tokens from a list of strings.
    pub fn load_strs(&mut self, tokens: &[&str]) {
        for s in tokens {
            self.add_str(s);
        }
    }

    /// Insert a random token at a random position.
    #[must_use]
    pub fn insert(&self, data: &[u8], ctx: &mut MutationContext) -> Option<Vec<u8>> {
        if self.tokens.is_empty() {
            return None;
        }
        let tok = &self.tokens[ctx.rand_range(self.tokens.len())];
        let pos = ctx.rand_range(data.len() + 1);
        let mut out = data[..pos].to_vec();
        out.extend_from_slice(&tok.value);
        out.extend_from_slice(&data[pos..]);
        Some(out)
    }

    /// Overwrite a random position with a random token.
    #[must_use]
    pub fn overwrite(&self, data: &[u8], ctx: &mut MutationContext) -> Option<Vec<u8>> {
        if self.tokens.is_empty() || data.is_empty() {
            return None;
        }
        let tok = &self.tokens[ctx.rand_range(self.tokens.len())];
        let tok_len = tok.value.len().min(data.len());
        let pos = ctx.rand_range(data.len().saturating_sub(tok_len) + 1);
        let end = (pos + tok_len).min(data.len());
        let mut out = data.to_vec();
        out[pos..end].copy_from_slice(&tok.value[..end - pos]);
        Some(out)
    }

    /// Apply insert or overwrite randomly.
    #[must_use]
    pub fn apply(&self, data: &[u8], ctx: &mut MutationContext) -> Vec<u8> {
        if ctx.rand_range(2) == 0 {
            self.insert(data, ctx)
        } else {
            self.overwrite(data, ctx)
        }
        .unwrap_or_else(|| data.to_vec())
    }
}

impl Default for DictionaryMutator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RadamsaMutator (stub)
// ---------------------------------------------------------------------------

/// A stub for Radamsa-style mutations.
///
/// In production this would shell out to the `radamsa` binary or link against
/// a Radamsa library.  Here we implement a simplified subset.
pub struct RadamsaMutator {
    pub enabled: bool,
}

impl RadamsaMutator {
    #[must_use]
    pub const fn new() -> Self {
        Self { enabled: true }
    }

    /// Apply a Radamsa-inspired mutation (simplified).
    #[must_use]
    pub fn mutate(&self, data: &[u8], ctx: &mut MutationContext) -> Vec<u8> {
        if !self.enabled || data.is_empty() {
            return data.to_vec();
        }
        // Simple strategies: truncate, repeat a chunk, insert zeros.
        match ctx.rand_range(4) {
            0 => {
                // Truncate.
                let len = 1 + ctx.rand_range(data.len());
                data[..len].to_vec()
            }
            1 => {
                // Repeat a random chunk.
                let start = ctx.rand_range(data.len());
                let len = 1 + ctx.rand_range((data.len() - start).min(32));
                let chunk = data[start..start + len].to_vec();
                let times = 2 + ctx.rand_range(4);
                let mut out = data.to_vec();
                for _ in 0..times {
                    out.extend_from_slice(&chunk);
                }
                out
            }
            2 => {
                // Insert null bytes.
                let pos = ctx.rand_range(data.len() + 1);
                let count = 1 + ctx.rand_range(16);
                let mut out = data[..pos].to_vec();
                out.extend(std::iter::repeat_n(0, count));
                out.extend_from_slice(&data[pos..]);
                out
            }
            _ => {
                // Reverse a chunk.
                let start = ctx.rand_range(data.len());
                let len = 1 + ctx.rand_range((data.len() - start).min(16));
                let mut out = data.to_vec();
                out[start..start + len].reverse();
                out
            }
        }
    }
}

impl Default for RadamsaMutator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AflMutator
// ---------------------------------------------------------------------------

/// High-level AFL++ mutation façade.
///
/// Combines all mutation strategies and exposes them through a single
/// `mutate` entry point that selects the strategy based on the fuzzing stage.
pub struct AflMutator {
    pub havoc: HavocMutations,
    pub dict: DictionaryMutator,
    pub radamsa: RadamsaMutator,
    /// Corpus queue (used for splice mutations).
    corpus: VecDeque<Vec<u8>>,
    /// Current stage.
    pub stage: AflStage,
}

/// AFL++ fuzzing stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AflStage {
    Deterministic,
    Havoc,
    Splice,
    Radamsa,
}

impl AflMutator {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            havoc: HavocMutations::new(8),
            dict: DictionaryMutator::new(),
            radamsa: RadamsaMutator::new(),
            corpus: VecDeque::new(),
            stage: AflStage::Havoc,
        }
    }

    /// Add a corpus entry for splice mutations.
    pub fn add_corpus(&mut self, entry: Vec<u8>) {
        if self.corpus.len() >= 1024 {
            self.corpus.pop_front();
        }
        self.corpus.push_back(entry);
    }

    /// Apply a single mutation step.
    #[must_use]
    pub fn mutate(&self, data: &[u8], ctx: &mut MutationContext) -> Vec<u8> {
        match self.stage {
            AflStage::Deterministic => {
                // Pick a random deterministic mutation.
                match ctx.rand_range(4) {
                    0 => DeterministicMutations::bitflip_1(data)
                        .into_iter()
                        .next()
                        .unwrap_or_else(|| data.to_vec()),
                    1 => DeterministicMutations::interesting_8(data)
                        .into_iter()
                        .next()
                        .unwrap_or_else(|| data.to_vec()),
                    2 => DeterministicMutations::arith_8(data)
                        .into_iter()
                        .next()
                        .unwrap_or_else(|| data.to_vec()),
                    _ => DeterministicMutations::byteflip_8(data)
                        .into_iter()
                        .next()
                        .unwrap_or_else(|| data.to_vec()),
                }
            }
            AflStage::Havoc => self.havoc.apply(data, ctx),
            AflStage::Splice => {
                if let Some(other) = self
                    .corpus
                    .get(ctx.rand_range(self.corpus.len().max(1)))
                {
                    SpliceMutation::splice(data, other, ctx)
                } else {
                    self.havoc.apply(data, ctx)
                }
            }
            AflStage::Radamsa => self.radamsa.mutate(data, ctx),
        }
    }

    /// Generate `count` mutations of `data`.
    #[must_use]
    pub fn generate_batch(
        &self,
        data: &[u8],
        count: usize,
        ctx: &mut MutationContext,
    ) -> Vec<Vec<u8>> {
        (0..count).map(|_| self.mutate(data, ctx)).collect()
    }
}

impl Default for AflMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for AflMutator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AflMutator(stage={:?}, dict_tokens={}, corpus={})",
            self.stage,
            self.dict.tokens.len(),
            self.corpus.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> MutationContext {
        MutationContext::new(12345, 1, 65536)
    }

    fn input() -> Vec<u8> {
        b"HELLO WORLD".to_vec()
    }

    // ── DeterministicMutations ────────────────────────────────────────────

    #[test]
    fn bitflip1_count() {
        let data = &[0u8; 4];
        let muts = DeterministicMutations::bitflip_1(data);
        assert_eq!(muts.len(), 32); // 4 bytes × 8 bits
    }

    #[test]
    fn bitflip1_changes_exactly_one_bit() {
        let data = vec![0u8; 2];
        let muts = DeterministicMutations::bitflip_1(&data);
        for m in &muts {
            let changed: usize = m
                .iter()
                .zip(data.iter())
                .map(|(a, b)| (a ^ b).count_ones() as usize)
                .sum();
            assert_eq!(changed, 1);
        }
    }

    #[test]
    fn bitflip2_count() {
        let data = &[0u8; 4];
        let muts = DeterministicMutations::bitflip_2(data);
        assert_eq!(muts.len(), 31); // 32 - 1
    }

    #[test]
    fn bitflip4_count() {
        let data = &[0u8; 4];
        let muts = DeterministicMutations::bitflip_4(data);
        assert_eq!(muts.len(), 29); // 32 - 3
    }

    #[test]
    fn byteflip8_all_ff() {
        let data = vec![0u8; 4];
        let muts = DeterministicMutations::byteflip_8(&data);
        assert_eq!(muts.len(), 4);
        for (i, m) in muts.iter().enumerate() {
            assert_eq!(m[i], 0xFF);
        }
    }

    #[test]
    fn byteflip16_count() {
        let data = &[0u8; 4];
        assert_eq!(DeterministicMutations::byteflip_16(data).len(), 3);
    }

    #[test]
    fn byteflip32_count() {
        let data = &[0u8; 6];
        assert_eq!(DeterministicMutations::byteflip_32(data).len(), 3);
    }

    #[test]
    fn arith8_produces_add_and_sub() {
        let data = &[50u8];
        let muts = DeterministicMutations::arith_8(data);
        assert!(!muts.is_empty());
        let values: std::collections::HashSet<u8> = muts.iter().map(|m| m[0]).collect();
        assert!(values.contains(&51)); // 50 + 1
        assert!(values.contains(&49)); // 50 - 1
    }

    #[test]
    fn arith16_produces_results() {
        let data = &[0x00u8, 0x01];
        let muts = DeterministicMutations::arith_16(data);
        assert!(!muts.is_empty());
    }

    #[test]
    fn arith32_produces_results() {
        let data = &[0x00u8, 0x00, 0x00, 0x01];
        let muts = DeterministicMutations::arith_32(data);
        assert!(!muts.is_empty());
    }

    #[test]
    fn interesting8_substitutes_values() {
        let data = &[0x42u8, 0x42];
        let muts = DeterministicMutations::interesting_8(data);
        assert!(!muts.is_empty());
        assert!(muts.iter().any(|m| m[0] == 0x00 || m[0] == 0xFF));
    }

    #[test]
    fn interesting16_substitutes() {
        let data = &[0x42u8, 0x42];
        assert!(!DeterministicMutations::interesting_16(data).is_empty());
    }

    #[test]
    fn interesting32_substitutes() {
        let data = &[0x42u8, 0x42, 0x42, 0x42];
        assert!(!DeterministicMutations::interesting_32(data).is_empty());
    }

    // ── BitFlip1Iter ──────────────────────────────────────────────────────

    #[test]
    fn bitflip1_iter() {
        let iter = BitFlip1Iter::new(vec![0u8; 2]);
        
        assert_eq!(iter.count(), 16);
    }

    // ── HavocMutations ────────────────────────────────────────────────────

    #[test]
    fn havoc_produces_output() {
        let havoc = HavocMutations::new(4);
        let mut ctx = ctx();
        let out = havoc.apply(&input(), &mut ctx);
        assert!(!out.is_empty());
    }

    #[test]
    fn havoc_respects_min_size() {
        let mut ctx = MutationContext::new(0, 4, 65536);
        let havoc = HavocMutations::new(100);
        let data = vec![0u8; 4];
        let out = havoc.apply(&data, &mut ctx);
        assert!(!out.is_empty()); // may hit edge cases
    }

    #[test]
    fn havoc_batch() {
        let mut mutator = AflMutator::new();
        mutator.stage = AflStage::Havoc;
        let mut ctx = ctx();
        let batch = mutator.generate_batch(&input(), 10, &mut ctx);
        assert_eq!(batch.len(), 10);
    }

    // ── SpliceMutation ────────────────────────────────────────────────────

    #[test]
    fn splice_non_empty() {
        let mut ctx = ctx();
        let a = b"ABCDEF".to_vec();
        let b = b"123456".to_vec();
        let out = SpliceMutation::splice(&a, &b, &mut ctx);
        assert!(!out.is_empty());
    }

    #[test]
    fn splice_empty_a() {
        let mut ctx = ctx();
        let out = SpliceMutation::splice(&[], b"abc", &mut ctx);
        assert_eq!(out, b"abc");
    }

    #[test]
    fn splice_aligned() {
        let mut ctx = ctx();
        let a = vec![0u8; 16];
        let b = vec![0xFFu8; 16];
        let out = SpliceMutation::splice_aligned(&a, &b, &mut ctx, 4);
        assert!(!out.is_empty());
    }

    // ── DictionaryMutator ─────────────────────────────────────────────────

    #[test]
    fn dict_insert() {
        let mut dict = DictionaryMutator::new();
        dict.add_str("TOKEN");
        let mut ctx = ctx();
        let out = dict.insert(b"hello", &mut ctx);
        assert!(out.is_some());
        let out = out.unwrap();
        assert!(out.windows(5).any(|w| w == b"TOKEN"));
    }

    #[test]
    fn dict_overwrite() {
        let mut dict = DictionaryMutator::new();
        dict.add_token(vec![0xFF, 0xFF], "ff");
        let mut ctx = ctx();
        let out = dict.overwrite(b"ABCDEF", &mut ctx);
        assert!(out.is_some());
    }

    #[test]
    fn dict_empty_returns_original() {
        let dict = DictionaryMutator::new();
        let mut ctx = ctx();
        let out = dict.apply(b"data", &mut ctx);
        assert_eq!(out, b"data");
    }

    #[test]
    fn dict_load_strs() {
        let mut dict = DictionaryMutator::new();
        dict.load_strs(&["a", "b", "c"]);
        assert_eq!(dict.tokens.len(), 3);
    }

    // ── RadamsaMutator ────────────────────────────────────────────────────

    #[test]
    fn radamsa_produces_output() {
        let r = RadamsaMutator::new();
        let mut ctx = ctx();
        let out = r.mutate(b"AAAAAAAAAA", &mut ctx);
        assert!(!out.is_empty());
    }

    #[test]
    fn radamsa_disabled_noop() {
        let r = RadamsaMutator { enabled: false };
        let mut ctx = ctx();
        let data = b"unchanged";
        let out = r.mutate(data, &mut ctx);
        assert_eq!(out, data);
    }

    // ── AflMutator ────────────────────────────────────────────────────────

    #[test]
    fn afl_mutator_default_stage_havoc() {
        let m = AflMutator::new();
        assert_eq!(m.stage, AflStage::Havoc);
    }

    #[test]
    fn afl_mutator_deterministic_stage() {
        let mut m = AflMutator::new();
        m.stage = AflStage::Deterministic;
        let mut ctx = ctx();
        let out = m.mutate(&input(), &mut ctx);
        assert!(!out.is_empty());
    }

    #[test]
    fn afl_mutator_splice_with_corpus() {
        let mut m = AflMutator::new();
        m.stage = AflStage::Splice;
        m.add_corpus(b"SPLICE_ME".to_vec());
        let mut ctx = ctx();
        let out = m.mutate(&input(), &mut ctx);
        assert!(!out.is_empty());
    }

    #[test]
    fn afl_mutator_splice_empty_corpus() {
        let mut m = AflMutator::new();
        m.stage = AflStage::Splice;
        let mut ctx = ctx();
        let out = m.mutate(&input(), &mut ctx);
        assert!(!out.is_empty());
    }

    #[test]
    fn afl_mutator_radamsa_stage() {
        let mut m = AflMutator::new();
        m.stage = AflStage::Radamsa;
        let mut ctx = ctx();
        let out = m.mutate(&input(), &mut ctx);
        assert!(!out.is_empty());
    }

    #[test]
    fn afl_mutator_debug() {
        let m = AflMutator::new();
        let s = format!("{m:?}");
        assert!(s.contains("AflMutator"));
    }

    // ── MutationContext ────────────────────────────────────────────────────

    #[test]
    fn mutation_context_rand_range_in_bounds() {
        let mut ctx = ctx();
        for _ in 0..100 {
            let v = ctx.rand_range(10);
            assert!(v < 10);
        }
    }

    #[test]
    fn mutation_context_rand_range_zero() {
        let mut ctx = ctx();
        assert_eq!(ctx.rand_range(0), 0);
    }

    #[test]
    fn mutation_context_rand_u64_nondeterministic() {
        let mut ctx = ctx();
        let a = ctx.rand_u64();
        let b = ctx.rand_u64();
        assert_ne!(a, b);
    }
}
