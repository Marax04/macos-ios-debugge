//! `function_hasher` — Hashing strategies for function bodies used in binary diff.
//!
//! Provides [`FunctionHasher`], [`HashKind`], and [`FunctionHash`] along with
//! the primary entry point [`hash_function`].

use std::collections::HashMap;
use std::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by function hashing operations.
#[derive(Debug, Error)]
pub enum HasherError {
    /// The input byte slice is empty.
    #[error("empty function body")]
    EmptyBody,
    /// A requested hash kind is not supported by this hasher configuration.
    #[error("unsupported hash kind: {0}")]
    UnsupportedKind(String),
}

// ---------------------------------------------------------------------------
// HashKind
// ---------------------------------------------------------------------------

/// The hashing strategy to apply to a function body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashKind {
    /// FNV-1a 64-bit hash of raw bytes — fastest, collision-prone.
    Fnv64,
    /// DJB2 hash — simple, widely used in symbol tables.
    Djb2,
    /// CRC-32 of raw bytes — commonly used in binary tooling.
    Crc32,
    /// Locality-sensitive minhash over 4-byte n-grams — fuzzy matching.
    Minhash4,
    /// Byte histogram hash — order-independent structural fingerprint.
    HistogramHash,
    /// CFG-aware block hash — XOR of per-block hashes, order-independent.
    BlockXor,
    /// Length-normalised hash: FNV-1a folded into a 32-bit value weighted
    /// by function length.
    LengthNorm,
}

impl HashKind {
    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Fnv64 => "fnv64",
            Self::Djb2 => "djb2",
            Self::Crc32 => "crc32",
            Self::Minhash4 => "minhash4",
            Self::HistogramHash => "histogram",
            Self::BlockXor => "block_xor",
            Self::LengthNorm => "length_norm",
        }
    }

    /// Whether this hash kind produces a fuzzy/locality-sensitive result
    /// suitable for approximate matching.
    #[must_use]
    pub const fn is_fuzzy(self) -> bool {
        matches!(self, Self::Minhash4 | Self::HistogramHash | Self::BlockXor)
    }
}

impl fmt::Display for HashKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ---------------------------------------------------------------------------
// FunctionHash
// ---------------------------------------------------------------------------

/// The result of hashing a function body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionHash {
    /// The hashing strategy used.
    pub kind: HashKind,
    /// The primary 64-bit hash value.
    pub value: u64,
    /// Optional secondary hash for schemes that produce two outputs
    /// (e.g. minhash produces a vector compressed into two u64).
    pub secondary: Option<u64>,
    /// Length of the hashed function body in bytes.
    pub body_len: usize,
}

impl FunctionHash {
    /// Create a simple single-value hash.
    #[must_use]
    pub const fn new(kind: HashKind, value: u64, body_len: usize) -> Self {
        Self { kind, value, secondary: None, body_len }
    }

    /// Create a hash with a secondary value.
    #[must_use]
    pub const fn with_secondary(kind: HashKind, value: u64, secondary: u64, body_len: usize) -> Self {
        Self { kind, value, secondary: Some(secondary), body_len }
    }

    /// Estimate similarity to another hash of the same kind.
    ///
    /// Returns `1.0` for identical hashes, `0.0` for different hashes,
    /// or a fractional value for fuzzy hash kinds.
    #[must_use]
    pub fn similarity(&self, other: &Self) -> f64 {
        if self.kind != other.kind {
            return 0.0;
        }
        if self.value == other.value && self.secondary == other.secondary {
            return 1.0;
        }
        match self.kind {
            HashKind::Minhash4 => minhash_similarity(self.value, other.value),
            HashKind::HistogramHash => histogram_hash_similarity(self.value, other.value),
            HashKind::BlockXor => {
                // XOR hashes: popcount of (a XOR b) measures distance
                let diff_bits = f64::from((self.value ^ other.value).count_ones());
                1.0 - diff_bits / 64.0
            }
            _ => {
                if self.value == other.value { 1.0 } else { 0.0 }
            }
        }
    }

    /// Returns `true` if this hash exactly matches another (same kind and value).
    #[must_use]
    pub fn exact_match(&self, other: &Self) -> bool {
        self.kind == other.kind && self.value == other.value && self.secondary == other.secondary
    }
}

impl fmt::Display for FunctionHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{:#018x}(len={})", self.kind, self.value, self.body_len)?;
        if let Some(sec) = self.secondary {
            write!(f, "+{sec:#018x}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FunctionHasher
// ---------------------------------------------------------------------------

/// Configurable hasher that can produce one or more [`FunctionHash`]es for a
/// function body.
#[derive(Debug, Clone)]
pub struct FunctionHasher {
    /// Hash kinds to compute when [`hash_function`] is called.
    kinds: Vec<HashKind>,
    /// Number of minhash permutations (must be a multiple of 64 for packing).
    minhash_perms: usize,
    /// Block size for CFG-aware block hashing.
    block_size: usize,
}

impl FunctionHasher {
    /// Create a hasher with the given hash kinds.
    #[must_use]
    pub const fn new(kinds: Vec<HashKind>) -> Self {
        Self {
            kinds,
            minhash_perms: 128,
            block_size: 16,
        }
    }

    /// Create a hasher that computes all available hash kinds.
    #[must_use]
    pub fn all() -> Self {
        Self::new(vec![
            HashKind::Fnv64,
            HashKind::Djb2,
            HashKind::Crc32,
            HashKind::Minhash4,
            HashKind::HistogramHash,
            HashKind::BlockXor,
            HashKind::LengthNorm,
        ])
    }

    /// Create a hasher for fast exact matching only.
    #[must_use]
    pub fn exact_only() -> Self {
        Self::new(vec![HashKind::Fnv64, HashKind::Crc32])
    }

    /// Create a hasher for fuzzy (approximate) matching.
    #[must_use]
    pub fn fuzzy_only() -> Self {
        Self::new(vec![HashKind::Minhash4, HashKind::HistogramHash, HashKind::BlockXor])
    }

    /// Set the number of minhash permutations (must be >= 64).
    #[must_use]
    pub fn with_minhash_perms(mut self, perms: usize) -> Self {
        self.minhash_perms = perms.max(64);
        self
    }

    /// Set the block size for block-XOR hashing.
    #[must_use]
    pub fn with_block_size(mut self, size: usize) -> Self {
        self.block_size = size.max(1);
        self
    }

    /// Compute all configured hashes for the given function body.
    ///
    /// # Errors
    ///
    /// Returns [`HasherError::EmptyBody`] if `body` is empty.
    pub fn hash_all(&self, body: &[u8]) -> Result<Vec<FunctionHash>, HasherError> {
        if body.is_empty() {
            return Err(HasherError::EmptyBody);
        }
        let mut results = Vec::with_capacity(self.kinds.len());
        for &kind in &self.kinds {
            let h = compute_hash(kind, body, self.minhash_perms, self.block_size);
            results.push(h);
        }
        Ok(results)
    }

    /// Compute hashes and return them as a map from `HashKind` to `FunctionHash`.
    ///
    /// # Errors
    ///
    /// Returns [`HasherError::EmptyBody`] if `body` is empty.
    pub fn hash_map(&self, body: &[u8]) -> Result<HashMap<HashKind, FunctionHash>, HasherError> {
        let hashes = self.hash_all(body)?;
        Ok(hashes.into_iter().map(|h| (h.kind, h)).collect())
    }

    /// Compute a single hash of the specified kind.
    ///
    /// # Errors
    ///
    /// Returns [`HasherError::EmptyBody`] if `body` is empty, or
    /// [`HasherError::UnsupportedKind`] if the kind is not configured.
    pub fn hash_one(&self, body: &[u8], kind: HashKind) -> Result<FunctionHash, HasherError> {
        if body.is_empty() {
            return Err(HasherError::EmptyBody);
        }
        if !self.kinds.contains(&kind) {
            return Err(HasherError::UnsupportedKind(kind.name().to_string()));
        }
        Ok(compute_hash(kind, body, self.minhash_perms, self.block_size))
    }

    /// Similarity between two function bodies computed over all configured
    /// hash kinds.  Returns the maximum similarity observed.
    ///
    /// # Errors
    ///
    /// Returns [`HasherError::EmptyBody`] if either body is empty.
    pub fn similarity(&self, a: &[u8], b: &[u8]) -> Result<f64, HasherError> {
        let ha = self.hash_all(a)?;
        let hb = self.hash_all(b)?;
        let map_b: HashMap<HashKind, &FunctionHash> = hb.iter().map(|h| (h.kind, h)).collect();
        let mut max_sim = 0.0f64;
        for h in &ha {
            if let Some(hb) = map_b.get(&h.kind) {
                let s = h.similarity(hb);
                if s > max_sim {
                    max_sim = s;
                }
            }
        }
        Ok(max_sim)
    }
}

impl Default for FunctionHasher {
    fn default() -> Self {
        Self::new(vec![HashKind::Fnv64, HashKind::Minhash4, HashKind::HistogramHash])
    }
}

// ---------------------------------------------------------------------------
// hash_function — primary entry point
// ---------------------------------------------------------------------------

/// Hash a function body using the specified kind.
///
/// This is the primary entry point for one-shot hashing.
///
/// # Errors
///
/// Returns [`HasherError::EmptyBody`] if `body` is empty.
pub fn hash_function(body: &[u8], kind: HashKind) -> Result<FunctionHash, HasherError> {
    if body.is_empty() {
        return Err(HasherError::EmptyBody);
    }
    Ok(compute_hash(kind, body, 128, 16))
}

// ---------------------------------------------------------------------------
// Internal hash computations
// ---------------------------------------------------------------------------

fn compute_hash(kind: HashKind, body: &[u8], minhash_perms: usize, block_size: usize) -> FunctionHash {
    let len = body.len();
    match kind {
        HashKind::Fnv64 => FunctionHash::new(kind, fnv1a_64(body), len),
        HashKind::Djb2 => FunctionHash::new(kind, djb2_hash(body), len),
        HashKind::Crc32 => FunctionHash::new(kind, u64::from(crc32_hash(body)), len),
        HashKind::Minhash4 => {
            let (v, s) = minhash_ngram4(body, minhash_perms);
            FunctionHash::with_secondary(kind, v, s, len)
        }
        HashKind::HistogramHash => FunctionHash::new(kind, histogram_fingerprint(body), len),
        HashKind::BlockXor => FunctionHash::new(kind, block_xor_hash(body, block_size), len),
        HashKind::LengthNorm => FunctionHash::new(kind, length_norm_hash(body), len),
    }
}

/// FNV-1a 64-bit hash.
fn fnv1a_64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// DJB2 hash (64-bit extension).
fn djb2_hash(data: &[u8]) -> u64 {
    let mut h: u64 = 5381;
    for &b in data {
        h = h.wrapping_shl(5).wrapping_add(h).wrapping_add(u64::from(b));
    }
    h
}

/// Simple CRC-32 using the standard polynomial.
fn crc32_hash(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        let mut byte = u32::from(b);
        for _ in 0..8 {
            if (crc ^ byte) & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
            byte >>= 1;
        }
    }
    !crc
}

/// Locality-sensitive minhash over 4-byte n-grams, compressed into two u64.
///
/// Uses `minhash_perms / 64` bit-planes where each plane tracks the minhash
/// for 64 hash functions simultaneously via bitwise AND simulation.
fn minhash_ngram4(data: &[u8], perms: usize) -> (u64, u64) {
    let perms = perms.max(64) / 64 * 64; // round to multiple of 64
    let perms = perms.min(128); // cap at 128 for packing into two u64
    // Collect 4-grams
    if data.len() < 4 {
        return (fnv1a_64(data), djb2_hash(data));
    }
    // Simple minhash: for each of `perms` hash functions, compute min over all 4-grams.
    // We use a family of hash functions: h_i(x) = fnv1a(x XOR seed_i).
    let seeds: Vec<u64> = (0..perms as u64)
        .map(|i| i.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(0x6c62_272e_07bb_0142))
        .collect();
    let mut minhashes: Vec<u64> = seeds.iter().map(|&s| u64::MAX.wrapping_sub(s)).collect();
    for window in data.windows(4) {
        let gram = u32::from_le_bytes([window[0], window[1], window[2], window[3]]);
        for (i, &seed) in seeds.iter().enumerate() {
            let h = fnv1a_64(&(u64::from(gram) ^ seed).to_le_bytes());
            if h < minhashes[i] {
                minhashes[i] = h;
            }
        }
    }
    // Pack first 64 minhash values into a simhash-style u64
    let pack = |start: usize| -> u64 {
        let mut v = 0u64;
        let end = (start + 64).min(minhashes.len());
        for (bit, &mh) in minhashes[start..end].iter().enumerate() {
            if mh & 1 == 0 {
                v |= 1u64 << bit;
            }
        }
        v
    };
    let primary = pack(0);
    let secondary = if perms >= 128 { pack(64) } else { pack(0).rotate_right(17) };
    (primary, secondary)
}

/// Byte-histogram fingerprint: fold the 256-bin histogram into a 64-bit value.
fn histogram_fingerprint(data: &[u8]) -> u64 {
    let mut hist = [0u32; 256];
    for &b in data {
        hist[b as usize] += 1;
    }
    // Fold: XOR pairs of 32-bit histogram entries to produce 128 values,
    // then pack top/bottom bits into a 64-bit fingerprint.
    let mut h: u64 = 0;
    for i in 0..128 {
        let combined = hist[i].wrapping_add(hist[i + 128]);
        if combined & 1 != 0 {
            h |= 1u64 << (i % 64);
        }
    }
    // Mix with popcount of each byte frequency bucket
    let mix: u64 = hist.iter().enumerate().fold(0u64, |acc, (i, &c)| {
        acc ^ (u64::from(c).wrapping_mul(i as u64 + 1))
    });
    h ^ (mix >> 7)
}

/// Block-XOR hash: split body into fixed-size blocks, XOR their FNV hashes.
fn block_xor_hash(data: &[u8], block_size: usize) -> u64 {
    let mut h: u64 = 0;
    for chunk in data.chunks(block_size) {
        h ^= fnv1a_64(chunk);
    }
    h
}

/// Length-normalised hash: FNV-1a folded and mixed with the function length.
fn length_norm_hash(data: &[u8]) -> u64 {
    let raw = fnv1a_64(data);
    let len = data.len() as u64;
    // Mix in length to distinguish functions with same content but different padding
    raw ^ len.wrapping_mul(0x517c_c1b7_2722_0a95)
}

// ---------------------------------------------------------------------------
// Similarity helpers
// ---------------------------------------------------------------------------

/// Hamming-based minhash similarity: fraction of bit positions that agree.
fn minhash_similarity(a: u64, b: u64) -> f64 {
    let matching = 64usize - usize::try_from((a ^ b).count_ones()).unwrap_or(64);
    f64::from(u32::try_from(matching).unwrap_or(u32::MAX)) / 64.0
}

/// Histogram hash similarity: Hamming similarity on the folded fingerprint.
fn histogram_hash_similarity(a: u64, b: u64) -> f64 {
    minhash_similarity(a, b)
}

// ---------------------------------------------------------------------------
// BatchHashResult
// ---------------------------------------------------------------------------

/// Result of batch-hashing multiple function bodies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchHashResult {
    /// Per-function hash maps.  Key is the function name or index string.
    pub entries: HashMap<String, Vec<FunctionHash>>,
    /// Total functions processed.
    pub total: usize,
    /// Number of functions that produced errors (empty bodies).
    pub errors: usize,
}

impl BatchHashResult {
    /// Look up the hashes for a function by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Vec<FunctionHash>> {
        self.entries.get(name)
    }

    /// Compute pairwise similarity between two named functions using a
    /// specific hash kind.
    #[must_use]
    pub fn pairwise_similarity(&self, name_a: &str, name_b: &str, kind: HashKind) -> Option<f64> {
        let ha = self.entries.get(name_a)?.iter().find(|h| h.kind == kind)?;
        let hb = self.entries.get(name_b)?.iter().find(|h| h.kind == kind)?;
        Some(ha.similarity(hb))
    }
}

/// Batch-hash a collection of named function bodies.
///
/// Functions with empty bodies are counted in `errors` and skipped.
#[must_use]
pub fn batch_hash<S: ::std::hash::BuildHasher>(
    functions: &HashMap<String, Vec<u8>, S>,
    hasher: &FunctionHasher,
) -> BatchHashResult {
    let mut entries = HashMap::new();
    let mut errors = 0usize;
    for (name, body) in functions {
        match hasher.hash_all(body) {
            Ok(fn_hashes) => {
                entries.insert(name.clone(), fn_hashes);
            }
            Err(_) => {
                errors += 1;
            }
        }
    }
    let total = functions.len();
    BatchHashResult { entries, total, errors }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_kind_names() {
        assert_eq!(HashKind::Fnv64.name(), "fnv64");
        assert_eq!(HashKind::Minhash4.name(), "minhash4");
        assert_eq!(HashKind::HistogramHash.name(), "histogram");
    }

    #[test]
    fn test_hash_kind_fuzzy() {
        assert!(HashKind::Minhash4.is_fuzzy());
        assert!(HashKind::HistogramHash.is_fuzzy());
        assert!(HashKind::BlockXor.is_fuzzy());
        assert!(!HashKind::Fnv64.is_fuzzy());
        assert!(!HashKind::Crc32.is_fuzzy());
    }

    #[test]
    fn test_hash_function_empty_error() {
        let err = hash_function(b"", HashKind::Fnv64);
        assert!(err.is_err());
    }

    #[test]
    fn test_hash_function_fnv64_deterministic() {
        let body = b"push rbp; mov rbp, rsp; sub rsp, 0x20";
        let h1 = hash_function(body, HashKind::Fnv64).unwrap();
        let h2 = hash_function(body, HashKind::Fnv64).unwrap();
        assert_eq!(h1.value, h2.value);
    }

    #[test]
    fn test_hash_function_different_bodies() {
        let a = hash_function(b"function_a_body", HashKind::Fnv64).unwrap();
        let b = hash_function(b"function_b_body", HashKind::Fnv64).unwrap();
        assert_ne!(a.value, b.value);
    }

    #[test]
    fn test_function_hash_exact_match() {
        let body = b"some function bytes";
        let h1 = hash_function(body, HashKind::Crc32).unwrap();
        let h2 = hash_function(body, HashKind::Crc32).unwrap();
        assert!(h1.exact_match(&h2));
    }

    #[test]
    fn test_function_hash_similarity_identical() {
        let body = b"test function body 12345";
        let h = hash_function(body, HashKind::Minhash4).unwrap();
        assert!((h.similarity(&h) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_hasher_all_kinds() {
        let hasher = FunctionHasher::all();
        let body = b"mov eax, 1; ret";
        let hashes = hasher.hash_all(body).unwrap();
        assert_eq!(hashes.len(), 7);
    }

    #[test]
    fn test_hasher_hash_map() {
        let hasher = FunctionHasher::exact_only();
        let body = b"xor eax, eax; ret";
        let map = hasher.hash_map(body).unwrap();
        assert!(map.contains_key(&HashKind::Fnv64));
        assert!(map.contains_key(&HashKind::Crc32));
    }

    #[test]
    fn test_hasher_similarity_identical() {
        let hasher = FunctionHasher::default();
        let body = b"push rbp; mov rbp, rsp; pop rbp; ret";
        let sim = hasher.similarity(body, body).unwrap();
        assert!(sim > 0.9);
    }

    #[test]
    fn test_hasher_unsupported_kind_error() {
        let hasher = FunctionHasher::exact_only();
        let err = hasher.hash_one(b"bytes", HashKind::Minhash4);
        assert!(err.is_err());
    }

    #[test]
    fn test_batch_hash() {
        let mut funcs: HashMap<String, Vec<u8>> = HashMap::new();
        funcs.insert("main".to_string(), b"push rbp".to_vec());
        funcs.insert("helper".to_string(), b"xor eax, eax".to_vec());
        funcs.insert("empty".to_string(), vec![]);
        let hasher = FunctionHasher::exact_only();
        let result = batch_hash(&funcs, &hasher);
        assert_eq!(result.total, 3);
        assert_eq!(result.errors, 1);
        assert!(result.get("main").is_some());
        assert!(result.get("empty").is_none());
    }

    #[test]
    fn test_batch_hash_pairwise_similarity() {
        let mut funcs: HashMap<String, Vec<u8>> = HashMap::new();
        let body = b"mov eax, 0; ret";
        funcs.insert("f1".to_string(), body.to_vec());
        funcs.insert("f2".to_string(), body.to_vec());
        let hasher = FunctionHasher::exact_only();
        let result = batch_hash(&funcs, &hasher);
        let sim = result.pairwise_similarity("f1", "f2", HashKind::Fnv64).unwrap();
        assert!((sim - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_function_hash_display() {
        let body = b"test";
        let h = hash_function(body, HashKind::Fnv64).unwrap();
        let s = h.to_string();
        assert!(s.contains("fnv64"));
        assert!(s.contains("len=4"));
    }

    #[test]
    fn test_all_hash_kinds_produce_nonzero() {
        let body = b"int foo() { return 42; }";
        for kind in [
            HashKind::Fnv64, HashKind::Djb2, HashKind::Crc32,
            HashKind::Minhash4, HashKind::HistogramHash,
            HashKind::BlockXor, HashKind::LengthNorm,
        ] {
            let h = hash_function(body, kind).unwrap();
            assert_ne!(h.value, 0, "zero hash for {kind}");
        }
    }
}
