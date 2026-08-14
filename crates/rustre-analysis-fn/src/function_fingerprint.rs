//! Unique function identification via content-based fingerprinting.
//!
//! Computes `ByteHash` (hash of the first N raw bytes), `SemanticHash`
//! (normalised IL instruction sequence), and `CallPattern` (called addresses).
//! A `FingerprintDb` stores fingerprints for all analysed functions, and
//! `SimilaritySearch` finds near-duplicates.

use std::collections::{HashMap, HashSet};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// ByteHash — raw byte prefix hash
// ─────────────────────────────────────────────────────────────────────────────

/// Hash of the first `N` raw bytes of a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ByteHash {
    /// Number of bytes hashed.
    pub byte_count: usize,
    /// FNV-1a 64-bit hash of the prefix bytes.
    pub hash: u64,
}

impl ByteHash {
    /// Compute a `ByteHash` from the first `max_bytes` bytes of `data`.
    #[must_use]
    pub fn compute(data: &[u8], max_bytes: usize) -> Self {
        let slice = &data[..data.len().min(max_bytes)];
        let hash = fnv1a_64(slice);
        Self {
            byte_count: slice.len(),
            hash,
        }
    }

    /// Whether the hash covers fewer bytes than requested (function too short).
    #[must_use]
    pub const fn is_truncated(&self, max_bytes: usize) -> bool {
        self.byte_count < max_bytes
    }
}

impl fmt::Display for ByteHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ByteHash({} bytes, {:#018x})",
            self.byte_count, self.hash
        )
    }
}

/// FNV-1a 64-bit hash.
#[must_use]
pub fn fnv1a_64(data: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET_BASIS;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(PRIME);
    }
    h
}

// ─────────────────────────────────────────────────────────────────────────────
// SemanticHash — normalised IL hash
// ─────────────────────────────────────────────────────────────────────────────

/// A normalised representation of one IL instruction for hashing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NormInstr {
    /// Opcode mnemonic string.
    pub opcode: String,
    /// Number of operands (not their values, which may be address-dependent).
    pub operand_count: u8,
    /// Whether the instruction writes to memory.
    pub writes_mem: bool,
    /// Whether the instruction reads from memory.
    pub reads_mem: bool,
}

impl NormInstr {
    #[must_use]
    pub fn new(opcode: impl Into<String>, operands: u8, writes_mem: bool, reads_mem: bool) -> Self {
        Self {
            opcode: opcode.into(),
            operand_count: operands,
            writes_mem,
            reads_mem,
        }
    }

    /// Serialise to a compact byte representation.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(self.opcode.as_bytes());
        v.push(b':');
        v.push(self.operand_count);
        v.push(u8::from(self.writes_mem));
        v.push(u8::from(self.reads_mem));
        v
    }
}

/// Hash of the normalised IL instruction sequence of a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SemanticHash {
    /// Number of normalised instructions hashed.
    pub instr_count: usize,
    /// FNV-1a 64-bit hash of the serialised normalised sequence.
    pub hash: u64,
}

impl SemanticHash {
    /// Compute a `SemanticHash` from a normalised instruction sequence.
    #[must_use]
    pub fn compute(instrs: &[NormInstr]) -> Self {
        let mut data: Vec<u8> = Vec::new();
        for instr in instrs {
            data.extend_from_slice(&instr.to_bytes());
            data.push(b'|');
        }
        Self {
            instr_count: instrs.len(),
            hash: fnv1a_64(&data),
        }
    }

    /// Whether two functions are semantically identical.
    #[must_use]
    pub const fn identical_to(&self, other: &Self) -> bool {
        self.hash == other.hash && self.instr_count == other.instr_count
    }
}

impl fmt::Display for SemanticHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SemanticHash({} instrs, {:#018x})",
            self.instr_count, self.hash
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallPattern
// ─────────────────────────────────────────────────────────────────────────────

/// Represents the set of functions called by a function.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallPattern {
    /// Sorted list of called function addresses.
    pub callees: Vec<u64>,
    /// Number of call sites (may exceed `callees.len()` for repeated calls).
    pub call_site_count: usize,
    /// Hash of the sorted callees list.
    pub hash: u64,
}

impl CallPattern {
    #[must_use]
    pub fn from_callees(mut callees: Vec<u64>, call_site_count: usize) -> Self {
        callees.sort_unstable();
        callees.dedup();
        let hash = fnv1a_64(
            &callees
                .iter()
                .flat_map(|&a| a.to_le_bytes())
                .collect::<Vec<_>>(),
        );
        Self {
            callees,
            call_site_count,
            hash,
        }
    }

    /// Whether `addr` is called by this function.
    #[must_use]
    pub fn calls(&self, addr: u64) -> bool {
        self.callees.binary_search(&addr).is_ok()
    }

    /// Jaccard similarity with another `CallPattern`.
    #[must_use]
    pub fn jaccard(&self, other: &Self) -> f32 {
        let a: HashSet<u64> = self.callees.iter().copied().collect();
        let b: HashSet<u64> = other.callees.iter().copied().collect();
        let inter = a.intersection(&b).count();
        let union = a.union(&b).count();
        if union == 0 {
            return 1.0;
        }
        f32::from(u16::try_from(inter).unwrap_or(u16::MAX))
            / f32::from(u16::try_from(union).unwrap_or(u16::MAX))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionFingerprint
// ─────────────────────────────────────────────────────────────────────────────

/// Complete fingerprint for a single function.
#[derive(Debug, Clone)]
pub struct FunctionFingerprint {
    /// Virtual address of the function.
    pub address: u64,
    /// Optional symbol name.
    pub name: Option<String>,
    /// Raw-byte prefix hash.
    pub byte_hash: ByteHash,
    /// Semantic (normalised IL) hash.
    pub semantic_hash: SemanticHash,
    /// Call pattern.
    pub call_pattern: CallPattern,
    /// Function size in bytes.
    pub size: u64,
}

impl FunctionFingerprint {
    #[must_use]
    pub const fn new(
        address: u64,
        byte_hash: ByteHash,
        semantic_hash: SemanticHash,
        call_pattern: CallPattern,
        size: u64,
    ) -> Self {
        Self {
            address,
            name: None,
            byte_hash,
            semantic_hash,
            call_pattern,
            size,
        }
    }

    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Whether two fingerprints represent exactly the same function.
    #[must_use]
    pub fn is_identical_to(&self, other: &Self) -> bool {
        self.byte_hash == other.byte_hash && self.semantic_hash.identical_to(&other.semantic_hash)
    }

    /// Compute a combined similarity score in `[0.0, 1.0]`.
    ///
    /// Weights: `byte_hash` 40%, `semantic_hash` 40%, `call_pattern` 20%.
    #[must_use]
    pub fn similarity(&self, other: &Self) -> f32 {
        let byte_sim = if self.byte_hash.hash == other.byte_hash.hash {
            1.0_f32
        } else {
            0.0
        };
        let sem_sim = if self.semantic_hash.hash == other.semantic_hash.hash {
            1.0
        } else {
            0.0
        };
        let call_sim = self.call_pattern.jaccard(&other.call_pattern);
        0.2f32.mul_add(call_sim, 0.4f32.mul_add(byte_sim, 0.4 * sem_sim))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FingerprintDb
// ─────────────────────────────────────────────────────────────────────────────

/// A database of function fingerprints.
#[derive(Debug, Default)]
pub struct FingerprintDb {
    /// Fingerprints keyed by function address.
    fingerprints: HashMap<u64, FunctionFingerprint>,
    /// Reverse index: `byte_hash` → addresses.
    byte_index: HashMap<u64, Vec<u64>>,
    /// Reverse index: `semantic_hash` → addresses.
    semantic_index: HashMap<u64, Vec<u64>>,
}

impl FingerprintDb {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a fingerprint.
    pub fn insert(&mut self, fp: FunctionFingerprint) {
        let addr = fp.address;
        self.byte_index
            .entry(fp.byte_hash.hash)
            .or_default()
            .push(addr);
        self.semantic_index
            .entry(fp.semantic_hash.hash)
            .or_default()
            .push(addr);
        self.fingerprints.insert(addr, fp);
    }

    /// Look up a fingerprint by address.
    #[must_use]
    pub fn get(&self, addr: u64) -> Option<&FunctionFingerprint> {
        self.fingerprints.get(&addr)
    }

    /// Find functions with the same byte hash.
    #[must_use]
    pub fn by_byte_hash(&self, hash: u64) -> Vec<u64> {
        self.byte_index.get(&hash).cloned().unwrap_or_default()
    }

    /// Find functions with the same semantic hash.
    #[must_use]
    pub fn by_semantic_hash(&self, hash: u64) -> Vec<u64> {
        self.semantic_index.get(&hash).cloned().unwrap_or_default()
    }

    /// Total number of functions in the database.
    #[must_use]
    pub fn len(&self) -> usize {
        self.fingerprints.len()
    }

    /// Whether the database is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }

    /// All addresses in the database.
    #[must_use]
    pub fn addresses(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self.fingerprints.keys().copied().collect();
        v.sort_unstable();
        v
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SimilaritySearch
// ─────────────────────────────────────────────────────────────────────────────

/// A similarity search result entry.
#[derive(Debug, Clone)]
pub struct SimilarityMatch {
    pub address: u64,
    pub score: f32,
}

/// Searches a `FingerprintDb` for similar functions.
pub struct SimilaritySearch<'a> {
    pub db: &'a FingerprintDb,
    /// Minimum similarity score to include in results.
    pub threshold: f32,
}

impl<'a> SimilaritySearch<'a> {
    #[must_use]
    pub const fn new(db: &'a FingerprintDb, threshold: f32) -> Self {
        Self { db, threshold }
    }

    /// Find all functions similar to `query`.
    #[must_use]
    pub fn search(&self, query: &FunctionFingerprint) -> Vec<SimilarityMatch> {
        let mut results: Vec<SimilarityMatch> = self
            .db
            .fingerprints
            .values()
            .filter(|fp| fp.address != query.address)
            .map(|fp| SimilarityMatch {
                address: fp.address,
                score: query.similarity(fp),
            })
            .filter(|m| m.score >= self.threshold)
            .collect();

        results.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results
    }

    /// Find exact byte-hash duplicates of `query`.
    #[must_use]
    pub fn exact_duplicates(&self, query: &FunctionFingerprint) -> Vec<u64> {
        self.db
            .by_byte_hash(query.byte_hash.hash)
            .into_iter()
            .filter(|&a| a != query.address)
            .collect()
    }

    /// Find semantically equivalent functions (same normalised IL).
    #[must_use]
    pub fn semantic_equivalents(&self, query: &FunctionFingerprint) -> Vec<u64> {
        self.db
            .by_semantic_hash(query.semantic_hash.hash)
            .into_iter()
            .filter(|&a| a != query.address)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers for building test fingerprints
// ─────────────────────────────────────────────────────────────────────────────

/// Build a simple fingerprint from raw bytes and a call list.
#[must_use]
pub fn fingerprint_from_bytes(addr: u64, data: &[u8], callees: Vec<u64>) -> FunctionFingerprint {
    let byte_hash = ByteHash::compute(data, 32);
    // Normalise: one NormInstr per byte (simple test model)
    let instrs: Vec<NormInstr> = data
        .iter()
        .map(|&b| NormInstr::new(format!("op{b:02x}"), 0, b & 1 != 0, b & 2 != 0))
        .collect();
    let semantic_hash = SemanticHash::compute(&instrs);
    let call_pattern = CallPattern::from_callees(callees, 0);
    FunctionFingerprint::new(
        addr,
        byte_hash,
        semantic_hash,
        call_pattern,
        data.len() as u64,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // 1. fnv1a_64 is deterministic
    #[test]
    fn test_fnv1a_deterministic() {
        let h1 = fnv1a_64(b"hello");
        let h2 = fnv1a_64(b"hello");
        assert_eq!(h1, h2);
    }

    // 2. fnv1a_64 different inputs differ
    #[test]
    fn test_fnv1a_different() {
        assert_ne!(fnv1a_64(b"hello"), fnv1a_64(b"world"));
    }

    // 3. fnv1a_64 empty input
    #[test]
    fn test_fnv1a_empty() {
        let h = fnv1a_64(&[]);
        assert_ne!(h, 0); // FNV offset basis
    }

    // 4. ByteHash compute basic
    #[test]
    fn test_byte_hash_compute() {
        let bh = ByteHash::compute(&[0x55, 0x89, 0xE5], 32);
        assert_eq!(bh.byte_count, 3);
    }

    // 5. ByteHash truncation
    #[test]
    fn test_byte_hash_truncated() {
        let bh = ByteHash::compute(&[1, 2, 3], 10);
        assert!(bh.is_truncated(10));
    }

    // 6. ByteHash not truncated when data >= max_bytes
    #[test]
    fn test_byte_hash_not_truncated() {
        let data: Vec<u8> = (0..32).collect();
        let bh = ByteHash::compute(&data, 32);
        assert!(!bh.is_truncated(32));
    }

    // 7. ByteHash same data → same hash
    #[test]
    fn test_byte_hash_same_data() {
        let a = ByteHash::compute(b"hello", 32);
        let b = ByteHash::compute(b"hello", 32);
        assert_eq!(a.hash, b.hash);
    }

    // 8. ByteHash different data → different hash
    #[test]
    fn test_byte_hash_different_data() {
        let a = ByteHash::compute(b"hello", 32);
        let b = ByteHash::compute(b"world", 32);
        assert_ne!(a.hash, b.hash);
    }

    // 9. NormInstr to_bytes includes opcode
    #[test]
    fn test_norm_instr_bytes() {
        let ni = NormInstr::new("MOV", 2, false, true);
        let bytes = ni.to_bytes();
        assert!(bytes.starts_with(b"MOV"));
    }

    // 10. SemanticHash compute empty
    #[test]
    fn test_semantic_hash_empty() {
        let sh = SemanticHash::compute(&[]);
        assert_eq!(sh.instr_count, 0);
    }

    // 11. SemanticHash identical sequences
    #[test]
    fn test_semantic_hash_identical() {
        let instrs = vec![NormInstr::new("MOV", 2, false, true)];
        let a = SemanticHash::compute(&instrs);
        let b = SemanticHash::compute(&instrs);
        assert!(a.identical_to(&b));
    }

    // 12. SemanticHash different sequences
    #[test]
    fn test_semantic_hash_different() {
        let a = SemanticHash::compute(&[NormInstr::new("ADD", 2, false, false)]);
        let b = SemanticHash::compute(&[NormInstr::new("SUB", 2, false, false)]);
        assert!(!a.identical_to(&b));
    }

    // 13. CallPattern from_callees sorts and deduplicates
    #[test]
    fn test_call_pattern_sorted_dedup() {
        let cp = CallPattern::from_callees(vec![0x3000, 0x1000, 0x2000, 0x1000], 4);
        assert_eq!(cp.callees, vec![0x1000, 0x2000, 0x3000]);
    }

    // 14. CallPattern calls
    #[test]
    fn test_call_pattern_calls() {
        let cp = CallPattern::from_callees(vec![0x1000, 0x2000], 2);
        assert!(cp.calls(0x1000));
        assert!(!cp.calls(0x3000));
    }

    // 15. CallPattern Jaccard identity
    #[test]
    fn test_call_pattern_jaccard_identity() {
        let cp = CallPattern::from_callees(vec![0x1000, 0x2000], 2);
        assert!((cp.jaccard(&cp) - 1.0).abs() < 1e-6);
    }

    // 16. CallPattern Jaccard disjoint
    #[test]
    fn test_call_pattern_jaccard_disjoint() {
        let a = CallPattern::from_callees(vec![0x1000], 1);
        let b = CallPattern::from_callees(vec![0x2000], 1);
        assert!((a.jaccard(&b) - 0.0).abs() < 1e-6);
    }

    // 17. CallPattern Jaccard partial overlap
    #[test]
    fn test_call_pattern_jaccard_partial() {
        let a = CallPattern::from_callees(vec![0x1000, 0x2000], 2);
        let b = CallPattern::from_callees(vec![0x2000, 0x3000], 2);
        let j = a.jaccard(&b);
        assert!((j - 1.0 / 3.0).abs() < 0.01);
    }

    // 18. FunctionFingerprint is_identical_to self
    #[test]
    fn test_fingerprint_identical_to_self() {
        let fp = fingerprint_from_bytes(0x1000, b"hello", vec![]);
        assert!(fp.is_identical_to(&fp));
    }

    // 19. FunctionFingerprint is_identical_to different
    #[test]
    fn test_fingerprint_not_identical() {
        let a = fingerprint_from_bytes(0x1000, b"hello", vec![]);
        let b = fingerprint_from_bytes(0x2000, b"world", vec![]);
        assert!(!a.is_identical_to(&b));
    }

    // 20. FunctionFingerprint similarity self = 1.0 (minus call_pattern weight if empty)
    #[test]
    fn test_fingerprint_similarity_self() {
        let fp = fingerprint_from_bytes(0x1000, b"hello", vec![]);
        let s = fp.similarity(&fp);
        // byte and semantic both match; call pattern jaccard(empty, empty) = 1.0
        assert!((s - 1.0).abs() < 1e-5);
    }

    // 21. FunctionFingerprint similarity different = 0.0 (or low)
    #[test]
    fn test_fingerprint_similarity_different() {
        let a = fingerprint_from_bytes(0x1000, b"hello", vec![]);
        let b = fingerprint_from_bytes(0x2000, b"world", vec![]);
        let s = a.similarity(&b);
        assert!(s < 0.5, "unexpected high similarity: {s}");
    }

    // 22. FingerprintDb insert and get
    #[test]
    fn test_db_insert_get() {
        let mut db = FingerprintDb::new();
        let fp = fingerprint_from_bytes(0x1000, b"hello", vec![]);
        db.insert(fp);
        assert!(db.get(0x1000).is_some());
    }

    // 23. FingerprintDb len
    #[test]
    fn test_db_len() {
        let mut db = FingerprintDb::new();
        assert_eq!(db.len(), 0);
        db.insert(fingerprint_from_bytes(0x1000, b"a", vec![]));
        assert_eq!(db.len(), 1);
    }

    // 24. FingerprintDb is_empty
    #[test]
    fn test_db_is_empty() {
        let db = FingerprintDb::new();
        assert!(db.is_empty());
    }

    // 25. FingerprintDb addresses sorted
    #[test]
    fn test_db_addresses_sorted() {
        let mut db = FingerprintDb::new();
        db.insert(fingerprint_from_bytes(0x3000, b"c", vec![]));
        db.insert(fingerprint_from_bytes(0x1000, b"a", vec![]));
        db.insert(fingerprint_from_bytes(0x2000, b"b", vec![]));
        let addrs = db.addresses();
        assert_eq!(addrs, vec![0x1000, 0x2000, 0x3000]);
    }

    // 26. FingerprintDb by_byte_hash
    #[test]
    fn test_db_by_byte_hash() {
        let mut db = FingerprintDb::new();
        let fp = fingerprint_from_bytes(0x1000, b"hello", vec![]);
        let hash = fp.byte_hash.hash;
        db.insert(fp);
        let found = db.by_byte_hash(hash);
        assert!(found.contains(&0x1000));
    }

    // 27. FingerprintDb by_semantic_hash
    #[test]
    fn test_db_by_semantic_hash() {
        let mut db = FingerprintDb::new();
        let fp = fingerprint_from_bytes(0x1000, b"hello", vec![]);
        let hash = fp.semantic_hash.hash;
        db.insert(fp);
        let found = db.by_semantic_hash(hash);
        assert!(found.contains(&0x1000));
    }

    // 28. SimilaritySearch finds identical function
    #[test]
    fn test_similarity_search_exact() {
        let mut db = FingerprintDb::new();
        let fp1 = fingerprint_from_bytes(0x1000, b"hello", vec![]);
        let fp2 = fingerprint_from_bytes(0x2000, b"hello", vec![]);
        db.insert(fp1.clone());
        db.insert(fp2);
        let search = SimilaritySearch::new(&db, 0.9);
        let results = search.search(&fp1);
        assert!(!results.is_empty());
        assert_eq!(results[0].address, 0x2000);
    }

    // 29. SimilaritySearch respects threshold
    #[test]
    fn test_similarity_search_threshold() {
        let mut db = FingerprintDb::new();
        let fp1 = fingerprint_from_bytes(0x1000, b"hello", vec![]);
        let fp2 = fingerprint_from_bytes(0x2000, b"world", vec![]);
        db.insert(fp1.clone());
        db.insert(fp2);
        let search = SimilaritySearch::new(&db, 0.9); // strict threshold
        let results = search.search(&fp1);
        assert!(results.is_empty()); // fp2 is too different
    }

    // 30. SimilaritySearch exact_duplicates
    #[test]
    fn test_exact_duplicates() {
        let mut db = FingerprintDb::new();
        let fp1 = fingerprint_from_bytes(0x1000, b"test", vec![]);
        let fp2 = fingerprint_from_bytes(0x2000, b"test", vec![]);
        db.insert(fp1.clone());
        db.insert(fp2);
        let search = SimilaritySearch::new(&db, 0.0);
        let dups = search.exact_duplicates(&fp1);
        assert!(dups.contains(&0x2000));
    }

    // 31. SimilaritySearch semantic_equivalents
    #[test]
    fn test_semantic_equivalents() {
        let mut db = FingerprintDb::new();
        let fp1 = fingerprint_from_bytes(0x1000, b"hello", vec![]);
        let fp2 = fingerprint_from_bytes(0x2000, b"hello", vec![]);
        db.insert(fp1.clone());
        db.insert(fp2);
        let search = SimilaritySearch::new(&db, 0.0);
        let equivs = search.semantic_equivalents(&fp1);
        assert!(equivs.contains(&0x2000));
    }

    // 32. FunctionFingerprint with_name
    #[test]
    fn test_fingerprint_with_name() {
        let fp = fingerprint_from_bytes(0x1000, b"x", vec![]).with_name("printf");
        assert_eq!(fp.name.as_deref(), Some("printf"));
    }

    // 33. ByteHash Display
    #[test]
    fn test_byte_hash_display() {
        let bh = ByteHash::compute(b"hi", 32);
        let s = bh.to_string();
        assert!(s.contains("ByteHash"));
    }

    // 34. SemanticHash Display
    #[test]
    fn test_semantic_hash_display() {
        let sh = SemanticHash::compute(&[]);
        let s = sh.to_string();
        assert!(s.contains("SemanticHash"));
    }

    // 35. CallPattern empty callees
    #[test]
    fn test_call_pattern_empty() {
        let cp = CallPattern::from_callees(vec![], 0);
        assert!(cp.callees.is_empty());
        assert!(!cp.calls(0x1000));
    }

    // 36. fingerprint_from_bytes size
    #[test]
    fn test_fingerprint_size() {
        let fp = fingerprint_from_bytes(0x1000, b"hello", vec![]);
        assert_eq!(fp.size, 5);
    }

    // 37. SemanticHash count stored
    #[test]
    fn test_semantic_hash_instr_count() {
        let instrs = vec![
            NormInstr::new("A", 0, false, false),
            NormInstr::new("B", 0, false, false),
        ];
        let sh = SemanticHash::compute(&instrs);
        assert_eq!(sh.instr_count, 2);
    }

    // 38. NormInstr equality
    #[test]
    fn test_norm_instr_eq() {
        let a = NormInstr::new("MOV", 2, false, true);
        let b = NormInstr::new("MOV", 2, false, true);
        assert_eq!(a, b);
    }

    // 39. NormInstr writes_mem reads_mem stored
    #[test]
    fn test_norm_instr_flags() {
        let ni = NormInstr::new("STR", 1, true, false);
        assert!(ni.writes_mem);
        assert!(!ni.reads_mem);
    }

    // 40. FingerprintDb get returns None for unknown
    #[test]
    fn test_db_get_none() {
        let db = FingerprintDb::new();
        assert!(db.get(0xdeadbeef).is_none());
    }

    // 41. SimilaritySearch results sorted by score descending
    #[test]
    fn test_similarity_results_sorted() {
        let mut db = FingerprintDb::new();
        let query = fingerprint_from_bytes(0x1000, b"abc", vec![]);
        // fp2 identical bytes; fp3 different
        let fp2 = fingerprint_from_bytes(0x2000, b"abc", vec![]);
        let fp3 = fingerprint_from_bytes(0x3000, b"xyz", vec![]);
        db.insert(fp2);
        db.insert(fp3);
        let search = SimilaritySearch::new(&db, 0.0);
        let results = search.search(&query);
        assert!(!results.is_empty());
        // Higher scores first
        for w in results.windows(2) {
            assert!(w[0].score >= w[1].score);
        }
    }

    // 42. CallPattern hash changes when callees change
    #[test]
    fn test_call_pattern_hash_changes() {
        let a = CallPattern::from_callees(vec![0x1000], 1);
        let b = CallPattern::from_callees(vec![0x2000], 1);
        assert_ne!(a.hash, b.hash);
    }

    // ── Additional edge-case tests ───────────────────────────────────────────

    #[test]
    fn test_byte_hash_truncated_for_short_data() {
        let h = ByteHash::compute(b"ab", 32);
        assert_eq!(h.byte_count, 2);
        assert!(h.is_truncated(32));
        assert!(!h.is_truncated(2));
    }

    #[test]
    fn test_byte_hash_empty_data() {
        let h = ByteHash::compute(&[], 16);
        assert_eq!(h.byte_count, 0);
        // FNV-1a of empty is offset basis.
        assert_eq!(h.hash, 0xcbf2_9ce4_8422_2325);
    }

    #[test]
    fn test_call_pattern_jaccard_edge_cases() {
        let empty = CallPattern::from_callees(vec![], 0);
        // Both empty → similarity 1.0 by definition.
        assert_eq!(empty.jaccard(&empty), 1.0);
        let a = CallPattern::from_callees(vec![1, 2, 3], 3);
        let b = CallPattern::from_callees(vec![1, 2, 3], 3);
        assert_eq!(a.jaccard(&b), 1.0);
        // Disjoint sets → 0.0
        let c = CallPattern::from_callees(vec![10, 11], 2);
        assert_eq!(a.jaccard(&c), 0.0);
    }

    #[test]
    fn test_call_pattern_dedupes_and_sorts() {
        let cp = CallPattern::from_callees(vec![3, 1, 2, 1, 3], 5);
        assert_eq!(cp.callees, vec![1, 2, 3]);
        assert_eq!(cp.call_site_count, 5);
        assert!(cp.calls(2));
        assert!(!cp.calls(99));
    }

    #[test]
    fn test_semantic_hash_empty_and_identical() {
        let h_empty = SemanticHash::compute(&[]);
        assert_eq!(h_empty.instr_count, 0);
        let a = SemanticHash::compute(&[NormInstr::new("mov", 2, false, false)]);
        let b = SemanticHash::compute(&[NormInstr::new("mov", 2, false, false)]);
        assert!(a.identical_to(&b));
        let c = SemanticHash::compute(&[NormInstr::new("mov", 2, true, false)]);
        assert!(!a.identical_to(&c));
    }

    #[test]
    fn test_similarity_search_excludes_self() {
        let mut db = FingerprintDb::new();
        let q = fingerprint_from_bytes(0x1000, b"hello", vec![]);
        db.insert(q.clone());
        let search = SimilaritySearch::new(&db, 0.0);
        let results = search.search(&q);
        assert!(results.iter().all(|m| m.address != q.address));
        let dups = search.exact_duplicates(&q);
        assert!(!dups.contains(&q.address));
    }

    #[test]
    fn test_fingerprint_db_empty_lookups() {
        let db = FingerprintDb::new();
        assert!(db.is_empty());
        assert_eq!(db.len(), 0);
        assert!(db.get(0x1000).is_none());
        assert!(db.by_byte_hash(0).is_empty());
        assert!(db.by_semantic_hash(0).is_empty());
        assert!(db.addresses().is_empty());
    }

    /// Property: `CallPattern::from_callees` is documented to sort+dedup, so
    /// its hash, callee list, and jaccard must be invariant under any input
    /// ordering (and under duplicates). Randomized over 300 shuffled multisets.
    #[test]
    fn prop_call_pattern_order_invariant() {
        use crate::test_prng::xs;
        let mut state = 0xfeed_face_0123_4567u64;
        for _ in 0..300 {
            let n = 1 + (xs(&mut state) % 12) as usize;
            let base: Vec<u64> = (0..n).map(|_| 0x1000 + (xs(&mut state) % 32) * 8).collect();
            // Permuted copy (Fisher-Yates) with some extra duplicates appended.
            let mut perm = base.clone();
            for i in (1..perm.len()).rev() {
                let j = (xs(&mut state) % (i as u64 + 1)) as usize;
                perm.swap(i, j);
            }
            for _ in 0..(xs(&mut state) % 4) {
                let pick = base[(xs(&mut state) % base.len() as u64) as usize];
                perm.push(pick);
            }
            let a = CallPattern::from_callees(base.clone(), base.len());
            let b = CallPattern::from_callees(perm, base.len());
            assert_eq!(a.callees, b.callees, "callee set must be order/dup invariant");
            assert_eq!(a.hash, b.hash, "hash must be order/dup invariant");
            assert!((a.jaccard(&b) - 1.0).abs() < 1e-6);
        }
    }

    /// Property: `similarity` is symmetric and in [0,1]; `is_identical_to` is
    /// invariant under callee ordering (callees do not participate) and
    /// fingerprints built from the same bytes are always identical regardless
    /// of address or callee-list ordering.
    #[test]
    fn prop_fingerprint_symmetry_and_order_invariance() {
        use crate::test_prng::xs;
        let mut state = 0x1122_3344_5566_7788u64;
        for _ in 0..200 {
            let la = 1 + (xs(&mut state) % 48) as usize;
            let lb = 1 + (xs(&mut state) % 48) as usize;
            let bytes_a: Vec<u8> = (0..la).map(|_| (xs(&mut state) & 0xFF) as u8).collect();
            let bytes_b: Vec<u8> = (0..lb).map(|_| (xs(&mut state) & 0xFF) as u8).collect();
            let callees: Vec<u64> = (0..(xs(&mut state) % 6)).map(|_| xs(&mut state) % 64).collect();
            let mut rev = callees.clone();
            rev.reverse();

            let fa = fingerprint_from_bytes(0x1000, &bytes_a, callees.clone());
            let fa_rev = fingerprint_from_bytes(0x2000, &bytes_a, rev);
            let fb = fingerprint_from_bytes(0x3000, &bytes_b, callees);

            // Same bytes + same callee multiset (any order) → similarity 1.0.
            assert!((fa.similarity(&fa_rev) - 1.0).abs() < 1e-6);
            assert!(fa.is_identical_to(&fa_rev));
            // Symmetry and range.
            let s1 = fa.similarity(&fb);
            let s2 = fb.similarity(&fa);
            assert!((s1 - s2).abs() < 1e-6, "similarity must be symmetric");
            assert!((0.0..=1.0 + 1e-6).contains(&s1), "similarity out of range: {s1}");
        }
    }

    #[test]
    fn test_fingerprint_identical_with_different_addresses() {
        let a = fingerprint_from_bytes(0x1000, b"same", vec![]);
        let b = fingerprint_from_bytes(0x2000, b"same", vec![]);
        // Address doesn't affect byte/semantic identity.
        assert!(a.is_identical_to(&b));
        assert_eq!(a.similarity(&b), 1.0);
    }
}
