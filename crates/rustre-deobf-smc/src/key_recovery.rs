// rustre-deobf-smc/src/key_recovery.rs
//! `KeyRecovery` — extract encryption keys used in SMC decryption stubs.

use std::collections::HashMap;

// ─── KeyAlgorithm ─────────────────────────────────────────────────────────────

/// Algorithm for which a key candidate is valid.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeyAlgorithm {
    /// AES-128 (16-byte key).
    Aes128,
    /// AES-256 (32-byte key).
    Aes256,
    /// Simple XOR with repeating key.
    Xor,
    /// RC4 (key-scheduling array detected).
    Rc4,
    /// `ChaCha20` (32-byte key + 4-byte constant).
    ChaCha20,
    /// Unknown / unclassified.
    Unknown,
}

impl KeyAlgorithm {
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Aes128 => "AES-128",
            Self::Aes256 => "AES-256",
            Self::Xor => "XOR",
            Self::Rc4 => "RC4",
            Self::ChaCha20 => "ChaCha20",
            Self::Unknown => "Unknown",
        }
    }

    /// Expected key length in bytes, `None` if variable / unknown.
    #[must_use]
    pub const fn key_len(&self) -> Option<usize> {
        match self {
            Self::Aes128 => Some(16),
            Self::Aes256 | Self::ChaCha20 => Some(32),
            Self::Rc4 | Self::Xor | Self::Unknown => None,
        }
    }
}

impl std::fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─── KeyCandidate ─────────────────────────────────────────────────────────────

/// A potential encryption key recovered from a binary.
#[derive(Debug, Clone)]
pub struct KeyCandidate {
    /// Raw key bytes.
    pub key_bytes: Vec<u8>,
    /// Best-guess algorithm for this key.
    pub algorithm: KeyAlgorithm,
    /// Confidence score in [0, 100].
    pub confidence: u8,
    /// Virtual address at which the key was found.
    pub source_addr: u64,
    /// Brief note on how the key was found.
    pub provenance: String,
}

/// Rank two key candidates, best first.
///
/// The single ordering used by every "which key wins" decision in this module,
/// so those decisions cannot drift apart from one another.
///
/// It is a **total** order on purpose. `confidence` is a `u8` in `[0, 100]` and
/// candidates are held in a `HashMap`, whose iteration order Rust randomises per
/// process — so ranking on confidence alone let equally-confident candidates be
/// separated by the hash seed. For a key-recovery database that meant the same
/// input yielded a different decryption key from one run to the next.
/// `source_addr` is the address the key was found at, which makes the order
/// reproducible; `key_bytes` settles the remainder.
fn best_first(a: &KeyCandidate, b: &KeyCandidate) -> std::cmp::Ordering {
    b.confidence
        .cmp(&a.confidence)
        .then_with(|| a.source_addr.cmp(&b.source_addr))
        .then_with(|| a.key_bytes.cmp(&b.key_bytes))
}

impl KeyCandidate {
    #[must_use]
    pub const fn new(
        key_bytes: Vec<u8>,
        algorithm: KeyAlgorithm,
        confidence: u8,
        source_addr: u64,
    ) -> Self {
        Self {
            key_bytes,
            algorithm,
            confidence,
            source_addr,
            provenance: String::new(),
        }
    }

    #[must_use]
    pub fn with_provenance(mut self, p: &str) -> Self {
        self.provenance = p.to_string();
        self
    }

    /// Return a hex-encoded representation of the key bytes.
    #[must_use]
    pub fn hex(&self) -> String {
        self.key_bytes.iter().fold(String::new(), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        })
    }

    /// Compute a simple uniqueness fingerprint (FNV-1a hash of the key bytes).
    #[must_use]
    pub fn fingerprint(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        let prime: u64 = 0x0000_0100_0000_01b3;
        for &b in &self.key_bytes {
            h ^= u64::from(b);
            h = h.wrapping_mul(prime);
        }
        h
    }
}

// ─── AES Key-Schedule Detection ───────────────────────────────────────────────

/// Check whether `bytes` at `offset` look like an AES-128 or AES-256 key schedule.
///
/// Heuristic: an AES key has high byte entropy and does not consist entirely of
/// repeated bytes. We also check for the key length (16 or 32 bytes).
fn looks_like_aes_key(bytes: &[u8]) -> Option<KeyAlgorithm> {
    let len = bytes.len();
    if len != 16 && len != 32 {
        return None;
    }
    // Reject all-zero or all-same-byte keys
    if bytes.windows(2).all(|w| w[0] == w[1]) {
        return None;
    }
    // Require at least 8 distinct byte values in an AES-128 key
    let distinct: std::collections::HashSet<u8> = bytes.iter().copied().collect();
    if distinct.len() < 8 {
        return None;
    }
    if len == 16 {
        Some(KeyAlgorithm::Aes128)
    } else {
        Some(KeyAlgorithm::Aes256)
    }
}

// ─── XOR Key Repetition Detection ────────────────────────────────────────────

/// Detect an XOR key by finding the shortest repeating pattern in `plaintext_guess`.
///
/// Works by XOR-ing consecutive byte pairs to look for period-P repetition.
fn detect_xor_key(data: &[u8], max_key_len: usize) -> Option<Vec<u8>> {
    if data.len() < 4 {
        return None;
    }
    for period in 1..=max_key_len.min(32) {
        let mut is_periodic = true;
        for i in period..data.len() {
            if data[i] != data[i % period] {
                is_periodic = false;
                break;
            }
        }
        if is_periodic {
            return Some(data[..period].to_vec());
        }
    }
    None
}

// ─── RC4 S-Box Detection ──────────────────────────────────────────────────────

/// Return `true` when `sbox` looks like a full RC4 substitution S-box.
///
/// An initialised RC4 S-box is a permutation of 0x00–0xFF, so every byte
/// value must appear exactly once.
fn looks_like_rc4_sbox(data: &[u8]) -> bool {
    if data.len() < 256 {
        return false;
    }
    let mut freq = [0u32; 256];
    for &b in &data[..256] {
        freq[b as usize] += 1;
    }
    freq.iter().all(|&c| c == 1)
}

// ─── KeyHarvester ─────────────────────────────────────────────────────────────

/// Scans decoded memory regions for cryptographic key material.
pub struct KeyHarvester {
    /// Maximum XOR key length to test for.
    pub max_xor_key_len: usize,
    /// Minimum confidence to include a result.
    pub min_confidence: u8,
}

impl Default for KeyHarvester {
    fn default() -> Self {
        Self {
            max_xor_key_len: 32,
            min_confidence: 30,
        }
    }
}

impl KeyHarvester {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_min_confidence(mut self, c: u8) -> Self {
        self.min_confidence = c;
        self
    }

    /// Scan `data` (already decoded region) starting at virtual address `base_addr`.
    /// Returns all key candidates found.
    #[must_use]
    pub fn harvest(&self, data: &[u8], base_addr: u64) -> Vec<KeyCandidate> {
        let mut candidates = Vec::new();

        // AES key schedule scan: try every aligned 16-byte and 32-byte window
        for offset in (0..data.len().saturating_sub(15)).step_by(4) {
            // 16-byte window
            if offset + 16 <= data.len() {
                let window = &data[offset..offset + 16];
                if let Some(algo) = looks_like_aes_key(window) {
                    let confidence = Self::aes_confidence(window);
                    if confidence >= self.min_confidence {
                        candidates.push(
                            KeyCandidate::new(
                                window.to_vec(),
                                algo,
                                confidence,
                                base_addr + offset as u64,
                            )
                            .with_provenance("aes_key_scan_16"),
                        );
                    }
                }
            }
            // 32-byte window
            if offset + 32 <= data.len() {
                let window = &data[offset..offset + 32];
                if let Some(algo) = looks_like_aes_key(window) {
                    let confidence = Self::aes_confidence(window);
                    if confidence >= self.min_confidence {
                        candidates.push(
                            KeyCandidate::new(
                                window.to_vec(),
                                algo,
                                confidence,
                                base_addr + offset as u64,
                            )
                            .with_provenance("aes_key_scan_32"),
                        );
                    }
                }
            }
        }

        // XOR key repetition scan: look for periodic data patterns
        if data.len() >= 8 {
            for offset in (0..data.len().saturating_sub(7)).step_by(8) {
                let end = (offset + 64).min(data.len());
                let slice = &data[offset..end];
                if let Some(key) = detect_xor_key(slice, self.max_xor_key_len) && key.len() <= self.max_xor_key_len && !key.iter().all(|&b| b == 0) {
                    // Confidence based on period and data length
                    let confidence =
                        40u8.saturating_add(u8::try_from((slice.len() / key.len().max(1)).min(60)).unwrap_or(u8::MAX));
                    if confidence >= self.min_confidence {
                        candidates.push(
                            KeyCandidate::new(
                                key,
                                KeyAlgorithm::Xor,
                                confidence,
                                base_addr + offset as u64,
                            )
                            .with_provenance("xor_repetition_scan"),
                        );
                    }
                }
            }
        }

        // RC4 S-box detection
        if data.len() >= 256 {
            for offset in (0..data.len().saturating_sub(255)).step_by(16) {
                let slice = &data[offset..offset + 256];
                if looks_like_rc4_sbox(slice) {
                    candidates.push(
                        KeyCandidate::new(
                            slice[..32].to_vec(), // use first 32 bytes as key repr
                            KeyAlgorithm::Rc4,
                            80,
                            base_addr + offset as u64,
                        )
                        .with_provenance("rc4_sbox_scan"),
                    );
                }
            }
        }

        candidates
    }

    fn aes_confidence(key: &[u8]) -> u8 {
        let distinct: std::collections::HashSet<u8> = key.iter().copied().collect();
        let entropy_score = u8::try_from(distinct.len() * 100 / 256).unwrap_or(u8::MAX);
        // Avoid sequences like 00 01 02 03 ... or FF FE FD ...
        let sequential = key
            .windows(2)
            .filter(|w| w[1] == w[0].wrapping_add(1))
            .count();
        let seq_penalty = u8::try_from((sequential * 10) / key.len().max(1)).unwrap_or(u8::MAX);
        entropy_score.saturating_sub(seq_penalty).min(95)
    }
}

// ─── KeyDb ────────────────────────────────────────────────────────────────────

/// A deduplicated database of recovered key candidates.
#[derive(Default)]
pub struct KeyDb {
    /// Keys indexed by fingerprint → best candidate.
    entries: HashMap<u64, KeyCandidate>,
    /// Number of duplicates discarded.
    pub duplicates_discarded: usize,
}

impl KeyDb {
    /// Create a new empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a candidate. If a candidate with the same fingerprint already exists,
    /// keep the one with higher confidence.
    pub fn add(&mut self, candidate: KeyCandidate) {
        let fp = candidate.fingerprint();
        if let Some(existing) = self.entries.get(&fp) {
            if candidate.confidence <= existing.confidence {
                self.duplicates_discarded += 1;
                return;
            }
            self.duplicates_discarded += 1;
        }
        self.entries.insert(fp, candidate);
    }

    /// Add all candidates from a harvester result.
    pub fn add_all(&mut self, candidates: Vec<KeyCandidate>) {
        for c in candidates {
            self.add(c);
        }
    }

    /// Number of unique keys in the database.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All keys, ordered by confidence descending.
    #[must_use]
    pub fn all_sorted(&self) -> Vec<&KeyCandidate> {
        let mut v: Vec<&KeyCandidate> = self.entries.values().collect();
        v.sort_by(|a, b| best_first(a, b));
        v
    }

    /// Keys for a specific algorithm.
    #[must_use]
    pub fn by_algorithm(&self, algo: &KeyAlgorithm) -> Vec<&KeyCandidate> {
        self.entries
            .values()
            .filter(|c| &c.algorithm == algo)
            .collect()
    }

    /// Highest-confidence key in the database.
    ///
    /// Ties are broken deterministically — see [`best_first`]. `confidence` is a
    /// `u8` in `[0, 100]`, so ties are the norm rather than the exception, and
    /// `entries` is a `HashMap`: without a tie-break this returned a *different
    /// decryption key* on each run.
    #[must_use]
    pub fn best(&self) -> Option<&KeyCandidate> {
        self.entries.values().min_by(|a, b| best_first(a, b))
    }

    /// Clear the database.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.duplicates_discarded = 0;
    }
}

// ─── KeyRecovery ──────────────────────────────────────────────────────────────

/// High-level key recovery orchestrator.
pub struct KeyRecovery {
    harvester: KeyHarvester,
    pub db: KeyDb,
}

impl KeyRecovery {
    /// Create a new key recovery engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            harvester: KeyHarvester::new(),
            db: KeyDb::new(),
        }
    }

    /// Set minimum confidence threshold.
    #[must_use]
    pub const fn with_min_confidence(mut self, c: u8) -> Self {
        self.harvester.min_confidence = c;
        self
    }

    /// Scan a decoded region and store all found keys.
    pub fn scan_region(&mut self, data: &[u8], base_addr: u64) {
        let candidates = self.harvester.harvest(data, base_addr);
        self.db.add_all(candidates);
    }

    /// Return all recovered keys ordered by confidence.
    #[must_use]
    pub fn recover_keys(&self) -> Vec<&KeyCandidate> {
        self.db.all_sorted()
    }

    /// Return the most likely key for the given algorithm.
    #[must_use]
    pub fn best_key_for(&self, algo: &KeyAlgorithm) -> Option<&KeyCandidate> {
        self.db
            .by_algorithm(algo)
            .into_iter()
            .min_by(|a, b| best_first(a, b))
    }

    /// Number of keys recovered.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.db.len()
    }
}

impl Default for KeyRecovery {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── KeyAlgorithm ──────────────────────────────────────────────────────────

    #[test]
    fn test_key_algorithm_names() {
        assert_eq!(KeyAlgorithm::Aes128.name(), "AES-128");
        assert_eq!(KeyAlgorithm::Xor.name(), "XOR");
        assert_eq!(KeyAlgorithm::Rc4.name(), "RC4");
    }

    #[test]
    fn test_key_algorithm_len() {
        assert_eq!(KeyAlgorithm::Aes128.key_len(), Some(16));
        assert_eq!(KeyAlgorithm::Aes256.key_len(), Some(32));
        assert_eq!(KeyAlgorithm::Xor.key_len(), None);
    }

    // ── KeyCandidate ──────────────────────────────────────────────────────────

    #[test]
    fn test_key_candidate_hex() {
        let c = KeyCandidate::new(vec![0xDE, 0xAD, 0xBE, 0xEF], KeyAlgorithm::Xor, 50, 0x1000);
        assert_eq!(c.hex(), "deadbeef");
    }

    #[test]
    fn test_key_candidate_fingerprint_stable() {
        let c1 = KeyCandidate::new(vec![1, 2, 3, 4], KeyAlgorithm::Xor, 50, 0);
        let c2 = KeyCandidate::new(vec![1, 2, 3, 4], KeyAlgorithm::Xor, 60, 0x100);
        assert_eq!(c1.fingerprint(), c2.fingerprint());
    }

    #[test]
    fn test_key_candidate_different_keys_different_fingerprints() {
        let c1 = KeyCandidate::new(vec![1, 2, 3, 4], KeyAlgorithm::Xor, 50, 0);
        let c2 = KeyCandidate::new(vec![5, 6, 7, 8], KeyAlgorithm::Xor, 50, 0);
        assert_ne!(c1.fingerprint(), c2.fingerprint());
    }

    // ── looks_like_aes_key ────────────────────────────────────────────────────

    #[test]
    fn test_aes_key_detection_valid_16() {
        let key: Vec<u8> = (0u8..16).map(|i| i.wrapping_mul(17)).collect();
        assert!(looks_like_aes_key(&key).is_some());
    }

    #[test]
    fn test_aes_key_detection_all_zeros_rejected() {
        let key = vec![0u8; 16];
        assert!(looks_like_aes_key(&key).is_none());
    }

    #[test]
    fn test_aes_key_detection_wrong_length() {
        let key = vec![0xABu8; 8];
        assert!(looks_like_aes_key(&key).is_none());
    }

    // ── detect_xor_key ────────────────────────────────────────────────────────

    #[test]
    fn test_xor_key_detection_simple() {
        // Pattern: ABAB ABAB ABAB...
        let data = vec![
            0xAAu8, 0xBBu8, 0xAAu8, 0xBBu8, 0xAAu8, 0xBBu8, 0xAAu8, 0xBBu8,
        ];
        let key = detect_xor_key(&data, 16).unwrap();
        assert_eq!(key, vec![0xAAu8, 0xBBu8]);
    }

    #[test]
    fn test_xor_key_detection_no_pattern() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        // Pseudo-random data is unlikely to have a short period.
        let data: Vec<u8> = (0u8..32)
            .map(|i| {
                let mut h = DefaultHasher::new();
                i.hash(&mut h);
                u8::try_from(h.finish() & 0xFF).unwrap_or(0)
            })
            .collect();
        // May or may not find a pattern; just ensure no panic.
        let _ = detect_xor_key(&data, 4);
    }

    // ── looks_like_rc4_sbox ───────────────────────────────────────────────────

    #[test]
    fn test_rc4_sbox_detected() {
        // Build a valid permutation of 0..255
        let mut sbox: Vec<u8> = (0u8..=255).collect();
        // Shuffle with a simple deterministic permutation
        for i in 0..256usize {
            let j = (i * 7 + 13) % 256;
            sbox.swap(i, j);
        }
        assert!(looks_like_rc4_sbox(&sbox));
    }

    #[test]
    fn test_rc4_sbox_rejected_not_permutation() {
        let sbox = vec![0u8; 256];
        assert!(!looks_like_rc4_sbox(&sbox));
    }

    // ── KeyHarvester ──────────────────────────────────────────────────────────

    #[test]
    fn test_harvester_finds_xor_key() {
        let harvester = KeyHarvester::new().with_min_confidence(1);
        // 32 bytes with period-2 repetition
        let data: Vec<u8> = (0..32)
            .map(|i: usize| if i.is_multiple_of(2) { 0xAA } else { 0xBB })
            .collect();
        let candidates = harvester.harvest(&data, 0x1000);
        
        assert!(candidates
            .iter().any(|c| c.algorithm == KeyAlgorithm::Xor));
    }

    #[test]
    fn test_harvester_finds_aes_key() {
        let harvester = KeyHarvester::new().with_min_confidence(1);
        // Use a realistic-looking AES-128 key embedded in data
        let key: Vec<u8> = vec![
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let mut data = vec![0xFFu8; 16];
        data.extend_from_slice(&key);
        data.extend_from_slice(&[0x00u8; 16]);
        let candidates = harvester.harvest(&data, 0x400);
        
        assert!(candidates
            .iter().any(|c| c.algorithm == KeyAlgorithm::Aes128));
    }

    // ── KeyDb ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_key_db_dedup() {
        let mut db = KeyDb::new();
        let c1 = KeyCandidate::new(vec![1, 2, 3, 4], KeyAlgorithm::Xor, 50, 0);
        let c2 = KeyCandidate::new(vec![1, 2, 3, 4], KeyAlgorithm::Xor, 60, 0x100);
        db.add(c1);
        db.add(c2);
        assert_eq!(db.len(), 1);
        assert_eq!(db.best().unwrap().confidence, 60);
    }

    #[test]
    fn test_key_db_multiple_unique() {
        let mut db = KeyDb::new();
        db.add(KeyCandidate::new(vec![1, 2], KeyAlgorithm::Xor, 50, 0));
        db.add(KeyCandidate::new(vec![3, 4], KeyAlgorithm::Xor, 70, 0x10));
        assert_eq!(db.len(), 2);
    }

    #[test]
    fn test_key_db_by_algorithm() {
        let mut db = KeyDb::new();
        db.add(KeyCandidate::new(vec![1, 2], KeyAlgorithm::Xor, 50, 0));
        db.add(KeyCandidate::new(
            vec![3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
            KeyAlgorithm::Aes128,
            80,
            0x10,
        ));
        let xor_keys = db.by_algorithm(&KeyAlgorithm::Xor);
        assert_eq!(xor_keys.len(), 1);
    }

    #[test]
    fn test_key_db_all_sorted() {
        let mut db = KeyDb::new();
        db.add(KeyCandidate::new(vec![1, 2], KeyAlgorithm::Xor, 30, 0));
        db.add(KeyCandidate::new(vec![3, 4], KeyAlgorithm::Xor, 90, 0x10));
        let sorted = db.all_sorted();
        assert_eq!(sorted[0].confidence, 90);
    }

    #[test]
    fn test_key_db_clear() {
        let mut db = KeyDb::new();
        db.add(KeyCandidate::new(vec![1], KeyAlgorithm::Xor, 50, 0));
        db.clear();
        assert!(db.is_empty());
    }

    // ── KeyRecovery ───────────────────────────────────────────────────────────

    #[test]
    fn test_key_recovery_scan_region() {
        let mut kr = KeyRecovery::new().with_min_confidence(1);
        let data: Vec<u8> = (0..64)
            .map(|i: u8| if i.is_multiple_of(2) { 0xDE } else { 0xAD })
            .collect();
        kr.scan_region(&data, 0x1000);
        // Should have found at least an XOR key
        assert!(!kr.recover_keys().is_empty());
    }

    #[test]
    fn test_key_recovery_key_count() {
        let mut kr = KeyRecovery::new().with_min_confidence(1);
        let data: Vec<u8> = (0..64)
            .map(|i: u8| if i.is_multiple_of(4) { 0xFF } else { i })
            .collect();
        kr.scan_region(&data, 0);
        let _ = kr.key_count(); // no panic
    }

    #[test]
    fn test_key_recovery_best_key_for_unknown_algo() {
        let kr = KeyRecovery::new();
        assert!(kr.best_key_for(&KeyAlgorithm::ChaCha20).is_none());
    }
}
