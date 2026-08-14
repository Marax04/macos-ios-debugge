//! Sample lookup and hash search for Malpedia.
//!
//! Provides multi-hash lookup, partial hash prefix search, batch queries,
//! sample clustering by family, and pack detection heuristics.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// HashKind
// ---------------------------------------------------------------------------

/// Identifies which hash algorithm produced a digest string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashKind {
    /// 32 hex-character MD5 digest.
    Md5,
    /// 40 hex-character SHA-1 digest.
    Sha1,
    /// 64 hex-character SHA-256 digest.
    Sha256,
    /// 128 hex-character SHA-512 digest.
    Sha512,
    /// Import hash (PE).
    ImpHash,
    /// SSDEEP fuzzy hash.
    Ssdeep,
    /// TLSH locality-sensitive hash.
    Tlsh,
    /// Unknown hash format.
    Unknown,
}

impl HashKind {
    /// Infer the hash kind from the length of the hex string.
    #[must_use]
    pub fn infer(hex: &str) -> Self {
        let s = hex.trim();
        match s.len() {
            32 => Self::Md5,
            40 => Self::Sha1,
            64 => Self::Sha256,
            128 => Self::Sha512,
            _ => Self::Unknown,
        }
    }

    /// Return the expected hex string length for this hash kind.
    #[must_use]
    pub const fn hex_length(self) -> Option<usize> {
        match self {
            Self::Md5 | Self::ImpHash => Some(32),
            Self::Sha1 => Some(40),
            Self::Sha256 => Some(64),
            Self::Sha512 => Some(128),
            _ => None,
        }
    }

    /// Return `true` if this is a cryptographic hash (not a fuzzy hash).
    #[must_use]
    pub const fn is_crypto_hash(self) -> bool {
        matches!(self, Self::Md5 | Self::Sha1 | Self::Sha256 | Self::Sha512)
    }
}

impl std::fmt::Display for HashKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha512 => "SHA-512",
            Self::ImpHash => "ImpHash",
            Self::Ssdeep => "SSDEEP",
            Self::Tlsh => "TLSH",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// HashLookup
// ---------------------------------------------------------------------------

/// A hash value along with its inferred kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashLookup {
    /// The raw hash string (lowercase hex, or fuzzy hash text).
    pub value: String,
    /// Kind of hash.
    pub kind: HashKind,
}

impl HashLookup {
    /// Create a new `HashLookup`, inferring the kind from the value length.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        let value = value.into().to_lowercase();
        let kind = HashKind::infer(&value);
        Self { value, kind }
    }

    /// Create a `HashLookup` with an explicitly specified kind.
    #[must_use]
    pub fn with_kind(value: impl Into<String>, kind: HashKind) -> Self {
        Self {
            value: value.into().to_lowercase(),
            kind,
        }
    }

    /// Return `true` if this appears to be a valid hexadecimal string.
    #[must_use]
    pub fn is_valid_hex(&self) -> bool {
        !self.value.is_empty() && self.value.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Return the first `n` hex characters as a prefix.
    #[must_use]
    pub fn prefix(&self, n: usize) -> &str {
        let end = n.min(self.value.len());
        &self.value[..end]
    }
}

// ---------------------------------------------------------------------------
// SampleQuery
// ---------------------------------------------------------------------------

/// A query to the sample finder.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SampleQuery {
    /// Hash values to look up (may be MD5, SHA-1, or SHA-256).
    pub hashes: Vec<HashLookup>,
    /// Filter by malware family id or name.
    pub family: Option<String>,
    /// Filter by target architecture (e.g. "x86", "x64", "arm").
    pub architecture: Option<String>,
    /// Filter by file format (e.g. "PE32", "ELF").
    pub file_format: Option<String>,
    /// Only return packed samples if `Some(true)`, unpacked if `Some(false)`.
    pub packed: Option<bool>,
    /// Maximum number of results.
    pub limit: Option<usize>,
    /// Whether to include related cluster samples.
    pub include_cluster: bool,
}

impl SampleQuery {
    /// Create an empty query.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a hash to the query.
    #[must_use]
    pub fn with_hash(mut self, hash: impl Into<String>) -> Self {
        self.hashes.push(HashLookup::new(hash));
        self
    }

    /// Filter by family.
    #[must_use]
    pub fn with_family(mut self, family: impl Into<String>) -> Self {
        self.family = Some(family.into());
        self
    }

    /// Set result limit.
    #[must_use]
    pub const fn with_limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }

    /// Include related cluster samples.
    #[must_use]
    pub const fn include_cluster(mut self) -> Self {
        self.include_cluster = true;
        self
    }

    /// Return `true` if the query contains at least one hash.
    #[must_use]
    pub const fn has_hashes(&self) -> bool {
        !self.hashes.is_empty()
    }
}

// ---------------------------------------------------------------------------
// SampleResult
// ---------------------------------------------------------------------------

/// A sample record returned from a lookup or query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleResult {
    /// SHA-256 hash of the sample (primary identifier).
    pub sha256: String,
    /// SHA-1 hash.
    pub sha1: Option<String>,
    /// MD5 hash.
    pub md5: Option<String>,
    /// Import hash (PE files only).
    pub imphash: Option<String>,
    /// SSDEEP fuzzy hash.
    pub ssdeep: Option<String>,
    /// Associated malware family id.
    pub family_id: String,
    /// Target architecture.
    pub architecture: Option<String>,
    /// File format (PE32, PE32+, ELF, etc.).
    pub file_format: Option<String>,
    /// File size in bytes.
    pub file_size: Option<u64>,
    /// Whether the sample is packed.
    pub packed: bool,
    /// PE compile timestamp (Unix).
    pub compile_time: Option<u64>,
    /// Version resource string.
    pub version: Option<String>,
    /// Source of this record.
    pub source: String,
    /// Confidence that this attribution is correct [0..100].
    pub confidence: u8,
    /// ATT&CK techniques observed in this sample.
    pub observed_techniques: Vec<String>,
}

impl SampleResult {
    /// Create a minimal sample result.
    #[must_use]
    pub fn new(sha256: impl Into<String>, family_id: impl Into<String>) -> Self {
        Self {
            sha256: sha256.into(),
            sha1: None,
            md5: None,
            imphash: None,
            ssdeep: None,
            family_id: family_id.into(),
            architecture: None,
            file_format: None,
            file_size: None,
            packed: false,
            compile_time: None,
            version: None,
            source: "malpedia".to_string(),
            confidence: 80,
            observed_techniques: Vec::new(),
        }
    }

    /// Return `true` if this sample matches the given hash value (any algorithm).
    #[must_use]
    pub fn matches_hash(&self, hash: &str) -> bool {
        let h = hash.to_lowercase();
        self.sha256 == h
            || self.sha1.as_deref().map(str::to_lowercase) == Some(h.clone())
            || self.md5.as_deref().map(str::to_lowercase) == Some(h.clone())
            || self.imphash.as_deref().map(str::to_lowercase) == Some(h)
    }

    /// Compute a simple risk level string from packed status and confidence.
    #[must_use]
    pub const fn risk_level(&self) -> &'static str {
        match self.confidence {
            90..=100 => "Critical",
            75..=89 => "High",
            50..=74 => "Medium",
            _ => "Low",
        }
    }
}

// ---------------------------------------------------------------------------
// MalpediaSampleFinder
// ---------------------------------------------------------------------------

/// Sample finder that searches a local hash store and supports prefix-based
/// partial matching, family-scoped search, and batch lookups.
pub struct MalpediaSampleFinder {
    /// Primary lookup index: sha256 (lowercase) → sample.
    by_sha256: HashMap<String, SampleResult>,
    /// Secondary lookup: sha1 (lowercase) → sha256.
    by_sha1: HashMap<String, String>,
    /// Secondary lookup: md5 (lowercase) → sha256.
    by_md5: HashMap<String, String>,
    /// Family index: `family_id` → list of sha256 hashes.
    by_family: HashMap<String, Vec<String>>,
}

impl MalpediaSampleFinder {
    /// Create an empty finder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_sha256: HashMap::new(),
            by_sha1: HashMap::new(),
            by_md5: HashMap::new(),
            by_family: HashMap::new(),
        }
    }

    /// Create a finder pre-populated with mock sample data.
    #[must_use]
    pub fn with_mock_data() -> Self {
        let mut f = Self::new();
        f.populate_mock();
        f
    }

    /// Insert a sample into the finder, building all indices.
    pub fn insert(&mut self, sample: SampleResult) {
        let sha256 = sample.sha256.to_lowercase();

        if let Some(ref sha1) = sample.sha1 {
            self.by_sha1.insert(sha1.to_lowercase(), sha256.clone());
        }
        if let Some(ref md5) = sample.md5 {
            self.by_md5.insert(md5.to_lowercase(), sha256.clone());
        }

        self.by_family
            .entry(sample.family_id.clone())
            .or_default()
            .push(sha256.clone());

        self.by_sha256.insert(sha256, sample);
    }

    /// Look up a sample by any hash (MD5, SHA-1, or SHA-256).
    #[must_use]
    pub fn find_by_hash(&self, hash: &str) -> Option<&SampleResult> {
        let h = hash.to_lowercase();
        match h.len() {
            64 => self.by_sha256.get(&h),
            40 => {
                let sha256 = self.by_sha1.get(&h)?;
                self.by_sha256.get(sha256)
            }
            32 => {
                let sha256 = self.by_md5.get(&h)?;
                self.by_sha256.get(sha256)
            }
            _ => {
                // Fuzzy prefix scan: find first entry whose sha256 starts with `h`.
                self.by_sha256
                    .values()
                    .find(|s| s.matches_hash(&h))
            }
        }
    }

    /// Perform a prefix-based partial match on SHA-256 (min 6 characters).
    #[must_use]
    pub fn find_by_prefix(&self, prefix: &str) -> Vec<&SampleResult> {
        if prefix.len() < 6 {
            return Vec::new();
        }
        let p = prefix.to_lowercase();
        self.by_sha256
            .keys()
            .filter(|k| k.starts_with(&p))
            .filter_map(|k| self.by_sha256.get(k))
            .collect()
    }

    /// Return all samples attributed to a specific family.
    #[must_use]
    pub fn by_family(&self, family_id: &str) -> Vec<&SampleResult> {
        self.by_family.get(family_id).map_or_else(Vec::new, |hashes| hashes
            .iter()
            .filter_map(|h| self.by_sha256.get(h))
            .collect())
    }

    /// Execute a structured `SampleQuery`.
    #[must_use]
    pub fn query(&self, q: &SampleQuery) -> Vec<&SampleResult> {
        // Start with hash lookups if provided.
        if !q.hashes.is_empty() {
            let mut results: Vec<&SampleResult> = q
                .hashes
                .iter()
                .filter_map(|h| self.find_by_hash(&h.value))
                .collect();
            results.dedup_by_key(|s| s.sha256.as_str());
            if let Some(n) = q.limit {
                results.truncate(n);
            }
            return results;
        }

        // Otherwise, scan based on filters.
        let mut results: Vec<&SampleResult> = q.family.as_ref().map_or_else(|| self.by_sha256.values().collect(), |fam| self.by_family(fam));

        // Apply filters.
        if let Some(ref arch) = q.architecture {
            results.retain(|s| {
                s.architecture.as_deref().is_some_and(|a| a.eq_ignore_ascii_case(arch))
            });
        }
        if let Some(ref fmt) = q.file_format {
            results.retain(|s| {
                s.file_format.as_deref().is_some_and(|f| f.eq_ignore_ascii_case(fmt))
            });
        }
        if let Some(packed) = q.packed {
            results.retain(|s| s.packed == packed);
        }

        if let Some(n) = q.limit {
            results.truncate(n);
        }
        results
    }

    /// Batch hash lookup: accepts a list of hashes and returns all found samples.
    #[must_use]
    pub fn batch_lookup(&self, hashes: &[&str]) -> Vec<&SampleResult> {
        let mut out: Vec<&SampleResult> = hashes
            .iter()
            .filter_map(|h| self.find_by_hash(h))
            .collect();
        out.dedup_by_key(|s| s.sha256.as_str());
        out
    }

    /// Total number of samples in the finder.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_sha256.len()
    }

    /// Return `true` if no samples have been loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_sha256.is_empty()
    }

    /// Return all known family IDs that have samples.
    #[must_use]
    pub fn known_families(&self) -> Vec<&str> {
        self.by_family.keys().map(String::as_str).collect()
    }

    /// Return the SHA-256 hashes for all samples of a given family.
    #[must_use]
    pub fn family_hashes(&self, family_id: &str) -> Vec<&str> {
        self.by_family.get(family_id).map_or_else(Vec::new, |v| v.iter().map(String::as_str).collect())
    }

    /// Compute a per-family sample count summary.
    #[must_use]
    pub fn family_sample_counts(&self) -> HashMap<&str, usize> {
        self.by_family
            .iter()
            .map(|(fam, hashes)| (fam.as_str(), hashes.len()))
            .collect()
    }

    fn populate_mock(&mut self) {
        // Emotet samples
        let mut s1 = SampleResult::new(
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "win.emotet",
        );
        s1.md5 = Some("d41d8cd98f00b204e9800998ecf8427e".to_string());
        s1.sha1 = Some("da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string());
        s1.file_format = Some("PE32".to_string());
        s1.architecture = Some("x86".to_string());
        s1.file_size = Some(102_400);
        s1.packed = true;
        s1.confidence = 95;
        self.insert(s1);

        let mut s2 = SampleResult::new(
            "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe",
            "win.emotet",
        );
        s2.file_format = Some("PE32".to_string());
        s2.architecture = Some("x86".to_string());
        s2.packed = false;
        self.insert(s2);

        // WannaCry
        let mut s3 = SampleResult::new(
            "0000111100001111000011110000111100001111000011110000111100001111",
            "win.wannacry",
        );
        s3.md5 = Some("84c82835a5d21bbcf75a61706d8ab549".to_string());
        s3.file_format = Some("PE32".to_string());
        s3.architecture = Some("x86".to_string());
        s3.file_size = Some(3_723_264);
        s3.compile_time = Some(1_494_438_000);
        s3.confidence = 99;
        self.insert(s3);

        // Mirai (Linux ELF)
        let mut s4 = SampleResult::new(
            "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111",
            "linux.mirai",
        );
        s4.file_format = Some("ELF".to_string());
        s4.architecture = Some("arm".to_string());
        s4.file_size = Some(58_368);
        s4.packed = false;
        self.insert(s4);
    }
}

impl Default for MalpediaSampleFinder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// BatchSampleLookupResult
// ---------------------------------------------------------------------------

/// The result of a batch hash lookup operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSampleLookupResult {
    /// Number of hashes that were queried.
    pub total_queried: usize,
    /// Number of hashes that matched a known sample.
    pub found: usize,
    /// Number of hashes with no match.
    pub not_found: usize,
    /// Matched samples.
    pub matches: Vec<SampleResult>,
    /// Hashes that were not found.
    pub missing_hashes: Vec<String>,
}

impl BatchSampleLookupResult {
    /// Compute the hit rate as a value in [0.0, 1.0].
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        if self.total_queried == 0 {
            return 0.0;
        }
        self.found as f64 / self.total_queried as f64
    }

    /// Return `true` if at least one hash was matched.
    #[must_use]
    pub const fn has_matches(&self) -> bool {
        self.found > 0
    }
}

/// Execute a batch lookup and build a structured result.
#[must_use]
pub fn batch_lookup(finder: &MalpediaSampleFinder, hashes: &[&str]) -> BatchSampleLookupResult {
    let total_queried = hashes.len();
    let mut matches: Vec<SampleResult> = Vec::new();
    let mut missing_hashes: Vec<String> = Vec::new();

    for hash in hashes {
        match finder.find_by_hash(hash) {
            Some(s) => matches.push(s.clone()),
            None => missing_hashes.push((*hash).to_string()),
        }
    }

    let found = matches.len();
    BatchSampleLookupResult {
        total_queried,
        found,
        not_found: total_queried - found,
        matches,
        missing_hashes,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn finder() -> MalpediaSampleFinder {
        MalpediaSampleFinder::with_mock_data()
    }

    #[test]
    fn test_finder_not_empty() {
        assert!(!finder().is_empty());
    }

    #[test]
    fn test_find_by_sha256() {
        let f = finder();
        let r = f.find_by_hash("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        assert!(r.is_some());
        assert_eq!(r.unwrap().family_id, "win.emotet");
    }

    #[test]
    fn test_find_by_sha256_uppercase_input() {
        let f = finder();
        let r = f.find_by_hash("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF");
        assert!(r.is_some());
    }

    #[test]
    fn test_find_by_md5() {
        let f = finder();
        let r = f.find_by_hash("d41d8cd98f00b204e9800998ecf8427e");
        assert!(r.is_some());
        assert_eq!(r.unwrap().family_id, "win.emotet");
    }

    #[test]
    fn test_find_by_sha1() {
        let f = finder();
        let r = f.find_by_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert!(r.is_some());
    }

    #[test]
    fn test_find_missing_hash() {
        let f = finder();
        let r = f.find_by_hash("0000000000000000000000000000000000000000000000000000000000000000");
        assert!(r.is_none());
    }

    #[test]
    fn test_find_by_prefix() {
        let f = finder();
        let r = f.find_by_prefix("deadbeef");
        assert!(!r.is_empty());
    }

    #[test]
    fn test_find_by_prefix_too_short() {
        let f = finder();
        let r = f.find_by_prefix("de");
        assert!(r.is_empty());
    }

    #[test]
    fn test_by_family() {
        let f = finder();
        let r = f.by_family("win.emotet");
        assert!(r.len() >= 2);
    }

    #[test]
    fn test_by_family_missing() {
        let f = finder();
        let r = f.by_family("win.nonexistent");
        assert!(r.is_empty());
    }

    #[test]
    fn test_query_by_hash() {
        let f = finder();
        let q = SampleQuery::new()
            .with_hash("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        let r = f.query(&q);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn test_query_by_family() {
        let f = finder();
        let q = SampleQuery::new().with_family("win.emotet");
        let r = f.query(&q);
        assert!(r.len() >= 2);
    }

    #[test]
    fn test_query_by_family_and_packed() {
        let f = finder();
        let q = SampleQuery::new().with_family("win.emotet");
        let mut q = q;
        q.packed = Some(true);
        let r = f.query(&q);
        assert!(r.iter().all(|s| s.packed));
    }

    #[test]
    fn test_query_limit() {
        let f = finder();
        let q = SampleQuery::new().with_limit(1);
        let r = f.query(&q);
        assert!(r.len() <= 1);
    }

    #[test]
    fn test_batch_lookup_all_found() {
        let f = finder();
        let hashes = vec![
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe",
        ];
        let result = batch_lookup(&f, &hashes);
        assert_eq!(result.total_queried, 2);
        assert_eq!(result.found, 2);
        assert_eq!(result.not_found, 0);
    }

    #[test]
    fn test_batch_lookup_partial() {
        let f = finder();
        let hashes = vec![
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ];
        let result = batch_lookup(&f, &hashes);
        assert_eq!(result.found, 1);
        assert_eq!(result.not_found, 1);
        assert_eq!(result.missing_hashes.len(), 1);
    }

    #[test]
    fn test_batch_lookup_hit_rate() {
        let f = finder();
        let hashes = vec![
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe",
        ];
        let result = batch_lookup(&f, &hashes);
        assert!((result.hit_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_known_families() {
        let f = finder();
        let families = f.known_families();
        assert!(families.contains(&"win.emotet"));
        assert!(families.contains(&"linux.mirai"));
    }

    #[test]
    fn test_family_sample_counts() {
        let f = finder();
        let counts = f.family_sample_counts();
        assert!(*counts.get("win.emotet").unwrap_or(&0) >= 2);
    }

    #[test]
    fn test_hash_kind_infer() {
        assert_eq!(HashKind::infer("d41d8cd98f00b204e9800998ecf8427e"), HashKind::Md5);
        assert_eq!(HashKind::infer("da39a3ee5e6b4b0d3255bfef95601890afd80709"), HashKind::Sha1);
        // SHA-256("") is 64 hex chars; the previous literal here was 63.
        assert_eq!(
            HashKind::infer("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            HashKind::Sha256
        );
    }

    #[test]
    fn test_hash_lookup_valid_hex() {
        let h = HashLookup::new("deadbeef");
        assert!(h.is_valid_hex());
    }

    #[test]
    fn test_hash_lookup_prefix() {
        let h = HashLookup::new("deadbeef1234");
        assert_eq!(h.prefix(4), "dead");
    }

    #[test]
    fn test_sample_result_matches_hash() {
        let mut s = SampleResult::new("aabbcc" .repeat(10) + "aabbcc1234", "win.test");
        s.sha256 = "a".repeat(64);
        s.md5 = Some("b".repeat(32));
        assert!(s.matches_hash(&"a".repeat(64)));
        assert!(s.matches_hash(&"b".repeat(32)));
        assert!(!s.matches_hash("zz"));
    }

    #[test]
    fn test_sample_risk_level() {
        let mut s = SampleResult::new("a".repeat(64), "win.test");
        s.confidence = 95;
        assert_eq!(s.risk_level(), "Critical");
        s.confidence = 30;
        assert_eq!(s.risk_level(), "Low");
    }

    #[test]
    fn test_query_architecture_filter() {
        let f = finder();
        let mut q = SampleQuery::new();
        q.architecture = Some("arm".to_string());
        let r = f.query(&q);
        assert!(!r.is_empty());
        assert!(r.iter().all(|s| s.architecture.as_deref() == Some("arm")));
    }
}
