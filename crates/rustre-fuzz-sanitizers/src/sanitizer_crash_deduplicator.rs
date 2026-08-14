//! Sanitizer crash deduplicator — integration layer for structured reports.
//!
//! Deduplicates crash reports from `AddressSanitizer` and `UBSan` by computing
//! stable content-based hashes of their key features (error type + top stack
//! frames).  Two crashes are considered duplicates when their deduplicated key
//! matches exactly (FNV-1a hash).
//!
//! # Key types
//!
//! * [`SanitizerCrashDeduplicator`] — stateful deduplicator instance.
//! * [`CrashHash`] — stable content-based hash identifying a crash cluster.
//! * [`DeduplicatedCrash`] — a canonical representative for a crash cluster.
//! * Free function [`is_duplicate`] — compare two deduplicated keys.
//!
//! # Relationship to [`crate::crash_deduplicator`]
//!
//! [`crate::crash_deduplicator::CrashDeduplicator`] is the *generic* layer:
//! it accepts [`crate::crash_deduplicator::RawCrash`] from any text source and
//! uses fuzzy edit-distance bucketing together with exploitability scoring.
//!
//! This module is the *integration* layer: it consumes structured
//! [`crate::asan_report_parser::AsanReport`] / [`crate::ubsan_report_parser::UbReport`]
//! objects and performs exact-key deduplication via a stable `CrashHash`.
//! The two modules are **intentionally kept separate** and are not duplicates.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::asan_report_parser::{AsanReport, CrashKind};
use crate::ubsan_report_parser::UbReport;

// ── CrashHash ─────────────────────────────────────────────────────────────────

/// A stable hash (deterministic, 64-bit FNV-1a) identifying a crash cluster.
///
/// Two crashes that produce the same [`CrashHash`] are considered duplicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CrashHash(pub u64);

impl CrashHash {
    /// Compute a crash hash from an arbitrary string key.
    #[must_use]
    pub fn from_key(key: &str) -> Self {
        Self(fnv1a_64(key.as_bytes()))
    }

    /// Hex representation.
    #[must_use]
    pub fn hex(&self) -> String {
        format!("{:016x}", self.0)
    }
}

impl fmt::Display for CrashHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.hex())
    }
}

// ── CrashSource ───────────────────────────────────────────────────────────────

/// Which sanitizer produced the crash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrashSource {
    ASan,
    UBSan,
    /// Other / unspecified.
    Other(String),
}

impl fmt::Display for CrashSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ASan => write!(f, "ASan"),
            Self::UBSan => write!(f, "UBSan"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

// ── CrashFeatures ─────────────────────────────────────────────────────────────

/// Extracted, normalised features used to compute the dedup hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashFeatures {
    /// Error kind string (canonical).
    pub kind: String,
    /// Top-N normalised function names from the crash stack.
    pub top_frames: Vec<String>,
    /// Source file of the top frame, if available.
    pub top_file: Option<String>,
    /// Source line of the top frame, if available.
    pub top_line: Option<u32>,
}

impl CrashFeatures {
    /// Produce the dedup key string.
    #[must_use]
    pub fn dedup_key(&self) -> String {
        let mut parts = vec![self.kind.clone()];
        parts.extend(self.top_frames.iter().cloned());
        if let (Some(f), Some(l)) = (&self.top_file, self.top_line) {
            parts.push(format!("{f}:{l}"));
        }
        parts.join("|")
    }

    /// Compute the stable hash.
    #[must_use]
    pub fn hash(&self) -> CrashHash {
        CrashHash::from_key(&self.dedup_key())
    }
}

// ── DeduplicatedCrash ─────────────────────────────────────────────────────────

/// A canonical representative for a crash cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeduplicatedCrash {
    /// Stable hash identifying this cluster.
    pub hash: CrashHash,
    /// The source sanitizer.
    pub source: CrashSource,
    /// Extracted features that determine cluster membership.
    pub features: CrashFeatures,
    /// How many duplicate reports have been merged into this cluster.
    pub hit_count: usize,
    /// Raw text of the first (representative) report.
    pub representative_raw: String,
    /// One-line summary.
    pub summary: String,
}

impl DeduplicatedCrash {
    /// Returns `true` if this crash is security-relevant according to kind.
    #[must_use]
    pub fn is_security_relevant(&self) -> bool {
        let kind = CrashKind::parse(&self.features.kind);
        kind.is_likely_exploitable()
    }
}

impl fmt::Display for DeduplicatedCrash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} (hash={}, hits={})",
            self.source, self.summary, self.hash, self.hit_count
        )
    }
}

// ── SanitizerCrashDeduplicator ────────────────────────────────────────────────

/// Stateful deduplicator for `ASan` and `UBSan` crash reports.
///
/// Internally maintains a map from [`CrashHash`] to [`DeduplicatedCrash`] so
/// that successive calls to [`add_asan`] / [`add_ubsan`] / [`add_raw_key`]
/// accumulate deduplicated clusters.
pub struct SanitizerCrashDeduplicator {
    /// How many top frames to use for hashing (default: 5).
    pub stack_depth: usize,
    clusters: HashMap<CrashHash, DeduplicatedCrash>,
    /// Order of first insertion for deterministic iteration.
    insertion_order: Vec<CrashHash>,
    seen_keys: HashSet<String>,
}

impl Default for SanitizerCrashDeduplicator {
    fn default() -> Self {
        Self::new(5)
    }
}

impl SanitizerCrashDeduplicator {
    /// Create a new deduplicator using the top-`stack_depth` frames for hashing.
    #[must_use]
    pub fn new(stack_depth: usize) -> Self {
        Self {
            stack_depth,
            clusters: HashMap::new(),
            insertion_order: Vec::new(),
            seen_keys: HashSet::new(),
        }
    }

    // ── ASan ──────────────────────────────────────────────────────────────────

    /// Add an [`AsanReport`] to the deduplicator.
    ///
    /// Returns `(hash, is_new)`.  `is_new` is `false` if this was a duplicate.
    pub fn add_asan(&mut self, report: &AsanReport) -> (CrashHash, bool) {
        let features = Self::asan_features(report, self.stack_depth);
        self.upsert(features, CrashSource::ASan, report.raw_text.clone(), report.summary())
    }

    /// Feed all `ASan` reports from a slice and return new cluster hashes.
    pub fn add_asan_batch(&mut self, reports: &[AsanReport]) -> Vec<CrashHash> {
        let mut new_hashes = Vec::new();
        for r in reports {
            let (h, is_new) = self.add_asan(r);
            if is_new {
                new_hashes.push(h);
            }
        }
        new_hashes
    }

    fn asan_features(report: &AsanReport, depth: usize) -> CrashFeatures {
        let kind = report.kind.to_string();
        let top_frames: Vec<String> = report
            .crash_stack
            .iter()
            .take(depth)
            .map(|f| {
                f.function
                    .as_deref()
                    .unwrap_or("?")
                    .split('+')
                    .next()
                    .unwrap_or("?")
                    .trim()
                    .to_owned()
            })
            .collect();
        let top_file = report.crash_stack.first().and_then(|f| f.file.clone());
        let top_line = report.crash_stack.first().and_then(|f| f.line);
        CrashFeatures { kind, top_frames, top_file, top_line }
    }

    // ── UBSan ─────────────────────────────────────────────────────────────────

    /// Add a [`UbReport`] to the deduplicator.
    ///
    /// Returns `(hash, is_new)`.  `is_new` is `false` if this was a duplicate.
    pub fn add_ubsan(&mut self, report: &UbReport) -> (CrashHash, bool) {
        let features = Self::ubsan_features(report);
        let summary = report.summary();
        let raw = report.raw_text.clone();
        self.upsert(features, CrashSource::UBSan, raw, summary)
    }

    /// Feed all `UBSan` reports from a slice.
    pub fn add_ubsan_batch(&mut self, reports: &[UbReport]) -> Vec<CrashHash> {
        let mut new_hashes = Vec::new();
        for r in reports {
            let (h, is_new) = self.add_ubsan(r);
            if is_new {
                new_hashes.push(h);
            }
        }
        new_hashes
    }

    fn ubsan_features(report: &UbReport) -> CrashFeatures {
        let kind = report.kind.to_string();
        let top_file = report.location.as_ref().map(|l| l.file.clone());
        let top_line = report.location.as_ref().map(|l| l.line);
        CrashFeatures { kind, top_frames: Vec::new(), top_file, top_line }
    }

    // ── Generic raw-key API ───────────────────────────────────────────────────

    /// Deduplicate using an arbitrary precomputed key string.
    ///
    /// Returns `(hash, is_new)`.
    pub fn add_raw_key(
        &mut self,
        key: &str,
        source: CrashSource,
        raw_text: String,
        summary: String,
    ) -> (CrashHash, bool) {
        let features = CrashFeatures {
            kind: key.to_owned(),
            top_frames: Vec::new(),
            top_file: None,
            top_line: None,
        };
        self.upsert(features, source, raw_text, summary)
    }

    // ── Query ─────────────────────────────────────────────────────────────────

    /// Total number of unique crash clusters.
    #[must_use]
    pub fn cluster_count(&self) -> usize {
        self.clusters.len()
    }

    /// Total number of reports seen (including duplicates).
    #[must_use]
    pub fn total_reports(&self) -> usize {
        self.clusters.values().map(|c| c.hit_count).sum()
    }

    /// Look up a cluster by hash.
    #[must_use]
    pub fn cluster(&self, hash: &CrashHash) -> Option<&DeduplicatedCrash> {
        self.clusters.get(hash)
    }

    /// All clusters in insertion order.
    #[must_use]
    pub fn clusters(&self) -> Vec<&DeduplicatedCrash> {
        self.insertion_order
            .iter()
            .filter_map(|h| self.clusters.get(h))
            .collect()
    }

    /// Clusters with more than `min_hits` reports, sorted by hit count descending.
    #[must_use]
    pub fn hot_clusters(&self, min_hits: usize) -> Vec<&DeduplicatedCrash> {
        let mut v: Vec<&DeduplicatedCrash> = self
            .clusters
            .values()
            .filter(|c| c.hit_count >= min_hits)
            .collect();
        // The input comes from a `HashMap`, so clusters sharing a hit count
        // would be returned in an order that changes between runs of the same
        // binary. `hash` is the map key and therefore unique, which makes this
        // a total order. (Same reasoning as `buckets_by_severity` in
        // `crash_deduplicator`.)
        v.sort_by(|a, b| {
            b.hit_count
                .cmp(&a.hit_count)
                .then_with(|| a.hash.0.cmp(&b.hash.0))
        });
        v
    }

    /// Only security-relevant clusters.
    #[must_use]
    pub fn security_relevant_clusters(&self) -> Vec<&DeduplicatedCrash> {
        self.clusters
            .values()
            .filter(|c| c.is_security_relevant())
            .collect()
    }

    /// Return clusters from a specific source sanitizer.
    #[must_use]
    pub fn clusters_from(&self, source: &CrashSource) -> Vec<&DeduplicatedCrash> {
        self.clusters
            .values()
            .filter(|c| &c.source == source)
            .collect()
    }

    /// Remove all clusters.
    pub fn clear(&mut self) {
        self.clusters.clear();
        self.insertion_order.clear();
        self.seen_keys.clear();
    }

    // ── Private ───────────────────────────────────────────────────────────────

    fn upsert(
        &mut self,
        features: CrashFeatures,
        source: CrashSource,
        raw_text: String,
        summary: String,
    ) -> (CrashHash, bool) {
        let key = features.dedup_key();
        let hash = CrashHash::from_key(&key);

        if let Some(existing) = self.clusters.get_mut(&hash) {
            existing.hit_count += 1;
            self.seen_keys.insert(key);
            return (hash, false);
        }

        let crash = DeduplicatedCrash {
            hash,
            source,
            features,
            hit_count: 1,
            representative_raw: raw_text,
            summary,
        };
        self.clusters.insert(hash, crash);
        self.insertion_order.push(hash);
        self.seen_keys.insert(key);
        (hash, true)
    }
}

// ── Free functions ────────────────────────────────────────────────────────────

/// Returns `true` when two dedup keys represent the same crash.
///
/// This is simply a string equality check; the dedup keys are expected to have
/// been produced by the same normalisation logic.
#[must_use]
pub fn is_duplicate(key_a: &str, key_b: &str) -> bool {
    key_a == key_b
}

/// Compute the [`CrashHash`] for an arbitrary dedup key.
#[must_use]
pub fn hash_key(key: &str) -> CrashHash {
    CrashHash::from_key(key)
}

// ── FNV-1a ────────────────────────────────────────────────────────────────────

const FNV_OFFSET: u64 = 14_695_981_039_346_656_037;
const FNV_PRIME: u64 = 1_099_511_628_211;

fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asan_report_parser::{parse_asan_output, StackFrame};
    use crate::ubsan_report_parser::parse_ubsan_output;

    fn make_asan_report(kind_str: &str, funcs: &[&str]) -> AsanReport {
        let kind = CrashKind::parse(kind_str);
        let crash_stack: Vec<StackFrame> = funcs
            .iter()
            .enumerate()
            .map(|(i, f)| StackFrame {
                index: i,
                address: None,
                function: Some((*f).to_owned()),
                module: None,
                file: Some("test.c".into()),
                line: Some(crate::cast::usize_to_u32(i) + 1),
                column: None,
            })
            .collect();
        AsanReport {
            kind,
            access: None,
            crash_stack,
            allocation: None,
            thread_id: None,
            pid: None,
            raw_text: format!("==1==ERROR: AddressSanitizer: {kind_str}"),
            error_type_raw: kind_str.to_owned(),
        }
    }

    #[test]
    fn test_crash_hash_stability() {
        let h1 = CrashHash::from_key("use-after-free|foo|bar");
        let h2 = CrashHash::from_key("use-after-free|foo|bar");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_crash_hash_different_keys() {
        let h1 = CrashHash::from_key("use-after-free|foo");
        let h2 = CrashHash::from_key("use-after-free|baz");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_crash_hash_display() {
        let h = CrashHash(0xdead_beef_cafe_1234);
        assert_eq!(h.to_string(), "deadbeefcafe1234");
    }

    #[test]
    fn test_add_asan_new() {
        let mut dedup = SanitizerCrashDeduplicator::default();
        let report = make_asan_report("use-after-free", &["foo", "bar"]);
        let (_, is_new) = dedup.add_asan(&report);
        assert!(is_new);
        assert_eq!(dedup.cluster_count(), 1);
    }

    #[test]
    fn test_add_asan_duplicate() {
        let mut dedup = SanitizerCrashDeduplicator::default();
        let r1 = make_asan_report("use-after-free", &["foo", "bar"]);
        let r2 = make_asan_report("use-after-free", &["foo", "bar"]);
        let (_, _) = dedup.add_asan(&r1);
        let (_, is_new) = dedup.add_asan(&r2);
        assert!(!is_new);
        assert_eq!(dedup.cluster_count(), 1);
        assert_eq!(dedup.total_reports(), 2);
    }

    #[test]
    fn test_add_asan_different_kinds() {
        let mut dedup = SanitizerCrashDeduplicator::default();
        let r1 = make_asan_report("use-after-free", &["foo"]);
        let r2 = make_asan_report("heap-buffer-overflow", &["foo"]);
        dedup.add_asan(&r1);
        dedup.add_asan(&r2);
        assert_eq!(dedup.cluster_count(), 2);
    }

    #[test]
    fn test_add_asan_different_stacks() {
        let mut dedup = SanitizerCrashDeduplicator::default();
        let r1 = make_asan_report("use-after-free", &["foo", "bar"]);
        let r2 = make_asan_report("use-after-free", &["foo", "baz"]);
        dedup.add_asan(&r1);
        dedup.add_asan(&r2);
        assert_eq!(dedup.cluster_count(), 2);
    }

    #[test]
    fn test_add_asan_batch() {
        let mut dedup = SanitizerCrashDeduplicator::default();
        let reports = vec![
            make_asan_report("use-after-free", &["a", "b"]),
            make_asan_report("use-after-free", &["a", "b"]),
            make_asan_report("heap-buffer-overflow", &["c"]),
        ];
        let new_hashes = dedup.add_asan_batch(&reports);
        assert_eq!(new_hashes.len(), 2);
        assert_eq!(dedup.cluster_count(), 2);
    }

    #[test]
    fn test_add_ubsan() {
        let reports = parse_ubsan_output(
            "/src/x.c:10:3: runtime error: signed integer overflow: 1 + 2 cannot be represented",
        );
        let mut dedup = SanitizerCrashDeduplicator::default();
        let (_, is_new) = dedup.add_ubsan(&reports[0]);
        assert!(is_new);
    }

    #[test]
    fn test_add_ubsan_batch_dedup() {
        let text = concat!(
            "/a.c:1:1: runtime error: null pointer dereference\n",
            "/a.c:1:1: runtime error: null pointer dereference\n",
            "/b.c:5:2: runtime error: division by zero\n",
        );
        let reports = parse_ubsan_output(text);
        let mut dedup = SanitizerCrashDeduplicator::default();
        let new_hashes = dedup.add_ubsan_batch(&reports);
        assert_eq!(new_hashes.len(), 2);
        assert_eq!(dedup.cluster_count(), 2);
        assert_eq!(dedup.total_reports(), 3);
    }

    #[test]
    fn test_cluster_lookup() {
        let mut dedup = SanitizerCrashDeduplicator::default();
        let report = make_asan_report("use-after-free", &["foo"]);
        let (hash, _) = dedup.add_asan(&report);
        let cluster = dedup.cluster(&hash).unwrap();
        assert_eq!(cluster.hit_count, 1);
        assert_eq!(cluster.source, CrashSource::ASan);
    }

    #[test]
    fn test_clusters_in_order() {
        let mut dedup = SanitizerCrashDeduplicator::default();
        let r1 = make_asan_report("use-after-free", &["foo"]);
        let r2 = make_asan_report("heap-buffer-overflow", &["bar"]);
        let (h1, _) = dedup.add_asan(&r1);
        let (h2, _) = dedup.add_asan(&r2);
        let order: Vec<CrashHash> = dedup.clusters().iter().map(|c| c.hash).collect();
        assert_eq!(order[0], h1);
        assert_eq!(order[1], h2);
    }

    #[test]
    fn test_hot_clusters() {
        let mut dedup = SanitizerCrashDeduplicator::default();
        let r = make_asan_report("use-after-free", &["foo"]);
        dedup.add_asan(&r);
        dedup.add_asan(&r);
        dedup.add_asan(&r);
        let hot = dedup.hot_clusters(2);
        assert_eq!(hot.len(), 1);
        assert_eq!(hot[0].hit_count, 3);
    }

    #[test]
    fn test_security_relevant_clusters() {
        let mut dedup = SanitizerCrashDeduplicator::default();
        let r1 = make_asan_report("use-after-free", &["foo"]);
        let r2 = make_asan_report("memory-leak", &["bar"]);
        dedup.add_asan(&r1);
        dedup.add_asan(&r2);
        let sec = dedup.security_relevant_clusters();
        assert_eq!(sec.len(), 1);
        assert_eq!(sec[0].features.kind, "use-after-free");
    }

    #[test]
    fn test_clusters_from_source() {
        let mut dedup = SanitizerCrashDeduplicator::default();
        let r = make_asan_report("use-after-free", &["x"]);
        dedup.add_asan(&r);
        let asan = dedup.clusters_from(&CrashSource::ASan);
        assert_eq!(asan.len(), 1);
        let ubsan = dedup.clusters_from(&CrashSource::UBSan);
        assert_eq!(ubsan.len(), 0);
    }

    #[test]
    fn test_clear() {
        let mut dedup = SanitizerCrashDeduplicator::default();
        let r = make_asan_report("double-free", &["f"]);
        dedup.add_asan(&r);
        dedup.clear();
        assert_eq!(dedup.cluster_count(), 0);
    }

    #[test]
    fn test_add_raw_key() {
        let mut dedup = SanitizerCrashDeduplicator::default();
        let (_, is_new) = dedup.add_raw_key(
            "my-key",
            CrashSource::Other("custom".into()),
            "raw".to_owned(),
            "summary".to_owned(),
        );
        assert!(is_new);
        assert!(!is_duplicate("my-key", "other-key"));
        assert!(is_duplicate("my-key", "my-key"));
    }

    #[test]
    fn test_is_duplicate_fn() {
        assert!(is_duplicate("a|b|c", "a|b|c"));
        assert!(!is_duplicate("a|b|c", "a|b|d"));
    }

    #[test]
    fn test_hash_key_deterministic() {
        let h1 = hash_key("test-key");
        let h2 = hash_key("test-key");
        assert_eq!(h1, h2);
        assert_ne!(hash_key("key-a"), hash_key("key-b"));
    }

    #[test]
    fn test_dedup_with_real_asan_report() {
        let asan_text = r"==9999==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1234 thread T0
READ of size 1 at 0x1234 thread T0
    #0 0x401000 in vuln_func /src/vuln.c:10:3
    #1 0x401100 in main /src/main.c:50:5
";
        let report = parse_asan_output(asan_text).unwrap();
        let mut dedup = SanitizerCrashDeduplicator::default();
        let (h1, new1) = dedup.add_asan(&report);
        let (h2, new2) = dedup.add_asan(&report);
        assert!(new1);
        assert!(!new2);
        assert_eq!(h1, h2);
        assert_eq!(dedup.cluster(&h1).unwrap().hit_count, 2);
    }
}
