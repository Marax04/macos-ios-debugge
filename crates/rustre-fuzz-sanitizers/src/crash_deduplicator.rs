//! Crash deduplication engine — generic, self-contained layer.
//!
//! Operates on [`RawCrash`] values (parsed from any text source) and groups
//! them using a call-stack signature with fuzzy edit-distance bucketing.
//! Also provides exploitability scoring, [`SimilarityClusterer`], and
//! triage report generation.
//!
//! # Relationship to [`crate::sanitizer_crash_deduplicator`]
//!
//! [`crate::sanitizer_crash_deduplicator::SanitizerCrashDeduplicator`] is the
//! *integration* layer: it accepts structured [`crate::asan_report_parser::AsanReport`]
//! and [`crate::ubsan_report_parser::UbReport`] objects directly and produces
//! `CrashHash`-keyed clusters with exact (FNV-1a) matching.
//!
//! This module is the *generic* layer: it accepts any [`RawCrash`], does
//! fuzzy stack-distance deduplication, and computes exploitability scores.
//! The two modules are **intentionally kept separate** and are not duplicates.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;
use std::hash::Hash;
use std::time::Instant;

// ── CrashSignature ────────────────────────────────────────────────────────────

/// Normalised representation of a crash for deduplication.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CrashSignature {
    /// Top N frames of the call stack (function names, normalised).
    pub stack_key: Vec<String>,
    /// Broad category of the crash.
    pub crash_type: CrashType,
    /// Whether this was a write operation (vs. read).
    pub is_write: bool,
    /// Fault address bucket (None = unknown).
    pub fault_bucket: Option<FaultBucket>,
}

impl CrashSignature {
    /// Compute a stable 64-bit hash for fast bucketing.
    #[must_use] 
    pub fn hash64(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        let mut h = DefaultHasher::new();
        self.hash(&mut h);
        std::hash::Hasher::finish(&h)
    }

    /// Short human-readable label.
    #[must_use] 
    pub fn label(&self) -> String {
        let rw = if self.is_write { "WRITE" } else { "READ" };
        let top = self.stack_key.first().map_or("?", std::string::String::as_str);
        format!("{}/{}/{}", self.crash_type.label(), rw, top)
    }
}

/// Broad crash type taxonomy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CrashType {
    HeapBufferOverflow,
    HeapUseAfterFree,
    StackBufferOverflow,
    StackBufferUnderflow,
    NullDereference,
    DoubleFree,
    BadFree,
    UseAfterScope,
    UseAfterReturn,
    IntegerOverflow,
    DivideByZero,
    StackOverflow,
    FormatString,
    TypeConfusion,
    RaceCondition,
    AssertionFailed,
    Unknown(String),
}

impl std::str::FromStr for CrashType {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::parse(s))
    }
}

impl CrashType {
    #[must_use]
    pub fn parse(s: &str) -> Self {
        let lower = s.to_lowercase();
        if lower.contains("heap-buffer-overflow") || lower.contains("heap buffer overflow") {
            Self::HeapBufferOverflow
        } else if lower.contains("heap-use-after-free") || lower.contains("use after free") {
            Self::HeapUseAfterFree
        } else if lower.contains("stack-buffer-overflow") || lower.contains("stack buffer overflow") {
            Self::StackBufferOverflow
        } else if lower.contains("stack-buffer-underflow") {
            Self::StackBufferUnderflow
        } else if lower.contains("null") && lower.contains("deref") {
            Self::NullDereference
        } else if lower.contains("double-free") || lower.contains("double free") {
            Self::DoubleFree
        } else if lower.contains("bad-free") || lower.contains("bad free") {
            Self::BadFree
        } else if lower.contains("use-after-scope") {
            Self::UseAfterScope
        } else if lower.contains("use-after-return") {
            Self::UseAfterReturn
        } else if lower.contains("integer-overflow") || lower.contains("integer overflow") {
            Self::IntegerOverflow
        } else if lower.contains("divide") || lower.contains("division") {
            Self::DivideByZero
        } else if lower.contains("stack-overflow") || lower.contains("stack overflow") {
            Self::StackOverflow
        } else if lower.contains("format") {
            Self::FormatString
        } else if lower.contains("type") && lower.contains("confusion") {
            Self::TypeConfusion
        } else if lower.contains("race") || lower.contains("data race") {
            Self::RaceCondition
        } else if lower.contains("assert") {
            Self::AssertionFailed
        } else {
            Self::Unknown(s.to_string())
        }
    }

    #[must_use] 
    pub const fn label(&self) -> &str {
        match self {
            Self::HeapBufferOverflow => "HEAP_OVERFLOW",
            Self::HeapUseAfterFree => "USE_AFTER_FREE",
            Self::StackBufferOverflow => "STACK_OVERFLOW_BUF",
            Self::StackBufferUnderflow => "STACK_UNDERFLOW",
            Self::NullDereference => "NULL_DEREF",
            Self::DoubleFree => "DOUBLE_FREE",
            Self::BadFree => "BAD_FREE",
            Self::UseAfterScope => "USE_AFTER_SCOPE",
            Self::UseAfterReturn => "USE_AFTER_RETURN",
            Self::IntegerOverflow => "INT_OVERFLOW",
            Self::DivideByZero => "DIV_BY_ZERO",
            Self::StackOverflow => "STACK_OVERFLOW",
            Self::FormatString => "FORMAT_STRING",
            Self::TypeConfusion => "TYPE_CONFUSION",
            Self::RaceCondition => "RACE_CONDITION",
            Self::AssertionFailed => "ASSERTION",
            Self::Unknown(_) => "UNKNOWN",
        }
    }

    /// Base exploitability score 0-10.
    #[must_use] 
    pub const fn base_exploitability(&self) -> u8 {
        match self {
            Self::HeapUseAfterFree | Self::StackBufferOverflow | Self::FormatString => 9,
            Self::HeapBufferOverflow | Self::DoubleFree | Self::TypeConfusion => 8,
            Self::BadFree | Self::UseAfterScope | Self::UseAfterReturn => 7,
            Self::StackBufferUnderflow | Self::StackOverflow => 6,
            Self::IntegerOverflow | Self::RaceCondition => 5,
            Self::Unknown(_) => 3,
            Self::NullDereference => 2,
            Self::DivideByZero | Self::AssertionFailed => 1,
        }
    }
}

impl fmt::Display for CrashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Broad bucket for fault addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FaultBucket {
    NearNull,       // 0..0x1000
    SlightlyNull,   // 0x1000..0x10000
    UserSpace,      // 0x10000..0x8000_0000_0000
    KernelBoundary, // near 0x7FFF_FFFF_FFFF
    KernelSpace,    // >= 0x8000_0000_0000
    Mapped,         // any reasonably aligned
}

impl FaultBucket {
    #[must_use] 
    pub const fn from_address(addr: u64) -> Self {
        match addr {
            0..=0xfff => Self::NearNull,
            0x1000..=0xffff => Self::SlightlyNull,
            0x7fff_ffff_f000..=0x7fff_ffff_ffff => Self::KernelBoundary,
            a if a >= 0x8000_0000_0000 => Self::KernelSpace,
            _ => Self::UserSpace,
        }
    }

    /// Exploitability modifier.
    #[must_use] 
    pub const fn modifier(&self) -> i8 {
        match self {
            Self::NearNull => -4,
            Self::SlightlyNull => -2,
            Self::UserSpace => 0,
            Self::Mapped => 1,
            Self::KernelBoundary => 2,
            Self::KernelSpace => -3,
        }
    }
}

// ── ExploitabilityScore ───────────────────────────────────────────────────────

/// Exploitability rating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Exploitability {
    NotExploitable,
    Unknown,
    Interesting,
    Probably,
    Exploitable,
}

impl Exploitability {
    #[must_use] 
    pub const fn from_score(score: i32) -> Self {
        match score {
            i32::MIN..=0 => Self::NotExploitable,
            1..=3 => Self::Unknown,
            4..=5 => Self::Interesting,
            6..=7 => Self::Probably,
            _ => Self::Exploitable,
        }
    }

    #[must_use] 
    pub const fn label(&self) -> &str {
        match self {
            Self::NotExploitable => "NOT_EXPLOITABLE",
            Self::Unknown => "UNKNOWN",
            Self::Interesting => "INTERESTING",
            Self::Probably => "PROBABLY_EXPLOITABLE",
            Self::Exploitable => "EXPLOITABLE",
        }
    }
}

impl fmt::Display for Exploitability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ── RawCrash ──────────────────────────────────────────────────────────────────

/// Raw information about a single crash.
#[derive(Debug, Clone)]
pub struct RawCrash {
    pub id: u64,
    pub crash_type_str: String,
    pub is_write: bool,
    pub fault_address: Option<u64>,
    pub stack_frames: Vec<StackFrame>,
    pub input: Vec<u8>,
    pub description: String,
    pub discovered_at: Instant,
}

/// Single stack frame.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StackFrame {
    pub index: u32,
    pub address: u64,
    pub function: Option<String>,
    pub module: Option<String>,
    pub offset: Option<u64>,
    pub file: Option<String>,
    pub line: Option<u32>,
}

impl StackFrame {
    #[must_use] 
    pub fn normalized_name(&self) -> String {
        self.function.as_ref().map_or_else(|| format!("0x{:x}", self.address), |f| normalize_function_name(f))
    }

    #[must_use] 
    pub fn is_runtime_frame(&self) -> bool {
        let name = self.function.as_deref().unwrap_or("");
        RUNTIME_FRAMES.iter().any(|&prefix| name.starts_with(prefix))
    }
}

static RUNTIME_FRAMES: &[&str] = &[
    "__asan",
    "__sanitizer",
    "__interceptor",
    "malloc",
    "free",
    "operator new",
    "operator delete",
    "_start",
    "__libc",
    "__glibc",
    "std::rt::",
    "panic_unwind",
    "rust_panic",
    "std::panicking",
];

/// Normalise a function name for dedup (strip template args, addresses, Rust hash suffixes).
#[must_use] 
pub fn normalize_function_name(name: &str) -> String {
    // Strip Rust hash suffix like `::h1234abcd`
    let no_hash = name.rfind("::h").map_or(name, |pos| {
        let suffix = &name[pos + 3..];
        if suffix.len() == 16 && suffix.chars().all(|c| c.is_ascii_hexdigit()) {
            &name[..pos]
        } else {
            name
        }
    });
    // Truncate at `<` (C++ templates / Rust generics)
    let no_generic = no_hash
        .find('<')
        .map_or(no_hash, |i| &no_hash[..i]);
    // Strip leading/trailing whitespace and colons
    no_generic.trim_matches(':').trim().to_string()
}

// ── SignatureExtractor ────────────────────────────────────────────────────────

/// Extracts a `CrashSignature` from a `RawCrash`.
pub struct SignatureExtractor {
    /// How many frames from the top to include in the key.
    pub frame_depth: usize,
    /// Skip runtime/sanitizer frames when building the key.
    pub skip_runtime: bool,
}

impl SignatureExtractor {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            frame_depth: 5,
            skip_runtime: true,
        }
    }

    #[must_use] 
    pub const fn with_depth(mut self, d: usize) -> Self {
        self.frame_depth = d;
        self
    }

    pub fn extract(&self, crash: &RawCrash) -> CrashSignature {
        let crash_type = CrashType::parse(&crash.crash_type_str);
        let fault_bucket = crash.fault_address.map(FaultBucket::from_address);
        let stack_key: Vec<String> = crash
            .stack_frames
            .iter()
            .filter(|f| !self.skip_runtime || !f.is_runtime_frame())
            .take(self.frame_depth)
            .map(StackFrame::normalized_name)
            .collect();
        CrashSignature {
            stack_key,
            crash_type,
            is_write: crash.is_write,
            fault_bucket,
        }
    }

    /// Score the exploitability of a crash.
    #[must_use] 
    pub fn exploitability(&self, crash: &RawCrash) -> Exploitability {
        let crash_type = CrashType::parse(&crash.crash_type_str);
        let mut score = i32::from(crash_type.base_exploitability());
        if let Some(addr) = crash.fault_address {
            score += i32::from(FaultBucket::from_address(addr).modifier());
        }
        if crash.is_write {
            score += 1;
        }
        // Deeper stacks are slightly more exploitable (more context).
        let meaningful_frames = crash
            .stack_frames
            .iter()
            .filter(|f| !f.is_runtime_frame())
            .count();
        if meaningful_frames >= 5 {
            score += 1;
        }
        Exploitability::from_score(score.max(0))
    }
}

impl Default for SignatureExtractor {
    fn default() -> Self {
        Self::new()
    }
}

// ── DeduplicationBucket ───────────────────────────────────────────────────────

/// A bucket of crashes that share the same signature.
#[derive(Debug, Clone)]
pub struct DeduplicationBucket {
    pub signature: CrashSignature,
    pub bucket_id: u64,
    pub crashes: Vec<u64>, // crash IDs
    pub representative_id: u64,
    pub max_exploitability: Exploitability,
    pub first_seen: Instant,
    pub last_seen: Instant,
}

impl DeduplicationBucket {
    #[must_use] 
    pub fn new(sig: CrashSignature, first_crash_id: u64) -> Self {
        let bucket_id = sig.hash64();
        Self {
            bucket_id,
            representative_id: first_crash_id,
            crashes: vec![first_crash_id],
            signature: sig,
            max_exploitability: Exploitability::Unknown,
            first_seen: Instant::now(),
            last_seen: Instant::now(),
        }
    }

    pub fn add(&mut self, crash_id: u64, exploitability: Exploitability) {
        self.crashes.push(crash_id);
        if exploitability > self.max_exploitability {
            self.max_exploitability = exploitability;
        }
        self.last_seen = Instant::now();
    }

    #[must_use] 
    pub const fn count(&self) -> usize {
        self.crashes.len()
    }
}

// ── StackDistance ─────────────────────────────────────────────────────────────

/// Compute edit distance between two call-stack signatures (frame sequences).
#[must_use] 
pub fn stack_edit_distance(a: &[String], b: &[String]) -> usize {
    // Standard DP edit distance (flat 1-D allocation).
    let m = a.len();
    let n = b.len();
    let cols = n + 1;
    let mut dp = vec![0usize; (m + 1) * cols];
    for i in 0..=m {
        dp[i * cols] = i;
    }
    for (j, slot) in dp.iter_mut().take(n + 1).enumerate() {
        *slot = j;
    }
    for i in 1..=m {
        for j in 1..=n {
            dp[i * cols + j] = if a[i - 1] == b[j - 1] {
                dp[(i - 1) * cols + (j - 1)]
            } else {
                1 + dp[(i - 1) * cols + j]
                    .min(dp[i * cols + (j - 1)])
                    .min(dp[(i - 1) * cols + (j - 1)])
            };
        }
    }
    dp[m * cols + n]
}

/// Are two signatures "similar" (likely the same root cause)?
#[must_use] 
pub fn signatures_similar(a: &CrashSignature, b: &CrashSignature, max_distance: usize) -> bool {
    if a.crash_type != b.crash_type {
        return false;
    }
    let dist = stack_edit_distance(&a.stack_key, &b.stack_key);
    dist <= max_distance
}

// ── CrashDeduplicator ─────────────────────────────────────────────────────────

/// Deduplicates a stream of crashes by signature.
pub struct CrashDeduplicator {
    extractor: SignatureExtractor,
    crashes: HashMap<u64, RawCrash>,
    buckets: HashMap<u64, DeduplicationBucket>,
    next_id: u64,
    /// Maximum allowed stack edit distance for fuzzy bucketing.
    pub fuzzy_distance: usize,
}

impl CrashDeduplicator {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            extractor: SignatureExtractor::new(),
            crashes: HashMap::new(),
            buckets: HashMap::new(),
            next_id: 1,
            fuzzy_distance: 2,
        }
    }

    #[must_use] 
    pub const fn with_frame_depth(mut self, d: usize) -> Self {
        self.extractor = self.extractor.with_depth(d);
        self
    }

    #[must_use] 
    pub const fn with_fuzzy_distance(mut self, d: usize) -> Self {
        self.fuzzy_distance = d;
        self
    }

    /// Add a crash to the deduplicator. Returns `(crash_id, bucket_id, is_new_bucket)`.
    ///
    /// # Panics
    /// Documented for clippy.
    pub fn add(&mut self, crash: RawCrash) -> (u64, u64, bool) {
        let id = self.next_id;
        self.next_id += 1;
        let sig = self.extractor.extract(&crash);
        let exploitability = self.extractor.exploitability(&crash);
        let mut crash = crash;
        crash.id = id;
        let exact_key = sig.hash64();
        // Exact match.
        if let Some(bucket) = self.buckets.get_mut(&exact_key) {
            bucket.add(id, exploitability);
            let bucket_id = bucket.bucket_id;
            self.crashes.insert(id, crash);
            return (id, bucket_id, false);
        }
        // Fuzzy match.
        if self.fuzzy_distance > 0 {
            // A crash can be within `fuzzy_distance` of SEVERAL buckets at once,
            // because "similar" is a threshold relation and therefore not
            // transitive. Picking with `.find()` would take whichever match
            // `HashMap` iteration happened to reach first, and that order is
            // unspecified and re-seeded every process — so the same crash log
            // could bucket differently from one run to the next. Choosing the
            // smallest key makes the choice total and reproducible.
            let matching_key = self
                .buckets
                .iter()
                .filter(|(_, b)| signatures_similar(&b.signature, &sig, self.fuzzy_distance))
                .map(|(&k, _)| k)
                .min();
            if let Some(key) = matching_key {
                let bucket = self.buckets.get_mut(&key).unwrap();
                bucket.add(id, exploitability);
                let bucket_id = bucket.bucket_id;
                self.crashes.insert(id, crash);
                return (id, bucket_id, false);
            }
        }
        // New bucket.
        let mut bucket = DeduplicationBucket::new(sig, id);
        bucket.max_exploitability = exploitability;
        let bucket_id = bucket.bucket_id;
        self.buckets.insert(exact_key, bucket);
        self.crashes.insert(id, crash);
        (id, bucket_id, true)
    }

    /// Number of unique crash buckets.
    #[must_use] 
    pub fn unique_count(&self) -> usize {
        self.buckets.len()
    }

    /// Total crashes seen.
    #[must_use] 
    pub fn total_count(&self) -> usize {
        self.crashes.len()
    }

    /// Deduplication ratio (1 - unique/total).
    #[must_use] 
    pub fn dedup_ratio(&self) -> f64 {
        if self.crashes.is_empty() {
            return 0.0;
        }
        1.0 - (crate::cast::usize_to_f64(self.buckets.len()) / crate::cast::usize_to_f64(self.crashes.len()))
    }

    /// Get all buckets sorted by exploitability descending.
    #[must_use] 
    pub fn buckets_by_severity(&self) -> Vec<&DeduplicationBucket> {
        let mut v: Vec<&DeduplicationBucket> = self.buckets.values().collect();
        // Same reasoning as the fuzzy match in `add`: the input comes from a
        // `HashMap`, so buckets sharing an exploitability would be returned in
        // an order that changes between runs. `bucket_id` is the map key and is
        // therefore unique, which makes this a total order.
        v.sort_by(|a, b| {
            b.max_exploitability
                .cmp(&a.max_exploitability)
                .then_with(|| a.bucket_id.cmp(&b.bucket_id))
        });
        v
    }

    /// Get the representative crash for a bucket.
    #[must_use] 
    pub fn representative(&self, bucket_id: u64) -> Option<&RawCrash> {
        let bucket = self
            .buckets
            .values()
            .find(|b| b.bucket_id == bucket_id)?;
        self.crashes.get(&bucket.representative_id)
    }

    /// Get all crashes for a bucket.
    #[must_use] 
    pub fn bucket_crashes(&self, bucket_id: u64) -> Vec<&RawCrash> {
        let Some(bucket) = self
            .buckets
            .values()
            .find(|b| b.bucket_id == bucket_id) else { return Vec::new() };
        bucket
            .crashes
            .iter()
            .filter_map(|id| self.crashes.get(id))
            .collect()
    }

    /// Get all exploitable crashes (Probably + Exploitable).
    #[must_use] 
    pub fn exploitable_crashes(&self) -> Vec<&RawCrash> {
        self.crashes
            .values()
            .filter(|c| {
                let exp = self.extractor.exploitability(c);
                exp >= Exploitability::Probably
            })
            .collect()
    }

    #[must_use] 
    pub const fn buckets(&self) -> &HashMap<u64, DeduplicationBucket> {
        &self.buckets
    }

    #[must_use] 
    pub const fn crashes(&self) -> &HashMap<u64, RawCrash> {
        &self.crashes
    }

    /// Return a triage report as a structured list.
    #[must_use] 
    pub fn triage_report(&self) -> TriageReport {
        let buckets_sorted = self.buckets_by_severity();
        let total = self.total_count();
        let unique = self.unique_count();
        let exploitable: Vec<TriageBucketEntry> = buckets_sorted
            .iter()
            .map(|b| TriageBucketEntry {
                bucket_id: b.bucket_id,
                signature: b.signature.label(),
                crash_count: b.count(),
                exploitability: b.max_exploitability,
                representative_id: b.representative_id,
            })
            .collect();
        TriageReport {
            total_crashes: total,
            unique_buckets: unique,
            dedup_ratio: self.dedup_ratio(),
            buckets: exploitable,
        }
    }
}

impl Default for CrashDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

// ── TriageReport ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TriageBucketEntry {
    pub bucket_id: u64,
    pub signature: String,
    pub crash_count: usize,
    pub exploitability: Exploitability,
    pub representative_id: u64,
}

#[derive(Debug, Clone)]
pub struct TriageReport {
    pub total_crashes: usize,
    pub unique_buckets: usize,
    pub dedup_ratio: f64,
    pub buckets: Vec<TriageBucketEntry>,
}

impl TriageReport {
    #[must_use] 
    pub fn display(&self) -> String {
        // Pre-allocate: header ≈ 80 bytes + ~60 bytes per bucket.
        let mut out = String::with_capacity(128 + self.buckets.len() * 60);
        let _ = write!(
            out,
            "=== Crash Triage Report ===\n\
             Total:  {}\n\
             Unique: {}\n\
             Dedup:  {:.1}%\n\n",
            self.total_crashes,
            self.unique_buckets,
            self.dedup_ratio * 100.0
        );
        for (i, b) in self.buckets.iter().enumerate() {
            let _ = writeln!(
                out,
                "{:3}. [{:>19}] {:3}x  {}",
                i + 1,
                b.exploitability,
                b.crash_count,
                b.signature
            );
        }
        out
    }

    #[must_use] 
    pub fn most_exploitable(&self) -> Option<&TriageBucketEntry> {
        self.buckets.first()
    }

    #[must_use] 
    pub fn exploitable_count(&self) -> usize {
        self.buckets
            .iter()
            .filter(|b| b.exploitability >= Exploitability::Exploitable)
            .count()
    }
}

// ── CrashStatistics ───────────────────────────────────────────────────────────

/// Aggregate statistics over a crash set.
#[derive(Debug, Clone, Default)]
pub struct CrashStatistics {
    pub by_type: HashMap<String, usize>,
    pub by_exploitability: HashMap<String, usize>,
    pub total: usize,
}

impl CrashStatistics {
    #[must_use] 
    pub fn from_report(report: &TriageReport) -> Self {
        let mut stats = Self { total: report.total_crashes, ..Self::default() };
        for b in &report.buckets {
            let parts: Vec<&str> = b.signature.splitn(3, '/').collect();
            let crash_type = parts.first().unwrap_or(&"UNKNOWN").to_string();
            *stats.by_type.entry(crash_type).or_insert(0) += b.crash_count;
            let exp = b.exploitability.label().to_string();
            *stats.by_exploitability.entry(exp).or_insert(0) += b.crash_count;
        }
        stats
    }

    #[must_use] 
    pub fn most_common_type(&self) -> Option<(&str, usize)> {
        // Total order on ties — see `AsanStats::most_common`.
        self.by_type
            .iter()
            .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
            .map(|(k, &v)| (k.as_str(), v))
    }
}

// ── CrashParser ───────────────────────────────────────────────────────────────

/// Parse crashes from raw text output (ASAN / sanitizer / OS).
pub struct CrashParser;

impl CrashParser {
    /// Parse a raw ASAN-style text report into a `RawCrash`.
    #[must_use] 
    pub fn parse_asan(text: &str) -> Option<RawCrash> {
        let mut crash_type_str = String::from("UNKNOWN");
        let mut is_write = false;
        let mut fault_address: Option<u64> = None;
        let mut stack_frames: Vec<StackFrame> = Vec::new();
        for line in text.lines() {
            let trimmed = line.trim();
            // Detect bug type line: "=ERROR: AddressSanitizer: heap-buffer-overflow ..."
            // Shared with `AsanReportParser`: this used to scan for the first
            // token containing '-' / "overflow" / "free", which silently left
            // hyphen-free bug types (SEGV, FPE) as UNKNOWN.
            if let Some(t) = crate::asan_report_parser::asan_bug_type(trimmed) {
                crash_type_str = t;
            }
            // Detect READ/WRITE
            if trimmed.starts_with("READ") {
                is_write = false;
            } else if trimmed.starts_with("WRITE") {
                is_write = true;
            }
            // Fault address: "on address 0x..."
            if trimmed.contains("on address 0x")
                && let Some(start) = trimmed.find("0x") {
                    let hex_str: String = trimmed[start + 2..]
                        .chars()
                        .take_while(char::is_ascii_hexdigit)
                        .collect();
                    if let Ok(addr) = u64::from_str_radix(&hex_str, 16) {
                        fault_address = Some(addr);
                    }
                }
            // Stack frame: "#N 0xADDR in FUNCTION FILE:LINE"
            if let Some(rest) = trimmed.strip_prefix('#')
                && let Some(frame) = Self::parse_frame(rest) {
                    stack_frames.push(frame);
                }
        }
        Some(RawCrash {
            id: 0,
            crash_type_str,
            is_write,
            fault_address,
            stack_frames,
            input: Vec::new(),
            description: text.lines().next().unwrap_or("").to_string(),
            discovered_at: Instant::now(),
        })
    }

    fn parse_frame(s: &str) -> Option<StackFrame> {
        // Expected: "N 0xADDR in function_name [module] file.c:line"
        let mut parts = s.splitn(2, ' ');
        let index_str = parts.next()?;
        let index = index_str.trim().parse::<u32>().ok()?;
        let rest = parts.next().unwrap_or("").trim();
        // Address
        let (address, after_addr) = if let Some(stripped) = rest.strip_prefix("0x") {
            let hex: String = stripped.chars().take_while(char::is_ascii_hexdigit).collect();
            let addr = u64::from_str_radix(&hex, 16).ok()?;
            let skip = 2 + hex.len();
            (addr, rest[skip..].trim())
        } else {
            return None;
        };
        // Function: "in FNAME"
        let (function, after_func) = after_addr.strip_prefix("in ").map_or((None, after_addr), |rest2| {
            let fname: String = rest2.chars().take_while(|&c| c != ' ' && c != '\t').collect();
            (Some(fname.clone()), rest2[fname.len()..].trim())
        });
        // File: last token if it contains ':'
        let (file, line) = after_func
            .split_whitespace()
            .last()
            .and_then(|tok| {
                tok.rfind(':').map(|i| {
                    let f = tok[..i].to_string();
                    let l = tok[i + 1..].parse::<u32>().ok();
                    (Some(f), l)
                })
            })
            .unwrap_or((None, None));
        Some(StackFrame {
            index,
            address,
            function,
            module: None,
            offset: None,
            file,
            line,
        })
    }

    /// Parse multiple reports separated by blank lines.
    #[must_use] 
    pub fn parse_multiple(text: &str) -> Vec<RawCrash> {
        let mut results = Vec::new();
        let mut current = String::new();
        for line in text.lines() {
            if line.trim().is_empty() && current.contains("AddressSanitizer") {
                if let Some(crash) = Self::parse_asan(&current) {
                    results.push(crash);
                }
                current.clear();
            } else {
                current.push_str(line);
                current.push('\n');
            }
        }
        if !current.is_empty()
            && let Some(crash) = Self::parse_asan(&current) {
                results.push(crash);
            }
        results
    }
}

// ── SimilarityClusterer ───────────────────────────────────────────────────────

/// Cluster crashes by pairwise stack similarity into groups.
pub struct SimilarityClusterer {
    pub max_distance: usize,
}

impl SimilarityClusterer {
    #[must_use] 
    pub const fn new(max_distance: usize) -> Self {
        Self { max_distance }
    }

    /// Cluster a list of signatures into groups (indices into the input slice).
    #[must_use] 
    pub fn cluster(&self, sigs: &[CrashSignature]) -> Vec<Vec<usize>> {
        let n = sigs.len();
        let mut group = vec![usize::MAX; n];
        let mut next_group = 0usize;
        for i in 0..n {
            if group[i] != usize::MAX {
                continue;
            }
            group[i] = next_group;
            for j in (i + 1)..n {
                if group[j] == usize::MAX
                    && signatures_similar(&sigs[i], &sigs[j], self.max_distance)
                {
                    group[j] = next_group;
                }
            }
            next_group += 1;
        }
        let mut clusters: HashMap<usize, Vec<usize>> = HashMap::with_capacity(n);
        for (idx, &g) in group.iter().enumerate() {
            clusters.entry(g).or_default().push(idx);
        }
        let mut result: Vec<Vec<usize>> = clusters.into_values().collect();
        result.sort_by_key(|v| usize::MAX - v.len());
        result
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_crash(crash_type: &str, frames: &[&str]) -> RawCrash {
        RawCrash {
            id: 0,
            crash_type_str: crash_type.to_string(),
            is_write: true,
            fault_address: Some(0x0),
            stack_frames: frames
                .iter()
                .enumerate()
                .map(|(i, &f)| StackFrame {
                    index: crate::cast::usize_to_u32(i),
                    address: 0x1000 + i as u64,
                    function: Some(f.to_string()),
                    module: None,
                    offset: None,
                    file: None,
                    line: None,
                })
                .collect(),
            input: b"test".to_vec(),
            description: format!("{crash_type} crash"),
            discovered_at: Instant::now(),
        }
    }

    #[test]
    fn test_crash_type_from_str() {
        assert!(matches!(
            CrashType::parse("heap-buffer-overflow"),
            CrashType::HeapBufferOverflow
        ));
        assert!(matches!(
            CrashType::parse("heap-use-after-free"),
            CrashType::HeapUseAfterFree
        ));
    }

    #[test]
    fn test_dedup_same_crash() {
        let mut dedup = CrashDeduplicator::new();
        let c1 = make_crash("heap-buffer-overflow", &["foo", "bar", "baz"]);
        let c2 = make_crash("heap-buffer-overflow", &["foo", "bar", "baz"]);
        let (_, bid1, new1) = dedup.add(c1);
        let (_, bid2, new2) = dedup.add(c2);
        assert!(new1);
        assert!(!new2);
        assert_eq!(bid1, bid2);
        assert_eq!(dedup.unique_count(), 1);
    }

    #[test]
    fn test_dedup_different_crashes() {
        let mut dedup = CrashDeduplicator::new().with_fuzzy_distance(0);
        let c1 = make_crash("heap-buffer-overflow", &["alpha", "beta"]);
        let c2 = make_crash("heap-use-after-free", &["gamma", "delta"]);
        let (_, _, new1) = dedup.add(c1);
        let (_, _, new2) = dedup.add(c2);
        assert!(new1);
        assert!(new2);
        assert_eq!(dedup.unique_count(), 2);
    }

    #[test]
    fn test_exploitability_scoring() {
        let ext = SignatureExtractor::new();
        let uaf = make_crash("heap-use-after-free", &["foo"]);
        let null = make_crash("null dereference", &["bar"]);
        assert!(ext.exploitability(&uaf) > ext.exploitability(&null));
    }

    #[test]
    fn test_normalize_function_name() {
        let name = "my_func::hdeadbeef12345678";
        let norm = normalize_function_name(name);
        assert_eq!(norm, "my_func");
    }

    #[test]
    fn test_stack_edit_distance() {
        let a: Vec<String> = vec!["foo".into(), "bar".into(), "baz".into()];
        let b: Vec<String> = vec!["foo".into(), "bar".into(), "qux".into()];
        assert_eq!(stack_edit_distance(&a, &b), 1);
        assert_eq!(stack_edit_distance(&a, &a), 0);
    }

    #[test]
    fn test_similarity_clusterer() {
        let sigs = vec![
            CrashSignature {
                stack_key: vec!["foo".into(), "bar".into()],
                crash_type: CrashType::HeapBufferOverflow,
                is_write: true,
                fault_bucket: None,
            },
            CrashSignature {
                stack_key: vec!["foo".into(), "baz".into()],
                crash_type: CrashType::HeapBufferOverflow,
                is_write: true,
                fault_bucket: None,
            },
            CrashSignature {
                stack_key: vec!["qux".into(), "quux".into()],
                crash_type: CrashType::NullDereference,
                is_write: false,
                fault_bucket: None,
            },
        ];
        let clusterer = SimilarityClusterer::new(2);
        let clusters = clusterer.cluster(&sigs);
        // First two should be in the same cluster (edit dist 1), third separate.
        assert_eq!(clusters.len(), 2);
    }

    #[test]
    fn test_triage_report_display() {
        let mut dedup = CrashDeduplicator::new();
        for i in 0..5u64 {
            dedup.add(make_crash(
                "heap-buffer-overflow",
                &[&format!("func{i}")],
            ));
        }
        let report = dedup.triage_report();
        let text = report.display();
        assert!(text.contains("Crash Triage Report"));
    }

    #[test]
    fn test_fault_bucket() {
        assert_eq!(FaultBucket::from_address(0), FaultBucket::NearNull);
        assert_eq!(FaultBucket::from_address(0x5000), FaultBucket::SlightlyNull);
        assert_eq!(
            FaultBucket::from_address(0x7fff_ffff_f500),
            FaultBucket::KernelBoundary
        );
    }
}
