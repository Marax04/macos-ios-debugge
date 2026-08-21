//! String annotation: attaches rich metadata to recovered strings and writes
//! comments back to a (mock) binary view.
//!
//! Provides:
//! * [`StringCategory`] — URL, path, API, credential, C2, generic, etc.
//! * [`AnnotatedString`] — a recovered string with address, decoded value,
//!   algorithm used, confidence, and category.
//! * [`StringAnnotator`] — classifies and enriches recovered strings.
//! * [`AnnotationWriter`] — commits annotations as comments to a [`BinaryView`].

use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// StringCategory
// ─────────────────────────────────────────────────────────────────────────────

/// Semantic category of a recovered string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringCategory {
    /// A URL (`http://`, `https://`, `ftp://`, etc.).
    Url,
    /// A file system path (`C:\`, `/etc/`, `\Device\`, etc.).
    Path,
    /// An API name (e.g. `CreateFileW`, `VirtualAlloc`).
    Api,
    /// A potential credential (password, token, key).
    Credential,
    /// A C2 / network indicator (IP address, domain, port).
    C2,
    /// A registry key or value path.
    Registry,
    /// A mutex or event name.
    Mutex,
    /// A Windows service / process name.
    ServiceProcess,
    /// A command-line string (starts with common shell / tool names).
    CommandLine,
    /// Generic printable string.
    Generic,
    /// Unknown / unclassified.
    Unknown,
}

impl StringCategory {
    /// Short label string.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Url => "url",
            Self::Path => "path",
            Self::Api => "api",
            Self::Credential => "credential",
            Self::C2 => "c2",
            Self::Registry => "registry",
            Self::Mutex => "mutex",
            Self::ServiceProcess => "service/process",
            Self::CommandLine => "cmdline",
            Self::Generic => "generic",
            Self::Unknown => "unknown",
        }
    }

    /// Return `true` if the category is security-sensitive.
    #[must_use]
    pub const fn is_sensitive(self) -> bool {
        matches!(self, Self::Credential | Self::C2 | Self::CommandLine)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnnotatedString
// ─────────────────────────────────────────────────────────────────────────────

/// A recovered string enriched with metadata.
#[derive(Debug, Clone)]
pub struct AnnotatedString {
    /// Virtual address where the encrypted / encoded bytes live.
    pub address: u64,
    /// The decoded string value.
    pub decoded: String,
    /// The algorithm used to recover this string.
    pub algorithm: String,
    /// Confidence in [0, 100].
    pub confidence: u8,
    /// Semantic category.
    pub category: StringCategory,
    /// Length of the raw (encoded) bytes.
    pub raw_len: usize,
    /// Optional comment generated for the binary view.
    pub comment: Option<String>,
    /// Whether this string has already been written to the binary view.
    pub is_committed: bool,
}

impl AnnotatedString {
    /// Create a new annotated string.
    #[must_use]
    pub fn new(
        address: u64,
        decoded: impl Into<String>,
        algorithm: impl Into<String>,
        confidence: u8,
        raw_len: usize,
    ) -> Self {
        let decoded = decoded.into();
        let category = StringCategory::Unknown;
        Self {
            address,
            decoded,
            algorithm: algorithm.into(),
            confidence: confidence.min(100),
            category,
            raw_len,
            comment: None,
            is_committed: false,
        }
    }

    /// Set the category and return `self`.
    #[must_use]
    pub const fn with_category(mut self, cat: StringCategory) -> Self {
        self.category = cat;
        self
    }

    /// Build a default comment string from this annotation.
    #[must_use]
    pub fn default_comment(&self) -> String {
        format!(
            "[rustre] {} ({}, conf={}, algo={})",
            self.decoded,
            self.category.label(),
            self.confidence,
            self.algorithm,
        )
    }

    /// Return `true` if the string is flagged as high-value (high confidence and sensitive).
    #[must_use]
    pub const fn is_high_value(&self) -> bool {
        self.confidence >= 80 && self.category.is_sensitive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringSearchIndex — fast full-text search over annotated strings
// ─────────────────────────────────────────────────────────────────────────────

/// A lightweight inverted index over decoded string values.
#[derive(Debug, Clone, Default)]
pub struct StringSearchIndex {
    /// All indexed strings.
    pub strings: Vec<AnnotatedString>,
}

impl StringSearchIndex {
    /// Create an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a string to the index.
    pub fn insert(&mut self, s: AnnotatedString) {
        self.strings.push(s);
    }

    /// Add all strings from a vector.
    pub fn insert_all(&mut self, strings: Vec<AnnotatedString>) {
        self.strings.extend(strings);
    }

    /// Search for strings whose decoded value contains `query` (case-insensitive).
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&AnnotatedString> {
        let q = query.to_lowercase();
        self.strings
            .iter()
            .filter(|s| s.decoded.to_lowercase().contains(&q))
            .collect()
    }

    /// Search for strings in a given category.
    #[must_use]
    pub fn by_category(&self, cat: StringCategory) -> Vec<&AnnotatedString> {
        self.strings.iter().filter(|s| s.category == cat).collect()
    }

    /// Return strings at addresses in `[start, end)`.
    #[must_use]
    pub fn in_address_range(&self, start: u64, end: u64) -> Vec<&AnnotatedString> {
        self.strings
            .iter()
            .filter(|s| s.address >= start && s.address < end)
            .collect()
    }

    /// Total number of indexed strings.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.strings.len()
    }

    /// Return `true` when empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringDeduplicator — removes duplicate / near-duplicate strings
// ─────────────────────────────────────────────────────────────────────────────

/// Deduplication policy for annotated strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeduplicationPolicy {
    /// Keep only exact duplicate removal.
    Exact,
    /// Also remove strings that differ only in case.
    CaseInsensitive,
    /// Remove strings that are substrings of another string in the set.
    SubstringInclusion,
}

/// Deduplicates a list of annotated strings according to a policy.
#[derive(Debug, Clone, Default)]
pub struct StringDeduplicator {
    /// The deduplication policy (default: Exact).
    pub policy: Option<DeduplicationPolicy>,
}

impl StringDeduplicator {
    /// Create a deduplicator with exact policy.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            policy: Some(DeduplicationPolicy::Exact),
        }
    }

    /// Set the policy.
    #[must_use]
    pub const fn with_policy(mut self, p: DeduplicationPolicy) -> Self {
        self.policy = Some(p);
        self
    }

    /// Deduplicate `strings` and return the result.
    ///
    /// When duplicates exist, the one with the highest confidence is retained.
    #[must_use]
    pub fn dedup(&self, strings: Vec<AnnotatedString>) -> Vec<AnnotatedString> {
        let policy = self.policy.unwrap_or(DeduplicationPolicy::Exact);
        let mut seen: Vec<AnnotatedString> = Vec::new();

        'outer: for s in strings {
            for existing in &mut seen {
                let is_dup = match policy {
                    DeduplicationPolicy::Exact => existing.decoded == s.decoded,
                    DeduplicationPolicy::CaseInsensitive => {
                        existing.decoded.to_lowercase() == s.decoded.to_lowercase()
                    }
                    DeduplicationPolicy::SubstringInclusion => {
                        existing.decoded.contains(&s.decoded)
                            || s.decoded.contains(&existing.decoded)
                    }
                };
                if is_dup {
                    if s.confidence > existing.confidence {
                        *existing = s;
                    }
                    continue 'outer;
                }
            }
            seen.push(s);
        }
        seen
    }

    /// Count how many duplicates would be removed.
    #[must_use]
    pub fn count_duplicates(&self, strings: &[AnnotatedString]) -> usize {
        let deduped = self.dedup(strings.to_vec());
        strings.len().saturating_sub(deduped.len())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringStatistics — aggregate statistics over a collection of annotated strings
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate statistics computed from a batch of annotated strings.
#[derive(Debug, Clone, Default)]
pub struct StringStatistics {
    /// Total string count.
    pub total: usize,
    /// Number of unique categories observed.
    pub unique_categories: usize,
    /// Average confidence.
    pub avg_confidence: f32,
    /// Number of strings above 80% confidence.
    pub high_confidence_count: usize,
    /// Category frequency map: `label → count`.
    pub category_counts: std::collections::HashMap<String, usize>,
    /// Number of security-sensitive strings.
    pub sensitive_count: usize,
}

impl StringStatistics {
    /// Compute statistics from `strings`.
    #[must_use]
    pub fn from_strings(strings: &[AnnotatedString]) -> Self {
        let total = strings.len();
        if total == 0 {
            return Self::default();
        }

        let avg_confidence =
            strings.iter().map(|s| f32::from(s.confidence)).sum::<f32>() / total as f32;
        let high_confidence_count = strings.iter().filter(|s| s.confidence >= 80).count();
        let sensitive_count = strings.iter().filter(|s| s.category.is_sensitive()).count();

        let mut category_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for s in strings {
            *category_counts
                .entry(s.category.label().to_owned())
                .or_insert(0) += 1;
        }
        let unique_categories = category_counts.len();

        Self {
            total,
            unique_categories,
            avg_confidence,
            high_confidence_count,
            category_counts,
            sensitive_count,
        }
    }

    /// Return a one-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "total={} avg_conf={:.1} high_conf={} sensitive={} categories={}",
            self.total,
            self.avg_confidence,
            self.high_confidence_count,
            self.sensitive_count,
            self.unique_categories,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringAnnotator
// ─────────────────────────────────────────────────────────────────────────────

/// Classifies a list of recovered strings into [`StringCategory`] values and
/// enriches each with a comment.
#[derive(Debug, Clone, Default)]
pub struct StringAnnotator {
    /// Minimum confidence to classify a string (default 30).
    pub min_confidence: u8,
    /// Custom category overrides: exact `decoded` string → category.
    pub overrides: HashMap<String, StringCategory>,
}

impl StringAnnotator {
    /// Create a new annotator with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            min_confidence: 30,
            overrides: HashMap::new(),
        }
    }

    /// Set the minimum confidence threshold.
    #[must_use]
    pub const fn with_min_confidence(mut self, c: u8) -> Self {
        self.min_confidence = c;
        self
    }

    /// Register a category override for an exact string value.
    pub fn add_override(&mut self, s: impl Into<String>, cat: StringCategory) {
        self.overrides.insert(s.into(), cat);
    }

    /// Classify a single string value and return the best-matching category.
    #[must_use]
    pub fn classify(&self, s: &str) -> StringCategory {
        // Check overrides first.
        if let Some(&cat) = self.overrides.get(s) {
            return cat;
        }

        let lower = s.to_lowercase();

        // URL detection.
        if lower.starts_with("http://")
            || lower.starts_with("https://")
            || lower.starts_with("ftp://")
            || lower.starts_with("ftps://")
        {
            return StringCategory::Url;
        }

        // Path detection (Windows and Unix).
        if lower.starts_with("c:\\")
            || lower.starts_with("c:/")
            || lower.starts_with("\\\\")
            || lower.starts_with("/etc/")
            || lower.starts_with("/tmp/")
            || lower.starts_with("/var/")
            || lower.starts_with("\\device\\")
            || lower.starts_with("\\dosdevices\\")
            || lower.starts_with("%appdata%")
            || lower.starts_with("%temp%")
        {
            return StringCategory::Path;
        }

        // Registry key detection.
        if lower.starts_with("hklm\\")
            || lower.starts_with("hkcu\\")
            || lower.starts_with("hkcr\\")
            || lower.starts_with("software\\")
            || lower.starts_with("system\\")
        {
            return StringCategory::Registry;
        }

        // C2 / network indicator detection.
        if is_ip_address(s) || looks_like_domain(s) {
            return StringCategory::C2;
        }

        // API name detection (common Win32 / Nt suffixes) — check before credential.
        if looks_like_api(s) {
            return StringCategory::Api;
        }

        // Credential heuristic.
        if lower.contains("password")
            || lower.contains("passwd")
            || lower.contains("secret")
            || lower.contains("apikey")
            || lower.contains("token")
            || (s.len() >= 16 && looks_like_base64(s))
        {
            return StringCategory::Credential;
        }

        // Mutex / event names.
        if lower.contains("mutex")
            || lower.contains("event")
            || lower.contains("semaphore")
            || lower.starts_with("global\\")
            || lower.starts_with("local\\")
        {
            return StringCategory::Mutex;
        }

        // Command-line detection.
        if lower.starts_with("cmd ")
            || lower.starts_with("powershell")
            || lower.starts_with("wscript")
            || lower.starts_with("cscript")
            || lower.starts_with("mshta")
            || lower.starts_with("regsvr32")
        {
            return StringCategory::CommandLine;
        }

        // Service / process name heuristic.
        if std::path::Path::new(&lower).extension().is_some_and(|e| e.eq_ignore_ascii_case("exe")) || std::path::Path::new(&lower).extension().is_some_and(|e| e.eq_ignore_ascii_case("dll")) || std::path::Path::new(&lower).extension().is_some_and(|e| e.eq_ignore_ascii_case("sys")) {
            return StringCategory::ServiceProcess;
        }

        // Printable generic.
        if s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
            return StringCategory::Generic;
        }

        StringCategory::Unknown
    }

    /// Annotate a batch of strings, classifying each and generating comments.
    ///
    /// Strings with confidence below `min_confidence` are still annotated but
    /// receive category `Unknown`.
    #[must_use]
    pub fn annotate_all(&self, strings: Vec<AnnotatedString>) -> Vec<AnnotatedString> {
        strings
            .into_iter()
            .map(|mut s| {
                if s.confidence >= self.min_confidence {
                    s.category = self.classify(&s.decoded);
                }
                let comment = s.default_comment();
                s.comment = Some(comment);
                s
            })
            .collect()
    }

    /// Return only high-value strings from `strings`.
    #[must_use]
    pub fn high_value<'a>(&self, strings: &'a [AnnotatedString]) -> Vec<&'a AnnotatedString> {
        strings.iter().filter(|s| s.is_high_value()).collect()
    }
}

// ── Classification helpers ──────────────────────────────────────────────────

fn is_ip_address(s: &str) -> bool {
    // IPv4: d.d.d.d
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() == 4 {
        return parts.iter().all(|p| p.parse::<u8>().is_ok());
    }
    false
}

fn looks_like_domain(s: &str) -> bool {
    let tlds = [
        ".com", ".net", ".org", ".io", ".co", ".cc", ".ru", ".xyz", ".top", ".biz", ".info",
        ".onion",
    ];
    let lower = s.to_lowercase();
    tlds.iter().any(|t| lower.ends_with(t)) && s.contains('.') && !s.contains(' ') && s.len() >= 5
}

fn looks_like_base64(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
}

fn looks_like_api(s: &str) -> bool {
    // Common Win32 / NT API suffixes / prefixes.
    let api_suffixes = ["A", "W", "Ex", "ExW", "ExA"];
    let api_prefixes = [
        "Create", "Open", "Close", "Read", "Write", "Virtual", "Heap", "Map", "Unmap", "Load",
        "Free", "Get", "Set", "Query", "Nt", "Zw", "Rtl", "Ldr",
    ];
    // Must be a reasonable "identifier" length.
    if s.len() < 4 || s.len() > 64 {
        return false;
    }
    // Must start with uppercase.
    if !s.chars().next().is_some_and(char::is_uppercase) {
        return false;
    }
    let ends_with_suffix = api_suffixes.iter().any(|&suf| s.ends_with(suf));
    let starts_with_prefix = api_prefixes.iter().any(|&pre| s.starts_with(pre));
    // Must not contain spaces or special chars.
    let is_identifier = s.chars().all(|c| c.is_alphanumeric() || c == '_');
    is_identifier && (ends_with_suffix || starts_with_prefix)
}

// ─────────────────────────────────────────────────────────────────────────────
// StringConfidenceCalibrator — adjusts confidence scores based on heuristics
// ─────────────────────────────────────────────────────────────────────────────

/// Applies post-processing rules to adjust raw confidence scores.
///
/// Rules applied in order:
/// 1. High-entropy strings (looks like random bytes) → reduce confidence.
/// 2. Very short strings (< 4 chars) → reduce confidence.
/// 3. Known-bad words (e.g. "password", "secret") in credential category → boost.
/// 4. IPv4 addresses → boost C2 confidence.
#[derive(Debug, Clone, Default)]
pub struct StringConfidenceCalibrator;

impl StringConfidenceCalibrator {
    /// Create a new calibrator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Calibrate `confidence` for `s` and return the adjusted value.
    #[must_use]
    pub fn calibrate(&self, s: &AnnotatedString) -> u8 {
        let mut c = i16::from(s.confidence);

        // Very short strings are noisy.
        if s.decoded.len() < 4 {
            c -= 10;
        }
        // Extremely long strings (> 256 chars) may be false positives.
        if s.decoded.len() > 256 {
            c -= 5;
        }

        // Credential boost for known sensitive words.
        if s.category == StringCategory::Credential {
            let lower = s.decoded.to_lowercase();
            if lower.contains("password") || lower.contains("secret") || lower.contains("token") {
                c += 10;
            }
        }

        // C2 boost for valid IPv4.
        if s.category == StringCategory::C2 && is_ip_address(&s.decoded) {
            c += 10;
        }

        c.clamp(0, 100) as u8
    }

    /// Apply calibration to all strings in `batch`.
    pub fn calibrate_batch(&self, batch: &mut [AnnotatedString]) {
        for s in batch.iter_mut() {
            s.confidence = self.calibrate(s);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringExportFormat — serialisation helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A compact, serialisable representation of an annotated string.
#[derive(Debug, Clone)]
pub struct StringExportRecord {
    /// Virtual address (hex string).
    pub address: String,
    /// The decoded string value.
    pub value: String,
    /// Category label.
    pub category: String,
    /// Algorithm used.
    pub algorithm: String,
    /// Confidence (0–100).
    pub confidence: u8,
}

impl StringExportRecord {
    /// Convert an [`AnnotatedString`] to an export record.
    #[must_use]
    pub fn from_annotated(s: &AnnotatedString) -> Self {
        Self {
            address: format!("{:#x}", s.address),
            value: s.decoded.clone(),
            category: s.category.label().to_owned(),
            algorithm: s.algorithm.clone(),
            confidence: s.confidence,
        }
    }

    /// Format as a TSV line: `address\tvalue\tcategory\talgorithm\tconfidence`.
    #[must_use]
    pub fn to_tsv(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}",
            self.address,
            Self::sanitise_field(&self.value, '\t'),
            self.category,
            self.algorithm,
            self.confidence
        )
    }

    /// Neutralise the characters that would break a delimited record.
    ///
    /// `value` is a string decoded *out of a binary*, so tabs, commas and line
    /// breaks are not hypothetical — the decoder emits whatever the target
    /// contained. `to_csv` already substituted its own delimiter; its twin
    /// `to_tsv` did not, which is what gave this away. Neither handled CR/LF,
    /// which splits one record across two lines whatever the delimiter is, and
    /// both are documented as producing a single line.
    ///
    /// The comma substitution is kept exactly as `to_csv` already did it, so
    /// existing output is unchanged for every value that was already safe.
    fn sanitise_field(value: &str, delimiter: char) -> String {
        value.replace(delimiter, ";").replace(['\r', '\n'], " ")
    }

    /// Format as a CSV line.
    #[must_use]
    pub fn to_csv(&self) -> String {
        format!(
            "{},{},{},{},{}",
            self.address,
            Self::sanitise_field(&self.value, ','),
            self.category,
            self.algorithm,
            self.confidence
        )
    }
}

/// Export a list of annotated strings to TSV format.
#[must_use]
pub fn export_tsv(strings: &[AnnotatedString]) -> String {
    let header = "address\tvalue\tcategory\talgorithm\tconfidence";
    let rows: Vec<String> = strings
        .iter()
        .map(|s| StringExportRecord::from_annotated(s).to_tsv())
        .collect();
    std::iter::once(header.to_owned())
        .chain(rows)
        .collect::<Vec<_>>()
        .join("\n")
}

// ─────────────────────────────────────────────────────────────────────────────
// StringHeatmap — frequency-based string importance scoring
// ─────────────────────────────────────────────────────────────────────────────

/// Assigns an importance ("heat") score to each string based on category,
/// confidence, and frequency of occurrence.
#[derive(Debug, Clone, Default)]
pub struct StringHeatmap {
    /// Category weights: higher weight = more important.
    pub category_weights: HashMap<&'static str, f32>,
}

impl StringHeatmap {
    /// Create a heatmap with default category weights.
    #[must_use]
    pub fn new() -> Self {
        let mut w = HashMap::new();
        w.insert("c2", 1.0_f32);
        w.insert("credential", 0.95);
        w.insert("cmdline", 0.90);
        w.insert("url", 0.80);
        w.insert("api", 0.70);
        w.insert("registry", 0.65);
        w.insert("path", 0.60);
        w.insert("service/process", 0.55);
        w.insert("mutex", 0.50);
        w.insert("generic", 0.30);
        w.insert("unknown", 0.10);
        Self {
            category_weights: w,
        }
    }

    /// Compute the heat score for `s` in [0.0, 1.0].
    #[must_use]
    pub fn heat(&self, s: &AnnotatedString) -> f32 {
        let cat_weight = self
            .category_weights
            .get(s.category.label())
            .copied()
            .unwrap_or(0.1);
        (cat_weight * (f32::from(s.confidence) / 100.0)).clamp(0.0, 1.0)
    }

    /// Sort `strings` by heat score descending.
    #[must_use]
    pub fn sorted_by_heat<'a>(
        &self,
        strings: &'a [AnnotatedString],
    ) -> Vec<(&'a AnnotatedString, f32)> {
        let mut scored: Vec<(&AnnotatedString, f32)> =
            strings.iter().map(|s| (s, self.heat(s))).collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored
    }

    /// Return strings with heat above `threshold`.
    #[must_use]
    pub fn hot_strings<'a>(
        &self,
        strings: &'a [AnnotatedString],
        threshold: f32,
    ) -> Vec<&'a AnnotatedString> {
        strings
            .iter()
            .filter(|s| self.heat(s) >= threshold)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringDatabase — deduplication and aggregation of annotated strings
// ─────────────────────────────────────────────────────────────────────────────

/// A deduplicated database of annotated strings indexed by decoded value.
#[derive(Debug, Clone, Default)]
pub struct StringDatabase {
    /// All strings, deduplicated by decoded value (keeps highest confidence).
    pub entries: std::collections::HashMap<String, AnnotatedString>,
}

impl StringDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a string, keeping the higher-confidence entry when a duplicate exists.
    pub fn insert(&mut self, s: AnnotatedString) {
        let key = s.decoded.clone();
        let entry = self.entries.entry(key).or_insert_with(|| s.clone());
        if s.confidence > entry.confidence {
            *entry = s;
        }
    }

    /// Insert all strings from a vector.
    pub fn insert_all(&mut self, strings: Vec<AnnotatedString>) {
        for s in strings {
            self.insert(s);
        }
    }

    /// Return all entries sorted by confidence descending.
    #[must_use]
    pub fn sorted_by_confidence(&self) -> Vec<&AnnotatedString> {
        let mut v: Vec<&AnnotatedString> = self.entries.values().collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.confidence));
        v
    }

    /// Return all entries in a given category.
    #[must_use]
    pub fn by_category(&self, cat: StringCategory) -> Vec<&AnnotatedString> {
        self.entries
            .values()
            .filter(|s| s.category == cat)
            .collect()
    }

    /// Number of unique strings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` when empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return all strings above a confidence threshold.
    #[must_use]
    pub fn above_confidence(&self, threshold: u8) -> Vec<&AnnotatedString> {
        self.entries
            .values()
            .filter(|s| s.confidence >= threshold)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BinaryView (mock for annotation writing)
// ─────────────────────────────────────────────────────────────────────────────

/// A lightweight mock of a Binary Ninja / IDA binary view used to test
/// comment-writing without a real RE framework.
#[derive(Debug, Clone, Default)]
pub struct BinaryView {
    /// Comments indexed by address.
    pub comments: HashMap<u64, String>,
}

impl BinaryView {
    /// Create a new empty view.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a comment at `address`.
    pub fn set_comment(&mut self, address: u64, comment: impl Into<String>) {
        self.comments.insert(address, comment.into());
    }

    /// Retrieve the comment at `address`.
    #[must_use]
    pub fn get_comment(&self, address: u64) -> Option<&str> {
        self.comments.get(&address).map(String::as_str)
    }

    /// Number of comments stored.
    #[must_use]
    pub fn comment_count(&self) -> usize {
        self.comments.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnnotationWriter
// ─────────────────────────────────────────────────────────────────────────────

/// Writes string annotations as comments to a [`BinaryView`].
#[derive(Debug, Clone, Default)]
pub struct AnnotationWriter {
    /// Prefix added to every comment (default `"[rustre]"`).
    pub prefix: String,
    /// Only commit strings with confidence ≥ this value (default 50).
    pub min_confidence: u8,
    /// Overwrite existing comments (default `false`).
    pub overwrite: bool,
}

impl AnnotationWriter {
    /// Create a new writer with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            prefix: "[rustre]".into(),
            min_confidence: 50,
            overwrite: false,
        }
    }

    /// Set the comment prefix.
    #[must_use]
    pub fn with_prefix(mut self, p: impl Into<String>) -> Self {
        self.prefix = p.into();
        self
    }

    /// Set the minimum confidence threshold.
    #[must_use]
    pub const fn with_min_confidence(mut self, c: u8) -> Self {
        self.min_confidence = c;
        self
    }

    /// Allow overwriting existing comments.
    #[must_use]
    pub const fn with_overwrite(mut self, o: bool) -> Self {
        self.overwrite = o;
        self
    }

    /// Write all annotations in `strings` to `view`.
    ///
    /// Returns the number of comments actually written.
    pub fn write_all(&self, strings: &mut [AnnotatedString], view: &mut BinaryView) -> usize {
        let mut written = 0;
        for s in strings.iter_mut() {
            if s.confidence < self.min_confidence {
                continue;
            }
            if !self.overwrite && view.get_comment(s.address).is_some() {
                continue;
            }
            let comment = format!(
                "{} {} ({} conf={} algo={})",
                self.prefix,
                s.decoded,
                s.category.label(),
                s.confidence,
                s.algorithm
            );
            view.set_comment(s.address, comment.clone());
            s.comment = Some(comment);
            s.is_committed = true;
            written += 1;
        }
        written
    }

    /// Write a single annotation.
    pub fn write_one(&self, s: &mut AnnotatedString, view: &mut BinaryView) -> bool {
        if s.confidence < self.min_confidence {
            return false;
        }
        if !self.overwrite && view.get_comment(s.address).is_some() {
            return false;
        }
        let comment = s.comment.clone().unwrap_or_else(|| s.default_comment());
        view.set_comment(s.address, comment);
        s.is_committed = true;
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── StringCategory ────────────────────────────────────────────────────────

    /// A decoded string carries whatever bytes the binary held, delimiters
    /// included. Both exporters promise one line per record, so neither may
    /// let the value break the row — `to_tsv` used to pass tabs straight
    /// through, and both passed newlines.
    #[test]
    fn test_delimited_export_survives_delimiters_in_the_value() {
        let s = AnnotatedString::new(0x1000, "a,b\tc\nd\re", "xor", 90, 9);
        let rec = StringExportRecord::from_annotated(&s);

        let csv = rec.to_csv();
        assert_eq!(csv.lines().count(), 1, "CSV record spans several lines: {csv:?}");
        assert_eq!(csv.split(',').count(), 5, "wrong CSV field count: {csv:?}");

        let tsv = rec.to_tsv();
        assert_eq!(tsv.lines().count(), 1, "TSV record spans several lines: {tsv:?}");
        assert_eq!(tsv.split('\t').count(), 5, "wrong TSV field count: {tsv:?}");
    }

    #[test]
    fn test_category_labels() {
        assert_eq!(StringCategory::Url.label(), "url");
        assert_eq!(StringCategory::Credential.label(), "credential");
        assert_eq!(StringCategory::C2.label(), "c2");
    }

    #[test]
    fn test_category_is_sensitive() {
        assert!(StringCategory::Credential.is_sensitive());
        assert!(StringCategory::C2.is_sensitive());
        assert!(StringCategory::CommandLine.is_sensitive());
        assert!(!StringCategory::Generic.is_sensitive());
        assert!(!StringCategory::Api.is_sensitive());
    }

    // ── AnnotatedString ───────────────────────────────────────────────────────

    #[test]
    fn test_annotated_string_new() {
        let s = AnnotatedString::new(0x1000, "hello", "xor", 90, 5);
        assert_eq!(s.address, 0x1000);
        assert_eq!(s.decoded, "hello");
        assert_eq!(s.confidence, 90);
        assert_eq!(s.category, StringCategory::Unknown);
        assert!(!s.is_committed);
    }

    #[test]
    fn test_annotated_string_confidence_clamped() {
        let s = AnnotatedString::new(0, "", "none", 200, 0);
        assert_eq!(s.confidence, 100);
    }

    #[test]
    fn test_annotated_string_with_category() {
        let s = AnnotatedString::new(0, "http://evil.com", "xor", 90, 15)
            .with_category(StringCategory::Url);
        assert_eq!(s.category, StringCategory::Url);
    }

    #[test]
    fn test_annotated_string_default_comment() {
        let s = AnnotatedString::new(0x100, "test", "rc4", 80, 4)
            .with_category(StringCategory::Generic);
        let c = s.default_comment();
        assert!(c.contains("test"));
        assert!(c.contains("generic"));
        assert!(c.contains("80"));
    }

    #[test]
    fn test_annotated_string_is_high_value() {
        let s = AnnotatedString::new(0, "secret_pass", "xor", 90, 11)
            .with_category(StringCategory::Credential);
        assert!(s.is_high_value());
    }

    #[test]
    fn test_annotated_string_not_high_value_low_conf() {
        let s = AnnotatedString::new(0, "secret_pass", "xor", 50, 11)
            .with_category(StringCategory::Credential);
        assert!(!s.is_high_value());
    }

    // ── StringAnnotator ───────────────────────────────────────────────────────

    #[test]
    fn test_classify_url() {
        let a = StringAnnotator::new();
        assert_eq!(a.classify("https://evil.com/c2"), StringCategory::Url);
        assert_eq!(a.classify("http://127.0.0.1:8080"), StringCategory::Url);
    }

    #[test]
    fn test_classify_path_windows() {
        let a = StringAnnotator::new();
        assert_eq!(
            a.classify("C:\\Windows\\System32\\calc.exe"),
            StringCategory::Path
        );
    }

    #[test]
    fn test_classify_path_unix() {
        let a = StringAnnotator::new();
        assert_eq!(a.classify("/etc/passwd"), StringCategory::Path);
    }

    #[test]
    fn test_classify_ip() {
        let a = StringAnnotator::new();
        assert_eq!(a.classify("192.168.1.1"), StringCategory::C2);
    }

    #[test]
    fn test_classify_domain() {
        let a = StringAnnotator::new();
        assert_eq!(a.classify("malware.biz"), StringCategory::C2);
    }

    #[test]
    fn test_classify_api() {
        let a = StringAnnotator::new();
        assert_eq!(a.classify("CreateFileW"), StringCategory::Api);
        assert_eq!(a.classify("VirtualAllocEx"), StringCategory::Api);
        assert_eq!(a.classify("NtQuerySystemInformation"), StringCategory::Api);
    }

    #[test]
    fn test_classify_credential() {
        let a = StringAnnotator::new();
        assert_eq!(a.classify("my_password_123"), StringCategory::Credential);
        assert_eq!(a.classify("secret"), StringCategory::Credential);
    }

    #[test]
    fn test_classify_registry() {
        let a = StringAnnotator::new();
        assert_eq!(
            a.classify("HKLM\\Software\\Microsoft"),
            StringCategory::Registry
        );
    }

    #[test]
    fn test_classify_exe() {
        let a = StringAnnotator::new();
        assert_eq!(a.classify("svchost.exe"), StringCategory::ServiceProcess);
    }

    #[test]
    fn test_classify_cmdline() {
        let a = StringAnnotator::new();
        assert_eq!(a.classify("cmd /c whoami"), StringCategory::CommandLine);
        assert_eq!(
            a.classify("powershell -enc AAAA"),
            StringCategory::CommandLine
        );
    }

    #[test]
    fn test_classify_override() {
        let mut a = StringAnnotator::new();
        a.add_override("special_string", StringCategory::Mutex);
        assert_eq!(a.classify("special_string"), StringCategory::Mutex);
    }

    #[test]
    fn test_annotate_all() {
        let annotator = StringAnnotator::new();
        let strings = vec![
            AnnotatedString::new(0x100, "https://evil.com", "xor", 90, 16),
            AnnotatedString::new(0x200, "password123", "rc4", 85, 11),
        ];
        let annotated = annotator.annotate_all(strings);
        assert_eq!(annotated[0].category, StringCategory::Url);
        assert_eq!(annotated[1].category, StringCategory::Credential);
        // Comments should be set.
        assert!(annotated[0].comment.is_some());
    }

    #[test]
    fn test_annotate_below_min_confidence() {
        let annotator = StringAnnotator::new().with_min_confidence(80);
        let strings = vec![AnnotatedString::new(
            0x100,
            "https://evil.com",
            "xor",
            70,
            16,
        )];
        let annotated = annotator.annotate_all(strings);
        // Below min_confidence → category stays Unknown but comment is still set.
        assert_eq!(annotated[0].category, StringCategory::Unknown);
    }

    #[test]
    fn test_high_value_filter() {
        let annotator = StringAnnotator::new();
        let strings = vec![
            AnnotatedString::new(0, "https://c2.evil", "xor", 90, 15)
                .with_category(StringCategory::C2),
            AnnotatedString::new(0, "svchost.exe", "none", 80, 11)
                .with_category(StringCategory::ServiceProcess),
        ];
        let hv = annotator.high_value(&strings);
        assert_eq!(hv.len(), 1);
        assert_eq!(hv[0].category, StringCategory::C2);
    }

    // ── BinaryView ────────────────────────────────────────────────────────────

    #[test]
    fn test_binary_view_set_get_comment() {
        let mut v = BinaryView::new();
        v.set_comment(0x1000, "test comment");
        assert_eq!(v.get_comment(0x1000), Some("test comment"));
        assert_eq!(v.get_comment(0x2000), None);
    }

    #[test]
    fn test_binary_view_comment_count() {
        let mut v = BinaryView::new();
        v.set_comment(0x100, "a");
        v.set_comment(0x200, "b");
        assert_eq!(v.comment_count(), 2);
    }

    // ── AnnotationWriter ──────────────────────────────────────────────────────

    #[test]
    fn test_writer_write_all() {
        let writer = AnnotationWriter::new().with_min_confidence(50);
        let mut view = BinaryView::new();
        let mut strings = vec![
            AnnotatedString::new(0x100, "https://evil.com", "xor", 90, 16)
                .with_category(StringCategory::Url),
            AnnotatedString::new(0x200, "svchost.exe", "none", 80, 11)
                .with_category(StringCategory::ServiceProcess),
        ];
        let written = writer.write_all(&mut strings, &mut view);
        assert_eq!(written, 2);
        assert!(view.get_comment(0x100).is_some());
        assert!(strings[0].is_committed);
    }

    #[test]
    fn test_writer_below_min_confidence_skipped() {
        let writer = AnnotationWriter::new().with_min_confidence(80);
        let mut view = BinaryView::new();
        let mut strings = vec![AnnotatedString::new(0x100, "test", "xor", 50, 4)];
        let written = writer.write_all(&mut strings, &mut view);
        assert_eq!(written, 0);
        assert!(!strings[0].is_committed);
    }

    #[test]
    fn test_writer_no_overwrite() {
        let writer = AnnotationWriter::new().with_overwrite(false);
        let mut view = BinaryView::new();
        view.set_comment(0x100, "existing");
        let mut strings = vec![AnnotatedString::new(0x100, "new value", "xor", 90, 9)];
        let written = writer.write_all(&mut strings, &mut view);
        assert_eq!(written, 0);
        assert_eq!(view.get_comment(0x100), Some("existing"));
    }

    #[test]
    fn test_writer_overwrite_enabled() {
        let writer = AnnotationWriter::new().with_overwrite(true);
        let mut view = BinaryView::new();
        view.set_comment(0x100, "existing");
        let mut strings = vec![AnnotatedString::new(0x100, "new value", "xor", 90, 9)];
        let written = writer.write_all(&mut strings, &mut view);
        assert_eq!(written, 1);
        assert!(view.get_comment(0x100).unwrap().contains("new value"));
    }

    #[test]
    fn test_writer_write_one() {
        let writer = AnnotationWriter::new();
        let mut view = BinaryView::new();
        let mut s = AnnotatedString::new(0x300, "cmd.exe", "none", 85, 7);
        s.comment = Some("my comment".into());
        let ok = writer.write_one(&mut s, &mut view);
        assert!(ok);
        assert!(s.is_committed);
        assert_eq!(view.get_comment(0x300), Some("my comment"));
    }

    #[test]
    fn test_writer_with_prefix() {
        let writer = AnnotationWriter::new()
            .with_prefix("[custom]")
            .with_overwrite(true);
        let mut view = BinaryView::new();
        let mut strings = vec![
            AnnotatedString::new(0x100, "hello", "xor", 90, 5)
                .with_category(StringCategory::Generic),
        ];
        writer.write_all(&mut strings, &mut view);
        assert!(view.get_comment(0x100).unwrap().starts_with("[custom]"));
    }

    // ── Additional coverage tests ─────────────────────────────────────────────

    #[test]
    fn test_classify_ftp_url() {
        let a = StringAnnotator::new();
        assert_eq!(
            a.classify("ftp://files.example.com/payload"),
            StringCategory::Url
        );
    }

    #[test]
    fn test_classify_unc_path() {
        let a = StringAnnotator::new();
        assert_eq!(
            a.classify("\\\\server\\share\\file.exe"),
            StringCategory::Path
        );
    }

    #[test]
    fn test_classify_apikey_credential() {
        let a = StringAnnotator::new();
        assert_eq!(a.classify("apikey_12345abcdef"), StringCategory::Credential);
    }

    #[test]
    fn test_classify_global_mutex() {
        let a = StringAnnotator::new();
        assert_eq!(a.classify("Global\\MyMutexName"), StringCategory::Mutex);
    }

    #[test]
    fn test_classify_dll() {
        let a = StringAnnotator::new();
        assert_eq!(a.classify("evil.dll"), StringCategory::ServiceProcess);
    }

    #[test]
    fn test_classify_sys_driver() {
        let a = StringAnnotator::new();
        assert_eq!(a.classify("rootkit.sys"), StringCategory::ServiceProcess);
    }

    #[test]
    fn test_classify_hkcu_registry() {
        let a = StringAnnotator::new();
        assert_eq!(
            a.classify("HKCU\\Software\\Microsoft\\Windows\\Run"),
            StringCategory::Registry
        );
    }

    #[test]
    fn test_classify_token_credential() {
        let a = StringAnnotator::new();
        assert_eq!(a.classify("Bearer token12345"), StringCategory::Credential);
    }

    #[test]
    fn test_annotator_multiple_overrides() {
        let mut a = StringAnnotator::new();
        a.add_override("cmd1", StringCategory::CommandLine);
        a.add_override("api1", StringCategory::Api);
        assert_eq!(a.classify("cmd1"), StringCategory::CommandLine);
        assert_eq!(a.classify("api1"), StringCategory::Api);
    }

    #[test]
    fn test_binary_view_overwrite_comment() {
        let mut v = BinaryView::new();
        v.set_comment(0x100, "first");
        v.set_comment(0x100, "second");
        assert_eq!(v.get_comment(0x100), Some("second"));
    }

    #[test]
    fn test_annotation_writer_min_confidence_zero_accepts_all() {
        let writer = AnnotationWriter::new().with_min_confidence(0);
        let mut view = BinaryView::new();
        let mut strings = vec![AnnotatedString::new(0x500, "test", "xor", 1, 4)];
        let written = writer.write_all(&mut strings, &mut view);
        assert_eq!(written, 1);
    }

    #[test]
    fn test_annotated_string_default_category_unknown() {
        let s = AnnotatedString::new(0, "xyz", "xor", 50, 3);
        assert_eq!(s.category, StringCategory::Unknown);
    }

    #[test]
    fn test_string_category_registry_is_not_sensitive() {
        assert!(!StringCategory::Registry.is_sensitive());
    }

    #[test]
    fn test_classify_wscript() {
        let a = StringAnnotator::new();
        assert_eq!(
            a.classify("wscript //E:vbs payload.vbs"),
            StringCategory::CommandLine
        );
    }

    #[test]
    fn test_classify_appdata_path() {
        let a = StringAnnotator::new();
        assert_eq!(a.classify("%AppData%\\malware"), StringCategory::Path);
    }
}
