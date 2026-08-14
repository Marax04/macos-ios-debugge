// rustre-fuzz-net/src/crash_analyzer.rs
//! `CrashAnalyzer` — classify and deduplicate network fuzzing crashes.

use std::collections::HashMap;
use std::time::SystemTime;

// ─── CrashType ────────────────────────────────────────────────────────────────

/// Classification of a single network fuzzing crash.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CrashType {
    /// The target did not respond within the configured timeout.
    Timeout,
    /// The TCP/UDP connection was actively refused.
    ConnectionRefused,
    /// The server returned a response that did not match the expected pattern.
    UnexpectedResponse,
    /// The server violated the protocol framing rules.
    ProtocolError,
    /// The target process crashed (SIGSEGV / SIGABRT / heap corruption, etc.).
    Crash,
    /// The target returned a server-side error status (e.g. HTTP 500).
    ServerError,
    /// Unknown / unclassified.
    Unknown,
}

impl CrashType {
    /// Human-readable name.
    #[must_use] 
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::ConnectionRefused => "connection_refused",
            Self::UnexpectedResponse => "unexpected_response",
            Self::ProtocolError => "protocol_error",
            Self::Crash => "crash",
            Self::ServerError => "server_error",
            Self::Unknown => "unknown",
        }
    }

    /// Severity score in [0, 10]. Higher = more severe.
    #[must_use] 
    pub const fn severity(&self) -> u8 {
        match self {
            Self::Crash => 10,
            Self::ProtocolError => 7,
            Self::ServerError => 6,
            Self::UnexpectedResponse => 4,
            Self::Timeout => 3,
            Self::ConnectionRefused => 2,
            Self::Unknown => 1,
        }
    }

    /// Derive a crash type from a free-form reason string (as stored by `CrashLogger`).
    #[must_use] 
    pub fn from_reason(reason: &str) -> Self {
        let r = reason.to_lowercase();
        if r.contains("timeout") {
            return Self::Timeout;
        }
        if r.contains("refused") || r.contains("connect") {
            return Self::ConnectionRefused;
        }
        if r.contains("protocol") {
            return Self::ProtocolError;
        }
        if r.contains("crash") || r.contains("sigsegv") || r.contains("abort") {
            return Self::Crash;
        }
        if r.contains("500") || r.contains("server error") {
            return Self::ServerError;
        }
        if r.contains("unexpected") || r.contains("response") {
            return Self::UnexpectedResponse;
        }
        Self::Unknown
    }
}

impl std::fmt::Display for CrashType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─── CrashRecord ─────────────────────────────────────────────────────────────

/// A single crash event produced during network fuzzing.
#[derive(Debug, Clone)]
pub struct CrashRecord {
    /// The raw bytes that were sent to the target when the crash occurred.
    pub input: Vec<u8>,
    /// Classification of the crash.
    pub crash_type: CrashType,
    /// The raw bytes received from the target (may be empty).
    pub response: Vec<u8>,
    /// Wall-clock time at which the crash was recorded.
    pub timestamp: SystemTime,
    /// The protocol state the fuzzer was in.
    pub state: String,
    /// Unique ID assigned by the analyzer.
    pub id: u64,
}

impl CrashRecord {
    /// Create a new record, auto-classifying `crash_type` from `reason`.
    #[must_use] 
    pub fn from_reason(
        id: u64,
        input: Vec<u8>,
        reason: &str,
        response: Vec<u8>,
        state: &str,
    ) -> Self {
        Self {
            input,
            crash_type: CrashType::from_reason(reason),
            response,
            timestamp: SystemTime::now(),
            state: state.to_string(),
            id,
        }
    }

    /// Returns the input length.
    #[must_use] 
    pub const fn input_len(&self) -> usize {
        self.input.len()
    }

    /// Returns the response length.
    #[must_use] 
    pub const fn response_len(&self) -> usize {
        self.response.len()
    }

    /// True if the crash appears to be a memory-safety issue.
    #[must_use] 
    pub fn is_critical(&self) -> bool {
        self.crash_type == CrashType::Crash
    }
}

// ─── Deduplication signature ──────────────────────────────────────────────────

/// Compute a deduplication signature for a crash record.
/// Two crashes are considered duplicate if they share the same type, state,
/// and first 16 bytes of input.
fn crash_signature(record: &CrashRecord) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a offset basis
    let fnv_prime: u64 = 0x0000_0100_0000_01b3;
    // Mix crash type
    h ^= u64::from(record.crash_type.severity());
    h = h.wrapping_mul(fnv_prime);
    // Mix state bytes
    for b in record.state.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(fnv_prime);
    }
    // Mix first 16 bytes of input
    for b in record.input.iter().take(16) {
        h ^= u64::from(*b);
        h = h.wrapping_mul(fnv_prime);
    }
    h
}

// ─── CrashDeduplicator ────────────────────────────────────────────────────────

/// Signature-based deduplicator: keeps the first occurrence of each unique crash signature.
#[derive(Debug, Default)]
pub struct CrashDeduplicator {
    seen_signatures: HashMap<u64, u64>, // signature → record id
    /// Records that survived deduplication.
    pub unique_records: Vec<CrashRecord>,
    /// Total number of duplicates discarded.
    pub duplicates_discarded: u64,
}

impl CrashDeduplicator {
    /// Create a new deduplicator.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Submit a record; returns `true` if it was kept (i.e. not a duplicate).
    pub fn submit(&mut self, record: CrashRecord) -> bool {
        let sig = crash_signature(&record);
        if self.seen_signatures.contains_key(&sig) {
            self.duplicates_discarded += 1;
            return false;
        }
        self.seen_signatures.insert(sig, record.id);
        self.unique_records.push(record);
        true
    }

    /// Number of unique crashes retained.
    #[must_use] 
    pub const fn unique_count(&self) -> usize {
        self.unique_records.len()
    }

    /// Iterate over unique records.
    pub fn iter(&self) -> impl Iterator<Item = &CrashRecord> {
        self.unique_records.iter()
    }

    /// Clear all state.
    pub fn clear(&mut self) {
        self.seen_signatures.clear();
        self.unique_records.clear();
        self.duplicates_discarded = 0;
    }

    /// Return records of a specific crash type.
    #[must_use] 
    pub fn by_type(&self, ct: &CrashType) -> Vec<&CrashRecord> {
        self.unique_records
            .iter()
            .filter(|r| &r.crash_type == ct)
            .collect()
    }
}

// ─── CrashReport ─────────────────────────────────────────────────────────────

/// Overall severity of a fuzzing campaign.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// No issues found.
    Clean,
    /// Only low-risk crashes (timeouts, connection refused).
    Low,
    /// Protocol violations or unexpected responses.
    Medium,
    /// Server errors or protocol errors.
    High,
    /// Memory-safety crashes detected.
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clean => write!(f, "CLEAN"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A complete crash analysis report for a fuzzing campaign.
#[derive(Debug, Clone)]
pub struct CrashReport {
    /// Total crashes observed (including duplicates).
    pub total_crashes: u64,
    /// Unique crashes after deduplication.
    pub unique_crashes: u64,
    /// Duplicates discarded.
    pub duplicates: u64,
    /// Breakdown by crash type.
    pub by_type: HashMap<String, u64>,
    /// Overall campaign severity.
    pub severity: Severity,
    /// The most severe crash type seen.
    pub worst_crash_type: Option<CrashType>,
    /// Unique crashes in order of severity (highest first).
    pub top_crashes: Vec<CrashRecord>,
    /// Time at which the report was generated.
    pub generated_at: SystemTime,
}

impl CrashReport {
    /// Build a report from a deduplicator.
    #[must_use] 
    pub fn from_deduplicator(dedup: &CrashDeduplicator, total: u64) -> Self {
        let unique: Vec<CrashRecord> = dedup.unique_records.clone();
        let duplicates = dedup.duplicates_discarded;

        let mut by_type: HashMap<String, u64> = HashMap::new();
        for r in &unique {
            *by_type.entry(r.crash_type.name().to_string()).or_insert(0) += 1;
        }

        let worst = unique
            .iter()
            .max_by_key(|r| r.crash_type.severity())
            .map(|r| r.crash_type.clone());
        let severity = match worst.as_ref().map_or(0, CrashType::severity) {
            0 => Severity::Clean,
            1..=3 => Severity::Low,
            4..=5 => Severity::Medium,
            6..=8 => Severity::High,
            _ => Severity::Critical,
        };

        let mut top = unique.clone();
        top.sort_by(|a, b| b.crash_type.severity().cmp(&a.crash_type.severity()));
        top.truncate(10);

        Self {
            total_crashes: total,
            unique_crashes: unique.len() as u64,
            duplicates,
            by_type,
            severity,
            worst_crash_type: worst,
            top_crashes: top,
            generated_at: SystemTime::now(),
        }
    }

    /// True if critical crashes were found.
    #[must_use] 
    pub fn has_critical(&self) -> bool {
        self.severity == Severity::Critical
    }

    /// Return count for a crash type name.
    #[must_use] 
    pub fn count_for(&self, type_name: &str) -> u64 {
        self.by_type.get(type_name).copied().unwrap_or(0)
    }
}

// ─── CrashAnalyzer ────────────────────────────────────────────────────────────

/// Classifies, deduplicates, and reports network fuzzing crashes.
pub struct CrashAnalyzer {
    deduplicator: CrashDeduplicator,
    total_submitted: u64,
    next_id: u64,
}

impl CrashAnalyzer {
    /// Create a new analyzer.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            deduplicator: CrashDeduplicator::new(),
            total_submitted: 0,
            next_id: 1,
        }
    }

    /// Submit a crash from a fuzzing session.
    pub fn submit_crash(
        &mut self,
        input: Vec<u8>,
        reason: &str,
        response: Vec<u8>,
        state: &str,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.total_submitted += 1;
        let record = CrashRecord::from_reason(id, input, reason, response, state);
        self.deduplicator.submit(record);
        id
    }

    /// Classify an individual reason string without storing it.
    #[must_use] 
    pub fn classify(&self, reason: &str) -> CrashType {
        CrashType::from_reason(reason)
    }

    /// Generate a report from all submitted crashes.
    #[must_use] 
    pub fn generate_report(&self) -> CrashReport {
        CrashReport::from_deduplicator(&self.deduplicator, self.total_submitted)
    }

    /// Number of unique crashes seen.
    #[must_use] 
    pub const fn unique_count(&self) -> usize {
        self.deduplicator.unique_count()
    }

    /// Total crashes submitted (including duplicates).
    #[must_use] 
    pub const fn total_count(&self) -> u64 {
        self.total_submitted
    }

    /// Return unique crashes of a given type.
    #[must_use] 
    pub fn crashes_of_type(&self, ct: &CrashType) -> Vec<&CrashRecord> {
        self.deduplicator.by_type(ct)
    }

    /// Reset all state.
    pub fn reset(&mut self) {
        self.deduplicator.clear();
        self.total_submitted = 0;
        self.next_id = 1;
    }
}

impl Default for CrashAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn input(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    // ── CrashType ─────────────────────────────────────────────────────────────

    #[test]
    fn test_crash_type_from_reason_timeout() {
        assert_eq!(CrashType::from_reason("timeout"), CrashType::Timeout);
    }

    #[test]
    fn test_crash_type_from_reason_refused() {
        assert_eq!(
            CrashType::from_reason("connection refused"),
            CrashType::ConnectionRefused
        );
    }

    #[test]
    fn test_crash_type_from_reason_crash() {
        assert_eq!(CrashType::from_reason("SIGSEGV crash"), CrashType::Crash);
    }

    #[test]
    fn test_crash_type_from_reason_protocol() {
        assert_eq!(
            CrashType::from_reason("protocol error"),
            CrashType::ProtocolError
        );
    }

    #[test]
    fn test_crash_type_from_reason_unexpected() {
        assert_eq!(
            CrashType::from_reason("unexpected response"),
            CrashType::UnexpectedResponse
        );
    }

    #[test]
    fn test_crash_type_from_reason_unknown() {
        assert_eq!(
            CrashType::from_reason("some random text"),
            CrashType::Unknown
        );
    }

    #[test]
    fn test_crash_type_severity_ordering() {
        assert!(CrashType::Crash.severity() > CrashType::Timeout.severity());
        assert!(CrashType::ProtocolError.severity() > CrashType::ConnectionRefused.severity());
    }

    #[test]
    fn test_crash_type_display() {
        assert_eq!(CrashType::Timeout.to_string(), "timeout");
        assert_eq!(CrashType::Crash.to_string(), "crash");
    }

    // ── CrashRecord ───────────────────────────────────────────────────────────

    #[test]
    fn test_crash_record_creation() {
        let r = CrashRecord::from_reason(1, input("data"), "timeout", vec![], "start");
        assert_eq!(r.crash_type, CrashType::Timeout);
        assert_eq!(r.id, 1);
        assert_eq!(r.state, "start");
    }

    #[test]
    fn test_crash_record_is_critical_true() {
        let r = CrashRecord::from_reason(1, input("x"), "crash", vec![], "s");
        assert!(r.is_critical());
    }

    #[test]
    fn test_crash_record_is_critical_false() {
        let r = CrashRecord::from_reason(1, input("x"), "timeout", vec![], "s");
        assert!(!r.is_critical());
    }

    #[test]
    fn test_crash_record_input_len() {
        let r = CrashRecord::from_reason(1, input("hello"), "crash", vec![], "s");
        assert_eq!(r.input_len(), 5);
    }

    // ── CrashDeduplicator ──────────────────────────────────────────────────────

    #[test]
    fn test_dedup_keeps_unique() {
        let mut d = CrashDeduplicator::new();
        let r1 = CrashRecord::from_reason(1, input("aaa"), "timeout", vec![], "start");
        let r2 = CrashRecord::from_reason(2, input("bbb"), "crash", vec![], "start");
        assert!(d.submit(r1));
        assert!(d.submit(r2));
        assert_eq!(d.unique_count(), 2);
    }

    #[test]
    fn test_dedup_discards_duplicate() {
        let mut d = CrashDeduplicator::new();
        let r1 = CrashRecord::from_reason(1, input("aaa"), "timeout", vec![], "start");
        let r2 = CrashRecord::from_reason(2, input("aaa"), "timeout", vec![], "start");
        assert!(d.submit(r1));
        assert!(!d.submit(r2)); // same sig
        assert_eq!(d.unique_count(), 1);
        assert_eq!(d.duplicates_discarded, 1);
    }

    #[test]
    fn test_dedup_by_type() {
        let mut d = CrashDeduplicator::new();
        d.submit(CrashRecord::from_reason(
            1,
            input("a"),
            "crash",
            vec![],
            "s",
        ));
        d.submit(CrashRecord::from_reason(
            2,
            input("b"),
            "timeout",
            vec![],
            "s",
        ));
        d.submit(CrashRecord::from_reason(
            3,
            input("c"),
            "crash",
            vec![],
            "t",
        ));
        let crashes = d.by_type(&CrashType::Crash);
        assert_eq!(crashes.len(), 2);
    }

    #[test]
    fn test_dedup_clear() {
        let mut d = CrashDeduplicator::new();
        d.submit(CrashRecord::from_reason(
            1,
            input("a"),
            "crash",
            vec![],
            "s",
        ));
        d.clear();
        assert_eq!(d.unique_count(), 0);
        assert_eq!(d.duplicates_discarded, 0);
    }

    // ── CrashAnalyzer ─────────────────────────────────────────────────────────

    #[test]
    fn test_analyzer_submit_and_classify() {
        let mut a = CrashAnalyzer::new();
        a.submit_crash(input("hello"), "timeout", vec![], "start");
        assert_eq!(a.total_count(), 1);
        assert_eq!(a.unique_count(), 1);
    }

    #[test]
    fn test_analyzer_deduplication() {
        let mut a = CrashAnalyzer::new();
        a.submit_crash(input("hello"), "timeout", vec![], "start");
        a.submit_crash(input("hello"), "timeout", vec![], "start");
        assert_eq!(a.total_count(), 2);
        assert_eq!(a.unique_count(), 1);
    }

    #[test]
    fn test_analyzer_classify() {
        let a = CrashAnalyzer::new();
        assert_eq!(a.classify("crash"), CrashType::Crash);
        assert_eq!(a.classify("timeout"), CrashType::Timeout);
    }

    #[test]
    fn test_analyzer_report_severity_clean() {
        let a = CrashAnalyzer::new();
        let r = a.generate_report();
        assert_eq!(r.severity, Severity::Clean);
    }

    #[test]
    fn test_analyzer_report_severity_critical() {
        let mut a = CrashAnalyzer::new();
        a.submit_crash(input("exploit"), "crash SIGSEGV", vec![], "state");
        let r = a.generate_report();
        assert_eq!(r.severity, Severity::Critical);
        assert!(r.has_critical());
    }

    #[test]
    fn test_analyzer_report_count_for_type() {
        let mut a = CrashAnalyzer::new();
        a.submit_crash(input("a"), "timeout", vec![], "s");
        a.submit_crash(input("b"), "timeout", vec![], "t");
        let r = a.generate_report();
        assert_eq!(r.count_for("timeout"), 2);
    }

    #[test]
    fn test_analyzer_reset() {
        let mut a = CrashAnalyzer::new();
        a.submit_crash(input("a"), "crash", vec![], "s");
        a.reset();
        assert_eq!(a.total_count(), 0);
        assert_eq!(a.unique_count(), 0);
    }

    #[test]
    fn test_analyzer_crashes_of_type() {
        let mut a = CrashAnalyzer::new();
        a.submit_crash(input("a"), "crash", vec![], "s");
        a.submit_crash(input("b"), "timeout", vec![], "s");
        let crits = a.crashes_of_type(&CrashType::Crash);
        assert_eq!(crits.len(), 1);
    }

    // ── CrashReport ───────────────────────────────────────────────────────────

    #[test]
    fn test_report_top_crashes_sorted_by_severity() {
        let mut a = CrashAnalyzer::new();
        a.submit_crash(input("x"), "timeout", vec![], "s");
        a.submit_crash(input("y"), "crash", vec![], "s");
        let r = a.generate_report();
        assert_eq!(r.top_crashes[0].crash_type, CrashType::Crash);
    }

    #[test]
    fn test_report_duplicates_counted() {
        let mut a = CrashAnalyzer::new();
        a.submit_crash(input("z"), "timeout", vec![], "s");
        a.submit_crash(input("z"), "timeout", vec![], "s");
        let r = a.generate_report();
        assert_eq!(r.total_crashes, 2);
        assert_eq!(r.unique_crashes, 1);
        assert_eq!(r.duplicates, 1);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
        assert_eq!(Severity::Clean.to_string(), "CLEAN");
    }
}
