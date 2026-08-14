/// Crash and hang detection for network fuzzers.
///
/// Detects crashes via connection refused, timeout, ASAN/UBSAN output,
/// unexpected close, and abnormal response patterns. Provides hang detection,
/// crash de-duplication by bucketed hash, and a full `CrashReport` struct.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::fmt;

// ---------------------------------------------------------------------------
// CrashSignal — the raw signal that triggered detection
// ---------------------------------------------------------------------------

/// The raw signal observed that may indicate a crash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrashSignal {
    /// Connection was refused (port closed / process died).
    ConnectionRefused,
    /// No data received within the timeout window.
    Timeout { elapsed_ms: u64 },
    /// Remote side sent RST / abruptly closed.
    ConnectionReset,
    /// The response contained an ASAN/UBSAN/Valgrind error line.
    SanitizerOutput { line: String },
    /// The response contained a known crash string.
    CrashString { pattern: String, found_at: usize },
    /// The response length is outside the expected range.
    AbnormalResponseLength { got: usize, expected_min: usize, expected_max: usize },
    /// The process exited with a non-zero exit code.
    NonZeroExit { code: i32 },
    /// A custom application-level crash signal.
    Custom { tag: String, description: String },
}

impl CrashSignal {
    #[must_use]
    pub fn severity(&self) -> u8 {
        match self {
            CrashSignal::SanitizerOutput { .. } => 10,
            CrashSignal::ConnectionReset => 9,
            CrashSignal::NonZeroExit { .. } => 9,
            CrashSignal::CrashString { .. } => 8,
            CrashSignal::ConnectionRefused => 7,
            CrashSignal::Timeout { .. } => 5,
            CrashSignal::AbnormalResponseLength { .. } => 4,
            CrashSignal::Custom { .. } => 5,
        }
    }

    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            CrashSignal::ConnectionRefused => "conn_refused",
            CrashSignal::Timeout { .. } => "timeout",
            CrashSignal::ConnectionReset => "conn_reset",
            CrashSignal::SanitizerOutput { .. } => "sanitizer",
            CrashSignal::CrashString { .. } => "crash_string",
            CrashSignal::AbnormalResponseLength { .. } => "abnormal_len",
            CrashSignal::NonZeroExit { .. } => "nonzero_exit",
            CrashSignal::Custom { .. } => "custom",
        }
    }
}

impl fmt::Display for CrashSignal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CrashSignal::ConnectionRefused => write!(f, "Connection refused"),
            CrashSignal::Timeout { elapsed_ms } => write!(f, "Timeout after {}ms", elapsed_ms),
            CrashSignal::ConnectionReset => write!(f, "Connection reset"),
            CrashSignal::SanitizerOutput { line } => write!(f, "Sanitizer: {}", line),
            CrashSignal::CrashString { pattern, found_at } => {
                write!(f, "Crash string '{}' at offset {}", pattern, found_at)
            }
            CrashSignal::AbnormalResponseLength { got, expected_min, expected_max } => {
                write!(f, "Response len {} outside [{},{}]", got, expected_min, expected_max)
            }
            CrashSignal::NonZeroExit { code } => write!(f, "Non-zero exit {}", code),
            CrashSignal::Custom { tag, description } => write!(f, "[{}] {}", tag, description),
        }
    }
}

// ---------------------------------------------------------------------------
// CrashReport — full details about one crash
// ---------------------------------------------------------------------------

/// A de-duplicated crash report.
#[derive(Debug, Clone)]
pub struct CrashReport {
    pub id: u64,
    pub signal: CrashSignal,
    /// The input that triggered the crash.
    pub triggering_input: Vec<u8>,
    /// State label in the protocol state machine, if applicable.
    pub state_label: Option<String>,
    /// Raw response bytes received before crash.
    pub response_fragment: Vec<u8>,
    pub first_seen: std::time::SystemTime,
    pub occurrences: u32,
    pub bucket: u64,
}

impl CrashReport {
    #[must_use]
    pub fn new(
        signal: CrashSignal,
        input: Vec<u8>,
        state_label: Option<String>,
        response_fragment: Vec<u8>,
    ) -> Self {
        let bucket = bucket_hash(&signal, &input);
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self {
            id,
            signal,
            triggering_input: input,
            state_label,
            response_fragment,
            first_seen: std::time::SystemTime::now(),
            occurrences: 1,
            bucket,
        }
    }

    #[must_use]
    pub fn severity(&self) -> u8 {
        self.signal.severity()
    }
}

/// Compute a bucket hash for de-duplication: same signal type + first 16 bytes of input.
#[must_use]
pub fn bucket_hash(signal: &CrashSignal, input: &[u8]) -> u64 {
    let sig_byte = signal.severity() as u64;
    let name_hash = signal.name().bytes().fold(0u64, |a, b| a.wrapping_mul(31).wrapping_add(b as u64));
    let input_hash = input.iter().take(16).fold(0u64, |a, &b| a.wrapping_mul(257).wrapping_add(b as u64));
    sig_byte.wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ name_hash.wrapping_mul(0x6C62_272E_07BB_0142)
        ^ input_hash
}

// ---------------------------------------------------------------------------
// Sanitizer pattern detection
// ---------------------------------------------------------------------------

const SANITIZER_PATTERNS: &[&str] = &[
    "AddressSanitizer",
    "ASAN:",
    "==ERROR:",
    "UndefinedBehaviorSanitizer",
    "UBSAN:",
    "Valgrind",
    "Invalid read",
    "Invalid write",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "use-after-free",
    "double-free",
    "null-deref",
    "SEGV",
    "Segmentation fault",
    "Aborted",
    "Assertion failed",
    "panic!",
    "SIGSEGV",
    "SIGABRT",
];

/// Scan `text` for sanitizer/crash patterns and return the first matching line.
#[must_use]
pub fn detect_sanitizer_output(text: &str) -> Option<String> {
    for line in text.lines() {
        for pat in SANITIZER_PATTERNS {
            if line.contains(pat) {
                return Some(line.to_owned());
            }
        }
    }
    None
}

/// Scan `data` bytes for crash string patterns.
#[must_use]
pub fn detect_crash_string(data: &[u8]) -> Option<(String, usize)> {
    let text = String::from_utf8_lossy(data);
    for pat in SANITIZER_PATTERNS {
        if let Some(pos) = text.find(pat) {
            return Some((pat.to_string(), pos));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// CrashDetector — stateful detector
// ---------------------------------------------------------------------------

/// Configuration for crash detection thresholds.
#[derive(Debug, Clone)]
pub struct DetectorConfig {
    /// How long to wait for a response before declaring a hang.
    pub response_timeout: Duration,
    /// Minimum expected response size.
    pub min_response_len: usize,
    /// Maximum expected response size.
    pub max_response_len: usize,
    /// Whether to scan response bytes for sanitizer output.
    pub scan_sanitizer: bool,
    /// Custom crash strings to look for.
    pub custom_crash_strings: Vec<String>,
    /// Maximum unique crash buckets to store.
    pub max_buckets: usize,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            response_timeout: Duration::from_secs(5),
            min_response_len: 0,
            max_response_len: 65536,
            scan_sanitizer: true,
            custom_crash_strings: Vec::new(),
            max_buckets: 1024,
        }
    }
}

/// Stateful crash detector that de-duplicates reports.
#[derive(Debug)]
pub struct CrashDetector {
    config: DetectorConfig,
    /// bucket -> CrashReport
    seen_buckets: HashMap<u64, CrashReport>,
    total_crashes: u64,
    total_inputs: u64,
}

impl CrashDetector {
    #[must_use]
    pub fn new(config: DetectorConfig) -> Self {
        Self {
            config,
            seen_buckets: HashMap::new(),
            total_crashes: 0,
            total_inputs: 0,
        }
    }

    pub fn with_default_config() -> Self {
        Self::new(DetectorConfig::default())
    }

    /// Analyse a (input, response) pair.
    /// Returns `Some(CrashReport)` if a new unique crash was detected.
    pub fn analyse(
        &mut self,
        input: &[u8],
        response: Option<&[u8]>,
        elapsed: Duration,
        state_label: Option<String>,
        exit_code: Option<i32>,
        connection_error: Option<ConnectionError>,
    ) -> Option<CrashReport> {
        self.total_inputs += 1;

        let signal = self.classify(response, elapsed, exit_code, connection_error)?;
        self.total_crashes += 1;

        let fragment = response.map(|r| r[..r.len().min(256)].to_vec()).unwrap_or_default();
        let bucket = bucket_hash(&signal, input);

        if let Some(existing) = self.seen_buckets.get_mut(&bucket) {
            existing.occurrences += 1;
            return None; // duplicate
        }

        if self.seen_buckets.len() >= self.config.max_buckets {
            // evict oldest by ID
            if let Some((&k, _)) = self.seen_buckets.iter().min_by_key(|(_, v)| v.id) {
                self.seen_buckets.remove(&k);
            }
        }

        let report = CrashReport::new(signal, input.to_vec(), state_label, fragment);
        self.seen_buckets.insert(bucket, report.clone());
        Some(report)
    }

    fn classify(
        &self,
        response: Option<&[u8]>,
        elapsed: Duration,
        exit_code: Option<i32>,
        connection_error: Option<ConnectionError>,
    ) -> Option<CrashSignal> {
        // Connection-level errors
        if let Some(err) = connection_error {
            return Some(match err {
                ConnectionError::Refused => CrashSignal::ConnectionRefused,
                ConnectionError::Reset => CrashSignal::ConnectionReset,
            });
        }

        // Timeout
        if elapsed >= self.config.response_timeout {
            return Some(CrashSignal::Timeout { elapsed_ms: elapsed.as_millis() as u64 });
        }

        // Non-zero exit
        if let Some(code) = exit_code {
            if code != 0 {
                return Some(CrashSignal::NonZeroExit { code });
            }
        }

        if let Some(resp) = response {
            // Sanitizer scan
            if self.config.scan_sanitizer {
                let text = String::from_utf8_lossy(resp);
                if let Some(line) = detect_sanitizer_output(&text) {
                    return Some(CrashSignal::SanitizerOutput { line });
                }
            }

            // Custom crash strings
            let text = String::from_utf8_lossy(resp);
            for pat in &self.config.custom_crash_strings {
                if let Some(pos) = text.find(pat.as_str()) {
                    return Some(CrashSignal::CrashString { pattern: pat.clone(), found_at: pos });
                }
            }

            // Abnormal length
            let len = resp.len();
            if len < self.config.min_response_len || len > self.config.max_response_len {
                return Some(CrashSignal::AbnormalResponseLength {
                    got: len,
                    expected_min: self.config.min_response_len,
                    expected_max: self.config.max_response_len,
                });
            }
        }

        None
    }

    #[must_use]
    pub fn unique_crashes(&self) -> usize {
        self.seen_buckets.len()
    }

    #[must_use]
    pub fn total_crashes(&self) -> u64 {
        self.total_crashes
    }

    #[must_use]
    pub fn total_inputs(&self) -> u64 {
        self.total_inputs
    }

    #[must_use]
    pub fn crash_rate(&self) -> f64 {
        if self.total_inputs == 0 {
            0.0
        } else {
            self.total_crashes as f64 / self.total_inputs as f64
        }
    }

    pub fn reports(&self) -> impl Iterator<Item = &CrashReport> {
        self.seen_buckets.values()
    }

    pub fn reports_by_severity(&self) -> Vec<&CrashReport> {
        let mut v: Vec<&CrashReport> = self.seen_buckets.values().collect();
        v.sort_by(|a, b| b.severity().cmp(&a.severity()));
        v
    }

    pub fn clear(&mut self) {
        self.seen_buckets.clear();
        self.total_crashes = 0;
        self.total_inputs = 0;
    }
}

/// Simple connection error variants.
#[derive(Debug, Clone, Copy)]
pub enum ConnectionError {
    Refused,
    Reset,
}

// ---------------------------------------------------------------------------
// HangDetector — deadline-based hang detection
// ---------------------------------------------------------------------------

/// Track per-input deadlines to detect hangs.
#[derive(Debug)]
pub struct HangDetector {
    timeout: Duration,
    /// input_id -> deadline
    active: HashMap<u64, Instant>,
    hangs: Vec<HangEvent>,
    next_id: u64,
}

/// A recorded hang event.
#[derive(Debug, Clone)]
pub struct HangEvent {
    pub input_id: u64,
    pub timeout: Duration,
    pub detected_at: Instant,
}

impl HangDetector {
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            active: HashMap::new(),
            hangs: Vec::new(),
            next_id: 0,
        }
    }

    /// Register a new input for hang tracking. Returns the input_id.
    pub fn register(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.active.insert(id, Instant::now());
        id
    }

    /// Mark an input as completed (no hang).
    pub fn complete(&mut self, id: u64) {
        self.active.remove(&id);
    }

    /// Check all active inputs and collect hangs.
    pub fn tick(&mut self) {
        let now = Instant::now();
        let timed_out: Vec<u64> = self.active
            .iter()
            .filter(|&(_, &start)| now.duration_since(start) >= self.timeout)
            .map(|(&id, _)| id)
            .collect();
        for id in timed_out {
            self.active.remove(&id);
            self.hangs.push(HangEvent {
                input_id: id,
                timeout: self.timeout,
                detected_at: now,
            });
        }
    }

    #[must_use]
    pub fn hang_count(&self) -> usize {
        self.hangs.len()
    }

    pub fn hangs(&self) -> &[HangEvent] {
        &self.hangs
    }
}

// ---------------------------------------------------------------------------
// ReproResult — result of attempting to reproduce a crash
// ---------------------------------------------------------------------------

/// Outcome of a crash reproduction attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReproOutcome {
    Reproduced,
    NotReproduced,
    Inconclusive,
    DifferentSignal(String),
}

/// Full result of a reproduction attempt.
#[derive(Debug, Clone)]
pub struct ReproResult {
    pub report_id: u64,
    pub outcome: ReproOutcome,
    pub attempts: u32,
    pub repro_input: Option<Vec<u8>>,
    pub notes: String,
}

impl ReproResult {
    #[must_use]
    pub fn reproduced(report_id: u64, attempts: u32, input: Vec<u8>) -> Self {
        Self {
            report_id,
            outcome: ReproOutcome::Reproduced,
            attempts,
            repro_input: Some(input),
            notes: String::new(),
        }
    }

    #[must_use]
    pub fn not_reproduced(report_id: u64, attempts: u32) -> Self {
        Self {
            report_id,
            outcome: ReproOutcome::NotReproduced,
            attempts,
            repro_input: None,
            notes: "Crash not observed on replay".to_owned(),
        }
    }

    #[must_use]
    pub fn is_confirmed(&self) -> bool {
        self.outcome == ReproOutcome::Reproduced
    }
}

// ---------------------------------------------------------------------------
// CrashReproducer — simplifies crash inputs via delta debugging
// ---------------------------------------------------------------------------

/// Simplifies a crash-triggering input using a minimization strategy.
pub struct CrashReproducer {
    max_iterations: usize,
}

impl CrashReproducer {
    pub fn new(max_iterations: usize) -> Self {
        Self { max_iterations }
    }

    /// Minimise `input` by binary-delta removing chunks and checking `predicate`.
    /// `predicate(bytes) -> bool` returns true if the crash still occurs.
    pub fn minimise<F>(&self, input: &[u8], mut predicate: F) -> Vec<u8>
    where
        F: FnMut(&[u8]) -> bool,
    {
        if input.is_empty() {
            return Vec::new();
        }
        let mut current = input.to_vec();
        let mut granularity = current.len() / 2;
        let mut iters = 0;

        while granularity > 0 && iters < self.max_iterations {
            let mut changed = false;
            let mut offset = 0;
            while offset < current.len() {
                let end = (offset + granularity).min(current.len());
                let mut candidate = current.clone();
                candidate.drain(offset..end);
                if predicate(&candidate) {
                    current = candidate;
                    changed = true;
                } else {
                    offset += granularity;
                }
                iters += 1;
                if iters >= self.max_iterations {
                    break;
                }
            }
            if !changed {
                granularity /= 2;
            }
        }
        current
    }
}

// ---------------------------------------------------------------------------
// CrashSummary — aggregate view across multiple detectors
// ---------------------------------------------------------------------------

/// Summary across all crash reports.
#[derive(Debug, Default)]
pub struct CrashSummary {
    pub total_unique: usize,
    pub by_signal: HashMap<String, usize>,
    pub highest_severity: u8,
    pub total_occurrences: u32,
}

impl CrashSummary {
    #[must_use]
    pub fn from_reports<'a>(reports: impl Iterator<Item = &'a CrashReport>) -> Self {
        let mut s = CrashSummary::default();
        for r in reports {
            s.total_unique += 1;
            *s.by_signal.entry(r.signal.name().to_owned()).or_default() += 1;
            if r.severity() > s.highest_severity {
                s.highest_severity = r.severity();
            }
            s.total_occurrences += r.occurrences;
        }
        s
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_crash_signal_severity() {
        assert!(CrashSignal::SanitizerOutput { line: String::new() }.severity() > CrashSignal::Timeout { elapsed_ms: 5000 }.severity());
    }

    #[test]
    fn test_bucket_hash_deterministic() {
        let sig = CrashSignal::ConnectionRefused;
        let input = b"hello world";
        let h1 = bucket_hash(&sig, input);
        let h2 = bucket_hash(&sig, input);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_bucket_hash_distinct() {
        let h1 = bucket_hash(&CrashSignal::ConnectionRefused, b"aaa");
        let h2 = bucket_hash(&CrashSignal::ConnectionReset, b"aaa");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_detect_sanitizer_output() {
        let text = "some output\n==ERROR: AddressSanitizer: heap-buffer-overflow\nmore text";
        let found = detect_sanitizer_output(text);
        assert!(found.is_some());
        assert!(found.unwrap().contains("AddressSanitizer"));
    }

    #[test]
    fn test_detect_sanitizer_none() {
        let text = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert!(detect_sanitizer_output(text).is_none());
    }

    #[test]
    fn test_crash_detector_conn_refused() {
        let mut det = CrashDetector::with_default_config();
        let report = det.analyse(
            b"input",
            None,
            Duration::from_millis(1),
            None,
            None,
            Some(ConnectionError::Refused),
        );
        assert!(report.is_some());
        assert_eq!(report.unwrap().signal, CrashSignal::ConnectionRefused);
    }

    #[test]
    fn test_crash_detector_dedup() {
        let mut det = CrashDetector::with_default_config();
        let r1 = det.analyse(b"input", None, Duration::from_millis(1), None, None, Some(ConnectionError::Refused));
        let r2 = det.analyse(b"input", None, Duration::from_millis(1), None, None, Some(ConnectionError::Refused));
        assert!(r1.is_some());
        assert!(r2.is_none()); // duplicate
        assert_eq!(det.unique_crashes(), 1);
        assert_eq!(det.total_crashes(), 2);
    }

    #[test]
    fn test_crash_detector_timeout() {
        let cfg = DetectorConfig {
            response_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let mut det = CrashDetector::new(cfg);
        let report = det.analyse(
            b"data",
            Some(b""),
            Duration::from_millis(200),
            None,
            None,
            None,
        );
        assert!(report.is_some());
        if let Some(r) = report {
            assert!(matches!(r.signal, CrashSignal::Timeout { .. }));
        }
    }

    #[test]
    fn test_crash_detector_sanitizer() {
        let cfg = DetectorConfig { scan_sanitizer: true, ..Default::default() };
        let mut det = CrashDetector::new(cfg);
        let resp = b"==ERROR: AddressSanitizer: use-after-free\n";
        let report = det.analyse(b"in", Some(resp), Duration::from_millis(10), None, None, None);
        assert!(report.is_some());
        assert!(matches!(report.unwrap().signal, CrashSignal::SanitizerOutput { .. }));
    }

    #[test]
    fn test_crash_detector_no_crash() {
        let mut det = CrashDetector::with_default_config();
        let report = det.analyse(b"in", Some(b"OK"), Duration::from_millis(10), None, Some(0), None);
        assert!(report.is_none());
    }

    #[test]
    fn test_hang_detector() {
        let mut hd = HangDetector::new(Duration::from_millis(0));
        let id = hd.register();
        std::thread::sleep(Duration::from_millis(1));
        hd.tick();
        assert_eq!(hd.hang_count(), 1);
        assert_eq!(hd.hangs()[0].input_id, id);
    }

    #[test]
    fn test_hang_detector_complete_no_hang() {
        let mut hd = HangDetector::new(Duration::from_millis(0));
        let id = hd.register();
        hd.complete(id);
        std::thread::sleep(Duration::from_millis(1));
        hd.tick();
        assert_eq!(hd.hang_count(), 0);
    }

    #[test]
    fn test_repro_result() {
        let r = ReproResult::reproduced(42, 3, b"input".to_vec());
        assert!(r.is_confirmed());
        let r2 = ReproResult::not_reproduced(42, 5);
        assert!(!r2.is_confirmed());
    }

    #[test]
    fn test_crash_reproducer_minimise() {
        let input: Vec<u8> = (0..16u8).collect();
        // Predicate: crash if byte 0 == 0 (crashes with minimal non-empty input containing byte 0)
        let repro = CrashReproducer::new(1000);
        let min = repro.minimise(&input, |b| b.contains(&0u8));
        assert!(!min.is_empty());
        assert!(min.contains(&0u8));
        assert!(min.len() <= input.len());
    }

    #[test]
    fn test_crash_summary() {
        let reports = vec![
            CrashReport::new(CrashSignal::ConnectionRefused, b"a".to_vec(), None, vec![]),
            CrashReport::new(CrashSignal::ConnectionReset, b"b".to_vec(), None, vec![]),
        ];
        let summary = CrashSummary::from_reports(reports.iter());
        assert_eq!(summary.total_unique, 2);
        assert_eq!(summary.total_occurrences, 2);
        assert!(summary.highest_severity >= 7);
    }

    #[test]
    fn test_crash_report_severity_order() {
        let mut det = CrashDetector::with_default_config();
        det.analyse(b"a", None, Duration::from_millis(1), None, None, Some(ConnectionError::Refused));
        let resp = b"AddressSanitizer: heap-buffer-overflow\n";
        det.analyse(b"b", Some(resp), Duration::from_millis(1), None, None, None);
        let sorted = det.reports_by_severity();
        if sorted.len() >= 2 {
            assert!(sorted[0].severity() >= sorted[1].severity());
        }
    }
}
