//! `LibFuzzer` crash reproduction.
//!
//! Provides [`LibFuzzerCrashReproducer`], [`ReproResult`], [`CrashInput`], and
//! [`LibFuzzerCrashReproducer::reproduce_crash`] for systematically verifying,
//! minimizing, and classifying crash-producing inputs.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by the crash reproducer.
#[derive(Debug, Error, Clone)]
pub enum ReproError {
    #[error("crash input is empty")]
    EmptyInput,

    #[error("target returned no crash for the provided input")]
    NoCrash,

    #[error("io error: {0}")]
    Io(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("minimization produced an empty input")]
    MinimizationEmpty,

    #[error("reproduction timed out after {0:?}")]
    Timeout(Duration),

    #[error("verification failed: {0}")]
    VerificationFailed(String),
}

// ─── CrashClass ───────────────────────────────────────────────────────────────

/// Coarse classification of the crash type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CrashClass {
    /// Heap-use-after-free.
    HeapUseAfterFree,
    /// Stack buffer overflow.
    StackBufferOverflow,
    /// Heap buffer overflow.
    HeapBufferOverflow,
    /// Null-pointer dereference.
    NullDeref,
    /// Integer overflow.
    IntegerOverflow,
    /// Division by zero.
    DivisionByZero,
    /// Undefined behaviour (generic).
    UndefinedBehaviour,
    /// Assertion failure.
    AssertionFailure,
    /// Panic (Rust panic / abort).
    Panic,
    /// Out-of-memory.
    Oom,
    /// Timeout / infinite loop.
    Timeout,
    /// Unknown crash type.
    Unknown,
}

impl CrashClass {
    /// Return a short string label for this class.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::HeapUseAfterFree => "heap_uaf",
            Self::StackBufferOverflow => "stack_bof",
            Self::HeapBufferOverflow => "heap_bof",
            Self::NullDeref => "null_deref",
            Self::IntegerOverflow => "int_overflow",
            Self::DivisionByZero => "div_zero",
            Self::UndefinedBehaviour => "ub",
            Self::AssertionFailure => "assertion",
            Self::Panic => "panic",
            Self::Oom => "oom",
            Self::Timeout => "timeout",
            Self::Unknown => "unknown",
        }
    }

    /// Infer a crash class from a signal number.
    #[must_use]
    pub const fn from_signal(sig: i32) -> Self {
        match sig {
            11 => Self::NullDeref,   // SIGSEGV
            6 => Self::AssertionFailure, // SIGABRT
            8 => Self::DivisionByZero,   // SIGFPE
            4 => Self::UndefinedBehaviour, // SIGILL
            _ => Self::Unknown,
        }
    }

    /// Infer from a sanitizer message prefix.
    #[must_use]
    pub fn from_message(msg: &str) -> Self {
        let m = msg.to_ascii_lowercase();
        if m.contains("heap-use-after-free") {
            Self::HeapUseAfterFree
        } else if m.contains("stack-buffer-overflow") {
            Self::StackBufferOverflow
        } else if m.contains("heap-buffer-overflow") {
            Self::HeapBufferOverflow
        } else if m.contains("null") && m.contains("deref") {
            Self::NullDeref
        } else if m.contains("integer overflow") || m.contains("signed integer overflow") {
            Self::IntegerOverflow
        } else if m.contains("division by zero") {
            Self::DivisionByZero
        } else if m.contains("undefined behaviour") || m.contains("undefined-behavior") {
            Self::UndefinedBehaviour
        } else if m.contains("assertion") || m.contains("assert") {
            Self::AssertionFailure
        } else if m.contains("panic") || m.contains("abort") {
            Self::Panic
        } else if m.contains("out of memory") || m.contains("oom") {
            Self::Oom
        } else if m.contains("timeout") {
            Self::Timeout
        } else {
            Self::Unknown
        }
    }
}

impl fmt::Display for CrashClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ─── CrashInput ───────────────────────────────────────────────────────────────

/// A single crash-producing input with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashInput {
    /// Raw bytes that triggered the crash.
    pub data: Vec<u8>,
    /// FNV-1a hash of `data` (unique identifier).
    pub hash: u64,
    /// Signal number that caused the crash (0 = not from signal).
    pub signal: i32,
    /// Human-readable crash message.
    pub message: String,
    /// Crash class inferred from the message.
    pub class: CrashClass,
    /// Path to the file containing this input (if loaded from disk).
    pub file_path: Option<PathBuf>,
    /// When this crash was first observed.
    pub found_at: SystemTime,
    /// Number of times this input has been confirmed to reproduce.
    pub repro_count: u32,
    /// Additional metadata key/value pairs.
    pub metadata: HashMap<String, String>,
}

impl CrashInput {
    /// Create a new crash input.
    #[must_use]
    pub fn new(data: Vec<u8>, signal: i32, message: impl Into<String>) -> Self {
        let message = message.into();
        let hash = fnv1a(&data);
        let class = CrashClass::from_message(&message);
        Self {
            data,
            hash,
            signal,
            message,
            class,
            file_path: None,
            found_at: SystemTime::now(),
            repro_count: 0,
            metadata: HashMap::new(),
        }
    }

    /// Set the crash class explicitly.
    #[must_use]
    pub const fn with_class(mut self, class: CrashClass) -> Self {
        self.class = class;
        self
    }

    /// Attach a file path.
    #[must_use]
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.file_path = Some(path.into());
        self
    }

    /// Insert metadata.
    #[must_use]
    pub fn with_meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Length of the input in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the input is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Return a summary line.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "[{}] sig={} len={} hash={:#016x}: {}",
            self.class,
            self.signal,
            self.data.len(),
            self.hash,
            &self.message[..self.message.len().min(80)],
        )
    }
}

// ─── ReproConfig ──────────────────────────────────────────────────────────────

/// Configuration for a reproduction run.
#[derive(Debug, Clone)]
pub struct ReproConfig {
    /// Number of times to run the target to confirm the crash.
    pub confirmation_runs: u32,
    /// Whether to attempt input minimization after confirming the crash.
    pub minimize: bool,
    /// Maximum bytes to prune during one minimization pass.
    pub min_chunk_size: usize,
    /// Maximum bytes to keep in the minimized input.
    pub max_minimized_size: usize,
    /// Per-run wall-clock timeout.
    pub run_timeout: Option<Duration>,
}

impl Default for ReproConfig {
    fn default() -> Self {
        Self {
            confirmation_runs: 3,
            minimize: true,
            min_chunk_size: 1,
            max_minimized_size: 4096,
            run_timeout: None,
        }
    }
}

// ─── ReproResult ─────────────────────────────────────────────────────────────

/// The result of a crash reproduction run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproResult {
    /// The original crash input.
    pub original: CrashInput,
    /// Minimized input, if minimization was requested and succeeded.
    pub minimized: Option<CrashInput>,
    /// Whether the crash was confirmed in all `confirmation_runs` attempts.
    pub confirmed: bool,
    /// How many confirmation runs succeeded.
    pub successful_runs: u32,
    /// How many confirmation runs failed (unexpected non-crash).
    pub failed_runs: u32,
    /// Crash class determined during reproduction.
    pub crash_class: CrashClass,
    /// Wall-clock time for the entire reproduction.
    pub elapsed: Duration,
    /// Any notes accumulated during reproduction.
    pub notes: Vec<String>,
}

impl ReproResult {
    /// Return the best available input (minimized if present, otherwise original).
    #[must_use]
    pub fn best_input(&self) -> &CrashInput {
        self.minimized.as_ref().unwrap_or(&self.original)
    }

    /// Size reduction: original length - minimized length.
    #[must_use]
    pub fn size_reduction(&self) -> usize {
        self.minimized.as_ref().map_or(0, |m| self.original.len().saturating_sub(m.len()))
    }
}

impl fmt::Display for ReproResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ReproResult {{ confirmed={}, class={}, runs={}/{}, reduction={}B, elapsed={:.2?} }}",
            self.confirmed,
            self.crash_class,
            self.successful_runs,
            self.successful_runs + self.failed_runs,
            self.size_reduction(),
            self.elapsed,
        )
    }
}

// ─── CrashTarget trait ────────────────────────────────────────────────────────

/// A fuzz target used during crash reproduction.
pub trait CrashTarget: Send {
    /// Run the target against `input`.
    ///
    /// Returns `Some(message)` if the target crashes, `None` otherwise.
    fn run(&mut self, input: &[u8]) -> Option<String>;

    /// Name of the target.
    fn name(&self) -> &'static str {
        "unknown"
    }
}

// ─── LibFuzzerCrashReproducer ─────────────────────────────────────────────────

/// Reproduces and optionally minimizes crash-producing inputs.
pub struct LibFuzzerCrashReproducer {
    /// Reproduction configuration.
    pub config: ReproConfig,
}

impl LibFuzzerCrashReproducer {
    /// Create a reproducer with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self { config: ReproConfig::default() }
    }

    /// Create with explicit configuration.
    #[must_use]
    pub const fn with_config(config: ReproConfig) -> Self {
        Self { config }
    }

    /// Reproduce a crash for `input`, using `target` to verify.
    ///
    /// 1. Runs the target `config.confirmation_runs` times to confirm the crash.
    /// 2. Optionally minimizes the input with a byte-removal pass.
    /// 3. Returns a detailed [`ReproResult`].
    ///
    /// # Errors
    /// Returns [`ReproError::EmptyInput`] if the input is empty.
    /// Returns [`ReproError::NoCrash`] if the target never crashed.
    pub fn reproduce_crash(
        &self,
        mut crash_input: CrashInput,
        target: &mut dyn CrashTarget,
    ) -> Result<ReproResult, ReproError> {
        if crash_input.is_empty() {
            return Err(ReproError::EmptyInput);
        }

        let start = Instant::now();
        let mut notes = Vec::new();

        // Phase 1 — Confirm the crash.
        let mut successful = 0u32;
        let mut failed = 0u32;
        let mut crash_message: Option<String> = None;

        for run in 0..self.config.confirmation_runs {
            // Respect per-run timeout.
            if let Some(limit) = self.config.run_timeout
                && start.elapsed() > limit {
                    return Err(ReproError::Timeout(start.elapsed()));
                }

            if let Some(msg) = target.run(&crash_input.data) {
                successful += 1;
                crash_message.get_or_insert_with(|| msg.clone());
                notes.push(format!("run {run}: crash confirmed — {msg}"));
            } else {
                failed += 1;
                notes.push(format!("run {run}: no crash"));
            }
        }

        if successful == 0 {
            return Err(ReproError::NoCrash);
        }

        crash_input.repro_count = successful;
        let crash_class = crash_message
            .as_deref()
            .map_or(CrashClass::Unknown, CrashClass::from_message);
        crash_input.class = crash_class.clone();

        // Phase 2 — Optional minimization.
        let minimized = if self.config.minimize && crash_input.len() > 1 {
            match self.minimize_input(&crash_input, target, &mut notes) {
                Ok(m) => Some(m),
                Err(e) => {
                    notes.push(format!("minimization skipped: {e}"));
                    None
                }
            }
        } else {
            None
        };

        let confirmed = failed == 0;
        Ok(ReproResult {
            original: crash_input,
            minimized,
            confirmed,
            successful_runs: successful,
            failed_runs: failed,
            crash_class,
            elapsed: start.elapsed(),
            notes,
        })
    }

    /// Byte-removal minimization: iteratively remove chunks and verify the crash
    /// persists.
    fn minimize_input(
        &self,
        input: &CrashInput,
        target: &mut dyn CrashTarget,
        notes: &mut Vec<String>,
    ) -> Result<CrashInput, ReproError> {
        let max_size = self.config.max_minimized_size.max(1);
        let chunk = self.config.min_chunk_size.max(1);

        let mut current = input.data.clone();
        if current.len() > max_size {
            current.truncate(max_size);
        }

        let mut i = 0usize;
        let mut passes = 0u32;
        const MAX_PASSES: u32 = 20;

        while i < current.len() && passes < MAX_PASSES {
            let end = (i + chunk).min(current.len());
            let candidate: Vec<u8> = current[..i]
                .iter()
                .chain(&current[end..])
                .copied()
                .collect();

            if candidate.is_empty() {
                break;
            }

            if target.run(&candidate).is_some() {
                // Removal preserved the crash — keep it.
                notes.push(format!(
                    "minimization: removed {} bytes at offset {i}",
                    end - i
                ));
                current = candidate;
                passes += 1;
                // Don't advance i — try removing at the same position again.
            } else {
                // Removal fixed the crash — advance past this chunk.
                i += chunk;
            }
        }

        if current.is_empty() {
            return Err(ReproError::MinimizationEmpty);
        }

        let mut minimized = CrashInput::new(current, input.signal, input.message.clone());
        minimized.class = input.class.clone();
        Ok(minimized)
    }

    /// Load a crash input from raw bytes and a signal number.
    #[must_use]
    pub fn load_from_bytes(data: Vec<u8>, signal: i32) -> CrashInput {
        let msg = format!("signal {signal}");
        CrashInput::new(data, signal, msg)
    }

    /// Load a crash input from a file path (simulated — reads from memory).
    ///
    /// In production this would perform actual file I/O; here we accept the
    /// bytes directly to keep the implementation self-contained.
    ///
    /// # Errors
    /// Returns [`ReproError::Io`] if the provided path hint is empty.
    pub fn load_from_path(path: &Path, data: Vec<u8>, signal: i32) -> Result<CrashInput, ReproError> {
        if path.as_os_str().is_empty() {
            return Err(ReproError::Io("empty path".to_string()));
        }
        let msg = format!("signal {signal} from {}", path.display());
        let mut ci = CrashInput::new(data, signal, msg);
        ci.file_path = Some(path.to_path_buf());
        Ok(ci)
    }

    /// Deduplicate a list of crash inputs by their hash.
    #[must_use]
    pub fn deduplicate(inputs: Vec<CrashInput>) -> Vec<CrashInput> {
        let mut seen = std::collections::HashSet::new();
        inputs.into_iter().filter(|c| seen.insert(c.hash)).collect()
    }

    /// Group crash inputs by their [`CrashClass`].
    #[must_use]
    pub fn group_by_class(inputs: &[CrashInput]) -> HashMap<String, Vec<&CrashInput>> {
        let mut map: HashMap<String, Vec<&CrashInput>> = HashMap::new();
        for ci in inputs {
            map.entry(ci.class.label().to_string())
                .or_default()
                .push(ci);
        }
        map
    }
}

impl Default for LibFuzzerCrashReproducer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── CrashDatabase ────────────────────────────────────────────────────────────

/// An in-memory store of confirmed crash inputs.
#[derive(Debug, Clone, Default)]
pub struct CrashDatabase {
    entries: Vec<CrashInput>,
}

impl CrashDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a crash input (deduplicated by hash).
    pub fn insert(&mut self, crash: CrashInput) -> bool {
        if self.entries.iter().any(|c| c.hash == crash.hash) {
            return false;
        }
        self.entries.push(crash);
        true
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Retrieve by hash.
    #[must_use]
    pub fn get_by_hash(&self, hash: u64) -> Option<&CrashInput> {
        self.entries.iter().find(|c| c.hash == hash)
    }

    /// All entries.
    #[must_use]
    pub fn all(&self) -> &[CrashInput] {
        &self.entries
    }

    /// Count crashes per class.
    #[must_use]
    pub fn class_histogram(&self) -> HashMap<String, usize> {
        let mut m: HashMap<String, usize> = HashMap::new();
        for c in &self.entries {
            *m.entry(c.class.label().to_string()).or_insert(0) += 1;
        }
        m
    }

    /// Return the smallest crash input by byte length.
    #[must_use]
    pub fn smallest(&self) -> Option<&CrashInput> {
        self.entries.iter().min_by_key(|c| c.len())
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// FNV-1a (64-bit) hash.
#[inline]
fn fnv1a(data: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(PRIME);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Mock target ───────────────────────────────────────────────────────────

    struct CrashOnByte(u8);
    impl CrashTarget for CrashOnByte {
        fn run(&mut self, input: &[u8]) -> Option<String> {
            if input.contains(&self.0) {
                Some(format!("crash on byte 0x{:02x}", self.0))
            } else {
                None
            }
        }
        fn name(&self) -> &'static str {
            "CrashOnByte"
        }
    }

    struct AlwaysCrash;
    impl CrashTarget for AlwaysCrash {
        fn run(&mut self, _input: &[u8]) -> Option<String> {
            Some("always crashes".to_string())
        }
    }

    struct NeverCrash;
    impl CrashTarget for NeverCrash {
        fn run(&mut self, _input: &[u8]) -> Option<String> {
            None
        }
    }

    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_reproduce_crash_confirmed() {
        let reproducer = LibFuzzerCrashReproducer::with_config(ReproConfig {
            confirmation_runs: 3,
            minimize: false,
            ..Default::default()
        });
        let input = CrashInput::new(b"trigger\xff".to_vec(), 6, "test crash");
        let mut target = AlwaysCrash;
        let result = reproducer.reproduce_crash(input, &mut target).unwrap();
        assert!(result.confirmed);
        assert_eq!(result.successful_runs, 3);
        assert_eq!(result.failed_runs, 0);
    }

    #[test]
    fn test_reproduce_no_crash_error() {
        let reproducer = LibFuzzerCrashReproducer::new();
        let input = CrashInput::new(b"safe".to_vec(), 0, "no crash");
        let mut target = NeverCrash;
        let err = reproducer.reproduce_crash(input, &mut target).unwrap_err();
        assert!(matches!(err, ReproError::NoCrash));
    }

    #[test]
    fn test_reproduce_empty_input_error() {
        let reproducer = LibFuzzerCrashReproducer::new();
        let input = CrashInput::new(vec![], 6, "empty");
        let mut target = AlwaysCrash;
        let err = reproducer.reproduce_crash(input, &mut target).unwrap_err();
        assert!(matches!(err, ReproError::EmptyInput));
    }

    #[test]
    fn test_minimize_removes_safe_bytes() {
        // CrashOnByte(0xAA): only crashes if 0xAA is present.
        let reproducer = LibFuzzerCrashReproducer::with_config(ReproConfig {
            confirmation_runs: 1,
            minimize: true,
            min_chunk_size: 1,
            ..Default::default()
        });
        // Input: lots of padding + the trigger byte.
        let data: Vec<u8> = std::iter::repeat_n(0u8, 20)
            .chain(std::iter::once(0xAAu8))
            .collect();
        let input = CrashInput::new(data, 11, "heap_buffer_overflow");
        let mut target = CrashOnByte(0xAA);
        let result = reproducer.reproduce_crash(input, &mut target).unwrap();
        assert!(result.confirmed);
        if let Some(ref m) = result.minimized {
            // Minimized should be smaller.
            assert!(m.len() < result.original.len());
            // Must still contain the trigger byte.
            assert!(m.data.contains(&0xAA));
        }
    }

    #[test]
    fn test_crash_class_from_signal() {
        assert_eq!(CrashClass::from_signal(11), CrashClass::NullDeref);
        assert_eq!(CrashClass::from_signal(6), CrashClass::AssertionFailure);
        assert_eq!(CrashClass::from_signal(8), CrashClass::DivisionByZero);
        assert_eq!(CrashClass::from_signal(99), CrashClass::Unknown);
    }

    #[test]
    fn test_crash_class_from_message() {
        assert_eq!(
            CrashClass::from_message("ASAN: heap-use-after-free"),
            CrashClass::HeapUseAfterFree
        );
        assert_eq!(
            CrashClass::from_message("AddressSanitizer: heap-buffer-overflow"),
            CrashClass::HeapBufferOverflow
        );
        assert_eq!(
            CrashClass::from_message("panicked at 'index out of bounds'"),
            CrashClass::Panic
        );
    }

    #[test]
    fn test_crash_database_dedup() {
        let mut db = CrashDatabase::new();
        let c1 = CrashInput::new(b"same".to_vec(), 11, "crash");
        let c2 = CrashInput::new(b"same".to_vec(), 11, "crash"); // same hash
        assert!(db.insert(c1));
        assert!(!db.insert(c2)); // duplicate
        assert_eq!(db.len(), 1);
    }

    #[test]
    fn test_crash_database_histogram() {
        let mut db = CrashDatabase::new();
        db.insert(CrashInput::new(b"a".to_vec(), 11, "null deref").with_class(CrashClass::NullDeref));
        db.insert(CrashInput::new(b"b".to_vec(), 6, "panic").with_class(CrashClass::Panic));
        db.insert(CrashInput::new(b"c".to_vec(), 11, "null2").with_class(CrashClass::NullDeref));
        let h = db.class_histogram();
        assert_eq!(*h.get("null_deref").unwrap(), 2);
        assert_eq!(*h.get("panic").unwrap(), 1);
    }

    #[test]
    fn test_deduplicate_inputs() {
        let inputs = vec![
            CrashInput::new(b"dup".to_vec(), 11, "x"),
            CrashInput::new(b"dup".to_vec(), 11, "x"),
            CrashInput::new(b"unique".to_vec(), 11, "y"),
        ];
        let deduped = LibFuzzerCrashReproducer::deduplicate(inputs);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_load_from_bytes() {
        let ci = LibFuzzerCrashReproducer::load_from_bytes(b"crash".to_vec(), 11);
        assert_eq!(ci.signal, 11);
        assert!(!ci.is_empty());
    }

    #[test]
    fn test_group_by_class() {
        let inputs = vec![
            CrashInput::new(b"a".to_vec(), 11, "heap-buffer-overflow"),
            CrashInput::new(b"b".to_vec(), 11, "heap-buffer-overflow"),
            CrashInput::new(b"c".to_vec(), 11, "panic"),
        ];
        let groups = LibFuzzerCrashReproducer::group_by_class(&inputs);
        assert_eq!(groups.get("heap_bof").map_or(0, Vec::len), 2);
        assert_eq!(groups.get("panic").map_or(0, Vec::len), 1);
    }
}
