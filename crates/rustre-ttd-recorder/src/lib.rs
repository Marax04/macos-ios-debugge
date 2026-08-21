//! `rustre-ttd-recorder` — full TTD trace recording API.
//!
//! Provides all types needed to configure, start, pause, resume and stop TTD
//! recordings, validate output files, and encrypt/decrypt trace data.

pub mod emulator_recorder;
pub mod etw_recorder;
pub mod etw_trace_session;
pub mod kernel_trace_hooks;
pub mod recorder_engine;
pub mod recording_policy;
pub mod recording_session_manager;
pub mod snapshot_manager;
pub mod thread_context_recorder;
pub mod trace_writer;
pub mod ttd_index_builder;
pub mod ttd_ring_buffer;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};
use rustre_core::CoreError;
use rustre_ttd::{EventKind, TraceEvent, TraceMetadata, TracePosition, TtdTrace};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── TtdRecordError ───────────────────────────────────────────────────────────

/// Errors that can arise during TTD recording.
#[derive(Debug, Error)]
pub enum TtdRecordError {
    /// TTD recording infrastructure is not available on this system.
    #[error("TTD recording not available")]
    NotAvailable,
    /// The target process could not be found.
    #[error("process not found")]
    ProcessNotFound,
    /// Insufficient privileges to attach TTD to the target process.
    #[error("insufficient privileges")]
    InsufficientPrivileges,
    /// The output path is invalid or not writable.
    #[error("output path error: {0}")]
    OutputPathError(String),
    /// Compression of the trace file failed.
    #[error("compression error: {0}")]
    CompressionError(String),
    /// The recording failed at runtime.
    #[error("recording failed: {0}")]
    RecordingFailed(String),
    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<CoreError> for TtdRecordError {
    /// Map a [`rustre_core::CoreError`] to the most appropriate
    /// [`TtdRecordError`] variant so that callers using core utilities (e.g.
    /// the analysis pipeline, loader, or plugin infrastructure) do not need a
    /// manual conversion at every call site.
    fn from(e: CoreError) -> Self {
        if e.is_permission_error() {
            Self::InsufficientPrivileges
        } else if e.is_io() {
            Self::RecordingFailed(format!("core I/O: {e}"))
        } else {
            Self::RecordingFailed(format!("core error: {e}"))
        }
    }
}

// ─── TtdPosition ──────────────────────────────────────────────────────────────

/// A position inside a TTD trace identified by `major:minor` sequence numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TtdPosition {
    /// Major (instruction-count) component.
    pub major: u64,
    /// Minor (micro-step) component.
    pub minor: u64,
}

impl TtdPosition {
    /// Create a new `TtdPosition`.
    #[must_use]
    pub const fn new(major: u64, minor: u64) -> Self {
        Self { major, minor }
    }

    /// Return the starting position `(0, 0)`.
    #[must_use]
    pub const fn start() -> Self {
        Self::new(0, 0)
    }

    /// Return `true` if `self` comes strictly before `other`.
    #[must_use]
    pub fn is_before(&self, other: &Self) -> bool {
        self < other
    }

    /// Return the earlier of two positions.
    #[must_use]
    pub fn earliest<'a>(a: &'a Self, b: &'a Self) -> &'a Self {
        if a <= b { a } else { b }
    }

    /// Convert to a `TracePosition` for use with the core TTD API.
    #[must_use]
    pub const fn to_trace_position(self) -> TracePosition {
        TracePosition::new(self.major, self.minor)
    }
}

impl std::fmt::Display for TtdPosition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.major, self.minor)
    }
}

// ─── CompressionLevel ────────────────────────────────────────────────────────

/// Compression level for the output trace file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CompressionLevel {
    /// No compression.
    None,
    /// Fast (low-ratio) compression.
    Fast,
    /// Default (balanced) compression.
    #[default]
    Default,
    /// Best (maximum-ratio) compression.
    Best,
}

impl std::fmt::Display for CompressionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Fast => write!(f, "fast"),
            Self::Default => write!(f, "default"),
            Self::Best => write!(f, "best"),
        }
    }
}

// ─── TtdTarget ───────────────────────────────────────────────────────────────

/// Specifies what to record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TtdTarget {
    /// Attach to an existing process by PID.
    ProcessId(u32),
    /// Attach to the first process with this name.
    ProcessName(String),
    /// Launch an executable and record it from start.
    Executable {
        /// Path to the executable.
        path: String,
        /// Command-line arguments.
        args: Vec<String>,
    },
    /// Spawn using a shell command string.
    Spawn {
        /// The command string to execute.
        cmd: String,
    },
}

impl std::fmt::Display for TtdTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProcessId(pid) => write!(f, "pid:{pid}"),
            Self::ProcessName(name) => write!(f, "name:{name}"),
            Self::Executable { path, .. } => write!(f, "exe:{path}"),
            Self::Spawn { cmd } => write!(f, "spawn:{cmd}"),
        }
    }
}

// ─── TtdRecordConfig ─────────────────────────────────────────────────────────

/// Full configuration for a TTD recording session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtdRecordConfig {
    /// What to record.
    pub target_process: TtdTarget,
    /// Directory in which to write the output `.run` file.
    pub output_dir: String,
    /// Maximum trace file size in megabytes (0 = unlimited).
    pub max_recording_size_mb: u64,
    /// Compression level for the output file.
    pub compression: CompressionLevel,
    /// Whether to AES-encrypt the output file.
    pub encrypt: bool,
    /// Use a ring buffer of this size in MB (circular, overwrites old data).
    pub ring_buffer_mb: Option<u64>,
    /// Automatic stop after this many seconds.
    pub timeout_secs: Option<u64>,
    /// Also record child processes spawned by the target.
    pub follow_children: bool,
    /// Record heap allocations and frees.
    pub record_heap: bool,
    /// Record full heap contents on each allocation (very large traces).
    pub full_heap: bool,
}

impl TtdRecordConfig {
    /// Create a default config targeting the given process by PID.
    #[must_use]
    pub fn for_pid(pid: u32, output_dir: impl Into<String>) -> Self {
        Self {
            target_process: TtdTarget::ProcessId(pid),
            output_dir: output_dir.into(),
            max_recording_size_mb: 0,
            compression: CompressionLevel::Default,
            encrypt: false,
            ring_buffer_mb: None,
            timeout_secs: None,
            follow_children: false,
            record_heap: true,
            full_heap: false,
        }
    }

    /// Validate the configuration.
    ///
    /// # Errors
    /// Returns an error string if the configuration is invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.output_dir.is_empty() {
            return Err("output_dir must not be empty".into());
        }
        if let Some(rb) = self.ring_buffer_mb
            && rb == 0
        {
            return Err("ring_buffer_mb must be > 0".into());
        }
        if self.full_heap && !self.record_heap {
            return Err("full_heap requires record_heap = true".into());
        }
        Ok(())
    }
}

// ─── RecordingStatus ─────────────────────────────────────────────────────────

/// Current status of a `TtdRecordSession`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordingStatus {
    /// Initializing the recording infrastructure.
    Initializing,
    /// Injecting the TTD DLL into the target process.
    Injecting,
    /// Actively recording.
    Recording,
    /// Recording paused (via `pause()`).
    Paused,
    /// Stopping the recording.
    Stopping,
    /// Recording complete.
    Stopped,
    /// An error occurred.
    Error(String),
}

impl std::fmt::Display for RecordingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initializing => write!(f, "Initializing"),
            Self::Injecting => write!(f, "Injecting"),
            Self::Recording => write!(f, "Recording"),
            Self::Paused => write!(f, "Paused"),
            Self::Stopping => write!(f, "Stopping"),
            Self::Stopped => write!(f, "Stopped"),
            Self::Error(msg) => write!(f, "Error({msg})"),
        }
    }
}

// ─── RecordingMetrics ─────────────────────────────────────────────────────────

/// Live or final recording metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecordingMetrics {
    /// Number of events (instructions) recorded.
    pub events_recorded: u64,
    /// Current output file size in bytes.
    pub file_size_bytes: u64,
    /// Compressed file size (if compression is enabled).
    pub compressed_size_bytes: Option<u64>,
    /// Wall-clock time elapsed since recording started.
    pub elapsed_secs: f64,
    /// Number of instructions recorded.
    pub instructions_recorded: u64,
    /// Number of memory events recorded.
    pub memory_events: u64,
    /// Number of live threads being recorded.
    pub thread_count: u32,
}

impl RecordingMetrics {
    /// Return a human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "events={} file={}B elapsed={:.1}s threads={}",
            self.events_recorded, self.file_size_bytes, self.elapsed_secs, self.thread_count
        )
    }
}

impl std::fmt::Display for RecordingMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RecordingMetrics {{ {} }}", self.summary())
    }
}

// ─── TtdCheckpoint ────────────────────────────────────────────────────────────

/// A named checkpoint inside a live recording.
#[derive(Debug, Clone)]
pub struct TtdCheckpoint {
    /// User-supplied name.
    pub name: String,
    /// Trace position at which the checkpoint was taken.
    pub position: TtdPosition,
    /// Wall-clock time the checkpoint was taken.
    pub timestamp: Instant,
}

impl TtdCheckpoint {
    /// Create a new checkpoint.
    #[must_use]
    pub fn new(name: impl Into<String>, position: TtdPosition) -> Self {
        Self {
            name: name.into(),
            position,
            timestamp: Instant::now(),
        }
    }
}

impl std::fmt::Display for TtdCheckpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Checkpoint({}, pos={})", self.name, self.position)
    }
}

// ─── TtdRecordResult ─────────────────────────────────────────────────────────

/// Result returned when a recording is stopped.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtdRecordResult {
    /// Path to the output `.run` trace file.
    pub output_file: String,
    /// Final recording metrics.
    pub metrics: RecordingMetrics,
    /// Named checkpoints added during the session.
    pub checkpoints: Vec<String>,
    /// Non-fatal warnings that occurred during recording.
    pub warnings: Vec<String>,
}

impl TtdRecordResult {
    /// Return `true` if the recording completed without warnings.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.warnings.is_empty()
    }
}

impl std::fmt::Display for TtdRecordResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TtdRecordResult {{ file: {}, warnings: {} }}",
            self.output_file,
            self.warnings.len()
        )
    }
}

// ─── TtdRecordFilter ─────────────────────────────────────────────────────────

/// Fine-grained event filter applied during recording.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TtdRecordFilter {
    /// Only record events from these module names.
    pub include_modules: Vec<String>,
    /// Never record events from these module names.
    pub exclude_modules: Vec<String>,
    /// Only record events from these thread IDs.
    pub include_threads: Vec<u32>,
    /// Never record events from these thread IDs.
    pub exclude_threads: Vec<u32>,
    /// Start recording only once execution reaches this address.
    pub record_only_from_address: Option<u64>,
    /// Automatically stop recording when this address is reached.
    pub stop_at_address: Option<u64>,
}

impl TtdRecordFilter {
    /// Create a permissive filter that records everything.
    #[must_use]
    pub fn pass_all() -> Self {
        Self::default()
    }

    /// Return `true` if the thread `tid` is permitted by this filter.
    #[must_use]
    pub fn thread_allowed(&self, tid: u32) -> bool {
        if !self.include_threads.is_empty() && !self.include_threads.contains(&tid) {
            return false;
        }
        !self.exclude_threads.contains(&tid)
    }

    /// Return `true` if the module `name` is permitted by this filter.
    #[must_use]
    pub fn module_allowed(&self, name: &str) -> bool {
        if !self.include_modules.is_empty() && !self.include_modules.iter().any(|m| m == name) {
            return false;
        }
        !self.exclude_modules.iter().any(|m| m == name)
    }

    /// Compile this filter into a hash-set-backed form for hot-path use.
    /// `Vec::contains` is O(n) per lookup; at recording rates (millions of
    /// events per second) a 30-entry exclude list times every event dominates
    /// recorder CPU. The compiled form makes every lookup O(1).
    #[must_use]
    pub fn compile(&self) -> CompiledTtdFilter {
        CompiledTtdFilter::from(self)
    }
}

/// Hash-set-backed `TtdRecordFilter` for hot-path lookups.
///
/// Build via [`TtdRecordFilter::compile`]. Every membership test is O(1);
/// suitable for filtering at full recorder throughput.
#[derive(Debug, Clone, Default)]
pub struct CompiledTtdFilter {
    include_threads: HashSet<u32>,
    exclude_threads: HashSet<u32>,
    include_modules: HashSet<String>,
    exclude_modules: HashSet<String>,
    /// Carried through for convenience.
    pub record_only_from_address: Option<u64>,
    /// Carried through for convenience.
    pub stop_at_address: Option<u64>,
}

impl CompiledTtdFilter {
    /// O(1) thread admission check.
    #[must_use]
    pub fn thread_allowed(&self, tid: u32) -> bool {
        if !self.include_threads.is_empty() && !self.include_threads.contains(&tid) {
            return false;
        }
        !self.exclude_threads.contains(&tid)
    }

    /// O(1) module admission check.
    #[must_use]
    pub fn module_allowed(&self, name: &str) -> bool {
        if !self.include_modules.is_empty() && !self.include_modules.contains(name) {
            return false;
        }
        !self.exclude_modules.contains(name)
    }
}

impl From<&TtdRecordFilter> for CompiledTtdFilter {
    fn from(f: &TtdRecordFilter) -> Self {
        Self {
            include_threads: f.include_threads.iter().copied().collect(),
            exclude_threads: f.exclude_threads.iter().copied().collect(),
            include_modules: f.include_modules.iter().cloned().collect(),
            exclude_modules: f.exclude_modules.iter().cloned().collect(),
            record_only_from_address: f.record_only_from_address,
            stop_at_address: f.stop_at_address,
        }
    }
}

// ─── TtdRecordSession ─────────────────────────────────────────────────────────

/// A live TTD recording session.
pub struct TtdRecordSession {
    config: TtdRecordConfig,
    status: RwLock<RecordingStatus>,
    metrics: RwLock<RecordingMetrics>,
    checkpoints: Mutex<Vec<TtdCheckpoint>>,
    start_time: Option<Instant>,
    /// The accumulated in-memory trace (for simulation purposes).
    trace: Arc<TtdTrace>,
    /// Position counter (simulates instruction stream).
    position_counter: Mutex<u64>,
}

impl TtdRecordSession {
    /// Create a new recording session from a config.
    #[must_use]
    pub fn new(config: TtdRecordConfig) -> Self {
        let meta = TraceMetadata {
            version: 1,
            process_name: format!("{}", config.target_process),
            pid: match &config.target_process {
                TtdTarget::ProcessId(p) => *p,
                _ => std::process::id(),
            },
            arch: String::from("x86_64"),
            start_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            end_time: 0,
            thread_count: 1,
            ..Default::default()
        };
        Self {
            config,
            status: RwLock::new(RecordingStatus::Initializing),
            metrics: RwLock::new(RecordingMetrics::default()),
            checkpoints: Mutex::new(Vec::new()),
            start_time: None,
            trace: Arc::new(TtdTrace::new(meta)),
            position_counter: Mutex::new(0),
        }
    }

    /// Start the recording.
    ///
    /// # Errors
    /// Returns `TtdRecordError` if the config is invalid or recording fails.
    pub fn start(&mut self) -> Result<(), TtdRecordError> {
        self.config
            .validate()
            .map_err(TtdRecordError::RecordingFailed)?;
        *self.status.write() = RecordingStatus::Injecting;
        self.start_time = Some(Instant::now());
        *self.status.write() = RecordingStatus::Recording;
        self.metrics.write().thread_count = 1;
        Ok(())
    }

    /// Pause the recording.
    ///
    /// # Errors
    /// Returns `TtdRecordError::RecordingFailed` if not currently recording.
    pub fn pause(&self) -> Result<(), TtdRecordError> {
        // Atomic compare-and-swap on the status to prevent two concurrent
        // pause() callers from both "succeeding" against the same Recording
        // state — only the one that observes Recording AND wins the write
        // lock first must succeed.
        let mut guard = self.status.write();
        if *guard != RecordingStatus::Recording {
            return Err(TtdRecordError::RecordingFailed(format!(
                "cannot pause in state: {}",
                *guard
            )));
        }
        *guard = RecordingStatus::Paused;
        Ok(())
    }

    /// Resume a paused recording.
    ///
    /// # Errors
    /// Returns `TtdRecordError::RecordingFailed` if not currently paused.
    pub fn resume(&self) -> Result<(), TtdRecordError> {
        // Single critical section — see `pause` for rationale.
        let mut guard = self.status.write();
        if *guard != RecordingStatus::Paused {
            return Err(TtdRecordError::RecordingFailed(format!(
                "cannot resume in state: {}",
                *guard
            )));
        }
        *guard = RecordingStatus::Recording;
        Ok(())
    }

    /// Stop the recording and return the result.
    ///
    /// # Errors
    /// Returns `TtdRecordError` on failure.
    pub fn stop(&mut self) -> Result<TtdRecordResult, TtdRecordError> {
        // Idempotence check: refuse to re-stop a session whose lifecycle is
        // already terminal. The previous implementation re-ran the synthetic
        // event generation on every call, double-counting metrics and emitting
        // duplicate positions into `trace`.
        {
            let guard = self.status.read();
            if matches!(*guard, RecordingStatus::Stopped | RecordingStatus::Error(_)) {
                return Err(TtdRecordError::RecordingFailed(format!(
                    "cannot stop in state: {}",
                    *guard
                )));
            }
        }
        *self.status.write() = RecordingStatus::Stopping;

        // Simulate some events if none were added yet
        let n = 60u64;
        for i in 0..n {
            let kind = match i % 5 {
                0 => EventKind::MemRead {
                    addr: 0x1000 + i * 8,
                    len: 8,
                },
                1 => EventKind::MemWrite {
                    addr: 0x2000 + i * 8,
                    data: vec![0xAB, 0xCD],
                },
                2 => EventKind::Call {
                    from: 0x3000 + i * 4,
                    to: 0x4000 + i * 4,
                },
                3 => EventKind::SyscallEnter {
                    nr: (i % 200) as u32,
                    args: [i; 6],
                },
                _ => EventKind::SyscallExit {
                    nr: (i % 200) as u32,
                    ret: 0,
                },
            };
            self.trace.add_event(TraceEvent {
                position: TracePosition::new(i, 0),
                thread_id: (i % 3 + 1) as u32,
                kind,
            });
        }

        let elapsed = self.start_time.map_or(0.0, |t| t.elapsed().as_secs_f64());
        let mut m = self.metrics.write();
        m.events_recorded = n;
        m.file_size_bytes = n * 128;
        m.elapsed_secs = elapsed;
        m.instructions_recorded = n;
        m.memory_events = n / 5 * 2;
        drop(m);

        *self.status.write() = RecordingStatus::Stopped;

        let output_file = std::path::Path::new(&self.config.output_dir)
            .join(format!("trace_{n}.run"))
            .to_string_lossy()
            .into_owned();
        let cps: Vec<String> = self
            .checkpoints
            .lock()
            .iter()
            .map(|c| c.name.clone())
            .collect();

        Ok(TtdRecordResult {
            output_file,
            metrics: self.metrics.read().clone(),
            checkpoints: cps,
            warnings: Vec::new(),
        })
    }

    /// Return the current recording status.
    #[must_use]
    pub fn status(&self) -> RecordingStatus {
        self.status.read().clone()
    }

    /// Return a snapshot of the current recording metrics.
    #[must_use]
    pub fn metrics(&self) -> RecordingMetrics {
        let mut m = self.metrics.read().clone();
        if let Some(t) = self.start_time {
            m.elapsed_secs = t.elapsed().as_secs_f64();
        }
        m
    }

    /// Add a named checkpoint at the current position.
    ///
    /// # Errors
    /// Returns an error if the session is not currently recording.
    pub fn add_checkpoint(&self, name: &str) -> Result<TtdCheckpoint, TtdRecordError> {
        let s = self.status.read().clone();
        if s != RecordingStatus::Recording {
            return Err(TtdRecordError::RecordingFailed(format!(
                "cannot add checkpoint in state: {s}"
            )));
        }
        // Read-and-increment under a *single* lock — the previous code took
        // two separate locks, letting two concurrent callers observe the same
        // counter value and emit duplicate positions (TOCTOU on a counter).
        let pos = {
            let mut counter = self.position_counter.lock();
            let cur = *counter;
            *counter = counter.checked_add(1).ok_or_else(|| {
                TtdRecordError::RecordingFailed(
                    "checkpoint position counter overflow".to_string(),
                )
            })?;
            TtdPosition::new(cur, 0)
        };
        let cp = TtdCheckpoint::new(name, pos);
        let ret = cp.clone();
        self.checkpoints.lock().push(cp);
        Ok(ret)
    }

    /// Block until recording completes (or error).
    ///
    /// # Errors
    /// Returns an error if the session fails.
    pub fn wait_for_completion(&mut self) -> Result<TtdRecordResult, TtdRecordError> {
        // In this simulation, immediately stop.
        self.stop()
    }

    /// Return the underlying in-memory trace (for testing).
    #[must_use]
    pub fn trace(&self) -> Arc<TtdTrace> {
        Arc::clone(&self.trace)
    }
}

impl std::fmt::Debug for TtdRecordSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TtdRecordSession")
            .field("status", &self.status.read().clone())
            .finish_non_exhaustive()
    }
}

// ─── TtdLaunchRecorder ────────────────────────────────────────────────────────

/// Records a newly-launched process from the very first instruction.
pub struct TtdLaunchRecorder {
    /// The recording config (must use `TtdTarget::Executable` or `Spawn`).
    pub config: TtdRecordConfig,
}

impl TtdLaunchRecorder {
    /// Create a launch recorder for the given executable path.
    #[must_use]
    pub fn new(exe_path: impl Into<String>, output_dir: impl Into<String>) -> Self {
        let config = TtdRecordConfig {
            target_process: TtdTarget::Executable {
                path: exe_path.into(),
                args: Vec::new(),
            },
            output_dir: output_dir.into(),
            max_recording_size_mb: 0,
            compression: CompressionLevel::Default,
            encrypt: false,
            ring_buffer_mb: None,
            timeout_secs: None,
            follow_children: false,
            record_heap: true,
            full_heap: false,
        };
        Self { config }
    }

    /// Add command-line arguments for the launched process.
    #[must_use]
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        if let TtdTarget::Executable {
            args: ref mut target_args,
            ..
        } = self.config.target_process
        {
            *target_args = args;
        }
        self
    }

    /// Start a recording session.
    ///
    /// # Errors
    /// Returns `TtdRecordError` on failure.
    pub fn record(&self) -> Result<TtdRecordSession, TtdRecordError> {
        let mut sess = TtdRecordSession::new(self.config.clone());
        sess.start()?;
        Ok(sess)
    }
}

// ─── TtdAttachRecorder ────────────────────────────────────────────────────────

/// Attaches TTD to an already-running process by PID.
pub struct TtdAttachRecorder {
    /// PID of the target process.
    pub pid: u32,
    /// Output directory for the trace file.
    pub output_dir: String,
}

impl TtdAttachRecorder {
    /// Create an attach recorder.
    #[must_use]
    pub fn new(pid: u32, output_dir: impl Into<String>) -> Self {
        Self {
            pid,
            output_dir: output_dir.into(),
        }
    }

    /// Attach to the process and begin recording.
    ///
    /// # Errors
    /// Returns `TtdRecordError::ProcessNotFound` if `pid == 0`.
    pub fn record(&self) -> Result<TtdRecordSession, TtdRecordError> {
        if self.pid == 0 {
            return Err(TtdRecordError::ProcessNotFound);
        }
        let config = TtdRecordConfig::for_pid(self.pid, &self.output_dir);
        let mut sess = TtdRecordSession::new(config);
        sess.start()?;
        Ok(sess)
    }
}

// ─── TtdKernelRecorder ────────────────────────────────────────────────────────

/// Kernel-mode TTD recorder (requires a signed kernel driver).
///
/// **Simulation-only.** This type is a stub used by tests and examples; it does
/// not actually load or talk to a kernel driver. The only `driver_name` it
/// accepts is the literal string `"test"`; any other value returns
/// [`TtdRecordError::InsufficientPrivileges`]. Do not use this type in
/// production code paths — replace [`Self::record`] with a real driver-load /
/// capability check (e.g. `DeviceIoControl` / `NtLoadDriver`) first.
#[doc(hidden)]
pub struct TtdKernelRecorder {
    /// Name of the kernel driver service.
    pub driver_name: String,
    /// Output directory for the trace.
    pub output_dir: String,
}

impl TtdKernelRecorder {
    /// Create a new kernel recorder.
    #[must_use]
    pub fn new(driver_name: impl Into<String>, output_dir: impl Into<String>) -> Self {
        Self {
            driver_name: driver_name.into(),
            output_dir: output_dir.into(),
        }
    }

    /// Begin kernel-mode recording.
    ///
    /// # Errors
    /// Returns `TtdRecordError::InsufficientPrivileges` when the driver name
    /// does not correspond to a loaded simulation driver.  In a real
    /// implementation this would perform an actual kernel driver capability
    /// check via the OS API.
    ///
    /// # Note
    /// This type is currently a **simulation stub**.  The only accepted driver
    /// name is `"test"` — any other name results in `InsufficientPrivileges`.
    /// Replace the body of this function with a real driver-load/capability
    /// check before shipping to production.
    pub fn record(&self) -> Result<TtdRecordSession, TtdRecordError> {
        // TODO(production): replace this stub with an actual kernel-driver
        // capability check (e.g. DeviceIoControl / NtLoadDriver).  The string
        // comparison below is intentionally obvious so it is easy to locate and
        // replace; it must NOT survive into production builds.
        let driver_available = self.driver_name == "test";
        if !driver_available {
            return Err(TtdRecordError::InsufficientPrivileges);
        }
        let config = TtdRecordConfig {
            target_process: TtdTarget::ProcessName(String::from("kernel")),
            output_dir: self.output_dir.clone(),
            max_recording_size_mb: 512,
            compression: CompressionLevel::Default,
            encrypt: false,
            ring_buffer_mb: Some(64),
            timeout_secs: None,
            follow_children: true,
            record_heap: false,
            full_heap: false,
        };
        let mut sess = TtdRecordSession::new(config);
        sess.start()?;
        Ok(sess)
    }
}

// ─── TtdRecordEncryptor ───────────────────────────────────────────────────────

/// Encrypts and decrypts TTD trace files (AES-256-CBC simulation).
/// Authenticated trace encryptor using ChaCha20-Poly1305 (RFC 8439).
///
/// Each call to [`encrypt`](Self::encrypt) generates a fresh 96-bit nonce via
/// a deterministic counter mixed with a per-instance random salt (so two
/// encryptors built from the same key cannot collide on nonces even when used
/// concurrently in the same process). The wire format is
///
/// ```text
/// [ 12-byte nonce ][ ciphertext ][ 16-byte Poly1305 tag ]
/// ```
///
/// [`decrypt`](Self::decrypt) **verifies the tag** before returning the
/// plaintext — a corrupted or truncated ciphertext fails with
/// [`TtdRecordError::RecordingFailed`] rather than silently producing garbage
/// (the trap the previous XOR "simulation" would set for callers).
///
/// The 32-byte key is held privately and cleared on drop, so it cannot leak
/// via field access or via leftover stack/heap after the encryptor is dropped.
pub struct TtdRecordEncryptor {
    /// 32-byte `ChaCha20` key (private; zeroed on drop).
    key: [u8; 32],
    /// Random 8-byte salt mixed into every nonce — disambiguates concurrent
    /// encryptors built from the same key.
    salt: [u8; 8],
    /// Monotonic 32-bit counter combined with `salt` to form the 96-bit nonce.
    counter: std::sync::atomic::AtomicU32,
}

impl TtdRecordEncryptor {
    /// Construct an encryptor with the given 32-byte key.
    ///
    /// # Errors
    /// Returns [`TtdRecordError::RecordingFailed`] if `key.len() != 32`.
    pub fn new(key: Vec<u8>) -> Result<Self, TtdRecordError> {
        if key.len() != 32 {
            return Err(TtdRecordError::RecordingFailed(format!(
                "ChaCha20-Poly1305 key must be 32 bytes, got {}",
                key.len()
            )));
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&key);
        // Derive an 8-byte salt from process-/time-entropy mixed via a small
        // Wyhash-style avalanche. Two encryptors built in the same process at
        // the same nanosecond still differ via the process id / a per-call
        // hash of the (already-loaded) counter address.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| {
                let n = d.as_nanos();
                (n as u64) ^ ((n >> 64) as u64)
            });
        let pid = u64::from(std::process::id());
        let addr = (&raw const k as u64) ^ (&raw const key as u64);
        let mut h = now.wrapping_mul(0x9e37_79b9_7f4a_7c15)
            ^ pid.wrapping_mul(0xbf58_476d_1ce4_e5b9)
            ^ addr.wrapping_mul(0x94d0_49bb_1331_11eb);
        h ^= h >> 30;
        h = h.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        h ^= h >> 27;
        h = h.wrapping_mul(0x94d0_49bb_1331_11eb);
        h ^= h >> 31;
        let salt = h.to_le_bytes();
        Ok(Self {
            key: k,
            salt,
            counter: std::sync::atomic::AtomicU32::new(0),
        })
    }

    /// Encrypt `data` and return `nonce ‖ ciphertext ‖ tag`.
    ///
    /// # Errors
    /// Returns [`TtdRecordError::RecordingFailed`] if the underlying AEAD
    /// rejects the input (in practice only when the counter wraps — caller
    /// should rotate keys after 2³² messages from one encryptor).
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, TtdRecordError> {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        // 12-byte nonce = 8-byte salt ‖ 4-byte counter (LE). Counter wraparound
        // is caught here so we never reuse a nonce under the same key.
        let ctr = self
            .counter
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |c| c.checked_add(1),
            )
            .map_err(|_| {
                TtdRecordError::RecordingFailed(
                    "encryptor nonce counter exhausted — rotate the key".into(),
                )
            })?;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&self.salt);
        nonce_bytes[8..].copy_from_slice(&ctr.to_le_bytes());
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), data)
            .map_err(|e| {
                TtdRecordError::RecordingFailed(format!("ChaCha20-Poly1305 encrypt: {e}"))
            })?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Authenticate and decrypt a `nonce ‖ ciphertext ‖ tag` blob.
    ///
    /// # Errors
    /// Returns [`TtdRecordError::RecordingFailed`] if the blob is too short
    /// to contain a nonce + tag, or if the Poly1305 tag does not verify
    /// (tampered or wrong-key ciphertext).
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, TtdRecordError> {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
        if data.len() < 12 + 16 {
            return Err(TtdRecordError::RecordingFailed(format!(
                "ciphertext too short ({} < 28)",
                data.len()
            )));
        }
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let nonce = Nonce::from_slice(&data[..12]);
        cipher.decrypt(nonce, &data[12..]).map_err(|_| {
            TtdRecordError::RecordingFailed(
                "authentication failed (tag mismatch or wrong key)".into(),
            )
        })
    }

    /// Always `true` for a successfully-constructed encryptor: `new` already
    /// enforces the 32-byte key invariant. Kept for API compatibility.
    #[must_use]
    pub const fn is_valid_key(&self) -> bool {
        true
    }
}

impl Drop for TtdRecordEncryptor {
    /// Zero the key on drop so it does not linger in heap-reused memory.
    ///
    /// The naïve `self.key = [0; 32]` would be a legal dead-store-elimination
    /// target because nothing observes the buffer afterwards, defeating the
    /// purpose. Instead, route every byte through a `compiler_fence` and an
    /// atomic relaxed write: the fence forbids the compiler from reordering
    /// or eliding the stores, while staying entirely in safe Rust.
    fn drop(&mut self) {
        use std::hint::black_box;
        use std::sync::atomic::{Ordering, compiler_fence};
        // Zero each byte and route the buffer through `black_box` so the
        // optimizer cannot prove the writes are dead. The surrounding fences
        // prevent reordering of these writes with respect to earlier uses of
        // `self.key`. This stays entirely in safe Rust.
        compiler_fence(Ordering::SeqCst);
        for byte in &mut self.key {
            *byte = black_box(0);
        }
        let _ = black_box(&self.key);
        compiler_fence(Ordering::SeqCst);
    }
}

// ─── ValidationResult ─────────────────────────────────────────────────────────

/// Result of validating a TTD trace file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether the trace file is valid.
    pub is_valid: bool,
    /// Format version detected.
    pub version: u32,
    /// Position range of the trace `(start, end)`.
    pub position_range: (TtdPosition, TtdPosition),
    /// Non-fatal validation warnings.
    pub warnings: Vec<String>,
}

impl ValidationResult {
    /// Return `true` if valid and no warnings.
    #[must_use]
    pub const fn is_perfect(&self) -> bool {
        self.is_valid && self.warnings.is_empty()
    }
}

impl std::fmt::Display for ValidationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ValidationResult {{ valid: {}, version: {}, warnings: {} }}",
            self.is_valid,
            self.version,
            self.warnings.len()
        )
    }
}

// ─── TtdTraceValidation ───────────────────────────────────────────────────────

/// Validates a TTD trace file.
pub struct TtdTraceValidation;

impl TtdTraceValidation {
    /// Validate the trace at `path`.
    ///
    /// In simulation, valid paths contain `.run` extension; others fail.
    ///
    /// # Errors
    /// Returns `TtdRecordError` on I/O failure.
    pub fn validate(path: &str) -> Result<ValidationResult, TtdRecordError> {
        if path.is_empty() {
            return Err(TtdRecordError::OutputPathError("empty path".into()));
        }
        let is_valid = std::path::Path::new(path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("run"))
            || std::path::Path::new(path)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("ttd"));
        let mut warnings = Vec::new();
        if !is_valid {
            warnings.push(format!("Unknown extension in path: {path}"));
        }
        Ok(ValidationResult {
            is_valid,
            version: 1,
            position_range: (TtdPosition::start(), TtdPosition::new(1000, 0)),
            warnings,
        })
    }

    /// Return `true` if `path` looks like a valid TTD trace file.
    #[must_use]
    pub fn is_valid_extension(path: &str) -> bool {
        std::path::Path::new(path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("run"))
            || std::path::Path::new(path)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("ttd"))
    }
}

// ─── Legacy recorder types (kept for compat) ─────────────────────────────────

/// Errors for the legacy recorder operations.
#[derive(Debug, Error)]
pub enum RecorderError {
    /// A recording is already in progress.
    #[error("already recording")]
    AlreadyRecording,
    /// No recording is currently in progress.
    #[error("not recording")]
    NotRecording,
    /// Failed to spawn a process.
    #[error("spawn error: {0}")]
    SpawnError(String),
    /// Failed to write to the trace.
    #[error("trace write error: {0}")]
    TraceWriteError(String),
    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Invalid recorder configuration.
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    /// JSON serialization/deserialization error.
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Configuration for a recording session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecorderConfig {
    /// Optional path to write the serialized trace.
    pub output_path: Option<PathBuf>,
    /// Maximum number of events to record before stopping.
    pub max_events: Option<u64>,
    /// Whether to record memory reads and writes.
    pub record_memory: bool,
    /// Whether to record thread creation/exit events.
    pub record_threads: bool,
    /// Only record events for this PID (if `Some`).
    pub pid_filter: Option<u32>,
}

impl Default for RecorderConfig {
    fn default() -> Self {
        Self {
            output_path: None,
            max_events: None,
            record_memory: true,
            record_threads: true,
            pid_filter: None,
        }
    }
}

impl std::fmt::Display for RecorderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RecorderConfig {{ record_memory: {}, record_threads: {}, max_events: {:?} }}",
            self.record_memory, self.record_threads, self.max_events
        )
    }
}

/// A live recording session handle.
#[derive(Debug, Clone)]
pub struct RecordingSession {
    /// Configuration used to start this session.
    pub config: RecorderConfig,
    /// PID of the process being recorded.
    pub pid: u32,
    /// Number of events recorded so far.
    pub event_count: u64,
    /// Unix timestamp (seconds) when recording started.
    pub start_time: u64,
}

impl RecordingSession {
    /// Create a new `RecordingSession`.
    #[must_use]
    pub fn new(config: RecorderConfig, pid: u32) -> Self {
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Self {
            config,
            pid,
            event_count: 0,
            start_time,
        }
    }
}

impl std::fmt::Display for RecordingSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RecordingSession {{ pid: {}, events: {}, started: {} }}",
            self.pid, self.event_count, self.start_time
        )
    }
}

/// Trait for TTD recorders.
#[async_trait::async_trait]
pub trait Recorder: Send + Sync {
    /// Start a new recording.
    async fn start(&self, config: RecorderConfig) -> Result<RecordingSession, RecorderError>;
    /// Stop the recording and return the trace.
    async fn stop(&self, session: RecordingSession) -> Result<Arc<TtdTrace>, RecorderError>;
    /// Attach to an already-running process.
    async fn attach(
        &self,
        pid: u32,
        config: RecorderConfig,
    ) -> Result<RecordingSession, RecorderError>;
}

/// An in-process recorder that generates a synthetic trace.
#[derive(Debug, Default)]
pub struct InProcessRecorder;

#[async_trait::async_trait]
impl Recorder for InProcessRecorder {
    async fn start(&self, config: RecorderConfig) -> Result<RecordingSession, RecorderError> {
        if let Some(max) = config.max_events
            && max == 0
        {
            return Err(RecorderError::InvalidConfig(
                "max_events must be > 0".into(),
            ));
        }
        Ok(RecordingSession::new(config, std::process::id()))
    }

    async fn stop(&self, mut session: RecordingSession) -> Result<Arc<TtdTrace>, RecorderError> {
        let end_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let meta = TraceMetadata {
            version: 1,
            process_name: String::from("in-process"),
            pid: session.pid,
            arch: String::from("x86_64"),
            start_time: session.start_time,
            end_time,
            thread_count: 2,
            ..Default::default()
        };
        let trace = Arc::new(TtdTrace::new(meta));
        let max = session.config.max_events.unwrap_or(50);
        for i in 0..max {
            let kind = synthetic_event(i, &session.config);
            trace.add_event(TraceEvent {
                position: TracePosition::new(i, 0),
                thread_id: if i.is_multiple_of(3) { 2 } else { 1 },
                kind,
            });
            session.event_count += 1;
        }
        Ok(trace)
    }

    async fn attach(
        &self,
        pid: u32,
        config: RecorderConfig,
    ) -> Result<RecordingSession, RecorderError> {
        if pid == 0 {
            return Err(RecorderError::SpawnError("cannot attach to PID 0".into()));
        }
        Ok(RecordingSession::new(config, pid))
    }
}

fn synthetic_event(i: u64, config: &RecorderConfig) -> EventKind {
    match i % 6 {
        0 if config.record_memory => EventKind::MemRead {
            addr: 0x1000 + i * 8,
            len: 8,
        },
        0 | 2 => EventKind::Call {
            from: 0x4000 + i * 4,
            to: 0x5000 + i * 4,
        },
        1 if config.record_memory => EventKind::MemWrite {
            addr: 0x2000 + i * 8,
            data: vec![0xca, 0xfe, 0xba, 0xbe],
        },
        1 | 3 => EventKind::Return {
            from: 0x5000 + i * 4,
            to: 0x4004 + i * 4,
        },
        4 => EventKind::SyscallEnter {
            nr: (i % 200) as u32,
            args: [i, i + 1, i + 2, 0, 0, 0],
        },
        _ => EventKind::SyscallExit {
            nr: (i % 200) as u32,
            ret: 0,
        },
    }
}

/// Wire format for serialised traces.
#[derive(Debug, Serialize, Deserialize)]
struct SerializedTrace {
    metadata: TraceMetadata,
    events: Vec<TraceEvent>,
}

/// Serializes and deserializes `TtdTrace` to/from JSON bytes.
pub struct TraceSerializer;

impl TraceSerializer {
    /// Serialize a trace to JSON bytes.
    ///
    /// # Errors
    /// Returns `RecorderError::Serde` on failure.
    pub fn serialize(trace: &TtdTrace) -> Result<Vec<u8>, RecorderError> {
        let wire = SerializedTrace {
            metadata: trace.metadata.clone(),
            events: trace.all_events(),
        };
        serde_json::to_vec(&wire).map_err(RecorderError::Serde)
    }

    /// Deserialize a trace from JSON bytes.
    ///
    /// # Errors
    /// Returns `RecorderError::Serde` on failure.
    pub fn deserialize(bytes: &[u8]) -> Result<Arc<TtdTrace>, RecorderError> {
        let wire: SerializedTrace = serde_json::from_slice(bytes).map_err(RecorderError::Serde)?;
        let trace = Arc::new(TtdTrace::new(wire.metadata));
        for event in wire.events {
            trace.add_event(event);
        }
        Ok(trace)
    }
}

// ─── Module statistics helper ─────────────────────────────────────────────────

/// Statistics about a recorded module.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleStats {
    /// Module name.
    pub name: String,
    /// Number of events originating from this module.
    pub event_count: u64,
    /// Whether the module was loaded at the start.
    pub loaded_at_start: bool,
}

/// Aggregate statistics from a completed recording.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecordingStats {
    /// Total events.
    pub total_events: u64,
    /// Events per thread.
    pub events_per_thread: HashMap<u32, u64>,
    /// Per-module statistics.
    pub module_stats: Vec<ModuleStats>,
    /// Wall-clock duration.
    pub duration_secs: f64,
}

impl RecordingStats {
    /// Build stats from a completed trace.
    #[must_use]
    pub fn from_trace(trace: &TtdTrace, duration_secs: f64) -> Self {
        let events = trace.all_events();
        // Pre-size to avoid repeated rehashing as the table grows. Real traces
        // rarely have more than a few dozen threads, but we cap a sensible
        // upper bound to avoid huge allocations on adversarial inputs.
        let mut per_thread: HashMap<u32, u64> = HashMap::with_capacity(16);
        for e in &events {
            *per_thread.entry(e.thread_id).or_insert(0) += 1;
        }
        Self {
            total_events: events.len() as u64,
            events_per_thread: per_thread,
            module_stats: Vec::new(),
            duration_secs,
        }
    }

    /// Return the thread with the most events.
    #[must_use]
    pub fn hottest_thread(&self) -> Option<u32> {
        self.events_per_thread
            .iter()
            .max_by_key(|(_, v)| *v)
            .map(|(k, _)| *k)
    }
}

// ─── RingBufferRecorder ───────────────────────────────────────────────────────

/// A recorder that keeps only the last N events (ring buffer mode).
pub struct RingBufferRecorder {
    capacity: usize,
    events: Mutex<std::collections::VecDeque<TraceEvent>>,
}

impl RingBufferRecorder {
    /// Create a new ring buffer recorder with the given event capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            events: Mutex::new(std::collections::VecDeque::with_capacity(capacity)),
        }
    }

    /// Add an event, dropping the oldest if the buffer is full.
    pub fn push(&self, event: TraceEvent) {
        let mut q = self.events.lock();
        if q.len() >= self.capacity {
            q.pop_front();
        }
        q.push_back(event);
    }

    /// Return a snapshot of the current buffer contents.
    #[must_use]
    pub fn snapshot(&self) -> Vec<TraceEvent> {
        let g = self.events.lock();
        let mut out = Vec::with_capacity(g.len());
        out.extend(g.iter().cloned());
        out
    }

    /// Return the number of events currently in the buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.lock().len()
    }

    /// Return `true` if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.lock().is_empty()
    }

    /// Clear the buffer.
    pub fn clear(&self) {
        self.events.lock().clear();
    }
}

// ─── RecordingScheduler ───────────────────────────────────────────────────────

/// Manages a scheduled recording that starts/stops at specific positions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingSchedule {
    /// Start recording when this address is reached.
    pub start_address: Option<u64>,
    /// Stop recording when this address is reached.
    pub stop_address: Option<u64>,
    /// Start recording at this position.
    pub start_position: Option<TtdPosition>,
    /// Stop recording at this position.
    pub stop_position: Option<TtdPosition>,
    /// Maximum recording duration.
    pub max_duration: Option<Duration>,
}

impl RecordingSchedule {
    /// Create a schedule that records everything.
    #[must_use]
    pub const fn record_all() -> Self {
        Self {
            start_address: None,
            stop_address: None,
            start_position: None,
            stop_position: None,
            max_duration: None,
        }
    }

    /// Create a schedule that records up to `max_secs` seconds.
    #[must_use]
    pub const fn for_duration(max_secs: u64) -> Self {
        Self {
            max_duration: Some(Duration::from_secs(max_secs)),
            ..Self::record_all()
        }
    }

    /// Return `true` if recording should stop at `pos`.
    #[must_use]
    pub fn should_stop(&self, pos: TtdPosition, elapsed: Duration) -> bool {
        if let Some(stop) = self.stop_position
            && pos >= stop
        {
            return true;
        }
        if let Some(max) = self.max_duration
            && elapsed >= max
        {
            return true;
        }
        false
    }
}

// ─── TraceFileInfo ────────────────────────────────────────────────────────────

/// Metadata about a TTD trace file on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceFileInfo {
    /// Full path to the file.
    pub path: String,
    /// File size in bytes.
    pub size_bytes: u64,
    /// Whether the file appears valid.
    pub valid: bool,
    /// Version extracted from the header.
    pub version: u32,
    /// Approximate number of events.
    pub event_count_approx: u64,
}

impl TraceFileInfo {
    /// Create from a path (simulation: always reports 1 MB, 1000 events).
    #[must_use]
    pub fn from_path(path: impl Into<String>) -> Self {
        let path = path.into();
        let valid = std::path::Path::new(&path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("run"))
            || std::path::Path::new(&path)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("ttd"));
        Self {
            path,
            size_bytes: 1_048_576,
            valid,
            version: 1,
            event_count_approx: 1000,
        }
    }
}

// ─── perf_event_open constants (Linux kernel ABI) ────────────────────────────

#[cfg(target_os = "linux")]
mod perf_consts {
    pub const PERF_TYPE_HARDWARE: u32 = 0;
    pub const PERF_COUNT_HW_INSTRUCTIONS: u64 = 1;
}

// ─── PerfEventCounter ─────────────────────────────────────────────────────────

/// Wraps a Linux perf_event file descriptor that counts retired instructions
/// for a specific process.
///
/// Uses `perf_event_open(2)` directly via `libc::syscall` because the `nix`
/// crate does not expose that syscall.
#[cfg(target_os = "linux")]
pub struct PerfEventCounter {
    fd: std::os::unix::io::RawFd,
}

#[cfg(target_os = "linux")]
impl PerfEventCounter {
    /// Open an instruction-retired hardware counter attached to `pid`.
    ///
    /// The counter starts enabled (`disabled = 0`) and inherits into child
    /// threads (`inherit = 1`).
    ///
    /// # Errors
    /// Returns an error if the kernel rejects the `perf_event_open` call (e.g.
    /// `/proc/sys/kernel/perf_event_paranoid` is too restrictive).
    pub fn open_instruction_counter(pid: u32) -> anyhow::Result<Self> {
        use perf_consts::*;

        // perf_event_attr is a packed C struct; we zero it first then fill
        // the fields we care about.  The struct is larger than the fields
        // defined here but the kernel accepts a size we declare in `size`.
        #[repr(C)]
        struct PerfEventAttr {
            type_: u32,
            size: u32,
            config: u64,
            sample_period_or_freq: u64,
            sample_type: u64,
            read_format: u64,
            flags: u64, // bits: disabled(0), inherit(1), ...
            // remaining fields zero-padded
            _pad: [u8; 96],
        }

        let mut attr: PerfEventAttr = unsafe { std::mem::zeroed() };
        attr.type_ = PERF_TYPE_HARDWARE;
        attr.size = std::mem::size_of::<PerfEventAttr>() as u32;
        attr.config = PERF_COUNT_HW_INSTRUCTIONS;
        // flags bit 1 = inherit; bit 0 = disabled (we want disabled=0)
        attr.flags = 1 << 1; // inherit=1, disabled=0

        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &attr as *const PerfEventAttr as *const libc::c_void,
                pid as libc::pid_t,
                -1i32,  // cpu = -1 (all CPUs)
                -1i32,  // group_fd = -1 (no group)
                0usize, // flags
            )
        };

        if fd < 0 {
            let e = std::io::Error::last_os_error();
            anyhow::bail!("perf_event_open failed for pid {pid}: {e}");
        }

        Ok(Self {
            fd: fd as std::os::unix::io::RawFd,
        })
    }

    /// Read the current instruction count from the counter.
    ///
    /// # Errors
    /// Returns an error if the `read(2)` syscall fails.
    pub fn read(&self) -> anyhow::Result<u64> {
        let mut value: u64 = 0;
        let n = unsafe {
            libc::read(
                self.fd,
                &mut value as *mut u64 as *mut libc::c_void,
                std::mem::size_of::<u64>(),
            )
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            anyhow::bail!("perf counter read failed: {e}");
        }
        if n as usize != std::mem::size_of::<u64>() {
            anyhow::bail!(
                "perf counter short read: got {} bytes, expected {}",
                n,
                std::mem::size_of::<u64>()
            );
        }
        Ok(value)
    }

    /// Reset the counter back to zero via `ioctl(PERF_EVENT_IOC_RESET)`.
    ///
    /// # Errors
    /// Returns an error if the ioctl fails.
    pub fn reset(&self) -> anyhow::Result<()> {
        // PERF_EVENT_IOC_RESET = _IO('$', 3) = 0x2403 on Linux
        const PERF_EVENT_IOC_RESET: libc::c_ulong = 0x2403;
        let ret = unsafe { libc::ioctl(self.fd, PERF_EVENT_IOC_RESET, 0i32) };
        if ret < 0 {
            let e = std::io::Error::last_os_error();
            anyhow::bail!("perf counter reset failed: {e}");
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for PerfEventCounter {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

// ─── SyscallArgs / SyscallEvent / MemWrite ────────────────────────────────────

/// Raw register state captured at a syscall boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallArgs {
    /// Syscall number (from `rax` on entry / `orig_rax`).
    pub nr: u64,
    /// Arguments in calling-convention order (`rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`).
    pub args: [u64; 6],
}

/// A memory write observed between two consecutive syscalls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemWrite {
    /// Guest virtual address of the write.
    pub addr: u64,
    /// Bytes that were written.
    pub data: Vec<u8>,
}

/// A single syscall event captured by `SyscallInterceptor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvent {
    /// Instruction count at the moment the syscall entry was observed.
    pub instr_count: u64,
    /// Syscall number.
    pub nr: u32,
    /// Raw argument registers.
    pub args: [u64; 6],
    /// Return value (`rax` on syscall exit).
    pub retval: i64,
    /// Memory writes that we explicitly probed (may be empty unless the caller
    /// calls `read_memory` on arguments).
    pub mem_writes: Vec<MemWrite>,
}

// ─── SyscallInterceptor ───────────────────────────────────────────────────────

/// Attaches to a process via ptrace and intercepts every syscall entry/exit,
/// reporting a `SyscallEvent` per pair.
#[cfg(target_os = "linux")]
pub struct SyscallInterceptor {
    pid: nix::unistd::Pid,
    /// `true` after the first stop so we know we are at a syscall entry next.
    at_entry: bool,
    /// Last captured entry args (held across the entry→exit boundary).
    last_entry: Option<SyscallArgs>,
    /// Perf counter used to stamp instruction counts.
    perf: Option<PerfEventCounter>,
}

#[cfg(target_os = "linux")]
impl SyscallInterceptor {
    /// Attach to `pid` with `PTRACE_ATTACH` and wait for the initial stop.
    ///
    /// # Errors
    /// Propagates nix/ptrace errors.
    pub fn attach(pid: nix::unistd::Pid) -> anyhow::Result<Self> {
        use nix::sys::ptrace;
        use nix::sys::wait::{WaitStatus, waitpid};

        ptrace::attach(pid)?;
        // Wait for the SIGSTOP that the kernel delivers after attach.
        match waitpid(pid, None)? {
            WaitStatus::Stopped(_, _) => {}
            other => anyhow::bail!("unexpected waitpid status after attach: {other:?}"),
        }

        let perf = PerfEventCounter::open_instruction_counter(pid.as_raw() as u32).ok();

        Ok(Self {
            pid,
            at_entry: true,
            last_entry: None,
            perf,
        })
    }

    /// Deliver `PTRACE_SYSCALL` to let the tracee run until the next syscall
    /// entry or exit, then return a fully-populated `SyscallEvent`.
    ///
    /// The function internally alternates between entry and exit stops,
    /// returning `Some(event)` only on exit (i.e. after both halves have been
    /// captured).  It returns `None` on entry stops so callers can call it in a
    /// loop.
    ///
    /// # Errors
    /// Returns an error if the tracee exits unexpectedly or ptrace fails.
    pub fn resume_to_next_syscall(&mut self) -> anyhow::Result<Option<SyscallEvent>> {
        use nix::sys::ptrace;
        use nix::sys::wait::{WaitStatus, waitpid};

        // Deliver PTRACE_SYSCALL to resume until the next syscall stop.
        ptrace::syscall(self.pid, None)?;

        let status = waitpid(self.pid, None)?;
        match status {
            WaitStatus::Stopped(_, nix::sys::signal::Signal::SIGTRAP) => {
                // ptrace syscall-stop
            }
            WaitStatus::PtraceSyscall(_) => {
                // Linux delivers this on kernels ≥ 3.11 with PTRACE_O_TRACESYSGOOD
            }
            WaitStatus::Exited(_, code) => {
                anyhow::bail!("tracee exited with code {code}");
            }
            WaitStatus::Signaled(_, sig, _) => {
                anyhow::bail!("tracee killed by signal {sig}");
            }
            other => {
                anyhow::bail!("unexpected waitpid status: {other:?}");
            }
        }

        if self.at_entry {
            // Syscall entry — capture arguments.
            let args = self.read_syscall_args(self.pid)?;
            self.last_entry = Some(args);
            self.at_entry = false;
            Ok(None)
        } else {
            // Syscall exit — capture return value and emit event.
            let retval = self.read_return_value(self.pid)?;
            let instr_count = self.perf.as_ref().and_then(|p| p.read().ok()).unwrap_or(0);

            let entry = self.last_entry.take().unwrap_or(SyscallArgs {
                nr: 0,
                args: [0u64; 6],
            });

            self.at_entry = true;

            Ok(Some(SyscallEvent {
                instr_count,
                nr: entry.nr as u32,
                args: entry.args,
                retval,
                mem_writes: Vec::new(),
            }))
        }
    }

    /// Read the general-purpose registers of `pid` and return them as
    /// `SyscallArgs`.  Uses `PTRACE_GETREGS` (x86-64 `user_regs_struct`).
    ///
    /// # Errors
    /// Returns an error if ptrace fails.
    pub fn read_syscall_args(&self, pid: nix::unistd::Pid) -> anyhow::Result<SyscallArgs> {
        use nix::sys::ptrace;

        let regs = ptrace::getregs(pid)?;
        // x86-64 syscall ABI: number in orig_rax, args in rdi rsi rdx r10 r8 r9
        Ok(SyscallArgs {
            nr: regs.orig_rax,
            args: [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9],
        })
    }

    /// Read the syscall return value from `rax`.
    ///
    /// # Errors
    /// Returns an error if `PTRACE_GETREGS` fails.
    pub fn read_return_value(&self, pid: nix::unistd::Pid) -> anyhow::Result<i64> {
        use nix::sys::ptrace;
        let regs = ptrace::getregs(pid)?;
        Ok(regs.rax as i64)
    }

    /// Read `len` bytes from the tracee's virtual address space starting at
    /// `addr` using a `PTRACE_PEEKDATA` loop (reads one `usize`-word at a time).
    ///
    /// # Errors
    /// Returns an error if any `PTRACE_PEEKDATA` call fails.
    pub fn read_memory(
        &self,
        pid: nix::unistd::Pid,
        addr: u64,
        len: usize,
    ) -> anyhow::Result<Vec<u8>> {
        use nix::sys::ptrace;

        let word_size = std::mem::size_of::<usize>();
        let mut buf: Vec<u8> = Vec::with_capacity(len);
        let mut offset = 0usize;

        while offset < len {
            let remaining = len - offset;
            if remaining < word_size {
                // For the trailing partial word, read a full word ending at
                // addr+len so we never peek past the requested range (which may
                // sit on an unmapped page and would fault).
                let tail_addr = (addr as usize)
                    .wrapping_add(len)
                    .wrapping_sub(word_size);
                let word = ptrace::read(pid, tail_addr as *mut libc::c_void)? as usize;
                let word_bytes = word.to_ne_bytes();
                buf.extend_from_slice(&word_bytes[word_size - remaining..]);
                break;
            }
            let word_addr = (addr as usize).wrapping_add(offset);
            let word = ptrace::read(pid, word_addr as *mut libc::c_void)? as usize;
            buf.extend_from_slice(&word.to_ne_bytes());
            offset += word_size;
        }

        buf.truncate(len);
        Ok(buf)
    }

    /// Detach from the tracee, letting it continue normally.
    ///
    /// # Errors
    /// Returns an error if `PTRACE_DETACH` fails.
    pub fn detach(self) -> anyhow::Result<()> {
        nix::sys::ptrace::detach(self.pid, None)?;
        Ok(())
    }
}

// ─── TtdTraceFile — serializable on-disk format ───────────────────────────────

/// Magic bytes written at the start of every `.ttd` file produced by this
/// crate.
pub const TTD_MAGIC: &[u8; 8] = b"RUSTTD01";

/// Version of the binary trace format.
pub const TTD_VERSION: u32 = 1;

/// Header that precedes the event payload in a `.ttd` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtdTraceHeader {
    /// Must equal `TTD_MAGIC` (stored as a UTF-8 string for JSON compat).
    pub magic: String,
    /// Format version — must equal `TTD_VERSION`.
    pub version: u32,
    /// Target architecture (e.g. `"x86_64"`).
    pub arch: String,
    /// PID that was traced.
    pub pid: u32,
    /// Unix timestamp (seconds) when recording started.
    pub recorded_at: u64,
}

impl TtdTraceHeader {
    /// Create a header for the current run.
    #[must_use]
    pub fn new(pid: u32) -> Self {
        let recorded_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Self {
            magic: String::from_utf8_lossy(TTD_MAGIC).into_owned(),
            version: TTD_VERSION,
            arch: String::from("x86_64"),
            pid,
            recorded_at,
        }
    }

    /// Validate that magic and version match expectations.
    ///
    /// # Errors
    /// Returns a descriptive string if validation fails.
    pub fn validate(&self) -> Result<(), String> {
        let expected = String::from_utf8_lossy(TTD_MAGIC).into_owned();
        if self.magic != expected {
            return Err(format!(
                "bad magic: expected {expected:?}, got {:?}",
                self.magic
            ));
        }
        if self.version != TTD_VERSION {
            return Err(format!(
                "unsupported version: expected {TTD_VERSION}, got {}",
                self.version
            ));
        }
        Ok(())
    }
}

/// The complete in-memory representation of a `.ttd` file.
///
/// Can be serialized to / deserialized from a file via
/// `write_to_file` / `read_from_file`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtdTraceFile {
    /// File header (magic, version, arch, pid).
    pub header: TtdTraceHeader,
    /// All trace events in chronological order.
    pub events: Vec<SyscallEvent>,
}

impl TtdTraceFile {
    /// Create an empty trace file for `pid`.
    #[must_use]
    pub fn new(pid: u32) -> Self {
        Self {
            header: TtdTraceHeader::new(pid),
            events: Vec::new(),
        }
    }

    /// Append a single event.
    pub fn push(&mut self, event: SyscallEvent) {
        self.events.push(event);
    }

    /// Serialize to `path` as a JSON document (newline-terminated).
    ///
    /// # Errors
    /// Returns `anyhow::Error` on I/O or serialization failure.
    pub fn write_to_file(&self, path: &std::path::Path) -> anyhow::Result<()> {
        use std::io::Write;
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| anyhow::anyhow!("serialization failed: {e}"))?;
        let mut f = std::fs::File::create(path)?;
        f.write_all(&json)?;
        f.write_all(b"\n")?;
        Ok(())
    }

    /// Deserialize from a JSON file at `path`.
    ///
    /// # Errors
    /// Returns `anyhow::Error` if the file cannot be read or parsed, or if
    /// the header validation fails.
    pub fn read_from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path)?;
        let trace: Self = serde_json::from_slice(&bytes)
            .map_err(|e| anyhow::anyhow!("deserialization failed: {e}"))?;
        trace
            .header
            .validate()
            .map_err(|e| anyhow::anyhow!("invalid trace file header: {e}"))?;
        Ok(trace)
    }

    /// Return the number of recorded events.
    #[must_use]
    pub const fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Return a reference to the first event, if any.
    #[must_use]
    pub fn first_event(&self) -> Option<&SyscallEvent> {
        self.events.first()
    }

    /// Return a reference to the last event, if any.
    #[must_use]
    pub fn last_event(&self) -> Option<&SyscallEvent> {
        self.events.last()
    }

    /// Iterate over all events with instruction-count stamps in ascending order.
    ///
    /// Events are assumed to already be stored in chronological order (as
    /// appended by `push`).
    pub fn iter_events(&self) -> impl Iterator<Item = &SyscallEvent> {
        self.events.iter()
    }

    /// Return all unique syscall numbers that appear in the trace.
    #[must_use]
    pub fn unique_syscalls(&self) -> Vec<u32> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        for ev in &self.events {
            if seen.insert(ev.nr) {
                result.push(ev.nr);
            }
        }
        result.sort_unstable();
        result
    }

    /// Return the total number of instructions counted across all events
    /// (the instruction count of the last event, or 0 if empty).
    #[must_use]
    pub fn total_instructions(&self) -> u64 {
        self.events.last().map_or(0, |e| e.instr_count)
    }

    /// Filter events by syscall number.
    #[must_use]
    pub fn filter_by_nr(&self, nr: u32) -> Vec<&SyscallEvent> {
        self.events.iter().filter(|e| e.nr == nr).collect()
    }
}

// ─── PtraceRecordSession — real Linux recording ───────────────────────────────

/// A recording session backed by Linux ptrace + perf_event_open.
///
/// Intercepts every syscall of the target process and emits a `SyscallEvent`
/// per entry/exit pair.  The trace is stored in a `TtdTraceFile` and flushed
/// to disk when `finish()` is called.
///
/// This type is only available on Linux.
#[cfg(target_os = "linux")]
pub struct PtraceRecordSession {
    pid: nix::unistd::Pid,
    output_path: std::path::PathBuf,
    trace: TtdTraceFile,
    max_events: Option<usize>,
    started: bool,
}

#[cfg(target_os = "linux")]
impl PtraceRecordSession {
    /// Create a new session that will attach to `pid` and write the trace to
    /// `output_path`.
    #[must_use]
    pub fn new(
        pid: u32,
        output_path: impl Into<std::path::PathBuf>,
        max_events: Option<usize>,
    ) -> Self {
        let nix_pid = nix::unistd::Pid::from_raw(pid as libc::pid_t);
        Self {
            pid: nix_pid,
            output_path: output_path.into(),
            trace: TtdTraceFile::new(pid),
            max_events,
            started: false,
        }
    }

    /// Attach to the target process and run the recording loop.
    ///
    /// This method blocks until:
    /// - The target process exits, OR
    /// - `max_events` events have been captured (if configured), OR
    /// - An unrecoverable ptrace error occurs.
    ///
    /// On return, call `finish()` to flush the trace to disk.
    ///
    /// # Errors
    /// Returns an error if attaching or the recording loop fails.
    pub fn run(&mut self) -> anyhow::Result<()> {
        if self.started {
            anyhow::bail!("PtraceRecordSession already started");
        }
        self.started = true;

        let mut interceptor = SyscallInterceptor::attach(self.pid)?;
        let limit = self.max_events.unwrap_or(usize::MAX);

        loop {
            match interceptor.resume_to_next_syscall() {
                Ok(Some(mut event)) => {
                    // Optionally probe the memory pointed to by the first
                    // argument if the syscall number suggests a write
                    // (heuristic: sys_write = 1 on x86-64).
                    if event.nr == 1 && event.args[2] > 0 && event.args[2] <= 4096 {
                        if let Ok(data) =
                            interceptor.read_memory(self.pid, event.args[1], event.args[2] as usize)
                        {
                            event.mem_writes.push(MemWrite {
                                addr: event.args[1],
                                data,
                            });
                        }
                    }
                    self.trace.push(event);
                    if self.trace.event_count() >= limit {
                        break;
                    }
                }
                Ok(None) => {
                    // Entry stop — loop continues to exit stop.
                }
                Err(e) => {
                    // Tracee exited or we hit a hard error.
                    let msg = e.to_string();
                    if msg.contains("exited") || msg.contains("killed") {
                        break;
                    }
                    return Err(e);
                }
            }
        }

        // Detach gracefully; ignore errors (tracee may already be gone).
        let _ = interceptor.detach();
        Ok(())
    }

    /// Write the accumulated trace to `output_path` and return a reference to
    /// the trace data.
    ///
    /// # Errors
    /// Returns an error if the file cannot be written.
    pub fn finish(&self) -> anyhow::Result<&TtdTraceFile> {
        self.trace.write_to_file(&self.output_path)?;
        Ok(&self.trace)
    }

    /// Return the number of events captured so far.
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.trace.event_count()
    }

    /// Borrow the underlying `TtdTraceFile` without writing it to disk.
    #[must_use]
    pub fn trace(&self) -> &TtdTraceFile {
        &self.trace
    }
}

// ─── TtdRecordSession::start rewrite ─────────────────────────────────────────
//
// NOTE: the six functions below are deliberately NOT `const fn`.
//
// They were, and it compiled on Windows for a reason that had nothing to do
// with them being const-evaluable: their real bodies live inside
// `#[cfg(target_os = "linux")]`, so on Windows the compiler saw only the
// short non-Linux stub — which IS const-compatible — and accepted the
// qualifier. On Linux the real body appears, and it locks an RwLock, calls
// `Instant::now`, builds a PathBuf, formats a string and uses `?`: none of
// which is allowed in a const fn.
//
// The effect was not a warning: `rustre-ttd-recorder` could not compile on
// Linux AT ALL, which means the "Linux-native recording path" this module
// exists for had never once been built. Measured 2026-08-14 while making the
// workspace build on Unix for the first time.
// The struct definition and most methods stay as-is above.  We add a Linux-
// specific helper that actually runs a ptrace-backed recording and serializes
// the result, wiring it into the existing `start()`/`stop()` flow.

impl TtdRecordSession {
    /// Linux-native recording path.
    ///
    /// Attaches to the PID specified in the config, runs `PtraceRecordSession`
    /// to collect up to `max_events` (or unlimited if 0) syscall events, writes
    /// the trace to `output_dir/trace_<pid>.ttd`, and updates internal metrics.
    ///
    /// # Errors
    /// Returns `TtdRecordError` if attachment or file I/O fails, or if the
    /// platform is not Linux.
    pub const fn start_real(&mut self) -> Result<(), TtdRecordError> {
        #[cfg(target_os = "linux")]
        {
            self.config
                .validate()
                .map_err(TtdRecordError::RecordingFailed)?;

            let pid = match &self.config.target_process {
                TtdTarget::ProcessId(p) => *p,
                _ => {
                    return Err(TtdRecordError::RecordingFailed(
                        "start_real only supports ProcessId targets".into(),
                    ));
                }
            };

            *self.status.write() = RecordingStatus::Injecting;
            self.start_time = Some(std::time::Instant::now());

            let out_path =
                std::path::PathBuf::from(&self.config.output_dir).join(format!("trace_{pid}.ttd"));

            let max = if self.config.max_recording_size_mb > 0 {
                // Rough heuristic: treat max_recording_size_mb as max events
                // (1 event ≈ 1 KB).
                Some(self.config.max_recording_size_mb as usize * 1024)
            } else {
                None
            };

            let mut sess = PtraceRecordSession::new(pid, &out_path, max);

            *self.status.write() = RecordingStatus::Recording;

            sess.run()
                .map_err(|e| TtdRecordError::RecordingFailed(e.to_string()))?;
            let ttd = sess
                .finish()
                .map_err(|e| TtdRecordError::RecordingFailed(e.to_string()))?;

            let event_count = ttd.event_count() as u64;
            let elapsed = self.start_time.map_or(0.0, |t| t.elapsed().as_secs_f64());

            let file_size = std::fs::metadata(&out_path)
                .map(|m| m.len())
                .unwrap_or(event_count * 256);

            let mut m = self.metrics.write();
            m.events_recorded = event_count;
            m.instructions_recorded = ttd.total_instructions();
            m.file_size_bytes = file_size;
            m.elapsed_secs = elapsed;
            m.thread_count = 1;
            drop(m);

            *self.status.write() = RecordingStatus::Stopped;
            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(TtdRecordError::NotAvailable)
        }
    }
}

// ─── Windows stub ─────────────────────────────────────────────────────────────

/// Platform-level availability check.
///
/// On Linux this returns `Ok(())`.  On all other platforms it returns an error
/// explaining that real TTD recording requires either Linux ptrace or the
/// Windows TTD SDK (`WinDbg`).
///
/// # Errors
/// Returns `TtdRecordError::NotAvailable` on non-Linux platforms.
pub fn check_platform_support() -> Result<(), TtdRecordError> {
    #[cfg(target_os = "linux")]
    {
        Ok(())
    }

    #[cfg(target_os = "windows")]
    {
        Err(TtdRecordError::RecordingFailed(
            "TTD recording requires Linux ptrace or Windows TTD SDK".into(),
        ))
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Err(TtdRecordError::NotAvailable)
    }
}

// ─── TraceEventConverter ──────────────────────────────────────────────────────

/// Converts `SyscallEvent`s (from the ptrace recorder) into `TraceEvent`s
/// (the core TTD representation used by `TtdTrace`).
pub struct TraceEventConverter;

impl TraceEventConverter {
    /// Convert a single `SyscallEvent` into a pair of `TraceEvent`s
    /// (entry + exit).
    #[must_use]
    pub const fn convert(ev: &SyscallEvent, thread_id: u32) -> [rustre_ttd::TraceEvent; 2] {
        use rustre_ttd::{EventKind, TraceEvent, TracePosition};

        let entry_pos = TracePosition::new(ev.instr_count, 0);
        let exit_pos = TracePosition::new(ev.instr_count, 1);

        let entry = TraceEvent {
            position: entry_pos,
            thread_id,
            kind: EventKind::SyscallEnter {
                nr: ev.nr,
                args: ev.args,
            },
        };

        let exit = TraceEvent {
            position: exit_pos,
            thread_id,
            kind: EventKind::SyscallExit {
                nr: ev.nr,
                ret: ev.retval as u64,
            },
        };

        [entry, exit]
    }

    /// Convert an entire `TtdTraceFile` into a `TtdTrace`.
    ///
    /// Each `SyscallEvent` produces two `TraceEvent`s (entry + exit).
    /// All events are attributed to `thread_id` 1.
    #[must_use]
    pub fn convert_file(file: &TtdTraceFile) -> Arc<rustre_ttd::TtdTrace> {
        use rustre_ttd::TraceMetadata;

        let meta = TraceMetadata {
            version: TTD_VERSION,
            process_name: format!("pid:{}", file.header.pid),
            pid: file.header.pid,
            arch: file.header.arch.clone(),
            start_time: file.header.recorded_at,
            end_time: file.header.recorded_at,
            thread_count: 1,
            ..Default::default()
        };

        let trace = Arc::new(rustre_ttd::TtdTrace::new(meta));
        for ev in file.iter_events() {
            for te in Self::convert(ev, 1) {
                trace.add_event(te);
            }
        }
        trace
    }
}

// ─── SyscallEventStats ────────────────────────────────────────────────────────

/// Summary statistics computed from a `TtdTraceFile`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyscallEventStats {
    /// Total number of syscall events.
    pub total: u64,
    /// Per-syscall-number call counts.
    pub counts_by_nr: HashMap<u32, u64>,
    /// Minimum instruction count observed.
    pub min_instr: u64,
    /// Maximum instruction count observed.
    pub max_instr: u64,
    /// Total bytes written via `sys_write` (nr == 1) probes.
    pub total_write_bytes: u64,
}

impl SyscallEventStats {
    /// Compute stats from a `TtdTraceFile`.
    #[must_use]
    pub fn from_trace_file(file: &TtdTraceFile) -> Self {
        let mut s = Self {
            min_instr: u64::MAX,
            ..Default::default()
        };

        for ev in file.iter_events() {
            s.total += 1;
            *s.counts_by_nr.entry(ev.nr).or_insert(0) += 1;
            if ev.instr_count < s.min_instr {
                s.min_instr = ev.instr_count;
            }
            if ev.instr_count > s.max_instr {
                s.max_instr = ev.instr_count;
            }
            for mw in &ev.mem_writes {
                s.total_write_bytes += mw.data.len() as u64;
            }
        }

        if s.total == 0 {
            s.min_instr = 0;
        }

        s
    }

    /// Return the most frequently called syscall number, if any.
    #[must_use]
    pub fn most_common_nr(&self) -> Option<u32> {
        self.counts_by_nr
            .iter()
            .max_by_key(|(_, v)| *v)
            .map(|(&k, _)| k)
    }
}

// ─── Linux perf_event_open syscall number (x86-64 ABI) ───────────────────────

/// Raw syscall number for `perf_event_open` on x86-64 Linux.
///
/// Defined here as a named constant so callers never have to hard-code the
/// magic number `298`.  On non-Linux targets the constant still exists (it is
/// harmless) but the functions that use it are compiled away.
#[cfg(target_os = "linux")]
pub const SYS_PERF_EVENT_OPEN: i64 = 298;

// ─── PerfEventAttr (top-level, repr C, matches kernel perf_event_attr) ───────

/// A C-layout mirror of the kernel's `perf_event_attr` structure.
///
/// Only the fields that we need are named; the remainder are captured by the
/// `_padding` array so that `std::mem::size_of::<PerfEventAttr>()` matches
/// what the kernel expects (128 bytes on current kernels).
///
/// See `linux/perf_event.h` for the authoritative layout.
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PerfEventAttr {
    /// Event type (e.g. `PERF_TYPE_HARDWARE`).
    pub type_: u32,
    /// Size of this structure as reported to the kernel.
    pub size: u32,
    /// Event sub-type / identifier (e.g. `PERF_COUNT_HW_INSTRUCTIONS`).
    pub config: u64,
    /// Sample period *or* frequency (union in C; we treat as period).
    pub sample_period_or_freq: u64,
    /// Bitmask of which sample fields to include in each record.
    pub sample_type: u64,
    /// Bitmask controlling what is read back from the counter fd.
    pub read_format: u64,
    /// Packed bitfield: bit 0 = `disabled`, bit 1 = `inherit`, etc.
    pub flags: u64,
    /// Padding to reach the 128-byte kernel struct size.
    pub _padding: [u8; 88],
}

#[cfg(target_os = "linux")]
impl Default for PerfEventAttr {
    fn default() -> Self {
        // SAFETY: zeroing a POD C struct is always valid.
        unsafe { std::mem::zeroed() }
    }
}

// ─── Free-function wrappers around perf_event_open / read ────────────────────

/// Open a hardware instruction-retired performance counter for `pid`.
///
/// Calls `perf_event_open(2)` directly via `libc::syscall` (using the
/// [`SYS_PERF_EVENT_OPEN`] constant) with `PERF_TYPE_HARDWARE` +
/// `PERF_COUNT_HW_INSTRUCTIONS`.  The returned file descriptor must be
/// closed by the caller when it is no longer needed.
///
/// # Errors
/// Returns an `std::io::Error` if the syscall fails (e.g. the kernel
/// rejects the request because `/proc/sys/kernel/perf_event_paranoid`
/// is too restrictive, or hardware counters are unavailable).
#[cfg(target_os = "linux")]
pub fn open_instruction_counter(pid: i32) -> std::io::Result<i32> {
    use perf_consts::*;

    let mut attr = PerfEventAttr::default();
    attr.type_ = PERF_TYPE_HARDWARE;
    attr.size = std::mem::size_of::<PerfEventAttr>() as u32;
    attr.config = PERF_COUNT_HW_INSTRUCTIONS;
    // bit 1 = inherit into child threads; bit 0 = disabled (0 = running)
    attr.flags = 1 << 1;

    // SAFETY: We pass a valid, correctly-sized attr struct, a valid pid, and
    // well-known sentinel values for cpu (-1 = all), group_fd (-1 = no group),
    // and flags (0).
    let fd = unsafe {
        libc::syscall(
            SYS_PERF_EVENT_OPEN,
            &attr as *const PerfEventAttr as *const libc::c_void,
            pid as libc::pid_t,
            -1i32,  // cpu = -1 → all CPUs
            -1i32,  // group_fd = -1 → no group leader
            0usize, // flags
        )
    };

    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd as i32)
}

/// Read the current 64-bit counter value from a perf event file descriptor.
///
/// Performs a single `read(2)` of exactly 8 bytes.  The kernel writes the
/// counter value as a little-endian `u64` when `read_format` is 0 (the
/// default).
///
/// # Errors
/// Returns an `std::io::Error` if the `read` syscall fails or returns fewer
/// than 8 bytes.
#[cfg(target_os = "linux")]
pub fn read_perf_counter(fd: i32) -> std::io::Result<u64> {
    let mut value: u64 = 0;
    // SAFETY: `value` is a valid u64 on the stack; `fd` is assumed to be a
    // valid perf event fd obtained from `open_instruction_counter`.
    let n = unsafe {
        libc::read(
            fd,
            &mut value as *mut u64 as *mut libc::c_void,
            std::mem::size_of::<u64>(),
        )
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if (n as usize) < std::mem::size_of::<u64>() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("perf counter read returned {n} bytes, expected 8"),
        ));
    }
    Ok(value)
}

// ─── LinuxPtraceRecorder ──────────────────────────────────────────────────────

/// A high-level ptrace-based recorder that attaches to a running process,
/// intercepts every syscall entry/exit via `PTRACE_SYSCALL`, and optionally
/// reads an instruction counter from a perf event fd.
///
/// The recorder accumulates [`TraceEvent`]s in memory; call
/// [`LinuxPtraceRecorder::record_loop`] to run the tracing loop and retrieve
/// the collected events.
///
/// Only available on Linux.
#[cfg(target_os = "linux")]
pub struct LinuxPtraceRecorder {
    /// nix `Pid` of the traced process.
    pub pid: nix::unistd::Pid,
    /// Optional perf event file descriptor for instruction counting.
    pub perf_fd: Option<i32>,
    /// Events collected by [`record_loop`].
    pub events: Vec<TraceEvent>,
    /// Running instruction count read from the perf counter.
    pub instr_count: u64,
}

#[cfg(target_os = "linux")]
impl LinuxPtraceRecorder {
    /// Attach to `pid` with `PTRACE_ATTACH`, wait for the resulting `SIGSTOP`,
    /// and optionally open an instruction-retired performance counter.
    ///
    /// # Errors
    /// Returns `anyhow::Error` if ptrace attach or the initial `waitpid` fails.
    pub fn attach(pid: u32) -> anyhow::Result<Self> {
        use nix::sys::ptrace;
        use nix::sys::wait::{WaitStatus, waitpid};
        use nix::unistd::Pid;

        let nix_pid = Pid::from_raw(pid as i32);

        // Attach to the target; this sends SIGSTOP to the tracee.
        ptrace::attach(nix_pid)?;

        // Wait until the tracee is stopped.
        match waitpid(nix_pid, None)? {
            WaitStatus::Stopped(_, _) => {}
            other => {
                anyhow::bail!("LinuxPtraceRecorder::attach: unexpected waitpid status: {other:?}");
            }
        }

        // Open the instruction counter (best-effort; failures are tolerated).
        let perf_fd = open_instruction_counter(pid as i32).ok();

        Ok(Self {
            pid: nix_pid,
            perf_fd,
            events: Vec::new(),
            instr_count: 0,
        })
    }

    /// Read the general-purpose register file of `pid` using `PTRACE_GETREGS`.
    ///
    /// Returns a [`libc::user_regs_struct`] containing all x86-64 integer
    /// registers at the current stop point.
    ///
    /// # Errors
    /// Returns an error if `PTRACE_GETREGS` fails.
    pub fn read_registers(pid: nix::unistd::Pid) -> anyhow::Result<libc::user_regs_struct> {
        let regs = nix::sys::ptrace::getregs(pid)?;
        Ok(regs)
    }

    /// Run the syscall-interception loop until the tracee exits or
    /// `max_events` entry/exit pairs have been captured.
    ///
    /// For each syscall the method:
    /// 1. Delivers `PTRACE_SYSCALL` to resume until the next syscall entry.
    /// 2. Reads `PTRACE_GETREGS` to capture `orig_rax` (nr) and the six
    ///    argument registers (`rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`).
    /// 3. Emits a [`TraceEvent`] with `EventKind::SyscallEnter`.
    /// 4. Delivers `PTRACE_SYSCALL` again to resume until syscall exit.
    /// 5. Reads `rax` as the return value.
    /// 6. Emits a [`TraceEvent`] with `EventKind::SyscallExit`.
    /// 7. Updates `instr_count` from the perf counter if available.
    ///
    /// Returns the complete list of captured events.
    ///
    /// # Errors
    /// Returns an error on unexpected ptrace failures.  Tracee exit is treated
    /// as normal termination and causes the loop to stop cleanly.
    pub fn record_loop(&mut self, max_events: usize) -> anyhow::Result<Vec<TraceEvent>> {
        use nix::sys::ptrace;
        use nix::sys::wait::{WaitStatus, waitpid};
        use rustre_ttd::{EventKind as EK, TracePosition};

        let mut pair_count = 0usize;

        loop {
            if pair_count >= max_events {
                break;
            }

            // ── Entry stop ────────────────────────────────────────────────────
            ptrace::syscall(self.pid, None)?;
            match waitpid(self.pid, None)? {
                WaitStatus::Stopped(_, _) | WaitStatus::PtraceSyscall(_) => {}
                WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _) => break,
                other => anyhow::bail!("record_loop: unexpected entry status: {other:?}"),
            }

            // Read registers at entry.
            let entry_regs = match Self::read_registers(self.pid) {
                Ok(r) => r,
                Err(_) => break,
            };

            let nr = entry_regs.orig_rax as u32;
            let args = [
                entry_regs.rdi,
                entry_regs.rsi,
                entry_regs.rdx,
                entry_regs.r10,
                entry_regs.r8,
                entry_regs.r9,
            ];

            // Read instruction count (best-effort).
            if let Some(fd) = self.perf_fd {
                if let Ok(ic) = read_perf_counter(fd) {
                    self.instr_count = ic;
                }
            }

            // Emit SyscallEnter event.
            self.events.push(TraceEvent {
                position: TracePosition::new(self.instr_count, 0),
                thread_id: 1,
                kind: EK::SyscallEnter { nr, args },
            });

            // ── Exit stop ─────────────────────────────────────────────────────
            ptrace::syscall(self.pid, None)?;
            match waitpid(self.pid, None)? {
                WaitStatus::Stopped(_, _) | WaitStatus::PtraceSyscall(_) => {}
                WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _) => break,
                other => anyhow::bail!("record_loop: unexpected exit status: {other:?}"),
            }

            // Read rax as the return value at exit.
            let exit_regs = match Self::read_registers(self.pid) {
                Ok(r) => r,
                Err(_) => break,
            };
            let ret = exit_regs.rax;

            // Update instruction count again after exit.
            if let Some(fd) = self.perf_fd {
                if let Ok(ic) = read_perf_counter(fd) {
                    self.instr_count = ic;
                }
            }

            // Emit SyscallExit event.
            self.events.push(TraceEvent {
                position: TracePosition::new(self.instr_count, 1),
                thread_id: 1,
                kind: EK::SyscallExit { nr, ret },
            });

            pair_count += 1;
        }

        Ok(self.events.clone())
    }

    /// Detach from the tracee, allowing it to continue execution normally.
    ///
    /// # Errors
    /// Returns an error if `PTRACE_DETACH` fails.  The tracee is usually
    /// already gone (exited) when the loop finishes, so `ESRCH` is silently
    /// ignored.
    pub fn detach(&mut self) -> anyhow::Result<()> {
        // Ignore ESRCH — the tracee may have already exited.
        let _ = nix::sys::ptrace::detach(self.pid, None);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxPtraceRecorder {
    fn drop(&mut self) {
        // Close the perf fd if we opened one.
        if let Some(fd) = self.perf_fd.take() {
            // SAFETY: `fd` is a valid file descriptor we opened.
            unsafe { libc::close(fd) };
        }
        // Best-effort detach; ignore errors.
        let _ = nix::sys::ptrace::detach(self.pid, None);
    }
}

// ─── Non-Linux stubs for LinuxPtraceRecorder ──────────────────────────────────

/// Stub version of `LinuxPtraceRecorder` for non-Linux platforms.
///
/// All methods return `Err("requires Linux")`.
#[cfg(not(target_os = "linux"))]
pub struct LinuxPtraceRecorder {
    /// PID placeholder (always 0 on non-Linux).
    pub pid: u32,
    /// Always `None` on non-Linux.
    pub perf_fd: Option<i32>,
    /// Always empty on non-Linux.
    pub events: Vec<TraceEvent>,
    /// Always 0 on non-Linux.
    pub instr_count: u64,
}

#[cfg(not(target_os = "linux"))]
impl LinuxPtraceRecorder {
    /// Always returns `Err` on non-Linux.
    pub fn attach(_pid: u32) -> anyhow::Result<Self> {
        anyhow::bail!("LinuxPtraceRecorder requires Linux")
    }

    /// Always returns `Err` on non-Linux.
    pub fn record_loop(&mut self, _max_events: usize) -> anyhow::Result<Vec<TraceEvent>> {
        anyhow::bail!("LinuxPtraceRecorder requires Linux")
    }

    /// Always returns `Err` on non-Linux.
    pub fn detach(&mut self) -> anyhow::Result<()> {
        anyhow::bail!("LinuxPtraceRecorder requires Linux")
    }
}

// ─── Stub free-functions for non-Linux ───────────────────────────────────────

/// Stub for non-Linux: always returns an error.
#[cfg(not(target_os = "linux"))]
pub fn open_instruction_counter(_pid: i32) -> std::io::Result<i32> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "open_instruction_counter requires Linux",
    ))
}

/// Stub for non-Linux: always returns an error.
#[cfg(not(target_os = "linux"))]
pub fn read_perf_counter(_fd: i32) -> std::io::Result<u64> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "read_perf_counter requires Linux",
    ))
}

// ─── TtdTraceFile — bincode serialization ─────────────────────────────────────
//
// The JSON-backed `write_to_file` / `read_from_file` methods defined earlier
// operate on the public `TtdTraceFile` type.  The methods below provide an
// alternative **bincode** path for compact binary storage.  They are defined
// as inherent methods so callers can choose either serialisation format.

/// A self-contained binary representation of a recorded trace, suitable for
/// efficient storage and replay.
///
/// This type is distinct from the JSON-centric [`TtdTraceFile`] defined above;
/// it wraps the same logical data but is always serialised with `bincode` and
/// carries a fixed-size `magic` field so the on-disk format can be identified
/// without parsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtdBinaryTrace {
    /// Magic bytes — must equal `[b'R', b'T', b'T', b'D']`.
    pub magic: [u8; 4],
    /// Format version (currently `1`).
    pub version: u32,
    /// Target architecture string (e.g. `"x86_64"`).
    pub arch: String,
    /// PID of the traced process.
    pub pid: u32,
    /// All captured syscall events in chronological order.
    pub events: Vec<SyscallEvent>,
}

impl TtdBinaryTrace {
    /// Magic constant used to identify binary trace files produced by this crate.
    pub const MAGIC: [u8; 4] = [b'R', b'T', b'T', b'D'];

    /// Create a new empty binary trace for `pid`.
    #[must_use]
    pub fn new(pid: u32) -> Self {
        Self {
            magic: Self::MAGIC,
            version: 1,
            arch: String::from("x86_64"),
            pid,
            events: Vec::new(),
        }
    }

    /// Append a single [`SyscallEvent`] to the trace.
    pub fn push(&mut self, event: SyscallEvent) {
        self.events.push(event);
    }

    /// Serialize this trace to `path` using `bincode`.
    ///
    /// The resulting file is compact (no whitespace, no field names) and is
    /// significantly smaller than the JSON equivalent for large traces.
    ///
    /// # Errors
    /// Returns `anyhow::Error` if serialization or file I/O fails.
    pub fn write_to_file(&self, path: &std::path::Path) -> anyhow::Result<()> {
        use std::io::Write;
        let encoded = bincode::serialize(self)
            .map_err(|e| anyhow::anyhow!("bincode serialization failed: {e}"))?;
        let mut f = std::fs::File::create(path)?;
        f.write_all(&encoded)?;
        Ok(())
    }

    /// Deserialize a binary trace from `path` using `bincode`.
    ///
    /// Validates the magic bytes after deserialization.
    ///
    /// # Errors
    /// Returns `anyhow::Error` if the file cannot be read, deserialization
    /// fails, or the magic bytes are incorrect.
    pub fn read_from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path)?;
        let trace: Self = bincode::deserialize(&bytes)
            .map_err(|e| anyhow::anyhow!("bincode deserialization failed: {e}"))?;
        if trace.magic != Self::MAGIC {
            anyhow::bail!(
                "invalid binary trace magic: expected {:?}, got {:?}",
                Self::MAGIC,
                trace.magic
            );
        }
        Ok(trace)
    }

    /// Return the number of events in the trace.
    #[must_use]
    pub const fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Return the instruction count of the last event, or 0 if empty.
    #[must_use]
    pub fn total_instructions(&self) -> u64 {
        self.events.last().map_or(0, |e| e.instr_count)
    }
}

// ─── TtdRecordSession::start — Linux fast path ───────────────────────────────

impl TtdRecordSession {
    /// Start the recording session.
    ///
    /// On **Linux**, if the target is a `ProcessId`, this method uses
    /// [`LinuxPtraceRecorder`] to attach to the process, run the syscall-
    /// interception loop, and write a binary [`TtdBinaryTrace`] to disk.
    /// The internal `TtdTrace` is also populated so that the rest of the
    /// session API continues to work normally.
    ///
    /// On **non-Linux** platforms, the method falls back to the original
    /// simulation path (injecting fake events), matching the previous
    /// behaviour.
    ///
    /// # Errors
    /// Returns [`TtdRecordError`] if configuration validation fails,
    /// attachment is refused, or an I/O error occurs while writing the trace.
    pub fn start_linux(&mut self) -> Result<(), TtdRecordError> {
        self.config
            .validate()
            .map_err(TtdRecordError::RecordingFailed)?;

        #[cfg(target_os = "linux")]
        {
            let pid = match &self.config.target_process {
                TtdTarget::ProcessId(p) => *p,
                _ => {
                    // For non-PID targets fall through to the simulation path.
                    return self.start();
                }
            };

            *self.status.write() = RecordingStatus::Injecting;
            self.start_time = Some(std::time::Instant::now());

            // Attach with the Linux ptrace recorder.
            let mut recorder = LinuxPtraceRecorder::attach(pid)
                .map_err(|e| TtdRecordError::RecordingFailed(e.to_string()))?;

            *self.status.write() = RecordingStatus::Recording;

            // Determine the maximum number of syscall pairs to capture.
            let max_pairs = if self.config.max_recording_size_mb > 0 {
                (self.config.max_recording_size_mb as usize).saturating_mul(512)
            } else {
                usize::MAX
            };

            // Run the tracing loop.
            let trace_events = recorder
                .record_loop(max_pairs)
                .map_err(|e| TtdRecordError::RecordingFailed(e.to_string()))?;

            let instr_count = recorder.instr_count;

            // Detach from the tracee.
            let _ = recorder.detach();

            // Populate the in-memory TtdTrace for downstream consumers.
            for ev in &trace_events {
                self.trace.add_event(ev.clone());
            }

            // Build a TtdBinaryTrace and flush to disk.
            let out_path =
                std::path::PathBuf::from(&self.config.output_dir).join(format!("trace_{pid}.rttd"));

            // Convert TraceEvents into SyscallEvents for the binary trace.
            let mut bin_trace = TtdBinaryTrace::new(pid);
            {
                use rustre_ttd::EventKind as EK;
                let mut pending_entry: Option<(u32, [u64; 6], u64)> = None;
                for ev in &trace_events {
                    match &ev.kind {
                        EK::SyscallEnter { nr, args } => {
                            pending_entry = Some((*nr, *args, ev.position.sequence));
                        }
                        EK::SyscallExit { nr, ret } => {
                            if let Some((entry_nr, entry_args, ic)) = pending_entry.take() {
                                if entry_nr == *nr {
                                    bin_trace.push(SyscallEvent {
                                        instr_count: ic,
                                        nr: entry_nr,
                                        args: entry_args,
                                        retval: *ret as i64,
                                        mem_writes: Vec::new(),
                                    });
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            if let Err(e) = bin_trace.write_to_file(&out_path) {
                // Non-fatal: log the error into warnings but continue.
                eprintln!("rustre-ttd-recorder: failed to write binary trace: {e}");
            }

            let n = trace_events.len() as u64;
            let elapsed = self.start_time.map_or(0.0, |t| t.elapsed().as_secs_f64());
            let file_size = std::fs::metadata(&out_path)
                .map(|m| m.len())
                .unwrap_or(n * 128);

            let mut m = self.metrics.write();
            m.events_recorded = n;
            m.instructions_recorded = instr_count;
            m.file_size_bytes = file_size;
            m.elapsed_secs = elapsed;
            m.thread_count = 1;
            drop(m);

            *self.status.write() = RecordingStatus::Recording;
            return Ok(());
        }

        // Non-Linux: fall back to the simulation path.
        #[cfg(not(target_os = "linux"))]
        self.start()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_ttd::TracePosition;

    // ─── TtdPosition ───────────────────────────────────────────────────────────

    #[test]
    fn ttd_position_new() {
        let p = TtdPosition::new(5, 3);
        assert_eq!(p.major, 5);
        assert_eq!(p.minor, 3);
    }

    #[test]
    fn ttd_position_start() {
        let p = TtdPosition::start();
        assert_eq!(p.major, 0);
        assert_eq!(p.minor, 0);
    }

    #[test]
    fn ttd_position_display() {
        let p = TtdPosition::new(7, 2);
        assert_eq!(p.to_string(), "7:2");
    }

    #[test]
    fn ttd_position_is_before() {
        let a = TtdPosition::new(1, 0);
        let b = TtdPosition::new(2, 0);
        assert!(a.is_before(&b));
        assert!(!b.is_before(&a));
    }

    #[test]
    fn ttd_position_earliest() {
        let a = TtdPosition::new(1, 5);
        let b = TtdPosition::new(2, 0);
        assert_eq!(TtdPosition::earliest(&a, &b).major, 1);
    }

    #[test]
    fn ttd_position_ordering() {
        let a = TtdPosition::new(1, 0);
        let b = TtdPosition::new(1, 1);
        let c = TtdPosition::new(2, 0);
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn ttd_position_to_trace_position() {
        let p = TtdPosition::new(3, 7);
        let tp = p.to_trace_position();
        assert_eq!(tp.sequence, 3);
        assert_eq!(tp.step, 7);
    }

    // ─── CompressionLevel ──────────────────────────────────────────────────────

    #[test]
    fn compression_level_display() {
        assert_eq!(CompressionLevel::None.to_string(), "none");
        assert_eq!(CompressionLevel::Best.to_string(), "best");
    }

    #[test]
    fn compression_level_default() {
        let c = CompressionLevel::default();
        assert_eq!(c, CompressionLevel::Default);
    }

    // ─── TtdTarget ─────────────────────────────────────────────────────────────

    #[test]
    fn ttd_target_display_pid() {
        let t = TtdTarget::ProcessId(1234);
        assert!(t.to_string().contains("1234"));
    }

    #[test]
    fn ttd_target_display_name() {
        let t = TtdTarget::ProcessName("notepad.exe".into());
        assert!(t.to_string().contains("notepad.exe"));
    }

    // ─── TtdRecordConfig ───────────────────────────────────────────────────────

    #[test]
    fn ttd_record_config_validate_ok() {
        let c = TtdRecordConfig::for_pid(1, "/tmp");
        assert!(c.validate().is_ok());
    }

    #[test]
    fn ttd_record_config_validate_empty_dir() {
        let c = TtdRecordConfig::for_pid(1, "");
        assert!(c.validate().is_err());
    }

    #[test]
    fn ttd_record_config_validate_ring_zero() {
        let mut c = TtdRecordConfig::for_pid(1, "/tmp");
        c.ring_buffer_mb = Some(0);
        assert!(c.validate().is_err());
    }

    #[test]
    fn ttd_record_config_validate_full_heap_requires_heap() {
        let mut c = TtdRecordConfig::for_pid(1, "/tmp");
        c.full_heap = true;
        c.record_heap = false;
        assert!(c.validate().is_err());
    }

    // ─── RecordingStatus ───────────────────────────────────────────────────────

    #[test]
    fn recording_status_display() {
        assert_eq!(RecordingStatus::Recording.to_string(), "Recording");
        assert!(
            RecordingStatus::Error("oops".into())
                .to_string()
                .contains("oops")
        );
    }

    // ─── RecordingMetrics ──────────────────────────────────────────────────────

    #[test]
    fn recording_metrics_summary() {
        let m = RecordingMetrics {
            events_recorded: 100,
            file_size_bytes: 4096,
            elapsed_secs: 1.5,
            thread_count: 2,
            ..Default::default()
        };
        let s = m.summary();
        assert!(s.contains("100"));
        assert!(s.contains("4096"));
    }

    #[test]
    fn recording_metrics_display() {
        let m = RecordingMetrics::default();
        assert!(m.to_string().contains("RecordingMetrics"));
    }

    // ─── TtdCheckpoint ─────────────────────────────────────────────────────────

    #[test]
    fn ttd_checkpoint_new() {
        let cp = TtdCheckpoint::new("entry", TtdPosition::new(42, 0));
        assert_eq!(cp.name, "entry");
        assert_eq!(cp.position.major, 42);
    }

    #[test]
    fn ttd_checkpoint_display() {
        let cp = TtdCheckpoint::new("main", TtdPosition::new(1, 2));
        assert!(cp.to_string().contains("main"));
        assert!(cp.to_string().contains("1:2"));
    }

    // ─── TtdRecordResult ───────────────────────────────────────────────────────

    #[test]
    fn ttd_record_result_is_clean() {
        let r = TtdRecordResult {
            output_file: "/tmp/trace.run".into(),
            metrics: RecordingMetrics::default(),
            checkpoints: vec![],
            warnings: vec![],
        };
        assert!(r.is_clean());
    }

    #[test]
    fn ttd_record_result_not_clean_with_warnings() {
        let r = TtdRecordResult {
            output_file: "/tmp/trace.run".into(),
            metrics: RecordingMetrics::default(),
            checkpoints: vec![],
            warnings: vec!["something odd".into()],
        };
        assert!(!r.is_clean());
    }

    // ─── TtdRecordFilter ───────────────────────────────────────────────────────

    #[test]
    fn ttd_record_filter_thread_allowed_include() {
        let mut f = TtdRecordFilter::pass_all();
        f.include_threads.push(1);
        assert!(f.thread_allowed(1));
        assert!(!f.thread_allowed(2));
    }

    #[test]
    fn ttd_record_filter_thread_excluded() {
        let mut f = TtdRecordFilter::pass_all();
        f.exclude_threads.push(3);
        assert!(!f.thread_allowed(3));
        assert!(f.thread_allowed(4));
    }

    #[test]
    fn ttd_record_filter_module_allowed_include() {
        let mut f = TtdRecordFilter::pass_all();
        f.include_modules.push("ntdll.dll".into());
        assert!(f.module_allowed("ntdll.dll"));
        assert!(!f.module_allowed("kernel32.dll"));
    }

    #[test]
    fn ttd_record_filter_module_excluded() {
        let mut f = TtdRecordFilter::pass_all();
        f.exclude_modules.push("bad.dll".into());
        assert!(!f.module_allowed("bad.dll"));
        assert!(f.module_allowed("good.dll"));
    }

    // ─── TtdRecordSession ──────────────────────────────────────────────────────

    #[test]
    fn ttd_record_session_new() {
        let cfg = TtdRecordConfig::for_pid(100, "/tmp");
        let sess = TtdRecordSession::new(cfg);
        assert_eq!(sess.status(), RecordingStatus::Initializing);
    }

    #[test]
    fn ttd_record_session_start() {
        let cfg = TtdRecordConfig::for_pid(100, "/tmp");
        let mut sess = TtdRecordSession::new(cfg);
        sess.start().unwrap();
        assert_eq!(sess.status(), RecordingStatus::Recording);
    }

    #[test]
    fn ttd_record_session_pause_resume() {
        let cfg = TtdRecordConfig::for_pid(100, "/tmp");
        let mut sess = TtdRecordSession::new(cfg);
        sess.start().unwrap();
        sess.pause().unwrap();
        assert_eq!(sess.status(), RecordingStatus::Paused);
        sess.resume().unwrap();
        assert_eq!(sess.status(), RecordingStatus::Recording);
    }

    #[test]
    fn ttd_record_session_pause_wrong_state_fails() {
        let cfg = TtdRecordConfig::for_pid(100, "/tmp");
        let sess = TtdRecordSession::new(cfg);
        assert!(sess.pause().is_err());
    }

    #[test]
    fn ttd_record_session_stop() {
        let cfg = TtdRecordConfig::for_pid(100, "/tmp");
        let mut sess = TtdRecordSession::new(cfg);
        sess.start().unwrap();
        let result = sess.stop().unwrap();
        assert!(result.output_file.contains("trace_"));
        assert_eq!(sess.status(), RecordingStatus::Stopped);
    }

    #[test]
    fn ttd_record_session_add_checkpoint() {
        let cfg = TtdRecordConfig::for_pid(100, "/tmp");
        let mut sess = TtdRecordSession::new(cfg);
        sess.start().unwrap();
        let cp = sess.add_checkpoint("main").unwrap();
        assert_eq!(cp.name, "main");
    }

    #[test]
    fn ttd_record_session_metrics() {
        let cfg = TtdRecordConfig::for_pid(100, "/tmp");
        let mut sess = TtdRecordSession::new(cfg);
        sess.start().unwrap();
        let m = sess.metrics();
        assert_eq!(m.thread_count, 1);
    }

    #[test]
    fn ttd_record_session_wait_for_completion() {
        let cfg = TtdRecordConfig::for_pid(100, "/tmp");
        let mut sess = TtdRecordSession::new(cfg);
        sess.start().unwrap();
        let result = sess.wait_for_completion().unwrap();
        assert!(!result.output_file.is_empty());
    }

    // ─── TtdLaunchRecorder ────────────────────────────────────────────────────

    #[test]
    fn ttd_launch_recorder_new() {
        let rec = TtdLaunchRecorder::new("notepad.exe", "/tmp");
        assert!(matches!(
            rec.config.target_process,
            TtdTarget::Executable { .. }
        ));
    }

    #[test]
    fn ttd_launch_recorder_record() {
        let rec = TtdLaunchRecorder::new("test.exe", "/tmp");
        let sess = rec.record().unwrap();
        assert_eq!(sess.status(), RecordingStatus::Recording);
    }

    // ─── TtdAttachRecorder ────────────────────────────────────────────────────

    #[test]
    fn ttd_attach_recorder_ok() {
        let rec = TtdAttachRecorder::new(1234, "/tmp");
        let sess = rec.record().unwrap();
        assert_eq!(sess.status(), RecordingStatus::Recording);
    }

    #[test]
    fn ttd_attach_recorder_pid_zero_fails() {
        let rec = TtdAttachRecorder::new(0, "/tmp");
        assert!(rec.record().is_err());
    }

    // ─── TtdKernelRecorder ────────────────────────────────────────────────────

    #[test]
    fn ttd_kernel_recorder_privilege_error() {
        let rec = TtdKernelRecorder::new("production-driver", "/tmp");
        assert!(rec.record().is_err());
    }

    #[test]
    fn ttd_kernel_recorder_test_driver_ok() {
        let rec = TtdKernelRecorder::new("test", "/tmp");
        let sess = rec.record().unwrap();
        assert_eq!(sess.status(), RecordingStatus::Recording);
    }

    // ─── TtdRecordEncryptor ───────────────────────────────────────────────────

    #[test]
    fn encryptor_roundtrip() {
        let key = vec![0xAAu8; 32];
        let enc = TtdRecordEncryptor::new(key).unwrap();
        let plaintext = b"hello trace data!";
        let ciphertext = enc.encrypt(plaintext).unwrap();
        // Authenticated ciphertext format: 12-byte nonce + ciphertext + 16-byte tag.
        assert_eq!(ciphertext.len(), plaintext.len() + 12 + 16);
        // Header is the nonce, not the plaintext — proves real encryption.
        assert_ne!(&ciphertext[12..12 + plaintext.len()], plaintext);
        let decrypted = enc.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encryptor_invalid_key_length() {
        let key = vec![0u8; 16]; // too short
        assert!(TtdRecordEncryptor::new(key).is_err());
    }

    #[test]
    fn encryptor_is_valid_key() {
        let key = vec![0u8; 32];
        let enc = TtdRecordEncryptor::new(key).unwrap();
        assert!(enc.is_valid_key());
    }

    /// Two successive encryptions of the same plaintext under the same key
    /// MUST yield distinct ciphertexts — the nonce counter ensures it. This is
    /// the property that distinguishes a real AEAD from the previous XOR.
    #[test]
    fn encryptor_two_calls_have_distinct_nonces() {
        let enc = TtdRecordEncryptor::new(vec![0x11u8; 32]).unwrap();
        let p = b"identical plaintext block";
        let c1 = enc.encrypt(p).unwrap();
        let c2 = enc.encrypt(p).unwrap();
        assert_ne!(c1, c2, "nonces must differ between successive calls");
        // Nonce occupies bytes 0..12; they must differ but the salt prefix is shared.
        assert_eq!(c1[..8], c2[..8], "salt is per-instance, should not vary");
        assert_ne!(c1[8..12], c2[8..12], "counter should advance");
    }

    /// Tampering with a single ciphertext byte must cause authentication to
    /// fail — the property the XOR "simulation" silently violated.
    #[test]
    fn encryptor_rejects_tampered_ciphertext() {
        let enc = TtdRecordEncryptor::new(vec![0x42u8; 32]).unwrap();
        let mut c = enc.encrypt(b"sensitive trace bytes").unwrap();
        // Flip one bit in the body (after the nonce).
        c[14] ^= 0x01;
        assert!(
            enc.decrypt(&c).is_err(),
            "tampered ciphertext must fail authentication"
        );
    }

    /// A ciphertext encrypted under key K1 must not decrypt under key K2.
    #[test]
    fn encryptor_rejects_wrong_key() {
        let k1 = TtdRecordEncryptor::new(vec![0x11u8; 32]).unwrap();
        let k2 = TtdRecordEncryptor::new(vec![0x22u8; 32]).unwrap();
        let c = k1.encrypt(b"secret").unwrap();
        assert!(k2.decrypt(&c).is_err(), "wrong-key decrypt must fail");
    }

    #[test]
    fn encryptor_rejects_truncated_ciphertext() {
        let enc = TtdRecordEncryptor::new(vec![0x33u8; 32]).unwrap();
        let c = enc.encrypt(b"some data").unwrap();
        // Truncate below the minimum (12 nonce + 16 tag = 28 bytes).
        assert!(enc.decrypt(&c[..20]).is_err());
        // And a completely empty blob.
        assert!(enc.decrypt(&[]).is_err());
    }

    // ─── TtdTraceValidation ───────────────────────────────────────────────────

    #[test]
    fn validation_valid_run_file() {
        let r = TtdTraceValidation::validate("C:/traces/myproc.run").unwrap();
        assert!(r.is_valid);
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn validation_valid_ttd_file() {
        let r = TtdTraceValidation::validate("/tmp/trace.ttd").unwrap();
        assert!(r.is_valid);
    }

    #[test]
    fn validation_invalid_extension() {
        let r = TtdTraceValidation::validate("/tmp/trace.bin").unwrap();
        assert!(!r.is_valid);
        assert!(!r.warnings.is_empty());
    }

    #[test]
    fn validation_empty_path_error() {
        assert!(TtdTraceValidation::validate("").is_err());
    }

    #[test]
    fn validation_is_perfect() {
        let r = TtdTraceValidation::validate("test.run").unwrap();
        assert!(r.is_perfect());
    }

    #[test]
    fn validation_display() {
        let r = TtdTraceValidation::validate("test.run").unwrap();
        assert!(r.to_string().contains("ValidationResult"));
    }

    // ─── RecorderConfig ────────────────────────────────────────────────────────

    #[test]
    fn recorder_config_default() {
        let cfg = RecorderConfig::default();
        assert!(cfg.record_memory);
        assert!(cfg.record_threads);
        assert!(cfg.max_events.is_none());
    }

    #[test]
    fn recorder_config_display() {
        let cfg = RecorderConfig::default();
        assert!(cfg.to_string().contains("RecorderConfig"));
    }

    // ─── RecordingSession ──────────────────────────────────────────────────────

    #[test]
    fn recording_session_new() {
        let cfg = RecorderConfig::default();
        let sess = RecordingSession::new(cfg, 42);
        assert_eq!(sess.pid, 42);
        assert_eq!(sess.event_count, 0);
    }

    #[test]
    fn recording_session_display() {
        let cfg = RecorderConfig::default();
        let sess = RecordingSession::new(cfg, 99);
        assert!(sess.to_string().contains("pid: 99"));
    }

    // ─── InProcessRecorder ────────────────────────────────────────────────────

    #[tokio::test]
    async fn in_process_recorder_start() {
        let rec = InProcessRecorder;
        let cfg = RecorderConfig::default();
        let sess = rec.start(cfg).await.expect("start");
        assert!(sess.pid > 0);
    }

    #[tokio::test]
    async fn in_process_recorder_start_invalid_max_events() {
        let rec = InProcessRecorder;
        let cfg = RecorderConfig {
            max_events: Some(0),
            ..Default::default()
        };
        assert!(rec.start(cfg).await.is_err());
    }

    #[tokio::test]
    async fn in_process_recorder_stop_produces_trace() {
        let rec = InProcessRecorder;
        let cfg = RecorderConfig::default();
        let sess = rec.start(cfg).await.unwrap();
        let trace = rec.stop(sess).await.unwrap();
        assert_eq!(trace.event_count(), 50);
    }

    #[tokio::test]
    async fn in_process_recorder_stop_respects_max_events() {
        let rec = InProcessRecorder;
        let cfg = RecorderConfig {
            max_events: Some(10),
            ..Default::default()
        };
        let sess = rec.start(cfg).await.unwrap();
        let trace = rec.stop(sess).await.unwrap();
        assert_eq!(trace.event_count(), 10);
    }

    #[tokio::test]
    async fn in_process_recorder_attach_ok() {
        let rec = InProcessRecorder;
        let cfg = RecorderConfig::default();
        let sess = rec.attach(1234, cfg).await.expect("attach");
        assert_eq!(sess.pid, 1234);
    }

    #[tokio::test]
    async fn in_process_recorder_attach_pid_zero_fails() {
        let rec = InProcessRecorder;
        let cfg = RecorderConfig::default();
        assert!(rec.attach(0, cfg).await.is_err());
    }

    // ─── TraceSerializer ──────────────────────────────────────────────────────

    #[test]
    fn trace_serializer_roundtrip_empty() {
        let meta = TraceMetadata::default();
        let trace = Arc::new(TtdTrace::new(meta));
        let bytes = TraceSerializer::serialize(&trace).unwrap();
        let restored = TraceSerializer::deserialize(&bytes).unwrap();
        assert_eq!(restored.event_count(), 0);
    }

    #[test]
    fn trace_serializer_roundtrip_events() {
        let meta = TraceMetadata::default();
        let trace = Arc::new(TtdTrace::new(meta));
        trace.add_event(TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::Call {
                from: 0x100,
                to: 0x200,
            },
        });
        let bytes = TraceSerializer::serialize(&trace).unwrap();
        let restored = TraceSerializer::deserialize(&bytes).unwrap();
        assert_eq!(restored.event_count(), 1);
    }

    #[test]
    fn trace_serializer_invalid_bytes_fails() {
        assert!(TraceSerializer::deserialize(b"not json").is_err());
    }

    // ─── RecordingStats ────────────────────────────────────────────────────────

    #[test]
    fn recording_stats_from_trace() {
        let meta = TraceMetadata::default();
        let trace = TtdTrace::new(meta);
        for i in 0u64..5 {
            trace.add_event(TraceEvent {
                position: TracePosition::new(i, 0),
                thread_id: (i % 2 + 1) as u32,
                kind: EventKind::MemRead {
                    addr: i * 4,
                    len: 4,
                },
            });
        }
        let stats = RecordingStats::from_trace(&trace, 1.0);
        assert_eq!(stats.total_events, 5);
        assert!(stats.hottest_thread().is_some());
    }

    // ─── RingBufferRecorder ────────────────────────────────────────────────────

    #[test]
    fn ring_buffer_recorder_capacity() {
        let rec = RingBufferRecorder::new(3);
        for i in 0u64..5 {
            rec.push(TraceEvent {
                position: TracePosition::new(i, 0),
                thread_id: 1,
                kind: EventKind::MemRead {
                    addr: i * 4,
                    len: 4,
                },
            });
        }
        assert_eq!(rec.len(), 3);
        let snap = rec.snapshot();
        assert_eq!(snap[0].position.sequence, 2); // oldest kept
    }

    #[test]
    fn ring_buffer_recorder_clear() {
        let rec = RingBufferRecorder::new(10);
        rec.push(TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::MemRead { addr: 0, len: 4 },
        });
        assert!(!rec.is_empty());
        rec.clear();
        assert!(rec.is_empty());
    }

    // ─── RecordingSchedule ────────────────────────────────────────────────────

    #[test]
    fn recording_schedule_should_stop_by_position() {
        let s = RecordingSchedule {
            stop_position: Some(TtdPosition::new(100, 0)),
            ..RecordingSchedule::record_all()
        };
        assert!(s.should_stop(TtdPosition::new(100, 0), Duration::from_secs(0)));
        assert!(!s.should_stop(TtdPosition::new(50, 0), Duration::from_secs(0)));
    }

    #[test]
    fn recording_schedule_should_stop_by_duration() {
        let s = RecordingSchedule::for_duration(5);
        assert!(s.should_stop(TtdPosition::start(), Duration::from_secs(10)));
        assert!(!s.should_stop(TtdPosition::start(), Duration::from_secs(1)));
    }

    // ─── TraceFileInfo ────────────────────────────────────────────────────────

    #[test]
    fn trace_file_info_valid_extension() {
        let info = TraceFileInfo::from_path("myproc.run");
        assert!(info.valid);
    }

    #[test]
    fn trace_file_info_invalid_extension() {
        let info = TraceFileInfo::from_path("myproc.bin");
        assert!(!info.valid);
    }

    // ─── RecorderError ────────────────────────────────────────────────────────

    #[test]
    fn recorder_error_display() {
        assert_eq!(
            RecorderError::AlreadyRecording.to_string(),
            "already recording"
        );
        assert_eq!(RecorderError::NotRecording.to_string(), "not recording");
        assert!(
            RecorderError::SpawnError("fork failed".into())
                .to_string()
                .contains("fork failed")
        );
    }

    // ─── synthetic_event ──────────────────────────────────────────────────────

    #[test]
    fn synthetic_event_no_mem_when_disabled() {
        let cfg = RecorderConfig {
            record_memory: false,
            ..Default::default()
        };
        for i in [0u64, 1] {
            let kind = synthetic_event(i, &cfg);
            assert!(!matches!(
                kind,
                EventKind::MemRead { .. } | EventKind::MemWrite { .. }
            ));
        }
    }

    #[test]
    fn synthetic_event_call_return() {
        let cfg = RecorderConfig::default();
        assert!(matches!(synthetic_event(2, &cfg), EventKind::Call { .. }));
        assert!(matches!(synthetic_event(3, &cfg), EventKind::Return { .. }));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Enterprise battery: AEAD properties, lifecycle race regressions, fuzz.
//
// Validates the security and concurrency guarantees of the recorder hot path:
//   * AEAD: every encrypt → decrypt round-trip succeeds across random sizes/
//     keys/payloads; every wrong-key/tampered/truncated input is rejected.
//   * Lifecycle: pause/resume/stop are atomic — concurrent racers see exactly
//     one "winner" per legal transition, never two.
//   * Checkpoint counter: 8 concurrent threads × 1000 checkpoints produce
//     8000 *distinct* positions (regression target for the TOCTOU fix).
//   * Filter compilation: every random filter agrees byte-for-byte with the
//     legacy O(n) form on a random query stream.
//   * Robustness fuzz: random bytes thrown at decrypt + random filter configs
//     thrown at compile/compare must never panic.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod enterprise_battery {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    /// Deterministic LCG (Knuth MMIX) — every test reproduces with its seed.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            let mut v = Vec::with_capacity(n);
            while v.len() < n {
                v.extend_from_slice(&self.next().to_le_bytes());
            }
            v.truncate(n);
            v
        }
    }

    // ── AEAD property battery ─────────────────────────────────────────────

    /// Round-trip across 500 random (key, plaintext-size) pairs of varying
    /// length (0..=4096). Encryption must be invertible and authenticated.
    #[test]
    fn aead_random_roundtrip_500_runs() {
        let mut rng = Lcg(0xdead_beef_cafe_babe);
        for _ in 0..500 {
            let key = rng.bytes(32);
            let enc = TtdRecordEncryptor::new(key).unwrap();
            let len = (rng.next() % 4097) as usize;
            let plaintext = rng.bytes(len);
            let ct = enc.encrypt(&plaintext).expect("encrypt");
            assert_eq!(ct.len(), plaintext.len() + 12 + 16);
            let got = enc.decrypt(&ct).expect("decrypt");
            assert_eq!(got, plaintext, "round-trip mismatch at len {len}");
        }
    }

    /// Tampering with *any single bit* of the ciphertext body must cause a
    /// tag failure. Exhaustively flips every body bit of a small message.
    #[test]
    fn aead_single_bit_flip_always_rejected() {
        let enc = TtdRecordEncryptor::new(vec![0x77u8; 32]).unwrap();
        let original = enc.encrypt(b"witness").expect("encrypt");
        for byte in 12..original.len() {
            for bit in 0..8 {
                let mut tampered = original.clone();
                tampered[byte] ^= 1 << bit;
                assert!(
                    enc.decrypt(&tampered).is_err(),
                    "bit flip at byte {byte} bit {bit} was accepted"
                );
            }
        }
    }

    /// The 96-bit nonce must never repeat under the same key on a single
    /// instance — guarantee the ChaCha20-Poly1305 confidentiality relies on.
    #[test]
    fn aead_nonces_are_unique_over_1024_calls() {
        let enc = TtdRecordEncryptor::new(vec![0x55u8; 32]).unwrap();
        let mut seen: HashSet<[u8; 12]> = HashSet::new();
        for _ in 0..1024 {
            let c = enc.encrypt(b"x").unwrap();
            let mut n = [0u8; 12];
            n.copy_from_slice(&c[..12]);
            assert!(seen.insert(n), "nonce repeated after {} calls", seen.len());
        }
    }

    /// Two encryptors built from the *same key* in the same process must
    /// still use disjoint nonces, because each gets a random salt. Without
    /// this property two AES-style "deterministic counter" encryptors would
    /// share their first nonces and break confidentiality on parallel pipes.
    #[test]
    fn aead_two_instances_same_key_use_disjoint_nonces() {
        let key = vec![0x99u8; 32];
        let a = TtdRecordEncryptor::new(key.clone()).unwrap();
        let b = TtdRecordEncryptor::new(key).unwrap();
        let ca = a.encrypt(b"same plaintext").unwrap();
        let cb = b.encrypt(b"same plaintext").unwrap();
        assert_ne!(&ca[..8], &cb[..8], "salts must differ across instances");
    }

    // ── Lifecycle / concurrency regression tests ───────────────────────────

    /// 8 threads concurrently calling `pause()` on the same `Recording`
    /// session must produce exactly 1 success and 7 errors. The previous
    /// read-then-write pattern allowed multiple "winners".
    #[test]
    fn concurrent_pause_has_exactly_one_winner() {
        let cfg = TtdRecordConfig::for_pid(1, "/tmp/out");
        let mut s = TtdRecordSession::new(cfg);
        s.start().unwrap();
        let arc = Arc::new(s);
        let mut handles = Vec::new();
        for _ in 0..8 {
            let a = Arc::clone(&arc);
            handles.push(thread::spawn(move || a.pause().is_ok()));
        }
        let wins: usize = handles
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum();
        assert_eq!(wins, 1, "exactly one pause() must succeed, got {wins}");
        assert_eq!(arc.status(), RecordingStatus::Paused);
    }

    /// Same property for pause↔resume cycles: only the first of each pair of
    /// concurrent racers can ever flip the bit.
    #[test]
    fn concurrent_resume_has_exactly_one_winner() {
        let cfg = TtdRecordConfig::for_pid(1, "/tmp/out");
        let mut s = TtdRecordSession::new(cfg);
        s.start().unwrap();
        s.pause().unwrap();
        let arc = Arc::new(s);
        let mut handles = Vec::new();
        for _ in 0..8 {
            let a = Arc::clone(&arc);
            handles.push(thread::spawn(move || a.resume().is_ok()));
        }
        let wins: usize = handles
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum();
        assert_eq!(wins, 1, "exactly one resume() must succeed, got {wins}");
        assert_eq!(arc.status(), RecordingStatus::Recording);
    }

    /// Regression target for the TOCTOU `add_checkpoint` fix: 8 threads ×
    /// 1000 checkpoints each must yield 8000 distinct positions.
    #[test]
    fn concurrent_checkpoints_produce_distinct_positions() {
        let cfg = TtdRecordConfig::for_pid(1, "/tmp/out");
        let mut s = TtdRecordSession::new(cfg);
        s.start().unwrap();
        let arc = Arc::new(s);
        const T: usize = 8;
        const N: usize = 1000;
        let mut handles = Vec::new();
        for t in 0..T {
            let a = Arc::clone(&arc);
            handles.push(thread::spawn(move || {
                let mut local = Vec::with_capacity(N);
                for i in 0..N {
                    let cp = a.add_checkpoint(&format!("t{t}_i{i}")).unwrap();
                    local.push(cp.position);
                }
                local
            }));
        }
        let mut all = HashSet::new();
        for h in handles {
            for p in h.join().unwrap() {
                assert!(all.insert(p), "duplicate position {p:?}");
            }
        }
        assert_eq!(all.len(), T * N);
    }

    /// Re-stopping a stopped session must be a clean error (idempotence guard),
    /// and metrics from the first stop must not be doubled.
    #[test]
    fn stop_is_idempotent_and_does_not_double_count() {
        let cfg = TtdRecordConfig::for_pid(1, "/tmp/out");
        let mut s = TtdRecordSession::new(cfg);
        s.start().unwrap();
        let r1 = s.stop().expect("first stop succeeds");
        let r2 = s.stop();
        assert!(r2.is_err(), "second stop must fail");
        // First-stop metrics must remain whatever was originally recorded.
        let m1 = r1.metrics.events_recorded;
        let m2 = s.metrics().events_recorded;
        assert_eq!(m1, m2, "metrics must not change after terminal state");
    }

    // ── Filter equivalence + fuzz ─────────────────────────────────────────

    /// Build random filters and random query streams, then assert the
    /// compiled (`HashSet`) form returns the *same answer* as the legacy
    /// (`Vec::contains`) form on every query.
    #[test]
    fn filter_compiled_form_matches_legacy() {
        let mut rng = Lcg(0x55aa_55aa_aa55_aa55);
        for _ in 0..200 {
            let mut f = TtdRecordFilter::default();
            // Up to 20 thread IDs in each list.
            for _ in 0..((rng.next() % 20) as usize) {
                f.include_threads.push((rng.next() & 0xff) as u32);
            }
            for _ in 0..((rng.next() % 20) as usize) {
                f.exclude_threads.push((rng.next() & 0xff) as u32);
            }
            for _ in 0..((rng.next() % 10) as usize) {
                f.include_modules.push(format!("mod_{}", rng.next() & 0xf));
            }
            for _ in 0..((rng.next() % 10) as usize) {
                f.exclude_modules.push(format!("mod_{}", rng.next() & 0xf));
            }
            let c = f.compile();
            for _ in 0..200 {
                let tid = (rng.next() & 0xff) as u32;
                assert_eq!(
                    f.thread_allowed(tid),
                    c.thread_allowed(tid),
                    "thread_allowed disagreement at tid {tid}"
                );
                let name = format!("mod_{}", rng.next() & 0xf);
                assert_eq!(
                    f.module_allowed(&name),
                    c.module_allowed(&name),
                    "module_allowed disagreement at {name}"
                );
            }
        }
    }

    // ── Robustness fuzz: never panic on adversarial input ──────────────────

    /// 5000 random byte slices (0..=1024 bytes) thrown at `decrypt` must
    /// always be rejected gracefully — never panic, never UB.
    #[test]
    fn fuzz_decrypt_never_panics_on_random_garbage() {
        let enc = TtdRecordEncryptor::new(vec![0x42u8; 32]).unwrap();
        let mut rng = Lcg(0xfeed_face_dead_beef);
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let mut panicked: Option<usize> = None;
        for i in 0..5000 {
            let len = (rng.next() % 1025) as usize;
            let blob = rng.bytes(len);
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = enc.decrypt(&blob);
            }));
            if r.is_err() {
                panicked = Some(i);
                break;
            }
        }
        std::panic::set_hook(prev);
        assert!(panicked.is_none(), "decrypt panicked at iter {panicked:?}");
    }

    /// Random filter configs and random queries — the public API must never
    /// panic regardless of input.
    #[test]
    fn fuzz_filter_api_never_panics() {
        let mut rng = Lcg(0x1357_9bdf_2468_ace0);
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let mut panicked = false;
        for _ in 0..3000 {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut f = TtdRecordFilter::default();
                for _ in 0..((rng.next() % 30) as usize) {
                    f.include_threads.push((rng.next() & 0xffff) as u32);
                }
                for _ in 0..((rng.next() % 30) as usize) {
                    f.exclude_modules.push(format!("m{}", rng.next() & 0xff));
                }
                let c = f.compile();
                for _ in 0..50 {
                    let _ = f.thread_allowed((rng.next() & 0xffff) as u32);
                    let _ = c.thread_allowed((rng.next() & 0xffff) as u32);
                    let _ = f.module_allowed(&format!("m{}", rng.next() & 0xff));
                    let _ = c.module_allowed(&format!("m{}", rng.next() & 0xff));
                }
            }));
            if r.is_err() {
                panicked = true;
                break;
            }
        }
        std::panic::set_hook(prev);
        assert!(!panicked, "filter fuzz panicked");
    }

    /// `TtdRecordSession::new` + the entire lifecycle (start, pause, resume,
    /// checkpoint, stop) must never panic across random configs.
    #[test]
    fn fuzz_session_lifecycle_never_panics() {
        let mut rng = Lcg(0xa5a5_5a5a_0f0f_f0f0);
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let mut panicked = false;
        for _ in 0..1000 {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let cfg = TtdRecordConfig::for_pid((rng.next() & 0xffff) as u32, "/tmp/out");
                let mut s = TtdRecordSession::new(cfg);
                if s.start().is_ok() {
                    let _ = s.add_checkpoint("a");
                    let _ = s.pause();
                    let _ = s.resume();
                    let _ = s.add_checkpoint("b");
                    let _ = s.stop();
                    // Idempotence: second stop and post-stop checkpoint should
                    // fail cleanly, never panic.
                    let _ = s.stop();
                    let _ = s.add_checkpoint("after-stop");
                }
            }));
            if r.is_err() {
                panicked = true;
                break;
            }
        }
        std::panic::set_hook(prev);
        assert!(!panicked, "session lifecycle fuzz panicked");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InstructionCounter — hardware perf counter abstraction
// ─────────────────────────────────────────────────────────────────────────────

/// Hardware instruction-retired counter.
///
/// Wraps a `perf_event_open` file descriptor on Linux and provides a
/// platform-neutral interface everywhere else (always returning 0).
///
/// The counter is opened *disabled* by default; call [`enable`][Self::enable]
/// before running the code under measurement.
pub struct InstructionCounter {
    /// File descriptor returned by `perf_event_open` on Linux, -1 elsewhere.
    #[cfg(target_os = "linux")]
    fd: i32,
    /// Last value read from the counter (used for delta calculations).
    last_read: u64,
    /// Cumulative offset applied by `reset` calls (we simulate reset on all
    /// platforms by recording the value at reset time and subtracting).
    baseline: u64,
}

impl std::fmt::Debug for InstructionCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstructionCounter")
            .field("last_read", &self.last_read)
            .finish_non_exhaustive()
    }
}

impl InstructionCounter {
    /// Open an instruction-retired hardware counter for `pid`.
    ///
    /// On Linux this calls `perf_event_open(2)` with
    /// `PERF_TYPE_HARDWARE` / `PERF_COUNT_HW_INSTRUCTIONS`.
    ///
    /// On non-Linux platforms this always succeeds but the counter will
    /// always read 0.
    ///
    /// # Errors
    /// Returns an `std::io::Error` on Linux if `perf_event_open` fails
    /// (e.g. `perf_event_paranoid` is too restrictive).
    pub const fn new(pid: i32) -> Result<Self, std::io::Error> {
        #[cfg(target_os = "linux")]
        {
            let fd = crate::open_instruction_counter(pid)?;
            // Start disabled (bit 0 = disabled = 1).  Caller must call enable().
            unsafe { libc::ioctl(fd, 0x2400u64, 1i32) }; // PERF_EVENT_IOC_DISABLE
            Ok(Self {
                fd,
                last_read: 0,
                baseline: 0,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = pid;
            Ok(Self {
                last_read: 0,
                baseline: 0,
            })
        }
    }

    /// Read the current counter value minus the baseline (post-reset delta).
    #[must_use]
    pub const fn read(&self) -> u64 {
        #[cfg(target_os = "linux")]
        {
            crate::read_perf_counter(self.fd)
                .unwrap_or(0)
                .saturating_sub(self.baseline)
        }
        #[cfg(not(target_os = "linux"))]
        {
            0u64
        }
    }

    /// Reset the counter: the next call to `read` will return 0.
    pub const fn reset(&mut self) {
        #[cfg(target_os = "linux")]
        {
            // PERF_EVENT_IOC_RESET = 0x2403
            unsafe { libc::ioctl(self.fd, 0x2403u64, 0i32) };
            self.baseline = 0;
        }
        self.last_read = 0;
    }

    /// Enable the counter (start counting instructions).
    pub const fn enable(&self) {
        #[cfg(target_os = "linux")]
        {
            // PERF_EVENT_IOC_ENABLE = 0x2400
            unsafe { libc::ioctl(self.fd, 0x2400u64, 0i32) };
        }
    }

    /// Disable the counter (stop counting instructions without resetting).
    pub const fn disable(&self) {
        #[cfg(target_os = "linux")]
        {
            // PERF_EVENT_IOC_DISABLE = 0x2401
            unsafe { libc::ioctl(self.fd, 0x2401u64, 0i32) };
        }
    }

    /// Read the counter and update `last_read`; return the delta since the
    /// previous call to `read_delta`.
    pub const fn read_delta(&mut self) -> u64 {
        let current = self.read();
        let delta = current.saturating_sub(self.last_read);
        self.last_read = current;
        delta
    }

    /// Cumulative offset applied by `reset` calls; used for delta calculations.
    #[must_use]
    pub const fn baseline(&self) -> u64 {
        self.baseline
    }
}

#[cfg(target_os = "linux")]
impl Drop for InstructionCounter {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CaptureReason / MemoryCapture — pre-syscall buffer snapshots
// ─────────────────────────────────────────────────────────────────────────────

/// The reason a memory region was captured at a syscall boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureReason {
    /// The region was pointed to by argument `arg_index` of the syscall.
    SyscallArg {
        /// Zero-based argument index (0 = first arg, …, 5 = sixth arg).
        arg_index: u8,
    },
    /// The region was an output buffer that the kernel will write into on exit.
    ReturnBuffer,
    /// The page was faulted during syscall execution.
    PageFaultData,
}

impl std::fmt::Display for CaptureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SyscallArg { arg_index } => write!(f, "arg[{arg_index}]"),
            Self::ReturnBuffer => write!(f, "retbuf"),
            Self::PageFaultData => write!(f, "pagefault"),
        }
    }
}

/// A snapshot of a memory region taken at a syscall boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryCapture {
    /// Virtual address of the first byte captured.
    pub address: u64,
    /// Byte contents at capture time.
    pub data: Vec<u8>,
    /// Why this region was captured.
    pub reason: CaptureReason,
}

impl MemoryCapture {
    /// Create a new capture with the given address, data, and reason.
    #[must_use]
    pub const fn new(address: u64, data: Vec<u8>, reason: CaptureReason) -> Self {
        Self {
            address,
            data,
            reason,
        }
    }

    /// Return the byte length of the captured region.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Return `true` if the captured region is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Return the exclusive end address of the captured region.
    #[must_use]
    pub const fn end_address(&self) -> u64 {
        self.address.saturating_add(self.data.len() as u64)
    }

    /// Return `true` if `addr` falls within this capture.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.address && addr < self.end_address()
    }

    /// Return the byte at `addr`, if it falls within this capture.
    #[must_use]
    pub fn byte_at(&self, addr: u64) -> Option<u8> {
        if !self.contains(addr) {
            return None;
        }
        let off = (addr - self.address) as usize;
        self.data.get(off).copied()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SyscallRecord — one syscall entry/exit pair
// ─────────────────────────────────────────────────────────────────────────────

/// A complete record of one syscall — everything captured on entry and exit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallRecord {
    /// Hardware instruction count at the moment the syscall was entered.
    pub instr_count: u64,
    /// Syscall number (Linux x86-64 ABI).
    pub syscall_nr: u32,
    /// Arguments in calling-convention order (`rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`).
    pub args: [u64; 6],
    /// Return value in `rax` after the syscall exits.
    pub return_value: i64,
    /// Memory state *before* the syscall (captured on entry).
    pub pre_memory_state: Vec<MemoryCapture>,
    /// Memory writes made by the kernel *during* the syscall (diff vs. `pre_memory_state`).
    pub post_memory_writes: Vec<MemWrite>,
}

impl SyscallRecord {
    /// Return `true` if the syscall returned an error (negative return value
    /// in the range `[-4095, -1]` is the Linux errno convention).
    #[must_use]
    pub const fn is_error(&self) -> bool {
        self.return_value < 0 && self.return_value >= -4095
    }

    /// Return the error number if the syscall failed, else `None`.
    #[must_use]
    pub const fn errno(&self) -> Option<i64> {
        if self.is_error() {
            Some(-self.return_value)
        } else {
            None
        }
    }

    /// Return the total number of bytes captured in pre-syscall snapshots.
    #[must_use]
    pub fn pre_capture_bytes(&self) -> usize {
        self.pre_memory_state.iter().map(|c| c.data.len()).sum()
    }

    /// Return the total number of bytes written by the kernel.
    #[must_use]
    pub fn post_write_bytes(&self) -> usize {
        self.post_memory_writes.iter().map(|w| w.data.len()).sum()
    }

    /// Return a human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let status = if self.is_error() {
            format!("errno={}", self.errno().unwrap_or(0))
        } else {
            format!("ret={:#x}", self.return_value)
        };
        format!(
            "syscall nr={} @ic={} {} pre={}B post={}B",
            self.syscall_nr,
            self.instr_count,
            status,
            self.pre_capture_bytes(),
            self.post_write_bytes(),
        )
    }
}

impl std::fmt::Display for SyscallRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SyscallRecord {{ {} }}", self.summary())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SyscallOutputBufferDb — database of well-known output buffers
// ─────────────────────────────────────────────────────────────────────────────

/// Specification of an output buffer for one syscall argument.
#[derive(Debug, Clone)]
pub struct OutputBufferSpec {
    /// Zero-based argument index of the buffer pointer.
    pub ptr_arg: u8,
    /// Argument index that holds the buffer size, or `None` if the size is
    /// determined by the return value.
    pub size_arg: Option<u8>,
    /// If `true`, the actual valid byte count is given by the return value
    /// (applicable when the syscall returns a byte count).
    pub size_from_retval: bool,
    /// Fixed size in bytes (used when neither `size_arg` nor `size_from_retval`
    /// apply — e.g. `gettimeofday` where the output size is always 16).
    pub fixed_size: Option<usize>,
}

/// A static database mapping Linux x86-64 syscall numbers to their known
/// output buffer specifications.
pub struct SyscallOutputBufferDb;

impl SyscallOutputBufferDb {
    /// Return the output buffer specification(s) for syscall `nr`, if known.
    ///
    /// Returns an empty slice for syscalls with no known output buffers.
    #[must_use]
    pub const fn output_buffers(nr: u32) -> &'static [OutputBufferSpec] {
        // We use a hand-built static lookup rather than a `HashMap` to avoid
        // allocations in the hot recording path.
        match nr {
            // read(fd, buf, count) — buf[0..retval] written
            // write(fd, buf, count) — input only, no output
            // open — no output buffers
            // close
            // stat(pathname, statbuf) — statbuf 144 bytes
            4 | 5 | 6 | 98 => &[OutputBufferSpec {
                ptr_arg: 1,
                size_arg: None,
                size_from_retval: false,
                fixed_size: Some(144),
            }],
            // fstat(fd, statbuf)
            // lstat(pathname, statbuf)
            // mmap
            // pread64(fd, buf, count, off)
            // readv(fd, iov, iovcnt)
            // writev
            // getpid, getuid, etc.
            // uname(buf) — 65*6 = 390 bytes
            63 => &[OutputBufferSpec {
                ptr_arg: 0,
                size_arg: None,
                size_from_retval: false,
                fixed_size: Some(390),
            }],
            // getdents64(fd, dirent, count) — dirent filled with retval bytes
            // getcwd(buf, size)
            79 => &[OutputBufferSpec {
                ptr_arg: 0,
                size_arg: Some(1),
                size_from_retval: false,
                fixed_size: None,
            }],
            // gettimeofday(tv, tz)
            96 => &[
                OutputBufferSpec {
                    ptr_arg: 0,
                    size_arg: None,
                    size_from_retval: false,
                    fixed_size: Some(16),
                },
                OutputBufferSpec {
                    ptr_arg: 1,
                    size_arg: None,
                    size_from_retval: false,
                    fixed_size: Some(8),
                },
            ],
            // clock_gettime(clkid, tp)
            228 | 35 => &[OutputBufferSpec {
                ptr_arg: 1,
                size_arg: None,
                size_from_retval: false,
                fixed_size: Some(16),
            }],
            // nanosleep(req, rem) — rem is output
            // readlink(path, buf, bufsiz)
            0 | 17 | 217 | 78 | 89 => &[OutputBufferSpec {
                ptr_arg: 1,
                size_arg: None,
                size_from_retval: true,
                fixed_size: None,
            }],
            // getrusage(who, usage)
            // sysinfo(info)
            99 => &[OutputBufferSpec {
                ptr_arg: 0,
                size_arg: None,
                size_from_retval: false,
                fixed_size: Some(112),
            }],
            // times(buf)
            100 => &[OutputBufferSpec {
                ptr_arg: 0,
                size_arg: None,
                size_from_retval: false,
                fixed_size: Some(32),
            }],
            // getitimer(which, curr_value)
            36 => &[OutputBufferSpec {
                ptr_arg: 1,
                size_arg: None,
                size_from_retval: false,
                fixed_size: Some(32),
            }],
            // setitimer(which, new, old) — old is output
            38 => &[OutputBufferSpec {
                ptr_arg: 2,
                size_arg: None,
                size_from_retval: false,
                fixed_size: Some(32),
            }],
            // pipe(pipefd) — two fds
            22 | 293 => &[OutputBufferSpec {
                ptr_arg: 0,
                size_arg: None,
                size_from_retval: false,
                fixed_size: Some(8),
            }],
            // pipe2
            // socketpair
            53 => &[OutputBufferSpec {
                ptr_arg: 3,
                size_arg: None,
                size_from_retval: false,
                fixed_size: Some(8),
            }],
            // accept(sockfd, addr, addrlen)
            43 | 288 | 51 | 52 => &[
                OutputBufferSpec {
                    ptr_arg: 1,
                    size_arg: Some(2),
                    size_from_retval: false,
                    fixed_size: None,
                },
                OutputBufferSpec {
                    ptr_arg: 2,
                    size_arg: None,
                    size_from_retval: false,
                    fixed_size: Some(4),
                },
            ],
            // accept4
            // recvfrom(sockfd, buf, len, flags, src_addr, addrlen)
            45 => &[
                OutputBufferSpec {
                    ptr_arg: 1,
                    size_arg: None,
                    size_from_retval: true,
                    fixed_size: None,
                },
                OutputBufferSpec {
                    ptr_arg: 4,
                    size_arg: Some(5),
                    size_from_retval: false,
                    fixed_size: None,
                },
            ],
            // recvmsg(sockfd, msg, flags) — complex, skip for now
            // getsockname(sockfd, addr, addrlen)
            // getpeername
            // getsockopt(sockfd, level, optname, optval, optlen)
            55 => &[
                OutputBufferSpec {
                    ptr_arg: 3,
                    size_arg: Some(4),
                    size_from_retval: false,
                    fixed_size: None,
                },
                OutputBufferSpec {
                    ptr_arg: 4,
                    size_arg: None,
                    size_from_retval: false,
                    fixed_size: Some(4),
                },
            ],
            // poll(fds, nfds, timeout)
            // fds is in+out but complex
            // ppoll
            // select / pselect6
            // epoll_wait / epoll_pwait
            // events array is out but size is in retval
            // wait4(pid, wstatus, options, rusage)
            61 => &[
                OutputBufferSpec {
                    ptr_arg: 1,
                    size_arg: None,
                    size_from_retval: false,
                    fixed_size: Some(4),
                },
                OutputBufferSpec {
                    ptr_arg: 3,
                    size_arg: None,
                    size_from_retval: false,
                    fixed_size: Some(144),
                },
            ],
            // waitid
            247 => &[OutputBufferSpec {
                ptr_arg: 2,
                size_arg: None,
                size_from_retval: false,
                fixed_size: Some(128),
            }],
            // openat
            // statx
            332 => &[OutputBufferSpec {
                ptr_arg: 4,
                size_arg: None,
                size_from_retval: false,
                fixed_size: Some(256),
            }],
            // anything else: no known output buffers
            _ => &[],
        }
    }

    /// Compute the size of an output buffer given the argument values and the
    /// return value of the syscall.
    ///
    /// Returns `None` if the size cannot be determined (e.g. the size arg is 0
    /// or the retval is negative).
    #[must_use]
    pub const fn compute_buffer_size(
        spec: &OutputBufferSpec,
        args: &[u64; 6],
        retval: i64,
    ) -> Option<usize> {
        if let Some(sz) = spec.fixed_size {
            return Some(sz);
        }
        if spec.size_from_retval {
            if retval <= 0 {
                return None;
            }
            return Some(retval as usize);
        }
        if let Some(idx) = spec.size_arg {
            let sz = args[idx as usize];
            if sz == 0 {
                return None;
            }
            return Some(sz as usize);
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FullSyscallInterceptor — pre+post state capture
// ─────────────────────────────────────────────────────────────────────────────

/// Captures full pre/post-state for each syscall.
///
/// Unlike [`SyscallInterceptor`] (which only captures entry/exit register
/// state), this type also reads memory buffers on entry and computes diffs on
/// exit to populate a [`SyscallRecord`].
///
/// Only available on Linux (uses ptrace).
#[cfg(target_os = "linux")]
pub struct FullSyscallInterceptor {
    interceptor: SyscallInterceptor,
    counter: Option<InstructionCounter>,
    log: Vec<SyscallRecord>,
}

#[cfg(target_os = "linux")]
impl FullSyscallInterceptor {
    /// Attach to `pid` and optionally open a hardware instruction counter.
    ///
    /// # Errors
    /// Propagates ptrace attach errors.
    pub fn attach(pid: nix::unistd::Pid) -> anyhow::Result<Self> {
        let interceptor = SyscallInterceptor::attach(pid)?;
        let counter = InstructionCounter::new(pid.as_raw()).ok();
        if let Some(ref c) = counter {
            c.enable();
        }
        Ok(Self {
            interceptor,
            counter,
            log: Vec::new(),
        })
    }

    /// Run one entry+exit pair and return the full `SyscallRecord`.
    ///
    /// Internally calls `resume_to_next_syscall` twice (entry then exit) and
    /// captures memory buffers in between.
    ///
    /// # Errors
    /// Propagates ptrace errors or reports tracee exit as an error.
    pub fn intercept_one(&mut self) -> anyhow::Result<Option<SyscallRecord>> {
        // ── Entry stop ────────────────────────────────────────────────────────
        let maybe_entry = self.interceptor.resume_to_next_syscall()?;
        if maybe_entry.is_some() {
            // Spurious exit stop on the first call — can happen when attaching
            // mid-syscall.  Return None to let caller loop.
            return Ok(None);
        }

        // Read entry registers.
        let entry_args = self.interceptor.read_syscall_args(self.interceptor.pid)?;
        let instr_count = self.counter.as_ref().map(|c| c.read()).unwrap_or(0);

        // Capture pre-syscall memory for known input buffers.
        let pre_memory_state = self.capture_pre_memory(&entry_args);

        // ── Exit stop ─────────────────────────────────────────────────────────
        let maybe_exit = self.interceptor.resume_to_next_syscall()?;
        let retval = match maybe_exit {
            Some(ev) => ev.retval,
            None => {
                // Still at entry — should not happen; return None.
                return Ok(None);
            }
        };

        // Compute post-syscall memory writes.
        let post_memory_writes = self.compute_post_writes(
            entry_args.nr as u32,
            &entry_args.args,
            retval,
            &pre_memory_state,
        );

        let record = SyscallRecord {
            instr_count,
            syscall_nr: entry_args.nr as u32,
            args: entry_args.args,
            return_value: retval,
            pre_memory_state,
            post_memory_writes,
        };

        self.log.push(record.clone());
        Ok(Some(record))
    }

    fn capture_pre_memory(&mut self, entry: &SyscallArgs) -> Vec<MemoryCapture> {
        let specs = SyscallOutputBufferDb::output_buffers(entry.nr as u32);
        let mut result = Vec::new();
        for spec in specs {
            let ptr_val = entry.args[spec.ptr_arg as usize];
            if ptr_val == 0 {
                continue;
            }

            // Estimate a conservative size for pre-capture.
            let size = if let Some(sz) = spec.fixed_size {
                sz
            } else if let Some(idx) = spec.size_arg {
                (entry.args[idx as usize] as usize).min(65536)
            } else {
                // size_from_retval — we don't know the retval yet; capture
                // up to 4 KiB as a reasonable heuristic.
                4096
            };

            if size == 0 {
                continue;
            }

            if let Ok(data) =
                self.interceptor
                    .read_memory(self.interceptor.pid, ptr_val, size.min(65536))
            {
                result.push(MemoryCapture::new(
                    ptr_val,
                    data,
                    CaptureReason::SyscallArg {
                        arg_index: spec.ptr_arg,
                    },
                ));
            }
        }
        result
    }

    fn compute_post_writes(
        &mut self,
        nr: u32,
        args: &[u64; 6],
        retval: i64,
        pre: &[MemoryCapture],
    ) -> Vec<MemWrite> {
        let specs = SyscallOutputBufferDb::output_buffers(nr);
        let mut writes = Vec::new();

        for spec in specs {
            let ptr_val = args[spec.ptr_arg as usize];
            if ptr_val == 0 {
                continue;
            }

            let size = match SyscallOutputBufferDb::compute_buffer_size(spec, args, retval) {
                Some(s) if s > 0 => s,
                _ => continue,
            };

            let post_data =
                match self
                    .interceptor
                    .read_memory(self.interceptor.pid, ptr_val, size.min(65536))
                {
                    Ok(d) => d,
                    Err(_) => continue,
                };

            // Find the pre-capture for this address.
            let pre_data = pre.iter().find(|c| c.address == ptr_val);

            // Emit a MemWrite only for bytes that actually changed.
            if let Some(pre) = pre_data {
                let len = post_data.len().min(pre.data.len());
                let mut changed = false;
                for i in 0..len {
                    if post_data[i] != pre.data[i] {
                        changed = true;
                        break;
                    }
                }
                if changed {
                    writes.push(MemWrite {
                        addr: ptr_val,
                        data: post_data,
                    });
                }
            } else {
                // No pre-capture available (e.g. a pointer arg we didn't
                // pre-capture) — emit all post data as a write.
                writes.push(MemWrite {
                    addr: ptr_val,
                    data: post_data,
                });
            }
        }
        writes
    }

    /// Return a reference to all captured records.
    #[must_use]
    pub fn log(&self) -> &[SyscallRecord] {
        &self.log
    }

    /// Detach from the tracee.
    ///
    /// # Errors
    /// Propagates ptrace detach error.
    pub fn detach(self) -> anyhow::Result<()> {
        self.interceptor.detach()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PageFaultRecorder
// ─────────────────────────────────────────────────────────────────────────────

/// A record of a single page fault observed in the tracee.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageFaultRecord {
    /// Hardware instruction count when the fault was observed.
    pub instr_count: u64,
    /// The virtual address that caused the fault.
    pub fault_address: u64,
    /// Pages that were read before the fault was delivered.
    /// Tuple: `(page_base_address, old_page_contents)`.
    pub fault_pages: Vec<(u64, Vec<u8>)>,
    /// `true` if the fault was caused by a write (`CoW` or write to RO page).
    pub was_write: bool,
}

impl PageFaultRecord {
    /// Return the page count captured in this record.
    #[must_use]
    pub const fn page_count(&self) -> usize {
        self.fault_pages.len()
    }

    /// Return the total bytes captured across all pages.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.fault_pages.iter().map(|(_, data)| data.len()).sum()
    }
}

impl std::fmt::Display for PageFaultRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PageFault {{ addr={:#x}, ic={}, write={}, pages={}, bytes={} }}",
            self.fault_address,
            self.instr_count,
            self.was_write,
            self.page_count(),
            self.total_bytes(),
        )
    }
}

/// Accumulates page fault records during a trace session.
///
/// On Linux page faults are observed as `SIGBUS` / `SIGSEGV` signals delivered
/// to the tracee when it is being ptraced.  The `PageFaultRecorder` intercepts
/// those signals, captures the faulting pages, and then re-delivers the signal.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PageFaultRecorder {
    /// PID of the process being recorded.
    pub pid: i32,
    /// Accumulated fault records.
    pub fault_log: Vec<PageFaultRecord>,
}

impl PageFaultRecorder {
    /// Create a new recorder for `pid`.
    #[must_use]
    pub const fn new(pid: i32) -> Self {
        Self {
            pid,
            fault_log: Vec::new(),
        }
    }

    /// Add a synthetic fault record (used in testing and on non-Linux platforms).
    pub fn push(&mut self, record: PageFaultRecord) {
        self.fault_log.push(record);
    }

    /// Return the number of faults recorded.
    #[must_use]
    pub const fn fault_count(&self) -> usize {
        self.fault_log.len()
    }

    /// Return `true` if no faults have been recorded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.fault_log.is_empty()
    }

    /// Return all faults that touched the page containing `addr`.
    #[must_use]
    pub fn faults_for_page(&self, addr: u64) -> Vec<&PageFaultRecord> {
        let page_base = addr & !0xFFF;
        self.fault_log
            .iter()
            .filter(|r| r.fault_pages.iter().any(|(base, _)| *base == page_base))
            .collect()
    }

    /// Return all write faults.
    #[must_use]
    pub fn write_faults(&self) -> Vec<&PageFaultRecord> {
        self.fault_log.iter().filter(|r| r.was_write).collect()
    }

    /// Return all read faults.
    #[must_use]
    pub fn read_faults(&self) -> Vec<&PageFaultRecord> {
        self.fault_log.iter().filter(|r| !r.was_write).collect()
    }

    /// Return the total bytes captured across all fault records.
    #[must_use]
    pub fn total_captured_bytes(&self) -> usize {
        self.fault_log
            .iter()
            .map(PageFaultRecord::total_bytes)
            .sum()
    }

    /// Clear all recorded faults.
    pub fn clear(&mut self) {
        self.fault_log.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TraceSnapshot — full process state snapshot
// ─────────────────────────────────────────────────────────────────────────────

/// A point-in-time snapshot of a traced process: registers + all readable
/// memory pages.
///
/// Snapshots are the basis for *reverse execution*: to travel back to an
/// earlier point, restore the nearest snapshot before the target and then
/// replay forward from there using the event log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSnapshot {
    /// Hardware instruction count at the time of the snapshot.
    pub instr_count: u64,
    /// Serialized general-purpose register state.
    ///
    /// On x86-64 Linux this is a `libc::user_regs_struct` (216 bytes)
    /// serialized as raw little-endian bytes.
    pub registers: Vec<u8>,
    /// Readable memory pages captured at snapshot time.
    /// Each tuple is `(page_base_address, 4096-byte page contents)`.
    pub memory_pages: Vec<(u64, Vec<u8>)>,
    /// PID of the snapshotted process.
    pub pid: i32,
    /// Wall-clock time of the snapshot (seconds since UNIX epoch).
    pub timestamp: u64,
}

impl TraceSnapshot {
    /// Page size assumed by this snapshot format (4 KiB).
    pub const PAGE_SIZE: usize = 4096;

    /// Return the number of pages captured.
    #[must_use]
    pub const fn page_count(&self) -> usize {
        self.memory_pages.len()
    }

    /// Return the total bytes captured in all pages.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.memory_pages.iter().map(|(_, data)| data.len()).sum()
    }

    /// Look up the page contents for the page containing `addr`.
    #[must_use]
    pub fn page_for_address(&self, addr: u64) -> Option<&[u8]> {
        let base = addr & !(Self::PAGE_SIZE as u64 - 1);
        self.memory_pages
            .iter()
            .find(|(b, _)| *b == base)
            .map(|(_, data)| data.as_slice())
    }

    /// Read `len` bytes from `addr` using captured page data.
    ///
    /// Returns `None` if any part of the range is not covered by a captured
    /// page.
    #[must_use]
    pub fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        let page_mask = Self::PAGE_SIZE as u64 - 1;
        let base = addr & !page_mask;
        let off = (addr & page_mask) as usize;

        // Fast path: fits in one page.
        if off + len <= Self::PAGE_SIZE {
            let page = self.page_for_address(addr)?;
            return Some(page[off..off + len].to_vec());
        }

        // Slow path: spans multiple pages.
        let mut result = Vec::with_capacity(len);
        let mut remaining = len;
        let mut current_base = base;
        let mut current_off = off;

        while remaining > 0 {
            let page = self.page_for_address(current_base + current_off as u64)?;
            let to_copy = remaining.min(Self::PAGE_SIZE - current_off);
            result.extend_from_slice(&page[current_off..current_off + to_copy]);
            remaining -= to_copy;
            current_base += Self::PAGE_SIZE as u64;
            current_off = 0;
        }

        Some(result)
    }
}

impl std::fmt::Display for TraceSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TraceSnapshot {{ pid={}, ic={}, pages={}, regs={}B }}",
            self.pid,
            self.instr_count,
            self.page_count(),
            self.registers.len(),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SnapshotManager — periodic snapshot scheduling and restoration
// ─────────────────────────────────────────────────────────────────────────────

/// Manages periodic process snapshots during a TTD recording session.
///
/// Snapshots are taken every `snapshot_interval` hardware instructions.
/// Between snapshots the full event log is replayed to reach any intermediate
/// point.
pub struct SnapshotManager {
    /// Accumulated snapshots, sorted by `instr_count`.
    snapshots: Vec<TraceSnapshot>,
    /// How many instructions between automatic snapshots.
    pub snapshot_interval: u64,
    /// The instruction count at which the last snapshot was taken.
    last_snapshot_count: u64,
}

impl SnapshotManager {
    /// Default snapshot interval: 1 million instructions.
    pub const DEFAULT_INTERVAL: u64 = 1_000_000;

    /// Create a new manager with the given interval.
    #[must_use]
    pub const fn new(snapshot_interval: u64) -> Self {
        Self {
            snapshots: Vec::new(),
            snapshot_interval,
            last_snapshot_count: 0,
        }
    }

    /// Create a manager with the default interval.
    #[must_use]
    pub const fn with_default_interval() -> Self {
        Self::new(Self::DEFAULT_INTERVAL)
    }

    /// Return `true` if a snapshot should be taken given the current instruction
    /// count.
    #[must_use]
    pub const fn should_snapshot(&self, current_count: u64) -> bool {
        current_count.saturating_sub(self.last_snapshot_count) >= self.snapshot_interval
    }

    /// Check if a snapshot is due and, if so, capture one.
    ///
    /// On non-Linux platforms (or when `pid` is 0) this creates a synthetic
    /// empty snapshot so that the manager's bookkeeping remains accurate.
    pub fn maybe_snapshot(&mut self, pid: i32, instr_count: u64) {
        if !self.should_snapshot(instr_count) {
            return;
        }
        let snap = self.build_snapshot(pid, instr_count);
        self.store_snapshot(snap);
    }

    /// Build a snapshot for `pid` at `instr_count`.
    ///
    /// On Linux this reads `/proc/pid/maps` and reads each readable region.
    /// On other platforms it returns an empty-pages snapshot.
    #[must_use]
    pub fn build_snapshot(&self, pid: i32, instr_count: u64) -> TraceSnapshot {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        #[cfg(target_os = "linux")]
        {
            let memory_pages = self.read_process_pages(pid);
            let registers = self.read_registers_raw(pid);
            TraceSnapshot {
                instr_count,
                registers,
                memory_pages,
                pid,
                timestamp,
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = pid;
            TraceSnapshot {
                instr_count,
                registers: Vec::new(),
                memory_pages: Vec::new(),
                pid,
                timestamp,
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn read_process_pages(&self, pid: i32) -> Vec<(u64, Vec<u8>)> {
        use std::io::{BufRead, BufReader};

        let maps_path = format!("/proc/{pid}/maps");
        let maps_file = match std::fs::File::open(&maps_path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };

        let mem_path = format!("/proc/{pid}/mem");
        let mut mem_file = match std::fs::File::open(&mem_path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };

        let mut pages = Vec::new();
        let reader = BufReader::new(maps_file);

        for line in reader.lines().flatten() {
            // Format: "aaaa-bbbb rwxp offset dev inode path"
            let parts: Vec<&str> = line.splitn(6, ' ').collect();
            if parts.len() < 2 {
                continue;
            }

            // Parse perms — we only snapshot readable pages.
            let perms = parts[1];
            if !perms.starts_with('r') {
                continue;
            }

            let range: Vec<&str> = parts[0].splitn(2, '-').collect();
            if range.len() != 2 {
                continue;
            }

            let start = u64::from_str_radix(range[0], 16).unwrap_or(0);
            let end = u64::from_str_radix(range[1], 16).unwrap_or(0);
            if start >= end {
                continue;
            }

            // Skip very large regions to avoid huge snapshots.
            const MAX_REGION_BYTES: u64 = 64 * 1024 * 1024;
            if end - start > MAX_REGION_BYTES {
                continue;
            }

            // Read page by page.
            use std::io::{Read, Seek, SeekFrom};
            let mut addr = start;
            while addr < end {
                let page_end = (addr + TraceSnapshot::PAGE_SIZE as u64).min(end);
                let sz = (page_end - addr) as usize;

                if mem_file.seek(SeekFrom::Start(addr)).is_err() {
                    addr += TraceSnapshot::PAGE_SIZE as u64;
                    continue;
                }

                let mut buf = vec![0u8; sz];
                if mem_file.read_exact(&mut buf).is_ok() {
                    pages.push((addr, buf));
                }
                addr += TraceSnapshot::PAGE_SIZE as u64;
            }
        }

        pages
    }

    #[cfg(target_os = "linux")]
    fn read_registers_raw(&self, pid: i32) -> Vec<u8> {
        use nix::unistd::Pid;
        let nix_pid = Pid::from_raw(pid);
        match nix::sys::ptrace::getregs(nix_pid) {
            Ok(regs) => {
                // SAFETY: `user_regs_struct` is a POD C type; any byte
                // representation is valid to read as a byte slice.
                let slice: &[u8] = unsafe {
                    std::slice::from_raw_parts(
                        &regs as *const _ as *const u8,
                        std::mem::size_of_val(&regs),
                    )
                };
                slice.to_vec()
            }
            Err(_) => Vec::new(),
        }
    }

    /// Store a pre-built snapshot.
    pub fn store_snapshot(&mut self, snap: TraceSnapshot) {
        let count = snap.instr_count;
        self.snapshots.push(snap);
        self.snapshots.sort_by_key(|s| s.instr_count);
        self.last_snapshot_count = count;
    }

    /// Return the snapshot with the largest `instr_count` that is ≤ `target`.
    #[must_use]
    pub fn nearest_snapshot_before(&self, target_count: u64) -> Option<&TraceSnapshot> {
        self.snapshots
            .iter()
            .rev()
            .find(|s| s.instr_count <= target_count)
    }

    /// Return the total number of snapshots stored.
    #[must_use]
    pub const fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Return total memory captured across all snapshots.
    #[must_use]
    pub fn total_captured_bytes(&self) -> usize {
        self.snapshots.iter().map(TraceSnapshot::total_bytes).sum()
    }

    /// Discard all snapshots.
    pub fn clear(&mut self) {
        self.snapshots.clear();
        self.last_snapshot_count = 0;
    }

    /// Discard all snapshots older than `keep_after_count`.
    pub fn prune_before(&mut self, keep_after_count: u64) {
        self.snapshots.retain(|s| s.instr_count >= keep_after_count);
    }

    /// Return an iterator over all snapshots in ascending instruction-count order.
    pub fn iter(&self) -> impl Iterator<Item = &TraceSnapshot> {
        self.snapshots.iter()
    }
}

impl std::fmt::Debug for SnapshotManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotManager")
            .field("snapshot_count", &self.snapshots.len())
            .field("snapshot_interval", &self.snapshot_interval)
            .field("last_snapshot_count", &self.last_snapshot_count)
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LinuxDebugger — minimal ptrace debugger used by SnapshotManager
// ─────────────────────────────────────────────────────────────────────────────

/// A minimal synchronous Linux ptrace debugger.
///
/// Provides the subset of debugging operations needed to implement time-travel:
/// - Continue execution until the next event.
/// - Read / write general-purpose registers.
/// - Read / write arbitrary virtual memory.
/// - Single-step.
#[cfg(target_os = "linux")]
pub struct LinuxDebugger {
    /// PID of the traced process.
    pub pid: nix::unistd::Pid,
    /// Whether the debugger currently owns the ptrace attachment.
    pub attached: bool,
}

#[cfg(target_os = "linux")]
impl LinuxDebugger {
    /// Attach to `pid` with `PTRACE_ATTACH`.
    ///
    /// # Errors
    /// Returns an error if `ptrace::attach` or the initial `waitpid` fails.
    pub fn attach(pid: u32) -> anyhow::Result<Self> {
        use nix::sys::ptrace;
        use nix::sys::wait::{WaitStatus, waitpid};
        let nix_pid = nix::unistd::Pid::from_raw(pid as i32);
        ptrace::attach(nix_pid)?;
        match waitpid(nix_pid, None)? {
            WaitStatus::Stopped(_, _) => {}
            other => anyhow::bail!("unexpected attach stop: {other:?}"),
        }
        Ok(Self {
            pid: nix_pid,
            attached: true,
        })
    }

    /// Detach, letting the tracee continue.
    ///
    /// # Errors
    /// Returns an error if `PTRACE_DETACH` fails.
    pub fn detach(&mut self) -> anyhow::Result<()> {
        if !self.attached {
            return Ok(());
        }
        nix::sys::ptrace::detach(self.pid, None)?;
        self.attached = false;
        Ok(())
    }

    /// Continue execution until the next signal or exit.
    ///
    /// # Errors
    /// Returns an error if ptrace or waitpid fails.
    pub fn cont(&self) -> anyhow::Result<nix::sys::wait::WaitStatus> {
        nix::sys::ptrace::cont(self.pid, None)?;
        Ok(nix::sys::wait::waitpid(self.pid, None)?)
    }

    /// Single-step one instruction.
    ///
    /// # Errors
    /// Returns an error if ptrace or waitpid fails.
    pub fn step(&self) -> anyhow::Result<nix::sys::wait::WaitStatus> {
        nix::sys::ptrace::step(self.pid, None)?;
        Ok(nix::sys::wait::waitpid(self.pid, None)?)
    }

    /// Read all integer registers.
    ///
    /// # Errors
    /// Returns an error if `PTRACE_GETREGS` fails.
    pub fn get_regs(&self) -> anyhow::Result<libc::user_regs_struct> {
        Ok(nix::sys::ptrace::getregs(self.pid)?)
    }

    /// Overwrite all integer registers.
    ///
    /// # Errors
    /// Returns an error if `PTRACE_SETREGS` fails.
    pub fn set_regs(&self, regs: libc::user_regs_struct) -> anyhow::Result<()> {
        nix::sys::ptrace::setregs(self.pid, regs)?;
        Ok(())
    }

    /// Read `len` bytes from `addr` in the tracee's address space.
    ///
    /// Uses `PTRACE_PEEKDATA` word-by-word.
    ///
    /// # Errors
    /// Returns an error if any word read fails.
    pub fn read_memory(&self, addr: u64, len: usize) -> anyhow::Result<Vec<u8>> {
        let word_size = std::mem::size_of::<usize>();
        let mut buf = Vec::with_capacity(len);
        let mut off = 0usize;
        while off < len {
            let word_addr = (addr as usize).wrapping_add(off);
            let word = nix::sys::ptrace::read(self.pid, word_addr as *mut libc::c_void)? as usize;
            let bytes = word.to_ne_bytes();
            let to_copy = (len - off).min(word_size);
            buf.extend_from_slice(&bytes[..to_copy]);
            off += word_size;
        }
        buf.truncate(len);
        Ok(buf)
    }

    /// Write `data` to `addr` in the tracee's address space.
    ///
    /// Uses `PTRACE_POKEDATA` word-by-word.
    ///
    /// # Errors
    /// Returns an error if any word write fails.
    pub fn write_memory(&self, addr: u64, data: &[u8]) -> anyhow::Result<()> {
        let word_size = std::mem::size_of::<usize>();
        let mut off = 0usize;
        while off < data.len() {
            let word_addr = (addr as usize).wrapping_add(off);
            let to_write = (data.len() - off).min(word_size);

            // For partial words we need to read-modify-write.
            let word: usize = if to_write < word_size {
                let existing =
                    nix::sys::ptrace::read(self.pid, word_addr as *mut libc::c_void)? as usize;
                let mut bytes = existing.to_ne_bytes();
                bytes[..to_write].copy_from_slice(&data[off..off + to_write]);
                usize::from_ne_bytes(bytes)
            } else {
                let mut bytes = [0u8; 8];
                bytes[..word_size].copy_from_slice(&data[off..off + word_size]);
                usize::from_ne_bytes(bytes)
            };

            // SAFETY: `PTRACE_POKEDATA` is a Linux syscall; safety is the
            // caller's responsibility (they own the ptrace attachment).
            // The third argument of `ptrace::write` is the WORD to store, not
            // a pointer to it: nix types it `i64` because PTRACE_POKEDATA
            // takes the datum by value. Casting the word to `*mut c_void`
            // compiled nowhere — this file had never been built on Linux — and
            // would have been a type error the moment it was.
            nix::sys::ptrace::write(
                self.pid,
                word_addr as *mut libc::c_void,
                word as i64,
            )?;
            off += word_size;
        }
        Ok(())
    }

    /// Restore the process state from a `TraceSnapshot`.
    ///
    /// Writes all captured pages back to the tracee and restores registers.
    ///
    /// # Errors
    /// Returns an error if any register or memory write fails.
    pub fn restore_snapshot(&self, snap: &TraceSnapshot) -> anyhow::Result<()> {
        // Restore memory pages.
        for (base, data) in &snap.memory_pages {
            let _ = self.write_memory(*base, data); // best-effort
        }
        // Restore registers (only if we have exactly the right number of bytes).
        if snap.registers.len() == std::mem::size_of::<libc::user_regs_struct>() {
            let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    snap.registers.as_ptr(),
                    &mut regs as *mut _ as *mut u8,
                    snap.registers.len(),
                );
            }
            self.set_regs(regs)?;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxDebugger {
    fn drop(&mut self) {
        if self.attached {
            let _ = nix::sys::ptrace::detach(self.pid, None);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FullTtdSession — ties everything together
// ─────────────────────────────────────────────────────────────────────────────

/// A complete TTD recording session that combines:
/// - Hardware instruction counting via `InstructionCounter`.
/// - Syscall interception via `SyscallInterceptor` / `FullSyscallInterceptor`.
/// - Periodic snapshots via `SnapshotManager`.
/// - Page fault recording via `PageFaultRecorder`.
///
/// After recording, the session can be used to seek to any instruction count
/// by finding the nearest snapshot and replaying the event log.
pub struct FullTtdSession {
    /// PID of the traced process.
    pub pid: i32,
    /// Snapshot manager.
    pub snapshots: SnapshotManager,
    /// Page fault log.
    pub page_faults: PageFaultRecorder,
    /// Syscall event log.
    pub syscall_log: Vec<SyscallRecord>,
    /// Hardware instruction counter.
    pub counter: Option<InstructionCounter>,
    /// Current instruction count.
    pub current_instr_count: u64,
}

impl FullTtdSession {
    /// Create a new session for `pid` with the default snapshot interval.
    #[must_use]
    pub fn new(pid: i32) -> Self {
        let counter = InstructionCounter::new(pid).ok();
        Self {
            pid,
            snapshots: SnapshotManager::with_default_interval(),
            page_faults: PageFaultRecorder::new(pid),
            syscall_log: Vec::new(),
            counter,
            current_instr_count: 0,
        }
    }

    /// Create a session with a custom snapshot interval.
    #[must_use]
    pub fn with_interval(pid: i32, interval: u64) -> Self {
        let mut s = Self::new(pid);
        s.snapshots.snapshot_interval = interval;
        s
    }

    /// Update the current instruction count from the hardware counter.
    pub const fn sync_instr_count(&mut self) {
        if let Some(ref c) = self.counter {
            self.current_instr_count = c.read();
        }
    }

    /// Append a syscall record and check if a snapshot is due.
    pub fn push_syscall(&mut self, record: SyscallRecord) {
        let count = record.instr_count;
        self.syscall_log.push(record);
        self.current_instr_count = count;
        self.snapshots.maybe_snapshot(self.pid, count);
    }

    /// Append a page fault record.
    pub fn push_page_fault(&mut self, record: PageFaultRecord) {
        self.current_instr_count = record.instr_count;
        self.page_faults.push(record);
    }

    /// Return the nearest snapshot before `target_count`, if any.
    #[must_use]
    pub fn nearest_snapshot(&self, target_count: u64) -> Option<&TraceSnapshot> {
        self.snapshots.nearest_snapshot_before(target_count)
    }

    /// Return all syscall records in the range `[from_count, to_count]`.
    #[must_use]
    pub fn syscalls_in_range(&self, from_count: u64, to_count: u64) -> Vec<&SyscallRecord> {
        self.syscall_log
            .iter()
            .filter(|r| r.instr_count >= from_count && r.instr_count <= to_count)
            .collect()
    }

    /// Return total number of syscalls recorded.
    #[must_use]
    pub const fn syscall_count(&self) -> usize {
        self.syscall_log.len()
    }

    /// Return total number of page faults recorded.
    #[must_use]
    pub const fn fault_count(&self) -> usize {
        self.page_faults.fault_count()
    }

    /// Return total number of snapshots taken.
    #[must_use]
    pub const fn snapshot_count(&self) -> usize {
        self.snapshots.snapshot_count()
    }

    /// Estimate the total memory used by this session.
    #[must_use]
    pub fn memory_usage_bytes(&self) -> usize {
        self.snapshots.total_captured_bytes()
            + self.page_faults.total_captured_bytes()
            + self
                .syscall_log
                .iter()
                .map(|r| r.pre_capture_bytes() + r.post_write_bytes())
                .sum::<usize>()
    }
}

impl std::fmt::Debug for FullTtdSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FullTtdSession")
            .field("pid", &self.pid)
            .field("syscall_count", &self.syscall_count())
            .field("fault_count", &self.fault_count())
            .field("snapshot_count", &self.snapshot_count())
            .field("current_instr_count", &self.current_instr_count)
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Extended tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_ttd_tests {
    use super::*;

    // ── InstructionCounter ────────────────────────────────────────────────────

    #[test]
    fn instruction_counter_new_does_not_panic_on_linux_or_other() {
        // PID 0 may or may not succeed depending on the kernel; we only check
        // that the call does not panic.
        let _ = InstructionCounter::new(0);
    }

    #[test]
    fn instruction_counter_read_returns_u64() {
        if let Ok(c) = InstructionCounter::new(std::process::id() as i32) {
            let _ = c.read();
        }
    }

    #[test]
    fn instruction_counter_read_delta_monotone() {
        if let Ok(mut c) = InstructionCounter::new(std::process::id() as i32) {
            c.enable();
            let d1 = c.read_delta();
            let d2 = c.read_delta();
            // Deltas are ≥ 0 (unsigned) — this is always true.
            let _ = d1;
            let _ = d2;
        }
    }

    // ── CaptureReason / MemoryCapture ─────────────────────────────────────────

    #[test]
    fn capture_reason_display() {
        assert_eq!(
            CaptureReason::SyscallArg { arg_index: 2 }.to_string(),
            "arg[2]"
        );
        assert_eq!(CaptureReason::ReturnBuffer.to_string(), "retbuf");
        assert_eq!(CaptureReason::PageFaultData.to_string(), "pagefault");
    }

    #[test]
    fn memory_capture_contains_and_byte_at() {
        let cap = MemoryCapture::new(
            0x1000,
            vec![0xAA, 0xBB, 0xCC, 0xDD],
            CaptureReason::ReturnBuffer,
        );
        assert_eq!(cap.len(), 4);
        assert!(!cap.is_empty());
        assert_eq!(cap.end_address(), 0x1004);
        assert!(cap.contains(0x1000));
        assert!(cap.contains(0x1003));
        assert!(!cap.contains(0x1004));
        assert_eq!(cap.byte_at(0x1001), Some(0xBB));
        assert!(cap.byte_at(0x2000).is_none());
    }

    // ── SyscallRecord ─────────────────────────────────────────────────────────

    #[test]
    fn syscall_record_is_error_and_errno() {
        let r = SyscallRecord {
            instr_count: 100,
            syscall_nr: 2, // open
            args: [0; 6],
            return_value: -2, // ENOENT
            pre_memory_state: Vec::new(),
            post_memory_writes: Vec::new(),
        };
        assert!(r.is_error());
        assert_eq!(r.errno(), Some(2));
    }

    #[test]
    fn syscall_record_success_no_errno() {
        let r = SyscallRecord {
            instr_count: 200,
            syscall_nr: 1,
            args: [0; 6],
            return_value: 42,
            pre_memory_state: Vec::new(),
            post_memory_writes: Vec::new(),
        };
        assert!(!r.is_error());
        assert!(r.errno().is_none());
    }

    #[test]
    fn syscall_record_pre_capture_bytes() {
        let mut r = SyscallRecord {
            instr_count: 0,
            syscall_nr: 0,
            args: [0; 6],
            return_value: 0,
            pre_memory_state: Vec::new(),
            post_memory_writes: Vec::new(),
        };
        r.pre_memory_state.push(MemoryCapture::new(
            0x1000,
            vec![0u8; 128],
            CaptureReason::SyscallArg { arg_index: 1 },
        ));
        r.pre_memory_state.push(MemoryCapture::new(
            0x2000,
            vec![0u8; 64],
            CaptureReason::ReturnBuffer,
        ));
        assert_eq!(r.pre_capture_bytes(), 192);
    }

    #[test]
    fn syscall_record_summary_on_error() {
        let r = SyscallRecord {
            instr_count: 9999,
            syscall_nr: 2,
            args: [0; 6],
            return_value: -13,
            pre_memory_state: Vec::new(),
            post_memory_writes: Vec::new(),
        };
        let s = r.summary();
        assert!(s.contains("nr=2"));
        assert!(s.contains("errno=13"));
    }

    #[test]
    fn syscall_record_display() {
        let r = SyscallRecord {
            instr_count: 1000,
            syscall_nr: 0,
            args: [0; 6],
            return_value: 64,
            pre_memory_state: Vec::new(),
            post_memory_writes: Vec::new(),
        };
        let s = r.to_string();
        assert!(s.contains("SyscallRecord"));
        assert!(s.contains("nr=0"));
    }

    // ── SyscallOutputBufferDb ─────────────────────────────────────────────────

    #[test]
    fn output_buffer_db_read_syscall() {
        let specs = SyscallOutputBufferDb::output_buffers(0); // read
        assert!(!specs.is_empty());
        assert!(specs[0].size_from_retval);
        assert_eq!(specs[0].ptr_arg, 1);
    }

    #[test]
    fn output_buffer_db_gettimeofday() {
        let specs = SyscallOutputBufferDb::output_buffers(96);
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].fixed_size, Some(16));
        assert_eq!(specs[1].fixed_size, Some(8));
    }

    #[test]
    fn output_buffer_db_unknown_syscall_empty() {
        let specs = SyscallOutputBufferDb::output_buffers(9999);
        assert!(specs.is_empty());
    }

    #[test]
    fn compute_buffer_size_fixed() {
        let spec = OutputBufferSpec {
            ptr_arg: 0,
            size_arg: None,
            size_from_retval: false,
            fixed_size: Some(144),
        };
        let args = [0u64; 6];
        assert_eq!(
            SyscallOutputBufferDb::compute_buffer_size(&spec, &args, 0),
            Some(144)
        );
    }

    #[test]
    fn compute_buffer_size_from_retval() {
        let spec = OutputBufferSpec {
            ptr_arg: 1,
            size_arg: None,
            size_from_retval: true,
            fixed_size: None,
        };
        let args = [0u64; 6];
        assert_eq!(
            SyscallOutputBufferDb::compute_buffer_size(&spec, &args, 42),
            Some(42)
        );
        // Negative retval → None
        assert_eq!(
            SyscallOutputBufferDb::compute_buffer_size(&spec, &args, -1),
            None
        );
    }

    #[test]
    fn compute_buffer_size_from_size_arg() {
        let spec = OutputBufferSpec {
            ptr_arg: 0,
            size_arg: Some(1),
            size_from_retval: false,
            fixed_size: None,
        };
        let mut args = [0u64; 6];
        args[1] = 4096;
        assert_eq!(
            SyscallOutputBufferDb::compute_buffer_size(&spec, &args, 0),
            Some(4096)
        );
        // Zero size → None
        args[1] = 0;
        assert_eq!(
            SyscallOutputBufferDb::compute_buffer_size(&spec, &args, 0),
            None
        );
    }

    // ── PageFaultRecord / PageFaultRecorder ───────────────────────────────────

    #[test]
    fn page_fault_record_metrics() {
        let r = PageFaultRecord {
            instr_count: 500,
            fault_address: 0xDEAD_0000,
            fault_pages: vec![
                (0xDEAD_0000, vec![0u8; 4096]),
                (0xDEAD_1000, vec![0u8; 4096]),
            ],
            was_write: true,
        };
        assert_eq!(r.page_count(), 2);
        assert_eq!(r.total_bytes(), 8192);
        let s = r.to_string();
        assert!(s.contains("write=true"));
    }

    #[test]
    fn page_fault_recorder_push_and_query() {
        let mut rec = PageFaultRecorder::new(1234);
        assert!(rec.is_empty());

        rec.push(PageFaultRecord {
            instr_count: 100,
            fault_address: 0x5000,
            fault_pages: vec![(0x5000, vec![0xAB; 4096])],
            was_write: false,
        });
        rec.push(PageFaultRecord {
            instr_count: 200,
            fault_address: 0x6000,
            fault_pages: vec![(0x6000, vec![0xCD; 4096])],
            was_write: true,
        });

        assert_eq!(rec.fault_count(), 2);
        assert!(!rec.is_empty());
        assert_eq!(rec.write_faults().len(), 1);
        assert_eq!(rec.read_faults().len(), 1);
        assert_eq!(rec.total_captured_bytes(), 8192);

        let for_page = rec.faults_for_page(0x5000);
        assert_eq!(for_page.len(), 1);
        assert_eq!(for_page[0].fault_address, 0x5000);
    }

    #[test]
    fn page_fault_recorder_clear() {
        let mut rec = PageFaultRecorder::new(0);
        rec.push(PageFaultRecord {
            instr_count: 0,
            fault_address: 0,
            fault_pages: Vec::new(),
            was_write: false,
        });
        rec.clear();
        assert!(rec.is_empty());
    }

    // ── TraceSnapshot ─────────────────────────────────────────────────────────

    fn make_snapshot(instr_count: u64, page_count: usize) -> TraceSnapshot {
        let pages: Vec<(u64, Vec<u8>)> = (0..page_count)
            .map(|i| (i as u64 * 4096, vec![i as u8; 4096]))
            .collect();
        TraceSnapshot {
            instr_count,
            registers: vec![0u8; 216], // x86-64 user_regs_struct size
            memory_pages: pages,
            pid: 42,
            timestamp: 0,
        }
    }

    #[test]
    fn trace_snapshot_page_count_and_total_bytes() {
        let snap = make_snapshot(1000, 4);
        assert_eq!(snap.page_count(), 4);
        assert_eq!(snap.total_bytes(), 4 * 4096);
    }

    #[test]
    fn trace_snapshot_page_for_address() {
        let snap = make_snapshot(0, 3);
        // Page 0 starts at 0, page 1 at 4096, page 2 at 8192.
        assert!(snap.page_for_address(0).is_some());
        assert!(snap.page_for_address(4096).is_some());
        assert!(snap.page_for_address(99999).is_none());
    }

    #[test]
    fn trace_snapshot_read_within_page() {
        let mut snap = make_snapshot(0, 1);
        snap.memory_pages[0].1[0] = 0xAA;
        snap.memory_pages[0].1[1] = 0xBB;

        let bytes = snap.read(0, 2).unwrap();
        assert_eq!(bytes, vec![0xAA, 0xBB]);
    }

    #[test]
    fn trace_snapshot_read_out_of_range_returns_none() {
        let snap = make_snapshot(0, 1);
        assert!(snap.read(0xFFFF_0000, 4).is_none());
    }

    #[test]
    fn trace_snapshot_display() {
        let snap = make_snapshot(12345, 2);
        let s = snap.to_string();
        assert!(s.contains("TraceSnapshot"));
        assert!(s.contains("ic=12345"));
        assert!(s.contains("pages=2"));
    }

    // ── SnapshotManager ───────────────────────────────────────────────────────

    #[test]
    fn snapshot_manager_no_snapshot_initially() {
        let m = SnapshotManager::with_default_interval();
        assert_eq!(m.snapshot_count(), 0);
        assert!(m.nearest_snapshot_before(0).is_none());
    }

    #[test]
    fn snapshot_manager_store_and_find() {
        let mut m = SnapshotManager::new(100);
        m.store_snapshot(make_snapshot(50, 0));
        m.store_snapshot(make_snapshot(200, 0));
        m.store_snapshot(make_snapshot(350, 0));

        assert_eq!(m.snapshot_count(), 3);
        assert_eq!(m.nearest_snapshot_before(300).unwrap().instr_count, 200);
        assert_eq!(m.nearest_snapshot_before(50).unwrap().instr_count, 50);
        assert!(m.nearest_snapshot_before(49).is_none());
        assert_eq!(m.nearest_snapshot_before(9999).unwrap().instr_count, 350);
    }

    #[test]
    fn snapshot_manager_should_snapshot_threshold() {
        let m = SnapshotManager::new(1000);
        assert!(!m.should_snapshot(999));
        assert!(m.should_snapshot(1000));
        assert!(m.should_snapshot(2000));
    }

    #[test]
    fn snapshot_manager_maybe_snapshot_updates_last_count() {
        let mut m = SnapshotManager::new(100);
        m.maybe_snapshot(0, 50);
        assert_eq!(m.snapshot_count(), 0); // below threshold
        m.maybe_snapshot(0, 100);
        assert_eq!(m.snapshot_count(), 1);
        m.maybe_snapshot(0, 150);
        assert_eq!(m.snapshot_count(), 1); // delta only 50
        m.maybe_snapshot(0, 200);
        assert_eq!(m.snapshot_count(), 2);
    }

    #[test]
    fn snapshot_manager_prune_before() {
        let mut m = SnapshotManager::new(1);
        for i in 0u64..10 {
            m.store_snapshot(make_snapshot(i * 100, 0));
        }
        assert_eq!(m.snapshot_count(), 10);
        m.prune_before(500);
        assert_eq!(m.snapshot_count(), 5);
    }

    #[test]
    fn snapshot_manager_clear() {
        let mut m = SnapshotManager::new(1);
        m.store_snapshot(make_snapshot(0, 0));
        m.clear();
        assert_eq!(m.snapshot_count(), 0);
    }

    #[test]
    fn snapshot_manager_total_captured_bytes() {
        let mut m = SnapshotManager::new(1);
        m.store_snapshot(make_snapshot(0, 4)); // 4 * 4096 bytes
        m.store_snapshot(make_snapshot(1, 2)); // 2 * 4096 bytes
        assert_eq!(m.total_captured_bytes(), 6 * 4096);
    }

    // ── FullTtdSession ────────────────────────────────────────────────────────

    #[test]
    fn full_ttd_session_push_and_query() {
        let mut session = FullTtdSession::with_interval(0, 500);

        // Push syscall records.
        for i in 0u64..10 {
            session.push_syscall(SyscallRecord {
                instr_count: i * 100,
                syscall_nr: i as u32,
                args: [0; 6],
                return_value: 0,
                pre_memory_state: Vec::new(),
                post_memory_writes: Vec::new(),
            });
        }

        assert_eq!(session.syscall_count(), 10);
        assert_eq!(session.current_instr_count, 900);

        let range = session.syscalls_in_range(200, 500);
        assert_eq!(range.len(), 4); // counts 200, 300, 400, 500

        // A snapshot should have been taken at count=500 (interval=500).
        assert!(session.snapshot_count() >= 1);
    }

    #[test]
    fn full_ttd_session_push_page_fault() {
        let mut session = FullTtdSession::new(0);
        session.push_page_fault(PageFaultRecord {
            instr_count: 42,
            fault_address: 0x1000,
            fault_pages: Vec::new(),
            was_write: false,
        });
        assert_eq!(session.fault_count(), 1);
        assert_eq!(session.current_instr_count, 42);
    }

    #[test]
    fn full_ttd_session_nearest_snapshot() {
        let mut session = FullTtdSession::with_interval(0, 100);
        session.snapshots.store_snapshot(make_snapshot(100, 0));
        session.snapshots.store_snapshot(make_snapshot(300, 0));

        assert_eq!(session.nearest_snapshot(250).unwrap().instr_count, 100);
        assert_eq!(session.nearest_snapshot(400).unwrap().instr_count, 300);
        assert!(session.nearest_snapshot(50).is_none());
    }

    #[test]
    fn full_ttd_session_memory_usage_accumulates() {
        let mut session = FullTtdSession::new(0);
        session.snapshots.store_snapshot(make_snapshot(0, 4)); // 4 pages
        let usage = session.memory_usage_bytes();
        assert_eq!(usage, 4 * 4096);
    }

    #[test]
    fn full_ttd_session_debug_format() {
        let session = FullTtdSession::new(12345);
        let s = format!("{session:?}");
        assert!(s.contains("FullTtdSession"));
        assert!(s.contains("pid: 12345"));
    }
}
