// recording_session_manager.rs — TTD recording session lifecycle management
// Manages start/stop/pause/resume, session configuration, events, stats, and index generation.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ─── SessionConfig ────────────────────────────────────────────────────────────

/// Configuration used to create a new recording session.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Directory where trace files are written.
    pub output_path: PathBuf,
    /// Maximum trace size in gigabytes before auto-stop.
    pub max_trace_size_gb: f64,
    /// Whether trace chunks should be compressed.
    pub compress: bool,
    /// Whether kernel-mode execution should be included.
    pub include_kernel: bool,
    /// Only record these PIDs (empty = all).
    pub filter_pids: Vec<u32>,
    /// Only record modules whose lowercase name contains one of these substrings (empty = all).
    pub filter_modules: Vec<String>,
    /// Ring-buffer capacity in number of chunks.
    pub ring_buffer_capacity: usize,
    /// Human-readable label for this session.
    pub label: String,
}

const fn f64_to_u64_lossy(v: f64) -> u64 {
    v as u64
}
const fn u64_to_f64_lossy(v: u64) -> f64 {
    v as f64
}

impl SessionConfig {
    #[must_use]
    pub fn new(output_path: PathBuf) -> Self {
        Self {
            output_path,
            max_trace_size_gb: 4.0,
            compress: true,
            include_kernel: false,
            filter_pids: Vec::new(),
            filter_modules: Vec::new(),
            ring_buffer_capacity: 4096,
            label: String::from("default"),
        }
    }

    /// Return the maximum trace size in bytes.
    #[must_use]
    pub fn max_trace_bytes(&self) -> u64 {
        f64_to_u64_lossy(self.max_trace_size_gb * 1_073_741_824.0)
    }

    /// Return true if `pid` passes the PID filter.
    #[must_use]
    pub fn pid_allowed(&self, pid: u32) -> bool {
        self.filter_pids.is_empty() || self.filter_pids.contains(&pid)
    }

    /// Return true if `module_name` passes the module filter.
    #[must_use]
    pub fn module_allowed(&self, module_name: &str) -> bool {
        if self.filter_modules.is_empty() {
            return true;
        }
        let lower = module_name.to_lowercase();
        self.filter_modules.iter().any(|f| lower.contains(f.as_str()))
    }
}

// ─── SessionState ─────────────────────────────────────────────────────────────

/// Lifecycle state of a recording session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    Idle,
    Initializing,
    Recording,
    Paused,
    Flushing,
    Completed,
    Failed(String),
}

impl SessionState {
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed(_))
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Recording | Self::Paused)
    }

    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::Idle => "Idle",
            Self::Initializing => "Initializing",
            Self::Recording => "Recording",
            Self::Paused => "Paused",
            Self::Flushing => "Flushing",
            Self::Completed => "Completed",
            Self::Failed(_) => "Failed",
        }
    }
}

// ─── SessionEventType ────────────────────────────────────────────────────────

/// Type of lifecycle event emitted by a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEventType {
    SessionStarted,
    SessionPaused,
    SessionResumed,
    SessionStopped,
    SessionFlushed,
    SessionCompleted,
    SessionFailed,
    ChunkWritten,
    CapacityWarning,
    FilteredPid(u32),
    FilteredModule(String),
    SizeThresholdReached,
    IndexGenerated,
}

impl SessionEventType {
    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self, Self::SessionFailed)
    }

    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::SessionStarted => "session_started".into(),
            Self::SessionPaused => "session_paused".into(),
            Self::SessionResumed => "session_resumed".into(),
            Self::SessionStopped => "session_stopped".into(),
            Self::SessionFlushed => "session_flushed".into(),
            Self::SessionCompleted => "session_completed".into(),
            Self::SessionFailed => "session_failed".into(),
            Self::ChunkWritten => "chunk_written".into(),
            Self::CapacityWarning => "capacity_warning".into(),
            Self::FilteredPid(p) => format!("filtered_pid:{p}"),
            Self::FilteredModule(m) => format!("filtered_module:{m}"),
            Self::SizeThresholdReached => "size_threshold_reached".into(),
            Self::IndexGenerated => "index_generated".into(),
        }
    }
}

// ─── SessionEvent ─────────────────────────────────────────────────────────────

/// A timestamped event emitted during session operation.
#[derive(Debug, Clone)]
pub struct SessionEvent {
    pub event_type: SessionEventType,
    pub timestamp_ns: u64,
    pub session_id: u64,
    pub detail: Option<String>,
}

impl SessionEvent {
    #[must_use]
    pub fn new(event_type: SessionEventType, session_id: u64) -> Self {
        let ts = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        )
        .unwrap_or(u64::MAX);
        Self {
            event_type,
            timestamp_ns: ts,
            session_id,
            detail: None,
        }
    }

    #[must_use]
    pub fn with_detail(mut self, detail: &str) -> Self {
        self.detail = Some(detail.to_string());
        self
    }

    #[must_use]
    pub fn to_log_line(&self) -> String {
        let ts = self.timestamp_ns;
        let sid = self.session_id;
        let event = self.event_type.label();
        let detail = self.detail.as_deref().unwrap_or("-");
        format!("ts={ts} sid={sid} event={event} detail={detail}")
    }
}

// ─── SessionStats ──────────────────────────────────────────────────────────────

/// Accumulated statistics for a session.
#[derive(Debug, Clone, Default)]
pub struct SessionStats {
    pub chunks_written: u64,
    pub bytes_written: u64,
    pub bytes_compressed: u64,
    pub chunks_evicted: u64,
    pub pids_recorded: u32,
    pub modules_recorded: u32,
    pub pause_count: u32,
    pub resume_count: u32,
    pub events_emitted: u64,
    pub wall_time_ns: u64,
}

impl SessionStats {
    #[must_use]
    pub fn compression_ratio(&self) -> f64 {
        if self.bytes_written == 0 {
            return 1.0;
        }
        u64_to_f64_lossy(self.bytes_compressed) / u64_to_f64_lossy(self.bytes_written)
    }

    #[must_use]
    pub fn throughput_mbps(&self) -> f64 {
        if self.wall_time_ns == 0 {
            return 0.0;
        }
        let bytes = u64_to_f64_lossy(self.bytes_written);
        let secs = u64_to_f64_lossy(self.wall_time_ns) / 1_000_000_000.0;
        bytes / secs / (1024.0 * 1024.0)
    }

    pub fn merge(&mut self, other: &Self) {
        self.chunks_written += other.chunks_written;
        self.bytes_written += other.bytes_written;
        self.bytes_compressed += other.bytes_compressed;
        self.chunks_evicted += other.chunks_evicted;
        self.pids_recorded = self.pids_recorded.max(other.pids_recorded);
        self.modules_recorded = self.modules_recorded.max(other.modules_recorded);
        self.pause_count += other.pause_count;
        self.resume_count += other.resume_count;
        self.events_emitted += other.events_emitted;
        self.wall_time_ns += other.wall_time_ns;
    }
}

// ─── IndexEntry ───────────────────────────────────────────────────────────────

/// One record in the generated trace index.
#[derive(Debug, Clone)]
pub struct IndexEntry {
    pub seq: u64,
    pub timestamp_ns: u64,
    pub file_offset: u64,
    pub chunk_len: u32,
    pub compressed: bool,
    pub pid: Option<u32>,
    pub module: Option<String>,
}

impl IndexEntry {
    /// Serialize to a 40-byte fixed-size format.
    /// Layout: seq(8) ts(8) offset(8) len(4) pid(4) flags(1) pad(7)
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(40);
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.extend_from_slice(&self.timestamp_ns.to_le_bytes());
        out.extend_from_slice(&self.file_offset.to_le_bytes());
        out.extend_from_slice(&self.chunk_len.to_le_bytes());
        out.extend_from_slice(&self.pid.unwrap_or(0).to_le_bytes());
        out.push(u8::from(self.compressed));
        out.extend_from_slice(&[0u8; 7]); // pad
        out
    }

    #[must_use]
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 40 {
            return None;
        }
        let seq = u64::from_le_bytes(data[0..8].try_into().ok()?);
        let timestamp_ns = u64::from_le_bytes(data[8..16].try_into().ok()?);
        let file_offset = u64::from_le_bytes(data[16..24].try_into().ok()?);
        let chunk_len = u32::from_le_bytes(data[24..28].try_into().ok()?);
        let pid_raw = u32::from_le_bytes(data[28..32].try_into().ok()?);
        let flags = data[32];
        Some(Self {
            seq,
            timestamp_ns,
            file_offset,
            chunk_len,
            compressed: flags & 1 != 0,
            pid: if pid_raw == 0 { None } else { Some(pid_raw) },
            module: None,
        })
    }
}

// ─── RecordingSession ─────────────────────────────────────────────────────────

/// An individual recording session instance.
#[derive(Debug)]
pub struct RecordingSession {
    pub session_id: u64,
    pub config: SessionConfig,
    pub state: SessionState,
    pub stats: SessionStats,
    pub events: Vec<SessionEvent>,
    pub index: Vec<IndexEntry>,
    start_time: Option<SystemTime>,
    pause_time: Option<SystemTime>,
    paused_duration: Duration,
    current_file_offset: u64,
}

impl RecordingSession {
    fn new(session_id: u64, config: SessionConfig) -> Self {
        Self {
            session_id,
            config,
            state: SessionState::Idle,
            stats: SessionStats::default(),
            events: Vec::new(),
            index: Vec::new(),
            start_time: None,
            pause_time: None,
            paused_duration: Duration::ZERO,
            current_file_offset: 0,
        }
    }

    fn emit(&mut self, event_type: SessionEventType) {
        let ev = SessionEvent::new(event_type, self.session_id);
        self.stats.events_emitted += 1;
        self.events.push(ev);
    }

    fn emit_with_detail(&mut self, event_type: SessionEventType, detail: &str) {
        let ev = SessionEvent::new(event_type, self.session_id).with_detail(detail);
        self.stats.events_emitted += 1;
        self.events.push(ev);
    }

    /// Transition from Idle/Initializing to Recording.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the session is not in `Idle` state.
    pub fn start(&mut self) -> Result<(), String> {
        match &self.state {
            SessionState::Idle => {
                self.state = SessionState::Initializing;
                self.start_time = Some(SystemTime::now());
                self.state = SessionState::Recording;
                self.emit(SessionEventType::SessionStarted);
                Ok(())
            }
            other => Err(format!("Cannot start from state {}", other.as_str())),
        }
    }

    /// Transition from Recording to Paused.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the session is not in `Recording` state.
    pub fn pause(&mut self) -> Result<(), String> {
        if self.state != SessionState::Recording {
            return Err(format!(
                "Cannot pause from state {}",
                self.state.as_str()
            ));
        }
        self.pause_time = Some(SystemTime::now());
        self.state = SessionState::Paused;
        self.stats.pause_count += 1;
        self.emit(SessionEventType::SessionPaused);
        Ok(())
    }

    /// Transition from Paused to Recording.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the session is not in `Paused` state.
    pub fn resume(&mut self) -> Result<(), String> {
        if self.state != SessionState::Paused {
            return Err(format!(
                "Cannot resume from state {}",
                self.state.as_str()
            ));
        }
        if let Some(pt) = self.pause_time.take()
            && let Ok(d) = SystemTime::now().duration_since(pt)
        {
            self.paused_duration += d;
        }
        self.state = SessionState::Recording;
        self.stats.resume_count += 1;
        self.emit(SessionEventType::SessionResumed);
        Ok(())
    }

    /// Transition to Flushing then Completed.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the session is not active (Recording or Paused).
    pub fn stop(&mut self) -> Result<(), String> {
        if !self.state.is_active() {
            return Err(format!(
                "Cannot stop from state {}",
                self.state.as_str()
            ));
        }
        self.state = SessionState::Flushing;
        self.emit(SessionEventType::SessionStopped);
        // Compute wall time
        if let Some(start) = self.start_time
            && let Ok(dur) = SystemTime::now().duration_since(start)
        {
            self.stats.wall_time_ns = u64::try_from(
                dur.as_nanos().saturating_sub(self.paused_duration.as_nanos()),
            )
            .unwrap_or(u64::MAX);
        }
        self.emit(SessionEventType::SessionFlushed);
        self.state = SessionState::Completed;
        self.emit(SessionEventType::SessionCompleted);
        Ok(())
    }

    /// Mark the session as failed.
    pub fn fail(&mut self, reason: &str) {
        self.state = SessionState::Failed(reason.to_string());
        self.emit_with_detail(SessionEventType::SessionFailed, reason);
    }

    /// Record a chunk being written. Returns whether size threshold was exceeded.
    pub fn record_chunk(&mut self, raw_len: u32, compressed_len: u32, pid: Option<u32>, module: Option<String>) -> bool {
        if self.state != SessionState::Recording {
            return false;
        }
        let entry = IndexEntry {
            seq: self.stats.chunks_written,
            timestamp_ns: u64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos(),
            )
            .unwrap_or(u64::MAX),
            file_offset: self.current_file_offset,
            chunk_len: compressed_len,
            compressed: compressed_len < raw_len,
            pid,
            module,
        };
        self.current_file_offset += u64::from(compressed_len);
        self.stats.chunks_written += 1;
        self.stats.bytes_written += u64::from(raw_len);
        self.stats.bytes_compressed += u64::from(compressed_len);
        self.index.push(entry);
        self.emit(SessionEventType::ChunkWritten);

        if self.stats.bytes_written >= self.config.max_trace_bytes() {
            self.emit(SessionEventType::SizeThresholdReached);
            true
        } else {
            false
        }
    }

    /// Generate an index as a byte blob (magic + entries).
    pub fn generate_index(&mut self) -> Vec<u8> {
        let mut out = b"TTDIDX01".to_vec();
        let count = self.index.len() as u64;
        out.extend_from_slice(&count.to_le_bytes());
        for entry in &self.index {
            out.extend_from_slice(&entry.serialize());
        }
        self.emit(SessionEventType::IndexGenerated);
        out
    }

    /// Return events of a given type.
    #[must_use]
    pub fn events_of_type(&self, t: &SessionEventType) -> Vec<&SessionEvent> {
        self.events.iter().filter(|e| &e.event_type == t).collect()
    }

    /// Active recording time (wall time minus paused time).
    #[must_use]
    pub fn active_duration(&self) -> Duration {
        self.start_time.map_or(Duration::ZERO, |start| {
            let elapsed = SystemTime::now()
                .duration_since(start)
                .unwrap_or(Duration::ZERO);
            elapsed.saturating_sub(self.paused_duration)
        })
    }
}

// ─── RecordingSessionManager ──────────────────────────────────────────────────

/// Manages multiple named recording sessions.
pub struct RecordingSessionManager {
    sessions: HashMap<u64, RecordingSession>,
    next_id: u64,
    aggregate_stats: SessionStats,
    /// Sessions completed or failed (archived).
    archive: Vec<RecordingSession>,
    max_concurrent: usize,
}

impl RecordingSessionManager {
    #[must_use]
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            next_id: 1,
            aggregate_stats: SessionStats::default(),
            archive: Vec::new(),
            max_concurrent,
        }
    }

    /// Create and start a new recording session.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the maximum number of concurrent sessions has been reached.
    pub fn start_recording(&mut self, config: SessionConfig) -> Result<u64, String> {
        let active = self
            .sessions
            .values()
            .filter(|s| s.state.is_active())
            .count();
        if active >= self.max_concurrent {
            return Err(format!(
                "Max concurrent sessions ({}) reached",
                self.max_concurrent
            ));
        }
        let id = self.next_id;
        self.next_id += 1;
        let mut session = RecordingSession::new(id, config);
        session.start()?;
        self.sessions.insert(id, session);
        Ok(id)
    }

    /// Stop a session and move it to the archive.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the session ID is not found or if stopping fails.
    pub fn stop_recording(&mut self, session_id: u64) -> Result<SessionStats, String> {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| format!("Session {session_id} not found"))?;
        session.stop()?;
        let stats = session.stats.clone();
        self.aggregate_stats.merge(&stats);
        if let Some(s) = self.sessions.remove(&session_id) {
            self.archive.push(s);
        }
        Ok(stats)
    }

    /// Pause a recording session.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the session ID is not found or if pausing fails.
    pub fn pause_recording(&mut self, session_id: u64) -> Result<(), String> {
        self.sessions
            .get_mut(&session_id)
            .ok_or_else(|| format!("Session {session_id} not found"))?
            .pause()
    }

    /// Resume a paused session.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the session ID is not found or if resuming fails.
    pub fn resume_recording(&mut self, session_id: u64) -> Result<(), String> {
        self.sessions
            .get_mut(&session_id)
            .ok_or_else(|| format!("Session {session_id} not found"))?
            .resume()
    }

    /// Mark a session as failed.
    pub fn fail_session(&mut self, session_id: u64, reason: &str) {
        if let Some(s) = self.sessions.get_mut(&session_id) {
            s.fail(reason);
        }
        if let Some(s) = self.sessions.remove(&session_id) {
            self.archive.push(s);
        }
    }

    /// Record a chunk on a session.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the session ID is not found.
    pub fn record_chunk(
        &mut self,
        session_id: u64,
        raw_len: u32,
        compressed_len: u32,
        pid: Option<u32>,
        module: Option<String>,
    ) -> Result<bool, String> {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| format!("Session {session_id} not found"))?;
        Ok(session.record_chunk(raw_len, compressed_len, pid, module))
    }

    /// Generate an index for a session.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the session ID is not found.
    pub fn generate_index(&mut self, session_id: u64) -> Result<Vec<u8>, String> {
        self.sessions
            .get_mut(&session_id)
            .ok_or_else(|| format!("Session {session_id} not found"))
            .map(RecordingSession::generate_index)
    }

    /// Return current state of a session.
    #[must_use]
    pub fn session_state(&self, session_id: u64) -> Option<&SessionState> {
        self.sessions
            .get(&session_id)
            .map(|s| &s.state)
            .or_else(|| {
                self.archive
                    .iter()
                    .find(|s| s.session_id == session_id)
                    .map(|s| &s.state)
            })
    }

    /// Return all active session IDs.
    #[must_use]
    pub fn active_session_ids(&self) -> Vec<u64> {
        self.sessions
            .values()
            .filter(|s| s.state.is_active())
            .map(|s| s.session_id)
            .collect()
    }

    #[must_use]
    pub const fn aggregate_stats(&self) -> &SessionStats {
        &self.aggregate_stats
    }

    #[must_use]
    pub const fn archive_len(&self) -> usize {
        self.archive.len()
    }

    #[must_use]
    pub fn active_count(&self) -> usize {
        self.sessions.values().filter(|s| s.state.is_active()).count()
    }

    /// Get the stats of a live or archived session.
    #[must_use]
    pub fn session_stats(&self, session_id: u64) -> Option<&SessionStats> {
        self.sessions
            .get(&session_id)
            .map(|s| &s.stats)
            .or_else(|| {
                self.archive
                    .iter()
                    .find(|s| s.session_id == session_id)
                    .map(|s| &s.stats)
            })
    }
}

// ─── Thread-safe wrapper ──────────────────────────────────────────────────────

/// Thread-safe shared session manager.
pub struct SharedSessionManager(Arc<Mutex<RecordingSessionManager>>);

impl SharedSessionManager {
    #[must_use]
    pub fn new(max_concurrent: usize) -> Self {
        Self(Arc::new(Mutex::new(RecordingSessionManager::new(
            max_concurrent,
        ))))
    }

    /// # Panics
    ///
    /// Panics if the session manager lock is poisoned.
    pub fn with<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut RecordingSessionManager) -> R,
    {
        let mut guard = self.0.lock().expect("session manager lock poisoned");
        f(&mut guard)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn config() -> SessionConfig {
        SessionConfig::new(PathBuf::from("/tmp/rustre_test"))
    }

    // ── SessionConfig ──

    #[test]
    fn test_max_trace_bytes() {
        let cfg = SessionConfig::new(PathBuf::from("/tmp"));
        assert_eq!(cfg.max_trace_bytes(), 4 * 1_073_741_824u64);
    }

    #[test]
    fn test_pid_filter() {
        let mut cfg = config();
        assert!(cfg.pid_allowed(123));
        cfg.filter_pids.push(456);
        assert!(!cfg.pid_allowed(123));
        assert!(cfg.pid_allowed(456));
    }

    #[test]
    fn test_module_filter() {
        let mut cfg = config();
        assert!(cfg.module_allowed("anything.dll"));
        cfg.filter_modules.push("kernel32".into());
        assert!(cfg.module_allowed("KERNEL32.DLL"));
        assert!(!cfg.module_allowed("ntdll.dll"));
    }

    // ── SessionState ──

    #[test]
    fn test_session_state_terminal() {
        assert!(SessionState::Completed.is_terminal());
        assert!(SessionState::Failed("x".into()).is_terminal());
        assert!(!SessionState::Recording.is_terminal());
        assert!(!SessionState::Paused.is_terminal());
    }

    #[test]
    fn test_session_state_active() {
        assert!(SessionState::Recording.is_active());
        assert!(SessionState::Paused.is_active());
        assert!(!SessionState::Idle.is_active());
        assert!(!SessionState::Completed.is_active());
    }

    // ── RecordingSession lifecycle ──

    #[test]
    fn test_start_stop_lifecycle() {
        let mut sess = RecordingSession::new(1, config());
        assert_eq!(sess.state, SessionState::Idle);
        sess.start().unwrap();
        assert_eq!(sess.state, SessionState::Recording);
        sess.stop().unwrap();
        assert_eq!(sess.state, SessionState::Completed);
    }

    #[test]
    fn test_pause_resume() {
        let mut sess = RecordingSession::new(2, config());
        sess.start().unwrap();
        sess.pause().unwrap();
        assert_eq!(sess.state, SessionState::Paused);
        sess.resume().unwrap();
        assert_eq!(sess.state, SessionState::Recording);
        assert_eq!(sess.stats.pause_count, 1);
        assert_eq!(sess.stats.resume_count, 1);
    }

    #[test]
    fn test_double_pause_fails() {
        let mut sess = RecordingSession::new(3, config());
        sess.start().unwrap();
        sess.pause().unwrap();
        assert!(sess.pause().is_err());
    }

    #[test]
    fn test_fail_session() {
        let mut sess = RecordingSession::new(4, config());
        sess.start().unwrap();
        sess.fail("disk full");
        assert!(matches!(sess.state, SessionState::Failed(_)));
        let failed_events = sess.events_of_type(&SessionEventType::SessionFailed);
        assert_eq!(failed_events.len(), 1);
    }

    #[test]
    fn test_record_chunks() {
        let mut sess = RecordingSession::new(5, config());
        sess.start().unwrap();
        let over = sess.record_chunk(512, 300, Some(1234), Some("test.dll".into()));
        assert!(!over);
        assert_eq!(sess.stats.chunks_written, 1);
        assert_eq!(sess.stats.bytes_written, 512);
        assert_eq!(sess.stats.bytes_compressed, 300);
        assert_eq!(sess.index.len(), 1);
    }

    #[test]
    fn test_size_threshold() {
        let mut cfg = config();
        cfg.max_trace_size_gb = 0.000_000_001; // tiny: ~1 byte
        let mut sess = RecordingSession::new(6, cfg);
        sess.start().unwrap();
        let over = sess.record_chunk(1024, 512, None, None);
        assert!(over);
    }

    // ── IndexEntry ──

    #[test]
    fn test_index_entry_roundtrip() {
        let entry = IndexEntry {
            seq: 42,
            timestamp_ns: 1_000_000_000,
            file_offset: 65536,
            chunk_len: 512,
            compressed: true,
            pid: Some(1234),
            module: None,
        };
        let bytes = entry.serialize();
        assert_eq!(bytes.len(), 40);
        let back = IndexEntry::deserialize(&bytes).unwrap();
        assert_eq!(back.seq, 42);
        assert_eq!(back.chunk_len, 512);
        assert!(back.compressed);
        assert_eq!(back.pid, Some(1234));
    }

    #[test]
    fn test_index_entry_deserialize_short() {
        assert!(IndexEntry::deserialize(&[0u8; 10]).is_none());
    }

    // ── generate_index ──

    #[test]
    fn test_generate_index_magic() {
        let mut sess = RecordingSession::new(7, config());
        sess.start().unwrap();
        sess.record_chunk(100, 80, None, None);
        sess.record_chunk(200, 150, None, None);
        let idx = sess.generate_index();
        assert!(idx.starts_with(b"TTDIDX01"));
        let count = u64::from_le_bytes(idx[8..16].try_into().unwrap());
        assert_eq!(count, 2);
    }

    // ── RecordingSessionManager ──

    #[test]
    fn test_manager_start_stop() {
        let mut mgr = RecordingSessionManager::new(4);
        let id = mgr.start_recording(config()).unwrap();
        assert_eq!(mgr.active_count(), 1);
        let stats = mgr.stop_recording(id).unwrap();
        assert_eq!(mgr.active_count(), 0);
        assert_eq!(mgr.archive_len(), 1);
        // State in archive
        let state = mgr.session_state(id).unwrap();
        assert_eq!(*state, SessionState::Completed);
        drop(stats);
    }

    #[test]
    fn test_manager_max_concurrent() {
        let mut mgr = RecordingSessionManager::new(2);
        mgr.start_recording(config()).unwrap();
        mgr.start_recording(config()).unwrap();
        assert!(mgr.start_recording(config()).is_err());
    }

    #[test]
    fn test_manager_pause_resume() {
        let mut mgr = RecordingSessionManager::new(4);
        let id = mgr.start_recording(config()).unwrap();
        mgr.pause_recording(id).unwrap();
        assert_eq!(*mgr.session_state(id).unwrap(), SessionState::Paused);
        mgr.resume_recording(id).unwrap();
        assert_eq!(*mgr.session_state(id).unwrap(), SessionState::Recording);
    }

    #[test]
    fn test_manager_fail_session() {
        let mut mgr = RecordingSessionManager::new(4);
        let id = mgr.start_recording(config()).unwrap();
        mgr.fail_session(id, "test error");
        let state = mgr.session_state(id).unwrap();
        assert!(matches!(state, SessionState::Failed(_)));
    }

    #[test]
    fn test_manager_record_and_index() {
        let mut mgr = RecordingSessionManager::new(4);
        let id = mgr.start_recording(config()).unwrap();
        mgr.record_chunk(id, 128, 100, Some(42), Some("mod.dll".into())).unwrap();
        mgr.record_chunk(id, 256, 200, None, None).unwrap();
        let idx = mgr.generate_index(id).unwrap();
        assert!(idx.starts_with(b"TTDIDX01"));
    }

    #[test]
    fn test_session_event_log_line() {
        let ev = SessionEvent::new(SessionEventType::ChunkWritten, 1)
            .with_detail("len=512");
        let line = ev.to_log_line();
        assert!(line.contains("chunk_written"));
        assert!(line.contains("len=512"));
    }

    #[test]
    fn test_stats_compression_ratio() {
        let mut s = SessionStats::default();
        s.bytes_written = 1000;
        s.bytes_compressed = 600;
        assert!((s.compression_ratio() - 0.6).abs() < 1e-9);
    }

    #[test]
    fn test_shared_session_manager() {
        let shared = SharedSessionManager::new(4);
        let id = shared.with(|mgr| mgr.start_recording(config()).unwrap());
        let active = shared.with(|mgr| mgr.active_count());
        assert_eq!(active, 1);
        shared.with(|mgr| mgr.stop_recording(id).unwrap());
        let active2 = shared.with(|mgr| mgr.active_count());
        assert_eq!(active2, 0);
    }
}
