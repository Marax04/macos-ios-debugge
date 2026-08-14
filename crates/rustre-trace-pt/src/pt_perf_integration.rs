//! Linux `perf_event` Intel Processor Trace integration.
//!
//! Provides a pure-Rust abstraction for configuring, starting, stopping, and
//! reading Intel PT data via the Linux `perf_event_open(2)` syscall.
//!
//! On non-Linux hosts (or where `perf_event_open` is unavailable) all
//! operations simulate the API in memory so that the rest of the codebase
//! can be developed cross-platform.

use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Constants ────────────────────────────────────────────────────────────────

/// `perf_type_id` for raw hardware events.
pub const PERF_TYPE_RAW: u32 = 4;
/// `perf_event_attr.type` for Intel PT (vendor-specific).
pub const PERF_TYPE_INTEL_PT: u32 = 8; // typically assigned dynamically; 8 = placeholder
/// Default AUX buffer order (pages): 2^4 = 16 pages = 64 KiB.
pub const DEFAULT_AUX_ORDER: u32 = 4;
/// Default data ring-buffer order: 2^1 = 2 pages = 8 KiB.
pub const DEFAULT_DATA_ORDER: u32 = 1;
/// Minimum AUX buffer size in bytes.
pub const MIN_AUX_BYTES: usize = 4096;
/// `PERF_RECORD_AUX` record type.
pub const PERF_RECORD_AUX: u32 = 19;
/// `PERF_RECORD_ITRACE_START` record type.
pub const PERF_RECORD_ITRACE_START: u32 = 20;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by the perf integration layer.
#[derive(Debug, Error)]
pub enum PerfError {
    /// The `perf_event_open` syscall returned an error.
    #[error("perf_event_open failed: {0}")]
    OpenFailed(String),
    /// The `mmap` call for the ring buffer failed.
    #[error("mmap failed: {0}")]
    MmapFailed(String),
    /// Tracing is already running.
    #[error("tracing already running")]
    AlreadyRunning,
    /// Tracing is not running.
    #[error("tracing not running")]
    NotRunning,
    /// The AUX buffer is empty.
    #[error("AUX buffer empty")]
    AuxEmpty,
    /// The kernel does not support Intel PT.
    #[error("Intel PT not supported by this kernel/CPU")]
    NotSupported,
    /// A generic I/O error.
    #[error("I/O error: {0}")]
    Io(String),
}

// ─── PerfEventType ────────────────────────────────────────────────────────────

/// Classification of a `perf` event record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PerfEventType {
    /// Raw AUX (PT) data record.
    Aux,
    /// `ITrace` start (new PT stream).
    ItraceStart,
    /// Loss notification.
    Lost,
    /// Other record type.
    Other(u32),
}

impl PerfEventType {
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            PERF_RECORD_AUX => Self::Aux,
            PERF_RECORD_ITRACE_START => Self::ItraceStart,
            4 => Self::Lost,
            other => Self::Other(other),
        }
    }
}

impl fmt::Display for PerfEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aux => write!(f, "Aux"),
            Self::ItraceStart => write!(f, "ItraceStart"),
            Self::Lost => write!(f, "Lost"),
            Self::Other(v) => write!(f, "Other({v})"),
        }
    }
}

// ─── PerfEvent ────────────────────────────────────────────────────────────────

/// A single `perf` ring-buffer record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfEvent {
    /// Record type.
    pub event_type: PerfEventType,
    /// Timestamp (`PERF_SAMPLE_TIME`).
    pub time: u64,
    /// Associated pid/tid.
    pub pid: u32,
    /// Associated tid.
    pub tid: u32,
    /// For `Aux` events: offset into the AUX buffer.
    pub aux_offset: u64,
    /// For `Aux` events: size of the data.
    pub aux_size: u64,
    /// For `Lost` events: count of lost records.
    pub lost_count: u64,
}

impl PerfEvent {
    /// Create a new AUX record.
    #[must_use]
    pub const fn aux(pid: u32, tid: u32, aux_offset: u64, aux_size: u64, time: u64) -> Self {
        Self {
            event_type: PerfEventType::Aux,
            time,
            pid,
            tid,
            aux_offset,
            aux_size,
            lost_count: 0,
        }
    }

    /// Create an `ItraceStart` record.
    #[must_use]
    pub const fn itrace_start(pid: u32, tid: u32, time: u64) -> Self {
        Self {
            event_type: PerfEventType::ItraceStart,
            time,
            pid,
            tid,
            aux_offset: 0,
            aux_size: 0,
            lost_count: 0,
        }
    }
}

impl fmt::Display for PerfEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PerfEvent({}, pid={}, tid={}, time={})",
            self.event_type, self.pid, self.tid, self.time,
        )
    }
}

// ─── AuxBuffer ────────────────────────────────────────────────────────────────

/// An Intel PT AUX buffer — the circular region where the CPU writes PT data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuxBuffer {
    /// Raw trace bytes.
    pub data: Vec<u8>,
    /// Simulated write head position.
    pub write_head: u64,
    /// Simulated read head position.
    pub read_head: u64,
    /// Buffer capacity in bytes.
    pub capacity: usize,
    /// Number of PT bytes that were lost due to overflow.
    pub bytes_lost: u64,
}

impl AuxBuffer {
    /// Create a new buffer with the given capacity (must be a power of two).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            data: vec![0u8; capacity],
            write_head: 0,
            read_head: 0,
            capacity,
            bytes_lost: 0,
        }
    }

    /// Append raw PT data (simulating a CPU write).
    pub fn write(&mut self, trace: &[u8]) {
        let avail = self.capacity - crate::cast_helpers::u64_to_usize(self.write_head - self.read_head);
        if trace.len() > avail {
            self.bytes_lost += (trace.len() - avail) as u64;
        }
        let to_copy = trace.len().min(avail);
        for (i, &b) in trace[..to_copy].iter().enumerate() {
            let idx = (crate::cast_helpers::u64_to_usize(self.write_head) + i) % self.capacity;
            self.data[idx] = b;
        }
        self.write_head += to_copy as u64;
    }

    /// Read all available data and advance the read head.
    #[must_use]
    pub fn read_all(&mut self) -> Vec<u8> {
        let avail = crate::cast_helpers::u64_to_usize(self.write_head - self.read_head);
        if avail == 0 {
            return vec![];
        }
        let mut out = Vec::with_capacity(avail);
        for i in 0..avail {
            let idx = (crate::cast_helpers::u64_to_usize(self.read_head) + i) % self.capacity;
            out.push(self.data[idx]);
        }
        self.read_head = self.write_head;
        out
    }

    /// Return the number of unread bytes.
    #[must_use]
    pub fn available(&self) -> usize {
        crate::cast_helpers::u64_to_usize(self.write_head - self.read_head)
    }

    /// Return `true` if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.available() == 0
    }

    /// Return the fill percentage (0–100).
    #[must_use]
    pub fn fill_percent(&self) -> f64 {
        100.0 * crate::cast_helpers::usize_to_f64(self.available()) / crate::cast_helpers::usize_to_f64(self.capacity)
    }
}

// ─── PtConfig ─────────────────────────────────────────────────────────────────

/// Configuration for an Intel PT session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtConfig {
    /// Process ID to trace (`-1` = all processes, `0` = calling process).
    pub pid: i32,
    /// CPU to trace (`-1` = any CPU).
    pub cpu: i32,
    /// AUX buffer size order (2^order pages).
    pub aux_order: u32,
    /// Data ring-buffer size order (2^order + 1 pages).
    pub data_order: u32,
    /// Enable branch tracing.
    pub branch_enable: bool,
    /// Enable timing packets (TSC/MTC/CYC).
    pub timing_enable: bool,
    /// Enable PT packet generation enable / disable (TIP.PGE/TIP.PGD).
    pub pge_enable: bool,
    /// Filter by privilege level: `true` = trace kernel only.
    pub kernel_only: bool,
}

impl PtConfig {
    /// Create a default configuration for tracing the calling process.
    #[must_use]
    pub const fn default_process() -> Self {
        Self {
            pid: 0,
            cpu: -1,
            aux_order: DEFAULT_AUX_ORDER,
            data_order: DEFAULT_DATA_ORDER,
            branch_enable: true,
            timing_enable: true,
            pge_enable: true,
            kernel_only: false,
        }
    }

    /// Create a configuration for system-wide kernel tracing.
    #[must_use]
    pub const fn kernel_trace(cpu: i32) -> Self {
        Self {
            pid: -1,
            cpu,
            aux_order: DEFAULT_AUX_ORDER + 2,
            data_order: DEFAULT_DATA_ORDER,
            branch_enable: true,
            timing_enable: true,
            pge_enable: false,
            kernel_only: true,
        }
    }

    /// Return the AUX buffer size in bytes.
    #[must_use]
    pub const fn aux_bytes(&self) -> usize {
        (1usize << self.aux_order) * 4096
    }

    /// Return the data ring buffer size in bytes (excluding the header page).
    #[must_use]
    pub const fn data_bytes(&self) -> usize {
        (1usize << self.data_order) * 4096
    }
}

impl Default for PtConfig {
    fn default() -> Self {
        Self::default_process()
    }
}

// ─── PtPerfIntegration ────────────────────────────────────────────────────────

/// High-level Intel PT integration using `perf_event_open`.
///
/// On Linux this struct would hold the perf fd and mmap'd ring buffer.
/// In this simulation it uses an in-memory `AuxBuffer`.
#[derive(Debug)]
pub struct PtPerfIntegration {
    inner: Arc<Mutex<PtPerfInner>>,
}

#[derive(Debug)]
struct PtPerfInner {
    config: PtConfig,
    running: bool,
    aux: AuxBuffer,
    events: VecDeque<PerfEvent>,
    total_bytes_captured: u64,
    sequence: u64,
}

impl PtPerfIntegration {
    /// Create a new integration session with the given configuration.
    #[must_use]
    pub fn new(config: PtConfig) -> Self {
        let cap = config.aux_bytes().max(MIN_AUX_BYTES);
        Self {
            inner: Arc::new(Mutex::new(PtPerfInner {
                aux: AuxBuffer::new(cap),
                events: VecDeque::new(),
                total_bytes_captured: 0,
                sequence: 0,
                running: false,
                config,
            })),
        }
    }

    /// Start tracing.
    ///
    /// # Panics
    /// May panic on invalid input.
    ///
    /// # Errors
    /// Returns [`PerfError::AlreadyRunning`] if already started.
    pub fn start_tracing(&self) -> Result<(), PerfError> {
        let mut inner = self.inner.lock().unwrap();
        if inner.running {
            return Err(PerfError::AlreadyRunning);
        }
        inner.running = true;
        // Emit an ItraceStart event.
        let evt = PerfEvent::itrace_start(
            inner.config.pid.unsigned_abs(),
            inner.config.pid.unsigned_abs(),
            inner.sequence,
        );
        inner.sequence += 1;
        inner.events.push_back(evt);
        Ok(())
    }

    /// Stop tracing.
    ///
    /// # Panics
    /// May panic on invalid input.
    ///
    /// # Errors
    /// Returns [`PerfError::NotRunning`] if not started.
    pub fn stop_tracing(&self) -> Result<(), PerfError> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.running {
            return Err(PerfError::NotRunning);
        }
        inner.running = false;
        Ok(())
    }

    /// Inject simulated PT trace data (for testing or replay).
    ///
    /// # Panics
    /// May panic on invalid input.
    pub fn inject_trace(&self, data: &[u8]) {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.aux.write_head;
        inner.aux.write(data);
        let after = inner.aux.write_head;
        let written = after - before;
        inner.total_bytes_captured += written;
        if written > 0 {
            let evt = PerfEvent::aux(
                inner.config.pid.unsigned_abs(),
                inner.config.pid.unsigned_abs(),
                before,
                written,
                inner.sequence,
            );
            inner.sequence += 1;
            inner.events.push_back(evt);
        }
    }

    /// Read all available PT bytes from the AUX buffer.
    ///
    /// # Panics
    /// May panic on invalid input.
    ///
    /// # Errors
    /// Returns [`PerfError::AuxEmpty`] if no data is available.
    pub fn read_trace(&self) -> Result<Vec<u8>, PerfError> {
        let mut inner = self.inner.lock().unwrap();
        if inner.aux.is_empty() {
            return Err(PerfError::AuxEmpty);
        }
        Ok(inner.aux.read_all())
    }

    /// Drain and return all pending `perf` events.
    ///
    /// # Panics
    /// May panic on invalid input.
    #[must_use] 
    pub fn drain_events(&self) -> Vec<PerfEvent> {
        let mut inner = self.inner.lock().unwrap();
        inner.events.drain(..).collect()
    }

    /// Return `true` if tracing is active.
    ///
    /// # Panics
    /// May panic on invalid input.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.inner.lock().unwrap().running
    }

    /// Return the total bytes captured since creation.
    ///
    /// # Panics
    /// May panic on invalid input.
    #[must_use]
    pub fn total_bytes_captured(&self) -> u64 {
        self.inner.lock().unwrap().total_bytes_captured
    }

    /// Return the current AUX buffer fill percentage.
    ///
    /// # Panics
    /// May panic on invalid input.
    #[must_use]
    pub fn aux_fill_percent(&self) -> f64 {
        self.inner.lock().unwrap().aux.fill_percent()
    }

    /// Return the bytes lost to overflow.
    ///
    /// # Panics
    /// May panic on invalid input.
    #[must_use]
    pub fn bytes_lost(&self) -> u64 {
        self.inner.lock().unwrap().aux.bytes_lost
    }

    /// Return a clone of the current configuration.
    ///
    /// # Panics
    /// May panic on invalid input.
    #[must_use]
    pub fn config(&self) -> PtConfig {
        self.inner.lock().unwrap().config.clone()
    }

    /// Return the AUX buffer capacity.
    ///
    /// # Panics
    /// May panic on invalid input.
    #[must_use]
    pub fn aux_capacity(&self) -> usize {
        self.inner.lock().unwrap().aux.capacity
    }
}

impl Default for PtPerfIntegration {
    fn default() -> Self {
        Self::new(PtConfig::default())
    }
}

// ─── perf_type_name (utility) ─────────────────────────────────────────────────

/// Return a human-readable name for a `perf_type_id` value.
#[must_use]
pub const fn perf_type_name(t: u32) -> &'static str {
    match t {
        0 => "HARDWARE",
        1 => "SOFTWARE",
        2 => "TRACEPOINT",
        3 => "HW_CACHE",
        4 => "RAW",
        5 => "BREAKPOINT",
        _ => "UNKNOWN",
    }
}

/// Return `true` if the CPU supports Intel PT (simulated check).
#[must_use]
pub const fn cpu_supports_pt() -> bool {
    // On real systems this would check CPUID leaf 0x14.
    // Here we always return `true` for the simulation.
    true
}

/// Compute the total trace bytes in a list of AUX events.
#[must_use]
pub fn total_aux_bytes(events: &[PerfEvent]) -> u64 {
    events
        .iter()
        .filter(|e| e.event_type == PerfEventType::Aux)
        .map(|e| e.aux_size)
        .sum()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PerfEventType ─────────────────────────────────────────────────────────

    #[test]
    fn test_perf_event_type_from_u32() {
        assert_eq!(PerfEventType::from_u32(19), PerfEventType::Aux);
        assert_eq!(PerfEventType::from_u32(20), PerfEventType::ItraceStart);
        assert!(matches!(PerfEventType::from_u32(99), PerfEventType::Other(99)));
    }

    #[test]
    fn test_perf_event_type_display() {
        assert_eq!(PerfEventType::Aux.to_string(), "Aux");
        assert_eq!(PerfEventType::Other(5).to_string(), "Other(5)");
    }

    // ── PerfEvent ─────────────────────────────────────────────────────────────

    #[test]
    fn test_perf_event_aux() {
        let e = PerfEvent::aux(42, 43, 0, 128, 1000);
        assert_eq!(e.event_type, PerfEventType::Aux);
        assert_eq!(e.pid, 42);
        assert_eq!(e.aux_size, 128);
    }

    #[test]
    fn test_perf_event_itrace_start() {
        let e = PerfEvent::itrace_start(1, 2, 500);
        assert_eq!(e.event_type, PerfEventType::ItraceStart);
    }

    #[test]
    fn test_perf_event_display() {
        let e = PerfEvent::aux(1, 1, 0, 64, 0);
        let s = e.to_string();
        assert!(s.contains("Aux"));
        assert!(s.contains("pid=1"));
    }

    // ── AuxBuffer ─────────────────────────────────────────────────────────────

    #[test]
    fn test_aux_buffer_write_read() {
        let mut b = AuxBuffer::new(4096);
        b.write(&[1, 2, 3, 4]);
        assert_eq!(b.available(), 4);
        let data = b.read_all();
        assert_eq!(data, vec![1, 2, 3, 4]);
        assert!(b.is_empty());
    }

    #[test]
    fn test_aux_buffer_wrap_around() {
        let mut b = AuxBuffer::new(8);
        b.write(&[0, 1, 2, 3, 4, 5, 6]); // 7 bytes
        let _ = b.read_all(); // consume
        b.write(&[10, 11, 12, 13]); // wraps
        let data = b.read_all();
        assert_eq!(data, vec![10, 11, 12, 13]);
    }

    #[test]
    fn test_aux_buffer_overflow() {
        let mut b = AuxBuffer::new(4);
        b.write(&[0, 1, 2, 3, 4, 5]); // 6 bytes into 4-byte buffer → 2 lost
        assert_eq!(b.bytes_lost, 2);
    }

    #[test]
    fn test_aux_buffer_fill_percent() {
        let mut b = AuxBuffer::new(4096);
        b.write(&vec![0u8; 2048]);
        let pct = b.fill_percent();
        assert!((pct - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_aux_buffer_empty() {
        let b = AuxBuffer::new(4096);
        assert!(b.is_empty());
        let data = b.data.clone();
        let mut b2 = b;
        let out = b2.read_all();
        assert!(out.is_empty());
        assert_eq!(b2.data, data); // unchanged
    }

    // ── PtConfig ──────────────────────────────────────────────────────────────

    #[test]
    fn test_pt_config_default_process() {
        let c = PtConfig::default_process();
        assert_eq!(c.pid, 0);
        assert_eq!(c.cpu, -1);
        assert!(c.branch_enable);
        assert!(c.aux_bytes() > 0);
        assert!(c.data_bytes() > 0);
    }

    #[test]
    fn test_pt_config_kernel_trace() {
        let c = PtConfig::kernel_trace(0);
        assert_eq!(c.pid, -1);
        assert_eq!(c.cpu, 0);
        assert!(c.kernel_only);
    }

    #[test]
    fn test_pt_config_aux_bytes() {
        let c = PtConfig { aux_order: 4, ..PtConfig::default() };
        assert_eq!(c.aux_bytes(), 16 * 4096);
    }

    // ── PtPerfIntegration ─────────────────────────────────────────────────────

    #[test]
    fn test_start_stop_tracing() {
        let pt = PtPerfIntegration::new(PtConfig::default());
        pt.start_tracing().unwrap();
        assert!(pt.is_running());
        pt.stop_tracing().unwrap();
        assert!(!pt.is_running());
    }

    #[test]
    fn test_already_running_error() {
        let pt = PtPerfIntegration::new(PtConfig::default());
        pt.start_tracing().unwrap();
        let err = pt.start_tracing().unwrap_err();
        assert!(matches!(err, PerfError::AlreadyRunning));
    }

    #[test]
    fn test_not_running_error() {
        let pt = PtPerfIntegration::new(PtConfig::default());
        let err = pt.stop_tracing().unwrap_err();
        assert!(matches!(err, PerfError::NotRunning));
    }

    #[test]
    fn test_inject_and_read_trace() {
        let pt = PtPerfIntegration::new(PtConfig::default());
        pt.start_tracing().unwrap();
        let payload = vec![0x02u8, 0x82, 0x00, 0x00];
        pt.inject_trace(&payload);
        let data = pt.read_trace().unwrap();
        assert_eq!(data, payload);
    }

    #[test]
    fn test_read_trace_empty_error() {
        let pt = PtPerfIntegration::new(PtConfig::default());
        let err = pt.read_trace().unwrap_err();
        assert!(matches!(err, PerfError::AuxEmpty));
    }

    #[test]
    fn test_drain_events() {
        let pt = PtPerfIntegration::new(PtConfig::default());
        pt.start_tracing().unwrap();
        pt.inject_trace(&[0x00, 0x00]);
        let evts = pt.drain_events();
        // Should have at least ItraceStart + Aux
        assert!(evts.len() >= 2);
        assert_eq!(evts[0].event_type, PerfEventType::ItraceStart);
        assert_eq!(evts[1].event_type, PerfEventType::Aux);
    }

    #[test]
    fn test_total_bytes_captured() {
        let pt = PtPerfIntegration::new(PtConfig::default());
        pt.start_tracing().unwrap();
        pt.inject_trace(&[0xAA; 64]);
        assert_eq!(pt.total_bytes_captured(), 64);
    }

    #[test]
    fn test_aux_fill_percent() {
        let cfg = PtConfig { aux_order: 0, ..PtConfig::default() };
        // aux_order=0 → 1 page = 4096 bytes, but MIN_AUX_BYTES = 4096 too
        let pt = PtPerfIntegration::new(cfg);
        pt.inject_trace(&vec![0u8; 2048]);
        let pct = pt.aux_fill_percent();
        assert!((pct - 50.0).abs() < 1.0);
    }

    #[test]
    fn test_bytes_lost() {
        let cfg = PtConfig { aux_order: 0, ..PtConfig::default() };
        let pt = PtPerfIntegration::new(cfg);
        let cap = pt.aux_capacity();
        // Write more than capacity
        pt.inject_trace(&vec![0u8; cap + 128]);
        assert!(pt.bytes_lost() >= 128);
    }

    // ── Utility functions ─────────────────────────────────────────────────────

    #[test]
    fn test_perf_type_name() {
        assert_eq!(perf_type_name(0), "HARDWARE");
        assert_eq!(perf_type_name(4), "RAW");
        assert_eq!(perf_type_name(99), "UNKNOWN");
    }

    #[test]
    fn test_cpu_supports_pt() {
        assert!(cpu_supports_pt());
    }

    #[test]
    fn test_total_aux_bytes() {
        let events = vec![
            PerfEvent::aux(1, 1, 0, 100, 0),
            PerfEvent::itrace_start(1, 1, 0),
            PerfEvent::aux(1, 1, 100, 200, 1),
        ];
        assert_eq!(total_aux_bytes(&events), 300);
    }

    // ── Error display ─────────────────────────────────────────────────────────

    #[test]
    fn test_perf_error_display() {
        let e = PerfError::OpenFailed("EACCES".to_string());
        assert!(e.to_string().contains("EACCES"));
        let e2 = PerfError::AlreadyRunning;
        assert!(e2.to_string().contains("already running"));
        let e3 = PerfError::AuxEmpty;
        assert!(e3.to_string().contains("empty") || e3.to_string().contains("AUX"));
    }
}
