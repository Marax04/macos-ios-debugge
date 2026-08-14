//! `ttd_trace_loader` — parse and load TTD `.run` trace files.
//!
//! Implements a two-phase loader:
//!
//! 1. **Header parsing** (`parse_header`) — reads the fixed-size file header
//!    to obtain trace metadata (version, thread count, first/last tick,
//!    architecture, module list).
//! 2. **Body streaming** (`load_trace`) — iterates over the binary event
//!    stream, populating a [`TtdTrace`] with [`TraceEvent`]s and periodic
//!    [`TraceSnapshot`]s, and building a sparse [`PositionIndex`].
//!
//! The on-disk format modelled here is a simplified stand-in for the actual
//! `WinDBG` TTD format.  Frames are [`FRAME_SIZE`]-byte little-endian records
//! with a 1-byte kind discriminant followed by payload fields.

use std::fmt;
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{MemWriteRecord, TraceEvent, TraceSnapshot, TtdTrace};

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors produced by the TTD trace loader.
#[derive(Debug, Error)]
pub enum LoadError {
    /// I/O failure while reading the trace file.
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// The file header magic bytes do not match the expected value.
    #[error("invalid magic: expected {expected:#x} got {actual:#x}")]
    BadMagic { expected: u64, actual: u64 },

    /// The file format version is not supported.
    #[error("unsupported version {0}")]
    UnsupportedVersion(u32),

    /// The trace file is truncated mid-record.
    #[error("truncated trace: failed to read {expected} bytes")]
    Truncated { expected: usize },

    /// The path does not point to a regular file.
    #[error("not a file: {0}")]
    NotAFile(PathBuf),
}

// ── Constants ─────────────────────────────────────────────────────────────────

/// Magic bytes at the start of every `.run` file (little-endian `"TTD\0RUN\0"`).
pub const TRACE_MAGIC: u64 = 0x0052_554e_0044_5454;

/// Currently supported major version.
pub const SUPPORTED_VERSION_MAJOR: u32 = 2;

/// Size of the fixed file header in bytes.
pub const HEADER_SIZE: usize = 128;

/// Size of each event frame in bytes.
pub const FRAME_SIZE: usize = 32;

/// Event kind: syscall entry.
pub const KIND_SYSCALL_ENTRY: u8 = 0x01;
/// Event kind: syscall exit.
pub const KIND_SYSCALL_EXIT: u8 = 0x02;
/// Event kind: signal delivery.
pub const KIND_SIGNAL: u8 = 0x03;
/// Event kind: full checkpoint snapshot.
pub const KIND_SNAPSHOT: u8 = 0x10;
/// Event kind: module load.
pub const KIND_MODULE_LOAD: u8 = 0x20;
/// Event kind: end-of-trace marker.
pub const KIND_END: u8 = 0xFF;

// ── TraceArch ─────────────────────────────────────────────────────────────────

/// Target architecture recorded in the trace header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceArch {
    /// 64-bit x86.
    X86_64,
    /// 64-bit ARM.
    Arm64,
    /// 32-bit x86.
    X86,
    /// 32-bit ARM.
    Arm32,
    /// Unrecognised byte.
    Unknown(u8),
}

impl fmt::Display for TraceArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86_64 => write!(f, "x86_64"),
            Self::Arm64 => write!(f, "arm64"),
            Self::X86 => write!(f, "x86"),
            Self::Arm32 => write!(f, "arm32"),
            Self::Unknown(b) => write!(f, "unknown({b:#x})"),
        }
    }
}

impl TraceArch {
    const fn from_byte(b: u8) -> Self {
        match b {
            1 => Self::X86_64,
            2 => Self::Arm64,
            3 => Self::X86,
            4 => Self::Arm32,
            other => Self::Unknown(other),
        }
    }
}

// ── ModuleEntry ───────────────────────────────────────────────────────────────

/// A module (executable or DLL) loaded during the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleEntry {
    /// Module name (synthesized from base address when unavailable).
    pub name: String,
    /// Base load address.
    pub base: u64,
    /// Image size in bytes.
    pub size: u64,
    /// Tick when the module was loaded.
    pub load_tick: u64,
}

// ── TraceHeader ───────────────────────────────────────────────────────────────

/// Parsed TTD trace file header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceHeader {
    /// Major format version.
    pub version_major: u32,
    /// Minor format version.
    pub version_minor: u32,
    /// Target architecture.
    pub arch: TraceArch,
    /// Tick of the first recorded event.
    pub first_tick: u64,
    /// Tick of the last recorded event.
    pub last_tick: u64,
    /// Number of threads observed.
    pub thread_count: u32,
    /// File size in bytes (from filesystem metadata).
    pub file_size: u64,
    /// Timestamp when the trace was recorded (Unix epoch seconds).
    pub recorded_at: u64,
    /// Number of events declared in the header.
    pub event_count: u64,
    /// Number of module-load events declared in the header.
    pub module_count: u32,
    /// Optional user comment embedded in the header (null-terminated, max 71 bytes).
    pub comment: String,
    /// File path this header was loaded from.
    pub source_path: PathBuf,
}

impl TraceHeader {
    /// Return `true` if the header describes a supported trace file.
    #[must_use]
    pub const fn is_supported(&self) -> bool {
        self.version_major == SUPPORTED_VERSION_MAJOR
    }

    /// Human-readable one-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "TTD trace v{}.{} arch={} ticks={}..{} threads={} events={}",
            self.version_major,
            self.version_minor,
            self.arch,
            self.first_tick,
            self.last_tick,
            self.thread_count,
            self.event_count,
        )
    }
}

impl fmt::Display for TraceHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ── PositionIndex ─────────────────────────────────────────────────────────────

/// A sparse index mapping tick values to byte offsets inside the trace file.
///
/// Built during [`TtdTraceLoader::load_trace`] so that out-of-order seeks can
/// restart from the nearest earlier indexed position rather than scanning from
/// the beginning of the file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PositionIndex {
    /// Sorted `(tick, file_offset)` pairs.
    entries: Vec<(u64, u64)>,
}

impl PositionIndex {
    /// Create an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update a `(tick, offset)` entry.
    pub fn insert(&mut self, tick: u64, offset: u64) {
        match self.entries.binary_search_by_key(&tick, |&(t, _)| t) {
            Ok(i) => self.entries[i].1 = offset,
            Err(i) => self.entries.insert(i, (tick, offset)),
        }
    }

    /// Find the largest indexed tick that is `<= target`.
    ///
    /// Returns the `(tick, file_offset)` pair, or `None` when the index is
    /// empty or all entries are after `target`.
    #[must_use]
    pub fn find_before(&self, target: u64) -> Option<(u64, u64)> {
        let pos = self.entries.partition_point(|&(t, _)| t <= target);
        if pos == 0 {
            None
        } else {
            Some(self.entries[pos - 1])
        }
    }

    /// Number of entries in the index.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the index contains no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return all entries as a slice.
    #[must_use]
    pub fn entries(&self) -> &[(u64, u64)] {
        &self.entries
    }
}

// ── LoadOptions ───────────────────────────────────────────────────────────────

/// Options controlling how a trace file is loaded.
#[derive(Debug, Clone)]
pub struct LoadOptions {
    /// Snapshot interval: record a snapshot every N ticks (0 = use 256).
    pub snapshot_interval: u64,
    /// Maximum number of events to load (0 = unlimited).
    pub max_events: usize,
    /// Whether to build the position index during load.
    pub build_index: bool,
    /// Whether to parse `KIND_MODULE_LOAD` events.
    pub load_modules: bool,
}

impl Default for LoadOptions {
    fn default() -> Self {
        Self {
            snapshot_interval: 256,
            max_events: 0,
            build_index: true,
            load_modules: true,
        }
    }
}

// ── LoadResult ────────────────────────────────────────────────────────────────

/// Complete result of loading a TTD trace file.
pub struct LoadResult {
    /// Populated trace ready for replay.
    pub trace: TtdTrace,
    /// Parsed file header.
    pub header: TraceHeader,
    /// Sparse tick-to-file-offset position index.
    pub index: PositionIndex,
    /// Module entries found in the trace.
    pub modules: Vec<ModuleEntry>,
    /// Total number of frames parsed (including the END frame).
    pub frames_parsed: u64,
    /// Frames that had an unrecognised kind and were skipped.
    pub frames_skipped: u64,
}

// ── TtdTraceLoader ────────────────────────────────────────────────────────────

/// Loads a TTD `.run` trace file from disk.
///
/// # Example
///
/// ```no_run
/// use rustre_ttd_replayer::ttd_trace_loader::{TtdTraceLoader, LoadOptions};
///
/// let loader = TtdTraceLoader::with_defaults();
/// let result = loader.load_trace("/traces/app.run").unwrap();
/// println!("{}", result.header.summary());
/// println!("events loaded: {}", result.trace.len());
/// ```
pub struct TtdTraceLoader {
    options: LoadOptions,
}

impl TtdTraceLoader {
    /// Create a loader with the given options.
    #[must_use]
    pub const fn new(options: LoadOptions) -> Self {
        Self { options }
    }

    /// Create a loader with default options.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(LoadOptions::default())
    }

    // ── public API ────────────────────────────────────────────────────────────

    /// Parse only the header of a trace file without reading the full body.
    ///
    /// # Errors
    ///
    /// Returns [`LoadError`] on I/O failure, bad magic, or unsupported version.
    pub fn parse_header(&self, path: impl AsRef<Path>) -> Result<TraceHeader, LoadError> {
        let path = path.as_ref();
        if !path.is_file() {
            return Err(LoadError::NotAFile(path.to_path_buf()));
        }
        let file = std::fs::File::open(path)?;
        let meta = file.metadata()?;
        let mut reader = BufReader::new(file);
        self.read_header(&mut reader, path.to_path_buf(), meta.len())
    }

    /// Load a full TTD trace from the file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`LoadError`] on any I/O or format error.
    pub fn load_trace(&self, path: impl AsRef<Path>) -> Result<LoadResult, LoadError> {
        let path = path.as_ref();
        if !path.is_file() {
            return Err(LoadError::NotAFile(path.to_path_buf()));
        }

        let file = std::fs::File::open(path)?;
        let meta = file.metadata()?;
        let mut reader = BufReader::new(file);

        let header = self.read_header(&mut reader, path.to_path_buf(), meta.len())?;

        let mut trace = TtdTrace::new();
        let mut index = PositionIndex::new();
        let mut modules: Vec<ModuleEntry> = Vec::new();
        let mut frames_parsed: u64 = 0;
        let mut frames_skipped: u64 = 0;

        let snap_interval = if self.options.snapshot_interval == 0 {
            256
        } else {
            self.options.snapshot_interval
        };

        let mut last_snap_tick: u64 = 0;
        let mut buf = [0u8; FRAME_SIZE];
        // Tracks byte offset of the current frame (starts after header).
        let mut current_offset: u64 = HEADER_SIZE as u64;

        loop {
            match reader.read_exact(&mut buf) {
                Ok(()) => {}
                Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(LoadError::Io(e)),
            }

            let frame_offset = current_offset;
            current_offset += FRAME_SIZE as u64;
            let kind = buf[0];
            frames_parsed += 1;

            if self.options.max_events > 0
                && frames_parsed > self.options.max_events as u64
            {
                break;
            }

            match kind {
                KIND_SYSCALL_ENTRY => {
                    let tick = read_u64(&buf, 1);
                    let nr = read_u64(&buf, 9);
                    let mut args = [0u64; 6];
                    for i in 0..3 {
                        args[i] = u64::from(read_u32(&buf, 17 + i * 4));
                    }

                    if self.options.build_index {
                        index.insert(tick, frame_offset);
                    }

                    maybe_snapshot(&mut trace, tick, &mut last_snap_tick, snap_interval, tick);
                    trace.push_event(TraceEvent::SyscallEntry { tick, nr, args });
                }

                KIND_SYSCALL_EXIT => {
                    let tick = read_u64(&buf, 1);
                    let retval = i64::from_le_bytes(buf[9..17].try_into().unwrap_or([0; 8]));
                    let write_addr = read_u64(&buf, 17);
                    let write_len = buf[25] as usize;

                    let mut mem_writes: Vec<MemWriteRecord> = Vec::new();
                    if write_addr > 0 && (1..=8).contains(&write_len) {
                        mem_writes.push(MemWriteRecord::new(write_addr, vec![0xAAu8; write_len]));
                    }
                    trace.push_event(TraceEvent::SyscallExit { tick, retval, mem_writes });
                }

                KIND_SIGNAL => {
                    let tick = read_u64(&buf, 1);
                    let signal = i32::from_le_bytes(buf[9..13].try_into().unwrap_or([0; 4]));
                    let pc = read_u64(&buf, 13);
                    trace.push_event(TraceEvent::SignalDelivered { tick, signal, pc });
                }

                KIND_SNAPSHOT => {
                    let tick = read_u64(&buf, 1);
                    let rip = read_u64(&buf, 9);
                    let rsp = read_u64(&buf, 17);
                    let mut snap = TraceSnapshot::new(tick);
                    snap.set_reg("rip", rip);
                    snap.set_reg("rsp", rsp);
                    trace.push_snapshot(snap);
                    last_snap_tick = tick;
                }

                KIND_MODULE_LOAD if self.options.load_modules => {
                    let base = read_u64(&buf, 1);
                    let size = read_u64(&buf, 9);
                    let tick = read_u64(&buf, 17);
                    modules.push(ModuleEntry {
                        name: format!("module_{base:#x}"),
                        base,
                        size,
                        load_tick: tick,
                    });
                }

                KIND_END => break,

                _ => {
                    frames_skipped += 1;
                }
            }
        }

        Ok(LoadResult {
            trace,
            header,
            index,
            modules,
            frames_parsed,
            frames_skipped,
        })
    }

    // ── private ───────────────────────────────────────────────────────────────

    fn read_header<R: Read>(
        &self,
        reader: &mut R,
        path: PathBuf,
        file_size: u64,
    ) -> Result<TraceHeader, LoadError> {
        let mut hdr = [0u8; HEADER_SIZE];
        reader
            .read_exact(&mut hdr)
            .map_err(|_| LoadError::Truncated { expected: HEADER_SIZE })?;

        let magic = read_u64(&hdr, 0);
        if magic != TRACE_MAGIC {
            return Err(LoadError::BadMagic { expected: TRACE_MAGIC, actual: magic });
        }

        let version_major = read_u32(&hdr, 8);
        if version_major != SUPPORTED_VERSION_MAJOR {
            return Err(LoadError::UnsupportedVersion(version_major));
        }
        let version_minor = read_u32(&hdr, 12);
        let arch = TraceArch::from_byte(hdr[16]);
        let first_tick = read_u64(&hdr, 17);
        let last_tick = read_u64(&hdr, 25);
        let thread_count = read_u32(&hdr, 33);
        let event_count = read_u64(&hdr, 37);
        let module_count = read_u32(&hdr, 45);
        let recorded_at = read_u64(&hdr, 49);

        // Comment: null-terminated string in bytes 57..128.
        let comment_bytes = &hdr[57..128];
        let null_pos = comment_bytes.iter().position(|&b| b == 0).unwrap_or(comment_bytes.len());
        let comment = String::from_utf8_lossy(&comment_bytes[..null_pos]).into_owned();

        Ok(TraceHeader {
            version_major,
            version_minor,
            arch,
            first_tick,
            last_tick,
            thread_count,
            file_size,
            recorded_at,
            event_count,
            module_count,
            comment,
            source_path: path,
        })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

#[inline]
fn read_u64(buf: &[u8], off: usize) -> u64 {
    let bytes: [u8; 8] = buf[off..off + 8].try_into().unwrap_or([0; 8]);
    u64::from_le_bytes(bytes)
}

#[inline]
fn read_u32(buf: &[u8], off: usize) -> u32 {
    let bytes: [u8; 4] = buf[off..off + 4].try_into().unwrap_or([0; 4]);
    u32::from_le_bytes(bytes)
}

/// Insert a synthetic snapshot when the tick has advanced far enough.
fn maybe_snapshot(
    trace: &mut TtdTrace,
    tick: u64,
    last_snap_tick: &mut u64,
    interval: u64,
    rip: u64,
) {
    if tick.saturating_sub(*last_snap_tick) >= interval {
        let mut snap = TraceSnapshot::new(tick);
        snap.set_reg("rip", rip);
        trace.push_snapshot(snap);
        *last_snap_tick = tick;
    }
}

/// Build a minimal in-memory trace file buffer (no filesystem dependency).
///
/// Creates a valid header followed by one 32-byte frame per event, then an
/// `KIND_END` frame.  Suitable for unit tests via `write_test_trace_to_file`.
#[must_use]
pub fn build_test_trace_bytes(events: &[TraceEvent]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();

    // Header
    let mut hdr = [0u8; HEADER_SIZE];
    hdr[0..8].copy_from_slice(&TRACE_MAGIC.to_le_bytes());
    hdr[8..12].copy_from_slice(&SUPPORTED_VERSION_MAJOR.to_le_bytes());
    hdr[12..16].copy_from_slice(&0u32.to_le_bytes());
    hdr[16] = 1; // x86_64
    let first = events.first().map_or(0, super::TraceEvent::tick);
    let last = events.last().map_or(0, super::TraceEvent::tick);
    hdr[17..25].copy_from_slice(&first.to_le_bytes());
    hdr[25..33].copy_from_slice(&last.to_le_bytes());
    hdr[33..37].copy_from_slice(&1u32.to_le_bytes());
    hdr[37..45].copy_from_slice(&(events.len() as u64).to_le_bytes());
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    hdr[49..57].copy_from_slice(&now.to_le_bytes());
    out.extend_from_slice(&hdr);

    // Frames
    for ev in events {
        let mut frame = [0u8; FRAME_SIZE];
        match ev {
            TraceEvent::SyscallEntry { tick, nr, args } => {
                frame[0] = KIND_SYSCALL_ENTRY;
                frame[1..9].copy_from_slice(&tick.to_le_bytes());
                frame[9..17].copy_from_slice(&nr.to_le_bytes());
                for (i, &arg) in args.iter().take(3).enumerate() {
                    let lo = (arg & 0xFFFF_FFFF) as u32;
                    frame[17 + i * 4..21 + i * 4].copy_from_slice(&lo.to_le_bytes());
                }
            }
            TraceEvent::SyscallExit { tick, retval, mem_writes } => {
                frame[0] = KIND_SYSCALL_EXIT;
                frame[1..9].copy_from_slice(&tick.to_le_bytes());
                frame[9..17].copy_from_slice(&retval.to_le_bytes());
                if let Some(wr) = mem_writes.first() {
                    frame[17..25].copy_from_slice(&wr.addr.to_le_bytes());
                    frame[25] = wr.data.len().min(8) as u8;
                }
            }
            TraceEvent::SignalDelivered { tick, signal, pc } => {
                frame[0] = KIND_SIGNAL;
                frame[1..9].copy_from_slice(&tick.to_le_bytes());
                frame[9..13].copy_from_slice(&signal.to_le_bytes());
                frame[13..21].copy_from_slice(&pc.to_le_bytes());
            }
        }
        out.extend_from_slice(&frame);
    }

    // END marker
    let mut end = [0u8; FRAME_SIZE];
    end[0] = KIND_END;
    out.extend_from_slice(&end);
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // Write bytes to a temp file and return its path (no tempfile crate).
    fn write_tmp(bytes: &[u8]) -> PathBuf {
        let mut p = std::env::temp_dir();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        p.push(format!("rustre_ttd_test_{ts}.run"));
        let mut f = std::fs::File::create(&p).expect("create tmp");
        f.write_all(bytes).expect("write tmp");
        p
    }

    fn cleanup(p: &Path) {
        let _ = std::fs::remove_file(p);
    }

    fn entry(tick: u64, nr: u64) -> TraceEvent {
        TraceEvent::SyscallEntry { tick, nr, args: [0; 6] }
    }

    fn exit_ev(tick: u64, retval: i64) -> TraceEvent {
        TraceEvent::SyscallExit { tick, retval, mem_writes: vec![] }
    }

    fn signal_ev(tick: u64, sig: i32) -> TraceEvent {
        TraceEvent::SignalDelivered { tick, signal: sig, pc: 0xDEAD_BEEF }
    }

    // ── PositionIndex tests ───────────────────────────────────────────────────

    #[test]
    fn test_position_index_empty() {
        let idx = PositionIndex::new();
        assert!(idx.is_empty());
        assert!(idx.find_before(100).is_none());
    }

    #[test]
    fn test_position_index_insert_find() {
        let mut idx = PositionIndex::new();
        idx.insert(10, 100);
        idx.insert(20, 200);
        idx.insert(30, 300);
        assert_eq!(idx.find_before(25), Some((20, 200)));
        assert_eq!(idx.find_before(30), Some((30, 300)));
        assert_eq!(idx.find_before(5), None);
    }

    #[test]
    fn test_position_index_len() {
        let mut idx = PositionIndex::new();
        idx.insert(1, 10);
        idx.insert(2, 20);
        assert_eq!(idx.len(), 2);
    }

    #[test]
    fn test_position_index_update() {
        let mut idx = PositionIndex::new();
        idx.insert(5, 50);
        idx.insert(5, 99);
        assert_eq!(idx.find_before(5), Some((5, 99)));
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn test_position_index_entries_sorted() {
        let mut idx = PositionIndex::new();
        idx.insert(30, 3);
        idx.insert(10, 1);
        idx.insert(20, 2);
        let e = idx.entries();
        assert_eq!(e[0].0, 10);
        assert_eq!(e[1].0, 20);
        assert_eq!(e[2].0, 30);
    }

    // ── TraceArch tests ───────────────────────────────────────────────────────

    #[test]
    fn test_arch_from_byte_known() {
        assert_eq!(TraceArch::from_byte(1), TraceArch::X86_64);
        assert_eq!(TraceArch::from_byte(2), TraceArch::Arm64);
        assert_eq!(TraceArch::from_byte(3), TraceArch::X86);
        assert_eq!(TraceArch::from_byte(4), TraceArch::Arm32);
    }

    #[test]
    fn test_arch_from_byte_unknown() {
        assert!(matches!(TraceArch::from_byte(99), TraceArch::Unknown(99)));
    }

    #[test]
    fn test_arch_display() {
        assert_eq!(TraceArch::X86_64.to_string(), "x86_64");
        assert_eq!(TraceArch::Unknown(0x55).to_string(), "unknown(0x55)");
    }

    // ── build_test_trace_bytes ────────────────────────────────────────────────

    #[test]
    fn test_trace_bytes_empty_size() {
        let b = build_test_trace_bytes(&[]);
        assert_eq!(b.len(), HEADER_SIZE + FRAME_SIZE);
    }

    #[test]
    fn test_trace_bytes_magic() {
        let b = build_test_trace_bytes(&[]);
        let magic = u64::from_le_bytes(b[0..8].try_into().unwrap());
        assert_eq!(magic, TRACE_MAGIC);
    }

    #[test]
    fn test_trace_bytes_version() {
        let b = build_test_trace_bytes(&[]);
        let maj = u32::from_le_bytes(b[8..12].try_into().unwrap());
        assert_eq!(maj, SUPPORTED_VERSION_MAJOR);
    }

    // ── header-only parse ─────────────────────────────────────────────────────

    #[test]
    fn test_parse_header_from_file() {
        let bytes = build_test_trace_bytes(&[entry(1, 0)]);
        let p = write_tmp(&bytes);
        let loader = TtdTraceLoader::with_defaults();
        let hdr = loader.parse_header(&p).unwrap();
        cleanup(&p);
        assert_eq!(hdr.version_major, SUPPORTED_VERSION_MAJOR);
        assert!(hdr.is_supported());
    }

    #[test]
    fn test_parse_header_bad_magic() {
        let mut bytes = build_test_trace_bytes(&[]);
        bytes[0] = 0xDE;
        let p = write_tmp(&bytes);
        let loader = TtdTraceLoader::with_defaults();
        assert!(matches!(loader.parse_header(&p), Err(LoadError::BadMagic { .. })));
        cleanup(&p);
    }

    #[test]
    fn test_parse_header_bad_version() {
        let mut bytes = build_test_trace_bytes(&[]);
        bytes[8..12].copy_from_slice(&99u32.to_le_bytes());
        let p = write_tmp(&bytes);
        let loader = TtdTraceLoader::with_defaults();
        assert!(matches!(
            loader.parse_header(&p),
            Err(LoadError::UnsupportedVersion(99))
        ));
        cleanup(&p);
    }

    #[test]
    fn test_parse_header_not_a_file() {
        let loader = TtdTraceLoader::with_defaults();
        assert!(matches!(
            loader.parse_header("/no/such/path.run"),
            Err(LoadError::NotAFile(_))
        ));
    }

    // ── full load ─────────────────────────────────────────────────────────────

    #[test]
    fn test_load_empty_trace() {
        let bytes = build_test_trace_bytes(&[]);
        let p = write_tmp(&bytes);
        let loader = TtdTraceLoader::with_defaults();
        let result = loader.load_trace(&p).unwrap();
        cleanup(&p);
        assert_eq!(result.trace.len(), 0);
    }

    #[test]
    fn test_load_syscall_entry_exit() {
        let events = vec![entry(1, 60), exit_ev(2, 0)];
        let bytes = build_test_trace_bytes(&events);
        let p = write_tmp(&bytes);
        let loader = TtdTraceLoader::with_defaults();
        let result = loader.load_trace(&p).unwrap();
        cleanup(&p);
        assert_eq!(result.trace.len(), 2);
    }

    #[test]
    fn test_load_signal_event() {
        let events = vec![signal_ev(5, 11)];
        let bytes = build_test_trace_bytes(&events);
        let p = write_tmp(&bytes);
        let loader = TtdTraceLoader::with_defaults();
        let result = loader.load_trace(&p).unwrap();
        cleanup(&p);
        assert_eq!(result.trace.len(), 1);
        assert!(matches!(result.trace.events[0], TraceEvent::SignalDelivered { .. }));
    }

    #[test]
    fn test_load_builds_index() {
        let events: Vec<TraceEvent> = (0u64..10).map(|i| entry(i, 1)).collect();
        let bytes = build_test_trace_bytes(&events);
        let p = write_tmp(&bytes);
        let loader = TtdTraceLoader::with_defaults();
        let result = loader.load_trace(&p).unwrap();
        cleanup(&p);
        assert!(!result.index.is_empty());
    }

    #[test]
    fn test_load_no_index_when_disabled() {
        let events = vec![entry(1, 1), exit_ev(2, 0)];
        let bytes = build_test_trace_bytes(&events);
        let p = write_tmp(&bytes);
        let opts = LoadOptions { build_index: false, ..Default::default() };
        let loader = TtdTraceLoader::new(opts);
        let result = loader.load_trace(&p).unwrap();
        cleanup(&p);
        assert!(result.index.is_empty());
    }

    #[test]
    fn test_load_generates_snapshots() {
        let events: Vec<TraceEvent> = (0u64..512).map(|i| entry(i, 1)).collect();
        let bytes = build_test_trace_bytes(&events);
        let p = write_tmp(&bytes);
        let opts = LoadOptions { snapshot_interval: 100, ..Default::default() };
        let loader = TtdTraceLoader::new(opts);
        let result = loader.load_trace(&p).unwrap();
        cleanup(&p);
        assert!(!result.trace.snapshots.is_empty());
    }

    #[test]
    fn test_load_max_events() {
        let events: Vec<TraceEvent> = (0u64..20).map(|i| entry(i, 1)).collect();
        let bytes = build_test_trace_bytes(&events);
        let p = write_tmp(&bytes);
        let opts = LoadOptions { max_events: 5, build_index: false, ..Default::default() };
        let loader = TtdTraceLoader::new(opts);
        let result = loader.load_trace(&p).unwrap();
        cleanup(&p);
        assert!(result.trace.len() <= 5);
    }

    #[test]
    fn test_frames_parsed_count() {
        let events = vec![entry(1, 1), exit_ev(2, 0), signal_ev(3, 9)];
        let bytes = build_test_trace_bytes(&events);
        let p = write_tmp(&bytes);
        let loader = TtdTraceLoader::with_defaults();
        let result = loader.load_trace(&p).unwrap();
        cleanup(&p);
        // 3 event frames + 1 END frame = 4 total parsed
        assert!(result.frames_parsed >= 3);
    }

    #[test]
    fn test_header_summary_contains_arch() {
        let hdr = TraceHeader {
            version_major: 2,
            version_minor: 0,
            arch: TraceArch::X86_64,
            first_tick: 0,
            last_tick: 999,
            thread_count: 4,
            file_size: 8192,
            recorded_at: 0,
            event_count: 100,
            module_count: 3,
            comment: String::new(),
            source_path: PathBuf::from("/tmp/test.run"),
        };
        let s = hdr.summary();
        assert!(s.contains("x86_64"));
        assert!(s.contains("999"));
    }

    #[test]
    fn test_read_helpers() {
        let mut buf = [0u8; 16];
        let v64: u64 = 0x0102_0304_0506_0708;
        buf[4..12].copy_from_slice(&v64.to_le_bytes());
        assert_eq!(read_u64(&buf, 4), v64);

        let v32: u32 = 0xDEAD_BEEF;
        buf[0..4].copy_from_slice(&v32.to_le_bytes());
        assert_eq!(read_u32(&buf, 0), v32);
    }
}
