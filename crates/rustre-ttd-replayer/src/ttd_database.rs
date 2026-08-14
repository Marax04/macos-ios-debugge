//! TTD database reader — parse `.run` files (TTD binary format), index positions,
//! thread records, module load/unload events, and call-stack snapshots.
//!
//! The Windows Time Travel Debugging (TTD) `.run` file uses a proprietary binary
//! format.  This module implements a clean-room parser that covers the known
//! on-disk structures: file header, chunk table, thread records, module events,
//! and position records sufficient to drive the replayer.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

// ─── constants ────────────────────────────────────────────────────────────────

/// Magic bytes at offset 0 in every valid TTD `.run` file.
pub const TTD_FILE_MAGIC: [u8; 8] = [0x54, 0x54, 0x44, 0x4C, 0x6F, 0x67, 0x21, 0x00];

/// TTD format version this parser understands.
pub const TTD_FORMAT_VERSION: u16 = 2;

/// Maximum number of threads we will parse from a single run file.
pub const MAX_THREADS: usize = 4096;

/// Maximum number of module records per run file.
pub const MAX_MODULES: usize = 65536;

/// Chunk type: thread activity record.
pub const CHUNK_THREAD: u16 = 0x0001;
/// Chunk type: module load event.
pub const CHUNK_MODULE_LOAD: u16 = 0x0002;
/// Chunk type: module unload event.
pub const CHUNK_MODULE_UNLOAD: u16 = 0x0003;
/// Chunk type: call stack snapshot.
pub const CHUNK_CALL_STACK: u16 = 0x0010;
/// Chunk type: position index entry.
pub const CHUNK_POSITION_INDEX: u16 = 0x0020;
/// Chunk type: memory write record.
pub const CHUNK_MEM_WRITE: u16 = 0x0030;
/// Chunk type: end-of-file sentinel.
pub const CHUNK_EOF: u16 = 0xFFFF;

// ─── TtdError ─────────────────────────────────────────────────────────────────

/// Errors produced by the TTD database reader.
#[derive(Debug)]
pub enum TtdError {
    /// File could not be opened or read.
    Io(io::Error),
    /// Magic bytes do not match TTD format.
    BadMagic([u8; 8]),
    /// Format version is unsupported.
    UnsupportedVersion(u16),
    /// A chunk header is malformed.
    MalformedChunk { offset: u64, detail: String },
    /// A string record is malformed.
    BadString(String),
    /// Record is truncated unexpectedly.
    Truncated { expected: usize, got: usize },
    /// Internal parser logic error.
    Internal(String),
}

impl fmt::Display for TtdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::BadMagic(m) => write!(f, "bad magic: {m:02x?}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported TTD version {v}"),
            Self::MalformedChunk { offset, detail } => {
                write!(f, "malformed chunk at offset {offset:#x}: {detail}")
            }
            Self::BadString(s) => write!(f, "bad string record: {s}"),
            Self::Truncated { expected, got } => {
                write!(f, "truncated record: expected {expected} bytes, got {got}")
            }
            Self::Internal(s) => write!(f, "internal error: {s}"),
        }
    }
}

impl std::error::Error for TtdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for TtdError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

// ─── TTDPosition ──────────────────────────────────────────────────────────────

/// A TTD execution position: a `(sequence, step)` pair that identifies a unique
/// point in the recorded execution stream.
///
/// Sequence numbers correspond to major checkpoints (e.g., after each system
/// call or thread switch), and steps track fine-grained instruction counts
/// within a sequence.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TtdPosition {
    /// Sequence number (monotonically increasing, never wraps in a single trace).
    pub sequence: u64,
    /// Step within the sequence (instruction count since last checkpoint).
    pub step: u32,
}

impl TtdPosition {
    /// The position at the very beginning of a trace.
    pub const ZERO: Self = Self { sequence: 0, step: 0 };

    /// The sentinel "invalid" position.
    pub const INVALID: Self = Self { sequence: u64::MAX, step: u32::MAX };

    /// Construct a new position.
    #[inline]
    #[must_use] 
    pub const fn new(sequence: u64, step: u32) -> Self {
        Self { sequence, step }
    }

    /// True if this position is valid (not the sentinel).
    #[inline]
    #[must_use] 
    pub fn is_valid(self) -> bool {
        self != Self::INVALID
    }

    /// Increment the step by one, saturating at `u32::MAX`.
    #[inline]
    #[must_use] 
    pub const fn next_step(self) -> Self {
        Self { sequence: self.sequence, step: self.step.saturating_add(1) }
    }

    /// Return the position at the start of the next sequence.
    #[inline]
    #[must_use] 
    pub const fn next_sequence(self) -> Self {
        Self { sequence: self.sequence.saturating_add(1), step: 0 }
    }

    /// Compute the absolute distance in steps between two positions.
    /// Positions in different sequences cannot be compared this way; this
    /// returns `None` if they are in different sequences.
    #[must_use] 
    pub const fn step_distance(self, other: Self) -> Option<u32> {
        if self.sequence != other.sequence {
            return None;
        }
        Some(self.step.abs_diff(other.step))
    }

    /// Serialize to a 12-byte little-endian array `[u64_seq | u32_step]`.
    #[must_use] 
    pub fn to_bytes(self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[..8].copy_from_slice(&self.sequence.to_le_bytes());
        out[8..12].copy_from_slice(&self.step.to_le_bytes());
        out
    }

    /// Deserialize from a 12-byte little-endian array.
    #[must_use] 
    pub fn from_bytes(b: &[u8; 12]) -> Self {
        let seq = u64::from_le_bytes(b[..8].try_into().unwrap());
        let step = u32::from_le_bytes(b[8..12].try_into().unwrap());
        Self { sequence: seq, step }
    }
}

impl fmt::Display for TtdPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.sequence, self.step)
    }
}

// ─── TtdFileHeader ────────────────────────────────────────────────────────────

/// On-disk layout of the 64-byte TTD file header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtdFileHeader {
    /// Magic bytes (must equal [`TTD_FILE_MAGIC`]).
    pub magic: [u8; 8],
    /// Format version.
    pub version: u16,
    /// Flags word.
    pub flags: u16,
    /// Number of threads recorded in this trace.
    pub thread_count: u32,
    /// File offset of the first chunk.
    pub first_chunk_offset: u64,
    /// Total number of chunks.
    pub chunk_count: u64,
    /// Position of the trace start.
    pub trace_start: TtdPosition,
    /// Position of the trace end.
    pub trace_end: TtdPosition,
    /// Reserved (padding to 64 bytes).
    pub reserved: [u8; 8],
}

impl TtdFileHeader {
    /// Parse from a 64-byte buffer.
    pub fn parse(buf: &[u8; 64]) -> Result<Self, TtdError> {
        let magic: [u8; 8] = buf[..8].try_into().unwrap();
        if magic != TTD_FILE_MAGIC {
            return Err(TtdError::BadMagic(magic));
        }
        let version = u16::from_le_bytes([buf[8], buf[9]]);
        if version > TTD_FORMAT_VERSION {
            return Err(TtdError::UnsupportedVersion(version));
        }
        let flags = u16::from_le_bytes([buf[10], buf[11]]);
        let thread_count = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        let first_chunk_offset = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        let chunk_count = u64::from_le_bytes(buf[24..32].try_into().unwrap());
        let seq_start = u64::from_le_bytes(buf[32..40].try_into().unwrap());
        let step_start = u32::from_le_bytes(buf[40..44].try_into().unwrap());
        let seq_end = u64::from_le_bytes(buf[44..52].try_into().unwrap());
        let step_end = u32::from_le_bytes(buf[52..56].try_into().unwrap());
        let reserved: [u8; 8] = buf[56..64].try_into().unwrap();
        Ok(Self {
            magic,
            version,
            flags,
            thread_count,
            first_chunk_offset,
            chunk_count,
            trace_start: TtdPosition::new(seq_start, step_start),
            trace_end: TtdPosition::new(seq_end, step_end),
            reserved,
        })
    }

    /// True if the trace was recorded with full kernel mode tracking.
    #[must_use] 
    pub const fn is_kernel_mode(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    /// True if the file was closed cleanly (no crash during recording).
    #[must_use] 
    pub const fn is_clean(&self) -> bool {
        self.flags & 0x0002 != 0
    }
}

// ─── ChunkHeader ─────────────────────────────────────────────────────────────

/// Fixed 16-byte chunk header preceding every chunk in the stream.
#[derive(Debug, Clone, Copy)]
pub struct ChunkHeader {
    /// Chunk type tag.
    pub chunk_type: u16,
    /// Reserved/alignment.
    pub reserved: u16,
    /// Length of the payload that follows this header (bytes).
    pub payload_length: u32,
    /// Position at which this chunk was recorded.
    pub position: TtdPosition,
}

impl ChunkHeader {
    #[must_use] 
    pub fn parse(buf: &[u8; 16]) -> Self {
        let chunk_type = u16::from_le_bytes([buf[0], buf[1]]);
        let reserved = u16::from_le_bytes([buf[2], buf[3]]);
        let payload_length = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let seq = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        // Encode position as seq with step in high 16 bits (simplified model)
        let position = TtdPosition::new(seq & 0xFFFF_FFFF_FFFF, (seq >> 48) as u32);
        Self { chunk_type, reserved, payload_length, position }
    }
}

// ─── ThreadRecord ─────────────────────────────────────────────────────────────

/// A thread lifecycle record parsed from a `CHUNK_THREAD` chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadRecord {
    /// OS thread ID.
    pub thread_id: u32,
    /// Process ID owning this thread.
    pub process_id: u32,
    /// Position when this thread was created (or trace start for pre-existing threads).
    pub start_position: TtdPosition,
    /// Position when this thread exited, or `TtdPosition::INVALID` if still running.
    pub end_position: TtdPosition,
    /// Initial value of the instruction pointer at thread start.
    pub initial_ip: u64,
    /// Initial value of the stack pointer at thread start.
    pub initial_sp: u64,
    /// User-visible thread name (may be empty).
    pub name: String,
}

impl ThreadRecord {
    pub fn parse(payload: &[u8]) -> Result<Self, TtdError> {
        if payload.len() < 48 {
            return Err(TtdError::Truncated { expected: 48, got: payload.len() });
        }
        let thread_id = u32::from_le_bytes(payload[0..4].try_into().unwrap());
        let process_id = u32::from_le_bytes(payload[4..8].try_into().unwrap());
        let start_seq = u64::from_le_bytes(payload[8..16].try_into().unwrap());
        let start_step = u32::from_le_bytes(payload[16..20].try_into().unwrap());
        let end_seq = u64::from_le_bytes(payload[20..28].try_into().unwrap());
        let end_step = u32::from_le_bytes(payload[28..32].try_into().unwrap());
        let initial_ip = u64::from_le_bytes(payload[32..40].try_into().unwrap());
        let initial_sp = u64::from_le_bytes(payload[40..48].try_into().unwrap());
        let name = if payload.len() > 48 {
            parse_length_prefixed_utf8(&payload[48..])
                .unwrap_or_default()
        } else {
            String::new()
        };
        Ok(Self {
            thread_id,
            process_id,
            start_position: TtdPosition::new(start_seq, start_step),
            end_position: TtdPosition::new(end_seq, end_step),
            initial_ip,
            initial_sp,
            name,
        })
    }

    /// True if this thread was active at `pos`.
    #[must_use] 
    pub fn active_at(&self, pos: TtdPosition) -> bool {
        pos >= self.start_position
            && (!self.end_position.is_valid() || pos <= self.end_position)
    }
}

// ─── ModuleEvent ──────────────────────────────────────────────────────────────

/// A module load or unload event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleEvent {
    /// True = load, false = unload.
    pub is_load: bool,
    /// Position in the trace when this event occurred.
    pub position: TtdPosition,
    /// Base virtual address of the module image.
    pub base_address: u64,
    /// Size of the module image in bytes.
    pub image_size: u64,
    /// Full path to the module on disk (may be relative/stub for in-memory modules).
    pub path: PathBuf,
    /// Checksum from the PE header.
    pub checksum: u32,
    /// `TimeDateStamp` from the PE header.
    pub timestamp: u32,
}

impl ModuleEvent {
    pub fn parse(is_load: bool, payload: &[u8]) -> Result<Self, TtdError> {
        if payload.len() < 40 {
            return Err(TtdError::Truncated { expected: 40, got: payload.len() });
        }
        let seq = u64::from_le_bytes(payload[0..8].try_into().unwrap());
        let step = u32::from_le_bytes(payload[8..12].try_into().unwrap());
        let base_address = u64::from_le_bytes(payload[12..20].try_into().unwrap());
        let image_size = u64::from_le_bytes(payload[20..28].try_into().unwrap());
        let checksum = u32::from_le_bytes(payload[28..32].try_into().unwrap());
        let timestamp = u32::from_le_bytes(payload[32..36].try_into().unwrap());
        let _reserved = u32::from_le_bytes(payload[36..40].try_into().unwrap());
        let path_str = if payload.len() > 40 {
            parse_length_prefixed_utf8(&payload[40..]).unwrap_or_default()
        } else {
            String::new()
        };
        Ok(Self {
            is_load,
            position: TtdPosition::new(seq, step),
            base_address,
            image_size,
            path: PathBuf::from(path_str),
            checksum,
            timestamp,
        })
    }

    /// Module name (file stem without directory).
    #[must_use] 
    pub fn module_name(&self) -> &str {
        self.path.file_name().and_then(|s| s.to_str()).unwrap_or("<unknown>")
    }

    /// Address range `[base, base+size)`.
    #[must_use] 
    pub const fn address_range(&self) -> (u64, u64) {
        (self.base_address, self.base_address.saturating_add(self.image_size))
    }

    /// True if `addr` falls within this module's image.
    #[must_use] 
    pub const fn contains_addr(&self, addr: u64) -> bool {
        let (lo, hi) = self.address_range();
        addr >= lo && addr < hi
    }
}

// ─── CallFrame ────────────────────────────────────────────────────────────────

/// A single frame in a call stack snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallFrame {
    /// Return address (instruction pointer of the caller).
    pub return_address: u64,
    /// Frame pointer (base pointer register) at time of snapshot.
    pub frame_pointer: u64,
    /// Stack pointer at this frame.
    pub stack_pointer: u64,
    /// Inlined module base (0 if not resolved).
    pub module_base: u64,
    /// Offset from module base to the return address.
    pub rva: u32,
}

impl CallFrame {
    #[must_use] 
    pub fn parse(buf: &[u8; 28]) -> Self {
        let return_address = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let frame_pointer = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let stack_pointer = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        let module_base = 0u64;
        let rva = u32::from_le_bytes(buf[24..28].try_into().unwrap());
        Self { return_address, frame_pointer, stack_pointer, module_base, rva }
    }
}

impl fmt::Display for CallFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rip={:#018x} rbp={:#018x} rsp={:#018x}",
            self.return_address, self.frame_pointer, self.stack_pointer
        )
    }
}

// ─── CallStackSnapshot ────────────────────────────────────────────────────────

/// A call stack snapshot captured at a specific position.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallStackSnapshot {
    /// Position at which this snapshot was taken.
    pub position: TtdPosition,
    /// Thread ID whose stack this is.
    pub thread_id: u32,
    /// Frames, ordered from innermost (top of stack) to outermost.
    pub frames: Vec<CallFrame>,
}

impl CallStackSnapshot {
    pub fn parse(payload: &[u8]) -> Result<Self, TtdError> {
        if payload.len() < 16 {
            return Err(TtdError::Truncated { expected: 16, got: payload.len() });
        }
        let seq = u64::from_le_bytes(payload[0..8].try_into().unwrap());
        let step = u32::from_le_bytes(payload[8..12].try_into().unwrap());
        let thread_id = u32::from_le_bytes(payload[12..16].try_into().unwrap());
        let mut frames = Vec::new();
        let mut offset = 16usize;
        while offset + 28 <= payload.len() {
            let buf: [u8; 28] = payload[offset..offset + 28].try_into().unwrap();
            frames.push(CallFrame::parse(&buf));
            offset += 28;
        }
        Ok(Self {
            position: TtdPosition::new(seq, step),
            thread_id,
            frames,
        })
    }

    /// Number of frames in this snapshot.
    #[must_use] 
    pub const fn depth(&self) -> usize {
        self.frames.len()
    }

    /// Innermost (currently executing) frame, if any.
    #[must_use] 
    pub fn top_frame(&self) -> Option<&CallFrame> {
        self.frames.first()
    }

    /// Format as a simple backtrace string.
    #[must_use] 
    pub fn backtrace_string(&self) -> String {
        let mut out = format!("Thread {:#x} @ {}:\n", self.thread_id, self.position);
        for (i, frame) in self.frames.iter().enumerate() {
            out.push_str(&format!("  #{i:02} {frame}\n"));
        }
        out
    }
}

// ─── PositionIndexEntry ────────────────────────────────────────────────────────

/// An entry in the position index: maps a position to a file offset.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PositionIndexEntry {
    /// The TTD position.
    pub position: TtdPosition,
    /// Byte offset in the `.run` file for the data at this position.
    pub file_offset: u64,
}

// ─── TtdDatabase ──────────────────────────────────────────────────────────────

/// In-memory representation of a parsed TTD `.run` file.
///
/// After calling [`TtdDatabase::open`] or [`TtdDatabase::parse`], all thread
/// records, module events, call-stack snapshots, and the position index are
/// available for random access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtdDatabase {
    /// Path to the source file.
    pub path: PathBuf,
    /// Parsed file header.
    pub header: TtdFileHeader,
    /// All thread lifecycle records, keyed by thread ID.
    pub threads: BTreeMap<u32, ThreadRecord>,
    /// Module load/unload events in chronological order.
    pub module_events: Vec<ModuleEvent>,
    /// Call-stack snapshots ordered by position.
    pub call_stacks: Vec<CallStackSnapshot>,
    /// Position index for O(log n) seeks.
    pub position_index: Vec<PositionIndexEntry>,
    /// Count of bytes parsed from the file.
    pub bytes_parsed: u64,
}

impl TtdDatabase {
    /// Parse a TTD database from a byte buffer (e.g., a memory-mapped file).
    pub fn parse(path: impl Into<PathBuf>, data: &[u8]) -> Result<Self, TtdError> {
        if data.len() < 64 {
            return Err(TtdError::Truncated { expected: 64, got: data.len() });
        }
        let header_buf: [u8; 64] = data[..64].try_into().unwrap();
        let header = TtdFileHeader::parse(&header_buf)?;

        let mut db = Self {
            path: path.into(),
            header,
            threads: BTreeMap::new(),
            module_events: Vec::new(),
            call_stacks: Vec::new(),
            position_index: Vec::new(),
            bytes_parsed: 0,
        };

        // first_chunk_offset must not overlap the header itself.
        if db.header.first_chunk_offset < 64 {
            return Err(TtdError::MalformedChunk {
                offset: 0,
                detail: format!(
                    "first_chunk_offset {} is inside the file header (min 64)",
                    db.header.first_chunk_offset
                ),
            });
        }
        let mut cursor = Cursor::new(data);
        cursor.seek(SeekFrom::Start(db.header.first_chunk_offset))?;

        loop {
            let _offset = cursor.stream_position()?;
            let mut hdr_buf = [0u8; 16];
            match cursor.read_exact(&mut hdr_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(TtdError::Io(e)),
            }
            let hdr = ChunkHeader::parse(&hdr_buf);
            if hdr.chunk_type == CHUNK_EOF {
                break;
            }
            // Guard against malicious payload_length values that would cause
            // a multi-gigabyte allocation or OOM panic.
            const MAX_PAYLOAD: u32 = 64 * 1024 * 1024; // 64 MiB per chunk
            if hdr.payload_length > MAX_PAYLOAD {
                return Err(TtdError::MalformedChunk {
                    offset: _offset,
                    detail: format!(
                        "payload_length {} exceeds maximum allowed {}",
                        hdr.payload_length, MAX_PAYLOAD
                    ),
                });
            }
            let payload_len = hdr.payload_length as usize;
            let mut payload = vec![0u8; payload_len];
            cursor.read_exact(&mut payload).map_err(|e| {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    TtdError::Truncated { expected: payload_len, got: 0 }
                } else {
                    TtdError::Io(e)
                }
            })?;

            match hdr.chunk_type {
                CHUNK_THREAD => {
                    if db.threads.len() < MAX_THREADS
                        && let Ok(rec) = ThreadRecord::parse(&payload) { db.threads.insert(rec.thread_id, rec); }
                }
                CHUNK_MODULE_LOAD => {
                    if db.module_events.len() < MAX_MODULES
                        && let Ok(ev) = ModuleEvent::parse(true, &payload) {
                            db.module_events.push(ev);
                        }
                }
                CHUNK_MODULE_UNLOAD => {
                    if db.module_events.len() < MAX_MODULES
                        && let Ok(ev) = ModuleEvent::parse(false, &payload) {
                            db.module_events.push(ev);
                        }
                }
                CHUNK_CALL_STACK => {
                    const MAX_CALL_STACKS: usize = 1_000_000;
                    if db.call_stacks.len() < MAX_CALL_STACKS
                        && let Ok(snap) = CallStackSnapshot::parse(&payload) {
                            db.call_stacks.push(snap);
                        }
                }
                CHUNK_POSITION_INDEX => {
                    // Each entry is 20 bytes: 8 seq + 4 step + 8 file_offset
                    let mut off = 0usize;
                    while off + 20 <= payload.len() {
                        let seq = u64::from_le_bytes(payload[off..off + 8].try_into().unwrap());
                        let step = u32::from_le_bytes(payload[off + 8..off + 12].try_into().unwrap());
                        let file_off = u64::from_le_bytes(payload[off + 12..off + 20].try_into().unwrap());
                        db.position_index.push(PositionIndexEntry {
                            position: TtdPosition::new(seq, step),
                            file_offset: file_off,
                        });
                        off += 20;
                    }
                }
                _ => {} // unknown chunk: skip
            }

            db.bytes_parsed = cursor.stream_position().unwrap_or(0);
        }

        // Sort structures by position for binary-search access.
        db.call_stacks.sort_by_key(|s| s.position);
        db.position_index.sort_by_key(|e| e.position);
        db.module_events.sort_by_key(|e| e.position);

        Ok(db)
    }

    // ── Query API ──────────────────────────────────────────────────────────────

    /// Find the call-stack snapshot closest to but not exceeding `pos`.
    #[must_use] 
    pub fn nearest_call_stack(&self, pos: TtdPosition) -> Option<&CallStackSnapshot> {
        let idx = self.call_stacks.partition_point(|s| s.position <= pos);
        if idx == 0 { return None; }
        Some(&self.call_stacks[idx - 1])
    }

    /// Find the call-stack snapshot for a specific thread closest to `pos`.
    #[must_use] 
    pub fn nearest_thread_call_stack(
        &self,
        pos: TtdPosition,
        thread_id: u32,
    ) -> Option<&CallStackSnapshot> {
        self.call_stacks
            .iter()
            .rev()
            .find(|s| s.thread_id == thread_id && s.position <= pos)
    }

    /// Return all module load events at or before `pos`.
    #[must_use] 
    pub fn loaded_modules_at(&self, pos: TtdPosition) -> Vec<&ModuleEvent> {
        let mut loaded: BTreeMap<u64, &ModuleEvent> = BTreeMap::new();
        for ev in &self.module_events {
            if ev.position > pos {
                break;
            }
            if ev.is_load {
                loaded.insert(ev.base_address, ev);
            } else {
                loaded.remove(&ev.base_address);
            }
        }
        loaded.into_values().collect()
    }

    /// Find which module contains `addr` at trace position `pos`.
    #[must_use] 
    pub fn module_at_address(&self, addr: u64, pos: TtdPosition) -> Option<&ModuleEvent> {
        self.loaded_modules_at(pos)
            .into_iter()
            .find(|ev| ev.contains_addr(addr))
    }

    /// Find the position index entry nearest to (but not after) `pos`.
    #[must_use] 
    pub fn seek_position(&self, pos: TtdPosition) -> Option<PositionIndexEntry> {
        let idx = self.position_index.partition_point(|e| e.position <= pos);
        if idx == 0 { return None; }
        Some(self.position_index[idx - 1])
    }

    /// List all threads active at position `pos`.
    #[must_use] 
    pub fn active_threads_at(&self, pos: TtdPosition) -> Vec<&ThreadRecord> {
        self.threads.values().filter(|t| t.active_at(pos)).collect()
    }

    /// Return the thread record for `thread_id`, if known.
    #[must_use] 
    pub fn thread(&self, thread_id: u32) -> Option<&ThreadRecord> {
        self.threads.get(&thread_id)
    }

    /// Summary of the database for display.
    #[must_use] 
    pub fn summary(&self) -> TtdDatabaseSummary {
        TtdDatabaseSummary {
            path: self.path.clone(),
            thread_count: self.threads.len(),
            module_event_count: self.module_events.len(),
            call_stack_count: self.call_stacks.len(),
            position_index_entries: self.position_index.len(),
            trace_start: self.header.trace_start,
            trace_end: self.header.trace_end,
            format_version: self.header.version,
            bytes_parsed: self.bytes_parsed,
        }
    }
}

// ─── TtdDatabaseSummary ───────────────────────────────────────────────────────

/// Human-readable summary of a parsed TTD database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtdDatabaseSummary {
    pub path: PathBuf,
    pub thread_count: usize,
    pub module_event_count: usize,
    pub call_stack_count: usize,
    pub position_index_entries: usize,
    pub trace_start: TtdPosition,
    pub trace_end: TtdPosition,
    pub format_version: u16,
    pub bytes_parsed: u64,
}

impl fmt::Display for TtdDatabaseSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "TTD Database: {}", self.path.display())?;
        writeln!(f, "  Format version : {}", self.format_version)?;
        writeln!(f, "  Trace range    : {} → {}", self.trace_start, self.trace_end)?;
        writeln!(f, "  Threads        : {}", self.thread_count)?;
        writeln!(f, "  Module events  : {}", self.module_event_count)?;
        writeln!(f, "  Call stacks    : {}", self.call_stack_count)?;
        writeln!(f, "  Index entries  : {}", self.position_index_entries)?;
        write!(f, "  Bytes parsed   : {}", self.bytes_parsed)
    }
}

// ─── helpers ──────────────────────────────────────────────────────────────────

/// Parse a length-prefixed UTF-8 string: first 2 bytes = length, then UTF-8 bytes.
fn parse_length_prefixed_utf8(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let len = u16::from_le_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + len {
        return None;
    }
    String::from_utf8(data[2..2 + len].to_vec()).ok()
}

// ─── TtdDatabaseBuilder ───────────────────────────────────────────────────────

/// Builder for constructing a synthetic TTD database (for tests and
/// round-trip validation).
#[derive(Debug, Default)]
pub struct TtdDatabaseBuilder {
    threads: BTreeMap<u32, ThreadRecord>,
    module_events: Vec<ModuleEvent>,
    call_stacks: Vec<CallStackSnapshot>,
    position_index: Vec<PositionIndexEntry>,
    trace_start: TtdPosition,
    trace_end: TtdPosition,
}

impl TtdDatabaseBuilder {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub const fn with_trace_range(mut self, start: TtdPosition, end: TtdPosition) -> Self {
        self.trace_start = start;
        self.trace_end = end;
        self
    }

    #[must_use] 
    pub fn add_thread(mut self, rec: ThreadRecord) -> Self {
        self.threads.insert(rec.thread_id, rec);
        self
    }

    #[must_use] 
    pub fn add_module_event(mut self, ev: ModuleEvent) -> Self {
        self.module_events.push(ev);
        self
    }

    #[must_use] 
    pub fn add_call_stack(mut self, snap: CallStackSnapshot) -> Self {
        self.call_stacks.push(snap);
        self
    }

    #[must_use] 
    pub fn add_index_entry(mut self, entry: PositionIndexEntry) -> Self {
        self.position_index.push(entry);
        self
    }

    #[must_use] 
    pub fn build(mut self) -> TtdDatabase {
        self.call_stacks.sort_by_key(|s| s.position);
        self.position_index.sort_by_key(|e| e.position);
        self.module_events.sort_by_key(|e| e.position);
        let header = TtdFileHeader {
            magic: TTD_FILE_MAGIC,
            version: TTD_FORMAT_VERSION,
            flags: 0x0002,
            thread_count: self.threads.len() as u32,
            first_chunk_offset: 64,
            chunk_count: 0,
            trace_start: self.trace_start,
            trace_end: self.trace_end,
            reserved: [0u8; 8],
        };
        TtdDatabase {
            path: PathBuf::from("<synthetic>"),
            header,
            threads: self.threads,
            module_events: self.module_events,
            call_stacks: self.call_stacks,
            position_index: self.position_index,
            bytes_parsed: 0,
        }
    }
}

// ─── ModuleMap ────────────────────────────────────────────────────────────────

/// A snapshot of the loaded modules at a specific position,
/// supporting address-to-module lookups.
#[derive(Debug, Clone)]
pub struct ModuleMap<'db> {
    /// Modules loaded at the query position, sorted by base address.
    pub modules: Vec<&'db ModuleEvent>,
}

impl<'db> ModuleMap<'db> {
    /// Build a module map from a database at position `pos`.
    #[must_use] 
    pub fn build(db: &'db TtdDatabase, pos: TtdPosition) -> Self {
        let mut modules = db.loaded_modules_at(pos);
        modules.sort_by_key(|m| m.base_address);
        Self { modules }
    }

    /// Resolve `addr` to the owning module, if any.
    #[must_use] 
    pub fn resolve(&self, addr: u64) -> Option<&'db ModuleEvent> {
        // Binary search by base address.
        let idx = self.modules.partition_point(|m| m.base_address <= addr);
        if idx == 0 {
            return None;
        }
        let candidate = self.modules[idx - 1];
        if candidate.contains_addr(addr) { Some(candidate) } else { None }
    }

    /// Number of loaded modules.
    #[must_use] 
    pub const fn count(&self) -> usize {
        self.modules.len()
    }
}

// ─── unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttd_position_ordering() {
        let a = TtdPosition::new(1, 0);
        let b = TtdPosition::new(1, 5);
        let c = TtdPosition::new(2, 0);
        assert!(a < b);
        assert!(b < c);
        assert!(a < c);
    }

    #[test]
    fn ttd_position_round_trip() {
        let p = TtdPosition::new(0xDEAD_BEEF_CAFE, 0x1234_5678);
        let bytes = p.to_bytes();
        let p2 = TtdPosition::from_bytes(&bytes);
        assert_eq!(p, p2);
    }

    #[test]
    fn ttd_position_step_distance() {
        let a = TtdPosition::new(5, 10);
        let b = TtdPosition::new(5, 20);
        assert_eq!(a.step_distance(b), Some(10));
        let c = TtdPosition::new(6, 0);
        assert_eq!(a.step_distance(c), None);
    }

    #[test]
    fn builder_creates_valid_db() {
        let thread = ThreadRecord {
            thread_id: 1,
            process_id: 100,
            start_position: TtdPosition::ZERO,
            end_position: TtdPosition::INVALID,
            initial_ip: 0x0001_4000_1000_1000,
            initial_sp: 0x7fff_0000,
            name: "main".to_string(),
        };
        let db = TtdDatabaseBuilder::new()
            .with_trace_range(TtdPosition::ZERO, TtdPosition::new(100, 0))
            .add_thread(thread)
            .build();
        assert_eq!(db.threads.len(), 1);
        assert!(db.thread(1).is_some());
    }

    #[test]
    fn bad_magic_error() {
        let mut buf = [0u8; 64];
        buf[0] = 0xFF; // corrupt magic
        let err = TtdFileHeader::parse(&buf);
        assert!(matches!(err, Err(TtdError::BadMagic(_))));
    }
}
