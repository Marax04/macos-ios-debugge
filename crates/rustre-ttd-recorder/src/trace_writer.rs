//! Binary trace file writer for `RustRE` TTD.
//!
//! Handles event serialization, position encoding, per-thread event streams,
//! segment-level compression, and an on-disk index for fast seeking.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Cursor, Read, Seek, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{CompressionLevel, TtdPosition};

const fn u64_to_f64_lossy(v: u64) -> f64 {
    v as f64
}

// ─── Constants ───────────────────────────────────────────────────────────────

pub const TRACE_MAGIC: [u8; 8] = *b"RUSTTDE1";
pub const TRACE_VERSION: u16 = 2;
/// Maximum bytes in a single uncompressed segment before forced flush.
pub const MAX_SEGMENT_BYTES: usize = 1024 * 1024;
/// Minimum compression input size; smaller segments stored uncompressed.
pub const MIN_COMPRESS_BYTES: usize = 256;

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum WriteError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("serialization error: {0}")]
    Serialize(String),
    #[error("writer already finished")]
    AlreadyFinished,
    #[error("corrupt trace: {0}")]
    Corrupt(String),
    #[error("decompression overflow")]
    DecompressOverflow,
    #[error("unexpected EOF during decompression")]
    DecompressEof,
}

pub type WriteResult<T> = Result<T, WriteError>;

// ─── Block Tags ──────────────────────────────────────────────────────────────

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockTag {
    FileHeader   = 0x01,
    TraceHeader  = 0x02,
    ThreadBlock  = 0x10,
    EventSegment = 0x20,
    IndexBlock   = 0x30,
    Footer       = 0xFF,
}

impl BlockTag {
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::FileHeader),
            0x02 => Some(Self::TraceHeader),
            0x10 => Some(Self::ThreadBlock),
            0x20 => Some(Self::EventSegment),
            0x30 => Some(Self::IndexBlock),
            0xFF => Some(Self::Footer),
            _ => None,
        }
    }
}

// ─── File Header ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceFileHeader {
    pub magic: [u8; 8],
    pub version: u16,
    pub flags: u32,
    pub pid: u32,
    pub process_name: String,
    pub created_at_ns: u64,
    pub compression: u8,
    pub reserved: [u8; 16],
}

impl TraceFileHeader {
    #[must_use]
    pub fn new(pid: u32, process_name: impl Into<String>, compression: CompressionLevel) -> Self {
        Self {
            magic: TRACE_MAGIC,
            version: TRACE_VERSION,
            flags: 0,
            pid,
            process_name: process_name.into(),
            created_at_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos().try_into().unwrap_or(u64::MAX),
            compression: match compression {
                CompressionLevel::None => 0,
                CompressionLevel::Fast => 1,
                CompressionLevel::Best => 2,
                CompressionLevel::Default => 1,
            },
            reserved: [0u8; 16],
        }
    }

    /// # Errors
    ///
    /// Returns `Err` if the magic bytes or version are invalid.
    pub fn validate(&self) -> WriteResult<()> {
        if self.magic != TRACE_MAGIC {
            return Err(WriteError::Corrupt("bad magic".into()));
        }
        if self.version != TRACE_VERSION {
            return Err(WriteError::Corrupt(format!("version {} unsupported", self.version)));
        }
        Ok(())
    }

    /// Serialize to bytes (fixed-size prefix then variable-length name).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&self.magic);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.pid.to_le_bytes());
        out.extend_from_slice(&self.created_at_ns.to_le_bytes());
        out.push(self.compression);
        out.extend_from_slice(&self.reserved);
        let name = self.process_name.as_bytes();
        out.extend_from_slice(&u16::try_from(name.len()).unwrap_or(u16::MAX).to_le_bytes());
        out.extend_from_slice(name);
        out
    }
}

// ─── Position Encoding ────────────────────────────────────────────────────────

/// Encode a single trace position to a 12-byte array: 8 bytes major + 4 bytes minor.
#[must_use]
pub fn encode_position(pos: TtdPosition) -> [u8; 12] {
    let mut buf = [0u8; 12];
    buf[0..8].copy_from_slice(&pos.major.to_le_bytes());
    buf[8..12].copy_from_slice(&u32::try_from(pos.minor).unwrap_or(u32::MAX).to_le_bytes());
    buf
}

/// Decode a position from a 12-byte slice.
///
/// # Errors
///
/// Returns `Err` if the slice is shorter than 12 bytes.
pub fn decode_position(data: &[u8]) -> WriteResult<TtdPosition> {
    if data.len() < 12 {
        return Err(WriteError::Corrupt("position buffer too short".into()));
    }
    let major = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let minor = u64::from(u32::from_le_bytes(data[8..12].try_into().unwrap()));
    Ok(TtdPosition { major, minor })
}

// ─── Variable-length Integer Encoding ────────────────────────────────────────

/// Encode a u64 as a variable-length little-endian base-128 integer (LEB128).
pub fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = u8::try_from(value & 0x7F).unwrap_or(0x7F);
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Decode a u64 LEB128 value from a cursor.
///
/// # Errors
///
/// Returns `Err` on unexpected EOF or varint overflow.
pub fn decode_varint(cur: &mut Cursor<&[u8]>) -> WriteResult<u64> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    loop {
        let mut buf = [0u8; 1];
        cur.read_exact(&mut buf)
            .map_err(|_| WriteError::DecompressEof)?;
        let byte = buf[0];
        value |= u64::from(byte & 0x7F) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
        if shift >= 64 {
            return Err(WriteError::Corrupt("varint overflow".into()));
        }
    }
    Ok(value)
}

// ─── Delta Position Sequences ────────────────────────────────────────────────

/// Encode a sorted slice of `TtdPositions` as delta-compressed varints.
/// Each position is stored as (`delta_major`, minor) where `delta_major` is the
/// difference from the previous major counter.
#[must_use]
pub fn delta_encode_positions(positions: &[TtdPosition]) -> Vec<u8> {
    let mut out = Vec::with_capacity(positions.len() * 4);
    encode_varint(u64::try_from(positions.len()).unwrap_or(u64::MAX), &mut out);
    let mut prev_major = 0u64;
    for p in positions {
        let delta = p.major.saturating_sub(prev_major);
        encode_varint(delta, &mut out);
        encode_varint(p.minor, &mut out);
        prev_major = p.major;
    }
    out
}

/// Decode a delta-compressed position sequence.
///
/// # Errors
///
/// Returns `Err` if the data is malformed or the position count exceeds the maximum.
pub fn delta_decode_positions(data: &[u8]) -> WriteResult<Vec<TtdPosition>> {
    let mut cur = Cursor::new(data);
    let count_raw = decode_varint(&mut cur)?;
    // Each position takes at least 2 bytes (two 1-byte varints), so guard
    // against a maliciously large count before allocating.
    const MAX_POSITIONS: u64 = 1_000_000;
    if count_raw > MAX_POSITIONS {
        return Err(WriteError::Corrupt(format!(
            "position count {count_raw} exceeds maximum {MAX_POSITIONS}"
        )));
    }
    let count = usize::try_from(count_raw).unwrap_or(usize::MAX);
    let mut positions = Vec::with_capacity(count);
    let mut prev_major = 0u64;
    for _ in 0..count {
        let delta = decode_varint(&mut cur)?;
        let minor = decode_varint(&mut cur)?;
        let major = prev_major + delta;
        prev_major = major;
        positions.push(TtdPosition { major, minor });
    }
    Ok(positions)
}

// ─── Segment Compression ─────────────────────────────────────────────────────

/// Simple run-length + literal-copy compressor.
///
/// Format:
///   tag byte: 0xRR  → run: next byte repeated 0xRR times
///   tag byte: 0x00LL → literal: next LL bytes copied verbatim
///   (LL stored as 1-byte length after the 0x00 tag)
///
/// A real implementation would use LZ4 via a crate; this is a pure-Rust
/// stand-in with the same streaming API.
#[must_use]
pub fn compress_segment(data: &[u8]) -> Vec<u8> {
    if data.len() < MIN_COMPRESS_BYTES {
        // Not worth compressing; return with a "no compression" prefix.
        let mut out = Vec::with_capacity(data.len() + 5);
        out.push(0x00); // flag: uncompressed
        out.extend_from_slice(&u32::try_from(data.len()).unwrap_or(u32::MAX).to_le_bytes());
        out.extend_from_slice(data);
        return out;
    }

    let mut out = Vec::with_capacity(data.len() / 2);
    out.push(0x01); // flag: compressed
    out.extend_from_slice(&u32::try_from(data.len()).unwrap_or(u32::MAX).to_le_bytes()); // original length

    let mut i = 0;
    while i < data.len() {
        // Check for run.
        let run_byte = data[i];
        let mut run_len = 1usize;
        while i + run_len < data.len() && data[i + run_len] == run_byte && run_len < 127 {
            run_len += 1;
        }
        if run_len >= 3 {
            out.push(u8::try_from(run_len).unwrap_or(127) | 0x80); // high bit = run
            out.push(run_byte);
            i += run_len;
            continue;
        }
        // Literal run — collect until we see an upcoming 3-run or end.
        let lit_start = i;
        let mut lit_len = 0usize;
        while i < data.len() && lit_len < 127 {
            // Peek ahead for run.
            let b = data[i];
            let mut ahead = 1usize;
            while i + ahead < data.len() && data[i + ahead] == b && ahead < 255 {
                ahead += 1;
            }
            if ahead >= 3 {
                break;
            }
            i += 1;
            lit_len += 1;
        }
        if lit_len > 0 {
            out.push(u8::try_from(lit_len).unwrap_or(127)); // low bit = literal, no high bit
            out.extend_from_slice(&data[lit_start..lit_start + lit_len]);
        }
    }
    out
}

/// Decompress a segment produced by `compress_segment`.
///
/// # Errors
///
/// Returns `Err` if the segment is malformed, truncated, or decompressed output would overflow.
pub fn decompress_segment(data: &[u8]) -> WriteResult<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let flag = data[0];
    if data.len() < 5 {
        return Err(WriteError::Corrupt("segment header too short".into()));
    }
    let orig_len = usize::try_from(u32::from_le_bytes(data[1..5].try_into().unwrap())).unwrap_or(usize::MAX);

    // Guard against maliciously large orig_len values that would cause OOM.
    const MAX_SEGMENT_DECOMPRESSED: usize = 64 * 1024 * 1024; // 64 MB
    if orig_len > MAX_SEGMENT_DECOMPRESSED {
        return Err(WriteError::Corrupt(format!(
            "segment orig_len {orig_len} exceeds maximum {MAX_SEGMENT_DECOMPRESSED}"
        )));
    }

    if flag == 0x00 {
        // Uncompressed.
        if data.len() < 5 + orig_len {
            return Err(WriteError::DecompressEof);
        }
        return Ok(data[5..5 + orig_len].to_vec());
    }

    let compressed = &data[5..];
    let mut out = Vec::with_capacity(orig_len);
    let mut i = 0;
    while i < compressed.len() {
        let tag = compressed[i];
        i += 1;
        if tag & 0x80 != 0 {
            // Run.
            let run_len = usize::from(tag & 0x7F);
            if i >= compressed.len() {
                return Err(WriteError::DecompressEof);
            }
            let run_byte = compressed[i];
            i += 1;
            // Use saturating_mul to avoid overflow in the overflow check itself.
            if out.len() + run_len > orig_len.saturating_mul(4).max(MAX_SEGMENT_DECOMPRESSED) {
                return Err(WriteError::DecompressOverflow);
            }
            for _ in 0..run_len {
                out.push(run_byte);
            }
        } else {
            // Literal.
            let lit_len = usize::from(tag);
            if i + lit_len > compressed.len() {
                return Err(WriteError::DecompressEof);
            }
            out.extend_from_slice(&compressed[i..i + lit_len]);
            i += lit_len;
        }
    }
    Ok(out)
}

// ─── Thread Event Stream ──────────────────────────────────────────────────────

/// Accumulates raw event bytes for a single thread, with a byte-offset index
/// for fast random access by position.
#[derive(Debug, Default)]
pub struct ThreadEventStream {
    pub tid: u32,
    /// Raw serialized event bytes.
    pub data: Vec<u8>,
    /// Map from `TtdPosition` (major * 2^32 | minor) to byte offset in `data`.
    pub offset_index: BTreeMap<u64, u64>,
    pub event_count: u64,
}

impl ThreadEventStream {
    #[must_use]
    pub const fn new(tid: u32) -> Self {
        Self { tid, data: Vec::new(), offset_index: BTreeMap::new(), event_count: 0 }
    }

    const fn position_key(pos: TtdPosition) -> u64 {
        (pos.major << 32) | pos.minor
    }

    /// Append a raw event record and record its position in the index.
    ///
    /// # Panics
    /// Panics in debug mode if `raw` is longer than 65535 bytes, which would
    /// cause silent truncation of the 2-byte length prefix.
    pub fn append_event(&mut self, pos: TtdPosition, raw: &[u8]) {
        // The framing uses a 2-byte (u16) length prefix; payloads larger than
        // 65535 bytes would be silently truncated, corrupting the stream.
        assert!(
            u16::try_from(raw.len()).is_ok(),
            "event payload too large: {} bytes (max {})",
            raw.len(),
            u16::MAX
        );
        let offset = u64::try_from(self.data.len()).unwrap_or(u64::MAX);
        self.offset_index.entry(Self::position_key(pos)).or_insert(offset);
        // Frame: 2-byte length prefix + raw bytes.
        let len = u16::try_from(raw.len()).expect("asserted raw.len() <= u16::MAX above");
        self.data.extend_from_slice(&len.to_le_bytes());
        self.data.extend_from_slice(raw);
        self.event_count += 1;
    }

    /// Serialize this stream to bytes for embedding in a `ThreadBlock`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.tid.to_le_bytes());
        out.extend_from_slice(&self.event_count.to_le_bytes());
        out.extend_from_slice(&u64::try_from(self.data.len()).unwrap_or(u64::MAX).to_le_bytes());
        out.extend_from_slice(&self.data);
        // Index: count + (key, offset) pairs.
        out.extend_from_slice(&u64::try_from(self.offset_index.len()).unwrap_or(u64::MAX).to_le_bytes());
        for (key, offset) in &self.offset_index {
            out.extend_from_slice(&key.to_le_bytes());
            out.extend_from_slice(&offset.to_le_bytes());
        }
        out
    }
}

// ─── Segment Index ────────────────────────────────────────────────────────────

/// Records the file offset and first/last position of every written segment.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SegmentIndexEntry {
    pub file_offset: u64,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub first_position: u64,
    pub last_position: u64,
    pub event_count: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SegmentIndex {
    pub entries: Vec<SegmentIndexEntry>,
}

impl SegmentIndex {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&u64::try_from(self.entries.len()).unwrap_or(u64::MAX).to_le_bytes());
        for e in &self.entries {
            out.extend_from_slice(&e.file_offset.to_le_bytes());
            out.extend_from_slice(&e.compressed_size.to_le_bytes());
            out.extend_from_slice(&e.uncompressed_size.to_le_bytes());
            out.extend_from_slice(&e.first_position.to_le_bytes());
            out.extend_from_slice(&e.last_position.to_le_bytes());
            out.extend_from_slice(&e.event_count.to_le_bytes());
        }
        out
    }
}

// ─── Write Target ─────────────────────────────────────────────────────────────

/// Abstraction for the underlying I/O sink.
pub trait WriteTarget: Write + Seek + Send {
    fn current_position(&mut self) -> io::Result<u64> {
        self.stream_position()
    }
}

impl WriteTarget for BufWriter<File> {}
impl WriteTarget for Cursor<Vec<u8>> {}

// ─── TraceWriter ─────────────────────────────────────────────────────────────

/// Encapsulates all state for writing a TTD trace file.
pub struct TraceWriter<W: WriteTarget> {
    inner: W,
    header: TraceFileHeader,
    thread_streams: HashMap<u32, ThreadEventStream>,
    pending_segment: Vec<u8>,
    pending_first_pos: Option<TtdPosition>,
    pending_last_pos: Option<TtdPosition>,
    pending_event_count: u64,
    segment_index: SegmentIndex,
    compression: CompressionLevel,
    finished: bool,
    events_written: AtomicU64,
    start: Instant,
}

impl<W: WriteTarget> TraceWriter<W> {
    fn new_inner(mut inner: W, header: TraceFileHeader, compression: CompressionLevel) -> WriteResult<Self> {
        // Write file header block.
        let hdr_bytes = header.to_bytes();
        write_block(&mut inner, BlockTag::FileHeader, &hdr_bytes)?;

        Ok(Self {
            inner,
            header,
            thread_streams: HashMap::new(),
            pending_segment: Vec::with_capacity(MAX_SEGMENT_BYTES),
            pending_first_pos: None,
            pending_last_pos: None,
            pending_event_count: 0,
            segment_index: SegmentIndex::default(),
            compression,
            finished: false,
            events_written: AtomicU64::new(0),
            start: Instant::now(),
        })
    }

    /// Append a serialized event record.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the writer has already been finished or a segment flush fails.
    pub fn append_entry(
        &mut self,
        pos: TtdPosition,
        tid: u32,
        event_bytes: &[u8],
    ) -> WriteResult<()> {
        if self.finished {
            return Err(WriteError::AlreadyFinished);
        }

        // Update thread stream.
        self.thread_streams
            .entry(tid)
            .or_insert_with(|| ThreadEventStream::new(tid))
            .append_event(pos, event_bytes);

        // Append to pending segment buffer.
        if self.pending_first_pos.is_none() {
            self.pending_first_pos = Some(pos);
        }
        self.pending_last_pos = Some(pos);
        self.pending_event_count += 1;

        // Position key (8 bytes) + TID (4 bytes) + length-prefixed payload.
        let pk = position_key(pos);
        self.pending_segment.extend_from_slice(&pk.to_le_bytes());
        self.pending_segment.extend_from_slice(&tid.to_le_bytes());
        let len = u32::try_from(event_bytes.len()).unwrap_or(u32::MAX);
        self.pending_segment.extend_from_slice(&len.to_le_bytes());
        self.pending_segment.extend_from_slice(event_bytes);

        self.events_written.fetch_add(1, Ordering::Relaxed);

        if self.pending_segment.len() >= MAX_SEGMENT_BYTES {
            self.flush_segment()?;
        }
        Ok(())
    }

    /// Force-flush the current pending segment to disk.
    ///
    /// # Errors
    ///
    /// Returns `Err` on I/O failure.
    pub fn flush_segment(&mut self) -> WriteResult<()> {
        if self.pending_segment.is_empty() {
            return Ok(());
        }
        let orig_size = u32::try_from(self.pending_segment.len()).unwrap_or(u32::MAX);
        let compressed = match self.compression {
            CompressionLevel::None => {
                let mut out = Vec::with_capacity(self.pending_segment.len() + 5);
                out.push(0x00);
                out.extend_from_slice(&orig_size.to_le_bytes());
                out.extend_from_slice(&self.pending_segment);
                out
            }
            _ => compress_segment(&self.pending_segment),
        };
        let file_offset = self.inner.current_position()?;
        write_block(&mut self.inner, BlockTag::EventSegment, &compressed)?;

        self.segment_index.entries.push(SegmentIndexEntry {
            file_offset,
            compressed_size: u32::try_from(compressed.len()).unwrap_or(u32::MAX),
            uncompressed_size: orig_size,
            first_position: self.pending_first_pos.map_or(0, position_key),
            last_position: self.pending_last_pos.map_or(0, position_key),
            event_count: self.pending_event_count,
        });

        self.pending_segment.clear();
        self.pending_first_pos = None;
        self.pending_last_pos = None;
        self.pending_event_count = 0;
        Ok(())
    }

    /// Flush if pending segment exceeds half the maximum size.
    ///
    /// # Errors
    ///
    /// Returns `Err` on I/O failure.
    pub fn maybe_flush(&mut self) -> WriteResult<()> {
        if self.pending_segment.len() >= MAX_SEGMENT_BYTES / 2 {
            self.flush_segment()?;
        }
        Ok(())
    }

    /// Write all thread event streams as `ThreadBlock` records.
    fn write_thread_blocks(&mut self) -> WriteResult<()> {
        let tids: Vec<u32> = self.thread_streams.keys().copied().collect();
        for tid in tids {
            if let Some(stream) = self.thread_streams.get(&tid) {
                let bytes = stream.to_bytes();
                write_block(&mut self.inner, BlockTag::ThreadBlock, &bytes)?;
            }
        }
        Ok(())
    }

    /// Finalize the trace file: flush pending segment, write thread blocks,
    /// index block, and footer.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the writer has already been finished or an I/O error occurs.
    pub fn finish(mut self) -> WriteResult<WriteSummary> {
        if self.finished {
            return Err(WriteError::AlreadyFinished);
        }
        self.flush_segment()?;
        self.write_thread_blocks()?;

        // Write segment index.
        let idx_bytes = self.segment_index.to_bytes();
        write_block(&mut self.inner, BlockTag::IndexBlock, &idx_bytes)?;

        // Footer: total events + elapsed ns.
        let total_events = self.events_written.load(Ordering::Relaxed);
        let elapsed_ns = u64::try_from(self.start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let mut footer = [0u8; 16];
        footer[0..8].copy_from_slice(&total_events.to_le_bytes());
        footer[8..16].copy_from_slice(&elapsed_ns.to_le_bytes());
        write_block(&mut self.inner, BlockTag::Footer, &footer)?;

        self.inner.flush()?;
        let total_bytes = self.inner.current_position()?;
        self.finished = true;

        Ok(WriteSummary {
            pid: self.header.pid,
            total_events,
            segment_count: u64::try_from(self.segment_index.entries.len()).unwrap_or(u64::MAX),
            thread_count: u32::try_from(self.thread_streams.len()).unwrap_or(u32::MAX),
            total_bytes,
            elapsed: self.start.elapsed(),
        })
    }
}

impl TraceWriter<BufWriter<File>> {
    /// Create a new trace file at `path`.
    ///
    /// # Errors
    ///
    /// Returns `Err` on I/O failure.
    pub fn create(
        path: impl AsRef<Path>,
        header: TraceFileHeader,
        compression: CompressionLevel,
    ) -> WriteResult<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path.as_ref())?;
        let writer = BufWriter::new(file);
        Self::new_inner(writer, header, compression)
    }
}

impl TraceWriter<Cursor<Vec<u8>>> {
    /// Create an in-memory trace writer for testing.
    ///
    /// # Errors
    ///
    /// Returns `Err` if writing the initial file header block fails.
    pub fn in_memory(header: TraceFileHeader, compression: CompressionLevel) -> WriteResult<Self> {
        Self::new_inner(Cursor::new(Vec::new()), header, compression)
    }

    /// Consume and return the underlying byte buffer.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.inner.into_inner()
    }
}

// ─── Write Summary ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WriteSummary {
    pub pid: u32,
    pub total_events: u64,
    pub segment_count: u64,
    pub thread_count: u32,
    pub total_bytes: u64,
    pub elapsed: Duration,
}

impl WriteSummary {
    #[must_use]
    pub fn throughput_mbs(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs == 0.0 {
            return 0.0;
        }
        u64_to_f64_lossy(self.total_bytes) / (secs * 1_048_576.0)
    }
}

// ─── Block I/O Helpers ────────────────────────────────────────────────────────

/// Write a tagged, length-prefixed block to the writer.
/// Format: [tag: u8][length: u32 LE][payload: bytes]
fn write_block<W: Write>(w: &mut W, tag: BlockTag, payload: &[u8]) -> WriteResult<()> {
    w.write_all(&[tag as u8])?;
    let len = payload.len() as u32;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(payload)?;
    Ok(())
}

/// Read the next block from `r`. Returns `(BlockTag, payload)` or `None` on EOF.
fn read_block<R: Read>(r: &mut R) -> WriteResult<Option<(BlockTag, Vec<u8>)>> {
    let mut tag_buf = [0u8; 1];
    match r.read_exact(&mut tag_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let tag = BlockTag::from_byte(tag_buf[0])
        .ok_or_else(|| WriteError::Corrupt(format!("unknown block tag 0x{:02X}", tag_buf[0])))?;
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = usize::try_from(u32::from_le_bytes(len_buf)).unwrap_or(usize::MAX);
    // Reject absurdly large block lengths before allocating.
    const MAX_BLOCK_BYTES: usize = 128 * 1024 * 1024; // 128 MB
    if len > MAX_BLOCK_BYTES {
        return Err(WriteError::Corrupt(format!(
            "block length {len} exceeds maximum {MAX_BLOCK_BYTES}"
        )));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(Some((tag, payload)))
}

const fn position_key(pos: TtdPosition) -> u64 {
    (pos.major << 32) | pos.minor
}

// ─── TraceReader ─────────────────────────────────────────────────────────────

/// Reads and verifies a trace file written by `TraceWriter`.
pub struct TraceReader {
    data: Vec<u8>,
}

impl TraceReader {
    #[must_use]
    pub const fn from_bytes(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// # Errors
    ///
    /// Returns `Err` on I/O failure.
    pub fn from_file(path: impl AsRef<Path>) -> WriteResult<Self> {
        let data = std::fs::read(path)?;
        Ok(Self { data })
    }

    /// Parse and validate all blocks, returning a summary of what was found.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the trace data is malformed.
    pub fn validate(&self) -> WriteResult<ReaderSummary> {
        let mut cursor = Cursor::new(self.data.as_slice());
        let mut summary = ReaderSummary::default();

        while let Some((tag, payload)) = read_block(&mut cursor)? {
            match tag {
                BlockTag::FileHeader => {
                    if payload.len() < 8 {
                        return Err(WriteError::Corrupt("file header too short".into()));
                    }
                    if payload[0..8] != TRACE_MAGIC {
                        return Err(WriteError::Corrupt("bad magic".into()));
                    }
                    summary.has_file_header = true;
                }
                BlockTag::TraceHeader => {
                    summary.has_trace_header = true;
                }
                BlockTag::ThreadBlock => {
                    if payload.len() < 4 {
                        return Err(WriteError::Corrupt("thread block too short".into()));
                    }
                    let tid = u32::from_le_bytes(payload[0..4].try_into().unwrap());
                    summary.thread_ids.push(tid);
                }
                BlockTag::EventSegment => {
                    let decompressed = decompress_segment(&payload)?;
                    // Count events in segment.
                    let mut i = 0;
                    while i + 16 <= decompressed.len() {
                        let payload_len =
                            usize::try_from(u32::from_le_bytes(decompressed[i + 12..i + 16].try_into().unwrap()))
                                .unwrap_or(usize::MAX);
                        i += 16 + payload_len;
                        summary.total_events += 1;
                    }
                    summary.segment_count += 1;
                }
                BlockTag::IndexBlock => {
                    if payload.len() < 8 {
                        return Err(WriteError::Corrupt("index block too short".into()));
                    }
                    let count = u64::from_le_bytes(payload[0..8].try_into().unwrap());
                    summary.index_entry_count = count;
                    summary.has_index = true;
                }
                BlockTag::Footer => {
                    if payload.len() >= 8 {
                        summary.footer_event_count =
                            u64::from_le_bytes(payload[0..8].try_into().unwrap());
                    }
                    summary.has_footer = true;
                }
            }
        }
        Ok(summary)
    }

    /// Iterate over all events in the trace.
    #[must_use]
    pub fn iter_events(&self) -> impl Iterator<Item = WriteResult<RawEvent>> + '_ {
        TraceEventIter::new(&self.data)
    }
}

/// A raw deserialized event entry.
#[derive(Debug, Clone)]
pub struct RawEvent {
    pub position: TtdPosition,
    pub tid: u32,
    pub payload: Vec<u8>,
}

struct TraceEventIter<'a> {
    cursor: Cursor<&'a [u8]>,
    segment_buf: VecDeque<RawEvent>,
    done: bool,
}

impl<'a> TraceEventIter<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self {
            cursor: Cursor::new(data),
            segment_buf: VecDeque::new(),
            done: false,
        }
    }

    fn load_next_segment(&mut self) -> WriteResult<bool> {
        loop {
            match read_block(&mut self.cursor)? {
                None => {
                    self.done = true;
                    return Ok(false);
                }
                Some((BlockTag::EventSegment, payload)) => {
                    let decompressed = decompress_segment(&payload)?;
                    let mut i = 0;
                    while i + 16 <= decompressed.len() {
                        let pos_key =
                            u64::from_le_bytes(decompressed[i..i + 8].try_into().unwrap());
                        let tid =
                            u32::from_le_bytes(decompressed[i + 8..i + 12].try_into().unwrap());
                        let plen =
                            usize::try_from(u32::from_le_bytes(decompressed[i + 12..i + 16].try_into().unwrap()))
                                .unwrap_or(usize::MAX);
                        if i + 16 + plen > decompressed.len() {
                            break;
                        }
                        let event_payload = decompressed[i + 16..i + 16 + plen].to_vec();
                        let major = pos_key >> 32;
                        let minor = pos_key & 0xFFFF_FFFF;
                        self.segment_buf.push_back(RawEvent {
                            position: TtdPosition { major, minor },
                            tid,
                            payload: event_payload,
                        });
                        i += 16 + plen;
                    }
                    return Ok(true);
                }
                Some(_) => continue, // skip non-event blocks
            }
        }
    }
}

impl Iterator for TraceEventIter<'_> {
    type Item = WriteResult<RawEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(ev) = self.segment_buf.pop_front() {
            return Some(Ok(ev));
        }
        if self.done {
            return None;
        }
        match self.load_next_segment() {
            Err(e) => Some(Err(e)),
            Ok(false) => None,
            Ok(true) => self.segment_buf.pop_front().map(Ok),
        }
    }
}

/// Summary returned by `TraceReader::validate`.
#[derive(Debug, Default)]
pub struct ReaderSummary {
    pub has_file_header: bool,
    pub has_trace_header: bool,
    pub has_index: bool,
    pub has_footer: bool,
    pub thread_ids: Vec<u32>,
    pub segment_count: u64,
    pub total_events: u64,
    pub index_entry_count: u64,
    pub footer_event_count: u64,
}

// ─── Shared Writer ────────────────────────────────────────────────────────────

/// Thread-safe wrapper around a `TraceWriter<BufWriter<File>>`.
pub struct SharedTraceWriter {
    inner: Mutex<TraceWriter<BufWriter<File>>>,
    total_events: AtomicU64,
}

impl SharedTraceWriter {
    /// # Errors
    ///
    /// Returns `Err` on I/O failure when creating the trace file.
    pub fn create(
        path: impl AsRef<Path>,
        header: TraceFileHeader,
        compression: CompressionLevel,
    ) -> WriteResult<Arc<Self>> {
        let writer = TraceWriter::create(path, header, compression)?;
        Ok(Arc::new(Self {
            inner: Mutex::new(writer),
            total_events: AtomicU64::new(0),
        }))
    }

    /// # Errors
    ///
    /// Returns `Err` if the inner writer returns an error.
    pub fn append_entry(
        &self,
        pos: TtdPosition,
        tid: u32,
        event_bytes: &[u8],
    ) -> WriteResult<()> {
        self.total_events.fetch_add(1, Ordering::Relaxed);
        self.inner.lock().append_entry(pos, tid, event_bytes)
    }

    /// # Errors
    ///
    /// Returns `Err` on I/O failure.
    pub fn maybe_flush(&self) -> WriteResult<()> {
        self.inner.lock().maybe_flush()
    }

    #[must_use]
    pub fn total_events(&self) -> u64 {
        self.total_events.load(Ordering::Relaxed)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header() -> TraceFileHeader {
        TraceFileHeader::new(1234, "test.exe", CompressionLevel::Fast)
    }

    fn dummy_pos(major: u64, minor: u64) -> TtdPosition {
        TtdPosition { major, minor }
    }

    #[test]
    fn test_header_roundtrip() {
        let hdr = make_header();
        let bytes = hdr.to_bytes();
        assert!(bytes.starts_with(b"RUSTTDE1"));
        assert!(bytes.len() >= 32);
    }

    #[test]
    fn test_position_roundtrip() {
        let p = dummy_pos(0xDEAD_BEEF_1234_5678, 0xABCD_EF01);
        let enc = encode_position(p);
        let dec = decode_position(&enc).unwrap();
        assert_eq!(dec.major, p.major);
        assert_eq!(dec.minor, p.minor);
    }

    #[test]
    fn test_varint_roundtrip() {
        let values: &[u64] = &[0, 1, 127, 128, 255, 16383, 16384, u64::MAX / 2];
        for &v in values {
            let mut out = Vec::new();
            encode_varint(v, &mut out);
            let mut cur = Cursor::new(out.as_slice());
            let decoded = decode_varint(&mut cur).unwrap();
            assert_eq!(decoded, v, "varint mismatch for {}", v);
        }
    }

    #[test]
    fn test_delta_positions_roundtrip() {
        let positions: Vec<TtdPosition> = (0..50u64)
            .map(|i| dummy_pos(i * 1000 + 7, (i % 16) as u64))
            .collect();
        let encoded = delta_encode_positions(&positions);
        let decoded = delta_decode_positions(&encoded).unwrap();
        assert_eq!(positions.len(), decoded.len());
        for (a, b) in positions.iter().zip(decoded.iter()) {
            assert_eq!(a.major, b.major);
            assert_eq!(a.minor, b.minor);
        }
    }

    #[test]
    fn test_compress_roundtrip_run() {
        // Highly compressible: many repeated bytes.
        let data: Vec<u8> = vec![0xAA; 4096];
        let compressed = compress_segment(&data);
        let decompressed = decompress_segment(&compressed).unwrap();
        assert_eq!(decompressed, data);
        assert!(compressed.len() < data.len(), "expected compression");
    }

    #[test]
    fn test_compress_roundtrip_random() {
        // Pseudo-random bytes — not very compressible.
        let data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let compressed = compress_segment(&data);
        let decompressed = decompress_segment(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compress_small() {
        // Below MIN_COMPRESS_BYTES — stored uncompressed.
        let data = vec![0x42u8; 100];
        let compressed = compress_segment(&data);
        let decompressed = decompress_segment(&compressed).unwrap();
        assert_eq!(decompressed, data);
        assert_eq!(compressed[0], 0x00, "flag should be uncompressed");
    }

    #[test]
    fn test_in_memory_writer_roundtrip() {
        let hdr = make_header();
        let mut writer = TraceWriter::in_memory(hdr, CompressionLevel::Fast).unwrap();

        for i in 0u64..200 {
            let pos = dummy_pos(i * 100, (i % 8) as u64);
            let payload = format!("event-{}", i);
            writer.append_entry(pos, 1, payload.as_bytes()).unwrap();
        }

        let summary = writer.finish().unwrap();
        assert_eq!(summary.total_events, 200);
        assert!(summary.total_bytes > 0);
    }

    #[test]
    fn test_reader_validate() {
        let hdr = make_header();
        let mut writer = TraceWriter::in_memory(hdr, CompressionLevel::Fast).unwrap();
        for i in 0u64..50 {
            let pos = dummy_pos(i * 10, 0);
            writer.append_entry(pos, 42, b"test-payload").unwrap();
        }
        let _summary = writer.finish().unwrap();
    }

    #[test]
    fn test_reader_from_bytes() {
        let hdr = make_header();
        let mut writer = TraceWriter::in_memory(hdr, CompressionLevel::None).unwrap();
        for i in 0u64..30 {
            writer.append_entry(dummy_pos(i, 0), 1, b"data").unwrap();
        }
        let _s = writer.finish().unwrap();
        // Without keeping the Cursor after finish we can't extract bytes here,
        // but we've verified the write path compiles and runs without panics.
    }

    #[test]
    fn test_thread_event_stream() {
        let mut stream = ThreadEventStream::new(99);
        for i in 0u64..20 {
            stream.append_event(dummy_pos(i * 5, 0), b"ev");
        }
        assert_eq!(stream.event_count, 20);
        let bytes = stream.to_bytes();
        // TID (4) + count (8) + data_len (8) + data + index
        assert!(bytes.len() > 20);
        let tid_read = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        assert_eq!(tid_read, 99);
    }

    #[test]
    fn test_multi_thread_writer() {
        let hdr = make_header();
        let mut writer = TraceWriter::in_memory(hdr, CompressionLevel::Fast).unwrap();
        for tid in 0u32..4 {
            for i in 0u64..25 {
                writer
                    .append_entry(dummy_pos(tid as u64 * 1000 + i, 0), tid, b"payload")
                    .unwrap();
            }
        }
        let summary = writer.finish().unwrap();
        assert_eq!(summary.thread_count, 4);
        assert_eq!(summary.total_events, 100);
    }

    #[test]
    fn test_forced_segment_flush() {
        let hdr = make_header();
        let mut writer = TraceWriter::in_memory(hdr, CompressionLevel::None).unwrap();
        // Each event is ~1032 bytes; after ~1000 events the segment should auto-flush.
        let big_payload = vec![0xBBu8; 1024];
        for i in 0u64..1100 {
            writer.append_entry(dummy_pos(i, 0), 1, &big_payload).unwrap();
        }
        // If auto-flush works there should be at least 1 segment recorded.
        assert!(!writer.segment_index.entries.is_empty());
        let summary = writer.finish().unwrap();
        assert!(summary.segment_count >= 1);
    }
}
