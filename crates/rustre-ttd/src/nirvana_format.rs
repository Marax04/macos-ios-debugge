//! `nirvana_format` — TTD on-disk file format per Nirvana/WinDbg TTD.
//!
//! Implements the binary layout understood by Microsoft's Time-Travel Debugging
//! (formerly codenamed "Nirvana"). Provides:
//!
//! * [`TtdHeader`] — fixed-size file header with magic, version and offsets.
//! * [`TtdModuleList`] — table of loaded modules (name, base, size, timestamp).
//! * [`TtdThreadList`] — per-thread records (TID, creation/exit positions).
//! * [`TtdPositionMap`] — sorted array mapping sequence numbers to file offsets.
//! * [`TtdEventLog`] — compact on-disk event log with variable-length records.
//! * [`TtdParser`] — entry point that ties all of the above together.

use std::collections::BTreeMap;
use std::io::{self, Read, Seek, SeekFrom, Write as IoWrite};

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;

use crate::{EventKind, TraceEvent, TraceMetadata, TracePosition, TtdTrace};

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by the Nirvana TTD format layer.
#[derive(Debug, Error)]
pub enum NirvanaError {
    /// The file magic bytes did not match.
    #[error("bad magic: expected {expected:#x}, got {got:#x}")]
    BadMagic { expected: u64, got: u64 },
    /// The file is too short to contain the requested structure.
    #[error("truncated file: needed {needed} bytes at offset {offset}")]
    Truncated { needed: usize, offset: u64 },
    /// An unsupported format version was encountered.
    #[error("unsupported TTD version {major}.{minor}")]
    UnsupportedVersion { major: u16, minor: u16 },
    /// A string in the file could not be decoded as UTF-8.
    #[error("invalid UTF-8 string at offset {offset}")]
    InvalidString { offset: u64 },
    /// An I/O error from the underlying reader/writer.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// A sequence number was not present in the position map.
    #[error("sequence {seq} not found in position map")]
    SequenceNotFound { seq: u64 },
    /// A field value exceeded its expected range.
    #[error("field '{field}' out of range: value={value}")]
    FieldOutOfRange { field: &'static str, value: u64 },
}

// ─── Constants ───────────────────────────────────────────────────────────────

/// Magic bytes at the start of a Nirvana/WinDbg TTD trace file.
pub const TTD_MAGIC: u64 = 0x4454_5456_4E52_4E49; // "INRNVTTD" LE
/// Current format version supported by this parser.
pub const TTD_VERSION_MAJOR: u16 = 2;
pub const TTD_VERSION_MINOR: u16 = 0;
/// Size of the [`TtdHeader`] on disk in bytes.
pub const HEADER_SIZE: usize = 128;

// ─── TtdHeader ───────────────────────────────────────────────────────────────

/// Fixed-size header at the start of a Nirvana TTD file.
///
/// Offsets are relative to the start of the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TtdHeader {
    /// File magic (`TTD_MAGIC`).
    pub magic: u64,
    /// Format major version.
    pub version_major: u16,
    /// Format minor version.
    pub version_minor: u16,
    /// Flags bitmask (reserved; must be zero for reading).
    pub flags: u32,
    /// Byte offset of the module list section.
    pub module_list_offset: u64,
    /// Byte offset of the thread list section.
    pub thread_list_offset: u64,
    /// Byte offset of the position map section.
    pub position_map_offset: u64,
    /// Byte offset of the event log section.
    pub event_log_offset: u64,
    /// Total number of events recorded in the file.
    pub event_count: u64,
    /// Recorded process name (null-padded, max 64 bytes).
    #[serde(with = "BigArray")]
    pub process_name: [u8; 64],
    /// PID of the recorded process.
    pub pid: u32,
    /// Reserved padding to reach `HEADER_SIZE`.
    pub reserved: [u8; 16],
}

impl TtdHeader {
    /// Construct a new header for writing with default field values.
    #[must_use]
    pub fn new(process_name: &str, pid: u32) -> Self {
        let mut name_buf = [0u8; 64];
        let bytes = process_name.as_bytes();
        let len = bytes.len().min(63);
        name_buf[..len].copy_from_slice(&bytes[..len]);
        Self {
            magic: TTD_MAGIC,
            version_major: TTD_VERSION_MAJOR,
            version_minor: TTD_VERSION_MINOR,
            flags: 0,
            module_list_offset: 0,
            thread_list_offset: 0,
            position_map_offset: 0,
            event_log_offset: 0,
            event_count: 0,
            process_name: name_buf,
            pid,
            reserved: [0u8; 16],
        }
    }

    /// Validate the magic bytes and version.
    ///
    /// # Errors
    ///
    /// Returns [`NirvanaError::BadMagic`] or [`NirvanaError::UnsupportedVersion`].
    pub const fn validate(&self) -> Result<(), NirvanaError> {
        if self.magic != TTD_MAGIC {
            return Err(NirvanaError::BadMagic {
                expected: TTD_MAGIC,
                got: self.magic,
            });
        }
        if self.version_major > TTD_VERSION_MAJOR {
            return Err(NirvanaError::UnsupportedVersion {
                major: self.version_major,
                minor: self.version_minor,
            });
        }
        Ok(())
    }

    /// Retrieve the process name as a `String`, stripping null terminators.
    #[must_use]
    pub fn process_name_str(&self) -> String {
        let nul = self.process_name.iter().position(|&b| b == 0).unwrap_or(64);
        String::from_utf8_lossy(&self.process_name[..nul]).into_owned()
    }

    /// Serialize to a fixed-size byte buffer.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..8].copy_from_slice(&self.magic.to_le_bytes());
        buf[8..10].copy_from_slice(&self.version_major.to_le_bytes());
        buf[10..12].copy_from_slice(&self.version_minor.to_le_bytes());
        buf[12..16].copy_from_slice(&self.flags.to_le_bytes());
        buf[16..24].copy_from_slice(&self.module_list_offset.to_le_bytes());
        buf[24..32].copy_from_slice(&self.thread_list_offset.to_le_bytes());
        buf[32..40].copy_from_slice(&self.position_map_offset.to_le_bytes());
        buf[40..48].copy_from_slice(&self.event_log_offset.to_le_bytes());
        buf[48..56].copy_from_slice(&self.event_count.to_le_bytes());
        buf[56..120].copy_from_slice(&self.process_name);
        buf[120..124].copy_from_slice(&self.pid.to_le_bytes());
        buf
    }

    /// Deserialize from a fixed-size byte buffer.
    ///
    /// # Errors
    ///
    /// Returns [`NirvanaError::Truncated`] if the slice is too short.
    ///
    /// # Panics
    ///
    /// Panics if internal `try_into` conversions fail; this cannot happen
    /// because the length check above guarantees the required bytes exist.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NirvanaError> {
        if bytes.len() < HEADER_SIZE {
            return Err(NirvanaError::Truncated {
                needed: HEADER_SIZE,
                offset: 0,
            });
        }
        let magic = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let version_major = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
        let version_minor = u16::from_le_bytes(bytes[10..12].try_into().unwrap());
        let flags = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let module_list_offset = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let thread_list_offset = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        let position_map_offset = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        let event_log_offset = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
        let event_count = u64::from_le_bytes(bytes[48..56].try_into().unwrap());
        let mut process_name = [0u8; 64];
        process_name.copy_from_slice(&bytes[56..120]);
        let pid = u32::from_le_bytes(bytes[120..124].try_into().unwrap());
        Ok(Self {
            magic,
            version_major,
            version_minor,
            flags,
            module_list_offset,
            thread_list_offset,
            position_map_offset,
            event_log_offset,
            event_count,
            process_name,
            pid,
            reserved: [0u8; 16],
        })
    }

    /// Write the header to `writer`.
    ///
    /// # Errors
    ///
    /// Returns [`NirvanaError::Io`] on write failure.
    pub fn write<W: IoWrite>(&self, writer: &mut W) -> Result<(), NirvanaError> {
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }

    /// Read a header from `reader`.
    ///
    /// # Errors
    ///
    /// Returns [`NirvanaError::Io`] or [`NirvanaError::Truncated`].
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, NirvanaError> {
        let mut buf = [0u8; HEADER_SIZE];
        reader.read_exact(&mut buf).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                NirvanaError::Truncated {
                    needed: HEADER_SIZE,
                    offset: 0,
                }
            } else {
                NirvanaError::Io(e)
            }
        })?;
        Self::from_bytes(&buf)
    }
}

// ─── TtdModuleEntry ──────────────────────────────────────────────────────────

/// A single loaded module entry within a [`TtdModuleList`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TtdModuleEntry {
    /// Image base address.
    pub base: u64,
    /// Image size in bytes.
    pub size: u32,
    /// PE timestamp (seconds since Unix epoch).
    pub timestamp: u32,
    /// Module path (UTF-8, max 260 bytes).
    pub path: String,
    /// `TracePosition` at which this module was loaded.
    pub load_position: TracePosition,
    /// `TracePosition` at which this module was unloaded (all-ones = still loaded).
    pub unload_position: TracePosition,
}

impl TtdModuleEntry {
    /// Create a new module entry.
    #[must_use]
    pub fn new(
        base: u64,
        size: u32,
        timestamp: u32,
        path: impl Into<String>,
        load_position: TracePosition,
    ) -> Self {
        Self {
            base,
            size,
            timestamp,
            path: path.into(),
            load_position,
            unload_position: TracePosition::new(u64::MAX, u64::MAX),
        }
    }

    /// Return the exclusive end address of this module.
    #[must_use]
    pub fn end(&self) -> u64 {
        self.base.saturating_add(u64::from(self.size))
    }

    /// Return `true` if `addr` falls within this module's address range.
    #[must_use]
    pub fn contains_addr(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }

    /// Return `true` if the module is still loaded at `pos`.
    #[must_use]
    pub fn loaded_at(&self, pos: TracePosition) -> bool {
        pos >= self.load_position && pos < self.unload_position
    }

    /// Record the position at which this module was unloaded. The second
    /// argument is reserved for an exit/unload reason code and is currently
    /// ignored.
    pub const fn record_exit(&mut self, unload_position: TracePosition, _reason: u32) {
        self.unload_position = unload_position;
    }

    /// Return the file name portion of `path` (after the last `\` or `/`).
    #[must_use]
    pub fn file_name(&self) -> &str {
        self.path
            .rfind(['\\', '/'])
            .map_or(&self.path, |i| &self.path[i + 1..])
    }
}

// ─── TtdModuleList ───────────────────────────────────────────────────────────

/// Collection of loaded modules recorded in a TTD trace file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TtdModuleList {
    /// All module entries, in load order.
    pub modules: Vec<TtdModuleEntry>,
}

impl TtdModuleList {
    /// Create an empty module list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a module entry to the list.
    pub fn add(&mut self, entry: TtdModuleEntry) {
        self.modules.push(entry);
    }

    /// Find the module containing `addr` at trace position `pos`.
    #[must_use]
    pub fn module_at(&self, addr: u64, pos: TracePosition) -> Option<&TtdModuleEntry> {
        self.modules
            .iter()
            .find(|m| m.contains_addr(addr) && m.loaded_at(pos))
    }

    /// Find a module by its file name (case-insensitive).
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<&TtdModuleEntry> {
        let name_lower = name.to_lowercase();
        self.modules
            .iter()
            .find(|m| m.file_name().to_lowercase() == name_lower)
    }

    /// Return the number of modules.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.modules.len()
    }

    /// Return `true` if there are no modules.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    /// Write all entries to `writer` as a length-prefixed list.
    ///
    /// Format: `u32` entry count, then for each entry:
    /// `u64 base | u32 size | u32 ts | u64 load_seq | u64 load_step |
    ///  u64 unload_seq | u64 unload_step | u16 path_len | path bytes`
    ///
    /// # Errors
    ///
    /// Returns [`NirvanaError::Io`] on write failure.
    pub fn write<W: IoWrite>(&self, writer: &mut W) -> Result<(), NirvanaError> {
        write_u32(writer, u32::try_from(self.modules.len()).unwrap_or(u32::MAX))?;
        for m in &self.modules {
            write_u64(writer, m.base)?;
            write_u32(writer, m.size)?;
            write_u32(writer, m.timestamp)?;
            write_u64(writer, m.load_position.sequence)?;
            write_u64(writer, m.load_position.step)?;
            write_u64(writer, m.unload_position.sequence)?;
            write_u64(writer, m.unload_position.step)?;
            let path_bytes = m.path.as_bytes();
            let path_len = path_bytes.len().min(u16::MAX as usize);
            write_u16(writer, u16::try_from(path_len).unwrap_or(u16::MAX))?;
            writer.write_all(&path_bytes[..path_len])?;
        }
        Ok(())
    }

    /// Read module entries from `reader`.
    ///
    /// # Errors
    ///
    /// Returns [`NirvanaError::Io`], [`NirvanaError::Truncated`], or
    /// [`NirvanaError::InvalidString`].
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, NirvanaError> {
        // Cap module count to prevent unbounded iteration on malformed input.
        const MAX_MODULES: u32 = 4096;
        let count_raw = read_u32(reader)?;
        if count_raw > MAX_MODULES {
            return Err(NirvanaError::FieldOutOfRange {
                field: "module_count",
                value: u64::from(count_raw),
            });
        }
        let count = count_raw as usize;
        let mut modules = Vec::with_capacity(count);
        for _ in 0..count {
            let base = read_u64(reader)?;
            let size = read_u32(reader)?;
            let timestamp = read_u32(reader)?;
            let load_seq = read_u64(reader)?;
            let load_step = read_u64(reader)?;
            let unload_seq = read_u64(reader)?;
            let unload_step = read_u64(reader)?;
            let path_len = read_u16(reader)? as usize;
            let mut path_bytes = vec![0u8; path_len];
            reader.read_exact(&mut path_bytes)?;
            let path = String::from_utf8(path_bytes)
                .map_err(|_| NirvanaError::InvalidString { offset: 0 })?;
            modules.push(TtdModuleEntry {
                base,
                size,
                timestamp,
                path,
                load_position: TracePosition::new(load_seq, load_step),
                unload_position: TracePosition::new(unload_seq, unload_step),
            });
        }
        Ok(Self { modules })
    }
}

// ─── TtdThreadEntry ──────────────────────────────────────────────────────────

/// A single thread recorded in a [`TtdThreadList`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TtdThreadEntry {
    /// OS thread identifier.
    pub tid: u32,
    /// Position at which the thread was created.
    pub create_position: TracePosition,
    /// Position at which the thread exited (all-ones = still running).
    pub exit_position: TracePosition,
    /// Thread exit code (valid only when `exit_position != MAX`).
    pub exit_code: u32,
}

impl TtdThreadEntry {
    /// Create a new thread entry.
    #[must_use]
    pub const fn new(tid: u32, create_position: TracePosition) -> Self {
        Self {
            tid,
            create_position,
            exit_position: TracePosition::new(u64::MAX, u64::MAX),
            exit_code: 0,
        }
    }

    /// Record the thread exit.
    pub const fn record_exit(&mut self, exit_position: TracePosition, exit_code: u32) {
        self.exit_position = exit_position;
        self.exit_code = exit_code;
    }

    /// Return `true` if the thread was still alive at the end of the trace.
    #[must_use]
    pub const fn is_alive(&self) -> bool {
        self.exit_position.sequence == u64::MAX
    }

    /// Return `true` if the thread was alive at position `pos`.
    #[must_use]
    pub fn alive_at(&self, pos: TracePosition) -> bool {
        pos >= self.create_position && pos < self.exit_position
    }
}

// ─── TtdThreadList ───────────────────────────────────────────────────────────

/// Collection of thread records stored in a TTD trace file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TtdThreadList {
    /// All thread entries, in creation order.
    pub threads: Vec<TtdThreadEntry>,
}

impl TtdThreadList {
    /// Create an empty thread list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a thread entry.
    pub fn add(&mut self, entry: TtdThreadEntry) {
        self.threads.push(entry);
    }

    /// Find a thread entry by TID.
    #[must_use]
    pub fn find_by_tid(&self, tid: u32) -> Option<&TtdThreadEntry> {
        self.threads.iter().find(|t| t.tid == tid)
    }

    /// Find a mutable thread entry by TID.
    pub fn find_by_tid_mut(&mut self, tid: u32) -> Option<&mut TtdThreadEntry> {
        self.threads.iter_mut().find(|t| t.tid == tid)
    }

    /// Return all threads alive at position `pos`.
    #[must_use]
    pub fn alive_at(&self, pos: TracePosition) -> Vec<&TtdThreadEntry> {
        self.threads.iter().filter(|t| t.alive_at(pos)).collect()
    }

    /// Return the number of thread entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.threads.len()
    }

    /// Return `true` if there are no thread entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.threads.is_empty()
    }

    /// Write all thread entries to `writer`.
    ///
    /// Format: `u32` count, then for each entry:
    /// `u32 tid | u64 create_seq | u64 create_step | u64 exit_seq |
    ///  u64 exit_step | u32 exit_code`
    ///
    /// # Errors
    ///
    /// Returns [`NirvanaError::Io`].
    pub fn write<W: IoWrite>(&self, writer: &mut W) -> Result<(), NirvanaError> {
        write_u32(writer, u32::try_from(self.threads.len()).unwrap_or(u32::MAX))?;
        for t in &self.threads {
            write_u32(writer, t.tid)?;
            write_u64(writer, t.create_position.sequence)?;
            write_u64(writer, t.create_position.step)?;
            write_u64(writer, t.exit_position.sequence)?;
            write_u64(writer, t.exit_position.step)?;
            write_u32(writer, t.exit_code)?;
        }
        Ok(())
    }

    /// Read thread entries from `reader`.
    ///
    /// # Errors
    ///
    /// Returns [`NirvanaError::Io`] or [`NirvanaError::Truncated`].
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, NirvanaError> {
        // Cap thread count to prevent unbounded iteration on malformed input.
        const MAX_THREADS: u32 = 65536;
        let count_raw = read_u32(reader)?;
        if count_raw > MAX_THREADS {
            return Err(NirvanaError::FieldOutOfRange {
                field: "thread_count",
                value: u64::from(count_raw),
            });
        }
        let count = count_raw as usize;
        let mut threads = Vec::with_capacity(count);
        for _ in 0..count {
            let tid = read_u32(reader)?;
            let create_seq = read_u64(reader)?;
            let create_step = read_u64(reader)?;
            let exit_seq = read_u64(reader)?;
            let exit_step = read_u64(reader)?;
            let exit_code = read_u32(reader)?;
            threads.push(TtdThreadEntry {
                tid,
                create_position: TracePosition::new(create_seq, create_step),
                exit_position: TracePosition::new(exit_seq, exit_step),
                exit_code,
            });
        }
        Ok(Self { threads })
    }
}

// ─── TtdPositionMapEntry ─────────────────────────────────────────────────────

/// A single entry in the [`TtdPositionMap`]: maps a sequence number to a file
/// offset within the event log section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TtdPositionMapEntry {
    /// Sequence number.
    pub sequence: u64,
    /// Byte offset within the event log section.
    pub offset: u64,
}

// ─── TtdPositionMap ──────────────────────────────────────────────────────────

/// Sorted array mapping sequence numbers to byte offsets in the event log.
///
/// Used to support O(log n) seek-by-position on large traces.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TtdPositionMap {
    /// Sorted entries (by `sequence`, ascending).
    entries: Vec<TtdPositionMapEntry>,
}

impl TtdPositionMap {
    /// Create an empty position map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a (sequence → offset) mapping.  Entries must be inserted in
    /// non-decreasing sequence order (or call [`Self::sort`] afterwards).
    pub fn insert(&mut self, sequence: u64, offset: u64) {
        self.entries.push(TtdPositionMapEntry { sequence, offset });
    }

    /// Sort all entries by sequence number.
    pub fn sort(&mut self) {
        self.entries.sort_unstable_by_key(|e| e.sequence);
    }

    /// Look up the file offset for `sequence` via binary search.
    ///
    /// Returns the offset of the entry whose sequence number is the largest
    /// one that is ≤ `sequence`.
    ///
    /// # Errors
    ///
    /// Returns [`NirvanaError::SequenceNotFound`] if `sequence` is before the
    /// first mapped position.
    pub fn offset_for_sequence(&self, sequence: u64) -> Result<u64, NirvanaError> {
        if self.entries.is_empty() {
            return Err(NirvanaError::SequenceNotFound { seq: sequence });
        }
        let idx = self.entries.partition_point(|e| e.sequence <= sequence);
        if idx == 0 {
            return Err(NirvanaError::SequenceNotFound { seq: sequence });
        }
        Ok(self.entries[idx - 1].offset)
    }

    /// Return the total number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the map is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return all entries as a slice.
    #[must_use]
    pub fn entries(&self) -> &[TtdPositionMapEntry] {
        &self.entries
    }

    /// Write all entries to `writer`.
    ///
    /// Format: `u64` count, then pairs of `u64 sequence | u64 offset`.
    ///
    /// # Errors
    ///
    /// Returns [`NirvanaError::Io`].
    pub fn write<W: IoWrite>(&self, writer: &mut W) -> Result<(), NirvanaError> {
        write_u64(writer, self.entries.len() as u64)?;
        for e in &self.entries {
            write_u64(writer, e.sequence)?;
            write_u64(writer, e.offset)?;
        }
        Ok(())
    }

    /// Read entries from `reader`.
    ///
    /// # Errors
    ///
    /// Returns [`NirvanaError::Io`] or [`NirvanaError::Truncated`].
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, NirvanaError> {
        // Reject absurdly large position maps before allocating.
        const MAX_POSITION_MAP_ENTRIES: u64 = 1 << 20; // ~8 M entries
        let count_raw = read_u64(reader)?;
        if count_raw > MAX_POSITION_MAP_ENTRIES {
            return Err(NirvanaError::FieldOutOfRange {
                field: "position_map_count",
                value: count_raw,
            });
        }
        let count = usize::try_from(count_raw).map_err(|_| NirvanaError::FieldOutOfRange {
            field: "position_map_count",
            value: count_raw,
        })?;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let sequence = read_u64(reader)?;
            let offset = read_u64(reader)?;
            entries.push(TtdPositionMapEntry { sequence, offset });
        }
        Ok(Self { entries })
    }
}

// ─── EventRecord ─────────────────────────────────────────────────────────────

/// Discriminant byte used in the compact event log encoding.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventTag {
    MemRead = 0x01,
    MemWrite = 0x02,
    Call = 0x03,
    Return = 0x04,
    SyscallEnter = 0x05,
    SyscallExit = 0x06,
    Exception = 0x07,
    ThreadCreate = 0x08,
    ThreadExit = 0x09,
    Breakpoint = 0x0A,
}

impl EventTag {
    /// Parse a raw byte into an `EventTag`.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::MemRead),
            0x02 => Some(Self::MemWrite),
            0x03 => Some(Self::Call),
            0x04 => Some(Self::Return),
            0x05 => Some(Self::SyscallEnter),
            0x06 => Some(Self::SyscallExit),
            0x07 => Some(Self::Exception),
            0x08 => Some(Self::ThreadCreate),
            0x09 => Some(Self::ThreadExit),
            0x0A => Some(Self::Breakpoint),
            _ => None,
        }
    }
}

// ─── TtdEventLog ─────────────────────────────────────────────────────────────

/// Compact on-disk event log used within a Nirvana TTD file.
///
/// Each record is:
///   `tag:u8 | seq:u64 | step:u64 | tid:u32 | <payload>`
///
/// The payload varies by tag (see [`EventTag`]).
#[derive(Debug, Default)]
pub struct TtdEventLog {
    /// In-memory buffer.
    buffer: Vec<u8>,
    /// Index mapping sequence → byte offset within `buffer`.
    index: BTreeMap<u64, usize>,
}

impl TtdEventLog {
    /// Create an empty event log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a [`TraceEvent`] to the log.
    pub fn append(&mut self, event: &TraceEvent) {
        let offset = self.buffer.len();
        self.index.entry(event.position.sequence).or_insert(offset);
        encode_event(&mut self.buffer, event);
    }

    /// Append all events from `trace` to the log.
    pub fn append_all(&mut self, trace: &TtdTrace) {
        for event in trace.all_events() {
            self.append(&event);
        }
    }

    /// Decode all events stored in the log.
    ///
    /// # Errors
    ///
    /// Returns [`NirvanaError::Truncated`] on malformed data.
    pub fn decode_all(&self) -> Result<Vec<TraceEvent>, NirvanaError> {
        decode_events(&self.buffer)
    }

    /// Return the total number of bytes in the log buffer.
    #[must_use]
    pub const fn byte_len(&self) -> usize {
        self.buffer.len()
    }

    /// Return the raw buffer bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Write the log buffer to `writer`.
    ///
    /// Prefixes with a `u64` byte count.
    ///
    /// # Errors
    ///
    /// Returns [`NirvanaError::Io`].
    pub fn write<W: IoWrite>(&self, writer: &mut W) -> Result<(), NirvanaError> {
        write_u64(writer, self.buffer.len() as u64)?;
        writer.write_all(&self.buffer)?;
        // Note: usize -> u64 is allowed; clippy is fine with this on 64-bit.
        Ok(())
    }

    /// Read a log from `reader`.
    ///
    /// # Errors
    ///
    /// Returns [`NirvanaError::Io`] or [`NirvanaError::Truncated`].
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, NirvanaError> {
        // Reject event-log buffers larger than 256 MiB to prevent OOM from
        // attacker-controlled length fields.
        const MAX_EVENT_LOG_BYTES: u64 = 256 * 1024 * 1024;
        let len_raw = read_u64(reader)?;
        if len_raw > MAX_EVENT_LOG_BYTES {
            return Err(NirvanaError::FieldOutOfRange {
                field: "event_log_len",
                value: len_raw,
            });
        }
        let len = usize::try_from(len_raw).map_err(|_| NirvanaError::FieldOutOfRange {
            field: "event_log_len",
            value: len_raw,
        })?;
        let mut buffer = vec![0u8; len];
        reader.read_exact(&mut buffer)?;
        // Rebuild the index by scanning the buffer.
        let mut index = BTreeMap::new();
        let events = decode_events(&buffer)?;
        let mut offset = 0usize;
        for event in &events {
            index.entry(event.position.sequence).or_insert(offset);
            offset += encoded_event_size(event);
        }
        Ok(Self { buffer, index })
    }
}

// ─── TtdParser ───────────────────────────────────────────────────────────────

/// High-level parser that reads a complete Nirvana TTD file from a seekable
/// reader and reconstructs all components.
pub struct TtdParser;

impl TtdParser {
    /// Parse a TTD file from `reader`, returning the header, module list,
    /// thread list, position map, and a reconstructed [`TtdTrace`].
    ///
    /// # Errors
    ///
    /// Returns [`NirvanaError`] variants on malformed input or I/O failure.
    pub fn parse<R: Read + Seek>(
        reader: &mut R,
    ) -> Result<
        (
            TtdHeader,
            TtdModuleList,
            TtdThreadList,
            TtdPositionMap,
            TtdTrace,
        ),
        NirvanaError,
    > {
        // Read and validate header.
        let header = TtdHeader::read(reader)?;
        header.validate()?;

        // Module list.
        reader.seek(SeekFrom::Start(header.module_list_offset))?;
        let modules = TtdModuleList::read(reader)?;

        // Thread list.
        reader.seek(SeekFrom::Start(header.thread_list_offset))?;
        let threads = TtdThreadList::read(reader)?;

        // Position map.
        reader.seek(SeekFrom::Start(header.position_map_offset))?;
        let pos_map = TtdPositionMap::read(reader)?;

        // Event log.
        reader.seek(SeekFrom::Start(header.event_log_offset))?;
        let event_log = TtdEventLog::read(reader)?;
        let events = event_log.decode_all()?;

        // Build TtdTrace.
        let meta = TraceMetadata {
            version: u32::from(header.version_major) << 16 | u32::from(header.version_minor),
            process_name: header.process_name_str(),
            pid: header.pid,
            arch: String::from("x86_64"),
            start_time: 0,
            end_time: events.last().map_or(0, |e| e.position.sequence),
            thread_count: u32::try_from(threads.len()).unwrap_or(u32::MAX),
            start_position: TracePosition::start(),
            end_position: events
                .last().map_or_else(TracePosition::start, |e| e.position),
            thread_ids: threads.threads.iter().map(|t| t.tid).collect(),
        };
        let trace = TtdTrace::new(meta);
        for event in events {
            trace.add_event(event);
        }

        Ok((header, modules, threads, pos_map, trace))
    }

    /// Serialize a [`TtdTrace`] to `writer` in Nirvana TTD format.
    ///
    /// # Errors
    ///
    /// Returns [`NirvanaError::Io`] on write failure.
    pub fn serialize<W: IoWrite + Seek>(
        trace: &TtdTrace,
        modules: &TtdModuleList,
        threads: &TtdThreadList,
        writer: &mut W,
    ) -> Result<(), NirvanaError> {
        // Write placeholder header.
        let mut header = TtdHeader::new(&trace.metadata.process_name, trace.metadata.pid);
        header.event_count = trace.event_count() as u64;
        header.write(writer)?;

        // Module list section.
        let module_offset = writer.stream_position()?;
        header.module_list_offset = module_offset;
        modules.write(writer)?;

        // Thread list section.
        let thread_offset = writer.stream_position()?;
        header.thread_list_offset = thread_offset;
        threads.write(writer)?;

        // Build and write position map.
        let pos_map_offset = writer.stream_position()?;
        header.position_map_offset = pos_map_offset;
        let mut pos_map = TtdPositionMap::new();
        // We'll fill this after writing the event log.

        // Event log section: write placeholder length first.
        let event_log_offset_in_file = writer.stream_position()?
            + 8  // pos_map entry count
            + trace.event_count() as u64 * 16; // approximate; rewritten below
        // Build proper position map from events.
        let mut event_log = TtdEventLog::new();
        event_log.append_all(trace);

        // Build position map from log.
        let mut seq_offsets: BTreeMap<u64, u64> = BTreeMap::new();
        let mut cursor = 0u64;
        for event in trace.all_events() {
            seq_offsets.entry(event.position.sequence).or_insert(cursor);
            cursor += encoded_event_size(&event) as u64;
        }
        for (seq, off) in seq_offsets {
            pos_map.insert(seq, off);
        }

        // Re-seek to position map offset and write it.
        writer.seek(SeekFrom::Start(pos_map_offset))?;
        pos_map.write(writer)?;

        let event_log_offset = writer.stream_position()?;
        header.event_log_offset = event_log_offset;
        event_log.write(writer)?;

        // Re-write the header with correct offsets.
        writer.seek(SeekFrom::Start(0))?;
        header.write(writer)?;

        // Suppress unused variable warning.
        let _ = event_log_offset_in_file;

        Ok(())
    }
}

// ─── Encoding / decoding helpers ─────────────────────────────────────────────

/// Encode a single [`TraceEvent`] into `buf`.
fn encode_event(buf: &mut Vec<u8>, event: &TraceEvent) {
    let tag = event_to_tag(&event.kind);
    buf.push(tag as u8);
    buf.extend_from_slice(&event.position.sequence.to_le_bytes());
    buf.extend_from_slice(&event.position.step.to_le_bytes());
    buf.extend_from_slice(&event.thread_id.to_le_bytes());
    encode_payload(buf, &event.kind);
}

const fn event_to_tag(kind: &EventKind) -> EventTag {
    match kind {
        EventKind::MemRead { .. } => EventTag::MemRead,
        EventKind::MemWrite { .. } => EventTag::MemWrite,
        EventKind::Call { .. } => EventTag::Call,
        EventKind::Return { .. } => EventTag::Return,
        EventKind::SyscallEnter { .. } => EventTag::SyscallEnter,
        EventKind::SyscallExit { .. } => EventTag::SyscallExit,
        EventKind::Exception { .. } => EventTag::Exception,
        EventKind::ThreadCreate { .. } => EventTag::ThreadCreate,
        EventKind::ThreadExit { .. } => EventTag::ThreadExit,
        EventKind::Breakpoint { .. } => EventTag::Breakpoint,
    }
}

fn encode_payload(buf: &mut Vec<u8>, kind: &EventKind) {
    match kind {
        EventKind::MemRead { addr, len } => {
            buf.extend_from_slice(&addr.to_le_bytes());
            buf.extend_from_slice(&u32::try_from(*len).unwrap_or(u32::MAX).to_le_bytes());
        }
        EventKind::MemWrite { addr, data } => {
            buf.extend_from_slice(&addr.to_le_bytes());
            let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
            buf.extend_from_slice(&len.to_le_bytes());
            buf.extend_from_slice(data);
        }
        EventKind::Call { from, to } | EventKind::Return { from, to } => {
            buf.extend_from_slice(&from.to_le_bytes());
            buf.extend_from_slice(&to.to_le_bytes());
        }
        EventKind::SyscallEnter { nr, args } => {
            buf.extend_from_slice(&nr.to_le_bytes());
            for &a in args {
                buf.extend_from_slice(&a.to_le_bytes());
            }
        }
        EventKind::SyscallExit { nr, ret } => {
            buf.extend_from_slice(&nr.to_le_bytes());
            buf.extend_from_slice(&ret.to_le_bytes());
        }
        EventKind::Exception { code, addr } => {
            buf.extend_from_slice(&code.to_le_bytes());
            buf.extend_from_slice(&addr.to_le_bytes());
        }
        EventKind::ThreadCreate { tid } | EventKind::ThreadExit { tid, .. } => {
            buf.extend_from_slice(&tid.to_le_bytes());
            if let EventKind::ThreadExit { code, .. } = kind {
                buf.extend_from_slice(&code.to_le_bytes());
            }
        }
        EventKind::Breakpoint { addr } => {
            buf.extend_from_slice(&addr.to_le_bytes());
        }
    }
}

/// Return the encoded byte size of `event` (used for building the position map).
const fn encoded_event_size(event: &TraceEvent) -> usize {
    // tag(1) + seq(8) + step(8) + tid(4) + payload
    1 + 8 + 8 + 4 + payload_size(&event.kind)
}

const fn payload_size(kind: &EventKind) -> usize {
    match kind {
        EventKind::MemWrite { data, .. } => 8 + 4 + data.len(),
        EventKind::Call { .. } | EventKind::Return { .. } => 8 + 8,
        EventKind::SyscallEnter { .. } => 4 + 6 * 8,
        EventKind::MemRead { .. } | EventKind::SyscallExit { .. } | EventKind::Exception { .. } => 4 + 8,
        EventKind::ThreadCreate { .. } => 4,
        EventKind::ThreadExit { .. } | EventKind::Breakpoint { .. } => 4 + 4,
        }
}

fn decode_events(buf: &[u8]) -> Result<Vec<TraceEvent>, NirvanaError> {
    let mut pos = 0usize;
    let mut events = Vec::new();

    while pos < buf.len() {
        let start = pos;
        if pos + 21 > buf.len() {
            break; // not enough for header
        }
        let tag_byte = buf[pos];
        pos += 1;
        let Some(tag) = EventTag::from_byte(tag_byte) else {
            return Err(NirvanaError::FieldOutOfRange {
                field: "event_tag",
                value: u64::from(tag_byte),
            });
        };

        let seq = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let step = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let tid = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap());
        pos += 4;

        let (kind, new_pos) = decode_one_kind(tag, buf, pos, start)?;
        pos = new_pos;

        events.push(TraceEvent {
            position: TracePosition::new(seq, step),
            thread_id: tid,
            kind,
        });
    }

    Ok(events)
}

const fn ensure_remaining(buf: &[u8], pos: usize, needed: usize, start: usize) -> Result<(), NirvanaError> {
    if pos + needed > buf.len() {
        return Err(NirvanaError::Truncated {
            needed,
            offset: start as u64,
        });
    }
    Ok(())
}

fn decode_mem_kind(
    tag: EventTag,
    buf: &[u8],
    mut pos: usize,
    start: usize,
) -> Result<(EventKind, usize), NirvanaError> {
    let kind = match tag {
        EventTag::MemRead => {
            ensure_remaining(buf, pos, 12, start)?;
            let addr = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
            pos += 8;
            let len = usize::try_from(u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap()))
                .unwrap_or(usize::MAX);
            pos += 4;
            EventKind::MemRead { addr, len }
        }
        EventTag::MemWrite => {
            ensure_remaining(buf, pos, 12, start)?;
            let addr = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
            pos += 8;
            let len_u32 = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap());
            pos += 4;
            let len = usize::try_from(len_u32).map_err(|_| NirvanaError::FieldOutOfRange {
                field: "mem_write_len",
                value: u64::from(len_u32),
            })?;
            let end = pos.checked_add(len).ok_or_else(|| NirvanaError::FieldOutOfRange {
                field: "mem_write_len",
                value: u64::from(len_u32),
            })?;
            if end > buf.len() {
                return Err(NirvanaError::Truncated {
                    needed: len,
                    offset: pos as u64,
                });
            }
            let data = buf[pos..end].to_vec();
            pos = end;
            EventKind::MemWrite { addr, data }
        }
        _ => unreachable!("decode_mem_kind called with non-mem tag"),
    };
    Ok((kind, pos))
}

fn decode_thread_or_break_kind(
    tag: EventTag,
    buf: &[u8],
    mut pos: usize,
    start: usize,
) -> Result<(EventKind, usize), NirvanaError> {
    let kind = match tag {
        EventTag::ThreadCreate => {
            ensure_remaining(buf, pos, 4, start)?;
            let t = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap());
            pos += 4;
            EventKind::ThreadCreate { tid: t }
        }
        EventTag::ThreadExit => {
            ensure_remaining(buf, pos, 8, start)?;
            let t = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap());
            pos += 4;
            let code = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap());
            pos += 4;
            EventKind::ThreadExit { tid: t, code }
        }
        EventTag::Breakpoint => {
            ensure_remaining(buf, pos, 8, start)?;
            let addr = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
            pos += 8;
            EventKind::Breakpoint { addr }
        }
        _ => unreachable!("decode_thread_or_break_kind called with wrong tag"),
    };
    Ok((kind, pos))
}

fn decode_one_kind(
    tag: EventTag,
    buf: &[u8],
    mut pos: usize,
    start: usize,
) -> Result<(EventKind, usize), NirvanaError> {
    let kind = match tag {
            EventTag::MemRead | EventTag::MemWrite => {
                return decode_mem_kind(tag, buf, pos, start);
            }
            EventTag::ThreadCreate | EventTag::ThreadExit | EventTag::Breakpoint => {
                return decode_thread_or_break_kind(tag, buf, pos, start);
            }
            EventTag::Call => {
                if pos + 16 > buf.len() {
                    return Err(NirvanaError::Truncated {
                        needed: 16,
                        offset: start as u64,
                    });
                }
                let from = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
                pos += 8;
                let to = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
                pos += 8;
                EventKind::Call { from, to }
            }
            EventTag::Return => {
                if pos + 16 > buf.len() {
                    return Err(NirvanaError::Truncated {
                        needed: 16,
                        offset: start as u64,
                    });
                }
                let from = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
                pos += 8;
                let to = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
                pos += 8;
                EventKind::Return { from, to }
            }
            EventTag::SyscallEnter => {
                if pos + 52 > buf.len() {
                    return Err(NirvanaError::Truncated {
                        needed: 52,
                        offset: start as u64,
                    });
                }
                let nr = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap());
                pos += 4;
                let mut args = [0u64; 6];
                for a in &mut args {
                    *a = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
                    pos += 8;
                }
                EventKind::SyscallEnter { nr, args }
            }
            EventTag::SyscallExit => {
                if pos + 12 > buf.len() {
                    return Err(NirvanaError::Truncated {
                        needed: 12,
                        offset: start as u64,
                    });
                }
                let nr = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap());
                pos += 4;
                let ret = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
                pos += 8;
                EventKind::SyscallExit { nr, ret }
            }
            EventTag::Exception => {
                if pos + 12 > buf.len() {
                    return Err(NirvanaError::Truncated {
                        needed: 12,
                        offset: start as u64,
                    });
                }
                let code = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap());
                pos += 4;
                let addr = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
                pos += 8;
                EventKind::Exception { code, addr }
            }
        };
    Ok((kind, pos))
}

// ─── Low-level I/O helpers ───────────────────────────────────────────────────

fn write_u16<W: IoWrite>(w: &mut W, v: u16) -> Result<(), NirvanaError> {
    w.write_all(&v.to_le_bytes())?;
    Ok(())
}

fn write_u32<W: IoWrite>(w: &mut W, v: u32) -> Result<(), NirvanaError> {
    w.write_all(&v.to_le_bytes())?;
    Ok(())
}

fn write_u64<W: IoWrite>(w: &mut W, v: u64) -> Result<(), NirvanaError> {
    w.write_all(&v.to_le_bytes())?;
    Ok(())
}

fn read_u16<R: Read>(r: &mut R) -> Result<u16, NirvanaError> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_le_bytes(b))
}

fn read_u32<R: Read>(r: &mut R) -> Result<u32, NirvanaError> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64<R: Read>(r: &mut R) -> Result<u64, NirvanaError> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventKind, TraceEvent, TracePosition, build_test_trace};
    use std::io::Cursor;

    fn call_event(seq: u64) -> TraceEvent {
        TraceEvent {
            position: TracePosition::new(seq, 0),
            thread_id: 1,
            kind: EventKind::Call {
                from: 0x1000,
                to: 0x2000,
            },
        }
    }

    fn mem_write_event(seq: u64, data: Vec<u8>) -> TraceEvent {
        TraceEvent {
            position: TracePosition::new(seq, 0),
            thread_id: 1,
            kind: EventKind::MemWrite { addr: 0x5000, data },
        }
    }

    // ── TtdHeader ────────────────────────────────────────────────────────

    #[test]
    fn test_header_roundtrip() {
        let h = TtdHeader::new("notepad.exe", 1234);
        let bytes = h.to_bytes();
        let h2 = TtdHeader::from_bytes(&bytes).unwrap();
        assert_eq!(h2.magic, TTD_MAGIC);
        assert_eq!(h2.pid, 1234);
        assert_eq!(h2.process_name_str(), "notepad.exe");
    }

    #[test]
    fn test_header_validate_ok() {
        let h = TtdHeader::new("foo", 0);
        assert!(h.validate().is_ok());
    }

    #[test]
    fn test_header_validate_bad_magic() {
        let mut h = TtdHeader::new("foo", 0);
        h.magic = 0xDEAD_BEEF;
        assert!(matches!(h.validate(), Err(NirvanaError::BadMagic { .. })));
    }

    #[test]
    fn test_header_validate_bad_version() {
        let mut h = TtdHeader::new("foo", 0);
        h.version_major = 99;
        assert!(matches!(
            h.validate(),
            Err(NirvanaError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn test_header_process_name_truncation() {
        let long = "a".repeat(200);
        let h = TtdHeader::new(&long, 0);
        let name = h.process_name_str();
        assert!(name.len() <= 63);
    }

    #[test]
    fn test_header_write_read() {
        let h = TtdHeader::new("test.exe", 42);
        let mut buf = Vec::new();
        h.write(&mut buf).unwrap();
        let h2 = TtdHeader::read(&mut Cursor::new(buf)).unwrap();
        assert_eq!(h2.pid, 42);
        assert_eq!(h2.process_name_str(), "test.exe");
    }

    // ── TtdModuleEntry / TtdModuleList ───────────────────────────────────

    #[test]
    fn test_module_entry_contains_addr() {
        let e = TtdModuleEntry::new(0x1000, 0x1000, 0, "ntdll.dll", TracePosition::start());
        assert!(e.contains_addr(0x1000));
        assert!(e.contains_addr(0x1FFF));
        assert!(!e.contains_addr(0x2000));
    }

    #[test]
    fn test_module_file_name() {
        let e = TtdModuleEntry::new(
            0,
            0,
            0,
            r"C:\Windows\System32\ntdll.dll",
            TracePosition::start(),
        );
        assert_eq!(e.file_name(), "ntdll.dll");
    }

    #[test]
    fn test_module_loaded_at() {
        let mut e = TtdModuleEntry::new(0, 0, 0, "foo", TracePosition::new(10, 0));
        e.record_exit(TracePosition::new(100, 0), 0);
        assert!(e.loaded_at(TracePosition::new(50, 0)));
        assert!(!e.loaded_at(TracePosition::new(5, 0)));
        assert!(!e.loaded_at(TracePosition::new(100, 0)));
    }

    #[test]
    fn test_module_list_roundtrip() {
        let mut list = TtdModuleList::new();
        list.add(TtdModuleEntry::new(
            0x0040_0000,
            0x10000,
            0xABCD,
            "app.exe",
            TracePosition::start(),
        ));
        list.add(TtdModuleEntry::new(
            0x7FFF_0000,
            0x80000,
            0,
            "ntdll.dll",
            TracePosition::start(),
        ));
        let mut buf = Vec::new();
        list.write(&mut buf).unwrap();
        let list2 = TtdModuleList::read(&mut Cursor::new(buf)).unwrap();
        assert_eq!(list2.len(), 2);
        assert_eq!(list2.modules[0].base, 0x0040_0000);
        assert_eq!(list2.modules[1].file_name(), "ntdll.dll");
    }

    #[test]
    fn test_module_list_find_by_name() {
        let mut list = TtdModuleList::new();
        list.add(TtdModuleEntry::new(
            0,
            0,
            0,
            "kernel32.dll",
            TracePosition::start(),
        ));
        assert!(list.find_by_name("KERNEL32.DLL").is_some());
        assert!(list.find_by_name("user32.dll").is_none());
    }

    // ── TtdThreadEntry / TtdThreadList ───────────────────────────────────

    #[test]
    fn test_thread_entry_alive() {
        let mut t = TtdThreadEntry::new(0x1A2B, TracePosition::new(5, 0));
        assert!(t.is_alive());
        t.record_exit(TracePosition::new(200, 0), 0);
        assert!(!t.is_alive());
    }

    #[test]
    fn test_thread_list_roundtrip() {
        let mut list = TtdThreadList::new();
        let mut t = TtdThreadEntry::new(1, TracePosition::new(0, 0));
        t.record_exit(TracePosition::new(100, 0), 0);
        list.add(t);
        list.add(TtdThreadEntry::new(2, TracePosition::new(10, 0)));
        let mut buf = Vec::new();
        list.write(&mut buf).unwrap();
        let list2 = TtdThreadList::read(&mut Cursor::new(buf)).unwrap();
        assert_eq!(list2.len(), 2);
        assert!(!list2.threads[0].is_alive());
        assert!(list2.threads[1].is_alive());
    }

    #[test]
    fn test_thread_list_find_by_tid() {
        let mut list = TtdThreadList::new();
        list.add(TtdThreadEntry::new(42, TracePosition::start()));
        assert!(list.find_by_tid(42).is_some());
        assert!(list.find_by_tid(99).is_none());
    }

    // ── TtdPositionMap ───────────────────────────────────────────────────

    #[test]
    fn test_position_map_lookup() {
        let mut map = TtdPositionMap::new();
        map.insert(0, 0);
        map.insert(10, 100);
        map.insert(20, 200);
        assert_eq!(map.offset_for_sequence(0).unwrap(), 0);
        assert_eq!(map.offset_for_sequence(10).unwrap(), 100);
        assert_eq!(map.offset_for_sequence(15).unwrap(), 100); // floor
        assert_eq!(map.offset_for_sequence(20).unwrap(), 200);
    }

    #[test]
    fn test_position_map_not_found() {
        let map = TtdPositionMap::new();
        assert!(matches!(
            map.offset_for_sequence(5),
            Err(NirvanaError::SequenceNotFound { .. })
        ));
    }

    #[test]
    fn test_position_map_roundtrip() {
        let mut map = TtdPositionMap::new();
        for i in 0..50u64 {
            map.insert(i * 10, i * 128);
        }
        let mut buf = Vec::new();
        map.write(&mut buf).unwrap();
        let map2 = TtdPositionMap::read(&mut Cursor::new(buf)).unwrap();
        assert_eq!(map2.len(), 50);
        assert_eq!(map2.offset_for_sequence(490).unwrap(), 49 * 128);
    }

    // ── TtdEventLog ──────────────────────────────────────────────────────

    #[test]
    fn test_event_log_encode_decode_call() {
        let mut log = TtdEventLog::new();
        log.append(&call_event(7));
        let events = log.decode_all().unwrap();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0].kind,
            EventKind::Call {
                from: 0x1000,
                to: 0x2000
            }
        ));
        assert_eq!(events[0].position.sequence, 7);
    }

    #[test]
    fn test_event_log_encode_decode_mem_write() {
        let mut log = TtdEventLog::new();
        log.append(&mem_write_event(3, vec![0xDE, 0xAD]));
        let events = log.decode_all().unwrap();
        assert_eq!(events.len(), 1);
        if let EventKind::MemWrite { data, .. } = &events[0].kind {
            assert_eq!(data, &[0xDE, 0xAD]);
        } else {
            panic!("wrong kind");
        }
    }

    #[test]
    fn test_event_log_roundtrip_multi() {
        let trace = build_test_trace(20);
        let mut log = TtdEventLog::new();
        log.append_all(&trace);
        let events = log.decode_all().unwrap();
        assert_eq!(events.len(), 20);
    }

    #[test]
    fn test_event_log_write_read() {
        let mut log = TtdEventLog::new();
        log.append(&call_event(1));
        log.append(&call_event(2));
        let mut buf = Vec::new();
        log.write(&mut buf).unwrap();
        let log2 = TtdEventLog::read(&mut Cursor::new(buf)).unwrap();
        let events = log2.decode_all().unwrap();
        assert_eq!(events.len(), 2);
    }

    // ── TtdParser ────────────────────────────────────────────────────────

    #[test]
    fn test_parser_roundtrip_small_trace() {
        let trace = build_test_trace(10);
        let modules = TtdModuleList::new();
        let threads = TtdThreadList::new();
        let mut buf = Vec::new();
        let mut cursor = Cursor::new(&mut buf);
        TtdParser::serialize(&trace, &modules, &threads, &mut cursor).unwrap();
        let mut cursor2 = Cursor::new(buf);
        let (hdr, _mods, _thrs, _pos, trace2) = TtdParser::parse(&mut cursor2).unwrap();
        assert_eq!(hdr.process_name_str(), "test");
        assert_eq!(trace2.event_count(), 10);
    }

    #[test]
    fn test_parser_header_magic_validated() {
        let mut buf = vec![0u8; HEADER_SIZE + 8];
        // Bad magic
        buf[0..8].copy_from_slice(&0xDEADu64.to_le_bytes());
        let mut cursor = Cursor::new(buf);
        assert!(TtdParser::parse(&mut cursor).is_err());
    }

    #[test]
    fn test_event_log_syscall_roundtrip() {
        let mut log = TtdEventLog::new();
        let event = TraceEvent {
            position: TracePosition::new(5, 0),
            thread_id: 1,
            kind: EventKind::SyscallEnter {
                nr: 0x3B,
                args: [1, 2, 3, 4, 5, 6],
            },
        };
        log.append(&event);
        let events = log.decode_all().unwrap();
        if let EventKind::SyscallEnter { nr, args } = &events[0].kind {
            assert_eq!(*nr, 0x3B);
            assert_eq!(args[5], 6);
        } else {
            panic!("wrong");
        }
    }

    #[test]
    fn test_event_log_thread_exit_roundtrip() {
        let mut log = TtdEventLog::new();
        let event = TraceEvent {
            position: TracePosition::new(99, 0),
            thread_id: 3,
            kind: EventKind::ThreadExit { tid: 3, code: 42 },
        };
        log.append(&event);
        let events = log.decode_all().unwrap();
        if let EventKind::ThreadExit { code, .. } = events[0].kind {
            assert_eq!(code, 42);
        }
    }

    #[test]
    fn test_position_map_sort() {
        let mut map = TtdPositionMap::new();
        map.insert(30, 300);
        map.insert(10, 100);
        map.insert(20, 200);
        map.sort();
        assert_eq!(map.entries()[0].sequence, 10);
        assert_eq!(map.offset_for_sequence(25).unwrap(), 200);
    }
}
