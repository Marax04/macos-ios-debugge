//! `rustre-ttd-replay::ttd_format`
//!
//! Binary format structures for `WinDbg` Time-Travel Debugging files.
//!
//! Covers:
//! * `.run` file header — the main recording file with index pointers.
//! * `.idx` file — fast index mapping sequence IDs to file offsets.
//! * Per-record structures: [`ModuleRecord`], [`ThreadRecord`], [`ExceptionRecord`].
//! * [`SequenceId`] / [`ActivityId`] — strongly-typed position tokens.
//! * A pull-style binary parser: [`TtdParser`].
//!
//! All multi-byte fields are **little-endian**, matching the native TTD binary layout.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{Read, Seek, SeekFrom};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── constants ───────────────────────────────────────────────────────────────

/// Magic bytes at the start of every `.run` recording file.
pub const RUN_MAGIC: &[u8; 8] = b"TTDRUN01";

/// Magic bytes at the start of every `.idx` index file.
pub const IDX_MAGIC: &[u8; 8] = b"TTDIDX01";

/// Magic bytes at the start of a `TTD_INDEX` database file.
pub const TTDINDEX_MAGIC: &[u8; 8] = b"TTDDB001";

/// Granularity of index entries (every N instructions).
pub const DEFAULT_INDEX_GRANULARITY: u64 = 4096;

// ─── ParseError ──────────────────────────────────────────────────────────────

/// Errors produced while parsing TTD binary structures.
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("bad magic: expected {expected:?}, got {got:?}")]
    BadMagic { expected: Vec<u8>, got: Vec<u8> },

    #[error("unsupported version {0}")]
    UnsupportedVersion(u32),

    #[error("truncated input at offset {0:#x}")]
    Truncated(u64),

    #[error("record too large: {0} bytes")]
    RecordTooLarge(u64),

    #[error("invalid field: {0}")]
    InvalidField(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("string not UTF-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

// ─── SequenceId ───────────────────────────────────────────────────────────────

/// Strongly-typed sequence-number token corresponding to `seq` in `seq:step`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SequenceId(pub u64);

impl SequenceId {
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }
    pub fn prev(self) -> Option<Self> {
        self.0.checked_sub(1).map(SequenceId)
    }
    #[must_use]
    pub const fn distance(self, other: Self) -> u64 {
        self.0.abs_diff(other.0)
    }
}

impl fmt::Display for SequenceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "seq:{}", self.0)
    }
}

impl From<u64> for SequenceId {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

// ─── ActivityId ───────────────────────────────────────────────────────────────

/// Activity identifier — uniquely identifies an asynchronous activity (coroutine,
/// fiber, or OS thread) inside a TTD recording.  128-bit GUID-like.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActivityId {
    pub hi: u64,
    pub lo: u64,
}

impl ActivityId {
    pub const ZERO: Self = Self { hi: 0, lo: 0 };

    #[must_use]
    pub const fn new(hi: u64, lo: u64) -> Self {
        Self { hi, lo }
    }

    /// Parse from a 16-byte little-endian blob.
    ///
    /// # Panics
    /// Panics if internal invariants are violated.
    #[must_use]
    pub fn from_bytes(b: &[u8; 16]) -> Self {
        Self {
            lo: u64::from_le_bytes(b[0..8].try_into().unwrap()),
            hi: u64::from_le_bytes(b[8..16].try_into().unwrap()),
        }
    }

    #[must_use]
    pub fn to_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..8].copy_from_slice(&self.lo.to_le_bytes());
        out[8..16].copy_from_slice(&self.hi.to_le_bytes());
        out
    }

    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.hi == 0 && self.lo == 0
    }
}

impl fmt::Display for ActivityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}{:016x}", self.hi, self.lo)
    }
}

// ─── RunFileHeader ────────────────────────────────────────────────────────────

/// On-disk header of a `.run` file — 64 bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunFileHeader {
    /// Magic bytes (`TTDRUN01`).
    pub magic: [u8; 8],
    /// Format version — currently 1.
    pub version: u32,
    /// Feature flags (reserved, must be 0 for now).
    pub flags: u32,
    /// Number of threads recorded.
    pub thread_count: u32,
    /// Reserved / padding.
    pub reserved: u32,
    /// Offset in the file where the module table begins.
    pub module_table_offset: u64,
    /// Number of module records.
    pub module_count: u32,
    /// Offset where the thread table begins.
    pub thread_table_offset: u64,
    /// Offset where the exception table begins.
    pub exception_table_offset: u64,
    /// Total instruction count across all threads.
    pub total_instructions: u64,
}

impl RunFileHeader {
    pub const SIZE: usize = 64;

    /// Deserialize from exactly `SIZE` bytes.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// # Panics
    /// Panics if internal invariants are violated.
    pub fn from_bytes(b: &[u8; Self::SIZE]) -> Result<Self, ParseError> {
        let magic: [u8; 8] = b[0..8].try_into().unwrap();
        if &magic != RUN_MAGIC {
            return Err(ParseError::BadMagic {
                expected: RUN_MAGIC.to_vec(),
                got: magic.to_vec(),
            });
        }
        let version = u32::from_le_bytes(b[8..12].try_into().unwrap());
        if version != 1 {
            return Err(ParseError::UnsupportedVersion(version));
        }
        Ok(Self {
            magic,
            version,
            flags: u32::from_le_bytes(b[12..16].try_into().unwrap()),
            thread_count: u32::from_le_bytes(b[16..20].try_into().unwrap()),
            reserved: u32::from_le_bytes(b[20..24].try_into().unwrap()),
            module_table_offset: u64::from_le_bytes(b[24..32].try_into().unwrap()),
            module_count: u32::from_le_bytes(b[32..36].try_into().unwrap()),
            // 4-byte padding at [36..40]
            thread_table_offset: u64::from_le_bytes(b[40..48].try_into().unwrap()),
            exception_table_offset: u64::from_le_bytes(b[48..56].try_into().unwrap()),
            total_instructions: u64::from_le_bytes(b[56..64].try_into().unwrap()),
        })
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[0..8].copy_from_slice(&self.magic);
        out[8..12].copy_from_slice(&self.version.to_le_bytes());
        out[12..16].copy_from_slice(&self.flags.to_le_bytes());
        out[16..20].copy_from_slice(&self.thread_count.to_le_bytes());
        out[20..24].copy_from_slice(&self.reserved.to_le_bytes());
        out[24..32].copy_from_slice(&self.module_table_offset.to_le_bytes());
        out[32..36].copy_from_slice(&self.module_count.to_le_bytes());
        // [36..40] = padding
        out[40..48].copy_from_slice(&self.thread_table_offset.to_le_bytes());
        out[48..56].copy_from_slice(&self.exception_table_offset.to_le_bytes());
        out[56..64].copy_from_slice(&self.total_instructions.to_le_bytes());
        out
    }
}

// ─── IdxFileHeader ────────────────────────────────────────────────────────────

/// On-disk header for a `.idx` file — 48 bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdxFileHeader {
    pub magic: [u8; 8],
    pub version: u32,
    pub flags: u32,
    /// Number of index entries.
    pub entry_count: u64,
    /// Granularity — one entry every N instructions.
    pub granularity: u64,
    /// Offset of the first index entry.
    pub entries_offset: u64,
}

impl IdxFileHeader {
    pub const SIZE: usize = 40;

    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// # Panics
    /// Panics if internal invariants are violated.
    pub fn from_bytes(b: &[u8; Self::SIZE]) -> Result<Self, ParseError> {
        let magic: [u8; 8] = b[0..8].try_into().unwrap();
        if &magic != IDX_MAGIC {
            return Err(ParseError::BadMagic {
                expected: IDX_MAGIC.to_vec(),
                got: magic.to_vec(),
            });
        }
        let version = u32::from_le_bytes(b[8..12].try_into().unwrap());
        if version != 1 {
            return Err(ParseError::UnsupportedVersion(version));
        }
        Ok(Self {
            magic,
            version,
            flags: u32::from_le_bytes(b[12..16].try_into().unwrap()),
            entry_count: u64::from_le_bytes(b[16..24].try_into().unwrap()),
            granularity: u64::from_le_bytes(b[24..32].try_into().unwrap()),
            entries_offset: u64::from_le_bytes(b[32..40].try_into().unwrap()),
        })
    }
}

// ─── IdxEntry ─────────────────────────────────────────────────────────────────

/// A single entry in an `.idx` file: maps a sequence number to a byte offset in the `.run` file.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct IdxEntry {
    pub sequence: SequenceId,
    /// Absolute byte offset inside the `.run` file.
    pub run_file_offset: u64,
}

impl IdxEntry {
    pub const SIZE: usize = 16;

    ///
    /// # Panics
    /// Panics if internal invariants are violated.
    #[must_use]
    pub fn from_bytes(b: &[u8; Self::SIZE]) -> Self {
        Self {
            sequence: SequenceId(u64::from_le_bytes(b[0..8].try_into().unwrap())),
            run_file_offset: u64::from_le_bytes(b[8..16].try_into().unwrap()),
        }
    }

    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[0..8].copy_from_slice(&self.sequence.0.to_le_bytes());
        out[8..16].copy_from_slice(&self.run_file_offset.to_le_bytes());
        out
    }
}

// ─── ModuleRecord ─────────────────────────────────────────────────────────────

/// A loaded module recorded in the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleRecord {
    /// Base load address.
    pub base_address: u64,
    /// Size of the image in bytes.
    pub image_size: u32,
    /// PE `TimeDateStamp`.
    pub timestamp: u32,
    /// PE `SizeOfImage` checksum (optional).
    pub checksum: u32,
    /// Module load sequence position.
    pub load_sequence: SequenceId,
    /// Module unload sequence position (0 = still loaded at end).
    pub unload_sequence: SequenceId,
    /// Full path to the module on disk.
    pub path: String,
}

impl ModuleRecord {
    /// Fixed-size portion before the variable-length `path` string.
    pub const FIXED_SIZE: usize = 44;

    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// # Panics
    /// Panics if internal invariants are violated.
    pub fn parse<R: Read>(r: &mut R) -> Result<Self, ParseError> {
        let mut fixed = [0u8; Self::FIXED_SIZE];
        r.read_exact(&mut fixed)?;

        let base_address = u64::from_le_bytes(fixed[0..8].try_into().unwrap());
        let image_size = u32::from_le_bytes(fixed[8..12].try_into().unwrap());
        let timestamp = u32::from_le_bytes(fixed[12..16].try_into().unwrap());
        let checksum = u32::from_le_bytes(fixed[16..20].try_into().unwrap());
        // 4 bytes padding at [20..24]
        let load_sequence = SequenceId(u64::from_le_bytes(fixed[24..32].try_into().unwrap()));
        let unload_sequence = SequenceId(u64::from_le_bytes(fixed[32..40].try_into().unwrap()));
        let path_len = u32::from_le_bytes(fixed[40..44].try_into().unwrap()) as usize;

        if path_len > 32768 {
            return Err(ParseError::RecordTooLarge(path_len as u64));
        }
        let mut path_bytes = vec![0u8; path_len];
        r.read_exact(&mut path_bytes)?;
        let path = String::from_utf8(path_bytes)?;

        Ok(Self {
            base_address,
            image_size,
            timestamp,
            checksum,
            load_sequence,
            unload_sequence,
            path,
        })
    }

    /// Virtual address range `[base, base + image_size)`.
    #[must_use]
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base_address
            && addr < self.base_address.saturating_add(u64::from(self.image_size))
    }

    /// RVA of `addr` within this module.
    #[must_use]
    pub fn rva_of(&self, addr: u64) -> Option<u32> {
        if self.contains(addr) {
            Some(u32::try_from(addr - self.base_address).unwrap_or(u32::MAX))
        } else {
            None
        }
    }
}

impl fmt::Display for ModuleRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Module[{:#x}+{:#x}] {}",
            self.base_address, self.image_size, self.path
        )
    }
}

// ─── ThreadRecord ─────────────────────────────────────────────────────────────

/// A thread recorded in the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadRecord {
    /// OS thread ID.
    pub tid: u32,
    /// OS process ID (for process-wide replay sessions spanning children).
    pub pid: u32,
    /// `ActivityId` that corresponds to this thread.
    pub activity_id: ActivityId,
    /// Sequence at which the thread was created (or 0 for main thread).
    pub create_sequence: SequenceId,
    /// Sequence at which the thread exited (or 0 if still alive).
    pub exit_sequence: SequenceId,
    /// Thread exit code, if known.
    pub exit_code: u32,
    /// Initial value of the stack-pointer (TEB stack base).
    pub stack_base: u64,
    /// Stack limit (grows down; lowest valid RSP).
    pub stack_limit: u64,
}

impl ThreadRecord {
    pub const SIZE: usize = 72;

    ///
    /// # Panics
    /// Panics if internal invariants are violated.
    #[must_use]
    pub fn from_bytes(b: &[u8; Self::SIZE]) -> Self {
        let mut act_bytes = [0u8; 16];
        act_bytes.copy_from_slice(&b[8..24]);
        Self {
            tid: u32::from_le_bytes(b[0..4].try_into().unwrap()),
            pid: u32::from_le_bytes(b[4..8].try_into().unwrap()),
            activity_id: ActivityId::from_bytes(&act_bytes),
            create_sequence: SequenceId(u64::from_le_bytes(b[24..32].try_into().unwrap())),
            exit_sequence: SequenceId(u64::from_le_bytes(b[32..40].try_into().unwrap())),
            exit_code: u32::from_le_bytes(b[40..44].try_into().unwrap()),
            // [44..48] padding
            stack_base: u64::from_le_bytes(b[48..56].try_into().unwrap()),
            stack_limit: u64::from_le_bytes(b[56..64].try_into().unwrap()),
        }
    }

    #[must_use]
    pub fn is_alive_at(&self, seq: SequenceId) -> bool {
        seq >= self.create_sequence && (self.exit_sequence.0 == 0 || seq < self.exit_sequence)
    }
}

impl fmt::Display for ThreadRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Thread[tid={}, pid={}, created@{}, exited@{}]",
            self.tid, self.pid, self.create_sequence, self.exit_sequence
        )
    }
}

// ─── ExceptionRecord ──────────────────────────────────────────────────────────

/// An exception recorded in the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionRecord {
    /// OS exception code (e.g. `0xC0000005` = access violation).
    pub code: u32,
    /// OS exception flags.
    pub flags: u32,
    /// Address that raised the exception.
    pub address: u64,
    /// Number of exception parameters (up to 15).
    pub param_count: u32,
    /// Exception parameters.
    pub params: Vec<u64>,
    /// Thread that raised the exception.
    pub tid: u32,
    /// Replay position of the exception.
    pub sequence: SequenceId,
}

impl ExceptionRecord {
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// # Panics
    /// Panics if internal invariants are violated.
    pub fn parse<R: Read>(r: &mut R) -> Result<Self, ParseError> {
        let mut fixed = [0u8; 32];
        r.read_exact(&mut fixed)?;

        let code = u32::from_le_bytes(fixed[0..4].try_into().unwrap());
        let flags = u32::from_le_bytes(fixed[4..8].try_into().unwrap());
        let address = u64::from_le_bytes(fixed[8..16].try_into().unwrap());
        let param_count = u32::from_le_bytes(fixed[16..20].try_into().unwrap());
        let tid = u32::from_le_bytes(fixed[20..24].try_into().unwrap());
        let sequence = SequenceId(u64::from_le_bytes(fixed[24..32].try_into().unwrap()));

        let n = (param_count as usize).min(15);
        let mut params = Vec::with_capacity(n);
        for _ in 0..n {
            let mut buf = [0u8; 8];
            r.read_exact(&mut buf)?;
            params.push(u64::from_le_bytes(buf));
        }
        Ok(Self {
            code,
            flags,
            address,
            param_count,
            params,
            tid,
            sequence,
        })
    }

    /// Whether this is a first-chance exception.
    #[must_use]
    pub const fn is_first_chance(&self) -> bool {
        self.flags & 0x1 == 0
    }

    /// Human-readable name for common Windows exception codes.
    #[must_use]
    pub const fn code_name(&self) -> &'static str {
        match self.code {
            0xC000_0005 => "EXCEPTION_ACCESS_VIOLATION",
            0xC000_0094 => "EXCEPTION_INT_DIVIDE_BY_ZERO",
            0xC000_0095 => "EXCEPTION_INT_OVERFLOW",
            0x8000_0003 => "EXCEPTION_BREAKPOINT",
            0x8000_0004 => "EXCEPTION_SINGLE_STEP",
            0xC000_0096 => "EXCEPTION_PRIV_INSTRUCTION",
            0xC000_001D => "EXCEPTION_ILLEGAL_INSTRUCTION",
            0xC000_0025 => "EXCEPTION_NONCONTINUABLE",
            0xC000_0026 => "EXCEPTION_INVALID_DISPOSITION",
            0xC000_008C => "EXCEPTION_ARRAY_BOUNDS_EXCEEDED",
            0xC000_008F => "EXCEPTION_FLT_DENORMAL_OPERAND",
            0xC000_0090 => "EXCEPTION_FLT_DIVIDE_BY_ZERO",
            0xC000_0091 => "EXCEPTION_FLT_INEXACT_RESULT",
            0xC000_0092 => "EXCEPTION_FLT_INVALID_OPERATION",
            0xC000_0093 => "EXCEPTION_FLT_OVERFLOW",
            0xC000_0097 => "EXCEPTION_FLT_STACK_CHECK",
            0xC000_0098 => "EXCEPTION_FLT_UNDERFLOW",
            0x4001_0005 => "DBG_CONTROL_C",
            _ => "UNKNOWN_EXCEPTION",
        }
    }
}

impl fmt::Display for ExceptionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Exception[{:#010x}={} @ {:#x}, tid={}, seq={}]",
            self.code,
            self.code_name(),
            self.address,
            self.tid,
            self.sequence
        )
    }
}

// ─── TtdIndex ─────────────────────────────────────────────────────────────────

/// In-memory representation of the combined TTD index built from `.run` + `.idx`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtdIndex {
    /// Ordered map: sequence → file offset in the `.run` stream.
    pub entries: BTreeMap<SequenceId, u64>,
    /// Granularity used when building the index.
    pub granularity: u64,
    /// Total instruction count.
    pub total_instructions: u64,
}

impl TtdIndex {
    #[must_use]
    pub const fn new(granularity: u64, total_instructions: u64) -> Self {
        Self {
            entries: BTreeMap::new(),
            granularity,
            total_instructions,
        }
    }

    /// Insert an entry.
    pub fn insert(&mut self, seq: SequenceId, offset: u64) {
        self.entries.insert(seq, offset);
    }

    /// Find the largest sequence whose offset is `<= seq`.
    #[must_use]
    pub fn lookup_le(&self, seq: SequenceId) -> Option<(SequenceId, u64)> {
        self.entries
            .range(..=seq)
            .next_back()
            .map(|(&s, &o)| (s, o))
    }

    /// Find the smallest sequence whose offset is `>= seq`.
    #[must_use]
    pub fn lookup_ge(&self, seq: SequenceId) -> Option<(SequenceId, u64)> {
        self.entries.range(seq..).next().map(|(&s, &o)| (s, o))
    }

    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Estimate file offset for an arbitrary sequence, by linear interpolation
    /// between adjacent index entries.
    #[must_use]
    pub fn estimate_offset(&self, seq: SequenceId) -> Option<u64> {
        let (lo_seq, lo_off) = self.lookup_le(seq)?;
        if lo_seq == seq {
            return Some(lo_off);
        }
        if let Some((hi_seq, hi_off)) = self.lookup_ge(seq) {
            let range = hi_seq.0.saturating_sub(lo_seq.0);
            if range == 0 {
                return Some(lo_off);
            }
            let frac = seq.0.saturating_sub(lo_seq.0) as f64 / range as f64;
            let delta = ((hi_off as f64 - lo_off as f64) * frac) as u64;
            Some(lo_off.saturating_add(delta))
        } else {
            Some(lo_off)
        }
    }
}

impl fmt::Display for TtdIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TtdIndex[{} entries, granularity={}, total_instr={}]",
            self.entries.len(),
            self.granularity,
            self.total_instructions
        )
    }
}

// ─── RunFile ──────────────────────────────────────────────────────────────────

/// Complete parsed contents of a `.run` recording file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunFile {
    pub header: RunFileHeader,
    pub modules: Vec<ModuleRecord>,
    pub threads: Vec<ThreadRecord>,
    pub exceptions: Vec<ExceptionRecord>,
}

impl RunFile {
    /// Create an empty `RunFile` with the given header defaults.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            header: RunFileHeader {
                magic: *RUN_MAGIC,
                version: 1,
                flags: 0,
                thread_count: 0,
                reserved: 0,
                module_table_offset: RunFileHeader::SIZE as u64,
                module_count: 0,
                thread_table_offset: RunFileHeader::SIZE as u64,
                exception_table_offset: RunFileHeader::SIZE as u64,
                total_instructions: 0,
            },
            modules: Vec::new(),
            threads: Vec::new(),
            exceptions: Vec::new(),
        }
    }

    /// Find the module that contains `addr` at sequence `seq`.
    #[must_use]
    pub fn module_at(&self, addr: u64, seq: SequenceId) -> Option<&ModuleRecord> {
        self.modules.iter().find(|m| {
            m.contains(addr)
                && seq >= m.load_sequence
                && (m.unload_sequence.0 == 0 || seq < m.unload_sequence)
        })
    }

    /// Find a thread by OS TID.
    #[must_use]
    pub fn thread_by_tid(&self, tid: u32) -> Option<&ThreadRecord> {
        self.threads.iter().find(|t| t.tid == tid)
    }

    /// Return all exceptions for a given thread.
    #[must_use]
    pub fn exceptions_for_thread(&self, tid: u32) -> Vec<&ExceptionRecord> {
        self.exceptions.iter().filter(|e| e.tid == tid).collect()
    }

    /// Number of live threads at sequence `seq`.
    #[must_use]
    pub fn live_thread_count(&self, seq: SequenceId) -> usize {
        self.threads.iter().filter(|t| t.is_alive_at(seq)).count()
    }
}

impl fmt::Display for RunFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RunFile[v{}, {} modules, {} threads, {} exceptions, total_instr={}]",
            self.header.version,
            self.modules.len(),
            self.threads.len(),
            self.exceptions.len(),
            self.header.total_instructions
        )
    }
}

// ─── TtdParser ────────────────────────────────────────────────────────────────

/// Pull-style parser for TTD binary data.
pub struct TtdParser<R: Read + Seek> {
    inner: R,
    pos: u64,
}

impl<R: Read + Seek> TtdParser<R> {
    pub const fn new(inner: R) -> Self {
        Self { inner, pos: 0 }
    }

    pub const fn position(&self) -> u64 {
        self.pos
    }

    fn read_bytes(&mut self, buf: &mut [u8]) -> Result<(), ParseError> {
        self.inner.read_exact(buf).map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                ParseError::Truncated(self.pos)
            } else {
                ParseError::Io(e)
            }
        })?;
        self.pos += buf.len() as u64;
        Ok(())
    }

    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn read_u32(&mut self) -> Result<u32, ParseError> {
        let mut b = [0u8; 4];
        self.read_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn read_u64(&mut self) -> Result<u64, ParseError> {
        let mut b = [0u8; 8];
        self.read_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn seek_to(&mut self, offset: u64) -> Result<(), ParseError> {
        self.inner.seek(SeekFrom::Start(offset))?;
        self.pos = offset;
        Ok(())
    }

    /// Parse the `.run` file header.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse_run_header(&mut self) -> Result<RunFileHeader, ParseError> {
        let mut buf = [0u8; RunFileHeader::SIZE];
        self.read_bytes(&mut buf)?;
        RunFileHeader::from_bytes(&buf)
    }

    /// Parse the `.idx` file header.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse_idx_header(&mut self) -> Result<IdxFileHeader, ParseError> {
        let mut buf = [0u8; IdxFileHeader::SIZE];
        self.read_bytes(&mut buf)?;
        IdxFileHeader::from_bytes(&buf)
    }

    /// Parse `count` index entries starting at the current position.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse_idx_entries(&mut self, count: u64) -> Result<Vec<IdxEntry>, ParseError> {
        // Guard: more than 64M index entries is almost certainly corrupt data.
        if count > 64_000_000 {
            return Err(ParseError::RecordTooLarge(count));
        }
        let n = usize::try_from(count)
            .map_err(|_| ParseError::RecordTooLarge(count))?;
        let mut entries = Vec::with_capacity(n);
        for _ in 0..n {
            let mut buf = [0u8; IdxEntry::SIZE];
            self.read_bytes(&mut buf)?;
            entries.push(IdxEntry::from_bytes(&buf));
        }
        Ok(entries)
    }

    /// Parse `count` thread records.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse_thread_records(&mut self, count: u32) -> Result<Vec<ThreadRecord>, ParseError> {
        // Guard: more than 1M threads is almost certainly corrupt data.
        if count > 1_000_000 {
            return Err(ParseError::RecordTooLarge(u64::from(count)));
        }
        let mut threads = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let mut buf = [0u8; ThreadRecord::SIZE];
            self.read_bytes(&mut buf)?;
            threads.push(ThreadRecord::from_bytes(&buf));
        }
        Ok(threads)
    }

    /// Parse a module record (variable length).
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse_module_record(&mut self) -> Result<ModuleRecord, ParseError> {
        ModuleRecord::parse(&mut self.inner)
    }

    /// Parse an exception record (variable length).
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse_exception_record(&mut self) -> Result<ExceptionRecord, ParseError> {
        ExceptionRecord::parse(&mut self.inner)
    }

    /// Load a complete `.idx` file and build a [`TtdIndex`].
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn load_idx_file(&mut self, total_instructions: u64) -> Result<TtdIndex, ParseError> {
        self.seek_to(0)?;
        let hdr = self.parse_idx_header()?;
        self.seek_to(hdr.entries_offset)?;
        let raw = self.parse_idx_entries(hdr.entry_count)?;
        let mut idx = TtdIndex::new(hdr.granularity, total_instructions);
        for e in raw {
            idx.insert(e.sequence, e.run_file_offset);
        }
        Ok(idx)
    }
}

// ─── helpers ──────────────────────────────────────────────────────────────────

/// Decode a Windows FILETIME (100-ns intervals since 1601-01-01) to Unix
/// milliseconds.  Useful for correlating trace timestamps.
#[must_use]
pub fn filetime_to_unix_ms(filetime: u64) -> i64 {
    // 11644473600 seconds between epochs
    const EPOCH_DELTA_SECS: u64 = 11_644_473_600;
    let secs = filetime / 10_000_000;
    if secs < EPOCH_DELTA_SECS {
        return 0;
    }
    // secs - EPOCH_DELTA_SECS is guaranteed non-negative by the early return above.
    // Cast to i64 safely; saturate if the result would overflow i64 milliseconds.
    let unix_secs_u64 = secs - EPOCH_DELTA_SECS;
    // i64::MAX / 1000 ≈ 9.2 × 10^15 seconds (year ~292 million) — clip there.
    if unix_secs_u64 > (i64::MAX / 1000) as u64 {
        return i64::MAX;
    }
    let unix_secs = i64::try_from(unix_secs_u64).unwrap_or(i64::MAX);
    let sub_ms = i64::try_from((filetime % 10_000_000) / 10_000).unwrap_or(i64::MAX);
    unix_secs.saturating_mul(1000).saturating_add(sub_ms)
}

/// Round `seq` down to the nearest multiple of `granularity`.
#[must_use]
pub const fn align_to_granularity(seq: SequenceId, granularity: u64) -> SequenceId {
    if granularity == 0 {
        return seq;
    }
    SequenceId((seq.0 / granularity) * granularity)
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_run_header_bytes() -> [u8; RunFileHeader::SIZE] {
        let mut b = [0u8; RunFileHeader::SIZE];
        b[0..8].copy_from_slice(RUN_MAGIC);
        b[8..12].copy_from_slice(&1u32.to_le_bytes()); // version
        b[16..20].copy_from_slice(&2u32.to_le_bytes()); // thread_count
        b[24..32].copy_from_slice(&64u64.to_le_bytes()); // module_table_offset
        b[32..36].copy_from_slice(&1u32.to_le_bytes()); // module_count
        b[40..48].copy_from_slice(&128u64.to_le_bytes()); // thread_table_offset
        b[48..56].copy_from_slice(&256u64.to_le_bytes()); // exception_table_offset
        b[56..64].copy_from_slice(&100_000_u64.to_le_bytes()); // total_instructions
        b
    }

    #[test]
    fn run_header_roundtrip() {
        let bytes = make_run_header_bytes();
        let hdr = RunFileHeader::from_bytes(&bytes).unwrap();
        assert_eq!(&hdr.magic, RUN_MAGIC);
        assert_eq!(hdr.version, 1);
        assert_eq!(hdr.thread_count, 2);
        assert_eq!(hdr.total_instructions, 100_000);
        let rt = hdr.to_bytes();
        assert_eq!(&rt[..], &bytes[..]);
    }

    #[test]
    fn run_header_bad_magic() {
        let mut b = [0u8; RunFileHeader::SIZE];
        b[0..8].copy_from_slice(b"BADBADBA");
        b[8..12].copy_from_slice(&1u32.to_le_bytes());
        let r = RunFileHeader::from_bytes(&b);
        assert!(matches!(r, Err(ParseError::BadMagic { .. })));
    }

    #[test]
    fn run_header_bad_version() {
        let mut b = make_run_header_bytes();
        b[8..12].copy_from_slice(&99u32.to_le_bytes());
        let r = RunFileHeader::from_bytes(&b);
        assert!(matches!(r, Err(ParseError::UnsupportedVersion(99))));
    }

    #[test]
    fn sequence_id_ops() {
        let s = SequenceId(10);
        assert_eq!(s.next(), SequenceId(11));
        assert_eq!(s.prev(), Some(SequenceId(9)));
        assert_eq!(SequenceId(0).prev(), None);
        assert_eq!(s.distance(SequenceId(3)), 7);
        assert!(s.to_string().contains("10"));
    }

    #[test]
    fn activity_id_roundtrip() {
        let id = ActivityId::new(0xDEAD_BEEF, 0xCAFE_BABE);
        let bytes = id.to_bytes();
        let id2 = ActivityId::from_bytes(&bytes);
        assert_eq!(id, id2);
    }

    #[test]
    fn activity_id_zero() {
        assert!(ActivityId::ZERO.is_zero());
        assert!(!ActivityId::new(1, 0).is_zero());
    }

    #[test]
    fn idx_entry_roundtrip() {
        let e = IdxEntry {
            sequence: SequenceId(1234),
            run_file_offset: 0xABCD_EF01,
        };
        let bytes = e.to_bytes();
        let e2 = IdxEntry::from_bytes(&bytes);
        assert_eq!(e2.sequence, e.sequence);
        assert_eq!(e2.run_file_offset, e.run_file_offset);
    }

    #[test]
    fn ttd_index_lookup() {
        let mut idx = TtdIndex::new(1000, 50000);
        idx.insert(SequenceId(0), 0);
        idx.insert(SequenceId(1000), 4096);
        idx.insert(SequenceId(2000), 8192);

        let (s, o) = idx.lookup_le(SequenceId(1500)).unwrap();
        assert_eq!(s, SequenceId(1000));
        assert_eq!(o, 4096);

        let (s2, o2) = idx.lookup_ge(SequenceId(1500)).unwrap();
        assert_eq!(s2, SequenceId(2000));
        assert_eq!(o2, 8192);
    }

    #[test]
    fn ttd_index_estimate_offset() {
        let mut idx = TtdIndex::new(1000, 10000);
        idx.insert(SequenceId(0), 0);
        idx.insert(SequenceId(1000), 10000);
        // Midpoint should be ~5000
        let est = idx.estimate_offset(SequenceId(500)).unwrap();
        assert!((4000..=6000).contains(&est), "estimate={est}");
    }

    #[test]
    fn ttd_index_display() {
        let idx = TtdIndex::new(4096, 100_000);
        assert!(idx.to_string().contains("TtdIndex"));
    }

    #[test]
    fn module_record_contains_and_rva() {
        let m = ModuleRecord {
            base_address: 0x10000,
            image_size: 0x5000,
            timestamp: 0,
            checksum: 0,
            load_sequence: SequenceId(0),
            unload_sequence: SequenceId(0),
            path: "test.dll".into(),
        };
        assert!(m.contains(0x12000));
        assert!(!m.contains(0x20000));
        assert_eq!(m.rva_of(0x12000), Some(0x2000));
        assert_eq!(m.rva_of(0x1), None);
        assert!(m.to_string().contains("test.dll"));
    }

    #[test]
    fn thread_record_is_alive_at() {
        let t = ThreadRecord {
            tid: 1,
            pid: 100,
            activity_id: ActivityId::ZERO,
            create_sequence: SequenceId(10),
            exit_sequence: SequenceId(50),
            exit_code: 0,
            stack_base: 0,
            stack_limit: 0,
        };
        assert!(t.is_alive_at(SequenceId(20)));
        assert!(!t.is_alive_at(SequenceId(5)));
        assert!(!t.is_alive_at(SequenceId(50)));
    }

    #[test]
    fn thread_record_display() {
        let t = ThreadRecord {
            tid: 99,
            pid: 1,
            activity_id: ActivityId::ZERO,
            create_sequence: SequenceId(0),
            exit_sequence: SequenceId(0),
            exit_code: 0,
            stack_base: 0,
            stack_limit: 0,
        };
        assert!(t.to_string().contains("99"));
    }

    #[test]
    fn exception_code_name() {
        let mut buf = [0u8; 40];
        buf[0..4].copy_from_slice(&0xC000_0005_u32.to_le_bytes()); // code
        let exc = ExceptionRecord::parse(&mut std::io::Cursor::new(&buf[..])).unwrap();
        assert_eq!(exc.code_name(), "EXCEPTION_ACCESS_VIOLATION");
    }

    #[test]
    fn exception_display() {
        let exc = ExceptionRecord {
            code: 0xC000_0005,
            flags: 0,
            address: 0xDEAD,
            param_count: 0,
            params: vec![],
            tid: 1,
            sequence: SequenceId(42),
        };
        assert!(exc.to_string().contains("EXCEPTION_ACCESS_VIOLATION"));
    }

    #[test]
    fn run_file_module_at() {
        let mut rf = RunFile::empty();
        rf.modules.push(ModuleRecord {
            base_address: 0x10000,
            image_size: 0x1000,
            timestamp: 0,
            checksum: 0,
            load_sequence: SequenceId(0),
            unload_sequence: SequenceId(0),
            path: "foo.dll".into(),
        });
        assert!(rf.module_at(0x10500, SequenceId(100)).is_some());
        assert!(rf.module_at(0x20000, SequenceId(100)).is_none());
    }

    #[test]
    fn run_file_live_thread_count() {
        let mut rf = RunFile::empty();
        rf.threads.push(ThreadRecord {
            tid: 1,
            pid: 1,
            activity_id: ActivityId::ZERO,
            create_sequence: SequenceId(0),
            exit_sequence: SequenceId(100),
            exit_code: 0,
            stack_base: 0,
            stack_limit: 0,
        });
        rf.threads.push(ThreadRecord {
            tid: 2,
            pid: 1,
            activity_id: ActivityId::ZERO,
            create_sequence: SequenceId(50),
            exit_sequence: SequenceId(0),
            exit_code: 0,
            stack_base: 0,
            stack_limit: 0,
        });
        assert_eq!(rf.live_thread_count(SequenceId(30)), 1);
        assert_eq!(rf.live_thread_count(SequenceId(70)), 2);
    }

    #[test]
    fn filetime_conversion() {
        // Windows epoch for 2000-01-01 = 125911584000000000
        let ms = filetime_to_unix_ms(125_911_584_000_000_000);
        assert_eq!(ms, 946_684_800_000i64); // 2000-01-01 00:00:00 UTC in ms
    }

    #[test]
    fn align_to_granularity_basic() {
        let s = align_to_granularity(SequenceId(4500), 1000);
        assert_eq!(s, SequenceId(4000));
        let s2 = align_to_granularity(SequenceId(4000), 1000);
        assert_eq!(s2, SequenceId(4000));
    }

    #[test]
    fn ttd_parser_run_header() {
        let hdr_bytes = make_run_header_bytes();
        let cursor = Cursor::new(hdr_bytes.to_vec());
        let mut parser = TtdParser::new(cursor);
        let hdr = parser.parse_run_header().unwrap();
        assert_eq!(hdr.version, 1);
        assert_eq!(parser.position(), RunFileHeader::SIZE as u64);
    }
}
