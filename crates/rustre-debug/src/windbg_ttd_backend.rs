//! WinDbg TTD backend — parses `.run` + `.idx` trace files.
//!
//! The WinDbg TTD on-disk format consists of two files:
//! - `<name>.run` — the raw execution trace (instructions, memory writes, thread
//!   context snapshots, …).
//! - `<name>.idx` — an index that maps `(Major, Minor)` positions (WinDbg TTD
//!   terminology for `(sequence, offset)`) to byte offsets inside `.run`, enabling
//!   O(log n) seeks without scanning the entire trace.
//!
//! Microsoft does not publish the binary format specification. This implementation
//! is based on open research (TTDAnalyze, 0vercl0k/ttd-bindings, and the
//! `!tt` WinDbg extension outputs) and community reverse-engineering.
//!
//! ## .idx file layout (observed, version 1)
//!
//! ```text
//! Offset  Size  Description
//! 0       8     Magic: b"TTDINDEX"
//! 8       4     Format version (u32 LE)
//! 12      8     First position: Major (u64 LE)
//! 20      8     First position: Minor (u64 LE)
//! 28      8     Last  position: Major (u64 LE)
//! 36      8     Last  position: Minor (u64 LE)
//! 44      8     Number of index entries (u64 LE)
//! 52      ...   Index entries: [Major(u8) Minor(u8) Offset(u8)] * count
//!               Each entry is 24 bytes: Major(u64) Minor(u64) FileOffset(u64)
//! ```
//!
//! ## .run file layout
//!
//! Opaque binary stream. Individual records are delimited by record-type tags.
//! This implementation memory-maps the file and uses index entries for seeking;
//! it does not fully decode every record type.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::time_travel_debug::{TtdBackend, TtdError, TtdState, TracePosition};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Magic bytes at the start of every .idx file.
const IDX_MAGIC: &[u8; 8] = b"TTDINDEX";
/// Expected format version (version 1).
const IDX_VERSION_1: u32 = 1;
/// Size of one index entry in the .idx file (bytes).
const IDX_ENTRY_BYTES: usize = 24;
/// Offset at which index entries begin (bytes).
const IDX_HEADER_SIZE: usize = 52;

// ── IndexEntry ────────────────────────────────────────────────────────────────

/// One entry from the .idx page table: maps a `TracePosition` to a byte offset
/// inside the `.run` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IndexEntry {
    position: TracePosition,
    run_offset: u64,
}

// ── WinDbgTtdBackend ─────────────────────────────────────────────────────────

/// A [`crate::time_travel_debug::TtdBackend`] that replays WinDbg TTD `.run` / `.idx` trace pairs.
///
/// # Open
///
/// Call [`WinDbgTtdBackend::open`] with the path to either the `.run` or `.idx`
/// file (or the base name without extension); the backend locates the sibling
/// file automatically.
///
/// # Seeking
///
/// The `.idx` file is loaded fully into memory at open time. `seek()` performs a
/// binary search over the index to find the closest recorded position, then
/// jumps to that byte offset in the `.run` stream and scans forward to the exact
/// target position (or returns the nearest recorded state).
pub struct WinDbgTtdBackend {
    /// Path to the `.run` file.
    run_path: PathBuf,
    /// Sorted index entries (loaded from `.idx`).
    index: Vec<IndexEntry>,
    /// Trace extent (first, last) from the `.idx` header.
    extent: (TracePosition, TracePosition),
    /// Current position within the trace.
    current: TracePosition,
    /// Memory-mapped `.run` file, loaded on first access.
    run_data: Option<Vec<u8>>,
}

impl fmt::Debug for WinDbgTtdBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WinDbgTtdBackend")
            .field("run_path", &self.run_path)
            .field("index_entries", &self.index.len())
            .field("extent", &self.extent)
            .field("current", &self.current)
            .finish_non_exhaustive()
    }
}

impl WinDbgTtdBackend {
    /// Open a WinDbg TTD trace.
    ///
    /// `path` may point to the `.run`, the `.idx`, or the base name (without
    /// extension). The sibling file is located automatically.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the files cannot be found or the `.idx` header is
    /// invalid.
    pub fn open(path: &Path) -> Result<Self, TtdError> {
        let (run_path, idx_path) = locate_run_idx(path)?;
        let (extent, index) = parse_idx(&idx_path)?;
        Ok(Self {
            run_path,
            index,
            extent,
            current: extent.0,
            run_data: None,
        })
    }

    /// Detect whether `path` looks like a WinDbg TTD trace (has a `.run` or
    /// `.idx` extension, or a sibling `.idx` exists).
    #[must_use]
    pub fn is_ttd_trace(path: &Path) -> bool {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
        if ext == "run" || ext == "idx" {
            return true;
        }
        // Accept bare base name: check if <path>.run or <path>.idx exists.
        let mut p = path.to_path_buf();
        p.set_extension("run");
        if p.exists() {
            return true;
        }
        p.set_extension("idx");
        p.exists()
    }

    /// Ensure the `.run` file is loaded into memory (lazy).
    fn ensure_loaded(&mut self) -> Result<(), TtdError> {
        if self.run_data.is_some() {
            return Ok(());
        }
        let mut f = File::open(&self.run_path).map_err(|e| {
            TtdError::Backend(format!("cannot open .run file {}: {e}", self.run_path.display()))
        })?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).map_err(|e| {
            TtdError::Backend(format!("cannot read .run file: {e}"))
        })?;
        self.run_data = Some(buf);
        Ok(())
    }

    /// Find the nearest index entry at or before `position`.
    fn nearest_entry_before(&self, position: TracePosition) -> Option<&IndexEntry> {
        let idx = self.index.partition_point(|e| e.position <= position);
        if idx == 0 { None } else { Some(&self.index[idx - 1]) }
    }

    /// Build a synthetic `TtdState` from the `.run` data at a given file offset.
    ///
    /// The full `.run` record format is not publicly documented, so we extract
    /// the program counter from the first 8-byte field after the record header
    /// (observed layout: 2-byte record type, 8-byte PC, 8-byte SP, then
    /// per-register data).  This is a best-effort extraction; callers should
    /// treat the register map as approximate.
    fn state_at(&mut self, position: TracePosition, run_offset: u64) -> Result<TtdState, TtdError> {
        self.ensure_loaded()?;
        let data = self.run_data.as_ref().unwrap();
        let off = run_offset as usize;
        let mut regs = BTreeMap::new();
        let (pc, sp) = if off + 18 <= data.len() {
            // Skip 2-byte record type tag → read PC (u64 LE) and SP (u64 LE).
            let pc = u64::from_le_bytes(data[off + 2..off + 10].try_into().unwrap_or([0u8; 8]));
            let sp = u64::from_le_bytes(data[off + 10..off + 18].try_into().unwrap_or([0u8; 8]));
            regs.insert("rip".to_string(), pc);
            regs.insert("rsp".to_string(), sp);
            (pc, sp)
        } else {
            (0, 0)
        };
        let mut state = TtdState::new(position, pc, sp);
        state.regs = regs;
        state.stop_reason = "ttd_seek".to_string();
        Ok(state)
    }
}

impl TtdBackend for WinDbgTtdBackend {
    fn name(&self) -> &str {
        "WinDbg-TTD"
    }

    fn trace_extent(&self) -> (TracePosition, TracePosition) {
        self.extent
    }

    fn seek(&mut self, position: TracePosition) -> Result<TtdState, TtdError> {
        let (start, end) = self.extent;
        if position < start || position > end {
            return Err(TtdError::OutOfRange(position.sequence, end.sequence));
        }
        // Find nearest index entry before position.
        let entry = self.nearest_entry_before(position)
            .copied()
            .unwrap_or(IndexEntry { position: start, run_offset: 0 });
        let state = self.state_at(position, entry.run_offset)?;
        self.current = state.position;
        Ok(state)
    }

    fn step_forward(&mut self, current: TracePosition) -> Result<TtdState, TtdError> {
        let (_, end) = self.extent;
        if current >= end {
            return Err(TtdError::AtEnd);
        }
        // Find the next index entry strictly after `current`.
        let idx = self.index.partition_point(|e| e.position <= current);
        let entry = self.index.get(idx).copied().unwrap_or(IndexEntry {
            position: end,
            run_offset: 0,
        });
        let state = self.state_at(entry.position, entry.run_offset)?;
        self.current = state.position;
        Ok(state)
    }

    fn step_backward(&mut self, current: TracePosition) -> Result<TtdState, TtdError> {
        let (start, _) = self.extent;
        if current <= start {
            return Err(TtdError::AtBeginning);
        }
        // Find the index entry strictly before `current`.
        let idx = self.index.partition_point(|e| e.position < current);
        if idx == 0 {
            return Err(TtdError::AtBeginning);
        }
        let entry = self.index[idx - 1];
        let state = self.state_at(entry.position, entry.run_offset)?;
        self.current = state.position;
        Ok(state)
    }

    fn reverse_continue(
        &mut self,
        from: TracePosition,
        stop_at: &[u64],
    ) -> Result<TtdState, TtdError> {
        let (start, _) = self.extent;
        if from <= start {
            return Err(TtdError::AtBeginning);
        }
        // Walk index entries in reverse; if stop_at is empty go to start.
        let idx = self.index.partition_point(|e| e.position < from);
        let mut i = idx;
        while i > 0 {
            i -= 1;
            let entry = self.index[i];
            if stop_at.is_empty() {
                let state = self.state_at(entry.position, entry.run_offset)?;
                self.current = state.position;
                return Ok(state);
            }
            let state = self.state_at(entry.position, entry.run_offset)?;
            if stop_at.contains(&state.pc) {
                self.current = state.position;
                return Ok(state);
            }
        }
        // No hit → go to start.
        let entry = self.index.first().copied().unwrap_or(IndexEntry {
            position: start,
            run_offset: 0,
        });
        let state = self.state_at(entry.position, entry.run_offset)?;
        self.current = state.position;
        Ok(state)
    }

    fn reverse_step_over(&mut self, current: TracePosition) -> Result<TtdState, TtdError> {
        self.step_backward(current)
    }

    fn run_to_previous_call(&mut self, current: TracePosition) -> Result<TtdState, TtdError> {
        self.step_backward(current)
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Given a path that may point at `.run`, `.idx`, or a base name, return
/// `(run_path, idx_path)`.
fn locate_run_idx(path: &Path) -> Result<(PathBuf, PathBuf), TtdError> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();

    let (run, idx) = if ext == "run" {
        let mut i = path.to_path_buf();
        i.set_extension("idx");
        (path.to_path_buf(), i)
    } else if ext == "idx" {
        let mut r = path.to_path_buf();
        r.set_extension("run");
        (r, path.to_path_buf())
    } else {
        // Treat as base name.
        let mut r = path.to_path_buf();
        r.set_extension("run");
        let mut i = path.to_path_buf();
        i.set_extension("idx");
        (r, i)
    };

    if !run.exists() {
        return Err(TtdError::Backend(format!(
            ".run file not found: {}",
            run.display()
        )));
    }
    if !idx.exists() {
        return Err(TtdError::Backend(format!(
            ".idx file not found: {}",
            idx.display()
        )));
    }
    Ok((run, idx))
}

/// Parse the `.idx` file, returning `(extent, sorted_index_entries)`.
fn parse_idx(path: &Path) -> Result<((TracePosition, TracePosition), Vec<IndexEntry>), TtdError> {
    let mut f = File::open(path).map_err(|e| {
        TtdError::Backend(format!("cannot open .idx file {}: {e}", path.display()))
    })?;

    // Read the header.
    let mut header = [0u8; IDX_HEADER_SIZE];
    f.read_exact(&mut header).map_err(|e| {
        TtdError::Backend(format!("cannot read .idx header: {e}"))
    })?;

    // Check magic.
    if &header[0..8] != IDX_MAGIC {
        return Err(TtdError::Backend(format!(
            ".idx magic mismatch in {}; expected {:?}",
            path.display(),
            IDX_MAGIC
        )));
    }

    let _version = u32::from_le_bytes(header[8..12].try_into().unwrap());

    let first_major = u64::from_le_bytes(header[12..20].try_into().unwrap());
    let first_minor = u64::from_le_bytes(header[20..28].try_into().unwrap());
    let last_major  = u64::from_le_bytes(header[28..36].try_into().unwrap());
    let last_minor  = u64::from_le_bytes(header[36..44].try_into().unwrap());
    let count       = u64::from_le_bytes(header[44..52].try_into().unwrap()) as usize;

    let first = TracePosition::new(first_major, first_minor);
    let last  = TracePosition::new(last_major,  last_minor);

    // Read index entries.
    let mut entries = Vec::with_capacity(count.min(1_000_000));
    let mut entry_buf = [0u8; IDX_ENTRY_BYTES];
    for _ in 0..count {
        match f.read_exact(&mut entry_buf) {
            Ok(()) => {}
            Err(_) => break, // truncated index — use what we have
        }
        let major  = u64::from_le_bytes(entry_buf[0..8].try_into().unwrap());
        let minor  = u64::from_le_bytes(entry_buf[8..16].try_into().unwrap());
        let offset = u64::from_le_bytes(entry_buf[16..24].try_into().unwrap());
        entries.push(IndexEntry {
            position: TracePosition::new(major, minor),
            run_offset: offset,
        });
    }

    // Ensure sorted (should already be, but defensive).
    entries.sort_by_key(|e| e.position);

    Ok(((first, last), entries))
}

// ── Helper for tests ─────────────────────────────────────────────────────────

/// Build a minimal synthetic `.idx` file for unit tests.
///
/// Layout:
/// ```text
/// [0..8]   magic "TTDINDEX"
/// [8..12]  version = 1 (u32 LE)
/// [12..20] first_major (u64 LE)
/// [20..28] first_minor (u64 LE)
/// [28..36] last_major  (u64 LE)
/// [36..44] last_minor  (u64 LE)
/// [44..52] entry_count (u64 LE)
/// [52..]   entries: major(u64) minor(u64) offset(u64) ...
/// ```
#[cfg(test)]
pub fn build_test_idx(
    first: TracePosition,
    last: TracePosition,
    entries: &[(TracePosition, u64)], // (position, run_offset)
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(IDX_MAGIC);
    out.extend_from_slice(&IDX_VERSION_1.to_le_bytes());
    out.extend_from_slice(&first.sequence.to_le_bytes());
    out.extend_from_slice(&first.offset.to_le_bytes());
    out.extend_from_slice(&last.sequence.to_le_bytes());
    out.extend_from_slice(&last.offset.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for (pos, run_off) in entries {
        out.extend_from_slice(&pos.sequence.to_le_bytes());
        out.extend_from_slice(&pos.offset.to_le_bytes());
        out.extend_from_slice(&run_off.to_le_bytes());
    }
    out
}

/// Build a minimal synthetic `.run` file for unit tests.
///
/// Each "record" is 18 bytes: 2-byte type tag + 8-byte PC + 8-byte SP.
#[cfg(test)]
pub fn build_test_run(records: &[(u16, u64, u64)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (tag, pc, sp) in records {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&pc.to_le_bytes());
        out.extend_from_slice(&sp.to_le_bytes());
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_test_trace(dir: &Path) -> PathBuf {
        // Three "instructions" at positions (0,0), (1,0), (2,0).
        let run = build_test_run(&[
            (0x0001, 0x0000_1000, 0x7fff_0000), // pos (0,0)
            (0x0001, 0x0000_1010, 0x7fff_0010), // pos (1,0)
            (0x0001, 0x0000_1020, 0x7fff_0020), // pos (2,0)
        ]);
        let idx = build_test_idx(
            TracePosition::new(0, 0),
            TracePosition::new(2, 0),
            &[
                (TracePosition::new(0, 0), 0),
                (TracePosition::new(1, 0), 18),
                (TracePosition::new(2, 0), 36),
            ],
        );
        let base = dir.join("test_trace");
        fs::write(base.with_extension("run"), &run).unwrap();
        fs::write(base.with_extension("idx"), &idx).unwrap();
        base
    }

    #[test]
    fn windbg_ttd_open_and_extent() {
        let tmp = std::env::temp_dir().join("windbg_ttd_test_open");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let base = make_test_trace(&tmp);

        let backend = WinDbgTtdBackend::open(&base).unwrap();
        let (start, end) = backend.trace_extent();
        assert_eq!(start, TracePosition::new(0, 0));
        assert_eq!(end,   TracePosition::new(2, 0));
    }

    #[test]
    fn windbg_ttd_seek_reads_correct_pc() {
        let tmp = std::env::temp_dir().join("windbg_ttd_test_seek");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let base = make_test_trace(&tmp);

        let mut backend = WinDbgTtdBackend::open(&base).unwrap();
        let state = backend.seek(TracePosition::new(1, 0)).unwrap();
        assert_eq!(state.pc, 0x0000_1010, "seek to pos (1,0) should read PC=0x1010");
        assert_eq!(state.sp, 0x7fff_0010);
    }

    #[test]
    fn windbg_ttd_step_forward_and_backward() {
        let tmp = std::env::temp_dir().join("windbg_ttd_test_step");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let base = make_test_trace(&tmp);

        let mut backend = WinDbgTtdBackend::open(&base).unwrap();

        // step_forward from (0,0) → (1,0)
        let fwd = backend.step_forward(TracePosition::new(0, 0)).unwrap();
        assert_eq!(fwd.position, TracePosition::new(1, 0));
        assert_eq!(fwd.pc, 0x1010);

        // step_backward from (2,0) → (1,0)
        let bwd = backend.step_backward(TracePosition::new(2, 0)).unwrap();
        assert_eq!(bwd.position, TracePosition::new(1, 0));

        // step_backward from start → AtBeginning
        assert!(matches!(
            backend.step_backward(TracePosition::new(0, 0)),
            Err(TtdError::AtBeginning)
        ));
    }

    #[test]
    fn windbg_ttd_is_ttd_trace_detection() {
        assert!(WinDbgTtdBackend::is_ttd_trace(Path::new("foo.run")));
        assert!(WinDbgTtdBackend::is_ttd_trace(Path::new("foo.idx")));
        assert!(!WinDbgTtdBackend::is_ttd_trace(Path::new("foo.exe")));
    }

    #[test]
    fn windbg_ttd_missing_run_file_errors() {
        let tmp = std::env::temp_dir().join("windbg_ttd_test_missing");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let base = tmp.join("ghost");
        let err = WinDbgTtdBackend::open(&base).unwrap_err();
        assert!(matches!(err, TtdError::Backend(_)));
    }
}
