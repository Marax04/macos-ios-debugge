//! `hot_patch` — Apply patches to a running process at runtime, collaborating
//! with `rustre-debug` (or any other implementation of [`RuntimeMemoryWriter`]).
//!
//! `rustre-patch` deliberately has no dependency on `rustre-debug` — instead,
//! the debug crate (or a test harness) supplies an implementation of the
//! [`RuntimeMemoryWriter`] trait. This keeps the dependency graph one-way:
//! `rustre-debug -> rustre-patch`.

use std::collections::HashMap;
use std::fmt;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::Patch;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by runtime hot-patching.
#[derive(Debug, Error)]
pub enum HotPatchError {
    /// The memory writer reported a failure.
    #[error("memory writer error at {address:#x}: {message}")]
    Writer { address: u64, message: String },
    /// The bytes read from the target did not match the patch's expected originals.
    #[error("verification failed at {address:#x}: expected {expected} bytes, got {got} bytes")]
    Verification { address: u64, expected: usize, got: usize },
    /// The expected original bytes differ from those read from the target.
    #[error("original bytes mismatch at {address:#x}")]
    OriginalMismatch { address: u64 },
    /// No backup exists for the requested patch id.
    #[error("no live patch with id '{0}'")]
    NotFound(String),
    /// A patch with this id is already live.
    #[error("patch '{0}' is already live")]
    AlreadyLive(String),
}

// ---------------------------------------------------------------------------
// Memory writer trait
// ---------------------------------------------------------------------------

/// Bridge between `rustre-patch` and an actual process-memory implementation
/// (typically provided by `rustre-debug` adapters such as ptrace, `WriteProcessMemory`,
/// or a Frida script).
pub trait RuntimeMemoryWriter: Send + Sync {
    /// Read `len` bytes from `address` in the target process.
    ///
    /// # Errors
    ///
    /// Returns an implementation-specific error string when the read fails.
    fn read(&self, address: u64, len: usize) -> Result<Vec<u8>, String>;
    /// Write `data` to `address` in the target process.
    ///
    /// # Errors
    ///
    /// Returns an implementation-specific error string when the write fails.
    fn write(&self, address: u64, data: &[u8]) -> Result<(), String>;
    /// Optionally flush the instruction cache for the modified region. Default is a no-op.
    ///
    /// # Errors
    ///
    /// Returns an implementation-specific error string when the flush fails.
    fn flush_icache(&self, _address: u64, _len: usize) -> Result<(), String> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Live patch record
// ---------------------------------------------------------------------------

/// Metadata recorded for a patch that is currently live in the target process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivePatch {
    /// Patch id (matches [`Patch::id`]).
    pub id: String,
    /// Runtime address where the patch was written.
    pub address: u64,
    /// Original bytes captured from the live process before patching.
    pub captured_original: Vec<u8>,
    /// Bytes that were written by the patch.
    pub written_bytes: Vec<u8>,
}

impl fmt::Display for LivePatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LivePatch[{}] @{:#x} ({} bytes)",
            self.id,
            self.address,
            self.written_bytes.len()
        )
    }
}

// ---------------------------------------------------------------------------
// HotPatcher
// ---------------------------------------------------------------------------

/// Manages a set of patches applied to a live process.
///
/// The patcher is the sole owner of the runtime backup: every successful
/// [`HotPatcher::apply`] stores the captured original so that
/// [`HotPatcher::revert`] can reliably restore it later, even if the original
/// [`Patch`] no longer exists.
pub struct HotPatcher<W: RuntimeMemoryWriter> {
    writer: W,
    live: Mutex<HashMap<String, LivePatch>>,
    /// If true, verify the captured original matches `Patch::original_bytes` before writing.
    pub verify_originals: bool,
}

impl<W: RuntimeMemoryWriter> HotPatcher<W> {
    /// Create a new hot-patcher backed by the given writer.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            live: Mutex::new(HashMap::new()),
            verify_originals: true,
        }
    }

    /// Apply a single patch at `address` (uses the patch's `patch_bytes`).
    ///
    /// Captures the original bytes first so revert is always possible.
    ///
    /// # Errors
    ///
    /// Returns [`HotPatchError`] when the patch is already live, the memory
    /// reader/writer fails, verification fails, or the captured original bytes
    /// do not match the patch's expected originals.
    pub fn apply(&self, patch: &Patch, address: u64) -> Result<LivePatch, HotPatchError> {
        {
            let live = self.live.lock();
            if live.contains_key(&patch.id) {
                return Err(HotPatchError::AlreadyLive(patch.id.clone()));
            }
        }

        let len = patch.patch_bytes.len();
        let captured = self
            .writer
            .read(address, len)
            .map_err(|e| HotPatchError::Writer { address, message: e })?;
        if captured.len() != len {
            return Err(HotPatchError::Verification {
                address,
                expected: len,
                got: captured.len(),
            });
        }

        if self.verify_originals
            && !patch.original_bytes.is_empty()
            && patch.original_bytes.len() == captured.len()
            && patch.original_bytes != captured
        {
            return Err(HotPatchError::OriginalMismatch { address });
        }

        self.writer
            .write(address, &patch.patch_bytes)
            .map_err(|e| HotPatchError::Writer { address, message: e })?;
        self.writer
            .flush_icache(address, len)
            .map_err(|e| HotPatchError::Writer { address, message: e })?;

        let record = LivePatch {
            id: patch.id.clone(),
            address,
            captured_original: captured,
            written_bytes: patch.patch_bytes.clone(),
        };
        self.live.lock().insert(patch.id.clone(), record.clone());
        Ok(record)
    }

    /// Revert a previously-applied live patch by id.
    ///
    /// # Errors
    ///
    /// Returns [`HotPatchError::NotFound`] if no live patch matches `id`, or
    /// [`HotPatchError::Writer`] if the underlying memory writer fails.
    pub fn revert(&self, id: &str) -> Result<LivePatch, HotPatchError> {
        let record = {
            let mut live = self.live.lock();
            live.remove(id).ok_or_else(|| HotPatchError::NotFound(id.to_string()))?
        };
        if let Err(e) = self.writer.write(record.address, &record.captured_original) {
            // Restore the bookkeeping entry so the caller can retry.
            self.live.lock().insert(record.id.clone(), record.clone());
            return Err(HotPatchError::Writer { address: record.address, message: e });
        }
        if let Err(e) = self.writer.flush_icache(record.address, record.captured_original.len()) {
            return Err(HotPatchError::Writer { address: record.address, message: e });
        }
        Ok(record)
    }

    /// Revert every live patch. Failures are collected and returned; on error
    /// the remaining patches that did revert successfully are still removed.
    pub fn revert_all(&self) -> Vec<Result<LivePatch, HotPatchError>> {
        let ids: Vec<String> = {
            let guard = self.live.lock();
            guard.keys().cloned().collect()
        };
        ids.iter().map(|id| self.revert(id)).collect()
    }

    /// Number of currently-live patches.
    pub fn live_count(&self) -> usize {
        self.live.lock().len()
    }

    /// Snapshot of the live patches (cloned).
    pub fn live_patches(&self) -> Vec<LivePatch> {
        self.live.lock().values().cloned().collect()
    }

    /// Look up a single live patch by id.
    pub fn get(&self, id: &str) -> Option<LivePatch> {
        self.live.lock().get(id).cloned()
    }
}

// ---------------------------------------------------------------------------
// In-memory writer for tests and offline simulation
// ---------------------------------------------------------------------------

/// A [`RuntimeMemoryWriter`] backed by an in-memory byte buffer. Useful for
/// tests and for simulating hot-patches without a real debugger attached.
pub struct InMemoryWriter {
    /// Base virtual address that `buffer[0]` corresponds to.
    pub base: u64,
    buffer: Mutex<Vec<u8>>,
}

impl InMemoryWriter {
    /// Create a new in-memory writer mapped at `base`.
    #[must_use] 
    pub const fn new(base: u64, buffer: Vec<u8>) -> Self {
        Self { base, buffer: Mutex::new(buffer) }
    }

    /// Snapshot the underlying buffer.
    pub fn snapshot(&self) -> Vec<u8> {
        self.buffer.lock().clone()
    }
}

impl RuntimeMemoryWriter for InMemoryWriter {
    fn read(&self, address: u64, len: usize) -> Result<Vec<u8>, String> {
        if address < self.base {
            return Err(format!("address {address:#x} below base {:#x}", self.base));
        }
        let off = usize::try_from(address - self.base)
            .map_err(|_| format!("address {address:#x} offset exceeds usize"))?;
        let buf = self.buffer.lock();
        let buf_len = buf.len();
        if off + len > buf_len {
            return Err(format!("read {address:#x}+{len} exceeds buffer size {buf_len}"));
        }
        let out = buf[off..off + len].to_vec();
        drop(buf);
        Ok(out)
    }

    fn write(&self, address: u64, data: &[u8]) -> Result<(), String> {
        if address < self.base {
            return Err(format!("address {address:#x} below base {:#x}", self.base));
        }
        let off = usize::try_from(address - self.base)
            .map_err(|_| format!("address {address:#x} offset exceeds usize"))?;
        let data_len = data.len();
        let mut buf = self.buffer.lock();
        let buf_len = buf.len();
        if off + data_len > buf_len {
            return Err(format!("write {address:#x}+{data_len} exceeds buffer size {buf_len}"));
        }
        buf[off..off + data_len].copy_from_slice(data);
        drop(buf);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_patch() -> Patch {
        Patch::new("p1", "nop the call", 0, vec![0xE8, 0x10, 0x20, 0x30, 0x40], vec![0x90; 5])
    }

    #[test]
    fn apply_and_revert_roundtrip() {
        let original = vec![0xE8, 0x10, 0x20, 0x30, 0x40, 0xAA, 0xBB];
        let writer = InMemoryWriter::new(0x4000, original.clone());
        let patcher = HotPatcher::new(writer);
        let patch = sample_patch();

        let live = patcher.apply(&patch, 0x4000).unwrap();
        assert_eq!(live.captured_original, &original[..5]);
        assert_eq!(patcher.live_count(), 1);
        assert_eq!(&patcher.writer.snapshot()[..5], &[0x90; 5]);

        patcher.revert("p1").unwrap();
        assert_eq!(patcher.live_count(), 0);
        assert_eq!(patcher.writer.snapshot(), original);
    }

    #[test]
    fn rejects_double_apply() {
        let writer = InMemoryWriter::new(0, vec![0xE8, 0x10, 0x20, 0x30, 0x40]);
        let patcher = HotPatcher::new(writer);
        let patch = sample_patch();
        patcher.apply(&patch, 0).unwrap();
        assert!(matches!(patcher.apply(&patch, 0), Err(HotPatchError::AlreadyLive(_))));
    }

    #[test]
    fn detects_original_mismatch() {
        let writer = InMemoryWriter::new(0, vec![0x00; 8]); // not matching expected
        let patcher = HotPatcher::new(writer);
        let patch = sample_patch();
        assert!(matches!(patcher.apply(&patch, 0), Err(HotPatchError::OriginalMismatch { .. })));
    }

    #[test]
    fn revert_unknown_fails() {
        let writer = InMemoryWriter::new(0, vec![0u8; 4]);
        let patcher = HotPatcher::new(writer);
        assert!(matches!(patcher.revert("missing"), Err(HotPatchError::NotFound(_))));
    }

    #[test]
    fn revert_all_clears_state() {
        let writer = InMemoryWriter::new(0, vec![0xE8, 0x10, 0x20, 0x30, 0x40, 0xE8, 0x10, 0x20, 0x30, 0x40]);
        let patcher = HotPatcher::new(writer);
        let mut p2 = sample_patch();
        p2.id = "p2".to_string();
        patcher.apply(&sample_patch(), 0).unwrap();
        patcher.apply(&p2, 5).unwrap();
        let results = patcher.revert_all();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(std::result::Result::is_ok));
        assert_eq!(patcher.live_count(), 0);
    }
}
