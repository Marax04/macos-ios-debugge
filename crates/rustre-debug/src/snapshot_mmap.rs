//! Opt-4: Memory-mapped session snapshot files.
//!
//! Large session recordings serialised to disk (e.g. via `bincode` or
//! `serde_json`) can be multi-megabyte blobs.  Reading them with
//! `std::fs::read` incurs a kernel→user copy for every byte.  Using
//! `memmap2::Mmap` instead lets the OS page-in only the pages the consumer
//! actually touches, giving three concrete wins:
//!
//! 1. **Zero-copy load**: `Mmap::map` returns immediately; data arrives via
//!    page faults on first access, not a `read(2)` syscall.
//! 2. **OS-managed eviction**: unused pages are dropped by the kernel under
//!    memory pressure without explicit `free`.
//! 3. **Shared across processes**: if two debugger instances open the same
//!    snapshot the OS maps the same physical pages into both, halving RSS.
//!
//! `MmapSnapshot` wraps `memmap2::Mmap` and exposes a `data()` slice that
//! callers can hand to `serde_json::from_slice` or `bincode::deserialize`.

use std::fs::File;
use std::path::Path;

/// A memory-mapped view of a serialised session snapshot.
///
/// The mapping lives until this value is dropped.  Do not hold references
/// into `data()` across a `drop` of `MmapSnapshot`.
pub struct MmapSnapshot {
    // Keep the File alive for the lifetime of the mapping (required on Windows
    // where closing the file handle while the view is open is an error).
    _file: File,
    mmap: memmap2::Mmap,
}

impl MmapSnapshot {
    /// Open `path` and create a read-only memory mapping over its contents.
    ///
    /// # Errors
    ///
    /// Returns `std::io::Error` if the file cannot be opened or mapped.
    ///
    /// # Safety note
    ///
    /// The mapping is read-only and created via `memmap2::Mmap::map`, which
    /// wraps `mmap(2)` / `MapViewOfFile`.  The caller must ensure the file
    /// is not truncated while the mapping is live (the OS makes writes via
    /// other file handles visible to the mapping, which would produce
    /// undefined data but not UB in Rust's memory model because the bytes
    /// are accessed through `&[u8]`, not typed references).
    pub fn from_file(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let file = File::open(path.as_ref())?;
        // SAFETY: the file is valid and open; we hold `file` alive for the
        // duration of the mapping via the `_file` field.
        let mmap = unsafe { memmap2::Mmap::map(&file)? };
        Ok(Self { _file: file, mmap })
    }

    /// The raw bytes of the snapshot.  Valid for the lifetime of `self`.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.mmap
    }

    /// Number of bytes in the snapshot.
    #[must_use]
    pub fn len(&self) -> usize {
        self.mmap.len()
    }

    /// Returns `true` if the snapshot contains no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.mmap.is_empty()
    }
}

impl std::fmt::Debug for MmapSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MmapSnapshot")
            .field("len", &self.len())
            .finish()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn write_temp(content: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        f.write_all(content).expect("write");
        f.flush().expect("flush");
        f
    }

    #[test]
    fn mmap_snapshot_roundtrip() {
        let payload = b"session_v1:{\"events\":42}";
        let tmp = write_temp(payload);
        let snap = MmapSnapshot::from_file(tmp.path()).expect("map");
        assert_eq!(snap.data(), payload);
        assert_eq!(snap.len(), payload.len());
        assert!(!snap.is_empty());
    }

    #[test]
    fn mmap_snapshot_empty_file() {
        let tmp = write_temp(b"");
        let snap = MmapSnapshot::from_file(tmp.path()).expect("map");
        assert!(snap.is_empty());
    }

    #[test]
    fn mmap_snapshot_large_payload() {
        // 1 MiB of pseudo-data; exercises multi-page mapping.
        let payload: Vec<u8> = (0u8..=255).cycle().take(1024 * 1024).collect();
        let tmp = write_temp(&payload);
        let snap = MmapSnapshot::from_file(tmp.path()).expect("map");
        assert_eq!(snap.len(), payload.len());
        assert_eq!(snap.data()[0], 0);
        assert_eq!(snap.data()[255], 255);
    }

    #[test]
    fn mmap_snapshot_debug() {
        let tmp = write_temp(b"hello");
        let snap = MmapSnapshot::from_file(tmp.path()).expect("map");
        let s = format!("{snap:?}");
        assert!(s.contains("MmapSnapshot"));
    }
}
