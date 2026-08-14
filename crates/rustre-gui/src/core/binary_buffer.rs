// ============================================================================
// core/binary_buffer.rs — Zero-copy backing storage for the loaded binary
// ============================================================================
//
// `Vec<u8>` requires the whole binary to fit in physical RAM, which is fine
// for a 40 MiB sample but impossible for a 200 GiB firmware image. This
// module wraps two backends behind a single API:
//
//   * `Owned(Vec<u8>)`  — used for synthetic byte streams, fallback paths,
//                         and small files for which mmap setup would be
//                         needless overhead.
//   * `Mapped(Mmap)`    — memory-mapped file. The kernel pages bytes in on
//                         demand, so a 200 GiB target costs ~0 RAM up-front;
//                         each access faults the relevant page on first read
//                         and the page cache holds it for subsequent reads.
//
// Both backends expose a `&[u8]` view via `Deref` / `AsRef`, so the analysis
// pipeline (scan_strings, sweep, listing build, hex view, …) reads the bytes
// uniformly without caring which backend is active.
// ============================================================================

use memmap2::Mmap;
use std::fs::File;
use std::ops::Deref;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug)]
pub enum BinaryBuffer {
    /// In-memory byte buffer. Used for synthetic data and the fallback
    /// `std::fs::read` path on platforms where mmap fails.
    Owned(Vec<u8>),
    /// Memory-mapped file. The bytes live in the OS page cache and are
    /// faulted in on demand. Suitable for files larger than physical RAM.
    Mapped(Mmap),
}

impl BinaryBuffer {
    /// Wrap an owned `Vec<u8>` (preserves existing call sites that built the
    /// buffer in memory before the mmap fast path landed).
    #[must_use]
    pub const fn from_vec(v: Vec<u8>) -> Self {
        Self::Owned(v)
    }

    /// Memory-map the file at `path`. Returns `Ok(Self)` on success or an IO
    /// error if the file cannot be opened or mapped (e.g. empty file on some
    /// platforms — callers should fall back to `from_vec(read(path)?)`).
    ///
    /// # Errors
    /// Propagates any `io::Error` from `File::open` or `Mmap::map`.
    pub fn mmap<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let file = File::open(path)?;
        // SAFETY: We map the file read-only and rely on the OS's COW semantics.
        // If another process truncates the file under us the access faults — a
        // SIGBUS we accept because read-only static-analysis sessions are the
        // intended use case.
        let mm = unsafe { Mmap::map(&file)? };
        // Best-effort hint to the kernel that we'll read the bytes sequentially
        // during the load pipeline; doesn't matter on Windows but is cheap.
        #[cfg(unix)]
        let _ = mm.advise(memmap2::Advice::Sequential);
        Ok(Self::Mapped(mm))
    }

    /// Returns the raw bytes as a slice. Equivalent to `&*buf` but spells the
    /// intent more clearly at call sites that pass around `&[u8]`.
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Owned(v) => v.as_slice(),
            Self::Mapped(m) => m.as_ref(),
        }
    }

    /// Length in bytes. Equivalent to `buf.len()` thanks to `Deref` but kept
    /// here so the type's public API mirrors `Vec<u8>` exactly.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Whether the buffer holds zero bytes.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Deref for BinaryBuffer {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsRef<[u8]> for BinaryBuffer {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// Convenience: build an `Arc<BinaryBuffer>` from a `Vec<u8>`. Used by the
/// loader fallback path and by tests that pre-build a byte stream.
#[must_use]
pub fn shared_from_vec(v: Vec<u8>) -> Arc<BinaryBuffer> {
    Arc::new(BinaryBuffer::from_vec(v))
}

#[doc(hidden)]
pub fn ensure_used_binary_buffer() {
    let b = shared_from_vec(vec![1, 2, 3]);
    debug_assert_eq!(b.len(), 3);
    debug_assert_eq!(b.as_slice(), &[1u8, 2, 3]);
}
