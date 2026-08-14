//! Heap analysis: chunk parsing, anomaly detection, and reporting.
//!
//! Supports minimal glibc ptmalloc2 and Windows heap heuristic parsing.

use crate::casts::u64_to_usize;

// ─── HeapChunkState ───────────────────────────────────────────────────────────

/// The allocation state of a heap chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapChunkState {
    /// The chunk holds live allocated data.
    Allocated,
    /// The chunk is on the free list.
    Free,
    /// The chunk metadata appears corrupted.
    Corrupt,
}

// ─── HeapChunk ────────────────────────────────────────────────────────────────

/// A generic heap chunk for Windows heap parsing results.
#[derive(Debug, Clone)]
pub struct HeapChunk {
    /// Virtual address of the chunk header.
    pub address: u64,
    /// Usable data size (not counting headers).
    pub size: u64,
    /// Allocation state.
    pub state: HeapChunkState,
    /// Raw flags byte.
    pub flags: u8,
    /// First 16 bytes of chunk data (may be zero-padded).
    pub data_preview: [u8; 16],
}

impl HeapChunk {
    /// Create a new allocated chunk.
    #[must_use]
    pub const fn allocated(address: u64, size: u64, flags: u8) -> Self {
        Self {
            address,
            size,
            state: HeapChunkState::Allocated,
            flags,
            data_preview: [0u8; 16],
        }
    }

    /// Create a new free chunk.
    #[must_use]
    pub const fn free(address: u64, size: u64) -> Self {
        Self {
            address,
            size,
            state: HeapChunkState::Free,
            flags: 0,
            data_preview: [0u8; 16],
        }
    }
}

// ─── HeapRegion ───────────────────────────────────────────────────────────────

/// A contiguous region of heap memory containing parsed chunks.
#[derive(Debug, Clone)]
pub struct HeapRegion {
    /// Base virtual address of the region.
    pub base: u64,
    /// Total size in bytes.
    pub size: u64,
    /// Parsed chunks within this region.
    pub chunks: Vec<HeapChunk>,
}

impl HeapRegion {
    /// Create a new heap region.
    #[must_use]
    pub const fn new(base: u64, size: u64) -> Self {
        Self {
            base,
            size,
            chunks: Vec::new(),
        }
    }

    /// Count allocated chunks.
    #[must_use]
    pub fn allocated_count(&self) -> usize {
        self.chunks
            .iter()
            .filter(|c| c.state == HeapChunkState::Allocated)
            .count()
    }

    /// Count free chunks.
    #[must_use]
    pub fn free_count(&self) -> usize {
        self.chunks
            .iter()
            .filter(|c| c.state == HeapChunkState::Free)
            .count()
    }
}

// ─── GlibcChunk ───────────────────────────────────────────────────────────────

/// A parsed glibc ptmalloc2 chunk.
///
/// The in-memory layout for a 64-bit allocated chunk:
/// ```text
/// offset 0:  prev_size (8 bytes) — valid only when previous chunk is free
/// offset 8:  size      (8 bytes) — includes flags in low 3 bits
/// offset 16: user data begins
/// ```
#[derive(Debug, Clone)]
pub struct GlibcChunk {
    /// Virtual address of this chunk header (start of `prev_size` field).
    pub address: u64,
    /// `prev_size` field (meaningful when previous chunk is free).
    pub prev_size: u64,
    /// Chunk size including header, aligned to 16 bytes.
    pub size: u64,
    /// `true` if this chunk is currently allocated (`PREV_INUSE` of *next* chunk
    /// is set, or this chunk is the last in the region).
    pub in_use: bool,
    /// `true` if the previous adjacent chunk is in use (`PREV_INUSE` bit).
    pub prev_inuse: bool,
    /// `true` if this chunk was obtained via `mmap`.
    pub mmap_flag: bool,
}

impl GlibcChunk {
    /// Size of user data (size minus the two header fields of 8 bytes each).
    ///
    /// Returns 0 if size < 16.
    #[must_use]
    pub const fn user_size(&self) -> u64 {
        self.size.saturating_sub(16)
    }

    /// `true` if the chunk size is plausibly valid (non-zero, aligned to 16).
    #[must_use]
    pub const fn is_sane(&self) -> bool {
        self.size >= 16 && self.size.trailing_zeros() >= 3
    }
}

// ─── parse_glibc_heap ────────────────────────────────────────────────────────

/// Parse glibc ptmalloc2 chunks from raw memory.
///
/// Walks forward from the start of `mem` until all bytes are consumed or an
/// invalid chunk is encountered.
///
/// # Arguments
/// * `mem` — raw memory slice starting at the first chunk header
/// * `base` — virtual address of `mem[0]`
#[must_use]
pub fn parse_glibc_heap(mem: &[u8], base: u64) -> Vec<GlibcChunk> {
    let mut chunks = Vec::new();
    let mut pos = 0usize;

    while pos + 16 <= mem.len() {
        // prev_size and size are both 8-byte little-endian values
        let prev_size = u64::from_le_bytes(match mem[pos..pos + 8].try_into() {
            Ok(b) => b,
            Err(_) => break,
        });
        let raw_size = u64::from_le_bytes(match mem[pos + 8..pos + 16].try_into() {
            Ok(b) => b,
            Err(_) => break,
        });

        let prev_inuse = (raw_size & 1) != 0;
        let mmap_flag = (raw_size & 2) != 0;
        // non_main_arena = (raw_size & 4) != 0; — tracked via flags, not stored
        let size = raw_size & !0x7u64;

        if size == 0 || size > mem.len() as u64 {
            // Sentinel or invalid — stop walking
            break;
        }

        // Determine in_use from the PREV_INUSE flag of the next chunk
        let next_pos = pos + u64_to_usize(size);
        let in_use = if next_pos + 16 <= mem.len() {
            let arr: [u8; 8] = match mem[next_pos + 8..next_pos + 16].try_into() {
                Ok(b) => b,
                Err(_) => break,
            };
            let next_raw_size = u64::from_le_bytes(arr);
            (next_raw_size & 1) != 0
        } else {
            true // Last chunk is assumed in-use
        };

        chunks.push(GlibcChunk {
            address: base + pos as u64,
            prev_size,
            size,
            in_use,
            prev_inuse,
            mmap_flag,
        });

        pos += u64_to_usize(size);
    }

    chunks
}

// ─── parse_windows_heap_minimal ──────────────────────────────────────────────

/// Heuristic Windows heap chunk scanner.
///
/// Scans `mem` for the magic values `0xFFEEFFEE` or `0xEEFFEEFF` that appear
/// in Windows heap entry headers (simplified heuristic). Each hit is recorded
/// as an allocated chunk of heuristic size.
#[must_use]
pub fn parse_windows_heap_minimal(mem: &[u8], base: u64) -> Vec<HeapChunk> {
    const MAGIC1: [u8; 4] = [0xFF, 0xEE, 0xFF, 0xEE];
    const MAGIC2: [u8; 4] = [0xEE, 0xFF, 0xEE, 0xFF];

    let mut chunks = Vec::new();

    let end = mem.len().saturating_sub(4);
    let mut pos = 0usize;

    while pos < end {
        let window = &mem[pos..pos + 4];
        if window == MAGIC1 || window == MAGIC2 {
            // Read a 2-byte size field immediately after the magic (Windows
            // HEAP_ENTRY has a 2-byte size in allocation granularity units of 8 bytes)
            let granular_size = if pos + 6 <= mem.len() {
                u64::from(u16::from_le_bytes([mem[pos + 4], mem[pos + 5]])) * 8
            } else {
                8 // minimal guess
            };
            let flags = if pos + 7 <= mem.len() {
                mem[pos + 6]
            } else {
                0
            };
            let in_use = (flags & 0x01) != 0;

            let mut preview = [0u8; 16];
            let data_start = pos + 8;
            if data_start < mem.len() {
                let copy_len = (16).min(mem.len() - data_start);
                preview[..copy_len].copy_from_slice(&mem[data_start..data_start + copy_len]);
            }

            let mut chunk = HeapChunk {
                address: base + pos as u64,
                size: granular_size,
                state: if in_use {
                    HeapChunkState::Allocated
                } else {
                    HeapChunkState::Free
                },
                flags,
                data_preview: preview,
            };
            if granular_size == 0 || granular_size > 0x1000_0000 {
                chunk.state = HeapChunkState::Corrupt;
            }
            chunks.push(chunk);
            pos += 4; // advance past magic and keep scanning
        } else {
            pos += 1;
        }
    }

    chunks
}

// ─── HeapFinding ─────────────────────────────────────────────────────────────

/// A heap anomaly finding.
#[derive(Debug, Clone)]
pub enum HeapFinding {
    /// Free-list linkage appears corrupted at `addr`.
    FreeListCorruption { addr: u64 },
    /// A chunk at `addr` appears to have been used after being freed.
    UseAfterFree { addr: u64, size: u64 },
    /// Address `addr` appears on the free list more than once.
    DoubleFreeSuspect { addr: u64 },
    /// Chunk size at `addr` is unusually large.
    UnusualSize { addr: u64, size: u64 },
}

impl HeapFinding {
    /// Short description for reporting.
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::FreeListCorruption { addr } => {
                format!("Free-list corruption at 0x{addr:016x}")
            }
            Self::UseAfterFree { addr, size } => {
                format!("Use-after-free at 0x{addr:016x} (size {size})")
            }
            Self::DoubleFreeSuspect { addr } => {
                format!("Double-free suspect at 0x{addr:016x}")
            }
            Self::UnusualSize { addr, size } => {
                format!("Unusually large chunk at 0x{addr:016x} (size {size})")
            }
        }
    }
}

// ─── find_heap_anomalies ─────────────────────────────────────────────────────

/// Scan parsed glibc chunks for anomalies.
///
/// Checks:
/// 1. **Alignment**: chunk size must be a multiple of 8 (flags already masked).
/// 2. **Double-free**: same address appearing on the free list twice.
/// 3. **Unusual size**: data size > 10 MB.
#[must_use]
pub fn find_heap_anomalies(chunks: &[GlibcChunk]) -> Vec<HeapFinding> {
    const TEN_MB: u64 = 10 * 1024 * 1024;
    let mut findings = Vec::new();

    let mut free_addrs: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();

    for chunk in chunks {
        // Alignment check
        if chunk.size & 0x7 != 0 {
            findings.push(HeapFinding::FreeListCorruption {
                addr: chunk.address,
            });
            continue;
        }

        // Track free addresses
        if !chunk.in_use {
            let count = free_addrs.entry(chunk.address).or_insert(0);
            *count += 1;
        }

        // Unusual size
        if chunk.user_size() > TEN_MB {
            findings.push(HeapFinding::UnusualSize {
                addr: chunk.address,
                size: chunk.size,
            });
        }
    }

    // Report double-free suspects
    for (addr, count) in free_addrs {
        if count > 1 {
            findings.push(HeapFinding::DoubleFreeSuspect { addr });
        }
    }

    findings
}

// ─── HeapReport ──────────────────────────────────────────────────────────────

/// Summary report for a set of glibc chunks.
#[derive(Debug, Clone)]
pub struct HeapReport {
    /// Total number of chunks.
    pub total_chunks: usize,
    /// Number of allocated chunks.
    pub allocated: usize,
    /// Number of free chunks.
    pub free: usize,
    /// Total bytes in allocated chunks (user data only).
    pub total_allocated_bytes: u64,
    /// Total bytes in free chunks (user data only).
    pub total_free_bytes: u64,
    /// Anomalies found by [`find_heap_anomalies`].
    pub anomalies: Vec<HeapFinding>,
}

/// Build a summary report from parsed glibc chunks.
#[must_use]
pub fn build_heap_report(chunks: &[GlibcChunk]) -> HeapReport {
    let mut allocated = 0usize;
    let mut free = 0usize;
    let mut total_allocated_bytes = 0u64;
    let mut total_free_bytes = 0u64;

    for chunk in chunks {
        if chunk.in_use {
            allocated += 1;
            total_allocated_bytes += chunk.user_size();
        } else {
            free += 1;
            total_free_bytes += chunk.user_size();
        }
    }

    HeapReport {
        total_chunks: chunks.len(),
        allocated,
        free,
        total_allocated_bytes,
        total_free_bytes,
        anomalies: find_heap_anomalies(chunks),
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─── GlibcChunk ────────────────────────────────────────────────────────────

    #[test]
    fn glibc_chunk_user_size() {
        let c = GlibcChunk {
            address: 0x1000,
            prev_size: 0,
            size: 32,
            in_use: true,
            prev_inuse: true,
            mmap_flag: false,
        };
        assert_eq!(c.user_size(), 16);
    }

    #[test]
    fn glibc_chunk_user_size_small() {
        let c = GlibcChunk {
            address: 0,
            prev_size: 0,
            size: 8,
            in_use: true,
            prev_inuse: false,
            mmap_flag: false,
        };
        assert_eq!(c.user_size(), 0);
    }

    #[test]
    fn glibc_chunk_is_sane_ok() {
        let c = GlibcChunk {
            address: 0,
            prev_size: 0,
            size: 32,
            in_use: true,
            prev_inuse: true,
            mmap_flag: false,
        };
        assert!(c.is_sane());
    }

    #[test]
    fn glibc_chunk_is_sane_misaligned() {
        let c = GlibcChunk {
            address: 0,
            prev_size: 0,
            size: 31,
            in_use: true,
            prev_inuse: false,
            mmap_flag: false,
        };
        assert!(!c.is_sane());
    }

    // ─── parse_glibc_heap ──────────────────────────────────────────────────────

    fn make_glibc_chunk_bytes(prev_size: u64, size_with_flags: u64, data: &[u8]) -> Vec<u8> {
        let chunk_size = (size_with_flags & !0x7) as usize;
        let mut v = Vec::with_capacity(chunk_size);
        v.extend_from_slice(&prev_size.to_le_bytes());
        v.extend_from_slice(&size_with_flags.to_le_bytes());
        v.extend_from_slice(data);
        // Pad to chunk_size
        while v.len() < chunk_size {
            v.push(0);
        }
        v
    }

    #[test]
    fn parse_glibc_two_chunks() {
        // Chunk 1: size=32 (in-use bit set in chunk2 header)
        // Chunk 2: size=48 (end)
        let mut mem = Vec::new();
        // chunk1: prev_size=0, size=32|1 (PREV_INUSE set by convention), data
        mem.extend_from_slice(&make_glibc_chunk_bytes(0, 32 | 1, &[0xAA; 16]));
        // chunk2: prev_size=0, size=48|1
        mem.extend_from_slice(&make_glibc_chunk_bytes(0, 48 | 1, &[0xBB; 32]));

        let chunks = parse_glibc_heap(&mem, 0x1000);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].size, 32);
        assert_eq!(chunks[1].size, 48);
    }

    #[test]
    fn parse_glibc_empty_mem() {
        let chunks = parse_glibc_heap(&[], 0);
        assert!(chunks.is_empty());
    }

    #[test]
    fn parse_glibc_too_short() {
        let chunks = parse_glibc_heap(&[0u8; 10], 0);
        assert!(chunks.is_empty());
    }

    #[test]
    fn parse_glibc_flags_extracted() {
        let mut mem = make_glibc_chunk_bytes(0, 32 | 3, &[0u8; 16]);
        // Pad so next chunk can be read
        mem.extend_from_slice(&make_glibc_chunk_bytes(0, 32 | 1, &[0u8; 16]));
        let chunks = parse_glibc_heap(&mem, 0x2000);
        assert!(chunks[0].prev_inuse); // bit 0
        assert!(chunks[0].mmap_flag); // bit 1
    }

    #[test]
    fn parse_glibc_zero_size_stops() {
        // A zero-size chunk should stop the walk
        let mut mem = make_glibc_chunk_bytes(0, 32 | 1, &[0u8; 16]);
        mem.extend_from_slice(&[0u8; 16]); // zero size chunk
        let chunks = parse_glibc_heap(&mem, 0);
        assert_eq!(chunks.len(), 1);
    }

    // ─── parse_windows_heap_minimal ───────────────────────────────────────────

    #[test]
    fn win_heap_finds_magic() {
        let mut mem = vec![0u8; 64];
        // Plant FFEEFFE magic at offset 8
        mem[8..12].copy_from_slice(&[0xFF, 0xEE, 0xFF, 0xEE]);
        mem[12..14].copy_from_slice(&[2, 0]); // size = 2 * 8 = 16 bytes
        mem[14] = 0x01; // in-use flag
        let chunks = parse_windows_heap_minimal(&mem, 0x3000);
        assert!(!chunks.is_empty());
        assert!(chunks.iter().any(|c| c.state == HeapChunkState::Allocated));
    }

    #[test]
    fn win_heap_second_magic() {
        let mut mem = vec![0u8; 32];
        mem[0..4].copy_from_slice(&[0xEE, 0xFF, 0xEE, 0xFF]);
        mem[4..6].copy_from_slice(&[1, 0]);
        let chunks = parse_windows_heap_minimal(&mem, 0);
        assert!(!chunks.is_empty());
    }

    #[test]
    fn win_heap_empty() {
        let chunks = parse_windows_heap_minimal(&[], 0);
        assert!(chunks.is_empty());
    }

    // ─── find_heap_anomalies ──────────────────────────────────────────────────

    fn make_chunk(address: u64, size: u64, in_use: bool) -> GlibcChunk {
        GlibcChunk {
            address,
            prev_size: 0,
            size,
            in_use,
            prev_inuse: true,
            mmap_flag: false,
        }
    }

    #[test]
    fn anomaly_unusual_size() {
        let chunks = vec![make_chunk(0x1000, 11 * 1024 * 1024, true)];
        let findings = find_heap_anomalies(&chunks);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f, HeapFinding::UnusualSize { .. }))
        );
    }

    #[test]
    fn anomaly_double_free() {
        // Same address freed twice
        let chunks = vec![make_chunk(0x1000, 32, false), make_chunk(0x1000, 32, false)];
        let findings = find_heap_anomalies(&chunks);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f, HeapFinding::DoubleFreeSuspect { .. }))
        );
    }

    #[test]
    fn anomaly_free_list_corruption() {
        // Misaligned size (size & 7 != 0 after masking) — we have to pass it
        // pre-masked because parse_glibc_heap masks flags before storing.
        // Directly create a chunk with non-8-aligned size.
        let c = GlibcChunk {
            address: 0x2000,
            prev_size: 0,
            size: 31,
            in_use: false,
            prev_inuse: false,
            mmap_flag: false,
        };
        let findings = find_heap_anomalies(&[c]);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f, HeapFinding::FreeListCorruption { .. }))
        );
    }

    #[test]
    fn anomaly_no_findings_clean() {
        let chunks = vec![make_chunk(0x1000, 32, true), make_chunk(0x1020, 64, false)];
        let findings = find_heap_anomalies(&chunks);
        assert!(findings.is_empty());
    }

    // ─── build_heap_report ────────────────────────────────────────────────────

    #[test]
    fn heap_report_counts() {
        let chunks = vec![
            make_chunk(0x1000, 32, true),
            make_chunk(0x1020, 64, false),
            make_chunk(0x1060, 48, true),
        ];
        let report = build_heap_report(&chunks);
        assert_eq!(report.total_chunks, 3);
        assert_eq!(report.allocated, 2);
        assert_eq!(report.free, 1);
    }

    #[test]
    fn heap_report_bytes() {
        let chunks = vec![
            make_chunk(0x1000, 32, true),  // user_size = 16
            make_chunk(0x1020, 48, false), // user_size = 32
        ];
        let report = build_heap_report(&chunks);
        assert_eq!(report.total_allocated_bytes, 16);
        assert_eq!(report.total_free_bytes, 32);
    }

    #[test]
    fn heap_report_empty() {
        let report = build_heap_report(&[]);
        assert_eq!(report.total_chunks, 0);
        assert_eq!(report.allocated, 0);
        assert_eq!(report.free, 0);
    }

    // ─── HeapChunk helpers ────────────────────────────────────────────────────

    #[test]
    fn heap_chunk_allocated_constructor() {
        let c = HeapChunk::allocated(0x4000, 128, 0x01);
        assert_eq!(c.state, HeapChunkState::Allocated);
        assert_eq!(c.flags, 0x01);
    }

    #[test]
    fn heap_chunk_free_constructor() {
        let c = HeapChunk::free(0x4000, 64);
        assert_eq!(c.state, HeapChunkState::Free);
    }

    #[test]
    fn heap_region_counts() {
        let mut r = HeapRegion::new(0x5000, 4096);
        r.chunks.push(HeapChunk::allocated(0x5000, 32, 0));
        r.chunks.push(HeapChunk::free(0x5020, 64));
        assert_eq!(r.allocated_count(), 1);
        assert_eq!(r.free_count(), 1);
    }

    // ─── HeapFinding descriptions ─────────────────────────────────────────────

    #[test]
    fn finding_description_corrupt() {
        let f = HeapFinding::FreeListCorruption { addr: 0x1234 };
        assert!(f.description().contains("0x"));
    }

    #[test]
    fn finding_description_uaf() {
        let f = HeapFinding::UseAfterFree {
            addr: 0x1000,
            size: 32,
        };
        assert!(f.description().to_lowercase().contains("use"));
    }

    #[test]
    fn finding_description_double_free() {
        let f = HeapFinding::DoubleFreeSuspect { addr: 0x2000 };
        assert!(f.description().to_lowercase().contains("double"));
    }

    #[test]
    fn finding_description_unusual_size() {
        let f = HeapFinding::UnusualSize {
            addr: 0x3000,
            size: 20_000_000,
        };
        assert!(f.description().contains("20000000") || f.description().contains("size"));
    }
}
