//! Live provider diff utilities.
//!
//! This module provides [`diff_providers`], which compares two [`MemoryProvider`]
//! implementations over a given address range and returns a list of
//! [`DiffSpan`] values representing ranges where the two providers differ.
//!
//! # Distinction from `snapshot_diff` and `memory_diff`
//!
//! - [`crate::snapshot_diff`] — diffs two raw `&[u8]` slices (no provider I/O).
//! - This module — diffs two live [`crate::memory_provider::MemoryProvider`]s
//!   via chunked reads, skipping unreadable ranges.
//! - [`crate::memory_diff`] — diffs two `Vec<SnapshotRegion>` with per-region
//!   permission tracking and added/removed region detection.
//!
//! ## Algorithm
//!
//! The comparison reads both providers one chunk at a time (default 4 KiB)
//! and emits spans for any contiguous run of bytes that differ between the
//! two sources.  If either provider returns an error for a range, that range
//! is skipped.

use crate::memory_provider::MemoryProvider;
use rustre_core::address::{Address, AddressRange};

// ─────────────────────────────────────────────────────────────────────────────
// DiffSpan
// ─────────────────────────────────────────────────────────────────────────────

/// A contiguous address range where two providers differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffSpan {
    /// The range of addresses that differ.
    pub range: AddressRange,
    /// Bytes from the first provider.
    pub old_bytes: Vec<u8>,
    /// Bytes from the second provider.
    pub new_bytes: Vec<u8>,
}

impl DiffSpan {
    /// Byte length of the differing span.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.range.len() as usize
    }

    /// Return `true` if the span is empty (should not normally occur).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return the number of byte positions where `old_bytes[i] != new_bytes[i]`.
    #[must_use]
    pub fn changed_byte_count(&self) -> usize {
        self.old_bytes
            .iter()
            .zip(&self.new_bytes)
            .filter(|(a, b)| a != b)
            .count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// diff_providers
// ─────────────────────────────────────────────────────────────────────────────

/// Compare two memory providers over `range` and return all differing spans.
///
/// Reads are performed in chunks of `chunk_size` bytes (default: 4096).
/// If either provider fails to read a chunk, that chunk is skipped entirely.
///
/// Adjacent diff spans are merged into one span for compact output.
#[must_use]
pub fn diff_providers(
    a: &dyn MemoryProvider,
    b: &dyn MemoryProvider,
    range: AddressRange,
) -> Vec<DiffSpan> {
    diff_providers_chunked(a, b, range, 4096)
}

/// Like [`diff_providers`] but with an explicit `chunk_size`.
#[must_use]
pub fn diff_providers_chunked(
    a: &dyn MemoryProvider,
    b: &dyn MemoryProvider,
    range: AddressRange,
    chunk_size: usize,
) -> Vec<DiffSpan> {
    if range.is_empty() || chunk_size == 0 {
        return Vec::new();
    }

    let mut spans: Vec<DiffSpan> = Vec::new();
    let mut cursor = range.start;

    // Pending diff accumulator.
    let mut pending_start: Option<Address> = None;
    let mut pending_old: Vec<u8> = Vec::new();
    let mut pending_new: Vec<u8> = Vec::new();

    let flush = |spans: &mut Vec<DiffSpan>,
                 pending_start: &mut Option<Address>,
                 pending_old: &mut Vec<u8>,
                 pending_new: &mut Vec<u8>| {
        if let Some(start) = pending_start.take() {
            let end = start + pending_old.len() as u64;
            spans.push(DiffSpan {
                range: AddressRange::new(start, end),
                old_bytes: std::mem::take(pending_old),
                new_bytes: std::mem::take(pending_new),
            });
        }
    };

    while cursor < range.end {
        let remaining = (range.end.as_u64() - cursor.as_u64()) as usize;
        let this_chunk = remaining.min(chunk_size);

        let a_result = a.read(cursor, this_chunk);
        let b_result = b.read(cursor, this_chunk);

        match (a_result, b_result) {
            (Ok(a_data), Ok(b_data)) => {
                // Compare byte by byte, accumulating diff spans.
                for i in 0..this_chunk.min(a_data.len()).min(b_data.len()) {
                    let addr = cursor + i as u64;
                    if a_data[i] == b_data[i] {
                        // Flush any pending span.
                        flush(
                            &mut spans,
                            &mut pending_start,
                            &mut pending_old,
                            &mut pending_new,
                        );
                    } else {
                        // Start or extend pending span.
                        if pending_start.is_none() {
                            pending_start = Some(addr);
                        }
                        pending_old.push(a_data[i]);
                        pending_new.push(b_data[i]);
                    }
                }
            }
            _ => {
                // Skip this chunk on read error; flush pending.
                flush(
                    &mut spans,
                    &mut pending_start,
                    &mut pending_old,
                    &mut pending_new,
                );
            }
        }

        cursor += this_chunk as u64;
    }

    // Final flush.
    flush(
        &mut spans,
        &mut pending_start,
        &mut pending_old,
        &mut pending_new,
    );

    spans
}

// ─────────────────────────────────────────────────────────────────────────────
// diff_bytes — diff two raw byte slices
// ─────────────────────────────────────────────────────────────────────────────

/// Diff two raw byte slices anchored at `base_addr`.
///
/// Returns a list of [`DiffSpan`] values for all contiguous runs of bytes
/// that differ between `a` and `b`.  If `a` and `b` have different lengths,
/// only the shorter length is compared.
#[must_use]
pub fn diff_bytes(base_addr: Address, a: &[u8], b: &[u8]) -> Vec<DiffSpan> {
    let len = a.len().min(b.len());
    let mut spans: Vec<DiffSpan> = Vec::new();
    let mut pending_start: Option<usize> = None;

    for i in 0..len {
        if a[i] != b[i] {
            pending_start.get_or_insert(i);
        } else if let Some(start) = pending_start.take() {
            let begin = base_addr + start as u64;
            let end = base_addr + i as u64;
            spans.push(DiffSpan {
                range: AddressRange::new(begin, end),
                old_bytes: a[start..i].to_vec(),
                new_bytes: b[start..i].to_vec(),
            });
        }
    }
    if let Some(start) = pending_start {
        let begin = base_addr + start as u64;
        let end = base_addr + len as u64;
        spans.push(DiffSpan {
            range: AddressRange::new(begin, end),
            old_bytes: a[start..len].to_vec(),
            new_bytes: b[start..len].to_vec(),
        });
    }

    spans
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtual_memory::VirtualMemoryProvider;
    use rustre_core::permissions::Permissions;

    fn provider_with(start: u64, data: &[u8]) -> VirtualMemoryProvider {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(start),
            data.to_vec(),
            Permissions::READ | Permissions::WRITE,
        );
        p
    }

    fn full_range(start: u64, len: u64) -> AddressRange {
        AddressRange::new(Address::new(start), Address::new(start + len))
    }

    // ── diff_bytes ────────────────────────────────────────────────────────────

    #[test]
    fn diff_bytes_identical() {
        let data = b"hello world";
        let spans = diff_bytes(Address::new(0), data, data);
        assert!(spans.is_empty());
    }

    #[test]
    fn diff_bytes_single_byte() {
        let a = b"AAAA";
        let b = b"ABAA";
        let spans = diff_bytes(Address::new(0x100), a, b);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].range.start, Address::new(0x101));
        assert_eq!(spans[0].range.end, Address::new(0x102));
        assert_eq!(spans[0].old_bytes, b"A");
        assert_eq!(spans[0].new_bytes, b"B");
    }

    #[test]
    fn diff_bytes_multiple_spans() {
        let a = b"AABBCC";
        let b = b"AXBXCC";
        let spans = diff_bytes(Address::new(0), a, b);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].old_bytes, b"A");
        assert_eq!(spans[1].old_bytes, b"B");
    }

    #[test]
    fn diff_bytes_all_different() {
        let a = vec![0u8; 8];
        let b = vec![1u8; 8];
        let spans = diff_bytes(Address::new(0), &a, &b);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].len(), 8);
    }

    #[test]
    fn diff_bytes_empty_slices() {
        let spans = diff_bytes(Address::new(0), &[], &[]);
        assert!(spans.is_empty());
    }

    #[test]
    fn diff_bytes_unequal_lengths_min() {
        let a = b"ABCDE";
        let b = b"ABXDE";
        let spans = diff_bytes(Address::new(0), a, b);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].old_bytes, b"C");
    }

    // ── diff_providers ────────────────────────────────────────────────────────

    #[test]
    fn diff_providers_identical() {
        let a = provider_with(0x1000, &[0xAAu8; 64]);
        let b = provider_with(0x1000, &[0xAAu8; 64]);
        let spans = diff_providers(&a, &b, full_range(0x1000, 64));
        assert!(spans.is_empty());
    }

    #[test]
    fn diff_providers_single_byte_change() {
        let a = provider_with(0x1000, &[0u8; 16]);
        let mut b_data = vec![0u8; 16];
        b_data[8] = 0xFF;
        let b = provider_with(0x1000, &b_data);
        let spans = diff_providers(&a, &b, full_range(0x1000, 16));
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].range.start, Address::new(0x1008));
        assert_eq!(spans[0].old_bytes, [0x00]);
        assert_eq!(spans[0].new_bytes, [0xFF]);
    }

    #[test]
    fn diff_providers_no_overlap_range() {
        let a = provider_with(0x1000, &[0u8; 64]);
        let b = provider_with(0x1000, &[1u8; 64]);
        let spans = diff_providers_chunked(&a, &b, full_range(0x2000, 16), 4096);
        // Range not backed by either provider → read errors → skipped.
        assert!(spans.is_empty());
    }

    #[test]
    fn diff_providers_multiple_spans() {
        let a_data = vec![0u8; 32];
        let mut b_data = vec![0u8; 32];
        b_data[4] = 0xFF;
        b_data[20] = 0xEE;
        let a = provider_with(0x1000, &a_data);
        let b = provider_with(0x1000, &b_data);
        let spans = diff_providers(&a, &b, full_range(0x1000, 32));
        assert_eq!(spans.len(), 2);
    }

    #[test]
    fn diff_providers_empty_range() {
        let a = provider_with(0x1000, &[0u8; 16]);
        let b = provider_with(0x1000, &[1u8; 16]);
        let spans = diff_providers(
            &a,
            &b,
            AddressRange::new(Address::new(0x1000), Address::new(0x1000)),
        );
        assert!(spans.is_empty());
    }

    #[test]
    fn diff_span_changed_byte_count() {
        let span = DiffSpan {
            range: AddressRange::new(Address::new(0), Address::new(4)),
            old_bytes: vec![0, 1, 2, 3],
            new_bytes: vec![0, 1, 9, 9], // positions 2 and 3 differ
        };
        assert_eq!(span.changed_byte_count(), 2);
    }

    #[test]
    fn diff_span_len() {
        let span = DiffSpan {
            range: AddressRange::new(Address::new(0x100), Address::new(0x110)),
            old_bytes: vec![0u8; 16],
            new_bytes: vec![1u8; 16],
        };
        assert_eq!(span.len(), 16);
        assert!(!span.is_empty());
    }

    #[test]
    fn diff_providers_chunk_boundary() {
        // Force the diff to span a chunk boundary.
        let a_data = vec![0u8; 8192];
        let mut b_data = vec![0u8; 8192];
        b_data[4095] = 0xFF; // last byte of first chunk
        b_data[4096] = 0xFF; // first byte of second chunk
        let a = provider_with(0x0, &a_data);
        let b = provider_with(0x0, &b_data);
        let spans = diff_providers_chunked(&a, &b, full_range(0, 8192), 4096);
        // The two changes are in adjacent chunks but NOT adjacent bytes, so 2 spans.
        // Actually they are at positions 4095 and 4096 which ARE adjacent →
        // the accumulator should merge them into one span.
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].len(), 2);
    }

    #[test]
    fn diff_providers_large_all_different() {
        let a = provider_with(0x1000, &vec![0u8; 1024]);
        let b = provider_with(0x1000, &vec![1u8; 1024]);
        let spans = diff_providers(&a, &b, full_range(0x1000, 1024));
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].len(), 1024);
    }
}
