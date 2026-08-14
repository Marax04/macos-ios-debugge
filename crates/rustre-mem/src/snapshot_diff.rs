//! Byte-slice memory snapshot diffing.
//!
//! Compares two raw `&[u8]` snapshots anchored at the same base address and
//! produces a [`SnapshotDiff`] containing every contiguous run of changed bytes.
//!
//! # Layering
//!
//! There are three diff modules in this crate, each at a different abstraction
//! level:
//!
//! | Module | Input | Output | Use-case |
//! |---|---|---|---|
//! | `snapshot_diff` (this) | Two `&[u8]` slices | [`SnapshotDiff`] | Fast byte-level diff of equal-sized dumps |
//! | [`crate::diff`] | Two [`crate::memory_provider::MemoryProvider`]s + range | [`crate::diff::DiffSpan`] | Live provider comparison with chunked I/O |
//! | [`crate::memory_diff`] | Two `Vec<SnapshotRegion>` | [`crate::memory_diff::MemoryDiff`] | Region-aware diff with permission tracking |

use rustre_core::address::Address;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// MemoryChange
// ─────────────────────────────────────────────────────────────────────────────

/// A single contiguous run of bytes that differ between two snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryChange {
    /// Virtual address of the first differing byte.
    pub addr: Address,
    /// The byte values in the *before* snapshot.
    pub before: Vec<u8>,
    /// The byte values in the *after* snapshot.
    pub after: Vec<u8>,
}

impl MemoryChange {
    /// Length of this changed region in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.before.len()
    }

    /// Returns `true` if the changed region is empty (should never happen in
    /// practice).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.before.is_empty()
    }

    /// One-past-the-end address of the changed region.
    #[must_use]
    pub const fn end_addr(&self) -> Address {
        Address::new(self.addr.0 + self.len() as u64)
    }
}

impl std::fmt::Display for MemoryChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "0x{:x}..0x{:x} ({} bytes changed)",
            self.addr.0,
            self.end_addr().0,
            self.len()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SnapshotDiff
// ─────────────────────────────────────────────────────────────────────────────

/// The result of comparing two memory snapshots.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SnapshotDiff {
    pub changes: Vec<MemoryChange>,
}

impl SnapshotDiff {
    /// Returns `true` if there are no differences.
    #[must_use]
    pub const fn is_identical(&self) -> bool {
        self.changes.is_empty()
    }

    /// Total number of bytes that differ.
    #[must_use]
    pub fn changed_byte_count(&self) -> usize {
        self.changes.iter().map(MemoryChange::len).sum()
    }

    /// Number of changed regions.
    #[must_use]
    pub const fn region_count(&self) -> usize {
        self.changes.len()
    }

    /// Apply the *after* side of this diff to `buffer`, which is assumed to
    /// start at `base_addr`.
    ///
    /// # Errors
    /// Returns `Err(String)` if any change extends beyond `buffer`.
    pub fn apply_to(&self, buffer: &mut [u8], base_addr: Address) -> Result<(), String> {
        for change in &self.changes {
            let offset =
                change.addr.0.checked_sub(base_addr.0).ok_or_else(|| {
                    format!("change at 0x{:x} is before buffer base", change.addr.0)
                })? as usize;
            let end = offset + change.after.len();
            if end > buffer.len() {
                return Err(format!(
                    "change at 0x{:x} extends beyond buffer",
                    change.addr.0
                ));
            }
            buffer[offset..end].copy_from_slice(&change.after);
        }
        Ok(())
    }

    /// Build the inverse diff (swap before/after).
    #[must_use]
    pub fn invert(&self) -> Self {
        Self {
            changes: self
                .changes
                .iter()
                .map(|c| MemoryChange {
                    addr: c.addr,
                    before: c.after.clone(),
                    after: c.before.clone(),
                })
                .collect(),
        }
    }

    /// Serialize to JSON.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize from JSON.
    ///
    /// # Errors
    /// Returns an error if deserialization fails.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// diff_memory
// ─────────────────────────────────────────────────────────────────────────────

/// Compute a diff between `before` and `after`, both assumed to be byte slices
/// starting at `base_addr`.  Returns a `SnapshotDiff` with one `MemoryChange`
/// per contiguous run of differing bytes.
///
/// # Panics
/// Panics if `before.len() != after.len()`.
#[must_use]
pub fn diff_memory(before: &[u8], after: &[u8], base_addr: Address) -> SnapshotDiff {
    assert_eq!(
        before.len(),
        after.len(),
        "diff_memory: before and after must have equal length"
    );

    let mut changes = Vec::new();
    let mut i = 0;

    while i < before.len() {
        if before[i] == after[i] {
            i += 1;
            continue;
        }
        // Start of a changed run.
        let start = i;
        while i < before.len() && before[i] != after[i] {
            i += 1;
        }
        changes.push(MemoryChange {
            addr: Address::new(base_addr.0 + start as u64),
            before: before[start..i].to_vec(),
            after: after[start..i].to_vec(),
        });
    }

    SnapshotDiff { changes }
}

/// Compare two memory slices of *different* sizes by comparing the common
/// prefix.  Any bytes present in one but not the other are treated as
/// zero-differing.
#[must_use]
pub fn diff_memory_lenient(before: &[u8], after: &[u8], base_addr: Address) -> SnapshotDiff {
    let common_len = before.len().min(after.len());
    diff_memory(&before[..common_len], &after[..common_len], base_addr)
}

// ─────────────────────────────────────────────────────────────────────────────
// MemorySnapshot
// ─────────────────────────────────────────────────────────────────────────────

/// A complete snapshot of a memory range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySnapshot {
    /// Virtual address of the first byte.
    pub base: Address,
    /// Snapshot bytes.
    pub data: Vec<u8>,
    /// Optional snapshot ID / label.
    pub label: Option<String>,
}

impl MemorySnapshot {
    /// Create a new snapshot.
    #[must_use]
    pub const fn new(base: Address, data: Vec<u8>) -> Self {
        Self {
            base,
            data,
            label: None,
        }
    }

    /// Attach a label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the snapshot is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Compute the diff between `self` (before) and `other` (after).
    ///
    /// # Panics
    /// Panics if the two snapshots do not have the same base address.
    #[must_use]
    pub fn diff(&self, other: &Self) -> SnapshotDiff {
        assert_eq!(
            self.base, other.base,
            "snapshots must share the same base address"
        );
        diff_memory_lenient(&self.data, &other.data, self.base)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryStats
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics about a memory snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStats {
    pub total_bytes: usize,
    pub zero_bytes: usize,
    pub nonzero_bytes: usize,
    /// Approximate byte-entropy (Shannon entropy in bits-per-byte).
    pub entropy: f64,
    /// Count of unique byte values present.
    pub unique_byte_values: usize,
}

impl MemoryStats {
    /// Compute statistics for a byte slice.
    #[must_use]
    pub fn compute(data: &[u8]) -> Self {
        if data.is_empty() {
            return Self {
                total_bytes: 0,
                zero_bytes: 0,
                nonzero_bytes: 0,
                entropy: 0.0,
                unique_byte_values: 0,
            };
        }
        let mut freq = [0u64; 256];
        let mut zero_bytes = 0usize;
        for &b in data {
            freq[b as usize] += 1;
            if b == 0 {
                zero_bytes += 1;
            }
        }
        let n = data.len() as f64;
        let entropy: f64 = freq
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / n;
                -p * p.log2()
            })
            .sum();
        let unique_byte_values = freq.iter().filter(|&&c| c > 0).count();
        Self {
            total_bytes: data.len(),
            zero_bytes,
            nonzero_bytes: data.len() - zero_bytes,
            entropy,
            unique_byte_values,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    #[test]
    fn test_diff_identical() {
        let diff = diff_memory(&[1, 2, 3, 4], &[1, 2, 3, 4], addr(0));
        assert!(diff.is_identical());
        assert_eq!(diff.changed_byte_count(), 0);
    }

    #[test]
    fn test_diff_single_byte() {
        let diff = diff_memory(&[0, 0, 0, 0], &[0, 1, 0, 0], addr(0x1000));
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].addr, addr(0x1001));
        assert_eq!(diff.changes[0].before, vec![0]);
        assert_eq!(diff.changes[0].after, vec![1]);
    }

    #[test]
    fn test_diff_run_of_changes() {
        let before = [0u8, 0, 0, 1, 1, 1, 0];
        let after = [0u8, 0, 0, 2, 2, 2, 0];
        let diff = diff_memory(&before, &after, addr(0));
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].addr, addr(3));
        assert_eq!(diff.changes[0].len(), 3);
    }

    #[test]
    fn test_diff_multiple_runs() {
        let before = [1u8, 0, 1, 0, 1];
        let after = [2u8, 0, 2, 0, 2];
        let diff = diff_memory(&before, &after, addr(0));
        assert_eq!(diff.changes.len(), 3);
    }

    #[test]
    fn test_diff_apply_to() {
        let before = vec![0u8; 8];
        let after = vec![0, 0, 0xFF, 0xFF, 0, 0, 0, 0];
        let diff = diff_memory(&before, &after, addr(0x1000));
        let mut buf = vec![0u8; 8];
        diff.apply_to(&mut buf, addr(0x1000)).unwrap();
        assert_eq!(buf[2], 0xFF);
        assert_eq!(buf[3], 0xFF);
    }

    #[test]
    fn test_diff_apply_out_of_range() {
        let diff = SnapshotDiff {
            changes: vec![MemoryChange {
                addr: addr(0x2000),
                before: vec![0],
                after: vec![1],
            }],
        };
        let mut buf = vec![0u8; 4];
        // buf starts at 0x1000; 0x2000 - 0x1000 = 0x1000 which is beyond len 4
        assert!(diff.apply_to(&mut buf, addr(0x1000)).is_err());
    }

    #[test]
    fn test_diff_invert() {
        let diff = diff_memory(&[0, 1], &[1, 0], addr(0));
        let inv = diff.invert();
        assert_eq!(inv.changes[0].before, vec![1, 0]);
        assert_eq!(inv.changes[0].after, vec![0, 1]);
    }

    #[test]
    fn test_diff_json_roundtrip() {
        let diff = diff_memory(&[0, 1, 2], &[0, 2, 2], addr(0));
        let json = diff.to_json().unwrap();
        let back = SnapshotDiff::from_json(&json).unwrap();
        assert_eq!(back.changes.len(), diff.changes.len());
    }

    #[test]
    fn test_memory_snapshot_diff() {
        let snap1 = MemorySnapshot::new(addr(0), vec![0, 1, 2, 3]);
        let snap2 = MemorySnapshot::new(addr(0), vec![0, 1, 9, 3]);
        let diff = snap1.diff(&snap2);
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].after, vec![9]);
    }

    #[test]
    fn test_memory_stats_zero() {
        let stats = MemoryStats::compute(&[0u8; 128]);
        assert_eq!(stats.zero_bytes, 128);
        assert_eq!(stats.nonzero_bytes, 0);
        assert_eq!(stats.unique_byte_values, 1);
    }

    #[test]
    fn test_memory_stats_all_unique() {
        let data: Vec<u8> = (0..=255).collect();
        let stats = MemoryStats::compute(&data);
        assert_eq!(stats.unique_byte_values, 256);
        // Max entropy for uniform 256-byte alphabet is 8 bits/byte.
        assert!((stats.entropy - 8.0).abs() < 1e-10);
    }

    #[test]
    fn test_memory_stats_empty() {
        let stats = MemoryStats::compute(&[]);
        assert_eq!(stats.total_bytes, 0);
        assert_eq!(stats.entropy, 0.0);
    }

    #[test]
    fn test_memory_change_display() {
        let c = MemoryChange {
            addr: addr(0x1000),
            before: vec![0, 0],
            after: vec![1, 1],
        };
        let s = c.to_string();
        assert!(s.contains("1000"));
        assert!(s.contains("bytes changed"));
    }

    #[test]
    fn test_diff_lenient_shorter_before() {
        let diff = diff_memory_lenient(&[0, 1, 2], &[0, 1, 2, 3, 4], addr(0));
        assert!(diff.is_identical());
    }

    #[test]
    fn test_snapshot_with_label() {
        let snap = MemorySnapshot::new(addr(0), vec![0u8; 4]).with_label("heap_snapshot");
        assert_eq!(snap.label.as_deref(), Some("heap_snapshot"));
    }
}
