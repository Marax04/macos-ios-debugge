/// Snapshot management for `EmulatedMemoryProvider` and other mutable providers.
///
/// A `SnapshotStore` keeps a set of named, timestamped snapshots of a byte
/// buffer.  The caller is responsible for supplying the bytes to snapshot and
/// for restoring them; the store only manages the storage and naming.
///
/// # Design
/// - Snapshots are identified by a monotonically increasing [`SnapshotId`].
/// - Each snapshot carries an optional human-readable tag, a creation
///   timestamp (seconds since UNIX epoch), and the raw bytes.
/// - The store supports a configurable maximum number of retained snapshots;
///   when the limit is reached, the oldest snapshot is automatically evicted.
/// - Tags are unique within the store; adding a snapshot with a duplicate tag
///   replaces the old snapshot of that tag.
use crate::memory_provider::SnapshotId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

// ─────────────────────────────────────────────────────────────────────────────
// SnapshotMeta — metadata for a stored snapshot
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata and data for a single snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRecord {
    /// Unique monotonic identifier.
    pub id: u64,
    /// Optional human-readable tag.
    pub tag: Option<String>,
    /// Creation time in seconds since UNIX epoch.
    pub created_at_secs: u64,
    /// The raw bytes captured at snapshot time.
    pub data: Vec<u8>,
}

impl SnapshotRecord {
    /// Size of the snapshot data in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> usize {
        self.data.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SnapshotStore
// ─────────────────────────────────────────────────────────────────────────────

/// A thread-hostile (single-threaded, interior-mutable) store for memory
/// snapshots.
///
/// Lock yourself in a `parking_lot::Mutex<SnapshotStore>` for concurrent use.
#[derive(Debug, Clone, Default)]
pub struct SnapshotStore {
    /// Snapshots ordered by insertion (oldest first).
    records: VecDeque<SnapshotRecord>,
    /// Tag → record index for fast tag lookups.
    by_tag: HashMap<String, u64>,
    /// Next ID to issue.
    next_id: u64,
    /// Maximum number of retained snapshots (0 = unlimited).
    capacity: usize,
}

impl SnapshotStore {
    /// Create an unlimited-capacity snapshot store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a store that retains at most `capacity` snapshots.
    ///
    /// When a new snapshot would exceed the limit, the oldest is evicted.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            ..Default::default()
        }
    }

    /// Capture `data` as a new snapshot.
    ///
    /// If `tag` is `Some` and a snapshot with the same tag already exists, it
    /// is replaced.
    ///
    /// Returns the [`SnapshotId`] of the newly created snapshot.
    pub fn snapshot(&mut self, data: Vec<u8>, tag: Option<String>) -> SnapshotId {
        // If there is a duplicate tag, remove the old record first.
        if let Some(tag_str) = &tag
            && let Some(&old_id) = self.by_tag.get(tag_str.as_str()) {
                self.records.retain(|r| r.id != old_id);
                // by_tag will be overwritten below.
            }

        // Enforce capacity by evicting the oldest record if needed.
        if self.capacity > 0 && self.records.len() >= self.capacity {
            let evicted = self.records.pop_front();
            if let Some(evicted) = evicted
                && let Some(t) = &evicted.tag {
                    self.by_tag.remove(t.as_str());
                }
        }

        let id = self.next_id;
        self.next_id += 1;

        let created_at_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        if let Some(ref t) = tag {
            self.by_tag.insert(t.clone(), id);
        }

        self.records.push_back(SnapshotRecord {
            id,
            tag,
            created_at_secs,
            data,
        });

        SnapshotId(id)
    }

    /// Retrieve the data for a snapshot by its `SnapshotId`.
    ///
    /// Returns `None` if the id does not exist in the store.
    #[must_use]
    pub fn get_data(&self, id: SnapshotId) -> Option<&[u8]> {
        self.records
            .iter()
            .find(|r| r.id == id.0)
            .map(|r| r.data.as_slice())
    }

    /// Retrieve the full record for a snapshot by id.
    #[must_use]
    pub fn get_record(&self, id: SnapshotId) -> Option<&SnapshotRecord> {
        self.records.iter().find(|r| r.id == id.0)
    }

    /// Retrieve the data for a snapshot by its tag.
    ///
    /// Returns `None` if no snapshot with that tag exists.
    #[must_use]
    pub fn get_data_by_tag(&self, tag: &str) -> Option<&[u8]> {
        let &id = self.by_tag.get(tag)?;
        self.records
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.data.as_slice())
    }

    /// Remove the snapshot with the given `id`.  Returns `true` if it existed.
    pub fn discard(&mut self, id: SnapshotId) -> bool {
        if let Some(idx) = self.records.iter().position(|r| r.id == id.0) {
            if let Some(record) = self.records.remove(idx)
                && let Some(t) = &record.tag {
                    self.by_tag.remove(t.as_str());
                }
            true
        } else {
            false
        }
    }

    /// Remove all snapshots older than `id` (lower numeric id).
    ///
    /// Useful for a "checkpoint" pattern: after reaching a known-good state,
    /// discard all prior snapshots to save memory.
    pub fn discard_before(&mut self, id: SnapshotId) {
        let mut to_remove_tags: Vec<String> = Vec::new();
        self.records.retain(|r| {
            if r.id < id.0 {
                if let Some(t) = &r.tag {
                    to_remove_tags.push(t.clone());
                }
                false
            } else {
                true
            }
        });
        for t in &to_remove_tags {
            self.by_tag.remove(t.as_str());
        }
    }

    /// Remove all snapshots.
    pub fn discard_all(&mut self) {
        self.records.clear();
        self.by_tag.clear();
    }

    /// Number of stored snapshots.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Return `true` if no snapshots are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Iterate over all snapshot records in insertion order (oldest first).
    pub fn iter(&self) -> impl Iterator<Item = &SnapshotRecord> {
        self.records.iter()
    }

    /// Return the most recently created [`SnapshotId`], or `None` if empty.
    #[must_use]
    pub fn latest_id(&self) -> Option<SnapshotId> {
        self.records.back().map(|r| SnapshotId(r.id))
    }

    /// Return the total number of bytes stored across all snapshots.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.records.iter().map(SnapshotRecord::size_bytes).sum()
    }

    /// Return all snapshot IDs in insertion order.
    #[must_use]
    pub fn all_ids(&self) -> Vec<SnapshotId> {
        self.records.iter().map(|r| SnapshotId(r.id)).collect()
    }

    /// Return all snapshot tags that have been assigned.
    #[must_use]
    pub fn all_tags(&self) -> Vec<&str> {
        self.by_tag.keys().map(String::as_str).collect()
    }

    /// Return `true` if a snapshot with the given tag exists.
    #[must_use]
    pub fn has_tag(&self, tag: &str) -> bool {
        self.by_tag.contains_key(tag)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffRecord — compact diff between two snapshots
// ─────────────────────────────────────────────────────────────────────────────

/// A single contiguous changed region detected by snapshot diffing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotDiff {
    /// Byte offset (from the start of the compared buffer) where the change begins.
    pub offset: usize,
    /// Bytes from the "old" (baseline) snapshot.
    pub old_bytes: Vec<u8>,
    /// Bytes from the "new" (current) snapshot.
    pub new_bytes: Vec<u8>,
}

impl SnapshotDiff {
    /// Number of bytes that changed.
    #[must_use]
    pub const fn changed_bytes(&self) -> usize {
        self.old_bytes.len()
    }
}

/// Compare two byte slices and return a compact list of changed regions.
///
/// Consecutive changed bytes are merged into a single [`SnapshotDiff`] entry
/// if they form a contiguous run.
#[must_use]
pub fn diff_snapshots(old: &[u8], new: &[u8]) -> Vec<SnapshotDiff> {
    let len = old.len().min(new.len());
    let mut diffs: Vec<SnapshotDiff> = Vec::new();
    let mut i = 0usize;

    while i < len {
        if old[i] == new[i] {
            i += 1;
        } else {
            // Start of a changed run.
            let start = i;
            while i < len && old[i] != new[i] {
                i += 1;
            }
            diffs.push(SnapshotDiff {
                offset: start,
                old_bytes: old[start..i].to_vec(),
                new_bytes: new[start..i].to_vec(),
            });
        }
    }

    // If the new buffer is longer, treat appended bytes as changes from zero.
    if new.len() > old.len() {
        diffs.push(SnapshotDiff {
            offset: old.len(),
            old_bytes: vec![0u8; new.len() - old.len()],
            new_bytes: new[old.len()..].to_vec(),
        });
    }

    diffs
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_snapshot_roundtrip() {
        let mut store = SnapshotStore::new();
        let data = vec![1u8, 2, 3, 4, 5];
        let id = store.snapshot(data.clone(), None);
        assert_eq!(store.len(), 1);
        assert_eq!(store.get_data(id).unwrap(), &data[..]);
    }

    #[test]
    fn snapshot_with_tag() {
        let mut store = SnapshotStore::new();
        let id1 = store.snapshot(vec![0u8; 8], Some("pre-patch".into()));
        assert_eq!(store.len(), 1);
        assert!(store.has_tag("pre-patch"));

        // Overwrite with same tag.
        let new_data = vec![0xFFu8; 8];
        let id2 = store.snapshot(new_data.clone(), Some("pre-patch".into()));
        assert_eq!(store.len(), 1);
        assert_ne!(id1.0, id2.0);
        assert_eq!(store.get_data(id2).unwrap(), &new_data[..]);
        assert_eq!(store.get_data_by_tag("pre-patch").unwrap(), &new_data[..]);
    }

    #[test]
    fn snapshot_capacity_evicts_oldest() {
        let mut store = SnapshotStore::with_capacity(3);
        let id0 = store.snapshot(vec![0u8], None);
        let _id1 = store.snapshot(vec![1u8], None);
        let _id2 = store.snapshot(vec![2u8], None);
        assert_eq!(store.len(), 3);

        // Adding a 4th should evict id0.
        let _id3 = store.snapshot(vec![3u8], None);
        assert_eq!(store.len(), 3);
        assert!(store.get_data(id0).is_none());
    }

    #[test]
    fn discard_snapshot() {
        let mut store = SnapshotStore::new();
        let id = store.snapshot(vec![42u8], Some("keep".into()));
        let _ = store.snapshot(vec![99u8], Some("drop".into()));
        let removed = store.discard(id);
        assert!(removed);
        assert_eq!(store.len(), 1);
        assert!(!store.has_tag("keep"));
        assert!(store.has_tag("drop"));
    }

    #[test]
    fn discard_before_removes_old() {
        let mut store = SnapshotStore::new();
        let _id0 = store.snapshot(vec![0u8], Some("s0".into()));
        let _id1 = store.snapshot(vec![1u8], Some("s1".into()));
        let id2 = store.snapshot(vec![2u8], Some("s2".into()));
        let _id3 = store.snapshot(vec![3u8], None);

        store.discard_before(id2);
        assert_eq!(store.len(), 2);
        assert!(!store.has_tag("s0"));
        assert!(!store.has_tag("s1"));
        assert!(store.has_tag("s2"));
    }

    #[test]
    fn latest_id_and_all_ids() {
        let mut store = SnapshotStore::new();
        assert!(store.latest_id().is_none());
        let id1 = store.snapshot(vec![1], None);
        let id2 = store.snapshot(vec![2], None);
        let id3 = store.snapshot(vec![3], None);
        assert_eq!(store.latest_id().unwrap(), id3);
        let all = store.all_ids();
        assert_eq!(all, vec![id1, id2, id3]);
    }

    #[test]
    fn total_bytes() {
        let mut store = SnapshotStore::new();
        store.snapshot(vec![0u8; 100], None);
        store.snapshot(vec![0u8; 200], None);
        assert_eq!(store.total_bytes(), 300);
    }

    #[test]
    fn diff_snapshots_detects_changes() {
        let old = vec![0u8, 1, 2, 3, 4, 5, 6, 7];
        let mut new = old.clone();
        new[2] = 0xFF;
        new[3] = 0xFE;
        new[6] = 0xAA;

        let diffs = diff_snapshots(&old, &new);
        assert_eq!(diffs.len(), 2);
        assert_eq!(diffs[0].offset, 2);
        assert_eq!(diffs[0].old_bytes, [2, 3]);
        assert_eq!(diffs[0].new_bytes, [0xFF, 0xFE]);
        assert_eq!(diffs[1].offset, 6);
        assert_eq!(diffs[1].new_bytes, [0xAA]);
    }

    #[test]
    fn diff_snapshots_no_changes() {
        let data = vec![1u8, 2, 3, 4];
        let diffs = diff_snapshots(&data, &data);
        assert!(diffs.is_empty());
    }

    #[test]
    fn diff_snapshots_longer_new() {
        let old = vec![0u8; 4];
        let new = vec![0u8; 8];
        let diffs = diff_snapshots(&old, &new);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].offset, 4);
        assert_eq!(diffs[0].new_bytes.len(), 4);
    }

    #[test]
    fn snapshot_record_size_bytes() {
        let rec = SnapshotRecord {
            id: 0,
            tag: None,
            created_at_secs: 0,
            data: vec![0u8; 1024],
        };
        assert_eq!(rec.size_bytes(), 1024);
    }

    #[test]
    fn discard_all() {
        let mut store = SnapshotStore::new();
        store.snapshot(vec![1], Some("a".into()));
        store.snapshot(vec![2], Some("b".into()));
        store.discard_all();
        assert!(store.is_empty());
        assert!(!store.has_tag("a"));
    }
}
