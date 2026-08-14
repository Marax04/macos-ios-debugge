//! B-tree index for efficient TTD query lookups.
//!
//! Provides `BTreeIndex<K, V>`, a generic sorted-key index where each key maps
//! to a `Vec<V>` of associated values.  Binary search is used throughout so
//! both insertion (O(log n + m)) and range queries (O(log n + hits)) are fast.

use std::ops::{Bound, RangeBounds};

// ---------------------------------------------------------------------------
// IndexEntry
// ---------------------------------------------------------------------------

/// A single entry held inside a `BTreeIndex`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry<K, V> {
    /// The sort key.
    pub key: K,
    /// All values associated with this key.
    pub values: Vec<V>,
}

impl<K: Ord + Clone, V: Clone> IndexEntry<K, V> {
    /// Create a new entry with one initial value.
    #[must_use]
    pub fn new(key: K, value: V) -> Self {
        Self {
            key,
            values: vec![value],
        }
    }

    /// Append a value to this entry.
    pub fn push(&mut self, value: V) {
        self.values.push(value);
    }
}

// ---------------------------------------------------------------------------
// IndexStats
// ---------------------------------------------------------------------------

/// Statistics about a `BTreeIndex`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexStats {
    /// Number of distinct keys.
    pub key_count: usize,
    /// Total number of values across all keys.
    pub value_count: usize,
    /// Maximum number of values for a single key.
    pub max_values_per_key: usize,
    /// Minimum number of values for a single key.
    pub min_values_per_key: usize,
}

impl IndexStats {
    /// Compute the average values per key.
    #[must_use]
    pub fn avg_values_per_key(&self) -> f64 {
        if self.key_count == 0 {
            0.0
        } else {
            self.value_count as f64 / self.key_count as f64
        }
    }
}

impl std::fmt::Display for IndexStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IndexStats {{ keys: {}, values: {}, max_per_key: {}, avg: {:.2} }}",
            self.key_count,
            self.value_count,
            self.max_values_per_key,
            self.avg_values_per_key()
        )
    }
}

// ---------------------------------------------------------------------------
// BTreeIndex
// ---------------------------------------------------------------------------

/// A generic B-tree–style sorted index mapping `K` → `Vec<V>`.
///
/// Internally backed by a `Vec<IndexEntry<K, V>>` kept in sorted order by
/// key.  All operations use binary search for O(log n) key lookup.
#[derive(Debug, Clone)]
pub struct BTreeIndex<K, V> {
    entries: Vec<IndexEntry<K, V>>,
}

impl<K: Ord + Clone, V: Clone> BTreeIndex<K, V> {
    /// Create an empty index.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Create an index pre-allocated for `capacity` distinct keys.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
        }
    }

    /// Insert a `(key, value)` pair.
    ///
    /// If `key` already exists, `value` is appended to its value list.
    /// Otherwise a new entry is inserted at the correct sorted position.
    pub fn insert(&mut self, key: K, value: V) {
        match self.entries.binary_search_by(|e| e.key.cmp(&key)) {
            Ok(idx) => {
                self.entries[idx].push(value);
            }
            Err(idx) => {
                self.entries.insert(idx, IndexEntry::new(key, value));
            }
        }
    }

    /// Insert multiple values for a single key at once.
    pub fn insert_many(&mut self, key: K, values: impl IntoIterator<Item = V>) {
        for v in values {
            self.insert(key.clone(), v);
        }
    }

    /// Look up all values associated with `key`.
    /// Returns `None` if the key is not present.
    #[must_use]
    pub fn get(&self, key: &K) -> Option<&[V]> {
        self.entries
            .binary_search_by(|e| e.key.cmp(key))
            .ok()
            .map(|idx| self.entries[idx].values.as_slice())
    }

    /// Return all values whose key falls within `range` (inclusive on both ends).
    ///
    /// Uses binary search to locate the start and end positions, then collects
    /// all matching values.
    #[must_use]
    pub fn range_query<R>(&self, range: R) -> Vec<&V>
    where
        R: RangeBounds<K>,
    {
        // Find start index
        let start = match range.start_bound() {
            Bound::Included(lo) => self.entries.partition_point(|e| e.key < *lo),
            Bound::Excluded(lo) => self.entries.partition_point(|e| e.key <= *lo),
            Bound::Unbounded => 0,
        };
        // Find end index
        let end = match range.end_bound() {
            Bound::Included(hi) => self.entries.partition_point(|e| e.key <= *hi),
            Bound::Excluded(hi) => self.entries.partition_point(|e| e.key < *hi),
            Bound::Unbounded => self.entries.len(),
        };
        self.entries[start..end]
            .iter()
            .flat_map(|e| e.values.iter())
            .collect()
    }

    /// Return the key-value entry at the given logical position (sorted order).
    #[must_use]
    pub fn entry_at(&self, idx: usize) -> Option<&IndexEntry<K, V>> {
        self.entries.get(idx)
    }

    /// Number of distinct keys.
    #[must_use]
    pub const fn key_count(&self) -> usize {
        self.entries.len()
    }

    /// Total number of values across all keys.
    #[must_use]
    pub fn value_count(&self) -> usize {
        self.entries.iter().map(|e| e.values.len()).sum()
    }

    /// Whether the index contains no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `key` is present in the index.
    #[must_use]
    pub fn contains_key(&self, key: &K) -> bool {
        self.entries.binary_search_by(|e| e.key.cmp(key)).is_ok()
    }

    /// Remove all values for `key`. Returns `true` if the key existed.
    pub fn remove_key(&mut self, key: &K) -> bool {
        match self.entries.binary_search_by(|e| e.key.cmp(key)) {
            Ok(idx) => {
                self.entries.remove(idx);
                true
            }
            Err(_) => false,
        }
    }

    /// Iterate over all entries in sorted key order.
    pub fn iter(&self) -> impl Iterator<Item = &IndexEntry<K, V>> {
        self.entries.iter()
    }

    /// All keys in sorted order.
    #[must_use]
    pub fn keys(&self) -> Vec<&K> {
        self.entries.iter().map(|e| &e.key).collect()
    }

    /// Compute statistics for this index.
    #[must_use]
    pub fn stats(&self) -> IndexStats {
        if self.entries.is_empty() {
            return IndexStats {
                key_count: 0,
                value_count: 0,
                max_values_per_key: 0,
                min_values_per_key: 0,
            };
        }
        let max_v = self
            .entries
            .iter()
            .map(|e| e.values.len())
            .max()
            .unwrap_or(0);
        let min_v = self
            .entries
            .iter()
            .map(|e| e.values.len())
            .min()
            .unwrap_or(0);
        IndexStats {
            key_count: self.entries.len(),
            value_count: self.value_count(),
            max_values_per_key: max_v,
            min_values_per_key: min_v,
        }
    }

    /// Merge another index into this one, consuming it.
    pub fn merge(&mut self, other: Self) {
        for entry in other.entries {
            for v in entry.values {
                self.insert(entry.key.clone(), v);
            }
        }
    }

    /// Retain only entries whose key satisfies the predicate.
    pub fn retain_keys(&mut self, mut predicate: impl FnMut(&K) -> bool) {
        self.entries.retain(|e| predicate(&e.key));
    }

    /// Find the smallest key greater than or equal to `key` (lower bound).
    #[must_use]
    pub fn lower_bound(&self, key: &K) -> Option<&K> {
        let idx = self.entries.partition_point(|e| e.key < *key);
        self.entries.get(idx).map(|e| &e.key)
    }

    /// Find the largest key less than or equal to `key` (floor).
    #[must_use]
    pub fn floor(&self, key: &K) -> Option<&K> {
        let idx = self.entries.partition_point(|e| e.key <= *key);
        if idx == 0 {
            None
        } else {
            Some(&self.entries[idx - 1].key)
        }
    }
}

impl<K: Ord + Clone, V: Clone> Default for BTreeIndex<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Specialization for u64 keys (address-based lookup)
// ---------------------------------------------------------------------------

/// An address-based B-tree index: `u64` key → `Vec<V>`.
pub type AddressBTreeIndex<V> = BTreeIndex<u64, V>;

impl<V: Clone> AddressBTreeIndex<V> {
    /// Query all values in the address range `[lo, hi]` (inclusive).
    #[must_use]
    pub fn address_range_query(&self, lo: u64, hi: u64) -> Vec<&V> {
        self.range_query(lo..=hi)
    }

    /// Find the entry whose key is the greatest address ≤ `addr`.
    #[must_use]
    pub fn floor_address(&self, addr: u64) -> Option<u64> {
        self.floor(&addr).copied()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn build_index() -> BTreeIndex<u64, &'static str> {
        let mut idx: BTreeIndex<u64, &'static str> = BTreeIndex::new();
        idx.insert(10, "a");
        idx.insert(20, "b");
        idx.insert(10, "c"); // duplicate key
        idx.insert(30, "d");
        idx.insert(25, "e");
        idx
    }

    #[test]
    fn test_insert_and_get() {
        let idx = build_index();
        let vals = idx.get(&10).unwrap();
        assert_eq!(vals.len(), 2);
        assert!(vals.contains(&"a"));
        assert!(vals.contains(&"c"));
    }

    #[test]
    fn test_get_missing_key() {
        let idx = build_index();
        assert!(idx.get(&99).is_none());
    }

    #[test]
    fn test_key_count() {
        let idx = build_index();
        assert_eq!(idx.key_count(), 4);
    }

    #[test]
    fn test_value_count() {
        let idx = build_index();
        assert_eq!(idx.value_count(), 5);
    }

    #[test]
    fn test_sorted_key_order() {
        let idx = build_index();
        let keys: Vec<u64> = idx.keys().into_iter().copied().collect();
        assert_eq!(keys, vec![10, 20, 25, 30]);
    }

    #[test]
    fn test_range_query_inclusive() {
        let idx = build_index();
        let vals = idx.range_query(15u64..=25u64);
        assert_eq!(vals.len(), 2); // keys 20 and 25
    }

    #[test]
    fn test_range_query_full() {
        let idx = build_index();
        let vals = idx.range_query(0u64..=100u64);
        assert_eq!(vals.len(), 5);
    }

    #[test]
    fn test_range_query_empty() {
        let idx = build_index();
        let vals = idx.range_query(50u64..=100u64);
        assert!(vals.is_empty());
    }

    #[test]
    fn test_contains_key() {
        let idx = build_index();
        assert!(idx.contains_key(&10));
        assert!(!idx.contains_key(&11));
    }

    #[test]
    fn test_remove_key() {
        let mut idx = build_index();
        assert!(idx.remove_key(&20));
        assert!(!idx.contains_key(&20));
        assert_eq!(idx.key_count(), 3);
    }

    #[test]
    fn test_remove_missing_key() {
        let mut idx = build_index();
        assert!(!idx.remove_key(&99));
    }

    #[test]
    fn test_stats() {
        let idx = build_index();
        let s = idx.stats();
        assert_eq!(s.key_count, 4);
        assert_eq!(s.value_count, 5);
        assert_eq!(s.max_values_per_key, 2);
        assert_eq!(s.min_values_per_key, 1);
    }

    #[test]
    fn test_stats_display() {
        let idx = build_index();
        let s = idx.stats().to_string();
        assert!(s.contains("keys: 4"));
    }

    #[test]
    fn test_merge() {
        let mut a: BTreeIndex<u64, &str> = BTreeIndex::new();
        a.insert(1, "x");
        let mut b: BTreeIndex<u64, &str> = BTreeIndex::new();
        b.insert(2, "y");
        b.insert(1, "z");
        a.merge(b);
        assert_eq!(a.key_count(), 2);
        assert_eq!(a.get(&1).unwrap().len(), 2);
    }

    #[test]
    fn test_lower_bound() {
        let idx = build_index();
        assert_eq!(idx.lower_bound(&15), Some(&20));
        assert_eq!(idx.lower_bound(&10), Some(&10));
        assert_eq!(idx.lower_bound(&31), None);
    }

    #[test]
    fn test_floor() {
        let idx = build_index();
        assert_eq!(idx.floor(&22), Some(&20));
        assert_eq!(idx.floor(&10), Some(&10));
        assert_eq!(idx.floor(&5), None);
    }

    #[test]
    fn test_address_range_query() {
        let mut idx: AddressBTreeIndex<&str> = AddressBTreeIndex::new();
        idx.insert(0x1000, "func_a");
        idx.insert(0x2000, "func_b");
        idx.insert(0x3000, "func_c");
        let results = idx.address_range_query(0x1000, 0x2000);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_retain_keys() {
        let mut idx = build_index();
        idx.retain_keys(|k| *k >= 20);
        assert!(!idx.contains_key(&10));
        assert!(idx.contains_key(&20));
    }

    #[test]
    fn test_empty_index_stats() {
        let idx: BTreeIndex<u64, u32> = BTreeIndex::new();
        let s = idx.stats();
        assert_eq!(s.key_count, 0);
        assert_eq!(s.avg_values_per_key(), 0.0);
    }

    #[test]
    fn test_insert_many() {
        let mut idx: BTreeIndex<u64, u32> = BTreeIndex::new();
        idx.insert_many(42, [1, 2, 3]);
        assert_eq!(idx.get(&42).unwrap().len(), 3);
    }

    #[test]
    fn test_floor_address() {
        let mut idx: AddressBTreeIndex<&str> = AddressBTreeIndex::new();
        idx.insert(0x1000, "a");
        idx.insert(0x2000, "b");
        assert_eq!(idx.floor_address(0x1500), Some(0x1000));
        assert_eq!(idx.floor_address(0x0fff), None);
    }
}
