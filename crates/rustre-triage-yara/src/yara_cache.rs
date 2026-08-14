//! YARA scan result cache.
//!
//! An in-memory LRU/FIFO/LFU cache that stores `YaraMatch` vectors keyed by
//! the pair `(file_hash, rules_hash)`.  Eviction, TTL expiry, memory
//! accounting, and per-policy ordering are all handled in pure Rust with no
//! external dependencies.

use std::collections::{HashMap, VecDeque};

use crate::yara_threat_tagger::YaraMatch;

// ---------------------------------------------------------------------------
// CacheKey
// ---------------------------------------------------------------------------

/// A 64-byte composite key: 32 bytes of file hash + 32 bytes of rules hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// SHA-256 (or BLAKE3) of the scanned file.
    pub file_hash: [u8; 32],
    /// Hash of the compiled YARA rule set.
    pub rules_hash: [u8; 32],
}

impl CacheKey {
    /// Create a `CacheKey` from two 32-byte slices.
    ///
    /// # Panics
    /// Panics if either slice has a length other than 32.
    #[must_use]
    pub const fn from_slices(file: &[u8], rules: &[u8]) -> Self {
        let mut fh = [0u8; 32];
        let mut rh = [0u8; 32];
        fh.copy_from_slice(file);
        rh.copy_from_slice(rules);
        Self {
            file_hash: fh,
            rules_hash: rh,
        }
    }

    /// Create a `CacheKey` from two hex strings (each must be 64 hex chars).
    #[must_use]
    pub fn from_hex(file_hex: &str, rules_hex: &str) -> Option<Self> {
        let fh = hex_to_32(file_hex)?;
        let rh = hex_to_32(rules_hex)?;
        Some(Self {
            file_hash: fh,
            rules_hash: rh,
        })
    }

    /// Return a short hex prefix string (first 8 bytes of `file_hash`).
    #[must_use]
    pub fn short_display(&self) -> String {
        use std::fmt::Write as _;
        self.file_hash[..8]
            .iter()
            .fold(String::with_capacity(16), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            })
    }
}

// ---------------------------------------------------------------------------
// CacheEntry
// ---------------------------------------------------------------------------

/// A single entry stored inside the cache.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Cache key.
    pub key: CacheKey,
    /// The YARA match results.
    pub result: Vec<YaraMatch>,
    /// How long the underlying scan took.
    pub scan_time_ms: u64,
    /// Unix timestamp (seconds) when this entry was created.
    pub created_at: u64,
    /// How many times this entry has been accessed.
    pub access_count: u32,
    /// Unix timestamp of the most recent access.
    pub last_accessed: u64,
}

impl CacheEntry {
    /// Create a new `CacheEntry`.
    #[must_use]
    pub const fn new(
        key: CacheKey,
        result: Vec<YaraMatch>,
        scan_time_ms: u64,
        now: u64,
    ) -> Self {
        Self {
            key,
            result,
            scan_time_ms,
            created_at: now,
            access_count: 0,
            last_accessed: now,
        }
    }

    /// Returns `true` if the entry is older than `max_age_secs`.
    #[must_use]
    pub const fn is_expired(&self, now: u64, max_age_secs: u64) -> bool {
        now.saturating_sub(self.created_at) > max_age_secs
    }

    /// Approximate memory usage of this entry in bytes.
    ///
    /// Accounts for the fixed `CacheEntry` size plus per-match string storage.
    #[must_use]
    pub fn memory_bytes(&self) -> u64 {
        let base = u64::try_from(std::mem::size_of::<Self>()).unwrap_or(u64::MAX);
        let match_bytes: u64 = self
            .result
            .iter()
            .map(|m| {
                u64::try_from(m.rule_name.len() + m.namespace.len() + m.tags.iter().map(String::len).sum::<usize>()).unwrap_or(u64::MAX)
                    + u64::try_from(std::mem::size_of::<YaraMatch>()).unwrap_or(u64::MAX)
            })
            .sum();
        base + match_bytes
    }
}

// ---------------------------------------------------------------------------
// CachePolicy
// ---------------------------------------------------------------------------

/// Eviction policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CachePolicy {
    /// Least Recently Used — evict the entry with the oldest `last_accessed`.
    LRU,
    /// First In First Out — evict the entry with the oldest `created_at`.
    FIFO,
    /// Least Frequently Used — evict the entry with the smallest `access_count`.
    LFU,
}

// ---------------------------------------------------------------------------
// CacheStats
// ---------------------------------------------------------------------------

/// Aggregated cache statistics.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Number of cache hits.
    pub hits: u64,
    /// Number of cache misses.
    pub misses: u64,
    /// Number of entries evicted.
    pub evictions: u64,
    /// Current number of entries.
    pub total_entries: u32,
    /// Approximate total memory used in bytes.
    pub memory_bytes: u64,
}

impl CacheStats {
    /// Returns the hit rate in [0.0, 1.0].
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            // Decompose to avoid u64→f64 precision-loss lint
            let h = u32::try_from(self.hits).unwrap_or(u32::MAX);
            let t = u32::try_from(total).unwrap_or(u32::MAX);
            f64::from(h) / f64::from(t)
        }
    }

    /// Returns the miss rate in [0.0, 1.0].
    #[must_use]
    pub fn miss_rate(&self) -> f64 {
        1.0 - self.hit_rate()
    }
}

// ---------------------------------------------------------------------------
// YaraCache
// ---------------------------------------------------------------------------

/// In-memory YARA scan result cache.
///
/// # Example
/// ```rust
/// use rustre_triage_yara::yara_cache::{YaraCache, CacheKey, CachePolicy};
///
/// let mut cache = YaraCache::new(1000, 64 * 1024 * 1024, CachePolicy::LRU);
/// let key = CacheKey { file_hash: [0u8; 32], rules_hash: [1u8; 32] };
/// cache.insert(key, vec![], 5, 1_000_000);
/// assert!(cache.get(&key, 1_000_001).is_some());
/// ```
pub struct YaraCache {
    /// Entry map.
    entries: HashMap<CacheKey, CacheEntry>,
    /// Ordered queue used by FIFO/LRU eviction.
    order: VecDeque<CacheKey>,
    /// Maximum number of entries.
    pub max_entries: u32,
    /// Maximum total memory in bytes.
    pub max_memory_bytes: u64,
    /// Eviction policy.
    pub policy: CachePolicy,
    /// Aggregate statistics.
    stats: CacheStats,
}

impl YaraCache {
    /// Create a new `YaraCache`.
    #[must_use]
    pub fn new(max_entries: u32, max_memory_bytes: u64, policy: CachePolicy) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            max_entries,
            max_memory_bytes,
            policy,
            stats: CacheStats::default(),
        }
    }

    // ── lookup ─────────────────────────────────────────────────────────────

    /// Look up a cache entry.
    ///
    /// Returns `None` on a miss (also increments miss counter).
    /// On a hit the `access_count` and `last_accessed` are updated.
    pub fn get(&mut self, key: &CacheKey, now: u64) -> Option<&Vec<YaraMatch>> {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.access_count += 1;
            entry.last_accessed = now;
            self.stats.hits += 1;
            // Move to back of FIFO/LRU queue
            if self.policy == CachePolicy::LRU {
                self.order.retain(|k| k != key);
                self.order.push_back(*key);
            }
            Some(&self.entries[key].result)
        } else {
            self.stats.misses += 1;
            None
        }
    }

    /// Returns a reference without updating statistics (for read-only inspection).
    #[must_use]
    pub fn peek(&self, key: &CacheKey) -> Option<&CacheEntry> {
        self.entries.get(key)
    }

    // ── insertion ─────────────────────────────────────────────────────────

    /// Insert a scan result.
    ///
    /// Evicts entries as needed to satisfy capacity and memory constraints.
    pub fn insert(
        &mut self,
        key: CacheKey,
        result: Vec<YaraMatch>,
        scan_time_ms: u64,
        now: u64,
    ) {
        // If the key already exists, replace it
        if self.entries.contains_key(&key) {
            let entry = CacheEntry::new(key, result, scan_time_ms, now);
            self.stats.memory_bytes = self.stats.memory_bytes
                .saturating_sub(self.entries[&key].memory_bytes())
                + entry.memory_bytes();
            self.entries.insert(key, entry);
            return;
        }

        // Evict until constraints are satisfied
        let new_entry = CacheEntry::new(key, result, scan_time_ms, now);
        let new_mem = new_entry.memory_bytes();

        while !self.entries.is_empty()
            && (u32::try_from(self.entries.len()).unwrap_or(u32::MAX) >= self.max_entries
                || self.stats.memory_bytes + new_mem > self.max_memory_bytes)
        {
            self.evict_one();
        }

        self.stats.memory_bytes += new_mem;
        self.stats.total_entries = u32::try_from(self.entries.len() + 1).unwrap_or(u32::MAX);
        self.order.push_back(key);
        self.entries.insert(key, new_entry);
    }

    // ── eviction ──────────────────────────────────────────────────────────

    /// Evict a single entry according to the configured policy.
    ///
    /// Returns `true` if an entry was evicted.
    pub fn evict_one(&mut self) -> bool {
        let victim_key = match self.policy {
            CachePolicy::FIFO => {
                // Evict the oldest inserted entry
                self.order.pop_front()
            }
            CachePolicy::LRU => {
                // Evict the least-recently-used (front of the ordered queue)
                self.order.pop_front()
            }
            CachePolicy::LFU => {
                // Evict the entry with the smallest access_count
                if let Some(k) = self.find_lfu_victim() {
                    self.order.retain(|x| x != &k);
                    Some(k)
                } else {
                    None
                }
            }
        };

        if let Some(entry) = victim_key.and_then(|k| self.entries.remove(&k)) {
            self.stats.memory_bytes =
                self.stats.memory_bytes.saturating_sub(entry.memory_bytes());
            self.stats.evictions += 1;
            self.stats.total_entries = u32::try_from(self.entries.len()).unwrap_or(u32::MAX);
            return true;
        }
        false
    }

    /// Remove all entries older than `max_age_secs`.
    ///
    /// Returns the number of entries removed.
    pub fn evict_expired(&mut self, now: u64, max_age_secs: u64) -> usize {
        let expired_keys: Vec<CacheKey> = self
            .entries
            .iter()
            .filter(|(_, e)| e.is_expired(now, max_age_secs))
            .map(|(k, _)| *k)
            .collect();

        let count = expired_keys.len();
        for key in &expired_keys {
            if let Some(entry) = self.entries.remove(key) {
                self.stats.memory_bytes =
                    self.stats.memory_bytes.saturating_sub(entry.memory_bytes());
                self.stats.evictions += 1;
                self.order.retain(|k| k != key);
            }
        }
        self.stats.total_entries = u32::try_from(self.entries.len()).unwrap_or(u32::MAX);
        count
    }

    /// Remove a specific entry.
    ///
    /// Returns `true` if the entry existed.
    pub fn remove(&mut self, key: &CacheKey) -> bool {
        if let Some(entry) = self.entries.remove(key) {
            self.stats.memory_bytes =
                self.stats.memory_bytes.saturating_sub(entry.memory_bytes());
            self.order.retain(|k| k != key);
            self.stats.total_entries = u32::try_from(self.entries.len()).unwrap_or(u32::MAX);
            true
        } else {
            false
        }
    }

    /// Flush all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
        self.stats.memory_bytes = 0;
        self.stats.total_entries = 0;
    }

    // ── statistics ────────────────────────────────────────────────────────

    /// Returns the current hit rate in [0.0, 1.0].
    #[must_use]
    pub fn cache_hit_rate(&self) -> f64 {
        self.stats.hit_rate()
    }

    /// Returns a snapshot of the current statistics.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.stats.hits,
            misses: self.stats.misses,
            evictions: self.stats.evictions,
            total_entries: u32::try_from(self.entries.len()).unwrap_or(u32::MAX),
            memory_bytes: self.stats.memory_bytes,
        }
    }

    /// Returns the number of entries currently in the cache.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Approximate total memory usage in bytes.
    #[must_use]
    pub const fn memory_bytes(&self) -> u64 {
        self.stats.memory_bytes
    }

    /// Estimate memory for a new entry (without inserting it).
    #[must_use]
    pub fn estimate_entry_memory(result: &[YaraMatch]) -> u64 {
        let base = u64::try_from(std::mem::size_of::<CacheEntry>()).unwrap_or(0);
        let match_bytes: u64 = result
            .iter()
            .map(|m| {
                let str_bytes = m.rule_name.len() + m.namespace.len() + m.tags.iter().map(String::len).sum::<usize>();
                u64::try_from(str_bytes).unwrap_or(0)
                    + u64::try_from(std::mem::size_of::<YaraMatch>()).unwrap_or(0)
            })
            .sum();
        base + match_bytes
    }

    // ── internal helpers ─────────────────────────────────────────────────

    fn find_lfu_victim(&self) -> Option<CacheKey> {
        self.entries
            .iter()
            .min_by_key(|(_, e)| e.access_count)
            .map(|(k, _)| *k)
    }
}

// ---------------------------------------------------------------------------
// Hex helper
// ---------------------------------------------------------------------------

fn hex_to_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> CacheKey {
        CacheKey {
            file_hash: [n; 32],
            rules_hash: [0u8; 32],
        }
    }

    fn empty_matches() -> Vec<YaraMatch> {
        vec![]
    }

    fn one_match() -> Vec<YaraMatch> {
        vec![YaraMatch::new("Test_Rule")]
    }

    #[test]
    fn test_insert_and_get() {
        let mut cache = YaraCache::new(10, 1024 * 1024, CachePolicy::LRU);
        let k = key(1);
        cache.insert(k, one_match(), 10, 1000);
        let result = cache.get(&k, 1001);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn test_get_miss() {
        let mut cache = YaraCache::new(10, 1024 * 1024, CachePolicy::LRU);
        let result = cache.get(&key(99), 1000);
        assert!(result.is_none());
        assert_eq!(cache.stats().misses, 1);
    }

    #[test]
    fn test_hit_rate() {
        let mut cache = YaraCache::new(10, 1024 * 1024, CachePolicy::LRU);
        cache.insert(key(1), empty_matches(), 5, 1000);
        cache.get(&key(1), 1001); // hit
        cache.get(&key(2), 1002); // miss
        let rate = cache.cache_hit_rate();
        assert!((rate - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_evict_expired() {
        let mut cache = YaraCache::new(10, 1024 * 1024, CachePolicy::LRU);
        cache.insert(key(1), empty_matches(), 5, 1000);
        cache.insert(key(2), empty_matches(), 5, 1000);
        let removed = cache.evict_expired(2001, 500); // max_age = 500 s → 1000+500 < 2001
        assert_eq!(removed, 2);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_evict_expired_none_expired() {
        let mut cache = YaraCache::new(10, 1024 * 1024, CachePolicy::LRU);
        cache.insert(key(1), empty_matches(), 5, 1000);
        let removed = cache.evict_expired(1100, 500); // 1000 + 500 > 1100
        assert_eq!(removed, 0);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_lru_eviction_order() {
        let mut cache = YaraCache::new(2, u64::MAX, CachePolicy::LRU);
        cache.insert(key(1), empty_matches(), 5, 1000);
        cache.insert(key(2), empty_matches(), 5, 1001);
        // Access key(1) so key(2) is least recently used
        cache.get(&key(1), 1002);
        // Insert key(3) — should evict key(2)
        cache.insert(key(3), empty_matches(), 5, 1003);
        assert!(cache.peek(&key(1)).is_some());
        assert!(cache.peek(&key(3)).is_some());
        assert!(cache.peek(&key(2)).is_none());
    }

    #[test]
    fn test_fifo_eviction_order() {
        let mut cache = YaraCache::new(2, u64::MAX, CachePolicy::FIFO);
        cache.insert(key(1), empty_matches(), 5, 1000);
        cache.insert(key(2), empty_matches(), 5, 1001);
        // Insert key(3) — FIFO evicts key(1)
        cache.insert(key(3), empty_matches(), 5, 1002);
        assert!(cache.peek(&key(1)).is_none());
        assert!(cache.peek(&key(2)).is_some());
        assert!(cache.peek(&key(3)).is_some());
    }

    #[test]
    fn test_lfu_eviction_order() {
        let mut cache = YaraCache::new(2, u64::MAX, CachePolicy::LFU);
        cache.insert(key(1), empty_matches(), 5, 1000);
        cache.insert(key(2), empty_matches(), 5, 1001);
        // Access key(2) twice → key(1) has access_count=0
        cache.get(&key(2), 1002);
        cache.get(&key(2), 1003);
        // Insert key(3) — LFU evicts key(1) (access_count=0)
        cache.insert(key(3), empty_matches(), 5, 1004);
        assert!(cache.peek(&key(1)).is_none(), "LFU should evict key(1)");
        assert!(cache.peek(&key(2)).is_some());
    }

    #[test]
    fn test_remove_entry() {
        let mut cache = YaraCache::new(10, 1024 * 1024, CachePolicy::LRU);
        cache.insert(key(1), empty_matches(), 5, 1000);
        assert!(cache.remove(&key(1)));
        assert!(!cache.remove(&key(1)));
        assert!(cache.is_empty());
    }

    #[test]
    fn test_clear() {
        let mut cache = YaraCache::new(10, 1024 * 1024, CachePolicy::LRU);
        for i in 0..5u8 {
            cache.insert(key(i), empty_matches(), 5, 1000);
        }
        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.memory_bytes(), 0);
    }

    #[test]
    fn test_memory_tracking() {
        let mut cache = YaraCache::new(10, 1024 * 1024, CachePolicy::LRU);
        cache.insert(key(1), one_match(), 5, 1000);
        assert!(cache.memory_bytes() > 0);
        let mem_before = cache.memory_bytes();
        cache.remove(&key(1));
        assert!(cache.memory_bytes() < mem_before);
    }

    #[test]
    fn test_estimate_entry_memory_empty() {
        let mem = YaraCache::estimate_entry_memory(&[]);
        assert!(mem >= std::mem::size_of::<CacheEntry>() as u64);
    }

    #[test]
    fn test_estimate_entry_memory_nonempty() {
        let matches = vec![YaraMatch::new("SomeRule"), YaraMatch::new("AnotherRule")];
        let mem = YaraCache::estimate_entry_memory(&matches);
        assert!(mem > YaraCache::estimate_entry_memory(&[]));
    }

    #[test]
    fn test_cache_key_from_slices() {
        let k = CacheKey::from_slices(&[1u8; 32], &[2u8; 32]);
        assert_eq!(k.file_hash, [1u8; 32]);
        assert_eq!(k.rules_hash, [2u8; 32]);
    }

    #[test]
    fn test_cache_key_short_display_len() {
        let k = CacheKey { file_hash: [0xABu8; 32], rules_hash: [0u8; 32] };
        assert_eq!(k.short_display().len(), 16); // 8 bytes × 2 hex chars
    }

    #[test]
    fn test_cache_key_from_hex_invalid() {
        assert!(CacheKey::from_hex("abc", "def").is_none());
    }

    #[test]
    fn test_duplicate_insert_replaces() {
        let mut cache = YaraCache::new(10, 1024 * 1024, CachePolicy::LRU);
        let k = key(5);
        cache.insert(k, empty_matches(), 5, 1000);
        cache.insert(k, one_match(), 10, 1001);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.peek(&k).unwrap().result.len(), 1);
    }
}
