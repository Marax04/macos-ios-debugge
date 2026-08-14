//! `agent_memory_store` —  Agent working memory for RE analysis results.
//!
//! Provides [`AgentMemoryStore`]: a thread-safe, capacity-bounded in-memory
//! store for analysis findings.  Supports full-text search, tag-based recall,
//! TTL-based expiry, and serialisation to/from JSON.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

// â"€â"€ MemoryKind â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Classifies the type of information stored in a memory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryKind {
    /// Function-level analysis result (e.g. decompilation summary).
    FunctionAnalysis,
    /// A detected vulnerability or weakness.
    Vulnerability,
    /// A string constant found in the binary.
    StringEvidence,
    /// A cryptographic algorithm identification.
    CryptoFinding,
    /// An API call pattern.
    ApiPattern,
    /// An imported or exported symbol.
    Symbol,
    /// A code structure (loop, switch, etc.).
    CodeStructure,
    /// A data type definition.
    TypeDefinition,
    /// Free-form observation.
    Observation,
    /// User-provided annotation.
    Annotation,
}

impl std::fmt::Display for MemoryKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl MemoryKind {
    /// Returns `true` for security-relevant kinds.
    #[must_use]
    pub const fn is_security_relevant(self) -> bool {
        matches!(self, Self::Vulnerability | Self::CryptoFinding)
    }

    /// Returns `true` for code-structure kinds.
    #[must_use]
    pub const fn is_code_related(self) -> bool {
        matches!(
            self,
            Self::FunctionAnalysis | Self::ApiPattern | Self::CodeStructure | Self::TypeDefinition
        )
    }
}

// â"€â"€ MemoryEntry â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A single entry in the agent's working memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    /// Unique key within the store (e.g. `"func:0x401000"`).
    pub key: String,
    /// Classification of this entry.
    pub kind: MemoryKind,
    /// Human-readable summary.
    pub summary: String,
    /// Structured data associated with this entry.
    pub data: serde_json::Value,
    /// Optional binary virtual address this entry relates to.
    pub address: Option<u64>,
    /// Confidence in [0.0, 1.0].
    pub confidence: f32,
    /// Searchable tags.
    pub tags: Vec<String>,
    /// Creation timestamp (ms since Unix epoch).
    pub created_at: u64,
    /// Last-updated timestamp.
    pub updated_at: u64,
    /// Optional TTL in milliseconds after which the entry should be considered
    /// stale.  `None` means no expiry.
    pub ttl_ms: Option<u64>,
    /// Number of times this entry has been read.
    pub access_count: u64,
}

impl MemoryEntry {
    /// Create a new entry.
    #[must_use]
    pub fn new(
        key: impl Into<String>,
        kind: MemoryKind,
        summary: impl Into<String>,
        data: serde_json::Value,
    ) -> Self {
        let now = now_ms();
        Self {
            key: key.into(),
            kind,
            summary: summary.into(),
            data,
            address: None,
            confidence: 0.5,
            tags: Vec::new(),
            created_at: now,
            updated_at: now,
            ttl_ms: None,
            access_count: 0,
        }
    }

    /// Set the virtual address this entry relates to.
    #[must_use]
    pub const fn at_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    /// Set the confidence level.
    #[must_use]
    pub const fn with_confidence(mut self, c: f32) -> Self {
        // NaN-safe clamp: `f32::clamp` propagates NaN and `is_nan()` is not
        // available in a const fn.
        self.confidence = if c >= 1.0 {
            1.0
        } else if c > 0.0 {
            c
        } else {
            0.0
        };
        self
    }

    /// Attach tags.
    #[must_use]
    pub fn with_tags(mut self, tags: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.tags = tags.into_iter().map(std::convert::Into::into).collect();
        self
    }

    /// Set a TTL in milliseconds.
    #[must_use]
    pub const fn with_ttl_ms(mut self, ttl: u64) -> Self {
        self.ttl_ms = Some(ttl);
        self
    }

    /// Returns `true` if this entry has expired past its TTL.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.ttl_ms.is_some_and(|ttl| now_ms().saturating_sub(self.created_at) >= ttl)
    }

    /// Returns `true` if the `summary` or any tag contains `query` (case-insensitive).
    #[must_use]
    pub fn matches_text(&self, query: &str) -> bool {
        let q = query.to_lowercase();
        self.summary.to_lowercase().contains(&q)
            || self.key.to_lowercase().contains(&q)
            || self.tags.iter().any(|t| t.to_lowercase().contains(&q))
    }

    /// Touch the `updated_at` timestamp and increment `access_count`.
    pub fn touch(&mut self) {
        self.updated_at = now_ms();
        self.access_count += 1;
    }
}

// â"€â"€ AgentMemoryStore â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Thread-safe, capacity-bounded store for [`MemoryEntry`] values.
///
/// When the store is full and a new entry is inserted, the entry with the
/// lowest confidence (then oldest `created_at`) is evicted.
pub struct AgentMemoryStore {
    entries: RwLock<HashMap<String, MemoryEntry>>,
    capacity: usize,
}

impl AgentMemoryStore {
    /// Create a new store with the given maximum capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            capacity: capacity.max(1),
        }
    }

    /// Store a new entry or replace an existing one with the same key.
    pub fn store(&self, mut entry: MemoryEntry) {
        let mut guard = self.entries.write();

        // If the key already exists, just update in place.
        if guard.contains_key(&entry.key) {
            entry.updated_at = now_ms();
            guard.insert(entry.key.clone(), entry);
            return;
        }

        // Evict if at capacity.
        if guard.len() >= self.capacity
            && let Some(victim_key) = Self::pick_eviction_victim(&guard) {
                guard.remove(&victim_key);
            }

        guard.insert(entry.key.clone(), entry);
    }

    /// Retrieve an entry by key, incrementing its access count.
    pub fn get(&self, key: &str) -> Option<MemoryEntry> {
        // Check with read lock first.
        let expired_or_missing = {
            let guard = self.entries.read();
            let r = guard.get(key).map(MemoryEntry::is_expired);
            drop(guard);
            r
        };
        match expired_or_missing {
            None | Some(true) => return None,
            Some(false) => {}
        }
        // Upgrade to write lock to update access count.
        let mut guard = self.entries.write();
        let entry = guard.get_mut(key)?;
        entry.touch();
        let result = entry.clone();
        drop(guard);
        Some(result)
    }

    /// Remove an entry by key.  Returns `true` if it existed.
    pub fn remove(&self, key: &str) -> bool {
        self.entries.write().remove(key).is_some()
    }

    /// Returns `true` if a non-expired entry with `key` exists.
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.entries
            .read()
            .get(key)
            .is_some_and(|e| !e.is_expired())
    }

    /// Search entries whose text matches `query` (case-insensitive substring).
    ///
    /// Returns entries sorted by confidence descending.
    #[must_use]
    pub fn search_memory(&self, query: &str) -> Vec<MemoryEntry> {
        let mut results: Vec<MemoryEntry> = self
            .entries
            .read()
            .values()
            .filter(|e| !e.is_expired() && e.matches_text(query))
            .cloned()
            .collect();
        results.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results
    }

    /// Recall all entries of a given [`MemoryKind`], sorted by confidence.
    #[must_use]
    pub fn recall(&self, kind: MemoryKind) -> Vec<MemoryEntry> {
        let mut results: Vec<MemoryEntry> = self
            .entries
            .read()
            .values()
            .filter(|e| !e.is_expired() && e.kind == kind)
            .cloned()
            .collect();
        results.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results
    }

    /// Return entries related to `address`, sorted by confidence.
    #[must_use]
    pub fn recall_by_address(&self, address: u64) -> Vec<MemoryEntry> {
        let mut results: Vec<MemoryEntry> = self
            .entries
            .read()
            .values()
            .filter(|e| !e.is_expired() && e.address == Some(address))
            .cloned()
            .collect();
        results.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results
    }

    /// Return entries that have all of the given `tags`.
    #[must_use]
    pub fn recall_by_tags(&self, tags: &[&str]) -> Vec<MemoryEntry> {
        let guard = self.entries.read();
        guard
            .values()
            .filter(|e| {
                !e.is_expired()
                    && tags
                        .iter()
                        .all(|t| e.tags.iter().any(|et| et.as_str() == *t))
            })
            .cloned()
            .collect()
    }

    /// Return all non-expired entries sorted by `created_at` descending
    /// (most recent first), up to `limit`.
    #[must_use]
    pub fn recent(&self, limit: usize) -> Vec<MemoryEntry> {
        let mut entries: Vec<MemoryEntry> = {
            let guard = self.entries.read();
            guard.values().filter(|e| !e.is_expired()).cloned().collect()
        };
        entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        entries.into_iter().take(limit).collect()
    }

    /// Return all entries with confidence â‰¥ `min_confidence`.
    #[must_use]
    pub fn high_confidence(&self, min_confidence: f32) -> Vec<MemoryEntry> {
        self.entries
            .read()
            .values()
            .filter(|e| !e.is_expired() && e.confidence >= min_confidence)
            .cloned()
            .collect()
    }

    /// Total number of non-expired entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
            .read()
            .values()
            .filter(|e| !e.is_expired())
            .count()
    }

    /// Returns `true` if the store contains no non-expired entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Maximum capacity of the store.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Purge all entries that have exceeded their TTL.  Returns the count removed.
    pub fn purge_expired(&self) -> usize {
        let mut guard = self.entries.write();
        let before = guard.len();
        guard.retain(|_, e| !e.is_expired());
        before - guard.len()
    }

    /// Clear all entries from the store.
    pub fn clear(&self) {
        self.entries.write().clear();
    }

    /// Serialise all non-expired entries to a JSON string.
    /// # Errors
    /// Returns `serde_json::Error` if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let snapshot: Vec<MemoryEntry> = {
            let guard = self.entries.read();
            guard.values().filter(|e| !e.is_expired()).cloned().collect()
        };
        serde_json::to_string(&snapshot)
    }

    /// Load entries from a JSON string, merging with existing data.
    ///
    /// Entries from the JSON take precedence over existing entries with the same key.
    /// # Errors
    /// Returns `serde_json::Error` if deserialization fails.
    pub fn from_json(&self, json: &str) -> Result<usize, serde_json::Error> {
        let entries: Vec<MemoryEntry> = serde_json::from_str(json)?;
        let count = entries.len();
        for entry in entries {
            self.store(entry);
        }
        Ok(count)
    }

    /// Return a per-kind count of non-expired entries.
    #[must_use]
    pub fn kind_histogram(&self) -> HashMap<MemoryKind, usize> {
        let mut hist: HashMap<MemoryKind, usize> = HashMap::new();
        for e in self.entries.read().values() {
            if !e.is_expired() {
                *hist.entry(e.kind).or_insert(0) += 1;
            }
        }
        hist
    }

    /// Pick the key of the entry to evict (lowest confidence, then oldest).
    fn pick_eviction_victim(map: &HashMap<String, MemoryEntry>) -> Option<String> {
        map.values()
            .min_by(|a, b| {
                a.confidence
                    .partial_cmp(&b.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.created_at.cmp(&b.created_at))
            })
            .map(|e| e.key.clone())
    }
}

// â"€â"€ MemorySnapshot â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A read-only snapshot of the memory store for inspection / reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySnapshot {
    pub entries: Vec<MemoryEntry>,
    pub taken_at: u64,
}

impl MemorySnapshot {
    /// Take a snapshot of all non-expired entries.
    #[must_use]
    pub fn take(store: &AgentMemoryStore) -> Self {
        let entries: Vec<MemoryEntry> = {
            let guard = store.entries.read();
            guard.values().filter(|e| !e.is_expired()).cloned().collect()
        };
        Self {
            entries,
            taken_at: now_ms(),
        }
    }

    /// Return entries in this snapshot that match the given kind.
    #[must_use]
    pub fn filter_by_kind(&self, kind: MemoryKind) -> Vec<&MemoryEntry> {
        self.entries.iter().filter(|e| e.kind == kind).collect()
    }

    /// Total entry count in this snapshot.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the snapshot is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// â"€â"€ helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

// â"€â"€ Tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(key: &str, kind: MemoryKind, summary: &str, conf: f32) -> MemoryEntry {
        MemoryEntry::new(key, kind, summary, serde_json::json!({})).with_confidence(conf)
    }

    #[test]
    fn test_store_and_get() {
        let store = AgentMemoryStore::new(100);
        let entry = make_entry("func:0x1000", MemoryKind::FunctionAnalysis, "malloc wrapper", 0.9);
        store.store(entry);
        let got = store.get("func:0x1000").unwrap();
        assert_eq!(got.summary, "malloc wrapper");
        assert_eq!(got.access_count, 1);
    }

    #[test]
    fn test_get_missing_returns_none() {
        let store = AgentMemoryStore::new(10);
        assert!(store.get("nonexistent").is_none());
    }

    #[test]
    fn test_remove() {
        let store = AgentMemoryStore::new(10);
        store.store(make_entry("k1", MemoryKind::Observation, "x", 0.5));
        assert!(store.remove("k1"));
        assert!(!store.remove("k1"));
        assert!(store.is_empty());
    }

    #[test]
    fn test_search_memory_case_insensitive() {
        let store = AgentMemoryStore::new(50);
        store.store(make_entry("a", MemoryKind::Vulnerability, "Buffer Overflow found", 0.9));
        store.store(make_entry("b", MemoryKind::Observation, "nothing special", 0.5));
        let results = store.search_memory("buffer");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].key, "a");
    }

    #[test]
    fn test_recall_by_kind() {
        let store = AgentMemoryStore::new(50);
        store.store(make_entry("v1", MemoryKind::Vulnerability, "sqli", 0.95));
        store.store(make_entry("v2", MemoryKind::Vulnerability, "bof", 0.85));
        store.store(make_entry("o1", MemoryKind::Observation, "normal", 0.5));
        let vulns = store.recall(MemoryKind::Vulnerability);
        assert_eq!(vulns.len(), 2);
        // Sorted by confidence desc.
        assert!(vulns[0].confidence >= vulns[1].confidence);
    }

    #[test]
    fn test_recall_by_address() {
        let store = AgentMemoryStore::new(20);
        let e = make_entry("sym:0x4000", MemoryKind::Symbol, "sub_4000", 0.7)
            .at_address(0x4000);
        store.store(e);
        store.store(make_entry("other", MemoryKind::Observation, "other", 0.5));
        let found = store.recall_by_address(0x4000);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].key, "sym:0x4000");
    }

    #[test]
    fn test_recall_by_tags() {
        let store = AgentMemoryStore::new(20);
        let e = make_entry("t1", MemoryKind::ApiPattern, "CreateFile usage", 0.7)
            .with_tags(["filesystem", "windows"]);
        let e2 = make_entry("t2", MemoryKind::ApiPattern, "CreateMutex", 0.6)
            .with_tags(["sync", "windows"]);
        store.store(e);
        store.store(e2);
        let found = store.recall_by_tags(&["windows"]);
        assert_eq!(found.len(), 2);
        let found_fs = store.recall_by_tags(&["filesystem"]);
        assert_eq!(found_fs.len(), 1);
    }

    #[test]
    fn test_capacity_eviction() {
        let store = AgentMemoryStore::new(3);
        store.store(make_entry("low", MemoryKind::Observation, "x", 0.1));
        store.store(make_entry("mid", MemoryKind::Observation, "x", 0.5));
        store.store(make_entry("high", MemoryKind::Observation, "x", 0.9));
        // Adding a 4th entry should evict the lowest-confidence one.
        store.store(make_entry("new", MemoryKind::Observation, "x", 0.8));
        assert_eq!(store.len(), 3);
        assert!(!store.contains("low"), "low-confidence entry should have been evicted");
    }

    #[test]
    fn test_ttl_expiry() {
        let store = AgentMemoryStore::new(10);
        // TTL of 0 ms —" already expired.
        let e = make_entry("exp", MemoryKind::Observation, "soon gone", 0.5).with_ttl_ms(0);
        store.store(e);
        // get() should return None for an expired entry.
        assert!(store.get("exp").is_none());
    }

    #[test]
    fn test_purge_expired() {
        let store = AgentMemoryStore::new(10);
        let e = make_entry("e1", MemoryKind::Observation, "x", 0.5).with_ttl_ms(0);
        store.store(e);
        store.store(make_entry("e2", MemoryKind::Observation, "y", 0.5));
        assert_eq!(store.purge_expired(), 1);
    }

    #[test]
    fn test_high_confidence_filter() {
        let store = AgentMemoryStore::new(20);
        store.store(make_entry("a", MemoryKind::Vulnerability, "a", 0.9));
        store.store(make_entry("b", MemoryKind::Vulnerability, "b", 0.4));
        let high = store.high_confidence(0.8);
        assert_eq!(high.len(), 1);
        assert_eq!(high[0].key, "a");
    }

    #[test]
    fn test_json_roundtrip() {
        let store = AgentMemoryStore::new(50);
        store.store(make_entry("k1", MemoryKind::FunctionAnalysis, "summary", 0.8));
        store.store(make_entry("k2", MemoryKind::Symbol, "sym_name", 0.6));

        let json = store.to_json().unwrap();
        let store2 = AgentMemoryStore::new(50);
        let loaded = store2.from_json(&json).unwrap();
        assert_eq!(loaded, 2);
        assert!(store2.contains("k1"));
        assert!(store2.contains("k2"));
    }

    #[test]
    fn test_kind_histogram() {
        let store = AgentMemoryStore::new(20);
        store.store(make_entry("a", MemoryKind::Vulnerability, "x", 0.9));
        store.store(make_entry("b", MemoryKind::Vulnerability, "y", 0.8));
        store.store(make_entry("c", MemoryKind::Observation, "z", 0.5));
        let hist = store.kind_histogram();
        assert_eq!(hist[&MemoryKind::Vulnerability], 2);
        assert_eq!(hist[&MemoryKind::Observation], 1);
    }

    #[test]
    fn test_memory_snapshot() {
        let store = AgentMemoryStore::new(20);
        store.store(make_entry("x", MemoryKind::CryptoFinding, "AES detected", 0.95));
        let snap = MemorySnapshot::take(&store);
        assert_eq!(snap.len(), 1);
        let crypto = snap.filter_by_kind(MemoryKind::CryptoFinding);
        assert_eq!(crypto.len(), 1);
    }

    #[test]
    fn test_memory_kind_predicates() {
        assert!(MemoryKind::Vulnerability.is_security_relevant());
        assert!(MemoryKind::CryptoFinding.is_security_relevant());
        assert!(!MemoryKind::Observation.is_security_relevant());
        assert!(MemoryKind::FunctionAnalysis.is_code_related());
        assert!(!MemoryKind::Vulnerability.is_code_related());
    }

    #[test]
    fn test_recent() {
        let store = AgentMemoryStore::new(50);
        for i in 0..10u64 {
            let mut e = make_entry(&format!("k{i}"), MemoryKind::Observation, "x", 0.5);
            e.created_at = i;
            store.store(e);
        }
        let r = store.recent(3);
        assert_eq!(r.len(), 3);
        // Most recent should be first (highest created_at).
        assert!(r[0].created_at >= r[1].created_at);
    }

    #[test]
    fn test_update_existing_key() {
        let store = AgentMemoryStore::new(10);
        store.store(make_entry("dup", MemoryKind::Observation, "v1", 0.5));
        store.store(make_entry("dup", MemoryKind::Observation, "v2", 0.8));
        assert_eq!(store.len(), 1);
        assert_eq!(store.get("dup").unwrap().summary, "v2");
    }
}
