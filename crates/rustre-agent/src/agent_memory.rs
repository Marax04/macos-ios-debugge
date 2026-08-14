//! `agent_memory` —  multi-tier memory system for `RustRE` AI agents.
//!
//! Provides:
//! - [`ShortTermMemory`] —" bounded ring buffer of recent conversation turns
//! - [`LongTermMemory`] —" persistent key-value store with importance scoring
//! - [`AgentMemory`] —" unified facade consolidating both tiers
//! - [`MemoryEntry`] —" the unit of storage (key/value/timestamp/importance)
//! - [`MemorySearch`] —" query builder for memory lookups
//! - [`MemoryConsolidation`] —" moves important short-term entries to long-term
//! - [`MemoryExport`] —" JSON export/import of the full memory state

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// â"€â"€ MemoryEntry â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A single memory entry stored in the agent's memory system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    /// Unique key identifying this entry.
    pub key: String,
    /// The stored value (arbitrary JSON).
    pub value: serde_json::Value,
    /// Unix epoch timestamp in milliseconds when this entry was created.
    pub timestamp: u64,
    /// Importance score in [0.0, 1.0]. Higher = more important.
    pub importance: f32,
    /// Tags for grouping / filtering.
    pub tags: Vec<String>,
    /// Number of times this entry has been accessed.
    pub access_count: u64,
    /// Last access timestamp.
    pub last_accessed: u64,
}

impl MemoryEntry {
    /// Create a new entry with default importance 0.5.
    #[must_use]
    pub fn new(key: impl Into<String>, value: serde_json::Value) -> Self {
        let now = now_ms();
        Self {
            key: key.into(),
            value,
            timestamp: now,
            importance: 0.5,
            tags: Vec::new(),
            access_count: 0,
            last_accessed: now,
        }
    }

    /// Set importance.
    #[must_use]
    pub const fn with_importance(mut self, importance: f32) -> Self {
        // NaN-safe clamp: `f32::clamp` propagates NaN and `is_nan()` is not
        // available in a const fn. A NaN importance would lose every ranking
        // comparison it takes part in, so the entry would silently vanish.
        self.importance = if importance >= 1.0 {
            1.0
        } else if importance > 0.0 {
            importance
        } else {
            0.0
        };
        self
    }

    /// Add tags.
    #[must_use]
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Add a single tag.
    #[must_use]
    pub fn tag(mut self, t: impl Into<String>) -> Self {
        self.tags.push(t.into());
        self
    }

    /// Mark this entry as accessed, updating counters.
    pub fn touch(&mut self) {
        self.access_count += 1;
        self.last_accessed = now_ms();
    }

    /// Return `true` if this entry has been tagged with `t`.
    #[must_use]
    pub fn has_tag(&self, t: &str) -> bool {
        self.tags.iter().any(|tag| tag == t)
    }

    /// Age of this entry in seconds.
    #[must_use]
    pub fn age_secs(&self) -> u64 {
        (now_ms().saturating_sub(self.timestamp)) / 1000
    }

    /// Return a relevance score combining importance and recency.
    #[must_use]
    pub fn relevance_score(&self) -> f32 {
        let age_penalty = 1.0 / (1.0 + crate::casts::u64_to_f32(self.age_secs()) / 3600.0); // decay over hours
        self.importance * age_penalty
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

// â"€â"€ MemorySearch â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Query builder for searching memory entries.
#[derive(Debug, Clone, Default)]
pub struct MemorySearch {
    /// Substring that must appear in the key.
    pub key_contains: Option<String>,
    /// Tag that must be present.
    pub required_tag: Option<String>,
    /// Minimum importance score.
    pub min_importance: Option<f32>,
    /// Maximum age in seconds.
    pub max_age_secs: Option<u64>,
    /// Maximum number of results to return.
    pub limit: Option<usize>,
    /// Sort by relevance (default: true).
    pub sort_by_relevance: bool,
}

impl MemorySearch {
    /// Create a new empty search.
    #[must_use]
    pub fn new() -> Self {
        Self { sort_by_relevance: true, ..Default::default() }
    }

    /// Filter by key substring.
    #[must_use]
    pub fn key_contains(mut self, s: impl Into<String>) -> Self {
        self.key_contains = Some(s.into());
        self
    }

    /// Filter by tag.
    #[must_use]
    pub fn tagged(mut self, tag: impl Into<String>) -> Self {
        self.required_tag = Some(tag.into());
        self
    }

    /// Filter by minimum importance.
    #[must_use]
    pub const fn min_importance(mut self, v: f32) -> Self {
        self.min_importance = Some(v.clamp(0.0, 1.0));
        self
    }

    /// Filter by maximum age.
    #[must_use]
    pub const fn max_age(mut self, secs: u64) -> Self {
        self.max_age_secs = Some(secs);
        self
    }

    /// Limit results.
    #[must_use]
    pub const fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }

    /// Disable relevance sorting.
    #[must_use]
    pub const fn unsorted(mut self) -> Self {
        self.sort_by_relevance = false;
        self
    }

    /// Apply this search to a slice of entries and return matching clones.
    #[must_use]
    pub fn execute<'a>(&self, entries: &'a [MemoryEntry]) -> Vec<&'a MemoryEntry> {
        let mut results: Vec<&MemoryEntry> = entries
            .iter()
            .filter(|e| self.matches(e))
            .collect();

        if self.sort_by_relevance {
            results.sort_by(|a, b| {
                b.relevance_score()
                    .partial_cmp(&a.relevance_score())
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        }

        if let Some(limit) = self.limit {
            results.truncate(limit);
        }

        results
    }

    fn matches(&self, entry: &MemoryEntry) -> bool {
        if let Some(substr) = &self.key_contains
            && !entry.key.contains(substr.as_str()) {
                return false;
            }
        if let Some(tag) = &self.required_tag
            && !entry.has_tag(tag) {
                return false;
            }
        if let Some(min_imp) = self.min_importance
            && entry.importance < min_imp {
                return false;
            }
        if let Some(max_age) = self.max_age_secs
            && entry.age_secs() > max_age {
                return false;
            }
        true
    }
}

// â"€â"€ ShortTermMemory â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A bounded ring-buffer of recent conversation turns / observations.
///
/// When capacity is exceeded, the oldest entry is evicted.
#[derive(Debug, Clone, Default)]
pub struct ShortTermMemory {
    entries: Vec<MemoryEntry>,
    capacity: usize,
}

impl ShortTermMemory {
    /// Create a short-term memory with the given capacity.
    #[must_use]
    pub const fn new(capacity: usize) -> Self {
        Self { entries: Vec::new(), capacity }
    }

    /// Push a new entry, evicting the oldest if at capacity.
    pub fn push(&mut self, entry: MemoryEntry) {
        if self.capacity > 0 && self.entries.len() >= self.capacity {
            self.entries.remove(0);
        }
        self.entries.push(entry);
    }

    /// Return the most recent `n` entries.
    #[must_use]
    pub fn recent(&self, n: usize) -> Vec<&MemoryEntry> {
        self.entries.iter().rev().take(n).collect()
    }

    /// Find entries matching `search`.
    #[must_use]
    pub fn search(&self, search: &MemorySearch) -> Vec<&MemoryEntry> {
        search.execute(&self.entries)
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Return all entries.
    #[must_use]
    pub fn all(&self) -> &[MemoryEntry] {
        &self.entries
    }

    /// Return entries with importance above threshold.
    #[must_use]
    pub fn high_importance(&self, threshold: f32) -> Vec<&MemoryEntry> {
        self.entries.iter().filter(|e| e.importance >= threshold).collect()
    }
}

// â"€â"€ LongTermMemory â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Persistent key-value memory store with importance-based eviction.
#[derive(Debug, Default)]
pub struct LongTermMemory {
    entries: HashMap<String, MemoryEntry>,
    capacity: usize,
}

impl LongTermMemory {
    /// Create a long-term memory.  `capacity == 0` means unlimited.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self { entries: HashMap::new(), capacity }
    }

    /// Store or update an entry.  When at capacity, the least relevant entry
    /// is evicted (lowest `relevance_score()`).
    pub fn store(&mut self, entry: MemoryEntry) {
        if self.capacity > 0 && !self.entries.contains_key(&entry.key)
            && self.entries.len() >= self.capacity
        {
            // Evict least-relevant entry.
            if let Some(key) = self
                .entries
                .values()
                .min_by(|a, b| {
                    a.relevance_score()
                        .partial_cmp(&b.relevance_score())
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|e| e.key.clone())
            {
                self.entries.remove(&key);
            }
        }
        self.entries.insert(entry.key.clone(), entry);
    }

    /// Retrieve an entry by key, updating its access count.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut MemoryEntry> {
        let entry = self.entries.get_mut(key)?;
        entry.touch();
        Some(entry)
    }

    /// Retrieve an entry by key (immutable).
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&MemoryEntry> {
        self.entries.get(key)
    }

    /// Remove an entry by key.
    pub fn remove(&mut self, key: &str) -> bool {
        self.entries.remove(key).is_some()
    }

    /// Find entries matching `search`.
    #[must_use]
    pub fn search(&self, search: &MemorySearch) -> Vec<&MemoryEntry> {
        let mut results: Vec<&MemoryEntry> = self.entries.values().filter(|e| search.matches(e)).collect();
        if search.sort_by_relevance {
            results.sort_by(|a, b| {
                b.relevance_score()
                    .partial_cmp(&a.relevance_score())
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        }
        if let Some(limit) = search.limit {
            results.truncate(limit);
        }
        results
    }

    /// Return all entries as a flat list.
    #[must_use]
    pub fn all(&self) -> Vec<&MemoryEntry> {
        self.entries.values().collect()
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Return keys of all entries.
    #[must_use]
    pub fn keys(&self) -> Vec<&str> {
        self.entries.keys().map(String::as_str).collect()
    }
}

// â"€â"€ MemoryConsolidation â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Consolidates short-term entries into long-term memory based on importance.
#[derive(Debug, Clone)]
pub struct MemoryConsolidation {
    /// Entries with importance >= this threshold are promoted.
    pub importance_threshold: f32,
    /// Maximum age (seconds) of entries eligible for consolidation.
    pub max_age_secs: u64,
    /// Number of entries consolidated in the last run.
    pub last_consolidated: usize,
}

impl MemoryConsolidation {
    /// Create a consolidator with default threshold 0.7.
    #[must_use]
    pub const fn new(importance_threshold: f32) -> Self {
        Self {
            // NaN-safe clamp — see `set_threshold`.
            importance_threshold: if importance_threshold >= 1.0 {
                1.0
            } else if importance_threshold > 0.0 {
                importance_threshold
            } else {
                0.0
            },
            max_age_secs: 3600,
            last_consolidated: 0,
        }
    }

    /// Run consolidation: move qualifying entries from `short` to `long`.
    ///
    /// Returns the number of entries promoted.
    pub fn consolidate(
        &mut self,
        short: &mut ShortTermMemory,
        long: &mut LongTermMemory,
    ) -> usize {
        let threshold = self.importance_threshold;
        let max_age = self.max_age_secs;

        // Collect indices to promote.
        let to_promote: Vec<usize> = short
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.importance >= threshold && e.age_secs() <= max_age)
            .map(|(i, _)| i)
            .collect();

        let count = to_promote.len();
        // Remove in reverse order to preserve indices.
        for &idx in to_promote.iter().rev() {
            let entry = short.entries.remove(idx);
            long.store(entry);
        }

        self.last_consolidated = count;
        count
    }

    /// Change the importance threshold.
    pub const fn set_threshold(&mut self, threshold: f32) {
        // NaN-safe clamp: a NaN threshold rejects every entry in silence,
        // because all comparisons against NaN are false.
        self.importance_threshold = if threshold >= 1.0 {
            1.0
        } else if threshold > 0.0 {
            threshold
        } else {
            0.0
        };
    }
}

// â"€â"€ MemoryExport â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Exports and imports the full memory state to/from JSON.
pub struct MemoryExport;

impl MemoryExport {
    /// Serialize short-term and long-term memory to a JSON string.
    ///
    /// # Errors
    /// Returns a string description of serialisation errors.
    pub fn export_json(
        short: &ShortTermMemory,
        long: &LongTermMemory,
    ) -> Result<String, String> {
        let doc = serde_json::json!({
            "short_term": short.all(),
            "long_term": long.all(),
        });
        serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())
    }

    /// Import entries from a JSON string previously produced by `export_json`.
    ///
    /// Returns `(short_entries, long_entries)`.
    ///
    /// # Errors
    /// Returns a string description of parse errors.
    pub fn import_json(
        json: &str,
    ) -> Result<(Vec<MemoryEntry>, Vec<MemoryEntry>), String> {
        let doc: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;

        let parse_entries = |key: &str| -> Result<Vec<MemoryEntry>, String> {
            let arr = doc
                .get(key)
                .and_then(|v| v.as_array())
                .ok_or_else(|| format!("missing '{key}' array"))?;
            arr.iter()
                .map(|v| serde_json::from_value(v.clone()).map_err(|e| e.to_string()))
                .collect()
        };

        let short = parse_entries("short_term")?;
        let long = parse_entries("long_term")?;
        Ok((short, long))
    }
}

// â"€â"€ AgentMemory â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Unified memory facade combining short-term and long-term stores.
pub struct AgentMemory {
    /// Recent turns / observations (bounded).
    pub short_term: ShortTermMemory,
    /// Persistent knowledge (bounded by capacity).
    pub long_term: LongTermMemory,
    /// Consolidation settings.
    pub consolidation: MemoryConsolidation,
}

impl std::fmt::Debug for AgentMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentMemory")
            .field("short_term_len", &self.short_term.len())
            .field("long_term_len", &self.long_term.len())
            .finish_non_exhaustive()
    }
}

impl AgentMemory {
    /// Create an agent memory with sensible defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            short_term: ShortTermMemory::new(50),
            long_term: LongTermMemory::new(1000),
            consolidation: MemoryConsolidation::new(0.7),
        }
    }

    /// Create a memory with custom capacities.
    #[must_use]
    pub fn with_capacities(short_cap: usize, long_cap: usize) -> Self {
        Self {
            short_term: ShortTermMemory::new(short_cap),
            long_term: LongTermMemory::new(long_cap),
            consolidation: MemoryConsolidation::new(0.7),
        }
    }

    /// Remember an observation in short-term memory.
    pub fn observe(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.short_term.push(MemoryEntry::new(key, value));
    }

    /// Remember an important fact directly in long-term memory.
    pub fn remember(&mut self, entry: MemoryEntry) {
        self.long_term.store(entry);
    }

    /// Recall from long-term memory by key.
    #[must_use]
    pub fn recall(&self, key: &str) -> Option<&MemoryEntry> {
        self.long_term.get(key)
    }

    /// Search across both memory tiers.
    #[must_use]
    pub fn search_all(&self, query: &MemorySearch) -> Vec<&MemoryEntry> {
        let mut results: Vec<&MemoryEntry> = query.execute(self.short_term.all());
        results.extend(self.long_term.search(query));
        if query.sort_by_relevance {
            results.sort_by(|a, b| {
                b.relevance_score()
                    .partial_cmp(&a.relevance_score())
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        }
        if let Some(limit) = query.limit {
            results.truncate(limit);
        }
        results
    }

    /// Run consolidation, moving important short-term entries to long-term.
    pub fn consolidate(&mut self) -> usize {
        self.consolidation.consolidate(&mut self.short_term, &mut self.long_term)
    }

    /// Export both memory tiers to JSON.
    ///
    /// # Errors
    /// Returns a string description of serialisation errors.
    pub fn export_json(&self) -> Result<String, String> {
        MemoryExport::export_json(&self.short_term, &self.long_term)
    }

    /// Total number of entries across both tiers.
    #[must_use]
    pub fn total_entries(&self) -> usize {
        self.short_term.len() + self.long_term.len()
    }

    /// Clear all memory.
    pub fn clear_all(&mut self) {
        self.short_term.clear();
        self.long_term.clear();
    }
}

impl Default for AgentMemory {
    fn default() -> Self {
        Self::new()
    }
}

// â"€â"€ Tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(key: &str, importance: f32) -> MemoryEntry {
        MemoryEntry::new(key, serde_json::json!({"k": key})).with_importance(importance)
    }

    fn tagged_entry(key: &str, importance: f32, tag: &str) -> MemoryEntry {
        entry(key, importance).tag(tag)
    }

    // â"€â"€ MemoryEntry â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_memory_entry_new() {
        let e = entry("test", 0.8);
        assert_eq!(e.key, "test");
        assert!((e.importance - 0.8).abs() < 1e-6);
        assert_eq!(e.access_count, 0);
    }

    #[test]
    fn test_memory_entry_importance_clamped() {
        let e = MemoryEntry::new("k", serde_json::json!(null)).with_importance(2.0);
        assert!((e.importance - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_memory_entry_tag() {
        let e = entry("k", 0.5).tag("binary").tag("pe");
        assert!(e.has_tag("binary"));
        assert!(e.has_tag("pe"));
        assert!(!e.has_tag("elf"));
    }

    #[test]
    fn test_memory_entry_touch() {
        let mut e = entry("k", 0.5);
        e.touch();
        assert_eq!(e.access_count, 1);
    }

    #[test]
    fn test_memory_entry_relevance_score_high_importance() {
        let e = entry("k", 1.0);
        assert!(e.relevance_score() > 0.5);
    }

    #[test]
    fn test_memory_entry_age_secs() {
        let e = entry("k", 0.5);
        // Just created —" age should be 0 or very small.
        assert!(e.age_secs() < 2);
    }

    // â"€â"€ MemorySearch â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_memory_search_key_contains() {
        let entries = vec![entry("func_main", 0.5), entry("func_sub", 0.5), entry("data", 0.5)];
        let results = MemorySearch::new().key_contains("func").execute(&entries);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_memory_search_tagged() {
        let entries = vec![
            tagged_entry("a", 0.5, "binary"),
            tagged_entry("b", 0.5, "text"),
        ];
        let results = MemorySearch::new().tagged("binary").execute(&entries);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].key, "a");
    }

    #[test]
    fn test_memory_search_min_importance() {
        let entries = vec![entry("lo", 0.2), entry("hi", 0.9)];
        let results = MemorySearch::new().min_importance(0.7).execute(&entries);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].key, "hi");
    }

    #[test]
    fn test_memory_search_limit() {
        let entries: Vec<MemoryEntry> = (0..10).map(|i| entry(&format!("k{i}"), 0.5)).collect();
        let results = MemorySearch::new().limit(3).execute(&entries);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_memory_search_no_match() {
        let entries = vec![entry("k", 0.5)];
        let results = MemorySearch::new().key_contains("zzz").execute(&entries);
        assert!(results.is_empty());
    }

    // â"€â"€ ShortTermMemory â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_short_term_push_and_len() {
        let mut stm = ShortTermMemory::new(5);
        stm.push(entry("a", 0.5));
        stm.push(entry("b", 0.5));
        assert_eq!(stm.len(), 2);
    }

    #[test]
    fn test_short_term_capacity_eviction() {
        let mut stm = ShortTermMemory::new(3);
        for i in 0..5 {
            stm.push(entry(&format!("k{i}"), 0.5));
        }
        assert_eq!(stm.len(), 3);
        // Oldest entries evicted, most recent kept.
        assert_eq!(stm.all()[0].key, "k2");
    }

    #[test]
    fn test_short_term_recent() {
        let mut stm = ShortTermMemory::new(10);
        for i in 0..5 {
            stm.push(entry(&format!("k{i}"), 0.5));
        }
        let recent = stm.recent(2);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].key, "k4");
    }

    #[test]
    fn test_short_term_clear() {
        let mut stm = ShortTermMemory::new(10);
        stm.push(entry("a", 0.5));
        stm.clear();
        assert!(stm.is_empty());
    }

    #[test]
    fn test_short_term_high_importance() {
        let mut stm = ShortTermMemory::new(10);
        stm.push(entry("lo", 0.3));
        stm.push(entry("hi", 0.9));
        let results = stm.high_importance(0.7);
        assert_eq!(results.len(), 1);
    }

    // â"€â"€ LongTermMemory â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_long_term_store_and_get() {
        let mut ltm = LongTermMemory::new(10);
        ltm.store(entry("key_a", 0.8));
        assert!(ltm.get("key_a").is_some());
        assert!(ltm.get("missing").is_none());
    }

    #[test]
    fn test_long_term_update_existing() {
        let mut ltm = LongTermMemory::new(10);
        ltm.store(entry("key_a", 0.5));
        ltm.store(MemoryEntry::new("key_a", serde_json::json!("updated")).with_importance(0.9));
        assert_eq!(ltm.len(), 1);
        assert!((ltm.get("key_a").unwrap().importance - 0.9).abs() < 1e-6);
    }

    #[test]
    fn test_long_term_eviction() {
        let mut ltm = LongTermMemory::new(3);
        ltm.store(entry("lo1", 0.1));
        ltm.store(entry("lo2", 0.2));
        ltm.store(entry("hi", 0.9));
        ltm.store(entry("new", 0.5));
        assert_eq!(ltm.len(), 3);
        // "lo1" (lowest relevance) should have been evicted.
        assert!(ltm.get("lo1").is_none());
    }

    #[test]
    fn test_long_term_remove() {
        let mut ltm = LongTermMemory::new(10);
        ltm.store(entry("k", 0.5));
        assert!(ltm.remove("k"));
        assert!(!ltm.remove("k")); // already gone
    }

    #[test]
    fn test_long_term_search() {
        let mut ltm = LongTermMemory::new(10);
        ltm.store(tagged_entry("fn_main", 0.9, "function"));
        ltm.store(tagged_entry("string_01", 0.5, "string"));
        let results = ltm.search(&MemorySearch::new().tagged("function"));
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_long_term_keys() {
        let mut ltm = LongTermMemory::new(10);
        ltm.store(entry("a", 0.5));
        ltm.store(entry("b", 0.5));
        let keys = ltm.keys();
        assert_eq!(keys.len(), 2);
    }

    // â"€â"€ MemoryConsolidation â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_consolidation_promotes_high_importance() {
        let mut stm = ShortTermMemory::new(10);
        let mut ltm = LongTermMemory::new(10);
        stm.push(entry("important", 0.9));
        stm.push(entry("trivial", 0.2));

        let mut cons = MemoryConsolidation::new(0.7);
        let promoted = cons.consolidate(&mut stm, &mut ltm);

        assert_eq!(promoted, 1);
        assert_eq!(stm.len(), 1); // trivial remains
        assert_eq!(ltm.len(), 1); // important promoted
    }

    #[test]
    fn test_consolidation_nothing_to_promote() {
        let mut stm = ShortTermMemory::new(10);
        let mut ltm = LongTermMemory::new(10);
        stm.push(entry("low", 0.1));

        let mut cons = MemoryConsolidation::new(0.7);
        let promoted = cons.consolidate(&mut stm, &mut ltm);
        assert_eq!(promoted, 0);
        assert_eq!(ltm.len(), 0);
    }

    #[test]
    fn test_consolidation_set_threshold() {
        let mut cons = MemoryConsolidation::new(0.5);
        cons.set_threshold(0.9);
        assert!((cons.importance_threshold - 0.9).abs() < 1e-6);
    }

    // â"€â"€ MemoryExport â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_memory_export_roundtrip() {
        let mut stm = ShortTermMemory::new(10);
        let mut ltm = LongTermMemory::new(10);
        stm.push(entry("s1", 0.5));
        ltm.store(entry("l1", 0.8));

        let json = MemoryExport::export_json(&stm, &ltm).unwrap();
        let (short, long) = MemoryExport::import_json(&json).unwrap();
        assert_eq!(short.len(), 1);
        assert_eq!(long.len(), 1);
        assert_eq!(short[0].key, "s1");
        assert_eq!(long[0].key, "l1");
    }

    #[test]
    fn test_memory_export_invalid_json() {
        let result = MemoryExport::import_json("{invalid}");
        assert!(result.is_err());
    }

    // â"€â"€ AgentMemory â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_agent_memory_observe_and_recall() {
        let mut mem = AgentMemory::new();
        mem.observe("rax_type", serde_json::json!("int64_t"));
        assert_eq!(mem.short_term.len(), 1);
    }

    #[test]
    fn test_agent_memory_remember() {
        let mut mem = AgentMemory::new();
        mem.remember(entry("fn_main", 0.95));
        assert!(mem.recall("fn_main").is_some());
    }

    #[test]
    fn test_agent_memory_search_all() {
        let mut mem = AgentMemory::new();
        mem.observe("short_key", serde_json::json!(1));
        mem.remember(entry("long_key", 0.8));
        let results = mem.search_all(&MemorySearch::new());
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_agent_memory_consolidate() {
        let mut mem = AgentMemory::new();
        mem.short_term.push(entry("important", 0.9));
        mem.short_term.push(entry("trivial", 0.1));
        let promoted = mem.consolidate();
        assert_eq!(promoted, 1);
    }

    #[test]
    fn test_agent_memory_total_entries() {
        let mut mem = AgentMemory::new();
        mem.observe("s", serde_json::json!(1));
        mem.remember(entry("l", 0.8));
        assert_eq!(mem.total_entries(), 2);
    }

    #[test]
    fn test_agent_memory_clear_all() {
        let mut mem = AgentMemory::new();
        mem.observe("s", serde_json::json!(1));
        mem.remember(entry("l", 0.8));
        mem.clear_all();
        assert_eq!(mem.total_entries(), 0);
    }

    #[test]
    fn test_agent_memory_export_json() {
        let mut mem = AgentMemory::new();
        mem.observe("s", serde_json::json!(1));
        let json = mem.export_json().unwrap();
        assert!(json.contains("short_term"));
    }

    #[test]
    fn test_agent_memory_with_capacities() {
        let mem = AgentMemory::with_capacities(5, 20);
        assert_eq!(mem.short_term.len(), 0);
        assert_eq!(mem.long_term.len(), 0);
    }
}
