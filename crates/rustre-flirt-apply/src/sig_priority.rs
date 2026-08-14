//! Signature file priority and conflict resolution.
//!
//! When multiple `.sig` or `.pat` files are loaded, the same binary pattern
//! might match functions in different files.  This module defines:
//!
//! * [`SigPriority`] — an ordered list of signature sources with weights.
//! * [`ConflictResolver`] — decides which sig "wins" when multiple match.
//! * [`ManualOverride`] — explicit user-supplied mappings that beat everything.
//! * [`PriorityIndex`] — indexes all loaded sigs with priority metadata for fast lookup.

// AHashMap (randomised) prevents hash-collision DoS from attacker-controlled
// function addresses / library names sourced from untrusted .sig/.pat files.
use ahash::AHashMap as HashMap;
use crate::casts::u64_to_usize;

// ─────────────────────────────────────────────────────────────────────────────
// SigSource
// ─────────────────────────────────────────────────────────────────────────────

/// Identifies a signature source.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SigSource {
    /// Unique tag for the file (e.g. `"msvc2022_x64.sig"`).
    pub tag: String,
    /// Human-readable description.
    pub description: String,
    /// Numeric priority — higher = more trusted.  Default 100.
    pub priority: u32,
    /// Specificity score: how specific this sig file is (e.g. exact version → high).
    pub specificity: u32,
}

impl SigSource {
    /// Create a source with default priority.
    #[must_use]
    pub fn new(tag: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            description: description.into(),
            priority: 100,
            specificity: 50,
        }
    }

    /// Set priority.
    #[must_use]
    pub const fn with_priority(mut self, p: u32) -> Self {
        self.priority = p;
        self
    }

    /// Set specificity.
    #[must_use]
    pub const fn with_specificity(mut self, s: u32) -> Self {
        self.specificity = s;
        self
    }
}

impl std::fmt::Display for SigSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(prio={}, spec={})", self.tag, self.priority, self.specificity)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SigEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A single signature entry associated with a source.
#[derive(Debug, Clone)]
pub struct SigEntry {
    /// The name this signature identifies.
    pub name: String,
    /// Pattern bytes; `None` = wildcard.
    pub pattern: Vec<Option<u8>>,
    /// CRC-16 value.
    pub crc: u16,
    /// CRC offset.
    pub crc_offset: u16,
    /// CRC length.
    pub crc_len: u8,
    /// Source tag.
    pub source_tag: String,
    /// Unique entry ID within the source.
    pub entry_id: u32,
}

impl SigEntry {
    /// Number of concrete bytes in the pattern.
    #[must_use]
    pub fn concrete_bytes(&self) -> usize {
        self.pattern.iter().filter(|b| b.is_some()).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConflictPolicy
// ─────────────────────────────────────────────────────────────────────────────

/// How to handle conflicting matches at the same offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum ConflictPolicy {
    /// Pick the match from the highest-priority source.
    HighestPriority,
    /// Pick the match with the most concrete bytes (most specific).
    MostSpecific,
    /// Pick the match with the highest combined priority × specificity score.
    #[default]
    Weighted,
    /// Keep all conflicts and report them for manual resolution.
    KeepAll,
    /// Drop all conflicting matches (conservative: emit nothing).
    DropAll,
}


// ─────────────────────────────────────────────────────────────────────────────
// ConflictRecord
// ─────────────────────────────────────────────────────────────────────────────

/// Describes a conflict between two entries for the same function offset.
#[derive(Debug, Clone)]
pub struct ConflictRecord {
    pub offset: u64,
    pub winner: SigEntry,
    pub loser: SigEntry,
    pub policy_applied: ConflictPolicy,
}

// ─────────────────────────────────────────────────────────────────────────────
// ManualOverride
// ─────────────────────────────────────────────────────────────────────────────

/// Explicit user-supplied override: `offset → name`.
///
/// Manual overrides beat all sig-file matches.
#[derive(Debug, Clone, Default)]
pub struct ManualOverrideTable {
    overrides: HashMap<u64, String>,
}

impl ManualOverrideTable {
    /// Create an empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an override.
    pub fn add(&mut self, offset: u64, name: impl Into<String>) {
        self.overrides.insert(offset, name.into());
    }

    /// Remove an override.
    pub fn remove(&mut self, offset: u64) {
        self.overrides.remove(&offset);
    }

    /// Query an override.
    #[must_use]
    pub fn get(&self, offset: u64) -> Option<&str> {
        self.overrides.get(&offset).map(std::string::String::as_str)
    }

    /// `true` if the table has an override for the offset.
    #[must_use]
    pub fn has(&self, offset: u64) -> bool {
        self.overrides.contains_key(&offset)
    }

    /// Number of overrides.
    #[must_use]
    pub fn len(&self) -> usize {
        self.overrides.len()
    }

    /// `true` when empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.overrides.is_empty()
    }

    /// Iterate over all overrides.
    pub fn iter(&self) -> impl Iterator<Item = (u64, &str)> {
        self.overrides.iter().map(|(&k, v)| (k, v.as_str()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SigPriority (ordered source list)
// ─────────────────────────────────────────────────────────────────────────────

/// Ordered list of signature sources.
///
/// Sources with higher `priority` are consulted first.
pub struct SigPriority {
    sources: Vec<SigSource>,
}

impl SigPriority {
    /// Create an empty priority list.
    #[must_use]
    pub const fn new() -> Self {
        Self { sources: Vec::new() }
    }

    /// Add a source.
    pub fn add(&mut self, src: SigSource) {
        self.sources.push(src);
        // Keep sorted descending by priority, then by specificity.
        self.sources.sort_by(|a, b| {
            b.priority.cmp(&a.priority).then(b.specificity.cmp(&a.specificity))
        });
    }

    /// Return the ordered list of source tags (highest priority first).
    #[must_use]
    pub fn ordered_tags(&self) -> Vec<&str> {
        self.sources.iter().map(|s| s.tag.as_str()).collect()
    }

    /// Look up a source by tag.
    #[must_use]
    pub fn get(&self, tag: &str) -> Option<&SigSource> {
        self.sources.iter().find(|s| s.tag == tag)
    }

    /// Total number of sources.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.sources.len()
    }

    /// `true` when empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Compute a combined weight score for a source tag.
    #[must_use]
    pub fn weight(&self, tag: &str) -> u64 {
        self.get(tag).map_or(0, |s| u64::from(s.priority) * u64::from(s.specificity))
    }
}

impl Default for SigPriority {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConflictResolver
// ─────────────────────────────────────────────────────────────────────────────

/// Resolves conflicts between candidate matches using a [`SigPriority`] and [`ConflictPolicy`].
pub struct ConflictResolver {
    pub priority: SigPriority,
    pub policy: ConflictPolicy,
    pub overrides: ManualOverrideTable,
    /// Collected conflict records from the last resolve call.
    pub conflict_log: Vec<ConflictRecord>,
}

impl Default for ConflictResolver {
    fn default() -> Self {
        Self {
            priority: SigPriority::new(),
            policy: ConflictPolicy::default(),
            overrides: ManualOverrideTable::new(),
            conflict_log: Vec::new(),
        }
    }
}

impl ConflictResolver {
    /// Create a resolver with the given policy.
    #[must_use]
    pub fn new(policy: ConflictPolicy) -> Self {
        Self { policy, ..Default::default() }
    }

    /// Resolve a list of candidates for a single offset.
    ///
    /// Returns the winning entry (or `None` if policy = `DropAll` or no candidates).
    /// Side-effects: appends to `self.conflict_log`.
    pub fn resolve(&mut self, offset: u64, mut candidates: Vec<SigEntry>) -> Option<SigEntry> {
        // Manual override always wins.
        if let Some(name) = self.overrides.get(offset) {
            // Return a synthetic SigEntry for the override.
            return Some(SigEntry {
                name: name.to_string(),
                pattern: Vec::new(),
                crc: 0,
                crc_offset: 0,
                crc_len: 0,
                source_tag: "__manual__".into(),
                entry_id: u32::MAX,
            });
        }

        if candidates.is_empty() {
            return None;
        }
        if candidates.len() == 1 {
            return Some(candidates.remove(0));
        }

        // Multiple candidates → conflict.
        match self.policy {
            ConflictPolicy::DropAll => {
                // Log all as conflicts, return nothing.
                for i in 1..candidates.len() {
                    self.conflict_log.push(ConflictRecord {
                        offset,
                        winner: candidates[0].clone(),
                        loser: candidates[i].clone(),
                        policy_applied: ConflictPolicy::DropAll,
                    });
                }
                None
            }
            ConflictPolicy::KeepAll => {
                // Return the first; caller can inspect conflict_log.
                for i in 1..candidates.len() {
                    self.conflict_log.push(ConflictRecord {
                        offset,
                        winner: candidates[0].clone(),
                        loser: candidates[i].clone(),
                        policy_applied: ConflictPolicy::KeepAll,
                    });
                }
                Some(candidates.remove(0))
            }
            ConflictPolicy::HighestPriority => {
                // Rank by the source's PRIORITY, with specificity only as a
                // tie-break. This used `weight()`, which is priority ×
                // specificity — the rule belonging to `ConflictPolicy::Weighted`
                // — so a high-priority source lost to a low-priority one that
                // happened to be more specific: `msvc_exact` (200 × 10 = 2000)
                // was beaten by `generic` (100 × 50 = 5000), the exact opposite
                // of what this policy promises.
                //
                // `SigRegistry::add` already keeps its sources in this order.
                candidates.sort_by(|a, b| {
                    let sa = self.priority.get(&a.source_tag);
                    let sb = self.priority.get(&b.source_tag);
                    let pa = sa.map_or(0, |s| s.priority);
                    let pb = sb.map_or(0, |s| s.priority);
                    pb.cmp(&pa).then_with(|| {
                        let ea = sa.map_or(0, |s| s.specificity);
                        let eb = sb.map_or(0, |s| s.specificity);
                        eb.cmp(&ea)
                    })
                });
                let winner = candidates.remove(0);
                for loser in candidates {
                    self.conflict_log.push(ConflictRecord {
                        offset,
                        winner: winner.clone(),
                        loser,
                        policy_applied: ConflictPolicy::HighestPriority,
                    });
                }
                Some(winner)
            }
            ConflictPolicy::MostSpecific => {
                candidates.sort_by_key(|b| std::cmp::Reverse(b.concrete_bytes()));
                let winner = candidates.remove(0);
                for loser in candidates {
                    self.conflict_log.push(ConflictRecord {
                        offset, winner: winner.clone(), loser,
                        policy_applied: ConflictPolicy::MostSpecific,
                    });
                }
                Some(winner)
            }
            ConflictPolicy::Weighted => {
                candidates.sort_by(|a, b| {
                    let sa = u64_to_usize(self.priority.weight(&a.source_tag))
                        + a.concrete_bytes() * 10;
                    let sb = u64_to_usize(self.priority.weight(&b.source_tag))
                        + b.concrete_bytes() * 10;
                    sb.cmp(&sa)
                });
                let winner = candidates.remove(0);
                for loser in candidates {
                    self.conflict_log.push(ConflictRecord {
                        offset, winner: winner.clone(), loser,
                        policy_applied: ConflictPolicy::Weighted,
                    });
                }
                Some(winner)
            }
        }
    }

    /// Number of conflicts recorded.
    #[must_use]
    pub const fn conflict_count(&self) -> usize {
        self.conflict_log.len()
    }

    /// Clear the conflict log.
    pub fn clear_log(&mut self) {
        self.conflict_log.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PriorityIndex
// ─────────────────────────────────────────────────────────────────────────────

/// Index that maps pattern prefixes → (`source_tag`, entry) for fast lookup.
pub struct PriorityIndex {
    /// Source metadata.
    pub priority: SigPriority,
    /// All entries by source tag.
    entries: HashMap<String, Vec<SigEntry>>,
    total: usize,
}

impl PriorityIndex {
    /// Create an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self {
            priority: SigPriority::new(),
            entries: HashMap::new(),
            total: 0,
        }
    }

    /// Add a source with its entries.
    pub fn add_source(&mut self, src: SigSource, entries: Vec<SigEntry>) {
        self.total += entries.len();
        self.entries.insert(src.tag.clone(), entries);
        self.priority.add(src);
    }

    /// Total number of entries across all sources.
    #[must_use]
    pub const fn total_entries(&self) -> usize {
        self.total
    }

    /// Iterate all entries in priority order (highest-priority source first).
    pub fn iter_ordered(&self) -> impl Iterator<Item = &SigEntry> {
        let tags = self.priority.ordered_tags();
        tags.into_iter().flat_map(|tag| {
            self.entries.get(tag).map_or(&[][..], std::vec::Vec::as_slice).iter()
        })
    }

    /// Collect all entries matching a given function name across all sources.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Vec<&SigEntry> {
        self.entries.values()
            .flat_map(|v| v.iter())
            .filter(|e| e.name == name)
            .collect()
    }

    /// Number of sources registered.
    #[must_use]
    pub const fn source_count(&self) -> usize {
        self.priority.len()
    }
}

impl Default for PriorityIndex {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(name: &str, tag: &str, concrete: usize) -> SigEntry {
        SigEntry {
            name: name.into(),
            pattern: vec![Some(0x55); concrete],
            crc: 0,
            crc_offset: 0,
            crc_len: 0,
            source_tag: tag.into(),
            entry_id: 0,
        }
    }

    #[test]
    fn test_priority_sorting() {
        let mut sp = SigPriority::new();
        sp.add(SigSource::new("low", "low").with_priority(50));
        sp.add(SigSource::new("high", "high").with_priority(200));
        sp.add(SigSource::new("mid", "mid").with_priority(100));
        assert_eq!(sp.ordered_tags(), vec!["high", "mid", "low"]);
    }

    #[test]
    fn test_manual_override_wins() {
        let mut resolver = ConflictResolver::new(ConflictPolicy::DropAll);
        resolver.overrides.add(0x1000, "my_func");
        let candidates = vec![make_entry("other", "tag", 16)];
        let result = resolver.resolve(0x1000, candidates);
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "my_func");
    }

    #[test]
    fn test_most_specific_wins() {
        let mut resolver = ConflictResolver::new(ConflictPolicy::MostSpecific);
        let cands = vec![
            make_entry("short", "a", 8),
            make_entry("long", "b", 32),
        ];
        let result = resolver.resolve(0x2000, cands).unwrap();
        assert_eq!(result.name, "long");
    }

    #[test]
    fn test_drop_all_policy() {
        let mut resolver = ConflictResolver::new(ConflictPolicy::DropAll);
        let cands = vec![make_entry("a", "x", 16), make_entry("b", "y", 16)];
        let result = resolver.resolve(0x3000, cands);
        assert!(result.is_none());
        assert_eq!(resolver.conflict_count(), 1);
    }

    #[test]
    fn test_priority_index_ordered_iteration() {
        let mut idx = PriorityIndex::new();
        idx.add_source(
            SigSource::new("high", "high").with_priority(200),
            vec![make_entry("fn_h", "high", 16)],
        );
        idx.add_source(
            SigSource::new("low", "low").with_priority(50),
            vec![make_entry("fn_l", "low", 16)],
        );
        let names: Vec<&str> = idx.iter_ordered().map(|e| e.name.as_str()).collect();
        assert_eq!(names[0], "fn_h");
        assert_eq!(names[1], "fn_l");
    }

    #[test]
    fn test_single_candidate_no_conflict() {
        let mut resolver = ConflictResolver::default();
        let cands = vec![make_entry("foo", "lib", 16)];
        let result = resolver.resolve(0x5000, cands);
        assert!(result.is_some());
        assert_eq!(resolver.conflict_count(), 0);
    }
}
