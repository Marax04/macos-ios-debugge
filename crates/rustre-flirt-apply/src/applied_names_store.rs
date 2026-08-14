//! `applied_names_store` — Persist and query names that have been applied to
//! addresses as a result of FLIRT recognition.
//!
//! The store acts as the authoritative record of every rename committed by the
//! FLIRT engine, supporting conflict detection, rollback, and export.

use std::collections::HashSet;

use crate::casts::usize_to_f64;
// AHashMap (randomised) prevents hash-collision DoS from attacker-controlled
// addresses/names from untrusted .sig/.pat files.
use ahash::AHashMap as HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ─── NameOrigin ───────────────────────────────────────────────────────────────

/// Where a name assignment originated.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NameOrigin {
    /// Identified via a FLIRT `.sig` file with the given library name.
    FlirtSig { lib_name: String },
    /// Identified via a `.pat` text file.
    PatFile { lib_name: String },
    /// Propagated from a primary match to an adjacent public name.
    Propagated { from_addr: u64 },
    /// Manually assigned by the user (outside FLIRT).
    Manual,
    /// Custom external source.
    Custom(String),
}

impl fmt::Display for NameOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FlirtSig { lib_name } => write!(f, "sig:{lib_name}"),
            Self::PatFile { lib_name } => write!(f, "pat:{lib_name}"),
            Self::Propagated { from_addr } => write!(f, "propagated:0x{from_addr:x}"),
            Self::Manual => write!(f, "manual"),
            Self::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

impl NameOrigin {
    /// Returns the library name if this origin is `FlirtSig` or `PatFile`.
    #[must_use]
    pub fn lib_name(&self) -> Option<&str> {
        match self {
            Self::FlirtSig { lib_name } | Self::PatFile { lib_name } => Some(lib_name),
            _ => None,
        }
    }

    /// Returns `true` for automated (non-manual) origins.
    #[must_use]
    pub const fn is_automated(&self) -> bool {
        !matches!(self, Self::Manual)
    }
}

// ─── AppliedName ─────────────────────────────────────────────────────────────

/// A single name that was applied to an address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedName {
    /// The virtual address of the named item.
    pub address: u64,
    /// The assigned name.
    pub name: String,
    /// Confidence score at time of assignment (0–100).
    pub confidence: u8,
    /// Library the name came from.
    pub lib_name: String,
    /// Pattern length that produced this match.
    pub pattern_length: usize,
    /// Origin of the name assignment.
    pub origin: NameOrigin,
    /// UNIX timestamp (seconds) when the name was committed.
    pub timestamp: u64,
    /// Whether the user confirmed / accepted this name.
    pub confirmed: bool,
}

impl AppliedName {
    /// Create a new `AppliedName` stamped with the current time.
    #[must_use]
    pub fn new(
        address: u64,
        name: impl Into<String>,
        confidence: u8,
        lib_name: impl Into<String>,
        pattern_length: usize,
        origin: NameOrigin,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Self {
            address,
            name: name.into(),
            confidence,
            lib_name: lib_name.into(),
            pattern_length,
            origin,
            timestamp,
            confirmed: false,
        }
    }

    /// Create with an explicit timestamp (useful for deterministic tests).
    #[must_use]
    pub const fn with_timestamp(mut self, ts: u64) -> Self {
        self.timestamp = ts;
        self
    }

    /// Mark this name as confirmed by the user.
    #[must_use]
    pub const fn confirmed(mut self) -> Self {
        self.confirmed = true;
        self
    }

    /// Returns `true` if the name looks like an auto-generated placeholder
    /// (e.g. `sub_XXXX` or `loc_XXXX`).
    #[must_use]
    pub fn is_placeholder(&self) -> bool {
        let n = self.name.as_str();
        n.starts_with("sub_")
            || n.starts_with("loc_")
            || n.starts_with("nullsub_")
            || n.starts_with("j_")
            || n.is_empty()
    }
}

impl fmt::Display for AppliedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "0x{:x} → {} [{}] conf={}%",
            self.address, self.name, self.lib_name, self.confidence
        )
    }
}

// ─── CommitStats ──────────────────────────────────────────────────────────────

/// Statistics returned by a single [`AppliedNamesStore::commit_names`] call.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CommitStats {
    /// Number of new names inserted.
    pub inserted: usize,
    /// Number of existing names updated (higher confidence override).
    pub updated: usize,
    /// Number of names skipped due to conflicts or lower confidence.
    pub skipped: usize,
    /// Addresses that had a name collision (different names, same address).
    pub conflicts: Vec<u64>,
}

impl CommitStats {
    /// Total addresses processed.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.inserted + self.updated + self.skipped
    }

    /// Returns `true` if any conflicts were detected.
    #[must_use]
    pub const fn has_conflicts(&self) -> bool {
        !self.conflicts.is_empty()
    }
}

impl fmt::Display for CommitStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CommitStats(ins={} upd={} skip={} conflicts={})",
            self.inserted,
            self.updated,
            self.skipped,
            self.conflicts.len()
        )
    }
}

// ─── StoreConfig ──────────────────────────────────────────────────────────────

/// Configuration for the [`AppliedNamesStore`].
#[derive(Debug, Clone)]
pub struct StoreConfig {
    /// Allow overwriting an existing name if the new confidence is higher.
    pub allow_confidence_override: bool,
    /// Minimum confidence required to commit a name (0 = accept all).
    pub min_confidence: u8,
    /// If `true`, names with the same address but different content are
    /// recorded in the conflict list rather than silently dropped.
    pub track_conflicts: bool,
    /// Maximum number of names to retain (0 = unlimited).
    pub max_names: usize,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            allow_confidence_override: true,
            min_confidence: 0,
            track_conflicts: true,
            max_names: 0,
        }
    }
}

// ─── AppliedNamesStore ────────────────────────────────────────────────────────

/// Stores all names that have been applied to binary addresses by FLIRT.
///
/// Provides batch insertion ([`AppliedNamesStore::commit_names`]), lookup,
/// conflict tracking, and export.
pub struct AppliedNamesStore {
    /// `address → AppliedName` for the canonical set.
    names: HashMap<u64, AppliedName>,
    /// Conflict log: addresses where a name clash was detected.
    conflicts: Vec<(u64, String, String)>,
    /// Configuration.
    config: StoreConfig,
    /// Set of addresses that have been confirmed by the user.
    confirmed: HashSet<u64>,
}

impl AppliedNamesStore {
    /// Create a new empty store with default config.
    #[must_use]
    pub fn new() -> Self {
        Self {
            names: HashMap::new(),
            conflicts: Vec::new(),
            config: StoreConfig::default(),
            confirmed: HashSet::new(),
        }
    }

    /// Create a store with custom configuration.
    #[must_use]
    pub fn with_config(config: StoreConfig) -> Self {
        Self {
            names: HashMap::new(),
            conflicts: Vec::new(),
            config,
            confirmed: HashSet::new(),
        }
    }

    // ── Commit ────────────────────────────────────────────────────────────────

    /// Commit a batch of [`AppliedName`]s to the store, applying conflict rules.
    ///
    /// Returns [`CommitStats`] describing what happened.
    #[must_use]
    pub fn commit_names(&mut self, names: Vec<AppliedName>) -> CommitStats {
        let mut stats = CommitStats::default();

        for an in names {
            if an.confidence < self.config.min_confidence {
                stats.skipped += 1;
                continue;
            }
            if self.config.max_names > 0 && self.names.len() >= self.config.max_names {
                stats.skipped += 1;
                continue;
            }

            match self.names.get(&an.address) {
                None => {
                    self.names.insert(an.address, an);
                    stats.inserted += 1;
                }
                Some(existing) => {
                    if existing.name != an.name {
                        // Different name — conflict.
                        if self.config.track_conflicts {
                            self.conflicts.push((
                                an.address,
                                existing.name.clone(),
                                an.name.clone(),
                            ));
                            stats.conflicts.push(an.address);
                        }
                    }
                    // Common to both same-name and different-name: update if higher confidence.
                    if self.config.allow_confidence_override
                        && an.confidence > existing.confidence
                    {
                        self.names.insert(an.address, an);
                        stats.updated += 1;
                    } else {
                        stats.skipped += 1;
                    }
                }
            }
        }

        stats
    }

    // ── Lookup ────────────────────────────────────────────────────────────────

    /// Look up the name for an address.
    #[must_use]
    pub fn get(&self, address: u64) -> Option<&AppliedName> {
        self.names.get(&address)
    }

    /// Returns `true` if the address has a name.
    #[must_use]
    pub fn contains(&self, address: u64) -> bool {
        self.names.contains_key(&address)
    }

    /// Look up an address by name (linear scan; prefer `get` when address is known).
    #[must_use]
    pub fn address_of(&self, name: &str) -> Option<u64> {
        self.names
            .iter()
            .find(|(_, v)| v.name == name)
            .map(|(k, _)| *k)
    }

    /// All applied names sorted by address.
    #[must_use]
    pub fn all_sorted(&self) -> Vec<&AppliedName> {
        let mut v: Vec<&AppliedName> = self.names.values().collect();
        v.sort_unstable_by_key(|n| n.address);
        v
    }

    // ── Confirmation ─────────────────────────────────────────────────────────

    /// Confirm the name at `address` (marks it as user-accepted).
    pub fn confirm(&mut self, address: u64) {
        if let Some(n) = self.names.get_mut(&address) {
            n.confirmed = true;
            self.confirmed.insert(address);
        }
    }

    /// Returns `true` if the name at `address` has been confirmed.
    #[must_use]
    pub fn is_confirmed(&self, address: u64) -> bool {
        self.confirmed.contains(&address)
    }

    // ── Removal ──────────────────────────────────────────────────────────────

    /// Remove the name at `address`. Returns the removed entry if present.
    pub fn remove(&mut self, address: u64) -> Option<AppliedName> {
        self.confirmed.remove(&address);
        self.names.remove(&address)
    }

    /// Remove all names from the given library.
    pub fn remove_library(&mut self, lib_name: &str) -> usize {
        let to_remove: Vec<u64> = self
            .names
            .iter()
            .filter(|(_, v)| v.lib_name == lib_name)
            .map(|(k, _)| *k)
            .collect();
        let count = to_remove.len();
        for addr in to_remove {
            self.remove(addr);
        }
        count
    }

    /// Clear all names and reset state.
    pub fn clear(&mut self) {
        self.names.clear();
        self.conflicts.clear();
        self.confirmed.clear();
    }

    // ── Statistics / Queries ─────────────────────────────────────────────────

    /// Total number of named addresses.
    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Returns `true` if no names are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Number of conflicts recorded.
    #[must_use]
    pub const fn conflict_count(&self) -> usize {
        self.conflicts.len()
    }

    /// All recorded conflict entries `(address, old_name, new_name)`.
    #[must_use]
    pub fn conflicts(&self) -> &[(u64, String, String)] {
        &self.conflicts
    }

    /// All names sourced from a specific library.
    #[must_use]
    pub fn names_from_lib(&self, lib_name: &str) -> Vec<&AppliedName> {
        self.names
            .values()
            .filter(|n| n.lib_name == lib_name)
            .collect()
    }

    /// Names above a confidence threshold.
    #[must_use]
    pub fn names_above_confidence(&self, threshold: u8) -> Vec<&AppliedName> {
        self.names
            .values()
            .filter(|n| n.confidence >= threshold)
            .collect()
    }

    /// All unique library names represented in the store.
    #[must_use]
    pub fn library_names(&self) -> Vec<String> {
        let mut libs: Vec<String> = self
            .names
            .values()
            .map(|n| n.lib_name.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        libs.sort();
        libs
    }

    /// Average confidence across all stored names.
    #[must_use]
    pub fn average_confidence(&self) -> f64 {
        if self.names.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.names.values().map(|n| f64::from(n.confidence)).sum();
        sum / usize_to_f64(self.names.len())
    }

    /// Export all names as a `Vec` of `(address, name)` tuples.
    #[must_use]
    pub fn export_pairs(&self) -> Vec<(u64, String)> {
        let mut pairs: Vec<(u64, String)> = self
            .names
            .iter()
            .map(|(a, n)| (*a, n.name.clone()))
            .collect();
        pairs.sort_unstable_by_key(|(a, _)| *a);
        pairs
    }
}

impl Default for AppliedNamesStore {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for AppliedNamesStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AppliedNamesStore(names={} conflicts={})",
            self.names.len(),
            self.conflicts.len()
        )
    }
}

impl fmt::Display for AppliedNamesStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AppliedNamesStore({} names, {} conflicts)",
            self.names.len(),
            self.conflicts.len()
        )
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_name(addr: u64, name: &str, lib: &str, confidence: u8) -> AppliedName {
        AppliedName::new(
            addr,
            name,
            confidence,
            lib,
            8,
            NameOrigin::FlirtSig {
                lib_name: lib.to_owned(),
            },
        )
        .with_timestamp(1000)
    }

    // ── AppliedName ──────────────────────────────────────────────────────────

    #[test]
    fn test_applied_name_display() {
        let n = make_name(0x1000, "strlen", "msvcrt", 90);
        let s = n.to_string();
        assert!(s.contains("strlen"));
        assert!(s.contains("1000"));
        assert!(s.contains("90%"));
    }

    #[test]
    fn test_applied_name_is_placeholder() {
        let n = make_name(0x2000, "sub_2000", "unknown", 50);
        assert!(n.is_placeholder());
        let n2 = make_name(0x3000, "strlen", "msvcrt", 90);
        assert!(!n2.is_placeholder());
    }

    #[test]
    fn test_applied_name_confirmed() {
        let n = make_name(0x1000, "fn", "lib", 80).confirmed();
        assert!(n.confirmed);
    }

    #[test]
    fn test_name_origin_display() {
        assert_eq!(
            NameOrigin::FlirtSig { lib_name: "vc".into() }.to_string(),
            "sig:vc"
        );
        assert_eq!(NameOrigin::Manual.to_string(), "manual");
        assert_eq!(
            NameOrigin::Propagated { from_addr: 0x1000 }.to_string(),
            "propagated:0x1000"
        );
    }

    #[test]
    fn test_name_origin_lib_name() {
        let o = NameOrigin::PatFile { lib_name: "libc".into() };
        assert_eq!(o.lib_name(), Some("libc"));
        assert_eq!(NameOrigin::Manual.lib_name(), None);
    }

    #[test]
    fn test_name_origin_is_automated() {
        assert!(NameOrigin::FlirtSig { lib_name: "x".into() }.is_automated());
        assert!(!NameOrigin::Manual.is_automated());
    }

    // ── CommitStats ──────────────────────────────────────────────────────────

    #[test]
    fn test_commit_stats_total() {
        let s = CommitStats {
            inserted: 5,
            updated: 2,
            skipped: 3,
            conflicts: vec![],
        };
        assert_eq!(s.total(), 10);
    }

    #[test]
    fn test_commit_stats_display() {
        let s = CommitStats {
            inserted: 1,
            updated: 0,
            skipped: 0,
            conflicts: vec![],
        };
        assert!(!s.to_string().is_empty());
    }

    // ── AppliedNamesStore ────────────────────────────────────────────────────

    #[test]
    fn test_store_insert() {
        let mut store = AppliedNamesStore::new();
        let stats = store.commit_names(vec![make_name(0x1000, "strlen", "msvcrt", 90)]);
        assert_eq!(stats.inserted, 1);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_store_get() {
        let mut store = AppliedNamesStore::new();
        let _ = store.commit_names(vec![make_name(0x1000, "strlen", "msvcrt", 90)]);
        let n = store.get(0x1000).unwrap();
        assert_eq!(n.name, "strlen");
    }

    #[test]
    fn test_store_contains() {
        let mut store = AppliedNamesStore::new();
        let _ = store.commit_names(vec![make_name(0x1000, "f", "lib", 80)]);
        assert!(store.contains(0x1000));
        assert!(!store.contains(0x2000));
    }

    #[test]
    fn test_store_address_of() {
        let mut store = AppliedNamesStore::new();
        let _ = store.commit_names(vec![make_name(0x1000, "strlen", "msvcrt", 90)]);
        assert_eq!(store.address_of("strlen"), Some(0x1000));
        assert_eq!(store.address_of("memcpy"), None);
    }

    #[test]
    fn test_store_duplicate_same_name_higher_conf_updates() {
        let mut store = AppliedNamesStore::new();
        let _ = store.commit_names(vec![make_name(0x1000, "strlen", "msvcrt", 60)]);
        let stats = store.commit_names(vec![make_name(0x1000, "strlen", "msvcrt", 90)]);
        assert_eq!(stats.updated, 1);
        assert_eq!(store.get(0x1000).unwrap().confidence, 90);
    }

    #[test]
    fn test_store_duplicate_same_name_lower_conf_skipped() {
        let mut store = AppliedNamesStore::new();
        let _ = store.commit_names(vec![make_name(0x1000, "strlen", "msvcrt", 90)]);
        let stats = store.commit_names(vec![make_name(0x1000, "strlen", "msvcrt", 50)]);
        assert_eq!(stats.skipped, 1);
        assert_eq!(store.get(0x1000).unwrap().confidence, 90);
    }

    #[test]
    fn test_store_conflict_tracked() {
        let mut store = AppliedNamesStore::new();
        let _ = store.commit_names(vec![make_name(0x1000, "strlen", "msvcrt", 70)]);
        let stats =
            store.commit_names(vec![make_name(0x1000, "memcpy", "msvcrt", 80)]);
        assert_eq!(stats.conflicts.len(), 1);
        assert!(store.conflict_count() > 0);
    }

    #[test]
    fn test_store_remove() {
        let mut store = AppliedNamesStore::new();
        let _ = store.commit_names(vec![make_name(0x1000, "f", "lib", 80)]);
        let removed = store.remove(0x1000);
        assert!(removed.is_some());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_store_remove_library() {
        let mut store = AppliedNamesStore::new();
        let _ = store.commit_names(vec![
            make_name(0x1000, "strlen", "msvcrt", 90),
            make_name(0x2000, "memcpy", "msvcrt", 85),
            make_name(0x3000, "malloc", "libc", 80),
        ]);
        let removed = store.remove_library("msvcrt");
        assert_eq!(removed, 2);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_store_clear() {
        let mut store = AppliedNamesStore::new();
        let _ = store.commit_names(vec![make_name(0x1000, "f", "lib", 80)]);
        store.clear();
        assert!(store.is_empty());
        assert_eq!(store.conflict_count(), 0);
    }

    #[test]
    fn test_store_min_confidence_filter() {
        let config = StoreConfig {
            min_confidence: 80,
            ..Default::default()
        };
        let mut store = AppliedNamesStore::with_config(config);
        let stats = store.commit_names(vec![
            make_name(0x1000, "f", "lib", 79),
            make_name(0x2000, "g", "lib", 80),
        ]);
        assert_eq!(stats.inserted, 1);
        assert_eq!(stats.skipped, 1);
    }

    #[test]
    fn test_store_library_names() {
        let mut store = AppliedNamesStore::new();
        let _ = store.commit_names(vec![
            make_name(0x1000, "strlen", "msvcrt", 90),
            make_name(0x2000, "malloc", "libc", 85),
        ]);
        let libs = store.library_names();
        assert!(libs.contains(&"msvcrt".to_string()));
        assert!(libs.contains(&"libc".to_string()));
    }

    #[test]
    fn test_store_average_confidence() {
        let mut store = AppliedNamesStore::new();
        let _ = store.commit_names(vec![
            make_name(0x1000, "a", "lib", 80),
            make_name(0x2000, "b", "lib", 60),
        ]);
        let avg = store.average_confidence();
        assert!((avg - 70.0).abs() < 1e-9);
    }

    #[test]
    fn test_store_names_above_confidence() {
        let mut store = AppliedNamesStore::new();
        let _ = store.commit_names(vec![
            make_name(0x1000, "a", "lib", 90),
            make_name(0x2000, "b", "lib", 50),
        ]);
        let high = store.names_above_confidence(80);
        assert_eq!(high.len(), 1);
    }

    #[test]
    fn test_store_export_pairs() {
        let mut store = AppliedNamesStore::new();
        let _ = store.commit_names(vec![
            make_name(0x2000, "b", "lib", 80),
            make_name(0x1000, "a", "lib", 90),
        ]);
        let pairs = store.export_pairs();
        assert_eq!(pairs[0].0, 0x1000);
        assert_eq!(pairs[0].1, "a");
    }

    #[test]
    fn test_store_confirm() {
        let mut store = AppliedNamesStore::new();
        let _ = store.commit_names(vec![make_name(0x1000, "f", "lib", 80)]);
        assert!(!store.is_confirmed(0x1000));
        store.confirm(0x1000);
        assert!(store.is_confirmed(0x1000));
    }

    #[test]
    fn test_store_debug() {
        let store = AppliedNamesStore::new();
        assert!(!format!("{store:?}").is_empty());
    }

    #[test]
    fn test_store_display() {
        let store = AppliedNamesStore::new();
        let s = store.to_string();
        assert!(s.contains("AppliedNamesStore"));
    }

    #[test]
    fn test_store_all_sorted() {
        let mut store = AppliedNamesStore::new();
        let _ = store.commit_names(vec![
            make_name(0x3000, "c", "lib", 80),
            make_name(0x1000, "a", "lib", 90),
            make_name(0x2000, "b", "lib", 85),
        ]);
        let sorted = store.all_sorted();
        assert_eq!(sorted[0].address, 0x1000);
        assert_eq!(sorted[2].address, 0x3000);
    }
}
