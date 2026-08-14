//! Signature deduplication for FLIRT pattern databases.
//!
//! Merges identical or collision-prone patterns, resolves name conflicts, and
//! produces a cleaned [`DedupResult`] ready for serialisation.

use std::collections::HashMap;
use std::fmt;

use rustre_flirt::{FlirtPattern, PatternByte};

// ── CollisionKind ─────────────────────────────────────────────────────────────

/// How a collision between two signatures was resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollisionKind {
    /// Both patterns had identical hex + CRC — the duplicate was removed.
    Removed,
    /// The duplicate was merged by appending its names to the primary.
    Merged,
    /// A conflict could not be automatically resolved; both were retained.
    Retained,
}

impl fmt::Display for CollisionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Removed => write!(f, "removed"),
            Self::Merged => write!(f, "merged"),
            Self::Retained => write!(f, "retained"),
        }
    }
}

// ── CollisionRecord ───────────────────────────────────────────────────────────

/// One detected collision between two patterns.
#[derive(Debug, Clone)]
pub struct CollisionRecord {
    /// The hex of the colliding initial-byte pattern.
    pub pattern_hex: String,
    /// Name of the primary (surviving) pattern.
    pub primary_name: String,
    /// Name of the duplicate / conflicting pattern.
    pub duplicate_name: String,
    /// How the collision was resolved.
    pub resolution: CollisionKind,
}

impl fmt::Display for CollisionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} vs {} ({})",
            self.pattern_hex, self.primary_name, self.duplicate_name, self.resolution
        )
    }
}

// ── DedupResult ───────────────────────────────────────────────────────────────

/// Result of a deduplication pass.
#[derive(Debug, Clone, Default)]
pub struct DedupResult {
    /// Cleaned patterns after deduplication.
    pub patterns: Vec<FlirtPattern>,
    /// How many exact duplicates were removed.
    pub exact_duplicates_removed: usize,
    /// How many name collisions (same bytes, different names) were resolved.
    pub name_collisions_resolved: usize,
    /// How many CRC collisions (same bytes, different CRC) were retained.
    pub crc_collisions_retained: usize,
    /// Detailed collision records.
    pub collisions: Vec<CollisionRecord>,
}

impl DedupResult {
    /// Total number of patterns in the result.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Total number of collisions detected.
    #[must_use]
    pub const fn total_collisions(&self) -> usize {
        self.collisions.len()
    }

    /// Returns `true` if no collisions were detected.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.collisions.is_empty()
    }
}

impl fmt::Display for DedupResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DedupResult {{ patterns={}, exact_removed={}, name_collisions={}, crc_retained={} }}",
            self.patterns.len(),
            self.exact_duplicates_removed,
            self.name_collisions_resolved,
            self.crc_collisions_retained,
        )
    }
}

// ── CollisionResolver ─────────────────────────────────────────────────────────

/// Strategy used to resolve name collisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CollisionResolver {
    /// Keep the first occurrence; discard later duplicates.
    KeepFirst,
    /// Keep the last occurrence; earlier ones are discarded.
    KeepLast,
    /// Merge all names into the primary pattern (one entry per unique name).
    #[default]
    MergeNames,
    /// Keep all duplicates (no deduplication of name collisions).
    KeepAll,
}


impl fmt::Display for CollisionResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeepFirst => write!(f, "keep-first"),
            Self::KeepLast => write!(f, "keep-last"),
            Self::MergeNames => write!(f, "merge-names"),
            Self::KeepAll => write!(f, "keep-all"),
        }
    }
}

// ── PatternKey ────────────────────────────────────────────────────────────────

/// A fully-qualified pattern key used as a `HashMap` key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PatternKey {
    /// Hex-encoded initial bytes (wildcards as `..`).
    hex: String,
    /// CRC-16 over the bytes following the initial block.
    crc16: u16,
    /// CRC region length.
    crc_length: u8,
}

impl PatternKey {
    fn from_pattern(pat: &FlirtPattern) -> Self {
        Self {
            hex: pat.pattern_hex(),
            crc16: pat.crc16,
            crc_length: pat.crc_length,
        }
    }
}

// ── SignatureDeduplicator ─────────────────────────────────────────────────────

/// Removes duplicate and colliding FLIRT signatures from a pattern set.
///
/// # Collision types
///
/// 1. **Exact duplicates** — same initial-byte hex, same CRC-16, same primary
///    name.  These are unconditionally removed.
/// 2. **Name collisions** — same hex + CRC, different primary name.  Resolved
///    by [`CollisionResolver`].
/// 3. **CRC collisions** — same initial-byte hex, different CRC.  These are
///    kept by default (they represent genuinely different functions that happen
///    to share a 32-byte prefix).
#[derive(Debug, Clone)]
pub struct SignatureDeduplicator {
    /// Strategy for name collisions.
    pub resolver: CollisionResolver,
    /// If `true`, patterns with fewer than `min_length` initial bytes are
    /// dropped before deduplication.
    pub drop_short_patterns: bool,
    /// Minimum number of initial bytes required to keep a pattern.
    pub min_length: usize,
    /// If `true`, verbose collision records are populated in [`DedupResult`].
    pub record_collisions: bool,
}

impl Default for SignatureDeduplicator {
    fn default() -> Self {
        Self {
            resolver: CollisionResolver::MergeNames,
            drop_short_patterns: true,
            min_length: 4,
            record_collisions: true,
        }
    }
}

impl SignatureDeduplicator {
    /// Create a new deduplicator with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a deduplicator with a specific resolver strategy.
    #[must_use]
    pub fn with_resolver(resolver: CollisionResolver) -> Self {
        Self {
            resolver,
            ..Self::default()
        }
    }

    /// Run deduplication on `patterns` and return a [`DedupResult`].
    ///
    /// # Panics
    ///
    /// Panics if internal pattern groups are unexpectedly empty (should not occur in practice).
    #[must_use]
    pub fn deduplicate(&self, patterns: Vec<FlirtPattern>) -> DedupResult {
        let mut result = DedupResult::default();

        // Step 1: filter short patterns.
        let patterns: Vec<FlirtPattern> = if self.drop_short_patterns {
            patterns.into_iter().filter(|p| p.initial_bytes.len() >= self.min_length).collect()
        } else {
            patterns
        };

        // Step 2: group by (hex, crc16, crc_length) key.
        let mut key_to_patterns: HashMap<PatternKey, Vec<FlirtPattern>> = HashMap::new();
        for pat in patterns {
            let key = PatternKey::from_pattern(&pat);
            key_to_patterns.entry(key).or_default().push(pat);
        }

        // Step 3: detect CRC collisions (same hex prefix, different CRC).
        let mut hex_to_crc_groups: HashMap<String, Vec<PatternKey>> = HashMap::new();
        for key in key_to_patterns.keys() {
            hex_to_crc_groups.entry(key.hex.clone()).or_default().push(key.clone());
        }
        for crc_keys in hex_to_crc_groups.values() {
            if crc_keys.len() > 1 {
                result.crc_collisions_retained += crc_keys.len() - 1;
            }
        }

        // Step 4: within each key group, resolve duplicates and name collisions.
        for (key, group_patterns) in key_to_patterns {
            if group_patterns.is_empty() {
                continue;
            }
            let mut by_name: HashMap<String, Vec<FlirtPattern>> = HashMap::new();
            for pat in group_patterns {
                let name = pat.primary_name().unwrap_or("<anonymous>").to_owned();
                by_name.entry(name).or_default().push(pat);
            }
            let name_count = by_name.len();
            let mut named_primaries: Vec<(String, FlirtPattern)> = Vec::new();
            for (name, mut same_name_pats) in by_name {
                result.exact_duplicates_removed += same_name_pats.len().saturating_sub(1);
                named_primaries.push((name, same_name_pats.remove(0)));
            }
            if name_count == 1 {
                result.patterns.push(named_primaries.remove(0).1);
            } else {
                result.name_collisions_resolved += name_count - 1;
                self.resolve_collision(&key, named_primaries, &mut result);
            }
        }

        result.patterns.sort_by_key(rustre_flirt::FlirtPattern::pattern_hex);
        result
    }

    fn resolve_collision(
        &self,
        key: &PatternKey,
        mut named_primaries: Vec<(String, FlirtPattern)>,
        result: &mut DedupResult,
    ) {
        match self.resolver {
            CollisionResolver::KeepFirst => {
                named_primaries.sort_by_key(|a| a.0.clone());
                let (primary_name, primary_pat) = named_primaries.remove(0);
                if self.record_collisions {
                    for (dup_name, _) in &named_primaries {
                        result.collisions.push(CollisionRecord {
                            pattern_hex: key.hex.clone(),
                            primary_name: primary_name.clone(),
                            duplicate_name: dup_name.clone(),
                            resolution: CollisionKind::Removed,
                        });
                    }
                }
                result.patterns.push(primary_pat);
            }
            CollisionResolver::KeepLast => {
                named_primaries.sort_by_key(|a| a.0.clone());
                let (primary_name, primary_pat) = named_primaries.pop().unwrap();
                if self.record_collisions {
                    for (dup_name, _) in &named_primaries {
                        result.collisions.push(CollisionRecord {
                            pattern_hex: key.hex.clone(),
                            primary_name: primary_name.clone(),
                            duplicate_name: dup_name.clone(),
                            resolution: CollisionKind::Removed,
                        });
                    }
                }
                result.patterns.push(primary_pat);
            }
            CollisionResolver::MergeNames => {
                named_primaries.sort_by_key(|a| a.0.clone());
                let (primary_name, mut primary_pat) = named_primaries.remove(0);
                for (dup_name, dup_pat) in &named_primaries {
                    for n in &dup_pat.names {
                        if !primary_pat.names.iter().any(|e| e.name == n.name) {
                            primary_pat.names.push(n.clone());
                        }
                    }
                    if self.record_collisions {
                        result.collisions.push(CollisionRecord {
                            pattern_hex: key.hex.clone(),
                            primary_name: primary_name.clone(),
                            duplicate_name: dup_name.clone(),
                            resolution: CollisionKind::Merged,
                        });
                    }
                }
                result.patterns.push(primary_pat);
            }
            CollisionResolver::KeepAll => {
                if self.record_collisions {
                    let primary_name = &named_primaries[0].0;
                    for (dup_name, _) in named_primaries.iter().skip(1) {
                        result.collisions.push(CollisionRecord {
                            pattern_hex: key.hex.clone(),
                            primary_name: primary_name.clone(),
                            duplicate_name: dup_name.clone(),
                            resolution: CollisionKind::Retained,
                        });
                    }
                }
                for (_, pat) in named_primaries {
                    result.patterns.push(pat);
                }
            }
        }
    }

    /// Deduplicate in-place: consume and return only the unique patterns.
    ///
    /// Convenience wrapper around [`deduplicate`](Self::deduplicate) that
    /// drops collision metadata.
    #[must_use]
    pub fn dedup_patterns(&self, patterns: Vec<FlirtPattern>) -> Vec<FlirtPattern> {
        self.deduplicate(patterns).patterns
    }

    /// Count exact duplicates in a pattern set without modifying it.
    #[must_use]
    pub fn count_duplicates(patterns: &[FlirtPattern]) -> usize {
        let mut seen: HashMap<(String, u16, u8, String), usize> = HashMap::new();
        for pat in patterns {
            let name = pat.primary_name().unwrap_or("").to_owned();
            let key = (pat.pattern_hex(), pat.crc16, pat.crc_length, name);
            *seen.entry(key).or_insert(0) += 1;
        }
        seen.values().map(|&c| c.saturating_sub(1)).sum()
    }

    /// Returns `true` if `a` and `b` are byte-for-byte identical patterns
    /// (same hex prefix, CRC, and primary name).
    #[must_use]
    pub fn are_identical(a: &FlirtPattern, b: &FlirtPattern) -> bool {
        a.pattern_hex() == b.pattern_hex()
            && a.crc16 == b.crc16
            && a.crc_length == b.crc_length
            && a.primary_name() == b.primary_name()
    }

    /// Classify two patterns with the same initial-byte hex as either an exact
    /// duplicate, a name collision, or a CRC collision.
    #[must_use]
    pub fn classify_collision(a: &FlirtPattern, b: &FlirtPattern) -> CollisionKind {
        if a.crc16 != b.crc16 || a.crc_length != b.crc_length {
            CollisionKind::Retained // CRC differs → different functions
        } else if a.primary_name() == b.primary_name() {
            CollisionKind::Removed // Same name → exact duplicate
        } else {
            CollisionKind::Merged // Same CRC, different name → name collision
        }
    }
}

// ── PatternComparator ─────────────────────────────────────────────────────────

/// Compares two patterns for similarity to support fuzzy deduplication.
#[derive(Debug, Clone, Default)]
pub struct PatternComparator;

impl PatternComparator {
    /// Create a new comparator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Compute a similarity score in `[0.0, 1.0]` between two patterns.
    ///
    /// The score is based on the fraction of initial bytes that agree, weighted
    /// by the CRC match.
    #[must_use]
    pub fn similarity(a: &FlirtPattern, b: &FlirtPattern) -> f64 {
        let len = a.initial_bytes.len().min(b.initial_bytes.len());
        if len == 0 {
            return 0.0;
        }
        let matches = a
            .initial_bytes
            .iter()
            .zip(b.initial_bytes.iter())
            .take(len)
            .filter(|(x, y)| {
                matches!((x, y), (PatternByte::Exact(bx), PatternByte::Exact(by)) if bx == by)
                    || (matches!(x, PatternByte::Wildcard) && matches!(y, PatternByte::Wildcard))
            })
            .count();
        let byte_sim = f64::from(u32::try_from(matches).unwrap_or(u32::MAX)) / f64::from(u32::try_from(len).unwrap_or(u32::MAX));
        let crc_bonus = if a.crc16 == b.crc16 && a.crc_length == b.crc_length {
            0.1
        } else {
            0.0
        };
        (byte_sim + crc_bonus).min(1.0)
    }

    /// Return `true` if the patterns are considered "near-duplicates"
    /// (similarity ≥ `threshold`).
    #[must_use]
    pub fn is_near_duplicate(a: &FlirtPattern, b: &FlirtPattern, threshold: f64) -> bool {
        Self::similarity(a, b) >= threshold
    }

    /// Partition `patterns` into groups of near-duplicates.
    ///
    /// Returns a `Vec<Vec<usize>>` where each inner `Vec` is a group of indices
    /// into `patterns` that are mutually near-duplicates.
    #[must_use]
    pub fn group_near_duplicates(patterns: &[FlirtPattern], threshold: f64) -> Vec<Vec<usize>> {
        let n = patterns.len();
        let mut group_id = vec![usize::MAX; n];
        let mut num_groups = 0;

        for i in 0..n {
            if group_id[i] != usize::MAX {
                continue;
            }
            group_id[i] = num_groups;
            for j in (i + 1)..n {
                if group_id[j] == usize::MAX
                    && Self::is_near_duplicate(&patterns[i], &patterns[j], threshold)
                {
                    group_id[j] = num_groups;
                }
            }
            num_groups += 1;
        }

        let mut groups: Vec<Vec<usize>> = vec![Vec::new(); num_groups];
        for (idx, &gid) in group_id.iter().enumerate() {
            if gid < num_groups {
                groups[gid].push(idx);
            }
        }
        groups.retain(|g| !g.is_empty());
        groups
    }
}

// ── DeduplicationStats ────────────────────────────────────────────────────────

/// Aggregate deduplication statistics across multiple libraries.
#[derive(Debug, Clone, Default)]
pub struct DeduplicationStats {
    /// Total patterns input.
    pub total_input: usize,
    /// Total patterns in the output.
    pub total_output: usize,
    /// Total exact duplicates removed.
    pub exact_removed: usize,
    /// Total name collisions resolved.
    pub name_collisions: usize,
    /// Total CRC collisions retained.
    pub crc_collisions: usize,
}

impl DeduplicationStats {
    /// Accumulate one [`DedupResult`] into the running totals.
    pub const fn accumulate(&mut self, input_count: usize, result: &DedupResult) {
        self.total_input += input_count;
        self.total_output += result.patterns.len();
        self.exact_removed += result.exact_duplicates_removed;
        self.name_collisions += result.name_collisions_resolved;
        self.crc_collisions += result.crc_collisions_retained;
    }

    /// Reduction ratio: how many patterns were removed as a fraction of input.
    #[must_use]
    pub fn reduction_ratio(&self) -> f64 {
        if self.total_input == 0 {
            0.0
        } else {
            1.0 - (f64::from(u32::try_from(self.total_output).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.total_input).unwrap_or(u32::MAX)))
        }
    }
}

impl fmt::Display for DeduplicationStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "in={} out={} exact_removed={} name_collisions={} crc_retained={} reduction={:.1}%",
            self.total_input,
            self.total_output,
            self.exact_removed,
            self.name_collisions,
            self.crc_collisions,
            self.reduction_ratio() * 100.0,
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_flirt::FlirtName;
    use crate::PatternGenerator;

    fn make_pattern(bytes: &[u8], name: &str) -> FlirtPattern {
        let pg = PatternGenerator::new();
        let fname = FlirtName {
            name: name.to_owned(),
            offset: 0,
            is_public: true,
            is_local: false,
        };
        pg.generate(bytes, &[], vec![fname]).unwrap()
    }

    #[test]
    fn dedup_removes_exact_duplicates() {
        let p1 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "foo");
        let p2 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "foo");
        let dedup = SignatureDeduplicator::new();
        let result = dedup.deduplicate(vec![p1, p2]);
        assert_eq!(result.patterns.len(), 1);
        assert_eq!(result.exact_duplicates_removed, 1);
    }

    #[test]
    fn dedup_keeps_different_patterns() {
        let p1 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "foo");
        let p2 = make_pattern(&[0x56, 0x48, 0x89, 0xE5, 0xC3], "bar");
        let dedup = SignatureDeduplicator::new();
        let result = dedup.deduplicate(vec![p1, p2]);
        assert_eq!(result.patterns.len(), 2);
        assert_eq!(result.exact_duplicates_removed, 0);
    }

    #[test]
    fn dedup_merge_names_combines_names() {
        let p1 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "foo");
        let p2 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "bar");
        let dedup = SignatureDeduplicator::with_resolver(CollisionResolver::MergeNames);
        let result = dedup.deduplicate(vec![p1, p2]);
        assert_eq!(result.patterns.len(), 1);
        assert_eq!(result.name_collisions_resolved, 1);
        // The merged pattern should have at least one name.
        assert!(!result.patterns[0].names.is_empty());
    }

    #[test]
    fn dedup_keep_first_drops_second() {
        let p1 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "aaa");
        let p2 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "zzz");
        let dedup = SignatureDeduplicator::with_resolver(CollisionResolver::KeepFirst);
        let result = dedup.deduplicate(vec![p1, p2]);
        assert_eq!(result.patterns.len(), 1);
        assert_eq!(result.patterns[0].primary_name(), Some("aaa"));
    }

    #[test]
    fn dedup_keep_last_drops_first() {
        let p1 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "aaa");
        let p2 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "zzz");
        let dedup = SignatureDeduplicator::with_resolver(CollisionResolver::KeepLast);
        let result = dedup.deduplicate(vec![p1, p2]);
        assert_eq!(result.patterns.len(), 1);
        assert_eq!(result.patterns[0].primary_name(), Some("zzz"));
    }

    #[test]
    fn dedup_keep_all_retains_both() {
        let p1 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "foo");
        let p2 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "bar");
        let dedup = SignatureDeduplicator::with_resolver(CollisionResolver::KeepAll);
        let result = dedup.deduplicate(vec![p1, p2]);
        assert_eq!(result.patterns.len(), 2);
    }

    #[test]
    fn are_identical_true_for_same_pattern() {
        let p1 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "foo");
        let p2 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "foo");
        assert!(SignatureDeduplicator::are_identical(&p1, &p2));
    }

    #[test]
    fn are_identical_false_for_different_name() {
        let p1 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "foo");
        let p2 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "bar");
        assert!(!SignatureDeduplicator::are_identical(&p1, &p2));
    }

    #[test]
    fn count_duplicates_zero_for_unique() {
        let p1 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "foo");
        let p2 = make_pattern(&[0x56, 0x48, 0x89, 0xE5, 0xC3], "bar");
        assert_eq!(SignatureDeduplicator::count_duplicates(&[p1, p2]), 0);
    }

    #[test]
    fn count_duplicates_counts_extras() {
        let p1 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "foo");
        let p2 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "foo");
        let p3 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "foo");
        assert_eq!(SignatureDeduplicator::count_duplicates(&[p1, p2, p3]), 2);
    }

    #[test]
    fn dedup_result_is_clean_no_collisions() {
        let result = DedupResult::default();
        assert!(result.is_clean());
    }

    #[test]
    fn dedup_result_total_collisions() {
        let mut result = DedupResult::default();
        result.collisions.push(CollisionRecord {
            pattern_hex: "55".into(),
            primary_name: "foo".into(),
            duplicate_name: "bar".into(),
            resolution: CollisionKind::Merged,
        });
        assert_eq!(result.total_collisions(), 1);
    }

    #[test]
    fn pattern_comparator_similarity_identical() {
        let p = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "foo");
        let q = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "foo");
        let sim = PatternComparator::similarity(&p, &q);
        assert!(sim > 0.9);
    }

    #[test]
    fn pattern_comparator_near_duplicate_at_100_pct() {
        let p = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "foo");
        let q = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "bar");
        assert!(PatternComparator::is_near_duplicate(&p, &q, 0.9));
    }

    #[test]
    fn dedup_stats_accumulate() {
        let p1 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "foo");
        let p2 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "foo");
        let dedup = SignatureDeduplicator::new();
        let result = dedup.deduplicate(vec![p1, p2]);
        let mut stats = DeduplicationStats::default();
        stats.accumulate(2, &result);
        assert_eq!(stats.total_input, 2);
        assert_eq!(stats.total_output, 1);
        assert_eq!(stats.exact_removed, 1);
        assert!(stats.reduction_ratio() > 0.0);
    }

    #[test]
    fn collision_resolver_display() {
        assert_eq!(CollisionResolver::KeepFirst.to_string(), "keep-first");
        assert_eq!(CollisionResolver::MergeNames.to_string(), "merge-names");
    }

    #[test]
    fn collision_kind_display() {
        assert_eq!(CollisionKind::Removed.to_string(), "removed");
        assert_eq!(CollisionKind::Merged.to_string(), "merged");
        assert_eq!(CollisionKind::Retained.to_string(), "retained");
    }

    #[test]
    fn dedup_result_display() {
        let r = DedupResult::default();
        let s = r.to_string();
        assert!(s.contains("DedupResult"));
    }

    #[test]
    fn drop_short_patterns_removes_tiny() {
        let short = make_pattern(&[0x55, 0x48], "tiny");
        let normal = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "normal");
        let dedup = SignatureDeduplicator {
            drop_short_patterns: true,
            min_length: 4,
            ..SignatureDeduplicator::default()
        };
        let result = dedup.deduplicate(vec![short, normal]);
        assert_eq!(result.patterns.len(), 1);
        assert_eq!(result.patterns[0].primary_name(), Some("normal"));
    }

    #[test]
    fn group_near_duplicates_groups_identicals() {
        let p1 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "foo");
        let p2 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "bar");
        let p3 = make_pattern(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE], "qux");
        let groups = PatternComparator::group_near_duplicates(&[p1, p2, p3], 0.9);
        // p1 and p2 should be in the same group; p3 alone.
        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn classify_collision_exact_dup() {
        let p1 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "foo");
        let p2 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "foo");
        assert_eq!(
            SignatureDeduplicator::classify_collision(&p1, &p2),
            CollisionKind::Removed
        );
    }

    #[test]
    fn classify_collision_name_collision() {
        let p1 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "foo");
        let p2 = make_pattern(&[0x55, 0x48, 0x89, 0xE5, 0xC3], "bar");
        assert_eq!(
            SignatureDeduplicator::classify_collision(&p1, &p2),
            CollisionKind::Merged
        );
    }

    #[test]
    fn dedup_empty_input_ok() {
        let dedup = SignatureDeduplicator::new();
        let result = dedup.deduplicate(vec![]);
        assert_eq!(result.patterns.len(), 0);
        assert!(result.is_clean());
    }

    #[test]
    fn dedup_stats_reduction_zero_empty() {
        let stats = DeduplicationStats::default();
        assert_eq!(stats.reduction_ratio(), 0.0);
    }
}
