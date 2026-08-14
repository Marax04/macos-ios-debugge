//! `match_conflict_resolver` — Resolve conflicts when multiple FLIRT patterns
//! claim the same address.
//!
//! When the scanner finds that two or more patterns match at the same offset,
//! this module selects the "best" match using configurable [`ResolutionStrategy`]
//! policies, producing a deduplicated output list.

use std::fmt;
// AHashMap (randomised) prevents hash-collision DoS from attacker-controlled
// function names/addresses sourced from untrusted .sig/.pat files.
use ahash::AHashMap as HashMap;

use serde::{Deserialize, Serialize};

use crate::FlirtMatch;

// ─── ConflictSet ─────────────────────────────────────────────────────────────

/// A group of [`FlirtMatch`] records that all claim the same address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictSet {
    /// The address all matches share.
    pub address: u64,
    /// Competing matches, sorted by descending confidence on construction.
    pub candidates: Vec<FlirtMatch>,
}

impl ConflictSet {
    /// Create a conflict set from a non-empty list of matches at the same address.
    ///
    /// The candidates are sorted by descending confidence so that
    /// `candidates[0]` is always the highest-confidence match.
    #[must_use]
    pub fn new(address: u64, mut candidates: Vec<FlirtMatch>) -> Self {
        candidates.sort_unstable_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| b.pattern_length.cmp(&a.pattern_length))
                .then_with(|| a.function_name.cmp(&b.function_name))
        });
        Self { address, candidates }
    }

    /// Number of competing candidates.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.candidates.len()
    }

    /// Returns `true` when there is only a single candidate (no real conflict).
    #[must_use]
    pub const fn is_trivial(&self) -> bool {
        self.candidates.len() == 1
    }

    /// The highest-confidence candidate.
    #[must_use]
    pub fn best(&self) -> Option<&FlirtMatch> {
        self.candidates.first()
    }

    /// Returns `true` if all candidates have the same function name, indicating
    /// the conflict is between the same function from different libraries.
    #[must_use]
    pub fn same_name(&self) -> bool {
        let first = match self.candidates.first() {
            Some(m) => &m.function_name,
            None => return true,
        };
        self.candidates
            .iter()
            .all(|m| &m.function_name == first)
    }

    /// Confidence spread between the best and worst candidates.
    #[must_use]
    pub fn confidence_spread(&self) -> u8 {
        let best = self.candidates.first().map_or(0, |m| m.confidence);
        let worst = self.candidates.last().map_or(0, |m| m.confidence);
        best.saturating_sub(worst)
    }

    /// Returns all unique library names in this conflict set.
    #[must_use]
    pub fn libraries(&self) -> Vec<&str> {
        let mut libs: Vec<&str> = self
            .candidates
            .iter()
            .map(|m| m.lib_name.as_str())
            .collect();
        libs.dedup();
        libs
    }
}

impl fmt::Display for ConflictSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ConflictSet(addr=0x{:x} candidates={})",
            self.address,
            self.candidates.len()
        )
    }
}

// ─── ResolutionStrategy ──────────────────────────────────────────────────────

/// Strategy used by [`MatchConflictResolver`] when multiple patterns match at
/// the same address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ResolutionStrategy {
    /// Keep the candidate with the highest confidence score.
    /// Ties are broken by longer pattern, then alphabetically by name.
    #[default]
    HighestConfidence,

    /// Keep the candidate with the longest pattern (more specific match).
    LongestPattern,

    /// Keep the candidate from the preferred library when available, falling back
    /// to `HighestConfidence`.
    PreferLibrary(String),

    /// Keep all candidates (no deduplication). Callers receive the full set.
    KeepAll,

    /// Discard all candidates if there is genuine conflict (> 1 unique name).
    /// Unambiguous matches (all names agree) are passed through.
    DiscardAmbiguous,

    /// Keep the candidate whose name appears most frequently across *all* matches
    /// (majority vote). Falls back to `HighestConfidence`.
    MajorityVote,
}

impl fmt::Display for ResolutionStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HighestConfidence => write!(f, "HighestConfidence"),
            Self::LongestPattern => write!(f, "LongestPattern"),
            Self::PreferLibrary(lib) => write!(f, "PreferLibrary({lib})"),
            Self::KeepAll => write!(f, "KeepAll"),
            Self::DiscardAmbiguous => write!(f, "DiscardAmbiguous"),
            Self::MajorityVote => write!(f, "MajorityVote"),
        }
    }
}

// ─── ResolutionResult ─────────────────────────────────────────────────────────

/// The outcome of resolving one [`ConflictSet`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResolutionResult {
    /// A single winner was selected.
    Winner(FlirtMatch),
    /// Multiple matches are retained (only with [`ResolutionStrategy::KeepAll`]).
    Multiple(Vec<FlirtMatch>),
    /// The conflict was discarded (no match emitted for this address).
    Discarded,
}

impl ResolutionResult {
    /// Return the winner if exactly one match was kept.
    #[must_use]
    pub const fn winner(&self) -> Option<&FlirtMatch> {
        match self {
            Self::Winner(m) => Some(m),
            _ => None,
        }
    }

    /// Flatten to a `Vec` of matches (empty when [`ResolutionResult::Discarded`]).
    #[must_use]
    pub fn into_matches(self) -> Vec<FlirtMatch> {
        match self {
            Self::Winner(m) => vec![m],
            Self::Multiple(v) => v,
            Self::Discarded => vec![],
        }
    }
}

// ─── MatchConflictResolver ────────────────────────────────────────────────────

/// Resolves conflicts in FLIRT match output.
///
/// # Usage
///
/// ```rust,no_run
/// use rustre_flirt_apply::match_conflict_resolver::{MatchConflictResolver, ResolutionStrategy};
/// let resolver = MatchConflictResolver::new(ResolutionStrategy::HighestConfidence);
/// // let resolved = resolver.resolve(matches);
/// ```
pub struct MatchConflictResolver {
    strategy: ResolutionStrategy,
    /// Minimum confidence delta required to declare a clear winner over
    /// the second-best candidate.  Values below this threshold with
    /// `HighestConfidence` trigger `DiscardAmbiguous` fallback.
    pub min_confidence_delta: u8,
}

impl MatchConflictResolver {
    /// Create a resolver with the given strategy and default delta (0 = off).
    #[must_use]
    pub const fn new(strategy: ResolutionStrategy) -> Self {
        Self {
            strategy,
            min_confidence_delta: 0,
        }
    }

    /// Set the minimum confidence delta for `HighestConfidence` disambiguation.
    #[must_use]
    pub const fn with_min_delta(mut self, delta: u8) -> Self {
        self.min_confidence_delta = delta;
        self
    }

    /// Resolve a single [`ConflictSet`].
    #[must_use]
    pub fn resolve_one(&self, conflict: &ConflictSet) -> ResolutionResult {
        if conflict.candidates.is_empty() {
            return ResolutionResult::Discarded;
        }
        if conflict.is_trivial() {
            return ResolutionResult::Winner(conflict.candidates[0].clone());
        }
        match &self.strategy {
            ResolutionStrategy::HighestConfidence => {
                self.resolve_highest_confidence(conflict)
            }
            ResolutionStrategy::LongestPattern => Self::resolve_longest_pattern(conflict),
            ResolutionStrategy::PreferLibrary(lib) => {
                self.resolve_prefer_library(conflict, lib)
            }
            ResolutionStrategy::KeepAll => {
                ResolutionResult::Multiple(conflict.candidates.clone())
            }
            ResolutionStrategy::DiscardAmbiguous => {
                if conflict.same_name() {
                    ResolutionResult::Winner(conflict.candidates[0].clone())
                } else {
                    ResolutionResult::Discarded
                }
            }
            ResolutionStrategy::MajorityVote => {
                // resolve_one does not have access to cross-address frequency
                // data.  Callers should prefer `resolve()` for MajorityVote,
                // which pre-computes a global name-frequency map.  When called
                // directly here we fall back to HighestConfidence so that the
                // result is at least deterministic.
                self.resolve_highest_confidence(conflict)
            }
        }
    }

    fn resolve_highest_confidence(&self, conflict: &ConflictSet) -> ResolutionResult {
        let best = &conflict.candidates[0];
        if self.min_confidence_delta > 0 && conflict.candidates.len() > 1 {
            let second = &conflict.candidates[1];
            if best
                .confidence
                .saturating_sub(second.confidence)
                < self.min_confidence_delta
            {
                return ResolutionResult::Discarded;
            }
        }
        ResolutionResult::Winner(best.clone())
    }

    fn resolve_longest_pattern(conflict: &ConflictSet) -> ResolutionResult {
        let winner = conflict
            .candidates
            .iter()
            .max_by(|a, b| {
                a.pattern_length
                    .cmp(&b.pattern_length)
                    .then_with(|| a.confidence.cmp(&b.confidence))
            })
            .cloned();
        winner.map_or(ResolutionResult::Discarded, ResolutionResult::Winner)
    }

    fn resolve_prefer_library(&self, conflict: &ConflictSet, lib: &str) -> ResolutionResult {
        if let Some(preferred) = conflict
            .candidates
            .iter()
            .find(|m| m.lib_name == lib)
            .cloned()
        {
            return ResolutionResult::Winner(preferred);
        }
        // Fallback: highest confidence.
        self.resolve_highest_confidence(conflict)
    }

    /// Resolve a flat list of [`FlirtMatch`] records, grouping conflicts by
    /// address and applying the configured strategy to each group.
    ///
    /// Returns a deduplicated, sorted list of matches.
    #[must_use]
    pub fn resolve(&self, matches: Vec<FlirtMatch>) -> Vec<FlirtMatch> {
        // For MajorityVote: compute the global name-frequency map first so
        // that each conflict set can be decided by cross-address vote counts.
        let name_freq: HashMap<String, usize> = if self.strategy == ResolutionStrategy::MajorityVote {
            let mut freq: HashMap<String, usize> = HashMap::new();
            for m in &matches {
                *freq.entry(m.function_name.clone()).or_insert(0) += 1;
            }
            freq
        } else {
            HashMap::new()
        };

        // Group by address.
        let mut by_addr: HashMap<u64, Vec<FlirtMatch>> = HashMap::new();
        for m in matches {
            by_addr.entry(m.address).or_default().push(m);
        }

        // Build conflict sets and resolve.
        let mut out: Vec<FlirtMatch> = Vec::new();
        for (addr, candidates) in by_addr {
            let set = ConflictSet::new(addr, candidates);
            let result = if self.strategy == ResolutionStrategy::MajorityVote {
                Self::resolve_majority_vote_with_freq(&set, &name_freq)
            } else {
                self.resolve_one(&set)
            };
            out.extend(result.into_matches());
        }

        // Sort by address for deterministic output.
        out.sort_unstable_by_key(|m| m.address);
        out
    }

    /// Resolve a conflict using a pre-computed global name-frequency map.
    ///
    /// Picks the candidate whose `function_name` appears most often across all
    /// matches.  Ties are broken by highest confidence, then longest pattern,
    /// then alphabetically.
    fn resolve_majority_vote_with_freq(
        conflict: &ConflictSet,
        name_freq: &HashMap<String, usize>,
    ) -> ResolutionResult {
        if conflict.candidates.is_empty() {
            return ResolutionResult::Discarded;
        }
        if conflict.is_trivial() {
            return ResolutionResult::Winner(conflict.candidates[0].clone());
        }
        // Pick the candidate with the highest vote count.
        let winner = conflict
            .candidates
            .iter()
            .max_by(|a, b| {
                let fa = name_freq.get(&a.function_name).copied().unwrap_or(0);
                let fb = name_freq.get(&b.function_name).copied().unwrap_or(0);
                fa.cmp(&fb)
                    .then_with(|| a.confidence.cmp(&b.confidence))
                    .then_with(|| a.pattern_length.cmp(&b.pattern_length))
                    .then_with(|| b.function_name.cmp(&a.function_name))
            })
            .cloned();
        winner.map_or(ResolutionResult::Discarded, ResolutionResult::Winner)
    }

    /// Collect conflict sets from a match list without resolving them.
    ///
    /// Returns only sets with two or more candidates.
    #[must_use]
    pub fn collect_conflicts(matches: &[FlirtMatch]) -> Vec<ConflictSet> {
        let mut by_addr: HashMap<u64, Vec<FlirtMatch>> = HashMap::new();
        for m in matches {
            by_addr.entry(m.address).or_default().push(m.clone());
        }
        let mut conflicts: Vec<ConflictSet> = by_addr
            .into_iter()
            .filter(|(_, v)| v.len() > 1)
            .map(|(addr, v)| ConflictSet::new(addr, v))
            .collect();
        conflicts.sort_unstable_by_key(|c| c.address);
        conflicts
    }

    /// Return the strategy name.
    #[must_use]
    pub fn strategy_name(&self) -> String {
        self.strategy.to_string()
    }
}

impl Default for MatchConflictResolver {
    fn default() -> Self {
        Self::new(ResolutionStrategy::HighestConfidence)
    }
}

impl fmt::Debug for MatchConflictResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MatchConflictResolver(strategy={} delta={})",
            self.strategy, self.min_confidence_delta
        )
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_match(addr: u64, name: &str, lib: &str, confidence: u8, pat_len: usize) -> FlirtMatch {
        FlirtMatch {
            address: addr,
            function_name: name.to_string(),
            lib_name: lib.to_string(),
            confidence,
            pattern_length: pat_len,
        }
    }

    // ── ConflictSet ──────────────────────────────────────────────────────────

    #[test]
    fn test_conflict_set_sorted_by_confidence() {
        let m1 = make_match(0x1000, "a", "lib", 50, 6);
        let m2 = make_match(0x1000, "b", "lib", 90, 4);
        let set = ConflictSet::new(0x1000, vec![m1, m2]);
        assert_eq!(set.candidates[0].confidence, 90);
    }

    #[test]
    fn test_conflict_set_trivial() {
        let m = make_match(0x1000, "a", "lib", 80, 6);
        let set = ConflictSet::new(0x1000, vec![m]);
        assert!(set.is_trivial());
    }

    #[test]
    fn test_conflict_set_not_trivial() {
        let set = ConflictSet::new(
            0x1000,
            vec![
                make_match(0x1000, "a", "lib", 80, 6),
                make_match(0x1000, "b", "lib", 70, 4),
            ],
        );
        assert!(!set.is_trivial());
    }

    #[test]
    fn test_conflict_set_same_name_true() {
        let set = ConflictSet::new(
            0x2000,
            vec![
                make_match(0x2000, "memcpy", "msvcrt", 80, 12),
                make_match(0x2000, "memcpy", "libc", 75, 12),
            ],
        );
        assert!(set.same_name());
    }

    #[test]
    fn test_conflict_set_same_name_false() {
        let set = ConflictSet::new(
            0x2000,
            vec![
                make_match(0x2000, "memcpy", "msvcrt", 80, 12),
                make_match(0x2000, "memmove", "msvcrt", 75, 14),
            ],
        );
        assert!(!set.same_name());
    }

    #[test]
    fn test_conflict_set_confidence_spread() {
        let set = ConflictSet::new(
            0x3000,
            vec![
                make_match(0x3000, "a", "lib", 90, 8),
                make_match(0x3000, "b", "lib", 60, 6),
            ],
        );
        assert_eq!(set.confidence_spread(), 30);
    }

    #[test]
    fn test_conflict_set_best() {
        let set = ConflictSet::new(
            0x1000,
            vec![
                make_match(0x1000, "a", "lib", 50, 6),
                make_match(0x1000, "b", "lib", 95, 8),
            ],
        );
        assert_eq!(set.best().unwrap().confidence, 95);
    }

    #[test]
    fn test_conflict_set_size() {
        let set = ConflictSet::new(
            0x1000,
            vec![
                make_match(0x1000, "a", "lib", 70, 6),
                make_match(0x1000, "b", "lib", 80, 8),
                make_match(0x1000, "c", "lib", 90, 10),
            ],
        );
        assert_eq!(set.size(), 3);
    }

    #[test]
    fn test_conflict_set_display() {
        let set = ConflictSet::new(0x1000, vec![make_match(0x1000, "a", "lib", 80, 6)]);
        let s = set.to_string();
        assert!(s.contains("1000"));
    }

    // ── ResolutionStrategy ───────────────────────────────────────────────────

    #[test]
    fn test_strategy_display() {
        assert_eq!(ResolutionStrategy::HighestConfidence.to_string(), "HighestConfidence");
        assert_eq!(ResolutionStrategy::LongestPattern.to_string(), "LongestPattern");
        assert_eq!(ResolutionStrategy::KeepAll.to_string(), "KeepAll");
    }

    // ── MatchConflictResolver ────────────────────────────────────────────────

    #[test]
    fn test_resolver_highest_confidence_picks_best() {
        let resolver = MatchConflictResolver::new(ResolutionStrategy::HighestConfidence);
        let set = ConflictSet::new(
            0x1000,
            vec![
                make_match(0x1000, "a", "lib", 70, 6),
                make_match(0x1000, "b", "lib", 95, 8),
            ],
        );
        let result = resolver.resolve_one(&set);
        let w = result.winner().unwrap();
        assert_eq!(w.function_name, "b");
        assert_eq!(w.confidence, 95);
    }

    #[test]
    fn test_resolver_longest_pattern() {
        let resolver = MatchConflictResolver::new(ResolutionStrategy::LongestPattern);
        let set = ConflictSet::new(
            0x1000,
            vec![
                make_match(0x1000, "short", "lib", 90, 4),
                make_match(0x1000, "long_fn", "lib", 70, 16),
            ],
        );
        let result = resolver.resolve_one(&set);
        assert_eq!(result.winner().unwrap().function_name, "long_fn");
    }

    #[test]
    fn test_resolver_keep_all() {
        let resolver = MatchConflictResolver::new(ResolutionStrategy::KeepAll);
        let set = ConflictSet::new(
            0x1000,
            vec![
                make_match(0x1000, "a", "lib", 80, 6),
                make_match(0x1000, "b", "lib", 70, 8),
            ],
        );
        let result = resolver.resolve_one(&set);
        assert!(matches!(result, ResolutionResult::Multiple(_)));
        assert_eq!(result.into_matches().len(), 2);
    }

    #[test]
    fn test_resolver_discard_ambiguous() {
        let resolver = MatchConflictResolver::new(ResolutionStrategy::DiscardAmbiguous);
        let set = ConflictSet::new(
            0x1000,
            vec![
                make_match(0x1000, "a", "lib1", 80, 6),
                make_match(0x1000, "b", "lib2", 80, 6),
            ],
        );
        assert!(matches!(resolver.resolve_one(&set), ResolutionResult::Discarded));
    }

    #[test]
    fn test_resolver_discard_ambiguous_same_name_passes() {
        let resolver = MatchConflictResolver::new(ResolutionStrategy::DiscardAmbiguous);
        let set = ConflictSet::new(
            0x1000,
            vec![
                make_match(0x1000, "memcpy", "lib1", 80, 6),
                make_match(0x1000, "memcpy", "lib2", 75, 6),
            ],
        );
        assert!(resolver.resolve_one(&set).winner().is_some());
    }

    #[test]
    fn test_resolver_prefer_library_found() {
        let resolver = MatchConflictResolver::new(ResolutionStrategy::PreferLibrary("msvcrt".into()));
        let set = ConflictSet::new(
            0x1000,
            vec![
                make_match(0x1000, "func", "libc", 90, 8),
                make_match(0x1000, "func2", "msvcrt", 70, 6),
            ],
        );
        let w = resolver.resolve_one(&set).winner().unwrap().clone();
        assert_eq!(w.lib_name, "msvcrt");
    }

    #[test]
    fn test_resolver_prefer_library_fallback() {
        let resolver = MatchConflictResolver::new(ResolutionStrategy::PreferLibrary("unknown".into()));
        let set = ConflictSet::new(
            0x1000,
            vec![
                make_match(0x1000, "a", "lib1", 80, 8),
                make_match(0x1000, "b", "lib2", 70, 6),
            ],
        );
        // Fallback to highest confidence.
        assert_eq!(resolver.resolve_one(&set).winner().unwrap().confidence, 80);
    }

    #[test]
    fn test_resolver_trivial_set() {
        let resolver = MatchConflictResolver::default();
        let set = ConflictSet::new(0x1000, vec![make_match(0x1000, "f", "lib", 80, 8)]);
        assert!(resolver.resolve_one(&set).winner().is_some());
    }

    #[test]
    fn test_resolver_empty_set() {
        let resolver = MatchConflictResolver::default();
        let set = ConflictSet { address: 0, candidates: vec![] };
        assert!(matches!(resolver.resolve_one(&set), ResolutionResult::Discarded));
    }

    #[test]
    fn test_resolve_flat_list() {
        let resolver = MatchConflictResolver::default();
        let matches = vec![
            make_match(0x1000, "a", "lib", 80, 8),
            make_match(0x1000, "b", "lib", 60, 6),
            make_match(0x2000, "c", "lib", 90, 10),
        ];
        let resolved = resolver.resolve(matches);
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].address, 0x1000);
        assert_eq!(resolved[0].function_name, "a");
        assert_eq!(resolved[1].address, 0x2000);
    }

    #[test]
    fn test_collect_conflicts() {
        let matches = vec![
            make_match(0x1000, "a", "lib", 80, 8),
            make_match(0x1000, "b", "lib", 60, 6),
            make_match(0x2000, "c", "lib", 90, 10),
        ];
        let conflicts = MatchConflictResolver::collect_conflicts(&matches);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].address, 0x1000);
    }

    #[test]
    fn test_resolver_debug() {
        let r = MatchConflictResolver::default();
        assert!(!format!("{r:?}").is_empty());
    }

    #[test]
    fn test_resolver_strategy_name() {
        let r = MatchConflictResolver::new(ResolutionStrategy::LongestPattern);
        assert_eq!(r.strategy_name(), "LongestPattern");
    }

    #[test]
    fn test_resolver_min_delta_discards_close_match() {
        let resolver = MatchConflictResolver::new(ResolutionStrategy::HighestConfidence)
            .with_min_delta(10);
        let set = ConflictSet::new(
            0x1000,
            vec![
                make_match(0x1000, "a", "lib", 82, 8),
                make_match(0x1000, "b", "lib", 80, 6),
            ],
        );
        // Spread is 2 < 10 → discard.
        assert!(matches!(resolver.resolve_one(&set), ResolutionResult::Discarded));
    }

    #[test]
    fn test_resolver_min_delta_keeps_clear_winner() {
        let resolver = MatchConflictResolver::new(ResolutionStrategy::HighestConfidence)
            .with_min_delta(10);
        let set = ConflictSet::new(
            0x1000,
            vec![
                make_match(0x1000, "a", "lib", 95, 8),
                make_match(0x1000, "b", "lib", 60, 6),
            ],
        );
        // Spread is 35 ≥ 10 → keep.
        assert!(resolver.resolve_one(&set).winner().is_some());
    }
}
