//! Candidate disambiguation and collision handling for applied FLIRT patterns.
//!
//! The [`crate::trie_index::PatternTrie`] narrows a function buffer down to a
//! small set of *candidate* patterns by leading bytes. This module takes that
//! candidate set and resolves it to a final answer using the remaining FLIRT
//! discriminators — CRC-16 over the stable region and total function length —
//! returning either a unique match or an ambiguity group when the evidence is
//! insufficient to separate distinct functions.

use crate::FlirtPattern;
use crate::apply_engine::crc16_flirt;
use crate::trie_index::PatternTrie;

// ── ResolvedMatch ────────────────────────────────────────────────────────────

/// A single resolved pattern, identified by its index and primary name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedMatch {
    /// Index of the pattern in the resolver's pattern slice.
    pub pattern_idx: usize,
    /// The matched function's name.
    pub name: String,
    /// Whether a CRC-16 check actually confirmed the match (vs. patterns with
    /// no CRC region, which match on bytes alone).
    pub crc_confirmed: bool,
}

// ── CollisionSet ─────────────────────────────────────────────────────────────

/// A set of distinctly-named patterns that share a byte prefix and CRC-16.
///
/// These cannot be separated by the standard FLIRT discriminators and are
/// surfaced to the caller as a group rather than silently picking one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollisionSet {
    /// The colliding matches (always length ≥ 2).
    pub members: Vec<ResolvedMatch>,
}

impl CollisionSet {
    /// Number of colliding members.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.members.len()
    }

    /// Returns `true` if there are no members (not expected for a real group).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Distinct, sorted names involved in the collision.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.members.iter().map(|m| m.name.clone()).collect();
        v.sort();
        v.dedup();
        v
    }
}

// ── MatchResolution ──────────────────────────────────────────────────────────

/// The result of resolving a candidate set against a function buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchResolution {
    /// Exactly one function matched.
    Unique(ResolvedMatch),
    /// Multiple distinct functions matched and could not be separated.
    Ambiguous(CollisionSet),
    /// No candidate matched the buffer.
    None,
}

impl MatchResolution {
    /// Returns `true` for a unique resolution.
    #[must_use]
    pub const fn is_unique(&self) -> bool {
        matches!(self, Self::Unique(_))
    }

    /// Returns `true` for an ambiguous resolution.
    #[must_use]
    pub const fn is_ambiguous(&self) -> bool {
        matches!(self, Self::Ambiguous(_))
    }

    /// The single resolved match, if this resolution is unique.
    #[must_use]
    pub const fn unique(&self) -> Option<&ResolvedMatch> {
        match self {
            Self::Unique(m) => Some(m),
            _ => None,
        }
    }
}

// ── Disambiguator ────────────────────────────────────────────────────────────

/// Resolves trie candidates to a [`MatchResolution`] using CRC-16 and length.
///
/// Build once from a pattern slice (an internal [`PatternTrie`] is constructed
/// for fast prefix lookup), then call [`Disambiguator::resolve`] for each
/// function buffer.
pub struct Disambiguator<'a> {
    patterns: &'a [FlirtPattern],
    trie: PatternTrie,
}

impl<'a> Disambiguator<'a> {
    /// Build a disambiguator (and its lookup trie) over `patterns`.
    #[must_use]
    pub fn new(patterns: &'a [FlirtPattern]) -> Self {
        let trie = PatternTrie::build_from_patterns(patterns);
        Self { patterns, trie }
    }

    /// Number of patterns indexed.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Resolve the function bytes at `data[offset..]` to a [`MatchResolution`].
    ///
    /// Steps:
    /// 1. Query the trie for candidates whose initial bytes match.
    /// 2. Keep only candidates whose CRC-16 (if any) confirms.
    /// 3. Prefer the longest (most specific) byte pattern.
    /// 4. Collapse same-name survivors to a unique result, otherwise report the
    ///    remaining distinct names as a collision.
    #[must_use]
    pub fn resolve(&self, data: &[u8], offset: usize) -> MatchResolution {
        if offset > data.len() {
            return MatchResolution::None;
        }
        let candidates = self.trie.search_at_offset(data, offset);

        let mut survivors: Vec<(usize, bool)> = Vec::new();
        for idx in candidates {
            let pat = &self.patterns[idx];
            if let Some(confirmed) = Self::check_crc(pat, data, offset) {
                survivors.push((idx, confirmed));
            }
        }

        if survivors.is_empty() {
            return MatchResolution::None;
        }

        // Prefer the most specific (longest byte pattern).
        let max_len = survivors
            .iter()
            .map(|&(i, _)| self.patterns[i].bytes.len())
            .max()
            .unwrap_or(0);
        survivors.retain(|&(i, _)| self.patterns[i].bytes.len() == max_len);

        let resolved: Vec<ResolvedMatch> = survivors
            .iter()
            .map(|&(i, confirmed)| ResolvedMatch {
                pattern_idx: i,
                name: self.patterns[i].name.clone(),
                crc_confirmed: confirmed,
            })
            .collect();

        let distinct: std::collections::BTreeSet<&str> =
            resolved.iter().map(|m| m.name.as_str()).collect();
        if distinct.len() <= 1 {
            // Single function (possibly recorded more than once). Prefer a
            // CRC-confirmed entry as the representative.
            let best = resolved
                .iter()
                .find(|m| m.crc_confirmed)
                .cloned()
                .unwrap_or_else(|| resolved[0].clone());
            return MatchResolution::Unique(best);
        }

        MatchResolution::Ambiguous(CollisionSet { members: resolved })
    }

    /// Verify a pattern's CRC against the buffer.
    ///
    /// Returns `Some(true)` if a CRC region was present and matched,
    /// `Some(false)` if there was no CRC region (byte match only), and `None`
    /// if a CRC region was present but did **not** match (reject the candidate).
    fn check_crc(pat: &FlirtPattern, data: &[u8], offset: usize) -> Option<bool> {
        if pat.crc_len == 0 {
            return Some(false);
        }
        // `crc_offset` is ABSOLUTE from the start of the match: the producers
        // in `ida_sig_compat` store it as `bytes.len()` / `pat_len`, i.e. the
        // offset just past the pattern body. Adding `pattern_len()` here would
        // count that length twice.
        let start = offset + pat.crc_offset as usize;
        let end = start + pat.crc_len as usize;
        if end > data.len() {
            return None;
        }
        if crc16_flirt(&data[start..end]) == pat.crc {
            Some(true)
        } else {
            None
        }
    }

    /// Enumerate every collision group across the whole pattern set.
    ///
    /// Patterns are grouped by `(byte-pattern-hex, crc_offset, crc_len, crc)`.
    /// Keys shared by two or more distinctly-named patterns become a
    /// [`CollisionSet`]. Output is sorted for determinism.
    #[must_use]
    pub fn collision_groups(&self) -> Vec<CollisionSet> {
        let mut map: std::collections::BTreeMap<String, Vec<usize>> =
            std::collections::BTreeMap::new();
        for (i, pat) in self.patterns.iter().enumerate() {
            let hex: String = pat
                .bytes
                .iter()
                .map(|b| b.as_ref().map_or_else(|| "..".to_string(), |v| format!("{v:02X}")))
                .collect();
            let key = format!("{hex}|{}|{}|{:04X}", pat.crc_offset, pat.crc_len, pat.crc);
            map.entry(key).or_default().push(i);
        }

        let mut groups = Vec::new();
        for indices in map.values() {
            if indices.len() < 2 {
                continue;
            }
            let members: Vec<ResolvedMatch> = indices
                .iter()
                .map(|&i| ResolvedMatch {
                    pattern_idx: i,
                    name: self.patterns[i].name.clone(),
                    crc_confirmed: self.patterns[i].crc_len > 0,
                })
                .collect();
            let distinct: std::collections::BTreeSet<&str> =
                members.iter().map(|m| m.name.as_str()).collect();
            if distinct.len() >= 2 {
                groups.push(CollisionSet { members });
            }
        }
        groups
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn pat(name: &str, bytes: &[Option<u8>]) -> FlirtPattern {
        FlirtPattern::new(name.to_string(), bytes.to_vec())
    }

    fn ex(bytes: &[u8]) -> Vec<Option<u8>> {
        bytes.iter().map(|&b| Some(b)).collect()
    }

    fn with_crc(
        name: &str,
        bytes: &[Option<u8>],
        crc_offset: u16,
        crc_len: u16,
        crc: u16,
    ) -> FlirtPattern {
        let mut p = pat(name, bytes);
        p.crc_offset = crc_offset;
        p.crc_len = crc_len;
        p.crc = crc;
        p
    }

    // ── unique resolution ──────────────────────────────────────────────────

    #[test]
    fn test_resolve_unique_no_crc() {
        let pats = vec![pat("memcpy", &ex(&[0x55, 0x8B, 0xEC, 0x83]))];
        let d = Disambiguator::new(&pats);
        let r = d.resolve(&[0x55, 0x8B, 0xEC, 0x83, 0x90], 0);
        assert!(r.is_unique());
        assert_eq!(r.unique().unwrap().name, "memcpy");
        assert!(!r.unique().unwrap().crc_confirmed);
    }

    #[test]
    fn test_resolve_none() {
        let pats = vec![pat("x", &ex(&[0xAA, 0xBB, 0xCC, 0xDD]))];
        let d = Disambiguator::new(&pats);
        assert_eq!(
            d.resolve(&[0x00, 0x11, 0x22, 0x33], 0),
            MatchResolution::None
        );
    }

    #[test]
    fn test_resolve_offset_past_end() {
        let pats = vec![pat("x", &ex(&[0x55, 0x8B]))];
        let d = Disambiguator::new(&pats);
        assert_eq!(d.resolve(&[0x55, 0x8B], 99), MatchResolution::None);
    }

    #[test]
    fn test_pattern_count() {
        let pats = vec![pat("a", &ex(&[0x55])), pat("b", &ex(&[0x8B]))];
        let d = Disambiguator::new(&pats);
        assert_eq!(d.pattern_count(), 2);
    }

    // ── CRC disambiguation ──────────────────────────────────────────────────

    #[test]
    fn test_resolve_crc_disambiguates() {
        // Same prefix [0x55,0x8B]; CRC region is the 2 bytes at offset 2.
        let body_a = [0x55u8, 0x8B, 0x11, 0x22];
        let body_b = [0x55u8, 0x8B, 0x33, 0x44];
        let crc_a = crc16_flirt(&body_a[2..4]);
        let crc_b = crc16_flirt(&body_b[2..4]);

        let pats = vec![
            with_crc("fa", &ex(&[0x55, 0x8B]), 2, 2, crc_a),
            with_crc("fb", &ex(&[0x55, 0x8B]), 2, 2, crc_b),
        ];
        let d = Disambiguator::new(&pats);

        let ra = d.resolve(&body_a, 0);
        assert_eq!(ra.unique().unwrap().name, "fa");
        assert!(ra.unique().unwrap().crc_confirmed);

        let rb = d.resolve(&body_b, 0);
        assert_eq!(rb.unique().unwrap().name, "fb");
    }

    #[test]
    fn test_resolve_crc_mismatch_rejected() {
        let pats = vec![with_crc("f", &ex(&[0x55, 0x8B]), 2, 2, 0xDEAD)];
        let d = Disambiguator::new(&pats);
        // CRC won't match → no result.
        assert_eq!(
            d.resolve(&[0x55, 0x8B, 0x11, 0x22], 0),
            MatchResolution::None
        );
    }

    #[test]
    fn test_resolve_crc_out_of_bounds_rejected() {
        let pats = vec![with_crc("f", &ex(&[0x55, 0x8B]), 2, 8, 0x0000)];
        let d = Disambiguator::new(&pats);
        // Buffer too short to cover CRC region.
        assert_eq!(d.resolve(&[0x55, 0x8B, 0x11], 0), MatchResolution::None);
    }

    // ── most-specific preference ────────────────────────────────────────────

    #[test]
    fn test_resolve_prefers_longer_pattern() {
        let pats = vec![
            pat("short", &ex(&[0x55, 0x8B])),
            pat("long", &ex(&[0x55, 0x8B, 0xEC, 0x83])),
        ];
        let d = Disambiguator::new(&pats);
        let r = d.resolve(&[0x55, 0x8B, 0xEC, 0x83], 0);
        assert_eq!(r.unique().unwrap().name, "long");
    }

    // ── ambiguity ───────────────────────────────────────────────────────────

    #[test]
    fn test_resolve_ambiguous() {
        let pats = vec![
            pat("alpha", &ex(&[0x55, 0x8B, 0xEC])),
            pat("beta", &ex(&[0x55, 0x8B, 0xEC])),
        ];
        let d = Disambiguator::new(&pats);
        let r = d.resolve(&[0x55, 0x8B, 0xEC, 0x00], 0);
        assert!(r.is_ambiguous());
        if let MatchResolution::Ambiguous(c) = r {
            assert_eq!(c.len(), 2);
            assert_eq!(c.names(), vec!["alpha".to_string(), "beta".to_string()]);
        }
    }

    #[test]
    fn test_resolve_same_name_collapses_to_unique() {
        let pats = vec![
            pat("dup", &ex(&[0x55, 0x8B, 0xEC])),
            pat("dup", &ex(&[0x55, 0x8B, 0xEC])),
        ];
        let d = Disambiguator::new(&pats);
        assert!(d.resolve(&[0x55, 0x8B, 0xEC], 0).is_unique());
    }

    #[test]
    fn test_collision_groups() {
        let pats = vec![
            pat("alpha", &ex(&[0x55, 0x8B, 0xEC])),
            pat("beta", &ex(&[0x55, 0x8B, 0xEC])),
            pat("solo", &ex(&[0x48, 0x89, 0xE5])),
        ];
        let d = Disambiguator::new(&pats);
        let groups = d.collision_groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].names(),
            vec!["alpha".to_string(), "beta".to_string()]
        );
    }

    #[test]
    fn test_collision_groups_none_when_crc_differs() {
        // Same prefix but different CRC → not a collision.
        let pats = vec![
            with_crc("a", &ex(&[0x55, 0x8B]), 2, 2, 0x1111),
            with_crc("b", &ex(&[0x55, 0x8B]), 2, 2, 0x2222),
        ];
        let d = Disambiguator::new(&pats);
        assert!(d.collision_groups().is_empty());
    }

    #[test]
    fn test_collision_set_is_empty_false() {
        let c = CollisionSet {
            members: vec![
                ResolvedMatch {
                    pattern_idx: 0,
                    name: "a".into(),
                    crc_confirmed: false,
                },
                ResolvedMatch {
                    pattern_idx: 1,
                    name: "b".into(),
                    crc_confirmed: false,
                },
            ],
        };
        assert!(!c.is_empty());
        assert_eq!(c.len(), 2);
    }
}
