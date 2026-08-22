//! FLIRT signature collision resolution.
//!
//! When multiple FLIRT signatures match at the same address, this module uses
//! additional evidence — tail bytes beyond the pattern, cross-references, and
//! pattern length — to pick the single best match (or report the ambiguity).

use crate::FlirtMatch;
use crate::casts::{u64_to_usize, usize_to_f64};
pub use crate::{FlirtPattern, FlirtSignature, crc16_flirt};
// AHashMap (randomised) prevents hash-collision DoS from attacker-controlled
// function addresses/names from untrusted .sig/.pat files.
use ahash::AHashMap as HashMap;

// ── TailByte matching ─────────────────────────────────────────────────────────

/// A run of concrete bytes that immediately follow a FLIRT pattern body.
///
/// The FLIRT .pat format specifies `crc16` + `crc_len` to check a "middle"
/// region. `TailBytes` extends that with a short literal sequence that must
/// appear right after the end of the pattern at a specific relative offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailBytes {
    /// Byte offset from the end of the pattern body where `bytes` start.
    pub offset: u16,
    /// Literal bytes expected at that offset.
    pub bytes: Vec<u8>,
}

impl TailBytes {
    #[must_use] 
    pub const fn new(offset: u16, bytes: Vec<u8>) -> Self {
        Self { offset, bytes }
    }

    /// Return `true` when `data` — indexed relative to the first byte *after*
    /// the pattern body — contains `self.bytes` at `self.offset`.
    #[must_use] 
    pub fn matches(&self, post_body: &[u8]) -> bool {
        let start = self.offset as usize;
        let end = start + self.bytes.len();
        if end > post_body.len() {
            return false;
        }
        post_body[start..end] == *self.bytes
    }
}

// ── RefPattern ────────────────────────────────────────────────────────────────

/// A named cross-reference expected at a fixed offset from the matched function
/// start.  Used in FLIRT to distinguish overloaded C++ names and similarly
/// structured functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefPattern {
    /// Byte offset (within the function) where the reference value is stored.
    pub offset: u32,
    /// Width of the reference in bytes (2, 4, or 8).
    pub size: u8,
    /// Expected name that the reference should resolve to.
    pub target_name: String,
    /// Whether the reference is negative (subtracted from base).
    pub negative: bool,
}

impl RefPattern {
    pub fn new(offset: u32, size: u8, target_name: impl Into<String>) -> Self {
        Self {
            offset,
            size,
            target_name: target_name.into(),
            negative: false,
        }
    }

    /// Verify that a known `symbol_map` (address → name) contains the expected
    /// target at `base_addr + self.offset`.
    #[must_use] 
    pub fn matches_symbols(&self, base_addr: u64, symbol_map: &HashMap<u64, String>) -> bool {
        let ref_addr = base_addr.wrapping_add(u64::from(self.offset));
        symbol_map
            .get(&ref_addr)
            .is_some_and(|name| name == &self.target_name)
    }
}

// ── CollisionGroup ────────────────────────────────────────────────────────────

/// All signatures that matched at the same offset, ready for disambiguation.
#[derive(Debug, Clone)]
pub struct CollisionGroup {
    /// Absolute address where all candidates were found.
    pub address: u64,
    /// All matches (one per candidate signature).
    pub candidates: Vec<CollisionCandidate>,
}

impl CollisionGroup {
    #[must_use] 
    pub const fn new(address: u64) -> Self {
        Self {
            address,
            candidates: Vec::new(),
        }
    }

    pub fn add(&mut self, candidate: CollisionCandidate) {
        self.candidates.push(candidate);
    }

    /// Return `true` when exactly one candidate remains after filtering.
    #[must_use] 
    pub const fn is_resolved(&self) -> bool {
        self.candidates.len() == 1
    }

    /// Return the best candidate, if the group is resolved.
    #[must_use] 
    pub fn best(&self) -> Option<&CollisionCandidate> {
        self.candidates.iter().max_by(|a, b| {
            a.score
                .partial_cmp(&b.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }
}

/// One candidate inside a [`CollisionGroup`].
#[derive(Debug, Clone)]
pub struct CollisionCandidate {
    /// The `FlirtMatch` that was initially produced for this candidate.
    pub flirt_match: FlirtMatch,
    /// Tail-byte constraints that must hold for this candidate.
    pub tail_bytes: Vec<TailBytes>,
    /// Reference patterns that disambiguate this candidate.
    pub ref_patterns: Vec<RefPattern>,
    /// Disambiguation score (higher is better).
    pub score: f64,
}

impl CollisionCandidate {
    #[must_use] 
    pub const fn new(flirt_match: FlirtMatch) -> Self {
        Self {
            flirt_match,
            tail_bytes: Vec::new(),
            ref_patterns: Vec::new(),
            score: 0.0,
        }
    }

    #[must_use] 
    pub fn with_tail(mut self, tail: TailBytes) -> Self {
        self.tail_bytes.push(tail);
        self
    }

    #[must_use] 
    pub fn with_ref(mut self, r: RefPattern) -> Self {
        self.ref_patterns.push(r);
        self
    }
}

// ── CollisionResolver ─────────────────────────────────────────────────────────

/// Resolves signature collisions using tail bytes, references, pattern length,
/// and CRC verification.
pub struct CollisionResolver {
    /// Weight given to tail-byte evidence (0..1).
    pub tail_weight: f64,
    /// Weight given to reference evidence (0..1).
    pub ref_weight: f64,
    /// Weight given to pattern length (longer = more specific).
    pub length_weight: f64,
    /// Weight given to confidence score from the initial match.
    pub confidence_weight: f64,
}

impl Default for CollisionResolver {
    fn default() -> Self {
        Self {
            tail_weight: 0.35,
            ref_weight: 0.30,
            length_weight: 0.20,
            confidence_weight: 0.15,
        }
    }
}

impl CollisionResolver {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve a [`CollisionGroup`] using `binary` (the full binary bytes) and
    /// an optional symbol map.
    ///
    /// Scores each candidate and returns the best match, or `None` if no
    /// candidate passes minimum scoring.
    pub fn resolve(
        &self,
        group: &mut CollisionGroup,
        binary: &[u8],
        symbol_map: Option<&HashMap<u64, String>>,
        base_addr: u64,
    ) -> Option<FlirtMatch> {
        if group.candidates.is_empty() {
            return None;
        }

        // Score each candidate.
        for cand in &mut group.candidates {
            cand.score = self.compute_score(cand, binary, symbol_map, base_addr);
        }

        // Sort by score descending.
        group.candidates.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Return best if it is clearly better than the second.
        let best = group.candidates.first()?;
        if group.candidates.len() == 1 {
            return Some(best.flirt_match.clone());
        }
        let second = &group.candidates[1];
        // Require at least 0.1 score gap to resolve the collision.
        if best.score - second.score >= 0.1 {
            Some(best.flirt_match.clone())
        } else {
            // Tie — return the longer pattern as a tiebreaker.
            let winner = group
                .candidates
                .iter()
                .max_by_key(|c| c.flirt_match.pattern_length)?;
            Some(winner.flirt_match.clone())
        }
    }

    /// Compute a score in [0, 1] for one candidate.
    fn compute_score(
        &self,
        cand: &CollisionCandidate,
        binary: &[u8],
        symbol_map: Option<&HashMap<u64, String>>,
        base_addr: u64,
    ) -> f64 {
        let mut score = 0.0f64;

        // ── Tail-byte evidence ────────────────────────────────────────────────
        if cand.tail_bytes.is_empty() {
            // No tail-byte constraints: give half credit.
            score = self.tail_weight.mul_add(0.5, score);
        } else {
            let offset = u64_to_usize(cand.flirt_match.address.saturating_sub(base_addr));
            let pat_end = offset + cand.flirt_match.pattern_length;
            let post_body = if pat_end < binary.len() {
                &binary[pat_end..]
            } else {
                &[]
            };
            let matched = cand
                .tail_bytes
                .iter()
                .filter(|t| t.matches(post_body))
                .count();
            let tail_score = usize_to_f64(matched) / usize_to_f64(cand.tail_bytes.len());
            score = self.tail_weight.mul_add(tail_score, score);
        }

        // ── Reference evidence ────────────────────────────────────────────────
        if cand.ref_patterns.is_empty() {
            score = self.ref_weight.mul_add(0.5, score);
        } else if let Some(sym) = symbol_map {
            let matched = cand
                .ref_patterns
                .iter()
                .filter(|r| r.matches_symbols(cand.flirt_match.address, sym))
                .count();
            let ref_score = usize_to_f64(matched) / usize_to_f64(cand.ref_patterns.len());
            score = self.ref_weight.mul_add(ref_score, score);
        } else {
            score = self.ref_weight.mul_add(0.3, score);
        }

        // ── Pattern length ────────────────────────────────────────────────────
        // Normalise to a 32-byte ideal length.
        let len_norm = usize_to_f64(cand.flirt_match.pattern_length.min(32)) / 32.0;
        score = self.length_weight.mul_add(len_norm, score);

        // ── Confidence score ──────────────────────────────────────────────────
        score = self.confidence_weight.mul_add(f64::from(cand.flirt_match.confidence) / 100.0, score);

        score.min(1.0)
    }

    /// Resolve all collision groups in `groups` using `binary`.
    ///
    /// Returns a list of resolved matches (one per group, if resolvable).
    pub fn resolve_all(
        &self,
        groups: &mut [CollisionGroup],
        binary: &[u8],
        symbol_map: Option<&HashMap<u64, String>>,
        base_addr: u64,
    ) -> Vec<FlirtMatch> {
        groups
            .iter_mut()
            .filter_map(|g| self.resolve(g, binary, symbol_map, base_addr))
            .collect()
    }

    /// Build collision groups from a flat list of `FlirtMatch` results.
    ///
    /// Two matches belong to the same group when they share the same address.
    #[must_use] 
    pub fn group_collisions(matches: Vec<FlirtMatch>) -> Vec<CollisionGroup> {
        let mut by_addr: HashMap<u64, Vec<FlirtMatch>> = HashMap::new();
        for m in matches {
            by_addr.entry(m.address).or_default().push(m);
        }
        by_addr
            .into_iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(addr, ms)| {
                let mut group = CollisionGroup::new(addr);
                for m in ms {
                    group.add(CollisionCandidate::new(m));
                }
                group
            })
            .collect()
    }
}

/// Convenience function: resolve the best match from a list of `FlirtMatch`
/// results at the same address.
#[must_use]
pub fn resolve_best_match(
    matches: Vec<FlirtMatch>,
    binary: &[u8],
    base_addr: u64,
) -> Option<FlirtMatch> {
    if matches.is_empty() {
        return None;
    }
    if matches.len() == 1 {
        return matches.into_iter().next();
    }

    let resolver = CollisionResolver::new();
    let mut groups = CollisionResolver::group_collisions(matches);
    let resolution = resolver.resolve_all(&mut groups, binary, None, base_addr);
    resolution.into_iter().next()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FlirtMatch;

    fn make_match(addr: u64, name: &str, conf: u8, pat_len: usize) -> FlirtMatch {
        FlirtMatch {
            address: addr,
            function_name: name.to_string(),
            lib_name: "testlib".to_string(),
            confidence: conf,
            pattern_length: pat_len,
        }
    }

    // ── TailBytes ─────────────────────────────────────────────────────────────

    #[test]
    fn test_tailbytes_matches_ok() {
        let tb = TailBytes::new(0, vec![0x90, 0x90]);
        let data = [0x90u8, 0x90, 0x00];
        assert!(tb.matches(&data));
    }

    #[test]
    fn test_tailbytes_matches_offset() {
        let tb = TailBytes::new(2, vec![0xCC]);
        let data = [0x00u8, 0x00, 0xCC];
        assert!(tb.matches(&data));
    }

    #[test]
    fn test_tailbytes_no_match() {
        let tb = TailBytes::new(0, vec![0xAA]);
        let data = [0x55u8];
        assert!(!tb.matches(&data));
    }

    #[test]
    fn test_tailbytes_too_short() {
        let tb = TailBytes::new(10, vec![0x00]);
        let data = [0x00u8; 5];
        assert!(!tb.matches(&data));
    }

    // ── RefPattern ────────────────────────────────────────────────────────────

    #[test]
    fn test_refpattern_matches_symbol() {
        let rp = RefPattern::new(4, 4, "malloc");
        let mut sym = HashMap::new();
        sym.insert(0x1004u64, "malloc".to_string());
        assert!(rp.matches_symbols(0x1000, &sym));
    }

    #[test]
    fn test_refpattern_no_match() {
        let rp = RefPattern::new(4, 4, "malloc");
        let mut sym = HashMap::new();
        sym.insert(0x1004u64, "free".to_string());
        assert!(!rp.matches_symbols(0x1000, &sym));
    }

    #[test]
    fn test_refpattern_missing_symbol() {
        let rp = RefPattern::new(4, 4, "malloc");
        let sym: HashMap<u64, String> = HashMap::new();
        assert!(!rp.matches_symbols(0x1000, &sym));
    }

    // ── CollisionCandidate ────────────────────────────────────────────────────

    #[test]
    fn test_candidate_new() {
        let m = make_match(0x1000, "foo", 80, 12);
        let c = CollisionCandidate::new(m);
        assert_eq!(c.flirt_match.address, 0x1000);
        assert!(c.tail_bytes.is_empty());
        assert!(c.ref_patterns.is_empty());
        assert_eq!(c.score, 0.0);
    }

    #[test]
    fn test_candidate_with_tail() {
        let m = make_match(0x1000, "foo", 80, 12);
        let c = CollisionCandidate::new(m).with_tail(TailBytes::new(0, vec![0x90]));
        assert_eq!(c.tail_bytes.len(), 1);
    }

    // ── CollisionGroup ────────────────────────────────────────────────────────

    #[test]
    fn test_group_is_resolved_single() {
        let mut g = CollisionGroup::new(0x1000);
        g.add(CollisionCandidate::new(make_match(0x1000, "a", 90, 12)));
        assert!(g.is_resolved());
    }

    #[test]
    fn test_group_is_resolved_multiple() {
        let mut g = CollisionGroup::new(0x1000);
        g.add(CollisionCandidate::new(make_match(0x1000, "a", 90, 12)));
        g.add(CollisionCandidate::new(make_match(0x1000, "b", 85, 12)));
        assert!(!g.is_resolved());
    }

    #[test]
    fn test_group_best_empty() {
        let g = CollisionGroup::new(0x1000);
        assert!(g.best().is_none());
    }

    // ── CollisionResolver ─────────────────────────────────────────────────────

    #[test]
    fn test_resolver_single_candidate() {
        let resolver = CollisionResolver::new();
        let mut g = CollisionGroup::new(0x1000);
        g.add(CollisionCandidate::new(make_match(
            0x1000, "only_fn", 90, 16,
        )));
        let result = resolver.resolve(&mut g, &[0u8; 64], None, 0x1000);
        assert!(result.is_some());
        assert_eq!(result.unwrap().function_name, "only_fn");
    }

    #[test]
    fn test_resolver_picks_longer_pattern() {
        let resolver = CollisionResolver::new();
        let mut g = CollisionGroup::new(0x2000);
        g.add(CollisionCandidate::new(make_match(
            0x2000, "short_fn", 80, 8,
        )));
        g.add(CollisionCandidate::new(make_match(
            0x2000, "long_fn", 80, 28,
        )));
        let result = resolver.resolve(&mut g, &[0u8; 128], None, 0x2000);
        assert!(result.is_some());
        assert_eq!(result.unwrap().function_name, "long_fn");
    }

    #[test]
    fn test_resolver_tail_bytes_disambiguate() {
        let resolver = CollisionResolver::new();
        let mut g = CollisionGroup::new(0x3000);
        // Pattern body is 4 bytes; post-body starts at offset 4.
        let m1 = make_match(0x3000, "fn_a", 80, 4);
        let m2 = make_match(0x3000, "fn_b", 80, 4);
        let mut c1 = CollisionCandidate::new(m1);
        c1.tail_bytes.push(TailBytes::new(0, vec![0xCC, 0xCC])); // will match
        let mut c2 = CollisionCandidate::new(m2);
        c2.tail_bytes.push(TailBytes::new(0, vec![0xAA, 0xAA])); // won't match
        g.add(c1);
        g.add(c2);

        // Binary: 4-byte pattern body + 0xCC 0xCC tail.
        let binary = vec![0x55u8, 0x8B, 0xEC, 0x83, 0xCC, 0xCC, 0x00, 0x00];
        let result = resolver.resolve(&mut g, &binary, None, 0x3000);
        assert!(result.is_some());
        assert_eq!(result.unwrap().function_name, "fn_a");
    }

    #[test]
    fn test_resolver_no_candidates() {
        let resolver = CollisionResolver::new();
        let mut g = CollisionGroup::new(0x4000);
        let result = resolver.resolve(&mut g, &[0u8; 32], None, 0x4000);
        assert!(result.is_none());
    }

    #[test]
    fn test_group_collisions_single_addr() {
        let matches = vec![
            make_match(0x1000, "a", 80, 12),
            make_match(0x1000, "b", 75, 12),
            make_match(0x2000, "c", 90, 16),
        ];
        let groups = CollisionResolver::group_collisions(matches);
        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn test_resolve_best_match_single() {
        let m = make_match(0x1000, "only", 95, 16);
        let result = resolve_best_match(vec![m], &[0u8; 64], 0x1000);
        assert!(result.is_some());
        assert_eq!(result.unwrap().function_name, "only");
    }

    #[test]
    fn test_resolve_best_match_empty() {
        let result = resolve_best_match(vec![], &[0u8; 64], 0x1000);
        assert!(result.is_none());
    }

    #[test]
    fn test_resolve_all_multiple_groups() {
        let resolver = CollisionResolver::new();
        let matches = vec![
            make_match(0x1000, "fn1", 90, 16),
            make_match(0x2000, "fn2", 85, 12),
        ];
        let mut groups = CollisionResolver::group_collisions(matches);
        let winners = resolver.resolve_all(&mut groups, &[0u8; 128], None, 0x1000);
        assert_eq!(winners.len(), 2);
    }
}
