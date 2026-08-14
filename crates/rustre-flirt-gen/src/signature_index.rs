//! Fast signature lookup and collision handling for generated FLIRT patterns.
//!
//! This module complements [`crate::PatternGenerator`] with the *matching* half
//! of a FLIRT workflow that is self-contained within `rustre-flirt-gen`:
//!
//! * [`SignatureIndex`] — a wildcard-aware prefix trie over the
//!   [`rustre_flirt::FlirtPattern::initial_bytes`] of a pattern set, providing
//!   `O(k)` candidate lookup (where `k` is the prefix length) instead of an
//!   `O(n·k)` linear scan.
//! * [`MatchOutcome`] — the result of resolving a candidate set against a code
//!   buffer: a unique match, an ambiguity group, or no match.
//! * [`AmbiguityGroup`] — patterns that share an identical masked prefix *and*
//!   CRC-16, kept together because byte/CRC evidence alone cannot separate them.
//!
//! All lookups apply the full FLIRT discriminator chain: masked initial bytes,
//! then CRC-16 over the post-prefix region, then tail bytes.

use rustre_flirt::{FlirtPattern, PatternByte, crc16_flirt};

// ── PatternRef ──────────────────────────────────────────────────────────────

/// A resolved reference to one matching pattern.
///
/// Carries the pattern's index in the original slice plus its primary name so
/// callers can report a result without re-borrowing the pattern slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternRef {
    /// Index of the pattern in the slice the index was built from.
    pub index: usize,
    /// Primary public name of the pattern, or empty if it has none.
    pub name: String,
}

// ── AmbiguityGroup ──────────────────────────────────────────────────────────

/// A set of patterns that cannot be distinguished by byte pattern + CRC-16.
///
/// When two or more signatures share the same masked initial bytes and the same
/// CRC-16 over the post-prefix region, FLIRT keeps them as a collision group;
/// only tail bytes or referenced names can break the tie. This type records
/// such a group so the caller can decide how to present the ambiguity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmbiguityGroup {
    /// The colliding pattern references (always length ≥ 2).
    pub members: Vec<PatternRef>,
}

impl AmbiguityGroup {
    /// Number of colliding patterns in this group.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.members.len()
    }

    /// Returns `true` if the group holds no members.
    ///
    /// A well-formed group always has at least two members, so this normally
    /// returns `false`; it exists to satisfy the clippy `len`/`is_empty` pairing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// All distinct names present in the group, sorted and de-duplicated.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.members.iter().map(|m| m.name.clone()).collect();
        v.sort();
        v.dedup();
        v
    }
}

// ── MatchOutcome ────────────────────────────────────────────────────────────

/// The outcome of resolving a code buffer against the index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchOutcome {
    /// Exactly one pattern matched after all discriminators were applied.
    Unique(PatternRef),
    /// Several patterns matched and could not be separated; kept as a group.
    Ambiguous(AmbiguityGroup),
    /// No pattern matched the buffer.
    None,
}

impl MatchOutcome {
    /// Returns `true` for a unique match.
    #[must_use]
    pub const fn is_unique(&self) -> bool {
        matches!(self, Self::Unique(_))
    }

    /// Returns `true` for an ambiguous (collision) result.
    #[must_use]
    pub const fn is_ambiguous(&self) -> bool {
        matches!(self, Self::Ambiguous(_))
    }

    /// Returns the matched [`PatternRef`] if and only if the outcome is unique.
    #[must_use]
    pub const fn unique_ref(&self) -> Option<&PatternRef> {
        match self {
            Self::Unique(r) => Some(r),
            _ => None,
        }
    }
}

// ── SignatureIndex ──────────────────────────────────────────────────────────

/// One node in the index's flat-arena trie.
#[derive(Debug, Default)]
struct IndexNode {
    /// Exact-byte children: byte value → arena index.
    exact: std::collections::HashMap<u8, usize>,
    /// Wildcard child (matches any byte), if present.
    wildcard: Option<usize>,
    /// Indices of patterns that terminate at this node.
    terminal: Vec<usize>,
}

/// A wildcard-aware prefix index over a set of [`FlirtPattern`]s.
///
/// Build the index once from a pattern slice, then call [`SignatureIndex::query`]
/// (full discriminator resolution) or [`SignatureIndex::candidates`] (prefix-only)
/// for each function buffer to be identified.
pub struct SignatureIndex<'a> {
    nodes: Vec<IndexNode>,
    patterns: &'a [FlirtPattern],
}

impl<'a> SignatureIndex<'a> {
    /// Build an index over `patterns`.
    ///
    /// Each pattern is inserted along the path described by its
    /// `initial_bytes`: [`PatternByte::Exact`] follows an exact edge and
    /// [`PatternByte::Wildcard`] follows the wildcard edge.
    #[must_use]
    pub fn build(patterns: &'a [FlirtPattern]) -> Self {
        let mut idx = Self {
            nodes: vec![IndexNode::default()],
            patterns,
        };
        for (pi, pat) in patterns.iter().enumerate() {
            idx.insert(pi, &pat.initial_bytes);
        }
        idx
    }

    fn insert(&mut self, pattern_idx: usize, bytes: &[PatternByte]) {
        let mut node = 0usize;
        for pb in bytes {
            node = match pb {
                PatternByte::Exact(b) => {
                    if let Some(&n) = self.nodes[node].exact.get(b) {
                        n
                    } else {
                        let n = self.nodes.len();
                        self.nodes.push(IndexNode::default());
                        self.nodes[node].exact.insert(*b, n);
                        n
                    }
                }
                PatternByte::Wildcard => {
                    if let Some(n) = self.nodes[node].wildcard {
                        n
                    } else {
                        let n = self.nodes.len();
                        self.nodes.push(IndexNode::default());
                        self.nodes[node].wildcard = Some(n);
                        n
                    }
                }
            };
        }
        self.nodes[node].terminal.push(pattern_idx);
    }

    /// Number of patterns the index was built from.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Number of trie nodes (a rough measure of index size).
    #[must_use]
    pub const fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Return the indices of all patterns whose masked initial bytes are
    /// compatible with the leading bytes of `code`.
    ///
    /// This is the cheap prefix filter; it does **not** apply CRC-16 or tail
    /// discriminators. Results are sorted and de-duplicated.
    #[must_use]
    pub fn candidates(&self, code: &[u8]) -> Vec<usize> {
        let mut out = Vec::new();
        self.walk(0, code, 0, &mut out);
        out.sort_unstable();
        out.dedup();
        out
    }

    fn walk(&self, node_idx: usize, code: &[u8], depth: usize, out: &mut Vec<usize>) {
        let node = &self.nodes[node_idx];
        out.extend_from_slice(&node.terminal);

        if depth >= code.len() {
            return;
        }
        let byte = code[depth];
        if let Some(&child) = node.exact.get(&byte) {
            self.walk(child, code, depth + 1, out);
        }
        if let Some(child) = node.wildcard {
            self.walk(child, code, depth + 1, out);
        }
    }

    /// Resolve `code` to a [`MatchOutcome`], applying the full discriminator
    /// chain (initial bytes → CRC-16 → tail bytes).
    ///
    /// Among patterns that fully match, the longest masked prefix wins (it is
    /// the most specific). Remaining ties form an [`AmbiguityGroup`].
    #[must_use]
    pub fn query(&self, code: &[u8]) -> MatchOutcome {
        let mut matched: Vec<usize> = self
            .candidates(code)
            .into_iter()
            .filter(|&i| self.patterns[i].matches_all(code))
            .collect();

        if matched.is_empty() {
            return MatchOutcome::None;
        }

        // Prefer the most specific (longest masked prefix) pattern.
        let max_prefix = matched
            .iter()
            .map(|&i| self.patterns[i].initial_bytes.len())
            .max()
            .unwrap_or(0);
        matched.retain(|&i| self.patterns[i].initial_bytes.len() == max_prefix);

        if matched.len() == 1 {
            return MatchOutcome::Unique(self.pattern_ref(matched[0]));
        }

        // Multiple equally-specific matches that share prefix + CRC: collision.
        // Collapse entries that resolve to the same name into a single ref so a
        // genuine single function recorded twice is still reported as unique.
        let mut refs: Vec<PatternRef> = matched.iter().map(|&i| self.pattern_ref(i)).collect();
        let distinct_names: std::collections::BTreeSet<&str> =
            refs.iter().map(|r| r.name.as_str()).collect();
        if distinct_names.len() == 1 {
            return MatchOutcome::Unique(refs.remove(0));
        }

        MatchOutcome::Ambiguous(AmbiguityGroup { members: refs })
    }

    fn pattern_ref(&self, index: usize) -> PatternRef {
        PatternRef {
            index,
            name: self.patterns[index]
                .primary_name()
                .unwrap_or("")
                .to_string(),
        }
    }

    /// Enumerate every collision group in the indexed pattern set.
    ///
    /// Patterns are grouped by the key `(masked-prefix-hex, crc_length, crc16)`.
    /// Any key shared by two or more *distinctly named* patterns yields an
    /// [`AmbiguityGroup`]. The returned groups are sorted for determinism.
    #[must_use]
    pub fn collision_groups(&self) -> Vec<AmbiguityGroup> {
        let mut map: std::collections::BTreeMap<String, Vec<usize>> =
            std::collections::BTreeMap::new();

        for (i, pat) in self.patterns.iter().enumerate() {
            let key = format!("{}|{}|{:04X}", pat.pattern_hex(), pat.crc_length, pat.crc16);
            map.entry(key).or_default().push(i);
        }

        let mut groups = Vec::new();
        for indices in map.values() {
            if indices.len() < 2 {
                continue;
            }
            let refs: Vec<PatternRef> = indices.iter().map(|&i| self.pattern_ref(i)).collect();
            let distinct: std::collections::BTreeSet<&str> =
                refs.iter().map(|r| r.name.as_str()).collect();
            if distinct.len() >= 2 {
                groups.push(AmbiguityGroup { members: refs });
            }
        }
        groups
    }
}

// ── Free helper ─────────────────────────────────────────────────────────────

/// Compute the FLIRT CRC-16 over the post-prefix region of a function body.
///
/// Given the full function `code`, the masked prefix length `prefix_len`, and
/// the desired `crc_len`, this returns the CRC-16/CCITT over
/// `code[prefix_len .. prefix_len + crc_len]`, clamped to the available bytes.
/// The second element of the tuple is the number of bytes actually covered.
///
/// This is the exact region that [`FlirtPattern::matches_crc16`] checks, so the
/// value returned here can be compared directly against a pattern's `crc16`.
#[must_use]
pub fn crc16_over_tail(code: &[u8], prefix_len: usize, crc_len: usize) -> (u16, u8) {
    if prefix_len >= code.len() || crc_len == 0 {
        return (0, 0);
    }
    let end = (prefix_len + crc_len).min(code.len());
    let covered = end - prefix_len;
    let crc = crc16_flirt(&code[prefix_len..end]);
    (crc, u8::try_from(covered).unwrap_or(u8::MAX))
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_flirt::{FlirtName, TailByte};

    fn pat(name: &str, bytes: &[PatternByte]) -> FlirtPattern {
        let mut p = FlirtPattern::new(bytes.to_vec());
        p.names.push(FlirtName {
            name: name.to_string(),
            offset: 0,
            is_public: true,
            is_local: false,
        });
        p.pattern_length = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
        p
    }

    fn ex(bytes: &[u8]) -> Vec<PatternByte> {
        bytes.iter().map(|&b| PatternByte::Exact(b)).collect()
    }

    // ── candidate lookup ──────────────────────────────────────────────────

    #[test]
    fn test_candidates_exact_hit() {
        let pats = vec![pat("a", &ex(&[0x55, 0x8B, 0xEC]))];
        let idx = SignatureIndex::build(&pats);
        let c = idx.candidates(&[0x55, 0x8B, 0xEC, 0x00]);
        assert_eq!(c, vec![0]);
    }

    #[test]
    fn test_candidates_miss() {
        let pats = vec![pat("a", &ex(&[0xAA, 0xBB, 0xCC]))];
        let idx = SignatureIndex::build(&pats);
        assert!(idx.candidates(&[0x55, 0x8B, 0xEC]).is_empty());
    }

    #[test]
    fn test_candidates_multiple_shared_prefix() {
        let pats = vec![
            pat("a", &ex(&[0x55, 0x8B, 0xEC])),
            pat("b", &ex(&[0x55, 0x8B, 0xC0])),
            pat("c", &ex(&[0x55, 0x89, 0xE5])),
        ];
        let idx = SignatureIndex::build(&pats);
        let c = idx.candidates(&[0x55, 0x8B, 0xEC, 0x00]);
        assert!(c.contains(&0));
        assert!(!c.contains(&2)); // 0x89 branch not taken
    }

    #[test]
    fn test_candidates_wildcard_branch() {
        let mut b = ex(&[0x55]);
        b.push(PatternByte::Wildcard);
        b.push(PatternByte::Exact(0xEC));
        let pats = vec![pat("w", &b)];
        let idx = SignatureIndex::build(&pats);
        assert_eq!(idx.candidates(&[0x55, 0x00, 0xEC]), vec![0]);
        assert_eq!(idx.candidates(&[0x55, 0xFF, 0xEC]), vec![0]);
        assert!(idx.candidates(&[0x55, 0xFF, 0xED]).is_empty());
    }

    #[test]
    fn test_node_and_pattern_counts() {
        let pats = vec![pat("a", &ex(&[0x55, 0x8B])), pat("b", &ex(&[0x55, 0x89]))];
        let idx = SignatureIndex::build(&pats);
        assert_eq!(idx.pattern_count(), 2);
        // root + shared 0x55 + two leaves = 4
        assert_eq!(idx.node_count(), 4);
    }

    // ── unique query ──────────────────────────────────────────────────────

    #[test]
    fn test_query_unique() {
        let pats = vec![pat("memcpy", &ex(&[0x55, 0x8B, 0xEC, 0x83]))];
        let idx = SignatureIndex::build(&pats);
        let out = idx.query(&[0x55, 0x8B, 0xEC, 0x83, 0x90]);
        assert!(out.is_unique());
        assert_eq!(out.unique_ref().unwrap().name, "memcpy");
    }

    #[test]
    fn test_query_none() {
        let pats = vec![pat("x", &ex(&[0xAA, 0xBB, 0xCC, 0xDD]))];
        let idx = SignatureIndex::build(&pats);
        assert_eq!(idx.query(&[0x00, 0x00, 0x00, 0x00]), MatchOutcome::None);
    }

    #[test]
    fn test_query_prefers_longer_prefix() {
        let short = pat("short", &ex(&[0x55, 0x8B]));
        let long = pat("long", &ex(&[0x55, 0x8B, 0xEC, 0x83]));
        let pats = vec![short, long];
        let idx = SignatureIndex::build(&pats);
        let out = idx.query(&[0x55, 0x8B, 0xEC, 0x83]);
        assert_eq!(out.unique_ref().unwrap().name, "long");
    }

    // ── CRC disambiguation ──────────────────────────────────────────────────

    #[test]
    fn test_query_crc_disambiguates() {
        // Two patterns: same 2-byte prefix, both with a 2-byte CRC region but
        // different CRC values. Only one should survive against a given buffer.
        let body_a = [0x55u8, 0x8B, 0x11, 0x22];
        let body_b = [0x55u8, 0x8B, 0x33, 0x44];

        let mut pa = pat("fa", &ex(&[0x55, 0x8B]));
        let (crc_a, len_a) = crc16_over_tail(&body_a, 2, 2);
        pa.crc16 = crc_a;
        pa.crc_length = len_a;

        let mut pb = pat("fb", &ex(&[0x55, 0x8B]));
        let (crc_b, len_b) = crc16_over_tail(&body_b, 2, 2);
        pb.crc16 = crc_b;
        pb.crc_length = len_b;

        let pats = vec![pa, pb];
        let idx = SignatureIndex::build(&pats);

        let out_a = idx.query(&body_a);
        assert_eq!(out_a.unique_ref().unwrap().name, "fa");
        let out_b = idx.query(&body_b);
        assert_eq!(out_b.unique_ref().unwrap().name, "fb");
    }

    #[test]
    fn test_query_tail_disambiguates() {
        // Same prefix and no CRC, separated only by a tail byte.
        let mut pa = pat("ta", &ex(&[0x55, 0x8B]));
        pa.tail_bytes.push(TailByte {
            offset: 4,
            value: 0xAA,
        });
        let mut pb = pat("tb", &ex(&[0x55, 0x8B]));
        pb.tail_bytes.push(TailByte {
            offset: 4,
            value: 0xBB,
        });
        let pats = vec![pa, pb];
        let idx = SignatureIndex::build(&pats);

        let out = idx.query(&[0x55, 0x8B, 0x00, 0x00, 0xAA]);
        assert_eq!(out.unique_ref().unwrap().name, "ta");
    }

    // ── ambiguity ───────────────────────────────────────────────────────────

    #[test]
    fn test_query_ambiguous_collision() {
        // Identical prefix, no CRC, no tail → genuine collision of two names.
        let pats = vec![
            pat("alpha", &ex(&[0x55, 0x8B, 0xEC])),
            pat("beta", &ex(&[0x55, 0x8B, 0xEC])),
        ];
        let idx = SignatureIndex::build(&pats);
        let out = idx.query(&[0x55, 0x8B, 0xEC, 0x00]);
        assert!(out.is_ambiguous());
        if let MatchOutcome::Ambiguous(g) = out {
            assert_eq!(g.len(), 2);
            assert_eq!(g.names(), vec!["alpha".to_string(), "beta".to_string()]);
        }
    }

    #[test]
    fn test_query_same_name_collapsed_to_unique() {
        // Same function recorded twice → reported as unique, not ambiguous.
        let pats = vec![
            pat("dup", &ex(&[0x55, 0x8B, 0xEC])),
            pat("dup", &ex(&[0x55, 0x8B, 0xEC])),
        ];
        let idx = SignatureIndex::build(&pats);
        assert!(idx.query(&[0x55, 0x8B, 0xEC]).is_unique());
    }

    #[test]
    fn test_collision_groups_enumeration() {
        let pats = vec![
            pat("alpha", &ex(&[0x55, 0x8B, 0xEC])),
            pat("beta", &ex(&[0x55, 0x8B, 0xEC])),
            pat("solo", &ex(&[0x48, 0x89, 0xE5])),
        ];
        let idx = SignatureIndex::build(&pats);
        let groups = idx.collision_groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].names(),
            vec!["alpha".to_string(), "beta".to_string()]
        );
    }

    #[test]
    fn test_collision_groups_none_when_distinct() {
        let pats = vec![pat("a", &ex(&[0x55, 0x8B])), pat("b", &ex(&[0x48, 0x89]))];
        let idx = SignatureIndex::build(&pats);
        assert!(idx.collision_groups().is_empty());
    }

    #[test]
    fn test_ambiguity_group_is_empty_false_for_real_group() {
        let g = AmbiguityGroup {
            members: vec![
                PatternRef {
                    index: 0,
                    name: "a".into(),
                },
                PatternRef {
                    index: 1,
                    name: "b".into(),
                },
            ],
        };
        assert!(!g.is_empty());
        assert_eq!(g.len(), 2);
    }

    // ── crc16_over_tail ──────────────────────────────────────────────────────

    #[test]
    fn test_crc16_over_tail_basic() {
        let code = [0x00u8, 0x00, b'1', b'2', b'3'];
        // Region is code[2..5] = "123"
        let (crc, len) = crc16_over_tail(&code, 2, 3);
        assert_eq!(len, 3);
        assert_eq!(crc, crc16_flirt(b"123"));
    }

    #[test]
    fn test_crc16_over_tail_clamped() {
        let code = [0xAAu8, 0xBB, 0xCC];
        // Ask for 10 bytes from offset 2: only 1 available.
        let (_, len) = crc16_over_tail(&code, 2, 10);
        assert_eq!(len, 1);
    }

    #[test]
    fn test_crc16_over_tail_prefix_past_end() {
        let code = [0xAAu8, 0xBB];
        assert_eq!(crc16_over_tail(&code, 5, 4), (0, 0));
    }

    #[test]
    fn test_crc16_over_tail_zero_len() {
        let code = [0xAAu8, 0xBB, 0xCC];
        assert_eq!(crc16_over_tail(&code, 0, 0), (0, 0));
    }
}
