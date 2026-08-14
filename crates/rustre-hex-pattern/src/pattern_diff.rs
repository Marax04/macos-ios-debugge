//! Pattern diff — compare two hex patterns, find common prefix/suffix,
//! divergence point, and compute a similarity score.

use serde::{Deserialize, Serialize};

use crate::{Pattern, PatternByte};

// ─────────────────────────────────────────────────────────────────────────────
// SimilarityScore
// ─────────────────────────────────────────────────────────────────────────────

/// A composite similarity score between two patterns.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SimilarityScore {
    /// Jaccard similarity over the exact-byte multisets: |A ∩ B| / |A ∪ B|.
    pub jaccard: f64,
    /// Longest Common Subsequence length (normalised by max pattern length).
    pub lcs_norm: f64,
    /// Length of common prefix divided by shorter pattern length.
    pub prefix_ratio: f64,
    /// Length of common suffix divided by shorter pattern length.
    pub suffix_ratio: f64,
    /// Combined score: weighted average of the above.
    pub combined: f64,
}

impl SimilarityScore {
    /// Compute the combined score from individual components.
    fn compute_combined(jaccard: f64, lcs_norm: f64, prefix_ratio: f64, suffix_ratio: f64) -> f64 {
        0.35 * jaccard + 0.35 * lcs_norm + 0.15 * prefix_ratio + 0.15 * suffix_ratio
    }

    /// Returns `true` if the patterns are considered "very similar" (combined ≥ 0.8).
    #[must_use]
    pub fn is_highly_similar(&self) -> bool {
        self.combined >= 0.8
    }

    /// Returns `true` if the patterns are considered "identical" (combined ≥ 0.999).
    #[must_use]
    pub fn is_identical(&self) -> bool {
        self.combined >= 0.999
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffEdit
// ─────────────────────────────────────────────────────────────────────────────

/// A single edit operation in the diff between two patterns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffEdit {
    /// Both patterns have the same byte at this position.
    Equal { offset: usize, byte: PatternByte },
    /// Pattern A has a byte that B does not (deletion from A's perspective).
    Delete { offset_a: usize, byte: PatternByte },
    /// Pattern B has a byte that A does not (insertion from A's perspective).
    Insert { offset_b: usize, byte: PatternByte },
    /// Both patterns have a byte at this position but they differ.
    Replace {
        offset_a: usize,
        offset_b: usize,
        old_byte: PatternByte,
        new_byte: PatternByte,
    },
}

impl DiffEdit {
    /// Returns `true` if this edit represents no change.
    #[must_use]
    pub const fn is_equal(&self) -> bool {
        matches!(self, Self::Equal { .. })
    }

    /// Returns `true` if this edit is a modification.
    #[must_use]
    pub const fn is_change(&self) -> bool {
        !self.is_equal()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffResult
// ─────────────────────────────────────────────────────────────────────────────

/// The result of diffing two patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    /// Name of pattern A.
    pub name_a: Option<String>,
    /// Name of pattern B.
    pub name_b: Option<String>,
    /// Length of the common prefix (in pattern slots).
    pub common_prefix_len: usize,
    /// Length of the common suffix (in pattern slots).
    pub common_suffix_len: usize,
    /// Byte offset within both patterns where divergence first occurs.
    pub divergence_point: usize,
    /// Length of the longest common subsequence.
    pub lcs_length: usize,
    /// Full edit script.
    pub edits: Vec<DiffEdit>,
    /// Similarity scores.
    pub similarity: SimilarityScore,
    /// Byte-by-byte agreement vector: `true` where patterns agree.
    pub agreement: Vec<bool>,
}

impl DiffResult {
    /// Returns `true` if the two patterns are identical (byte-by-byte).
    #[must_use]
    pub fn is_identical(&self) -> bool {
        self.similarity.is_identical()
    }

    /// Number of positions where the patterns disagree.
    #[must_use]
    pub fn disagreement_count(&self) -> usize {
        self.agreement.iter().filter(|&&a| !a).count()
    }

    /// Return only the edit operations that represent changes.
    #[must_use]
    pub fn changed_edits(&self) -> Vec<&DiffEdit> {
        self.edits.iter().filter(|e| e.is_change()).collect()
    }

    /// Number of changed positions.
    #[must_use]
    pub fn change_count(&self) -> usize {
        self.edits.iter().filter(|e| e.is_change()).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternDiff
// ─────────────────────────────────────────────────────────────────────────────

/// Utility for diffing and comparing hex patterns.
///
/// Usage:
/// ```
/// # use rustre_hex_pattern::{Pattern, pattern_diff::PatternDiff};
/// let a = Pattern::parse("DE AD BE EF").unwrap();
/// let b = Pattern::parse("DE AD ?? EF").unwrap();
/// let result = PatternDiff::diff(&a, &b);
/// assert_eq!(result.common_prefix_len, 2);
/// assert_eq!(result.divergence_point, 2);
/// ```
pub struct PatternDiff;

impl PatternDiff {
    /// Compute the diff between patterns `a` and `b`.
    #[must_use]
    pub fn diff(a: &Pattern, b: &Pattern) -> DiffResult {
        let common_prefix_len = Self::common_prefix(a, b);
        let common_suffix_len = Self::common_suffix(a, b, common_prefix_len);
        let lcs_length = Self::lcs_length(&a.bytes, &b.bytes);
        let edits = Self::compute_edits(&a.bytes, &b.bytes);
        let agreement = Self::build_agreement(&a.bytes, &b.bytes);
        let similarity = Self::compute_similarity(a, b, common_prefix_len, common_suffix_len, lcs_length);

        DiffResult {
            name_a: a.name.clone(),
            name_b: b.name.clone(),
            common_prefix_len,
            common_suffix_len,
            divergence_point: common_prefix_len,
            lcs_length,
            edits,
            similarity,
            agreement,
        }
    }

    /// Compute the similarity score between two patterns.
    #[must_use]
    pub fn similarity(a: &Pattern, b: &Pattern) -> SimilarityScore {
        let prefix = Self::common_prefix(a, b);
        let suffix = Self::common_suffix(a, b, prefix);
        let lcs = Self::lcs_length(&a.bytes, &b.bytes);
        Self::compute_similarity(a, b, prefix, suffix, lcs)
    }

    /// Check whether two patterns are structurally equivalent (ignoring names/tags).
    #[must_use]
    pub fn are_equivalent(a: &Pattern, b: &Pattern) -> bool {
        if a.bytes.len() != b.bytes.len() {
            return false;
        }
        a.bytes
            .iter()
            .zip(b.bytes.iter())
            .all(|(x, y)| Self::bytes_equal(x, y))
    }

    /// Find the largest common sub-pattern (contiguous) between a and b.
    ///
    /// Returns `(offset_in_a, offset_in_b, length)`.
    #[must_use]
    pub fn largest_common_sub(a: &Pattern, b: &Pattern) -> Option<(usize, usize, usize)> {
        let la = a.bytes.len();
        let lb = b.bytes.len();
        if la == 0 || lb == 0 {
            return None;
        }
        // Dynamic programming for longest common substring.
        // `dp[i][j]` = length of longest common substring ending at a[i-1], b[j-1].
        let mut dp = vec![vec![0usize; lb + 1]; la + 1];
        let mut best_len = 0;
        let mut best_ia = 0;
        let mut best_ib = 0;

        for i in 1..=la {
            for j in 1..=lb {
                if Self::bytes_match(&a.bytes[i - 1], &b.bytes[j - 1]) {
                    dp[i][j] = dp[i - 1][j - 1] + 1;
                    if dp[i][j] > best_len {
                        best_len = dp[i][j];
                        best_ia = i - best_len;
                        best_ib = j - best_len;
                    }
                }
            }
        }

        if best_len == 0 {
            None
        } else {
            Some((best_ia, best_ib, best_len))
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Two `PatternByte` slots "match" for diffing purposes if one is a wildcard
    /// or both represent the same exact value.
    fn bytes_match(a: &PatternByte, b: &PatternByte) -> bool {
        match (a, b) {
            (PatternByte::Wildcard, _) | (_, PatternByte::Wildcard) => true,
            (PatternByte::Exact(x), PatternByte::Exact(y)) => x == y,
            (PatternByte::Nibble { high: h1, low: l1 }, PatternByte::Nibble { high: h2, low: l2 }) => {
                h1 == h2 && l1 == l2
            }
            (PatternByte::Exact(x), PatternByte::Nibble { high, low }) => {
                let h = high.map_or(true, |h| (*x >> 4) == h);
                let l = low.map_or(true, |l| (*x & 0x0F) == l);
                h && l
            }
            (PatternByte::Nibble { high, low }, PatternByte::Exact(x)) => {
                let h = high.map_or(true, |h| (*x >> 4) == h);
                let l = low.map_or(true, |l| (*x & 0x0F) == l);
                h && l
            }
        }
    }

    /// Strict equality: two slots are literally identical.
    fn bytes_equal(a: &PatternByte, b: &PatternByte) -> bool {
        a == b
    }

    fn common_prefix(a: &Pattern, b: &Pattern) -> usize {
        a.bytes
            .iter()
            .zip(b.bytes.iter())
            .take_while(|(x, y)| Self::bytes_equal(x, y))
            .count()
    }

    fn common_suffix(a: &Pattern, b: &Pattern, skip_prefix: usize) -> usize {
        let la = a.bytes.len().saturating_sub(skip_prefix);
        let lb = b.bytes.len().saturating_sub(skip_prefix);
        let limit = la.min(lb);
        a.bytes[a.bytes.len().saturating_sub(la)..]
            .iter()
            .rev()
            .zip(b.bytes[b.bytes.len().saturating_sub(lb)..].iter().rev())
            .take(limit)
            .take_while(|(x, y)| Self::bytes_equal(x, y))
            .count()
    }

    /// Classic LCS length via dynamic programming.
    fn lcs_length(a: &[PatternByte], b: &[PatternByte]) -> usize {
        let la = a.len();
        let lb = b.len();
        if la == 0 || lb == 0 {
            return 0;
        }
        // Use two-row rolling DP to save memory.
        let mut prev = vec![0usize; lb + 1];
        let mut curr = vec![0usize; lb + 1];
        for i in 1..=la {
            for j in 1..=lb {
                curr[j] = if Self::bytes_equal(&a[i - 1], &b[j - 1]) {
                    prev[j - 1] + 1
                } else {
                    curr[j - 1].max(prev[j])
                };
            }
            std::mem::swap(&mut prev, &mut curr);
            curr.fill(0);
        }
        prev[lb]
    }

    /// Build an edit script using Myers diff on the pattern slots.
    fn compute_edits(a: &[PatternByte], b: &[PatternByte]) -> Vec<DiffEdit> {
        // Simple O(mn) LCS-based diff.
        let la = a.len();
        let lb = b.len();

        // Build LCS table.
        let mut dp = vec![vec![0usize; lb + 1]; la + 1];
        for i in (0..la).rev() {
            for j in (0..lb).rev() {
                dp[i][j] = if Self::bytes_equal(&a[i], &b[j]) {
                    dp[i + 1][j + 1] + 1
                } else {
                    dp[i + 1][j].max(dp[i][j + 1])
                };
            }
        }

        // Trace back.
        let mut edits = Vec::new();
        let mut i = 0;
        let mut j = 0;
        while i < la && j < lb {
            if Self::bytes_equal(&a[i], &b[j]) {
                edits.push(DiffEdit::Equal {
                    offset: i,
                    byte: a[i].clone(),
                });
                i += 1;
                j += 1;
            } else if dp[i + 1][j] >= dp[i][j + 1] {
                edits.push(DiffEdit::Delete {
                    offset_a: i,
                    byte: a[i].clone(),
                });
                i += 1;
            } else {
                edits.push(DiffEdit::Insert {
                    offset_b: j,
                    byte: b[j].clone(),
                });
                j += 1;
            }
        }
        while i < la {
            edits.push(DiffEdit::Delete {
                offset_a: i,
                byte: a[i].clone(),
            });
            i += 1;
        }
        while j < lb {
            edits.push(DiffEdit::Insert {
                offset_b: j,
                byte: b[j].clone(),
            });
            j += 1;
        }
        edits
    }

    /// Build a per-position agreement vector (max length).
    fn build_agreement(a: &[PatternByte], b: &[PatternByte]) -> Vec<bool> {
        let len = a.len().max(b.len());
        (0..len)
            .map(|i| match (a.get(i), b.get(i)) {
                (Some(x), Some(y)) => Self::bytes_equal(x, y),
                _ => false,
            })
            .collect()
    }

    fn compute_similarity(
        a: &Pattern,
        b: &Pattern,
        prefix: usize,
        suffix: usize,
        lcs: usize,
    ) -> SimilarityScore {
        let la = a.bytes.len();
        let lb = b.bytes.len();
        // If the prefix already covers the entire pair (fully identical sequences),
        // the suffix calculation skips them — bump suffix to the full length so
        // identical patterns score 1.0 rather than 0.85.
        let suffix = if la == lb && prefix == la { la } else { suffix };
        let shorter = la.min(lb) as f64;
        let longer = la.max(lb) as f64;

        // Jaccard over exact-byte multisets.
        let mut set_a: std::collections::HashMap<u8, usize> = std::collections::HashMap::new();
        let mut set_b: std::collections::HashMap<u8, usize> = std::collections::HashMap::new();
        for pb in &a.bytes {
            if let PatternByte::Exact(v) = pb {
                *set_a.entry(*v).or_insert(0) += 1;
            }
        }
        for pb in &b.bytes {
            if let PatternByte::Exact(v) = pb {
                *set_b.entry(*v).or_insert(0) += 1;
            }
        }
        let mut intersection = 0usize;
        let mut union = 0usize;
        let mut all_keys: std::collections::HashSet<u8> = std::collections::HashSet::new();
        all_keys.extend(set_a.keys().copied());
        all_keys.extend(set_b.keys().copied());
        for k in &all_keys {
            let ca = set_a.get(k).copied().unwrap_or(0);
            let cb = set_b.get(k).copied().unwrap_or(0);
            intersection += ca.min(cb);
            union += ca.max(cb);
        }
        let jaccard = if union == 0 {
            1.0
        } else {
            intersection as f64 / union as f64
        };

        let lcs_norm = if longer == 0.0 {
            1.0
        } else {
            lcs as f64 / longer
        };
        let prefix_ratio = if shorter == 0.0 {
            1.0
        } else {
            prefix as f64 / shorter
        };
        let suffix_ratio = if shorter == 0.0 {
            1.0
        } else {
            suffix as f64 / shorter
        };
        let combined =
            SimilarityScore::compute_combined(jaccard, lcs_norm, prefix_ratio, suffix_ratio);

        SimilarityScore {
            jaccard,
            lcs_norm,
            prefix_ratio,
            suffix_ratio,
            combined,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn pat(s: &str) -> Pattern {
        Pattern::parse(s).unwrap()
    }

    #[test]
    fn test_identical_patterns() {
        let a = pat("DE AD BE EF");
        let b = pat("DE AD BE EF");
        let result = PatternDiff::diff(&a, &b);
        assert_eq!(result.common_prefix_len, 4);
        assert_eq!(result.divergence_point, 4);
        assert!(result.is_identical());
        assert_eq!(result.change_count(), 0);
    }

    #[test]
    fn test_single_byte_difference() {
        let a = pat("DE AD BE EF");
        let b = pat("DE AD ?? EF");
        let result = PatternDiff::diff(&a, &b);
        assert_eq!(result.common_prefix_len, 2);
        assert_eq!(result.divergence_point, 2);
        assert!(!result.is_identical());
    }

    #[test]
    fn test_completely_different() {
        let a = pat("AA BB CC");
        let b = pat("11 22 33");
        let result = PatternDiff::diff(&a, &b);
        assert_eq!(result.common_prefix_len, 0);
        assert!(result.change_count() > 0);
    }

    #[test]
    fn test_common_suffix() {
        let a = pat("AA BB CC EE");
        let b = pat("FF BB CC EE");
        let result = PatternDiff::diff(&a, &b);
        assert_eq!(result.common_suffix_len, 3);
        assert_eq!(result.common_prefix_len, 0);
    }

    #[test]
    fn test_are_equivalent_same() {
        let a = pat("DE AD BE EF");
        let b = pat("DE AD BE EF");
        assert!(PatternDiff::are_equivalent(&a, &b));
    }

    #[test]
    fn test_are_equivalent_different() {
        let a = pat("DE AD BE EF");
        let b = pat("DE AD ?? EF");
        assert!(!PatternDiff::are_equivalent(&a, &b));
    }

    #[test]
    fn test_are_equivalent_different_length() {
        let a = pat("DE AD BE");
        let b = pat("DE AD BE EF");
        assert!(!PatternDiff::are_equivalent(&a, &b));
    }

    #[test]
    fn test_similarity_identical() {
        let a = pat("DE AD BE EF");
        let score = PatternDiff::similarity(&a, &a);
        assert!(score.combined >= 0.99);
        assert!(score.is_identical());
    }

    #[test]
    fn test_similarity_partial() {
        let a = pat("DE AD BE EF 00 11");
        let b = pat("DE AD BE EF FF FF");
        let score = PatternDiff::similarity(&a, &b);
        assert!(score.combined > 0.5 && score.combined < 1.0);
    }

    #[test]
    fn test_lcs_length() {
        let a = pat("AA BB CC DD");
        let b = pat("AA ?? CC ??");
        let lcs = PatternDiff::diff(&a, &b).lcs_length;
        // "AA" and "CC" are equal (exact); "BB" vs "??" is not equal strictly.
        assert!(lcs >= 2);
    }

    #[test]
    fn test_largest_common_sub() {
        let a = pat("AA BB CC DD EE");
        let b = pat("FF BB CC DD 11");
        let result = PatternDiff::largest_common_sub(&a, &b);
        assert!(result.is_some());
        let (ia, ib, len) = result.unwrap();
        assert_eq!(len, 3); // BB CC DD
        assert_eq!(ia, 1);
        assert_eq!(ib, 1);
    }

    #[test]
    fn test_largest_common_sub_none() {
        let a = pat("AA BB");
        let b = pat("CC DD");
        assert!(PatternDiff::largest_common_sub(&a, &b).is_none());
    }

    #[test]
    fn test_diff_agreement_vector() {
        let a = pat("DE AD BE EF");
        let b = pat("DE AD FF EF");
        let result = PatternDiff::diff(&a, &b);
        assert!(result.agreement[0]);
        assert!(result.agreement[1]);
        assert!(!result.agreement[2]);
        assert!(result.agreement[3]);
    }

    #[test]
    fn test_disagreement_count() {
        let a = pat("AA BB CC DD");
        let b = pat("AA FF CC FF");
        let result = PatternDiff::diff(&a, &b);
        assert_eq!(result.disagreement_count(), 2);
    }

    #[test]
    fn test_edits_only_equal_for_identical() {
        let a = pat("DE AD");
        let b = pat("DE AD");
        let result = PatternDiff::diff(&a, &b);
        assert!(result.edits.iter().all(|e| e.is_equal()));
    }

    #[test]
    fn test_similarity_score_highly_similar() {
        let s = SimilarityScore {
            jaccard: 0.9,
            lcs_norm: 0.9,
            prefix_ratio: 0.9,
            suffix_ratio: 0.9,
            combined: 0.9,
        };
        assert!(s.is_highly_similar());
        assert!(!s.is_identical());
    }

    #[test]
    fn test_diff_different_lengths() {
        let a = pat("AA BB CC");
        let b = pat("AA BB CC DD EE");
        let result = PatternDiff::diff(&a, &b);
        // Common prefix is 3 (all of a), remainder are insertions.
        assert_eq!(result.common_prefix_len, 3);
        assert!(result.change_count() > 0);
    }
}
