//! String similarity metrics and clustering.
//!
//! Provides:
//! * Edit distance (Levenshtein).
//! * Longest common subsequence (LCS).
//! * Jaro-Winkler similarity.
//! * Jaccard similarity on character n-grams.
//! * Simple centroid-based clustering.
//! * String template extraction from clusters.

// ─────────────────────────────────────────────────────────────────────────────
// Levenshtein distance
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum string length (in chars) accepted by the O(n·m) DP algorithms
/// before returning a sentinel, preventing dos-memory-exhaustion.
const DP_LENGTH_CAP: usize = 4096;

/// Compute the Levenshtein edit distance between two strings.
///
/// Uses the standard dynamic-programming O(n·m) algorithm.
/// Returns `usize::MAX` as a sentinel when either input exceeds
/// [`DP_LENGTH_CAP`] characters, preventing dos-memory-exhaustion on
/// attacker-supplied strings.
#[must_use]
pub fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let na = a.len();
    let nb = b.len();

    // Guard against O(n·m) allocation on untrusted long strings
    // (dos-memory-exhaustion).
    if na > DP_LENGTH_CAP || nb > DP_LENGTH_CAP {
        return usize::MAX;
    }

    if na == 0 {
        return nb;
    }
    if nb == 0 {
        return na;
    }

    let mut prev: Vec<usize> = (0..=nb).collect();
    let mut curr: Vec<usize> = vec![0; nb + 1];

    for i in 1..=na {
        curr[0] = i;
        for j in 1..=nb {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            curr[j] = (curr[j - 1] + 1).min(prev[j] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[nb]
}

/// Normalized similarity in [0, 1]: `1 - edit_dist / max(len_a, len_b)`.
#[must_use]
pub fn levenshtein_similarity(a: &str, b: &str) -> f64 {
    let d = levenshtein(a, b);
    // levenshtein returns usize::MAX as its over-cap sentinel; without this
    // guard the formula below would return a huge negative value, violating
    // the documented [0, 1] range.
    if d == usize::MAX {
        return 0.0;
    }
    let max_len = a.chars().count().max(b.chars().count());
    if max_len == 0 {
        return 1.0;
    }
    1.0 - f64::from(u32::try_from(d).unwrap_or(u32::MAX))
        / f64::from(u32::try_from(max_len).unwrap_or(u32::MAX))
}

// ─────────────────────────────────────────────────────────────────────────────
// Longest Common Subsequence
// ─────────────────────────────────────────────────────────────────────────────

/// Length of the longest common subsequence of `a` and `b`.
///
/// Returns 0 as a sentinel when either input exceeds [`DP_LENGTH_CAP`]
/// characters, preventing dos-memory-exhaustion.
#[must_use]
pub fn lcs_length(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let na = a.len();
    let nb = b.len();

    // Guard against O(n·m) allocation on untrusted long strings
    // (dos-memory-exhaustion).
    if na > DP_LENGTH_CAP || nb > DP_LENGTH_CAP {
        return 0;
    }

    let mut dp = vec![vec![0usize; nb + 1]; na + 1];
    for i in 1..=na {
        for j in 1..=nb {
            dp[i][j] = if a[i - 1] == b[j - 1] {
                dp[i - 1][j - 1] + 1
            } else {
                dp[i - 1][j].max(dp[i][j - 1])
            };
        }
    }
    dp[na][nb]
}

/// LCS-based similarity in [0, 1]: `lcs / max(len_a, len_b)`.
#[must_use]
pub fn lcs_similarity(a: &str, b: &str) -> f64 {
    let lcs = lcs_length(a, b);
    let max_len = a.chars().count().max(b.chars().count());
    if max_len == 0 {
        return 1.0;
    }
    f64::from(u32::try_from(lcs).unwrap_or(u32::MAX))
        / f64::from(u32::try_from(max_len).unwrap_or(u32::MAX))
}

// ─────────────────────────────────────────────────────────────────────────────
// Jaro-Winkler similarity
// ─────────────────────────────────────────────────────────────────────────────

/// Jaro similarity in [0, 1].
#[must_use]
pub fn jaro(a: &str, b: &str) -> f64 {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let na = a.len();
    let nb = b.len();
    if na == 0 && nb == 0 {
        return 1.0;
    }
    if na == 0 || nb == 0 {
        return 0.0;
    }

    let match_dist = (na.max(nb) / 2).saturating_sub(1);
    let mut a_matched = vec![false; na];
    let mut b_matched = vec![false; nb];
    let mut matches = 0usize;

    for ai in 0..na {
        let lo = ai.saturating_sub(match_dist);
        let hi = (ai + match_dist + 1).min(nb);
        for bj in lo..hi {
            if !b_matched[bj] && a[ai] == b[bj] {
                a_matched[ai] = true;
                b_matched[bj] = true;
                matches += 1;
                break;
            }
        }
    }

    if matches == 0 {
        return 0.0;
    }

    let mut transpositions = 0usize;
    let mut kk = 0usize;
    for ai in 0..na {
        if a_matched[ai] {
            while kk < nb && !b_matched[kk] {
                kk += 1;
            }
            if kk < nb {
                // Jaro: count matched-position pairs whose chars differ (transpositions).
                // `ai` indexes into `a`, `kk` indexes into the corresponding matched position in `b`.
                let a_ch = a[ai];
                let b_ch = b[kk];
                if a_ch.ne(&b_ch) {
                    transpositions += 1;
                }
            }
            kk += 1;
        }
    }

    let m = f64::from(u32::try_from(matches).unwrap_or(u32::MAX));
    let len_a = f64::from(u32::try_from(na).unwrap_or(u32::MAX));
    let len_b = f64::from(u32::try_from(nb).unwrap_or(u32::MAX));
    let t = f64::from(u32::try_from(transpositions).unwrap_or(u32::MAX));
    (m / len_a + m / len_b + (m - t / 2.0) / m) / 3.0
}

/// Jaro-Winkler similarity, using prefix boost factor `p = 0.1`.
#[must_use]
pub fn jaro_winkler(a: &str, b: &str) -> f64 {
    let j = jaro(a, b);
    let av: Vec<char> = a.chars().collect();
    let bv: Vec<char> = b.chars().collect();
    let prefix = av
        .iter()
        .zip(bv.iter())
        .take(4)
        .take_while(|(x, y)| x == y)
        .count();
    (f64::from(u32::try_from(prefix).unwrap_or(u32::MAX)) * 0.1).mul_add(1.0 - j, j)
}

// ─────────────────────────────────────────────────────────────────────────────
// Jaccard on character n-grams
// ─────────────────────────────────────────────────────────────────────────────

/// Character n-gram multiset of a string.
#[must_use]
pub fn ngrams(s: &str, n: usize) -> std::collections::HashSet<String> {
    if n == 0 || s.chars().count() < n {
        return std::collections::HashSet::new();
    }
    let chars: Vec<char> = s.chars().collect();
    (0..=(chars.len() - n))
        .map(|i| chars[i..i + n].iter().collect())
        .collect()
}

/// Jaccard similarity on character n-grams.
#[must_use]
pub fn jaccard_ngram(a: &str, b: &str, n: usize) -> f64 {
    let ga = ngrams(a, n);
    let gb = ngrams(b, n);
    if ga.is_empty() && gb.is_empty() {
        return 1.0;
    }
    if ga.is_empty() || gb.is_empty() {
        return 0.0;
    }
    let intersection = ga.intersection(&gb).count();
    let union = ga.union(&gb).count();
    if union == 0 {
        return 1.0;
    }
    f64::from(u32::try_from(intersection).unwrap_or(u32::MAX))
        / f64::from(u32::try_from(union).unwrap_or(u32::MAX))
}

// ─────────────────────────────────────────────────────────────────────────────
// Clustering
// ─────────────────────────────────────────────────────────────────────────────

/// A cluster of similar strings.
#[derive(Debug, Clone)]
pub struct StringCluster {
    /// The representative (centroid) string.
    pub representative: String,
    /// All strings in the cluster.
    pub members: Vec<String>,
}

impl StringCluster {
    /// Average pairwise Levenshtein similarity within the cluster.
    #[must_use]
    pub fn cohesion(&self) -> f64 {
        let n = self.members.len();
        if n < 2 {
            return 1.0;
        }
        let mut total = 0.0;
        let mut count = 0;
        for i in 0..n {
            for j in (i + 1)..n {
                total += levenshtein_similarity(&self.members[i], &self.members[j]);
                count += 1;
            }
        }
        if count == 0 {
            1.0
        } else {
            total / f64::from(count)
        }
    }
}

/// Simple greedy centroid clustering by Levenshtein similarity.
///
/// Strings with similarity >= `threshold` to a cluster's *representative*
/// (its first string) are merged into that cluster; other members are not
/// consulted.  New clusters are created for unmatched strings.
///
/// `threshold` should be in `[0.0, 1.0]`.
#[must_use]
pub fn cluster_strings(strings: &[&str], threshold: f64) -> Vec<StringCluster> {
    let mut clusters: Vec<StringCluster> = Vec::new();
    'outer: for &s in strings {
        for cluster in &mut clusters {
            let sim = levenshtein_similarity(&cluster.representative, s);
            if sim >= threshold {
                cluster.members.push(s.to_owned());
                continue 'outer;
            }
        }
        clusters.push(StringCluster {
            representative: s.to_owned(),
            members: vec![s.to_owned()],
        });
    }
    clusters
}

// ─────────────────────────────────────────────────────────────────────────────
// Template extraction
// ─────────────────────────────────────────────────────────────────────────────

/// Extract a common "template" from a cluster of similar strings by replacing
/// differing character positions with `'?'`.
///
/// Only produces a meaningful template when all strings have equal length.
#[must_use]
pub fn extract_template(strings: &[&str]) -> String {
    if strings.is_empty() {
        return String::new();
    }
    let first: Vec<char> = strings[0].chars().collect();
    let len = first.len();
    // Only meaningful for equal-length strings.
    if strings.iter().any(|s| s.chars().count() != len) {
        return strings[0].to_owned();
    }
    let mut template = first;
    for s in &strings[1..] {
        for (t, c) in template.iter_mut().zip(s.chars()) {
            if *t != c {
                *t = '?';
            }
        }
    }
    template.iter().collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_levenshtein_equal() {
        assert_eq!(levenshtein("abc", "abc"), 0);
    }

    #[test]
    fn test_levenshtein_empty_strings() {
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("abc", ""), 3);
        assert_eq!(levenshtein("", ""), 0);
    }

    #[test]
    fn test_levenshtein_substitution() {
        assert_eq!(levenshtein("kitten", "sitting"), 3);
    }

    #[test]
    fn test_levenshtein_insert_delete() {
        assert_eq!(levenshtein("abc", "ac"), 1);
        assert_eq!(levenshtein("ac", "abc"), 1);
    }

    #[test]
    fn test_levenshtein_similarity_range() {
        let sim = levenshtein_similarity("hello", "hello");
        assert!((sim - 1.0).abs() < 1e-9);
        let sim2 = levenshtein_similarity("hello", "world");
        assert!((0.0..=1.0).contains(&sim2));
    }

    #[test]
    fn regress_levenshtein_similarity_over_cap_stays_in_range() {
        // Inputs beyond DP_LENGTH_CAP hit the usize::MAX sentinel; the
        // similarity must stay in [0, 1] instead of going hugely negative.
        let long_a = "a".repeat(5000);
        let long_b = "b".repeat(5000);
        let sim = levenshtein_similarity(&long_a, &long_b);
        assert!((0.0..=1.0).contains(&sim), "sim was {}", sim);
    }

    #[test]
    fn test_lcs_length_basic() {
        assert_eq!(lcs_length("ABCBDAB", "BDCAB"), 4);
        assert_eq!(lcs_length("abc", "abc"), 3);
        assert_eq!(lcs_length("abc", "xyz"), 0);
    }

    #[test]
    fn test_lcs_similarity_range() {
        let s = lcs_similarity("abcde", "ace");
        assert!((0.0..=1.0).contains(&s));
    }

    #[test]
    fn test_jaro_equal() {
        assert!((jaro("abc", "abc") - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_jaro_empty() {
        assert!((jaro("", "") - 1.0).abs() < 1e-9);
        assert!((jaro("abc", "") - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_jaro_known() {
        // Known value: jaro("MARTHA", "MARHTA") ≈ 0.9444
        let j = jaro("MARTHA", "MARHTA");
        assert!(j > 0.9);
    }

    #[test]
    fn test_jaro_winkler_prefix_boost() {
        let jw = jaro_winkler("MARTHA", "MARHTA");
        let j = jaro("MARTHA", "MARHTA");
        assert!(jw >= j); // Winkler adds prefix boost
    }

    #[test]
    fn test_ngrams_basic() {
        let grams = ngrams("hello", 2);
        assert!(grams.contains("he"));
        assert!(grams.contains("el"));
        assert!(grams.contains("ll"));
        assert!(grams.contains("lo"));
    }

    #[test]
    fn test_ngrams_empty_when_too_short() {
        assert!(ngrams("ab", 3).is_empty());
        assert!(ngrams("", 1).is_empty());
    }

    #[test]
    fn test_jaccard_ngram_identical() {
        let sim = jaccard_ngram("hello", "hello", 2);
        assert!((sim - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_jaccard_ngram_disjoint() {
        let sim = jaccard_ngram("hello", "world", 3);
        assert!(sim < 0.5);
    }

    #[test]
    fn test_cluster_strings_identical() {
        let strs = vec!["hello", "hello", "hello"];
        let clusters = cluster_strings(&strs, 0.8);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].members.len(), 3);
    }

    #[test]
    fn test_cluster_strings_different() {
        let strs = vec!["alpha", "beta", "gamma", "delta"];
        let clusters = cluster_strings(&strs, 0.9);
        // All distinct, should each be their own cluster at high threshold
        assert!(clusters.len() >= 2);
    }

    #[test]
    fn test_cluster_cohesion() {
        let cluster = StringCluster {
            representative: "hello".to_owned(),
            members: vec!["hello".to_owned(), "hello".to_owned()],
        };
        assert!((cluster.cohesion() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_extract_template_identical() {
        let t = extract_template(&["hello", "hello", "hello"]);
        assert_eq!(t, "hello");
    }

    #[test]
    fn test_extract_template_differing() {
        let t = extract_template(&["abc", "axc", "azc"]);
        // Position 1 differs: should be '?'
        assert_eq!(t, "a?c");
    }

    #[test]
    fn test_extract_template_empty() {
        assert_eq!(extract_template(&[]), "");
    }

    #[test]
    fn test_extract_template_single() {
        assert_eq!(extract_template(&["hello"]), "hello");
    }
}
