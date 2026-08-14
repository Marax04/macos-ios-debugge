//! String clustering and deduplication.
//!
//! Provides multiple clustering algorithms (edit distance, fingerprint, TF-IDF,
//! n-gram) and a report structure summarising the result.

use ahash::{AHashMap, AHashSet};
use std::collections::HashMap;
use std::fmt;

// ─── StringRef ───────────────────────────────────────────────────────────────

/// A reference to a string together with its origin offset.
#[derive(Debug, Clone, PartialEq)]
pub struct StringRef {
    /// Byte offset of the string in the binary.
    pub offset: u64,
    /// The decoded string value.
    pub value: String,
}

impl StringRef {
    pub fn new(offset: u64, value: impl Into<String>) -> Self {
        Self { offset, value: value.into() }
    }
}

// ─── StringCluster ───────────────────────────────────────────────────────────

/// A group of similar strings with a representative centroid.
#[derive(Debug, Clone)]
pub struct StringCluster {
    pub cluster_id: u32,
    /// The string that best represents this cluster (closest to mean).
    pub centroid: String,
    pub members: Vec<StringRef>,
    /// Pairwise similarity of each member to the centroid; same order as `members`.
    pub similarity_scores: Vec<f64>,
}

impl StringCluster {
    pub fn average_similarity(&self) -> f64 {
        if self.similarity_scores.is_empty() { return 0.0; }
        self.similarity_scores.iter().sum::<f64>() / self.similarity_scores.len() as f64
    }
}

// ─── ClusterAlgorithm ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterAlgorithm {
    /// Group by normalised Levenshtein distance threshold.
    EditDistance,
    /// Group by sorted-word fingerprint.
    Fingerprint,
    /// Group using cosine similarity on TF-IDF trigram vectors.
    TfIdf,
    /// Group by Jaccard similarity of character n-gram sets.
    Ngram,
}

// ─── ClusterReport ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ClusterReport {
    pub clusters: Vec<StringCluster>,
    /// Strings that did not fit into any cluster.
    pub noise: Vec<StringRef>,
    pub total_strings: usize,
    pub total_clusters: usize,
    pub avg_cluster_size: f64,
}

impl ClusterReport {
    pub fn build(clusters: Vec<StringCluster>, noise: Vec<StringRef>, total_strings: usize) -> Self {
        let total_clusters = clusters.len();
        let avg_cluster_size = if total_clusters == 0 {
            0.0
        } else {
            clusters.iter().map(|c| c.members.len() as f64).sum::<f64>() / total_clusters as f64
        };
        Self { clusters, noise, total_strings, total_clusters, avg_cluster_size }
    }
}

impl fmt::Display for ClusterReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClusterReport({} clusters, {} noise, {:.1} avg size)",
            self.total_clusters, self.noise.len(), self.avg_cluster_size)
    }
}

// ─── StringClusterer ─────────────────────────────────────────────────────────

pub struct StringClusterer {
    algorithm: ClusterAlgorithm,
    /// Minimum similarity (0–1) for two strings to be placed in the same cluster.
    similarity_threshold: f64,
    /// n for n-gram similarity (default 3 = trigrams).
    ngram_n: usize,
    /// Maximum k for k-means (used only with TfIdf algorithm).
    max_k: usize,
}

impl StringClusterer {
    pub fn new(algorithm: ClusterAlgorithm, similarity_threshold: f64) -> Self {
        Self { algorithm, similarity_threshold, ngram_n: 3, max_k: 16 }
    }

    pub fn with_ngram_n(mut self, n: usize) -> Self { self.ngram_n = n; self }
    pub fn with_max_k(mut self, k: usize) -> Self { self.max_k = k; self }

    pub fn cluster(&self, strings: Vec<StringRef>) -> ClusterReport {
        match &self.algorithm {
            ClusterAlgorithm::EditDistance => self.cluster_edit_distance(strings),
            ClusterAlgorithm::Fingerprint => self.cluster_fingerprint(strings),
            ClusterAlgorithm::TfIdf => self.cluster_tfidf(strings),
            ClusterAlgorithm::Ngram => self.cluster_ngram(strings),
        }
    }

    // ── Edit-distance clustering (greedy, O(n²)) ────────────────────────────

    fn cluster_edit_distance(&self, strings: Vec<StringRef>) -> ClusterReport {
        let n = strings.len();
        let mut assigned = vec![false; n];
        let mut clusters: Vec<StringCluster> = Vec::new();
        let mut cluster_id = 0u32;

        for i in 0..n {
            if assigned[i] { continue; }
            assigned[i] = true;
            let mut members = vec![strings[i].clone()];

            for j in (i + 1)..n {
                if assigned[j] { continue; }
                let sim = normalized_edit_similarity(&strings[i].value, &strings[j].value);
                if sim >= self.similarity_threshold {
                    assigned[j] = true;
                    members.push(strings[j].clone());
                }
            }

            let centroid = choose_centroid(&members);
            // Score against the CENTROID, after it has been chosen.
            //
            // The scores used to be accumulated against the greedy SEED
            // (`strings[i]`) while gathering members, and only then was a
            // centroid picked — often a different member. `similarity_scores`
            // is documented as the similarity to the centroid, so every value
            // referred to the wrong string and `average_similarity()` was
            // computed from those. `cluster_fingerprint` below already scores
            // after choosing the centroid.
            let scores: Vec<f64> = members
                .iter()
                .map(|m| normalized_edit_similarity(&m.value, &centroid))
                .collect();
            clusters.push(StringCluster { cluster_id, centroid, members, similarity_scores: scores });
            cluster_id += 1;
        }

        let noise = Vec::new(); // greedy assigns everything
        ClusterReport::build(clusters, noise, n)
    }

    // ── Fingerprint clustering ───────────────────────────────────────────────

    fn cluster_fingerprint(&self, strings: Vec<StringRef>) -> ClusterReport {
        // Keyed by attacker-controlled fingerprint strings — use AHashMap to
        // prevent hash-collision DoS (dos-hash-collision).
        let mut buckets: AHashMap<String, Vec<StringRef>> = AHashMap::new();
        for s in strings.iter() {
            let fp = compute_fingerprint(&s.value);
            buckets.entry(fp).or_default().push(s.clone());
        }
        let total = strings.len();
        let mut clusters: Vec<StringCluster> = Vec::new();
        let mut noise: Vec<StringRef> = Vec::new();
        let mut cluster_id = 0u32;

        // AHashMap iteration order is nondeterministic; sort by fingerprint so
        // cluster_id assignment, cluster order, and noise order are stable.
        let mut buckets: Vec<(String, Vec<StringRef>)> = buckets.into_iter().collect();
        buckets.sort_by(|a, b| a.0.cmp(&b.0));
        for (_fp, members) in buckets {
            if members.len() < 2 {
                noise.extend(members);
                continue;
            }
            let centroid = choose_centroid(&members);
            // Compute similarity of each member to centroid via trigrams
            let scores: Vec<f64> = members.iter().map(|m| trigram_similarity(&m.value, &centroid)).collect();
            clusters.push(StringCluster { cluster_id, centroid, members, similarity_scores: scores });
            cluster_id += 1;
        }

        ClusterReport::build(clusters, noise, total)
    }

    // ── N-gram (Jaccard) clustering ──────────────────────────────────────────

    fn cluster_ngram(&self, strings: Vec<StringRef>) -> ClusterReport {
        let n = strings.len();
        let mut assigned = vec![false; n];
        let mut clusters: Vec<StringCluster> = Vec::new();
        let mut cluster_id = 0u32;

        for i in 0..n {
            if assigned[i] { continue; }
            assigned[i] = true;
            let mut members = vec![strings[i].clone()];

            for j in (i + 1)..n {
                if assigned[j] { continue; }
                let sim = ngram_jaccard_similarity(&strings[i].value, &strings[j].value, self.ngram_n);
                if sim >= self.similarity_threshold {
                    assigned[j] = true;
                    members.push(strings[j].clone());
                }
            }

            let centroid = choose_centroid(&members);
            // Score against the CENTROID — same defect and same fix as in
            // `cluster_edit_distance` above.
            let scores: Vec<f64> = members
                .iter()
                .map(|m| ngram_jaccard_similarity(&m.value, &centroid, self.ngram_n))
                .collect();
            clusters.push(StringCluster { cluster_id, centroid, members, similarity_scores: scores });
            cluster_id += 1;
        }

        ClusterReport::build(clusters, Vec::new(), n)
    }

    // ── TF-IDF / k-means clustering ─────────────────────────────────────────

    fn cluster_tfidf(&self, strings: Vec<StringRef>) -> ClusterReport {
        if strings.is_empty() {
            return ClusterReport::build(Vec::new(), Vec::new(), 0);
        }
        let total = strings.len();
        let k = self.max_k.min(total);
        let vectorizer = TfIdfVectorizer::fit(&strings.iter().map(|s| s.value.as_str()).collect::<Vec<_>>());
        let vectors: Vec<Vec<f64>> = strings.iter().map(|s| vectorizer.transform(&s.value)).collect();
        let labels = kmeans_cluster(&vectors, k, 100);

        let mut buckets: HashMap<usize, Vec<(usize, &StringRef)>> = HashMap::new();
        for (i, &label) in labels.iter().enumerate() {
            buckets.entry(label).or_default().push((i, &strings[i]));
        }

        let mut clusters: Vec<StringCluster> = Vec::new();
        let mut cluster_id = 0u32;
        // HashMap iteration order is nondeterministic; sort by k-means label so
        // cluster_id assignment and cluster order are stable.
        let mut buckets: Vec<(usize, Vec<(usize, &StringRef)>)> = buckets.into_iter().collect();
        buckets.sort_by_key(|(label, _)| *label);
        for (_label, group) in &buckets {
            if group.is_empty() { continue; }
            let members: Vec<StringRef> = group.iter().map(|(_, s)| (*s).clone()).collect();
            let centroid = choose_centroid(&members);
            let scores: Vec<f64> = group.iter().map(|(idx, _)| {
                let center_vec = vectorizer.transform(&centroid);
                cosine_similarity(&vectors[*idx], &center_vec)
            }).collect();
            clusters.push(StringCluster { cluster_id, centroid, members, similarity_scores: scores });
            cluster_id += 1;
        }

        ClusterReport::build(clusters, Vec::new(), total)
    }
}

// ─── Edit Distance ───────────────────────────────────────────────────────────

/// Maximum string length accepted by the O(n·m) DP algorithms before they
/// bail out with a sentinel value, preventing dos-memory-exhaustion.
const DP_LENGTH_CAP: usize = 4096;

/// Classic dynamic-programming Levenshtein distance.
///
/// Returns `usize::MAX` as a sentinel when either input exceeds
/// [`DP_LENGTH_CAP`] to prevent O(n·m) memory exhaustion on untrusted input.
pub fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let m = a_chars.len();
    let n = b_chars.len();

    // Guard against O(n·m) allocation on untrusted long strings
    // (dos-memory-exhaustion).
    if m > DP_LENGTH_CAP || n > DP_LENGTH_CAP {
        return usize::MAX;
    }

    if m == 0 { return n; }
    if n == 0 { return m; }

    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr = vec![0usize; n + 1];

    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = if a_chars[i - 1] == b_chars[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[n]
}

/// Normalised edit similarity: 1.0 - dist / max_len. Returns 1.0 for two empty strings.
pub fn normalized_edit_similarity(a: &str, b: &str) -> f64 {
    let max_len = a.chars().count().max(b.chars().count());
    if max_len == 0 { return 1.0; }
    let dist = levenshtein_distance(a, b);
    // levenshtein_distance returns usize::MAX as its over-cap sentinel; without
    // this guard the formula below would return a huge negative value,
    // violating the [0, 1] range every caller assumes.
    if dist == usize::MAX { return 0.0; }
    1.0 - dist as f64 / max_len as f64
}

// ─── Trigram / N-gram ─────────────────────────────────────────────────────────

/// Character n-grams of `s` as a sorted vector of owned strings.
pub fn char_ngrams(s: &str, n: usize) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < n { return Vec::new(); }
    (0..=(chars.len() - n)).map(|i| chars[i..i + n].iter().collect()).collect()
}

/// Trigram Jaccard similarity between two strings.
pub fn trigram_similarity(a: &str, b: &str) -> f64 {
    ngram_jaccard_similarity(a, b, 3)
}

/// Jaccard similarity of n-gram sets of two strings.
pub fn ngram_jaccard_similarity(a: &str, b: &str, n: usize) -> f64 {
    // Use AHashSet to prevent hash-collision DoS on attacker-controlled n-gram strings.
    let set_a: AHashSet<String> = char_ngrams(a, n).into_iter().collect();
    let set_b: AHashSet<String> = char_ngrams(b, n).into_iter().collect();
    if set_a.is_empty() && set_b.is_empty() { return 1.0; }
    if set_a.is_empty() || set_b.is_empty() { return 0.0; }
    let intersection = set_a.intersection(&set_b).count();
    let union = set_a.union(&set_b).count();
    intersection as f64 / union as f64
}

// ─── Fingerprint ─────────────────────────────────────────────────────────────

const STOP_WORDS: &[&str] = &["the", "a", "an", "of", "and", "or", "in", "is", "to", "it"];

/// Sort words, remove stop words, lowercase, join — used as a cluster key.
pub fn compute_fingerprint(s: &str) -> String {
    let mut words: Vec<String> = s.split_whitespace()
        .map(|w| w.to_lowercase())
        .filter(|w| !STOP_WORDS.contains(&w.as_str()))
        .collect();
    words.sort();
    words.dedup();
    words.join(" ")
}

// ─── TF-IDF ──────────────────────────────────────────────────────────────────

pub struct TfIdfVectorizer {
    vocab: Vec<String>,
    idf: Vec<f64>,
}

impl TfIdfVectorizer {
    /// Build vocabulary and IDF weights from a corpus.
    pub fn fit(docs: &[&str]) -> Self {
        let n = docs.len() as f64;
        // Keyed on tokens extracted from user-controlled strings; use AHashMap
        // to prevent hash-collision DoS (dos-hash-collision).
        let mut df: AHashMap<String, usize> = AHashMap::new();
        let mut vocab_set: AHashSet<String> = AHashSet::new();

        for doc in docs {
            let tokens = tokenize(doc);
            let unique: AHashSet<String> = tokens.into_iter().collect();
            for tok in &unique {
                *df.entry(tok.clone()).or_insert(0usize) += 1;
            }
            vocab_set.extend(unique);
        }

        let mut vocab: Vec<String> = vocab_set.into_iter().collect();
        vocab.sort();
        let idf: Vec<f64> = vocab.iter().map(|term| {
            let df_t = *df.get(term).unwrap_or(&0) as f64;
            ((n + 1.0) / (df_t + 1.0)).ln() + 1.0
        }).collect();

        Self { vocab, idf }
    }

    /// Transform a document into a TF-IDF vector (length = |vocab|).
    pub fn transform(&self, doc: &str) -> Vec<f64> {
        let tokens = tokenize(doc);
        let n = tokens.len() as f64;
        // Keyed on user-controlled token strings — use AHashMap (dos-hash-collision).
        let mut tf: AHashMap<&str, f64> = AHashMap::new();
        for tok in &tokens {
            *tf.entry(tok.as_str()).or_insert(0.0) += 1.0 / n;
        }
        self.vocab.iter().zip(self.idf.iter()).map(|(term, &idf)| {
            let term_tf = tf.get(term.as_str()).copied().unwrap_or(0.0);
            term_tf * idf
        }).collect()
    }
}

fn tokenize(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_lowercase())
        .collect()
}

// ─── K-Means ─────────────────────────────────────────────────────────────────

/// K-means clustering using cosine distance on pre-computed vectors.
/// Returns a label vector (0..k) of the same length as `vectors`.
///
/// Vectors whose length differs from `vectors[0]` contribute nothing to
/// centroid updates (and cosine similarity treats them as 0), instead of
/// panicking on a mismatched index.
pub fn kmeans_cluster(vectors: &[Vec<f64>], k: usize, max_iter: usize) -> Vec<usize> {
    let n = vectors.len();
    if n == 0 || k == 0 { return Vec::new(); }
    let k = k.min(n);
    let dim = vectors[0].len();

    // Initialise centroids by picking evenly spaced data points
    let mut centroids: Vec<Vec<f64>> = (0..k)
        .map(|i| vectors[(i * n / k).min(n - 1)].clone())
        .collect();

    let mut labels = vec![0usize; n];

    for _iter in 0..max_iter {
        // Assignment
        let mut changed = false;
        for (i, v) in vectors.iter().enumerate() {
            let best = (0..k).max_by(|&a, &b| {
                cosine_similarity(v, &centroids[a])
                    .partial_cmp(&cosine_similarity(v, &centroids[b]))
                    .unwrap_or(std::cmp::Ordering::Equal)
            }).unwrap_or(0);
            if labels[i] != best { changed = true; }
            labels[i] = best;
        }
        if !changed { break; }

        // Update centroids
        for c in 0..k {
            let members: Vec<&Vec<f64>> = vectors.iter().zip(&labels).filter(|&(_, &l)| l == c).map(|(v, _)| v).collect();
            if members.is_empty() { continue; }
            let mut new_centroid = vec![0.0f64; dim];
            for m in &members {
                for (j, &val) in m.iter().take(dim).enumerate() {
                    new_centroid[j] += val;
                }
            }
            let count = members.len() as f64;
            for j in 0..dim { new_centroid[j] /= count; }
            centroids[c] = new_centroid;
        }
    }

    labels
}

// ─── Hierarchical (single-linkage) ───────────────────────────────────────────

/// Single-linkage agglomerative clustering.
/// Returns cluster labels for each input string.
pub fn hierarchical_cluster(strings: &[String], threshold: f64) -> Vec<usize> {
    let n = strings.len();
    if n == 0 { return Vec::new(); }

    let mut labels: Vec<usize> = (0..n).collect();
    let mut changed = true;

    while changed {
        changed = false;
        'outer: for i in 0..n {
            for j in (i + 1)..n {
                if labels[i] == labels[j] { continue; }
                let sim = normalized_edit_similarity(&strings[i], &strings[j]);
                if sim >= threshold {
                    let old_label = labels[j];
                    let new_label = labels[i];
                    for k in 0..n {
                        if labels[k] == old_label { labels[k] = new_label; }
                    }
                    changed = true;
                    break 'outer;
                }
            }
        }
    }

    // Normalise labels to 0..k
    let mut mapping: HashMap<usize, usize> = HashMap::new();
    let mut next = 0usize;
    for l in &mut labels {
        let mapped = *mapping.entry(*l).or_insert_with(|| { let v = next; next += 1; v });
        *l = mapped;
    }
    labels
}

// ─── Utility ─────────────────────────────────────────────────────────────────

fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    if a.len() != b.len() { return 0.0; }
    let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
    let norm_b: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();
    if norm_a == 0.0 || norm_b == 0.0 { return 0.0; }
    dot / (norm_a * norm_b)
}

/// Pick the member whose average similarity to all others is highest.
fn choose_centroid(members: &[StringRef]) -> String {
    if members.len() == 1 { return members[0].value.clone(); }
    let scores: Vec<f64> = members.iter().map(|m| {
        members.iter().map(|other| normalized_edit_similarity(&m.value, &other.value)).sum::<f64>()
    }).collect();
    let best = scores.iter().enumerate().max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)).map(|(i, _)| i).unwrap_or(0);
    members[best].value.clone()
}

// ─── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sref(s: &str) -> StringRef { StringRef::new(0, s) }

    #[test]
    fn test_levenshtein_empty() {
        assert_eq!(levenshtein_distance("", ""), 0);
        assert_eq!(levenshtein_distance("", "abc"), 3);
        assert_eq!(levenshtein_distance("abc", ""), 3);
    }

    #[test]
    fn test_levenshtein_equal() {
        assert_eq!(levenshtein_distance("kitten", "kitten"), 0);
    }

    #[test]
    fn test_levenshtein_classic() {
        assert_eq!(levenshtein_distance("kitten", "sitting"), 3);
    }

    #[test]
    fn test_normalized_similarity_equal() {
        assert!((normalized_edit_similarity("hello", "hello") - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_normalized_similarity_totally_different() {
        let sim = normalized_edit_similarity("aaa", "bbb");
        assert!(sim < 0.1);
    }

    #[test]
    fn test_trigram_identical() {
        assert!((trigram_similarity("hello", "hello") - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_trigram_empty() {
        assert_eq!(trigram_similarity("", ""), 1.0);
        assert_eq!(trigram_similarity("abc", ""), 0.0);
    }

    #[test]
    fn test_fingerprint_stop_words_removed() {
        let fp = compute_fingerprint("the quick brown fox");
        assert!(!fp.contains("the"));
        assert!(fp.contains("quick"));
    }

    #[test]
    fn test_fingerprint_sorted() {
        let fp1 = compute_fingerprint("foo bar baz");
        let fp2 = compute_fingerprint("baz foo bar");
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_cluster_edit_distance_groups_similar() {
        let strings = vec![
            sref("hello world"),
            sref("hello worlds"),
            sref("completely different xyz"),
        ];
        let clusterer = StringClusterer::new(ClusterAlgorithm::EditDistance, 0.7);
        let report = clusterer.cluster(strings);
        // "hello world" and "hello worlds" should be grouped
        let big_cluster = report.clusters.iter().any(|c| c.members.len() >= 2);
        assert!(big_cluster);
    }

    #[test]
    fn test_cluster_fingerprint_identical_fp() {
        let strings = vec![
            sref("foo bar"),
            sref("bar foo"),
            sref("xyz abc"),
        ];
        let clusterer = StringClusterer::new(ClusterAlgorithm::Fingerprint, 0.5);
        let report = clusterer.cluster(strings);
        assert!(report.total_strings == 3);
    }

    #[test]
    fn test_tfidf_vectorizer_fit_transform() {
        let docs = ["hello world", "world peace", "hello peace"];
        let vect = TfIdfVectorizer::fit(&docs);
        let v = vect.transform("hello world");
        assert!(!v.is_empty());
        assert!(v.iter().any(|&x| x > 0.0));
    }

    #[test]
    fn test_cosine_similarity_same_vector() {
        let v = vec![1.0, 2.0, 3.0];
        let sim = cosine_similarity(&v, &v);
        assert!((sim - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_cosine_similarity_orthogonal() {
        let a = vec![1.0, 0.0];
        let b = vec![0.0, 1.0];
        assert!((cosine_similarity(&a, &b)).abs() < 1e-9);
    }

    #[test]
    fn test_kmeans_trivial() {
        let vecs = vec![vec![1.0, 0.0], vec![0.0, 1.0], vec![1.0, 0.1]];
        let labels = kmeans_cluster(&vecs, 2, 50);
        assert_eq!(labels.len(), 3);
        // vecs 0 and 2 should share a label
        assert_eq!(labels[0], labels[2]);
    }

    #[test]
    fn test_hierarchical_cluster_groups_similar() {
        let strings: Vec<String> = vec!["kitten".into(), "sitting".into(), "python".into()];
        let labels = hierarchical_cluster(&strings, 0.5);
        assert_eq!(labels.len(), 3);
    }

    #[test]
    fn test_ngram_jaccard_identical() {
        assert!((ngram_jaccard_similarity("abcde", "abcde", 3) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_ngram_jaccard_no_overlap() {
        let sim = ngram_jaccard_similarity("aaa", "bbb", 3);
        assert!(sim < 0.01);
    }

    #[test]
    fn test_cluster_report_display() {
        let report = ClusterReport::build(Vec::new(), Vec::new(), 10);
        let s = format!("{report}");
        assert!(s.contains("0 clusters"));
    }

    #[test]
    fn regress_fingerprint_cluster_order_deterministic() {
        // Bucket iteration used AHashMap order; cluster_id/order must be stable.
        let make = || {
            let strings: Vec<StringRef> = (0..20)
                .flat_map(|i| {
                    let a = format!("word{} common", i);
                    let b = format!("common word{}", i);
                    vec![StringRef::new(i * 2, a), StringRef::new(i * 2 + 1, b)]
                })
                .collect();
            let clusterer = StringClusterer::new(ClusterAlgorithm::Fingerprint, 0.5);
            let report = clusterer.cluster(strings);
            report.clusters.iter().map(|c| (c.cluster_id, c.centroid.clone())).collect::<Vec<_>>()
        };
        let first = make();
        for _ in 0..5 {
            assert_eq!(make(), first);
        }
    }

    #[test]
    fn regress_normalized_similarity_over_cap_stays_in_range() {
        let long_a = "a".repeat(5000);
        let long_b = "b".repeat(5000);
        let sim = normalized_edit_similarity(&long_a, &long_b);
        assert!((0.0..=1.0).contains(&sim), "sim was {}", sim);
    }

    #[test]
    fn regress_tfidf_cluster_order_deterministic() {
        let make = || {
            let strings: Vec<StringRef> = (0..12)
                .map(|i| StringRef::new(i, format!("token{} shared corpus text", i % 4)))
                .collect();
            let clusterer = StringClusterer::new(ClusterAlgorithm::TfIdf, 0.5).with_max_k(3);
            let report = clusterer.cluster(strings);
            report.clusters.iter().map(|c| (c.cluster_id, c.centroid.clone())).collect::<Vec<_>>()
        };
        let first = make();
        for _ in 0..5 {
            assert_eq!(make(), first);
        }
    }

    #[test]
    fn regress_kmeans_mismatched_vector_lengths_no_panic() {
        // A member vector longer than vectors[0] used to index past the
        // centroid buffer (new_centroid[j] with j >= dim) and panic.
        let vecs = vec![vec![1.0, 0.0], vec![0.0, 1.0, 5.0], vec![1.0, 0.1]];
        let labels = kmeans_cluster(&vecs, 2, 50);
        assert_eq!(labels.len(), 3);
    }

    #[test]
    fn test_choose_centroid_single() {
        let members = vec![StringRef::new(0, "hello")];
        assert_eq!(choose_centroid(&members), "hello");
    }
}
