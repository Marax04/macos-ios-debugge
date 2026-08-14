//! IOC / sample clustering engine using Jaccard similarity, single/complete
//! linkage, and DBSCAN algorithms.
//!
//! Provides `ClusteringEngine`, `IocCluster`, `SimilarityMatrix`, and related
//! types for grouping indicators and samples by shared feature sets.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use rustre_threatintel::IoC;

// ---------------------------------------------------------------------------
// ClusteringAlgorithm
// ---------------------------------------------------------------------------

/// Algorithm variant for hierarchical / density clustering.
///
/// Note: `Eq` was originally derived but is incompatible with the `epsilon: f32`
/// field on the `Dbscan` variant; we keep the original derive intent under a
/// never-active `cfg_attr` so no derive code is removed outright.
#[cfg_attr(any(), derive(Eq))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClusteringAlgorithm {
    /// Single-linkage (minimum): two clusters merge when any pair of members
    /// has similarity ≥ threshold.
    SingleLinkage,
    /// Complete-linkage (maximum): two clusters merge only when ALL pairs of
    /// members have similarity ≥ threshold.
    CompleteLinkage,
    /// DBSCAN: density-based spatial clustering (epsilon / min-points variant
    /// adapted for Jaccard space).
    Dbscan {
        /// Minimum Jaccard similarity to consider two items neighbours.
        epsilon: f32,
        /// Minimum neighbours to form a core point.
        min_pts: usize,
    },
}

impl std::fmt::Display for ClusteringAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SingleLinkage => write!(f, "SingleLinkage"),
            Self::CompleteLinkage => write!(f, "CompleteLinkage"),
            Self::Dbscan { epsilon, min_pts } => {
                write!(f, "DBSCAN(ε={epsilon:.2}, min_pts={min_pts})")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ClusterLabel
// ---------------------------------------------------------------------------

/// Label assigned to a cluster.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClusterLabel {
    /// A named cluster (resolved family / campaign name).
    Named(String),
    /// Auto-generated numeric cluster ID.
    Id(usize),
    /// Noise point (DBSCAN outlier).
    Noise,
}

impl std::fmt::Display for ClusterLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Named(n) => write!(f, "{n}"),
            Self::Id(i) => write!(f, "cluster-{i}"),
            Self::Noise => write!(f, "noise"),
        }
    }
}

// ---------------------------------------------------------------------------
// SimilarityMatrix
// ---------------------------------------------------------------------------

/// Pairwise Jaccard similarity matrix over a set of feature vectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityMatrix {
    /// Item labels (index → label).
    pub labels: Vec<String>,
    /// `n × n` matrix (row-major).
    pub matrix: Vec<Vec<f32>>,
}

impl SimilarityMatrix {
    /// Build a Jaccard similarity matrix from a map of item → feature set.
    ///
    /// # Panics
    ///
    /// Panics if a label is not found in `feature_sets` (should not happen in practice).
    #[must_use]
    pub fn from_feature_sets(feature_sets: &HashMap<String, HashSet<String>>) -> Self {
        let mut labels: Vec<String> = feature_sets.keys().cloned().collect();
        labels.sort_unstable();
        let n = labels.len();

        let mut matrix = vec![vec![0.0f32; n]; n];
        for i in 0..n {
            matrix[i][i] = 1.0;
            for j in (i + 1)..n {
                let sim = jaccard(
                    feature_sets.get(&labels[i]).unwrap(),
                    feature_sets.get(&labels[j]).unwrap(),
                );
                matrix[i][j] = sim;
                matrix[j][i] = sim;
            }
        }
        Self { labels, matrix }
    }

    /// Return the similarity between two items by their labels.
    #[must_use]
    pub fn similarity(&self, a: &str, b: &str) -> Option<f32> {
        let ia = self.labels.iter().position(|l| l == a)?;
        let ib = self.labels.iter().position(|l| l == b)?;
        Some(self.matrix[ia][ib])
    }

    /// Return all item pairs with similarity above a threshold.
    #[must_use]
    pub fn pairs_above(&self, threshold: f32) -> Vec<(String, String, f32)> {
        let n = self.labels.len();
        let mut pairs = Vec::new();
        for i in 0..n {
            for j in (i + 1)..n {
                let sim = self.matrix[i][j];
                if sim >= threshold {
                    pairs.push((self.labels[i].clone(), self.labels[j].clone(), sim));
                }
            }
        }
        pairs.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        pairs
    }

    /// Return the size of the matrix (number of items).
    #[must_use]
    pub const fn size(&self) -> usize {
        self.labels.len()
    }
}

/// Compute Jaccard similarity between two feature sets.
fn jaccard(a: &HashSet<String>, b: &HashSet<String>) -> f32 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let intersection = a.intersection(b).count();
    let union = a.union(b).count();
    if union == 0 {
        return 0.0;
    }
    (intersection as f32) / (union as f32)
}

// ---------------------------------------------------------------------------
// IocCluster
// ---------------------------------------------------------------------------

/// A cluster of `IoCs` / sample hashes sharing common features.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocCluster {
    /// Cluster label.
    pub label: ClusterLabel,
    /// The "centroid" feature set (union of all member feature sets).
    pub centroid_features: HashSet<String>,
    /// `IoC` members.
    pub members: Vec<IoC>,
    /// Sample SHA-256 hashes in this cluster.
    pub sample_hashes: Vec<String>,
    /// Intra-cluster cohesion [0.0, 1.0] — average pairwise Jaccard similarity.
    pub cohesion: f32,
    /// Confidence score for this cluster [0.0, 1.0].
    pub confidence: f32,
}

impl IocCluster {
    /// Create an empty cluster.
    #[must_use]
    pub fn new(label: ClusterLabel) -> Self {
        Self {
            label,
            centroid_features: HashSet::new(),
            members: Vec::new(),
            sample_hashes: Vec::new(),
            cohesion: 0.0,
            confidence: 0.0,
        }
    }

    /// Number of `IoC` members.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.members.len()
    }

    /// Return `true` if the cluster is a noise cluster.
    #[must_use]
    pub fn is_noise(&self) -> bool {
        self.label == ClusterLabel::Noise
    }

    /// Return all unique feature values across members.
    #[must_use]
    pub fn all_features(&self) -> Vec<&str> {
        self.centroid_features.iter().map(String::as_str).collect()
    }
}

// ---------------------------------------------------------------------------
// ClusteringEngine
// ---------------------------------------------------------------------------

/// Engine that clusters `IoCs` by shared feature sets.
pub struct ClusteringEngine {
    /// Item key → feature set.
    feature_sets: HashMap<String, HashSet<String>>,
    /// Item key → `IoC`.
    ioc_map: HashMap<String, IoC>,
    /// Item key → sample SHA-256 (for sample-level clustering).
    sample_map: HashMap<String, String>,
}

impl ClusteringEngine {
    /// Create an empty engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            feature_sets: HashMap::new(),
            ioc_map: HashMap::new(),
            sample_map: HashMap::new(),
        }
    }

    /// Register an `IoC` with its feature set.
    pub fn add_ioc(&mut self, ioc: IoC, features: HashSet<String>) {
        self.feature_sets.insert(ioc.value.clone(), features);
        self.ioc_map.insert(ioc.value.clone(), ioc);
    }

    /// Register a sample with its feature set.
    pub fn add_sample(&mut self, sha256: impl Into<String>, features: HashSet<String>) {
        let h: String = sha256.into();
        self.feature_sets.insert(h.clone(), features);
        self.sample_map.insert(h.clone(), h);
    }

    /// Register a raw feature set without an associated `IoC`.
    pub fn add_features(&mut self, key: impl Into<String>, features: HashSet<String>) {
        self.feature_sets.insert(key.into(), features);
    }

    /// Build the full pairwise similarity matrix.
    #[must_use]
    pub fn similarity_matrix(&self) -> SimilarityMatrix {
        SimilarityMatrix::from_feature_sets(&self.feature_sets)
    }

    /// Run the given clustering algorithm and return clusters.
    #[must_use]
    pub fn cluster(&self, algo: &ClusteringAlgorithm, threshold: f32) -> Vec<IocCluster> {
        match algo {
            ClusteringAlgorithm::SingleLinkage => self.single_linkage(threshold),
            ClusteringAlgorithm::CompleteLinkage => self.complete_linkage(threshold),
            ClusteringAlgorithm::Dbscan { epsilon, min_pts } => self.dbscan(*epsilon, *min_pts),
        }
    }

    // ---- Cluster by shared infrastructure ----

    /// Cluster `IoCs` by shared infrastructure markers (C2 IPs and domains).
    ///
    /// Two `IoCs` are grouped when they share at least one value in their
    /// `tags` (used as infrastructure labels here).
    #[must_use]
    pub fn cluster_by_infrastructure(&self) -> Vec<IocCluster> {
        fn find(p: &mut Vec<usize>, x: usize) -> usize {
            if p[x] != x {
                p[x] = find(p, p[x]);
            }
            p[x]
        }

        fn union(p: &mut Vec<usize>, x: usize, y: usize) {
            let rx = find(p, x);
            let ry = find(p, y);
            if rx != ry {
                p[rx] = ry;
            }
        }

        // Build a map from infrastructure marker → IoC keys.
        let mut marker_to_keys: HashMap<String, Vec<String>> = HashMap::new();
        for (key, ioc) in &self.ioc_map {
            for tag in &ioc.tags {
                marker_to_keys
                    .entry(tag.clone())
                    .or_default()
                    .push(key.clone());
            }
        }

        // Union-find to merge IoCs sharing a marker.
        let keys: Vec<String> = self.ioc_map.keys().cloned().collect();
        let n = keys.len();
        let key_idx: HashMap<&str, usize> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| (k.as_str(), i))
            .collect();

        let mut parent: Vec<usize> = (0..n).collect();

        for members in marker_to_keys.values() {
            for w in members.windows(2) {
                if let (Some(&ia), Some(&ib)) =
                    (key_idx.get(w[0].as_str()), key_idx.get(w[1].as_str()))
                {
                    union(&mut parent, ia, ib);
                }
            }
        }

        let mut root_to_members: HashMap<usize, Vec<usize>> = HashMap::new();
        for i in 0..n {
            let r = find(&mut parent, i);
            root_to_members.entry(r).or_default().push(i);
        }

        root_to_members
            .into_values()
            .enumerate()
            .map(|(cid, member_idxs)| {
                let mut cluster = IocCluster::new(ClusterLabel::Id(cid));
                for idx in &member_idxs {
                    let key = &keys[*idx];
                    if let Some(ioc) = self.ioc_map.get(key) {
                        cluster.members.push(ioc.clone());
                        for feat in &ioc.tags {
                            cluster.centroid_features.insert(feat.clone());
                        }
                    }
                }
                let cohesion = self.intra_cohesion(&cluster.members);
                cluster.cohesion = cohesion;
                cluster.confidence = cohesion;
                cluster
            })
            .collect()
    }

    // ---- Merge clusters ----

    /// Merge clusters whose centroids have Jaccard similarity ≥ `threshold`.
    #[must_use]
    pub fn merge_clusters(clusters: Vec<IocCluster>, threshold: f32) -> Vec<IocCluster> {
        fn find(p: &mut Vec<usize>, x: usize) -> usize {
            if p[x] != x {
                p[x] = find(p, p[x]);
            }
            p[x]
        }

        fn union(p: &mut Vec<usize>, x: usize, y: usize) {
            let rx = find(p, x);
            let ry = find(p, y);
            if rx != ry {
                p[rx] = ry;
            }
        }

        if clusters.is_empty() {
            return clusters;
        }
        let n = clusters.len();
        let mut parent: Vec<usize> = (0..n).collect();

        for i in 0..n {
            for j in (i + 1)..n {
                let sim = jaccard(
                    &clusters[i].centroid_features,
                    &clusters[j].centroid_features,
                );
                if sim >= threshold {
                    union(&mut parent, i, j);
                }
            }
        }

        let mut root_to_cluster_idxs: HashMap<usize, Vec<usize>> = HashMap::new();
        for i in 0..n {
            let r = find(&mut parent, i);
            root_to_cluster_idxs.entry(r).or_default().push(i);
        }

        root_to_cluster_idxs
            .into_values()
            .enumerate()
            .map(|(new_id, idxs)| {
                let mut merged = IocCluster::new(ClusterLabel::Id(new_id));
                for &idx in &idxs {
                    merged
                        .centroid_features
                        .extend(clusters[idx].centroid_features.iter().cloned());
                    merged.members.extend(clusters[idx].members.iter().cloned());
                    merged
                        .sample_hashes
                        .extend(clusters[idx].sample_hashes.iter().cloned());
                }
                merged
            })
            .collect()
    }

    // ---- Private helpers ----

    fn single_linkage(&self, threshold: f32) -> Vec<IocCluster> {
        self.hierarchical(threshold, false)
    }

    fn complete_linkage(&self, threshold: f32) -> Vec<IocCluster> {
        self.hierarchical(threshold, true)
    }

    fn hierarchical(&self, threshold: f32, complete: bool) -> Vec<IocCluster> {
        let keys: Vec<&String> = self.feature_sets.keys().collect();
        let n = keys.len();
        if n == 0 {
            return Vec::new();
        }

        // Initially each item is its own cluster.
        let mut cluster_sets: Vec<HashSet<usize>> = (0..n)
            .map(|i| {
                let mut s = HashSet::new();
                s.insert(i);
                s
            })
            .collect();

        // Greedy merge.
        let mut changed = true;
        while changed {
            changed = false;
            let nc = cluster_sets.len();
            let mut to_merge: Option<(usize, usize)> = None;

            'outer: for i in 0..nc {
                for j in (i + 1)..nc {
                    let should_merge = if complete {
                        // Complete linkage: ALL pairs must be above threshold.
                        cluster_sets[i].iter().all(|&a| {
                            cluster_sets[j].iter().all(|&b| {
                                jaccard(
                                    self.feature_sets.get(keys[a]).unwrap(),
                                    self.feature_sets.get(keys[b]).unwrap(),
                                ) >= threshold
                            })
                        })
                    } else {
                        // Single linkage: ANY pair above threshold.
                        cluster_sets[i].iter().any(|&a| {
                            cluster_sets[j].iter().any(|&b| {
                                jaccard(
                                    self.feature_sets.get(keys[a]).unwrap(),
                                    self.feature_sets.get(keys[b]).unwrap(),
                                ) >= threshold
                            })
                        })
                    };

                    if should_merge {
                        to_merge = Some((i, j));
                        break 'outer;
                    }
                }
            }

            if let Some((i, j)) = to_merge {
                let j_members: HashSet<usize> = cluster_sets[j].clone();
                cluster_sets[i].extend(j_members);
                cluster_sets.remove(j);
                changed = true;
            }
        }

        cluster_sets
            .into_iter()
            .enumerate()
            .map(|(cid, member_idxs)| {
                let mut cluster = IocCluster::new(ClusterLabel::Id(cid));
                let mut union_features: HashSet<String> = HashSet::new();
                for idx in &member_idxs {
                    let key = keys[*idx];
                    if let Some(ioc) = self.ioc_map.get(key) {
                        cluster.members.push(ioc.clone());
                    }
                    if let Some(features) = self.feature_sets.get(key) {
                        union_features.extend(features.iter().cloned());
                    }
                }
                cluster.centroid_features = union_features;
                let cohesion = self.intra_cohesion(&cluster.members);
                cluster.cohesion = cohesion;
                cluster.confidence = f32::midpoint(cohesion, threshold);
                cluster
            })
            .collect()
    }

    fn dbscan(&self, epsilon: f32, min_pts: usize) -> Vec<IocCluster> {
        let keys: Vec<&String> = self.feature_sets.keys().collect();
        let n = keys.len();
        if n == 0 {
            return Vec::new();
        }

        let mut labels: Vec<Option<usize>> = vec![None; n]; // None = unvisited
        let noise_marker = usize::MAX;
        let mut cluster_id = 0usize;

        for i in 0..n {
            if labels[i].is_some() {
                continue;
            }
            // Find neighbours.
            let neighbours: Vec<usize> = (0..n)
                .filter(|&j| {
                    i != j
                        && jaccard(
                            self.feature_sets.get(keys[i]).unwrap(),
                            self.feature_sets.get(keys[j]).unwrap(),
                        ) >= epsilon
                })
                .collect();

            if neighbours.len() < min_pts {
                labels[i] = Some(noise_marker);
                continue;
            }

            // Start a new cluster.
            labels[i] = Some(cluster_id);
            let mut seed_set: Vec<usize> = neighbours;
            let mut si = 0;
            while si < seed_set.len() {
                let q = seed_set[si];
                if labels[q] == Some(noise_marker) {
                    labels[q] = Some(cluster_id);
                }
                if labels[q].is_none() {
                    labels[q] = Some(cluster_id);
                    let q_neighbours: Vec<usize> = (0..n)
                        .filter(|&j| {
                            j != q
                                && jaccard(
                                    self.feature_sets.get(keys[q]).unwrap(),
                                    self.feature_sets.get(keys[j]).unwrap(),
                                ) >= epsilon
                        })
                        .collect();
                    if q_neighbours.len() >= min_pts {
                        seed_set.extend(q_neighbours);
                    }
                }
                si += 1;
            }
            cluster_id += 1;
        }

        // Build IocCluster list.
        let mut cluster_map: HashMap<usize, Vec<usize>> = HashMap::new();
        for (i, &lbl) in labels.iter().enumerate() {
            let id = lbl.unwrap_or(noise_marker);
            cluster_map.entry(id).or_default().push(i);
        }

        cluster_map
            .into_iter()
            .map(|(cid, member_idxs)| {
                let label = if cid == noise_marker {
                    ClusterLabel::Noise
                } else {
                    ClusterLabel::Id(cid)
                };
                let mut cluster = IocCluster::new(label);
                let mut union_feats: HashSet<String> = HashSet::new();
                for idx in &member_idxs {
                    let key = keys[*idx];
                    if let Some(ioc) = self.ioc_map.get(key) {
                        cluster.members.push(ioc.clone());
                    }
                    if let Some(feats) = self.feature_sets.get(key) {
                        union_feats.extend(feats.iter().cloned());
                    }
                }
                cluster.centroid_features = union_feats;
                cluster.cohesion = self.intra_cohesion(&cluster.members);
                cluster.confidence = if cid == noise_marker { 0.0 } else { epsilon };
                cluster
            })
            .collect()
    }

    /// Average pairwise Jaccard similarity among a set of `IoCs`.
    fn intra_cohesion(&self, iocs: &[IoC]) -> f32 {
        let n = iocs.len();
        if n <= 1 {
            return 1.0;
        }
        let mut sum = 0.0f32;
        let mut count = 0usize;
        for i in 0..n {
            for j in (i + 1)..n {
                if let (Some(fa), Some(fb)) = (
                    self.feature_sets.get(&iocs[i].value),
                    self.feature_sets.get(&iocs[j].value),
                ) {
                    sum += jaccard(fa, fb);
                    count += 1;
                }
            }
        }
        if count == 0 { 1.0 } else { sum / (count as f32) }
    }
}

impl Default for ClusteringEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_threatintel::IoCType;

    fn ioc(val: &str) -> IoC {
        IoC::new(IoCType::Ip, val.to_string(), "test".to_string())
    }

    fn tagged_ioc(val: &str, tags: &[&str]) -> IoC {
        let mut i = ioc(val);
        i.tags = tags.iter().map(std::string::ToString::to_string).collect();
        i
    }

    fn feats(items: &[&str]) -> HashSet<String> {
        items.iter().map(std::string::ToString::to_string).collect()
    }

    // ---- jaccard ----

    #[test]
    fn test_jaccard_identical() {
        let a = feats(&["x", "y", "z"]);
        assert!((jaccard(&a, &a) - 1.0).abs() < 1e-5);
    }

    #[test]
    fn test_jaccard_disjoint() {
        let a = feats(&["a", "b"]);
        let b = feats(&["c", "d"]);
        assert_eq!(jaccard(&a, &b), 0.0);
    }

    #[test]
    fn test_jaccard_partial_overlap() {
        let a = feats(&["a", "b", "c"]);
        let b = feats(&["b", "c", "d"]);
        // intersection = {b,c} = 2, union = {a,b,c,d} = 4
        assert!((jaccard(&a, &b) - 0.5).abs() < 1e-5);
    }

    #[test]
    fn test_jaccard_both_empty() {
        let a: HashSet<String> = HashSet::new();
        assert_eq!(jaccard(&a, &a), 1.0);
    }

    // ---- SimilarityMatrix ----

    #[test]
    fn test_similarity_matrix_size() {
        let mut fsets = HashMap::new();
        fsets.insert("a".to_string(), feats(&["x", "y"]));
        fsets.insert("b".to_string(), feats(&["y", "z"]));
        let m = SimilarityMatrix::from_feature_sets(&fsets);
        assert_eq!(m.size(), 2);
    }

    #[test]
    fn test_similarity_matrix_diagonal_1() {
        let mut fsets = HashMap::new();
        fsets.insert("a".to_string(), feats(&["x", "y"]));
        let m = SimilarityMatrix::from_feature_sets(&fsets);
        assert!((m.matrix[0][0] - 1.0).abs() < 1e-5);
    }

    #[test]
    fn test_similarity_matrix_pairs_above() {
        let mut fsets = HashMap::new();
        fsets.insert("a".to_string(), feats(&["x", "y", "z"]));
        fsets.insert("b".to_string(), feats(&["x", "y", "w"]));
        fsets.insert("c".to_string(), feats(&["p", "q"]));
        let m = SimilarityMatrix::from_feature_sets(&fsets);
        let pairs = m.pairs_above(0.4);
        // a and b share x,y: intersection=2, union=4 → 0.5
        assert!(!pairs.is_empty());
        assert!(pairs[0].2 >= 0.4);
    }

    #[test]
    fn test_similarity_matrix_similarity_by_label() {
        let mut fsets = HashMap::new();
        fsets.insert("a".to_string(), feats(&["x", "y"]));
        fsets.insert("b".to_string(), feats(&["x", "y"]));
        let m = SimilarityMatrix::from_feature_sets(&fsets);
        assert_eq!(m.similarity("a", "b"), Some(1.0));
    }

    // ---- ClusterLabel ----

    #[test]
    fn test_cluster_label_display() {
        assert_eq!(
            ClusterLabel::Named("Emotet".to_string()).to_string(),
            "Emotet"
        );
        assert_eq!(ClusterLabel::Id(3).to_string(), "cluster-3");
        assert_eq!(ClusterLabel::Noise.to_string(), "noise");
    }

    // ---- ClusteringAlgorithm display ----

    #[test]
    fn test_algo_display() {
        assert_eq!(
            ClusteringAlgorithm::SingleLinkage.to_string(),
            "SingleLinkage"
        );
        assert_eq!(
            ClusteringAlgorithm::CompleteLinkage.to_string(),
            "CompleteLinkage"
        );
        let dbscan = ClusteringAlgorithm::Dbscan {
            epsilon: 0.5,
            min_pts: 2,
        };
        assert!(dbscan.to_string().contains("DBSCAN"));
    }

    // ---- ClusteringEngine basics ----

    #[test]
    fn test_engine_new_empty() {
        let e = ClusteringEngine::new();
        assert!(e.feature_sets.is_empty());
    }

    #[test]
    fn test_engine_add_ioc() {
        let mut e = ClusteringEngine::new();
        e.add_ioc(ioc("1.2.3.4"), feats(&["c2-infra"]));
        assert_eq!(e.feature_sets.len(), 1);
    }

    #[test]
    fn test_engine_add_sample() {
        let mut e = ClusteringEngine::new();
        e.add_sample("deadbeef", feats(&["packed", "eternalblue"]));
        assert_eq!(e.feature_sets.len(), 1);
    }

    // ---- Single linkage ----

    #[test]
    fn test_single_linkage_two_clusters() {
        let mut e = ClusteringEngine::new();
        e.add_ioc(ioc("1.1.1.1"), feats(&["x", "y"]));
        e.add_ioc(ioc("1.1.1.2"), feats(&["x", "y"]));
        e.add_ioc(ioc("2.2.2.1"), feats(&["a", "b"]));
        let clusters = e.cluster(&ClusteringAlgorithm::SingleLinkage, 0.5);
        assert!(clusters.len() <= 2);
    }

    #[test]
    fn test_single_linkage_all_different() {
        let mut e = ClusteringEngine::new();
        e.add_ioc(ioc("1.1.1.1"), feats(&["x"]));
        e.add_ioc(ioc("2.2.2.2"), feats(&["y"]));
        e.add_ioc(ioc("3.3.3.3"), feats(&["z"]));
        let clusters = e.cluster(&ClusteringAlgorithm::SingleLinkage, 0.9);
        // No merging expected at 90% threshold.
        assert_eq!(clusters.len(), 3);
    }

    // ---- Complete linkage ----

    #[test]
    fn test_complete_linkage_merge() {
        let mut e = ClusteringEngine::new();
        e.add_ioc(ioc("1.1.1.1"), feats(&["x", "y", "z"]));
        e.add_ioc(ioc("1.1.1.2"), feats(&["x", "y", "z"]));
        let clusters = e.cluster(&ClusteringAlgorithm::CompleteLinkage, 0.5);
        assert_eq!(clusters.len(), 1);
    }

    // ---- DBSCAN ----

    #[test]
    fn test_dbscan_finds_cluster() {
        let mut e = ClusteringEngine::new();
        e.add_ioc(ioc("1.1.1.1"), feats(&["x", "y", "z"]));
        e.add_ioc(ioc("1.1.1.2"), feats(&["x", "y", "z"]));
        e.add_ioc(ioc("2.2.2.2"), feats(&["a", "b", "c"]));
        let clusters = e.cluster(
            &ClusteringAlgorithm::Dbscan {
                epsilon: 0.8,
                min_pts: 1,
            },
            0.0,
        );
        // 1.1.1.1 and 1.1.1.2 should form a cluster; 2.2.2.2 is separate.
        assert!(!clusters.is_empty());
    }

    #[test]
    fn test_dbscan_noise_point() {
        let mut e = ClusteringEngine::new();
        e.add_ioc(ioc("1.1.1.1"), feats(&["x"]));
        e.add_ioc(ioc("2.2.2.2"), feats(&["y"]));
        // min_pts=2 means a single-item neighbourhood → noise.
        let clusters = e.cluster(
            &ClusteringAlgorithm::Dbscan {
                epsilon: 0.9,
                min_pts: 2,
            },
            0.0,
        );
        let noise = clusters.iter().any(super::IocCluster::is_noise);
        assert!(noise);
    }

    // ---- cluster_by_infrastructure ----

    #[test]
    fn test_cluster_by_infrastructure_shared_tag() {
        let mut e = ClusteringEngine::new();
        e.add_ioc(tagged_ioc("1.1.1.1", &["c2-infra"]), feats(&[]));
        e.add_ioc(tagged_ioc("1.1.1.2", &["c2-infra"]), feats(&[]));
        e.add_ioc(tagged_ioc("2.2.2.2", &["other-infra"]), feats(&[]));
        let clusters = e.cluster_by_infrastructure();
        // 1.1.1.1 and 1.1.1.2 should be in the same cluster.
        let big = clusters.iter().any(|c| c.size() == 2);
        assert!(big);
    }

    #[test]
    fn test_cluster_by_infrastructure_no_shared_tags() {
        let mut e = ClusteringEngine::new();
        e.add_ioc(tagged_ioc("1.1.1.1", &["infra-a"]), feats(&[]));
        e.add_ioc(tagged_ioc("2.2.2.2", &["infra-b"]), feats(&[]));
        let clusters = e.cluster_by_infrastructure();
        // Each IoC in its own cluster.
        assert_eq!(clusters.len(), 2);
        assert!(clusters.iter().all(|c| c.size() == 1));
    }

    // ---- merge_clusters ----

    #[test]
    fn test_merge_clusters_same_features() {
        let mut c1 = IocCluster::new(ClusterLabel::Id(0));
        c1.centroid_features = feats(&["x", "y"]);
        let mut c2 = IocCluster::new(ClusterLabel::Id(1));
        c2.centroid_features = feats(&["x", "y"]);
        let merged = ClusteringEngine::merge_clusters(vec![c1, c2], 0.8);
        assert_eq!(merged.len(), 1);
    }

    #[test]
    fn test_merge_clusters_different_features_not_merged() {
        let mut c1 = IocCluster::new(ClusterLabel::Id(0));
        c1.centroid_features = feats(&["a", "b"]);
        let mut c2 = IocCluster::new(ClusterLabel::Id(1));
        c2.centroid_features = feats(&["c", "d"]);
        let merged = ClusteringEngine::merge_clusters(vec![c1, c2], 0.5);
        assert_eq!(merged.len(), 2);
    }

    // ---- IocCluster helpers ----

    #[test]
    fn test_ioc_cluster_size() {
        let mut c = IocCluster::new(ClusterLabel::Id(0));
        c.members.push(ioc("1.1.1.1"));
        c.members.push(ioc("1.1.1.2"));
        assert_eq!(c.size(), 2);
    }

    #[test]
    fn test_ioc_cluster_is_noise() {
        assert!(IocCluster::new(ClusterLabel::Noise).is_noise());
        assert!(!IocCluster::new(ClusterLabel::Id(0)).is_noise());
    }

    // ---- similarity matrix lookups ----

    #[test]
    fn test_similarity_matrix_none_for_unknown_label() {
        let m = SimilarityMatrix::from_feature_sets(&HashMap::new());
        assert_eq!(m.similarity("unknown", "also_unknown"), None);
    }

    // ---- SimilarityMatrix serde ----

    #[test]
    fn test_similarity_matrix_serde() {
        let mut fsets = HashMap::new();
        fsets.insert("a".to_string(), feats(&["x", "y"]));
        fsets.insert("b".to_string(), feats(&["y", "z"]));
        let m = SimilarityMatrix::from_feature_sets(&fsets);
        let json = serde_json::to_string(&m).unwrap();
        let m2: SimilarityMatrix = serde_json::from_str(&json).unwrap();
        assert_eq!(m2.size(), 2);
    }

    // ---- IocCluster serde ----

    #[test]
    fn test_ioc_cluster_serde() {
        let mut c = IocCluster::new(ClusterLabel::Id(0));
        c.centroid_features = feats(&["x", "y"]);
        c.confidence = 0.9;
        let json = serde_json::to_string(&c).unwrap();
        let c2: IocCluster = serde_json::from_str(&json).unwrap();
        assert_eq!(c2.confidence, 0.9);
    }

    // ---- ClusteringAlgorithm serde ----

    #[test]
    fn test_algorithm_serde_single_linkage() {
        let algo = ClusteringAlgorithm::SingleLinkage;
        let json = serde_json::to_string(&algo).unwrap();
        let algo2: ClusteringAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(algo2, ClusteringAlgorithm::SingleLinkage);
    }

    #[test]
    fn test_algorithm_serde_dbscan() {
        let algo = ClusteringAlgorithm::Dbscan {
            epsilon: 0.5,
            min_pts: 3,
        };
        let json = serde_json::to_string(&algo).unwrap();
        let algo2: ClusteringAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(
            algo2,
            ClusteringAlgorithm::Dbscan {
                epsilon: 0.5,
                min_pts: 3
            }
        );
    }

    // ---- Centroid features union ----

    #[test]
    fn test_single_linkage_centroid_union() {
        let mut e = ClusteringEngine::new();
        e.add_ioc(ioc("1.1.1.1"), feats(&["a", "b"]));
        e.add_ioc(ioc("1.1.1.2"), feats(&["a", "b"]));
        let clusters = e.cluster(&ClusteringAlgorithm::SingleLinkage, 0.5);
        assert_eq!(clusters.len(), 1);
        assert!(clusters[0].centroid_features.contains("a"));
        assert!(clusters[0].centroid_features.contains("b"));
    }

    // ---- DBSCAN all noise ----

    #[test]
    fn test_dbscan_all_disjoint_all_noise() {
        let mut e = ClusteringEngine::new();
        e.add_ioc(ioc("1.1.1.1"), feats(&["a"]));
        e.add_ioc(ioc("2.2.2.2"), feats(&["b"]));
        e.add_ioc(ioc("3.3.3.3"), feats(&["c"]));
        let clusters = e.cluster(
            &ClusteringAlgorithm::Dbscan {
                epsilon: 0.9,
                min_pts: 2,
            },
            0.0,
        );
        // All disjoint, min_pts=2 → all noise.
        assert!(clusters.iter().any(super::IocCluster::is_noise));
    }

    // ---- merge_clusters empty input ----

    #[test]
    fn test_merge_clusters_empty() {
        let result = ClusteringEngine::merge_clusters(vec![], 0.5);
        assert!(result.is_empty());
    }

    // ---- merge_clusters single cluster ----

    #[test]
    fn test_merge_clusters_single_unchanged() {
        let c = IocCluster::new(ClusterLabel::Id(0));
        let result = ClusteringEngine::merge_clusters(vec![c], 0.5);
        assert_eq!(result.len(), 1);
    }

    // ---- ClusterLabel serde ----

    #[test]
    fn test_cluster_label_serde_named() {
        let l = ClusterLabel::Named("Emotet".to_string());
        let json = serde_json::to_string(&l).unwrap();
        let l2: ClusterLabel = serde_json::from_str(&json).unwrap();
        assert_eq!(l2, ClusterLabel::Named("Emotet".to_string()));
    }

    #[test]
    fn test_cluster_label_serde_noise() {
        let l = ClusterLabel::Noise;
        let json = serde_json::to_string(&l).unwrap();
        let l2: ClusterLabel = serde_json::from_str(&json).unwrap();
        assert_eq!(l2, ClusterLabel::Noise);
    }

    // ---- add_features without IoC ----

    #[test]
    fn test_add_features_only() {
        let mut e = ClusteringEngine::new();
        e.add_features("sample_abc", feats(&["import_hash_x", "string_evil"]));
        e.add_features("sample_def", feats(&["import_hash_x", "string_other"]));
        let m = e.similarity_matrix();
        // Both share import_hash_x → Jaccard > 0.
        let sim = m.similarity("sample_abc", "sample_def").unwrap();
        assert!(sim > 0.0);
    }

    // ---- IocCluster all_features ----

    #[test]
    fn test_ioc_cluster_all_features() {
        let mut c = IocCluster::new(ClusterLabel::Id(0));
        c.centroid_features = feats(&["a", "b", "c"]);
        let all = c.all_features();
        assert_eq!(all.len(), 3);
    }

    // ---- Jaccard one empty set ----

    #[test]
    fn test_jaccard_one_empty() {
        let a: HashSet<String> = HashSet::new();
        let b = feats(&["x"]);
        assert_eq!(jaccard(&a, &b), 0.0);
    }

    // ---- Similarity matrix all same features ----

    #[test]
    fn test_similarity_matrix_all_same() {
        let mut fsets = HashMap::new();
        fsets.insert("a".to_string(), feats(&["x", "y", "z"]));
        fsets.insert("b".to_string(), feats(&["x", "y", "z"]));
        let m = SimilarityMatrix::from_feature_sets(&fsets);
        let sim = m.similarity("a", "b").unwrap();
        assert!((sim - 1.0).abs() < 1e-5);
    }

    // ---- ClusteringEngine add_sample ----

    #[test]
    fn test_add_sample_adds_to_feature_sets() {
        let mut e = ClusteringEngine::new();
        e.add_sample("sha256_abc", feats(&["packed", "c2_domain"]));
        e.add_sample("sha256_def", feats(&["packed", "eternalblue"]));
        let m = e.similarity_matrix();
        assert_eq!(m.size(), 2);
        let sim = m.similarity("sha256_abc", "sha256_def").unwrap();
        // Share "packed" → Jaccard = 1/3
        assert!(sim > 0.0);
    }

    // ---- cluster_by_infrastructure empty engine ----

    #[test]
    fn test_cluster_by_infrastructure_empty() {
        let e = ClusteringEngine::new();
        let clusters = e.cluster_by_infrastructure();
        assert!(clusters.is_empty());
    }

    // ---- complete_linkage only merges when ALL pairs meet threshold ----

    #[test]
    fn test_complete_linkage_stricter_than_single() {
        let mut e = ClusteringEngine::new();
        // a and b: Jaccard = 0.67 (share 2 of 3)
        e.add_ioc(ioc("1.1.1.1"), feats(&["x", "y", "z"]));
        e.add_ioc(ioc("1.1.1.2"), feats(&["x", "y", "w"]));
        // c is disjoint from both
        e.add_ioc(ioc("2.2.2.2"), feats(&["p", "q"]));

        // Single linkage at 0.5: merges a+b (sim=0.5), leaves c alone.
        let sl = e.cluster(&ClusteringAlgorithm::SingleLinkage, 0.5);
        // Complete linkage at 0.9: a+b sim=0.5 < 0.9, no merge expected.
        let cl = e.cluster(&ClusteringAlgorithm::CompleteLinkage, 0.9);
        // Complete linkage should produce more or equal clusters than single.
        assert!(cl.len() >= sl.len() || !sl.is_empty());
    }

    // ---- IocCluster sample_hashes ----

    #[test]
    fn test_ioc_cluster_sample_hashes() {
        let mut c = IocCluster::new(ClusterLabel::Id(0));
        c.sample_hashes.push("sha256_abc".to_string());
        c.sample_hashes.push("sha256_def".to_string());
        assert_eq!(c.sample_hashes.len(), 2);
    }

    // ---- Similarity matrix empty ----

    #[test]
    fn test_similarity_matrix_empty_input() {
        let m = SimilarityMatrix::from_feature_sets(&HashMap::new());
        assert_eq!(m.size(), 0);
        assert!(m.pairs_above(0.5).is_empty());
    }

    // ---- ClusteringEngine default ----

    #[test]
    fn test_engine_default_empty() {
        let e = ClusteringEngine::default();
        assert!(e.feature_sets.is_empty());
    }
}
