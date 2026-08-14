//! `function_clustering` — Cluster similar functions by feature vectors.
//!
//! Groups functions in a binary using k-means-style clustering based on
//! numeric feature vectors extracted from [`FunctionBoundary`] data.
//! Supports both Euclidean and Cosine similarity metrics.

use crate::FunctionBoundary;
// Re-export the boundary-related types so callers of this module can
// reach them without depending on the crate root directly.
pub use crate::{Confidence, DetectionSource};
pub use rustre_core::address::Address;
pub use std::collections::HashMap;

// ---------------------------------------------------------------------------
// FunctionFeatures
// ---------------------------------------------------------------------------

/// Numeric feature vector extracted from a single function.
///
/// All fields are normalised to `f64` to allow distance computations to work
/// uniformly regardless of the raw scale of each feature.
#[derive(Debug, Clone, PartialEq)]
pub struct FunctionFeatures {
    /// Byte size of the function body (0 if unknown).
    pub size: f64,
    /// Number of basic blocks estimated from branch count heuristic.
    pub block_count: f64,
    /// Number of call instructions found in the body.
    pub call_count: f64,
    /// Number of string-reference-like patterns found.
    pub string_count: f64,
    /// Number of import references (estimated from PLT/thunk patterns).
    pub import_count: f64,
    /// Cyclomatic complexity estimate (`block_count` - edges + 2).
    pub complexity: f64,
    /// Starting virtual address of the function (used for tie-breaking).
    pub address: u64,
    /// Optional name carried through from the boundary.
    pub name: Option<String>,
}

impl FunctionFeatures {
    /// Build a [`FunctionFeatures`] from a raw code slice and a
    /// [`FunctionBoundary`].
    ///
    /// For now uses heuristic byte-counting to estimate features.
    ///
    /// `base` is the virtual address at which `code` is loaded; it is
    /// subtracted from `fb.start` to obtain the slice offset.
    #[must_use]
    pub fn from_boundary(fb: &FunctionBoundary, code: &[u8], base: u64) -> Self {
        let size_bytes = fb.byte_size().unwrap_or(0);
        let size = f64::from(u32::try_from(size_bytes).unwrap_or(u32::MAX));

        // Slice of bytes that belong to this function.
        let func_bytes = if !code.is_empty() && size_bytes > 0 {
            let start = usize::try_from(fb.start.as_u64().wrapping_sub(base)).unwrap_or(usize::MAX);
            let end = start
                .saturating_add(usize::try_from(size_bytes).unwrap_or(usize::MAX))
                .min(code.len());
            if start < code.len() {
                &code[start..end]
            } else {
                &[]
            }
        } else {
            &[]
        };

        let call_count =
            f64::from(u32::try_from(count_call_instructions(func_bytes)).unwrap_or(u32::MAX));
        let block_count =
            f64::from(u32::try_from(estimate_block_count(func_bytes)).unwrap_or(u32::MAX));
        let string_count =
            f64::from(u32::try_from(count_string_refs(func_bytes)).unwrap_or(u32::MAX));
        let import_count =
            f64::from(u32::try_from(count_import_refs(func_bytes)).unwrap_or(u32::MAX));

        // Simple cyclomatic complexity: blocks - back-edges + 2
        // We approximate back-edges as 0 here.
        let complexity = (block_count - 0.0 + 2.0).max(1.0);

        Self {
            size,
            block_count,
            call_count,
            string_count,
            import_count,
            complexity,
            address: fb.start.as_u64(),
            name: fb.name.clone(),
        }
    }

    /// Create a synthetic feature vector with explicit values (useful for
    /// testing and manual construction).
    #[must_use]
    pub const fn new(
        address: u64,
        size: f64,
        block_count: f64,
        call_count: f64,
        string_count: f64,
        import_count: f64,
        complexity: f64,
    ) -> Self {
        Self {
            address,
            size,
            block_count,
            call_count,
            string_count,
            import_count,
            complexity,
            name: None,
        }
    }

    /// Attach a name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Return the feature values as a fixed-length array in a canonical order:
    /// `[size, block_count, call_count, string_count, import_count, complexity]`.
    #[must_use]
    pub const fn as_array(&self) -> [f64; 6] {
        [
            self.size,
            self.block_count,
            self.call_count,
            self.string_count,
            self.import_count,
            self.complexity,
        ]
    }

    /// Euclidean distance to `other`.
    #[must_use]
    pub fn euclidean_distance(&self, other: &Self) -> f64 {
        let a = self.as_array();
        let b = other.as_array();
        let sum_sq: f64 = a.iter().zip(b.iter()).map(|(x, y)| (x - y).powi(2)).sum();
        sum_sq.sqrt()
    }

    /// Cosine similarity to `other` (returns a value in [-1, 1]).
    /// Returns 0.0 when either vector is zero.
    #[must_use]
    pub fn cosine_similarity(&self, other: &Self) -> f64 {
        let a = self.as_array();
        let b = other.as_array();
        let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let norm_a: f64 = a.iter().map(|x| x.powi(2)).sum::<f64>().sqrt();
        let norm_b: f64 = b.iter().map(|x| x.powi(2)).sum::<f64>().sqrt();
        if norm_a == 0.0 || norm_b == 0.0 {
            return 0.0;
        }
        (dot / (norm_a * norm_b)).clamp(-1.0, 1.0)
    }

    /// Cosine distance (1 - `cosine_similarity`), in [0, 2].
    #[must_use]
    pub fn cosine_distance(&self, other: &Self) -> f64 {
        1.0 - self.cosine_similarity(other)
    }
}

// ---------------------------------------------------------------------------
// Private heuristic helpers
// ---------------------------------------------------------------------------

/// Count x86 CALL rel32 (E8) and CALL r/m (FF /2 = FF D*) instructions.
fn count_call_instructions(code: &[u8]) -> usize {
    let mut count = 0;
    let mut i = 0;
    while i < code.len() {
        if code[i] == 0xE8 {
            count += 1;
            i += 5;
        } else if code[i] == 0xFF && i + 1 < code.len() && (code[i + 1] & 0xF8) == 0xD0 {
            count += 1;
            i += 2;
        } else {
            i += 1;
        }
    }
    count
}

/// Estimate basic-block count from branch instructions.
fn estimate_block_count(code: &[u8]) -> usize {
    let mut branches = 0usize;
    let mut i = 0;
    while i < code.len() {
        let b = code[i];
        match b {
            // Jcc rel8 | JMP rel8 | LOOP/LOOPE/LOOPNE (all 2-byte branch instructions)
            0x70..=0x7F | 0xEB | 0xE0..=0xE2 => {
                branches += 1;
                i += 2;
            }
            // Jcc rel32 (0F 8x)
            0x0F if i + 1 < code.len() && code[i + 1] >= 0x80 && code[i + 1] <= 0x8F => {
                branches += 1;
                i += 6;
            }
            // JMP rel32
            0xE9 => {
                branches += 1;
                i += 5;
            }
            _ => {
                i += 1;
            }
        }
    }
    // block_count = branches + 1 (each branch creates a new block)
    branches + 1
}

/// Count probable string references: sequences of printable ASCII bytes ≥ 4.
fn count_string_refs(code: &[u8]) -> usize {
    let mut count = 0;
    let mut run = 0usize;
    for &b in code {
        if (0x20..0x7F).contains(&b) {
            run += 1;
        } else {
            if run >= 4 {
                count += 1;
            }
            run = 0;
        }
    }
    if run >= 4 {
        count += 1;
    }
    count
}

/// Estimate import references by counting indirect CALL through memory
/// (`FF 15 ...`), a common PLT/thunk pattern.
fn count_import_refs(code: &[u8]) -> usize {
    if code.len() < 6 {
        return 0;
    }
    let mut count = 0;
    let mut i = 0;
    while i + 5 < code.len() {
        if code[i] == 0xFF && code[i + 1] == 0x15 {
            count += 1;
            i += 6;
        } else {
            i += 1;
        }
    }
    count
}

// ---------------------------------------------------------------------------
// SimilarityMetric
// ---------------------------------------------------------------------------

/// Distance / similarity metric used during clustering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimilarityMetric {
    /// L2 Euclidean distance (lower = more similar).
    Euclidean,
    /// Cosine distance (1 − `cosine_similarity`, lower = more similar).
    Cosine,
}

impl SimilarityMetric {
    /// Compute the distance between `a` and `b` using this metric.
    #[must_use]
    pub fn distance(&self, a: &FunctionFeatures, b: &FunctionFeatures) -> f64 {
        match self {
            Self::Euclidean => a.euclidean_distance(b),
            Self::Cosine => a.cosine_distance(b),
        }
    }
}

// ---------------------------------------------------------------------------
// ClusterResult
// ---------------------------------------------------------------------------

/// The result of assigning a function to a cluster.
#[derive(Debug, Clone)]
pub struct ClusterResult {
    /// Cluster identifier (0-based).
    pub cluster_id: usize,
    /// Centroid of the cluster (average feature vector).
    pub centroid: FunctionFeatures,
    /// Addresses of all member functions.
    pub members: Vec<u64>,
}

impl ClusterResult {
    /// Return `true` if `address` is a member of this cluster.
    #[must_use]
    pub fn contains(&self, address: u64) -> bool {
        self.members.contains(&address)
    }

    /// Number of members.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.members.len()
    }
}

// ---------------------------------------------------------------------------
// FunctionCluster — a mutable cluster built during k-means
// ---------------------------------------------------------------------------

/// Internal mutable cluster used during the k-means iteration.
struct FunctionCluster {
    id: usize,
    centroid: FunctionFeatures,
    members: Vec<FunctionFeatures>,
}

impl FunctionCluster {
    const fn new(id: usize, seed: FunctionFeatures) -> Self {
        Self {
            id,
            centroid: seed,
            members: Vec::new(),
        }
    }

    fn add_member(&mut self, f: FunctionFeatures) {
        self.members.push(f);
    }

    fn clear_members(&mut self) {
        self.members.clear();
    }

    /// Recompute the centroid as the mean of member feature vectors.
    /// Returns `true` if the centroid moved (convergence check).
    fn recompute_centroid(&mut self) -> bool {
        if self.members.is_empty() {
            return false;
        }
        let n = f64::from(u32::try_from(self.members.len()).unwrap_or(u32::MAX));
        let mut sum = [0.0f64; 6];
        for m in &self.members {
            let arr = m.as_array();
            for (s, &v) in sum.iter_mut().zip(arr.iter()) {
                *s += v;
            }
        }
        let new_arr: [f64; 6] = sum.map(|s| s / n);

        let old = self.centroid.as_array();
        let moved = old
            .iter()
            .zip(new_arr.iter())
            .any(|(a, b)| (a - b).abs() > 1e-9);

        self.centroid = FunctionFeatures {
            size: new_arr[0],
            block_count: new_arr[1],
            call_count: new_arr[2],
            string_count: new_arr[3],
            import_count: new_arr[4],
            complexity: new_arr[5],
            address: self.members.first().map_or(0, |m| m.address),
            name: None,
        };
        moved
    }

    fn into_cluster_result(self) -> ClusterResult {
        let members: Vec<u64> = self.members.iter().map(|m| m.address).collect();
        ClusterResult {
            cluster_id: self.id,
            centroid: self.centroid,
            members,
        }
    }
}

// ---------------------------------------------------------------------------
// ClusteringConfig
// ---------------------------------------------------------------------------

/// Parameters for the clustering algorithm.
#[derive(Debug, Clone)]
pub struct ClusteringConfig {
    /// Number of clusters (k).
    pub k: usize,
    /// Maximum number of k-means iterations.
    pub max_iterations: usize,
    /// Similarity metric used to compute distances.
    pub metric: SimilarityMetric,
    /// Minimum number of functions required to attempt clustering.
    pub min_functions: usize,
    /// Random seed for deterministic centroid initialisation.
    pub seed: u64,
}

impl Default for ClusteringConfig {
    fn default() -> Self {
        Self {
            k: 5,
            max_iterations: 100,
            metric: SimilarityMetric::Euclidean,
            min_functions: 2,
            seed: 42,
        }
    }
}

// ---------------------------------------------------------------------------
// FunctionClusterer
// ---------------------------------------------------------------------------

/// Clusters similar functions using feature vectors and k-means.
///
/// # Example
/// ```rust,no_run
/// use rustre_analysis_fn::function_clustering::{FunctionClusterer, FunctionFeatures, ClusteringConfig};
///
/// let features = vec![
///     FunctionFeatures::new(0x1000, 100.0, 5.0, 3.0, 2.0, 1.0, 4.0),
///     FunctionFeatures::new(0x2000, 200.0, 10.0, 6.0, 4.0, 2.0, 8.0),
/// ];
/// let config = ClusteringConfig { k: 2, ..Default::default() };
/// let results = FunctionClusterer::cluster(&features, &config);
/// ```
pub struct FunctionClusterer;

impl FunctionClusterer {
    /// Run k-means clustering on `features` with the given `config`.
    ///
    /// Returns one [`ClusterResult`] per cluster. If `features.len() < config.min_functions`
    /// or `k == 0`, returns an empty vec.
    #[must_use]
    pub fn cluster(features: &[FunctionFeatures], config: &ClusteringConfig) -> Vec<ClusterResult> {
        if features.len() < config.min_functions || config.k == 0 || features.is_empty() {
            return Vec::new();
        }

        let k = config.k.min(features.len());
        // `k` can only be 0 here if `features` is empty, which is already
        // excluded above, but guard explicitly against div-by-zero in
        // `pick_seeds` (`n / k`, `seed % n`) in case that invariant changes.
        if k == 0 {
            return Vec::new();
        }

        // Initialise centroids using the first k distinct functions (deterministic).
        let seeds = Self::pick_seeds(features, k, config.seed);
        let mut clusters: Vec<FunctionCluster> = seeds
            .into_iter()
            .enumerate()
            .map(|(id, f)| FunctionCluster::new(id, f))
            .collect();

        for _iter in 0..config.max_iterations {
            // Assign step
            for c in &mut clusters {
                c.clear_members();
            }
            for f in features {
                let best = Self::nearest_cluster(&clusters, f, config.metric);
                clusters[best].add_member(f.clone());
            }

            // Update step
            let mut any_moved = false;
            for c in &mut clusters {
                if c.recompute_centroid() {
                    any_moved = true;
                }
            }

            if !any_moved {
                break;
            }
        }

        clusters
            .into_iter()
            .map(FunctionCluster::into_cluster_result)
            .collect()
    }

    /// Return the cluster index whose centroid is nearest to `f`.
    fn nearest_cluster(
        clusters: &[FunctionCluster],
        f: &FunctionFeatures,
        metric: SimilarityMetric,
    ) -> usize {
        clusters
            .iter()
            .enumerate()
            .map(|(i, c)| (i, metric.distance(&c.centroid, f)))
            .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map_or(0, |(i, _)| i)
    }

    /// Pick `k` seed centroids using a deterministic stride over `features`
    /// based on `seed`.
    fn pick_seeds(features: &[FunctionFeatures], k: usize, seed: u64) -> Vec<FunctionFeatures> {
        let n = features.len();
        let stride = (n / k).max(1);
        let start = usize::try_from(seed).unwrap_or(0) % n;
        let mut seeds = Vec::with_capacity(k);
        for i in 0..k {
            let idx = (start + i * stride) % n;
            seeds.push(features[idx].clone());
        }
        seeds
    }

    /// Assign a single function to the nearest cluster in `results`.
    ///
    /// Returns the `cluster_id`, or `usize::MAX` if `results` is empty.
    #[must_use]
    pub fn assign_to_cluster(
        f: &FunctionFeatures,
        results: &[ClusterResult],
        metric: SimilarityMetric,
    ) -> usize {
        results
            .iter()
            .map(|c| (c.cluster_id, metric.distance(&c.centroid, f)))
            .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map_or(usize::MAX, |(id, _)| id)
    }

    /// Compute intra-cluster variance (mean squared distance from centroid)
    /// for a single [`ClusterResult`] using the given feature list.
    #[must_use]
    pub fn intra_cluster_variance(
        cluster: &ClusterResult,
        features: &[FunctionFeatures],
        metric: SimilarityMetric,
    ) -> f64 {
        let members: Vec<&FunctionFeatures> = features
            .iter()
            .filter(|f| cluster.members.contains(&f.address))
            .collect();
        if members.is_empty() {
            return 0.0;
        }
        let sum_sq: f64 = members
            .iter()
            .map(|m| metric.distance(&cluster.centroid, m).powi(2))
            .sum();
        sum_sq / f64::from(u32::try_from(members.len()).unwrap_or(u32::MAX))
    }

    /// Build feature vectors from a list of boundaries and a code slice.
    ///
    /// `base` is the virtual address at which `code` is loaded.
    #[must_use]
    pub fn features_from_boundaries(
        boundaries: &[FunctionBoundary],
        code: &[u8],
        base: u64,
    ) -> Vec<FunctionFeatures> {
        boundaries
            .iter()
            .map(|fb| FunctionFeatures::from_boundary(fb, code, base))
            .collect()
    }

    /// Return a summary: number of clusters, sizes, and mean variance.
    #[must_use]
    pub fn summarise(
        results: &[ClusterResult],
        features: &[FunctionFeatures],
        metric: SimilarityMetric,
    ) -> ClusteringSummary {
        let cluster_count = results.len();
        let total_functions: usize = results.iter().map(ClusterResult::size).sum();
        let sizes: Vec<usize> = results.iter().map(ClusterResult::size).collect();
        let mean_variance: f64 = if results.is_empty() {
            0.0
        } else {
            results
                .iter()
                .map(|c| Self::intra_cluster_variance(c, features, metric))
                .sum::<f64>()
                / f64::from(u32::try_from(results.len()).unwrap_or(u32::MAX))
        };
        ClusteringSummary {
            cluster_count,
            total_functions,
            sizes,
            mean_variance,
        }
    }
}

/// High-level summary of a clustering run.
#[derive(Debug, Clone)]
pub struct ClusteringSummary {
    /// Number of clusters produced.
    pub cluster_count: usize,
    /// Total number of functions clustered.
    pub total_functions: usize,
    /// Per-cluster sizes in `cluster_id` order.
    pub sizes: Vec<usize>,
    /// Mean intra-cluster variance.
    pub mean_variance: f64,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_feature(addr: u64, size: f64, calls: f64) -> FunctionFeatures {
        FunctionFeatures::new(addr, size, 1.0, calls, 0.0, 0.0, 1.0)
    }

    // ── FunctionFeatures ──────────────────────────────────────────────────────

    #[test]
    fn features_as_array_has_six_elements() {
        let f = make_feature(0x1000, 100.0, 5.0);
        let arr = f.as_array();
        assert_eq!(arr.len(), 6);
        assert!((arr[0] - 100.0).abs() < 1e-9);
    }

    #[test]
    fn euclidean_distance_identical_is_zero() {
        let f = make_feature(0x1000, 100.0, 5.0);
        assert!(f.euclidean_distance(&f).abs() < 1e-9);
    }

    #[test]
    fn euclidean_distance_known_value() {
        let a = FunctionFeatures::new(0, 3.0, 0.0, 4.0, 0.0, 0.0, 2.0);
        let b = FunctionFeatures::new(0, 0.0, 0.0, 0.0, 0.0, 0.0, 2.0);
        // sqrt(9 + 16) = 5
        assert!((a.euclidean_distance(&b) - 5.0).abs() < 1e-9);
    }

    #[test]
    fn cosine_similarity_identical_is_one() {
        let f = make_feature(0x1000, 100.0, 5.0);
        let sim = f.cosine_similarity(&f);
        assert!((sim - 1.0).abs() < 1e-9);
    }

    #[test]
    fn cosine_similarity_orthogonal_is_zero() {
        let a = FunctionFeatures::new(0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0);
        let b = FunctionFeatures::new(0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0);
        // size=1 vs block_count=1: not all zeros, dot product = 0
        assert!(a.cosine_similarity(&b).abs() < 1e-9);
    }

    #[test]
    fn cosine_similarity_zero_vector_returns_zero() {
        let a = FunctionFeatures::new(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0);
        let b = make_feature(0, 100.0, 5.0);
        assert_eq!(a.cosine_similarity(&b), 0.0);
    }

    #[test]
    fn cosine_distance_complementary_to_similarity() {
        let a = make_feature(0, 100.0, 5.0);
        let b = make_feature(0, 200.0, 10.0);
        let sim = a.cosine_similarity(&b);
        let dist = a.cosine_distance(&b);
        assert!((sim + dist - 1.0).abs() < 1e-9);
    }

    #[test]
    fn features_with_name() {
        let f = make_feature(0x1000, 100.0, 5.0).with_name("main");
        assert_eq!(f.name.as_deref(), Some("main"));
    }

    // ── SimilarityMetric ──────────────────────────────────────────────────────

    #[test]
    fn similarity_metric_euclidean_dispatch() {
        let a = make_feature(0, 3.0, 4.0);
        let b = make_feature(0, 0.0, 0.0);
        let d = SimilarityMetric::Euclidean.distance(&a, &b);
        assert!(d > 0.0);
    }

    #[test]
    fn similarity_metric_cosine_dispatch() {
        // Test bug fix: `make_feature` injects nonzero constants for block_count
        // and complexity, so make_feature-built vectors are never orthogonal.
        // Construct orthogonal feature vectors directly to test Cosine dispatch.
        let a = FunctionFeatures::new(0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0);
        let b = FunctionFeatures::new(0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0);
        let d = SimilarityMetric::Cosine.distance(&a, &b);
        assert!((d - 1.0).abs() < 1e-9);
    }

    // ── ClusterResult ─────────────────────────────────────────────────────────

    #[test]
    fn cluster_result_contains() {
        let cr = ClusterResult {
            cluster_id: 0,
            centroid: make_feature(0, 0.0, 0.0),
            members: vec![0x1000, 0x2000],
        };
        assert!(cr.contains(0x1000));
        assert!(!cr.contains(0x3000));
        assert_eq!(cr.size(), 2);
    }

    // ── FunctionClusterer ─────────────────────────────────────────────────────

    #[test]
    fn cluster_empty_input_returns_empty() {
        let config = ClusteringConfig::default();
        let result = FunctionClusterer::cluster(&[], &config);
        assert!(result.is_empty());
    }

    #[test]
    fn cluster_empty_input_with_zero_min_functions_does_not_panic() {
        // Regression test: `min_functions: 0` combined with an empty
        // `features` slice used to reach `pick_seeds` with `n == 0`,
        // causing a division-by-zero panic (`n / k`, `seed % n`) since only
        // the *original* `config.k` (not the post-`.min()` effective `k`)
        // was checked for zero.
        let config = ClusteringConfig {
            min_functions: 0,
            k: 5,
            ..Default::default()
        };
        let result = FunctionClusterer::cluster(&[], &config);
        assert!(result.is_empty());
    }

    #[test]
    fn cluster_below_min_functions_returns_empty() {
        let config = ClusteringConfig {
            min_functions: 5,
            k: 2,
            ..Default::default()
        };
        let features = vec![make_feature(0, 1.0, 1.0), make_feature(1, 2.0, 2.0)];
        let result = FunctionClusterer::cluster(&features, &config);
        assert!(result.is_empty());
    }

    #[test]
    fn cluster_k_equals_one_puts_all_in_one_cluster() {
        let features: Vec<FunctionFeatures> = (0..10)
            .map(|i| make_feature(i as u64 * 0x100, f64::from(i) * 10.0, f64::from(i)))
            .collect();
        let config = ClusteringConfig {
            k: 1,
            ..Default::default()
        };
        let result = FunctionClusterer::cluster(&features, &config);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].size(), 10);
    }

    #[test]
    fn cluster_produces_k_clusters() {
        let features: Vec<FunctionFeatures> = (0..20)
            .map(|i| make_feature(i as u64 * 0x100, f64::from(i) * 5.0, f64::from(i) * 2.0))
            .collect();
        let config = ClusteringConfig {
            k: 4,
            ..Default::default()
        };
        let result = FunctionClusterer::cluster(&features, &config);
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn cluster_all_members_assigned() {
        let features: Vec<FunctionFeatures> = (0..15)
            .map(|i| make_feature(i as u64 * 0x100, f64::from(i) * 10.0, f64::from(i)))
            .collect();
        let config = ClusteringConfig {
            k: 3,
            ..Default::default()
        };
        let result = FunctionClusterer::cluster(&features, &config);
        let total: usize = result.iter().map(super::ClusterResult::size).sum();
        assert_eq!(total, features.len());
    }

    #[test]
    fn cluster_cosine_metric_does_not_panic() {
        let features: Vec<FunctionFeatures> = (1..10)
            .map(|i| make_feature(i as u64 * 0x100, f64::from(i) * 20.0, f64::from(i) * 3.0))
            .collect();
        let config = ClusteringConfig {
            k: 3,
            metric: SimilarityMetric::Cosine,
            ..Default::default()
        };
        let result = FunctionClusterer::cluster(&features, &config);
        assert!(!result.is_empty());
    }

    #[test]
    fn assign_to_cluster_returns_nearest() {
        let features: Vec<FunctionFeatures> =
            vec![make_feature(0, 1.0, 1.0), make_feature(1, 100.0, 100.0)];
        let config = ClusteringConfig {
            k: 2,
            ..Default::default()
        };
        let results = FunctionClusterer::cluster(&features, &config);

        // A very small function should go to the cluster with the smaller centroid.
        let query = make_feature(999, 1.5, 1.5);
        let cluster_id =
            FunctionClusterer::assign_to_cluster(&query, &results, SimilarityMetric::Euclidean);
        // The assigned cluster must be a valid id
        assert!(results.iter().any(|c| c.cluster_id == cluster_id));
    }

    #[test]
    fn intra_cluster_variance_zero_for_single_member() {
        let f = make_feature(0, 50.0, 5.0);
        let cr = ClusterResult {
            cluster_id: 0,
            centroid: f.clone(),
            members: vec![0],
        };
        let var = FunctionClusterer::intra_cluster_variance(&cr, &[f], SimilarityMetric::Euclidean);
        assert!(var < 1e-9);
    }

    #[test]
    fn summarise_reports_correct_count() {
        let features: Vec<FunctionFeatures> = (0..12)
            .map(|i| make_feature(i as u64 * 0x100, f64::from(i) * 10.0, f64::from(i)))
            .collect();
        let config = ClusteringConfig {
            k: 3,
            ..Default::default()
        };
        let results = FunctionClusterer::cluster(&features, &config);
        let summary =
            FunctionClusterer::summarise(&results, &features, SimilarityMetric::Euclidean);
        assert_eq!(summary.cluster_count, 3);
        assert_eq!(summary.total_functions, 12);
    }

    // ── Heuristic helpers ─────────────────────────────────────────────────────

    #[test]
    fn count_calls_basic() {
        // E8 00 00 00 00  — CALL rel32 to self+5
        let code = [0xE8u8, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(count_call_instructions(&code), 1);
    }

    #[test]
    fn estimate_block_count_minimum_one() {
        let code = [0x90u8; 16]; // all NOPs, no branches
        assert_eq!(estimate_block_count(&code), 1);
    }

    #[test]
    fn estimate_block_count_with_branches() {
        // 3 x JCC rel8 (74 xx)
        let code = [0x74u8, 0x00, 0x74, 0x00, 0x74, 0x00];
        assert_eq!(estimate_block_count(&code), 4); // 3 branches + 1
    }

    #[test]
    fn count_string_refs_finds_ascii_run() {
        let mut code = vec![0x00u8; 4];
        code.extend_from_slice(b"Hello"); // 5 printable bytes
        assert_eq!(count_string_refs(&code), 1);
    }

    #[test]
    fn count_string_refs_short_run_not_counted() {
        let code = b"AB\x00"; // only 2 printable bytes
        assert_eq!(count_string_refs(code), 0);
    }

    #[test]
    fn count_import_refs_counts_ff15() {
        let code = [0xFF, 0x15, 0x00, 0x00, 0x00, 0x00u8]; // CALL [rip+0]
        assert_eq!(count_import_refs(&code), 1);
    }

    // ── features_from_boundaries ──────────────────────────────────────────────

    #[test]
    fn features_from_boundaries_produces_correct_count() {
        let boundaries = vec![
            FunctionBoundary::new(
                Address::new(0),
                Confidence::High,
                DetectionSource::ProloguePattern,
            )
            .with_end(Address::new(16)),
            FunctionBoundary::new(
                Address::new(16),
                Confidence::Medium,
                DetectionSource::CallTarget,
            )
            .with_end(Address::new(32)),
        ];
        let code = vec![0x90u8; 64];
        let feats = FunctionClusterer::features_from_boundaries(&boundaries, &code, 0);
        assert_eq!(feats.len(), 2);
    }

    #[test]
    fn features_from_boundaries_huge_end_does_not_overflow() {
        // Regression test: a malformed/corrupted boundary with `end` far
        // beyond `start` (e.g. from bad input data) used to compute
        // `start + size_bytes` with plain `+`, which panics on overflow in
        // debug builds once both operands approach `usize::MAX`. It must now
        // saturate instead of overflowing.
        let boundaries = vec![FunctionBoundary::new(
            Address::new(u64::MAX - 4),
            Confidence::High,
            DetectionSource::ProloguePattern,
        )
        .with_end(Address::new(u64::MAX))];
        let code = vec![0x90u8; 64];
        // base = 0, so `start` derived from `fb.start` wraps to a huge usize,
        // and `size_bytes` is also huge; the addition must not panic.
        let feats = FunctionClusterer::features_from_boundaries(&boundaries, &code, 0);
        assert_eq!(feats.len(), 1);
    }
}
