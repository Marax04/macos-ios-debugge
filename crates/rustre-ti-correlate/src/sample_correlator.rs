//! Malware sample correlator — TLSH distance matrix, import-hash clustering,
//! section-entropy comparison, and string-overlap scoring.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Sample descriptor
// ---------------------------------------------------------------------------

/// SHA-256 hex digest of a sample.
pub type SampleId = String;

/// Import hash (md5 of sorted comma-separated imports, lower-case).
pub type ImportHash = String;

/// A TLSH digest (72-char hex string).
pub type TlshDigest = String;

/// Compact descriptor of a malware sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleDescriptor {
    pub id: SampleId,
    /// File name (may be empty).
    pub filename: String,
    /// MD5 of raw file bytes.
    pub md5: String,
    /// SHA-1 of raw file bytes.
    pub sha1: String,
    /// TLSH locality-sensitive hash (empty if computation failed).
    pub tlsh: TlshDigest,
    /// Import hash (empty for ELF/Mach-O without symbol tables).
    pub imphash: ImportHash,
    /// Sorted list of imported function names (lower-case, unique).
    pub imports: Vec<String>,
    /// Sorted list of exported function names.
    pub exports: Vec<String>,
    /// Printable strings extracted from the binary (length ≥ 6).
    pub strings: Vec<String>,
    /// Section entropy values ordered by section index.
    pub section_entropies: Vec<f64>,
    /// Section names in order.
    pub section_names: Vec<String>,
    /// Section raw sizes in order.
    pub section_sizes: Vec<u32>,
    /// Rich header hash (PE only, empty otherwise).
    pub rich_hash: String,
    /// File size in bytes.
    pub file_size: u64,
    /// Compilation timestamp (Unix epoch, 0 if absent).
    pub compile_time: u64,
    /// File format: "PE32", "PE64", "ELF32", "ELF64", "MachO", etc.
    pub file_format: String,
    /// Detected compiler/packer tags.
    pub tags: Vec<String>,
}

impl SampleDescriptor {
    pub fn import_set(&self) -> HashSet<&str> {
        self.imports.iter().map(|s| s.as_str()).collect()
    }
    pub fn string_set(&self) -> HashSet<&str> {
        self.strings.iter().map(|s| s.as_str()).collect()
    }
}

// ---------------------------------------------------------------------------
// TLSH distance (simplified implementation)
// ---------------------------------------------------------------------------

/// Compute TLSH distance between two hex-encoded TLSH digests.
///
/// TLSH is a locality-sensitive hash where distance 0 = identical, and
/// distances < 30 indicate very similar files. This is a simplified
/// implementation that computes Hamming distance on the digest nibbles,
/// adding header-field differences.
pub fn tlsh_distance(a: &str, b: &str) -> Option<u32> {
    // TLSH digests: optionally "T1" prefix + 70 hex chars.
    let a = a.strip_prefix("T1").unwrap_or(a);
    let b = b.strip_prefix("T1").unwrap_or(b);

    if a.len() < 70 || b.len() < 70 { return None; }

    // Header: first 4 nibbles encode checksum (1), length (1), q1/q2 ratios (2).
    // Body: remaining 64 nibbles (32 bytes = 128 2-bit codes).
    let a_bytes: Vec<u8> = (0..a.len()/2)
        .filter_map(|i| u8::from_str_radix(&a[i*2..i*2+2], 16).ok())
        .collect();
    let b_bytes: Vec<u8> = (0..b.len()/2)
        .filter_map(|i| u8::from_str_radix(&b[i*2..i*2+2], 16).ok())
        .collect();

    if a_bytes.len() < 35 || b_bytes.len() < 35 { return None; }

    // Header distance (bytes 0-2).
    let mut dist: u32 = 0;

    // Checksum nibble difference (byte 0).
    dist += (a_bytes[0] as i32 - b_bytes[0] as i32).unsigned_abs();

    // Length nibble (byte 1): logarithmic scale.
    let len_diff = (a_bytes[1] as i32 - b_bytes[1] as i32).abs();
    dist += if len_diff == 0 { 0 } else if len_diff == 1 { 1 } else { len_diff as u32 * 12 };

    // Q1/Q2 ratio differences (byte 2).
    let q1a = (a_bytes[2] >> 4) as i32;
    let q1b = (b_bytes[2] >> 4) as i32;
    let q2a = (a_bytes[2] & 0x0F) as i32;
    let q2b = (b_bytes[2] & 0x0F) as i32;
    dist += mod_diff(q1a, q1b, 16) * 12;
    dist += mod_diff(q2a, q2b, 16) * 12;

    // Body: 2-bit code array (bytes 3..35).
    for i in 3..35usize {
        if i >= a_bytes.len() || i >= b_bytes.len() { break; }
        dist += tri_code_distance(a_bytes[i], b_bytes[i]);
    }

    Some(dist)
}

fn mod_diff(a: i32, b: i32, r: i32) -> u32 {
    let dl = (a - b).abs();
    let dr = r - dl;
    dl.min(dr) as u32
}

fn tri_code_distance(a: u8, b: u8) -> u32 {
    // Each byte = four 2-bit codes; distance table for 2-bit values.
    const DIST: [[u32; 4]; 4] = [
        [0, 1, 2, 6],
        [1, 0, 1, 2],
        [2, 1, 0, 1],
        [6, 2, 1, 0],
    ];
    let mut d = 0u32;
    for shift in (0..8).step_by(2) {
        let ca = ((a >> shift) & 3) as usize;
        let cb = ((b >> shift) & 3) as usize;
        d += DIST[ca][cb];
    }
    d
}

// ---------------------------------------------------------------------------
// Import-hash similarity
// ---------------------------------------------------------------------------

/// Jaccard similarity between two import sets (0.0 = no overlap, 1.0 = identical).
pub fn import_jaccard(a: &[String], b: &[String]) -> f64 {
    if a.is_empty() && b.is_empty() { return 1.0; }
    let sa: HashSet<&str> = a.iter().map(|s| s.as_str()).collect();
    let sb: HashSet<&str> = b.iter().map(|s| s.as_str()).collect();
    let inter = sa.intersection(&sb).count() as f64;
    let union = sa.union(&sb).count() as f64;
    if union == 0.0 { 1.0 } else { inter / union }
}

// ---------------------------------------------------------------------------
// Section entropy comparison
// ---------------------------------------------------------------------------

/// Compute a section-entropy similarity score between two samples.
/// Uses normalised Euclidean distance on the entropy vectors (truncated/padded to same length).
pub fn section_entropy_similarity(a: &[f64], b: &[f64]) -> f64 {
    let len = a.len().max(b.len());
    if len == 0 { return 1.0; }
    let pad = |v: &[f64]| -> Vec<f64> {
        let mut out = v.to_vec();
        out.resize(len, 0.0);
        out
    };
    let pa = pad(a);
    let pb = pad(b);
    let sq_sum: f64 = pa.iter().zip(pb.iter()).map(|(x, y)| (x - y).powi(2)).sum();
    let max_possible = len as f64 * 8.0f64.powi(2); // max entropy is ~8.0 bits
    let norm_dist = (sq_sum / max_possible).sqrt();
    (1.0 - norm_dist).max(0.0)
}

// ---------------------------------------------------------------------------
// String overlap scoring
// ---------------------------------------------------------------------------

/// String overlap score using Jaccard similarity on the string sets.
pub fn string_overlap_score(a: &[String], b: &[String]) -> f64 {
    if a.is_empty() && b.is_empty() { return 0.0; }
    let sa: HashSet<&str> = a.iter().map(|s| s.as_str()).collect();
    let sb: HashSet<&str> = b.iter().map(|s| s.as_str()).collect();
    let inter = sa.intersection(&sb).count() as f64;
    let union = sa.union(&sb).count() as f64;
    if union == 0.0 { 0.0 } else { inter / union }
}

// ---------------------------------------------------------------------------
// Pairwise correlation
// ---------------------------------------------------------------------------

/// Feature weights for the combined correlation score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationWeights {
    pub tlsh: f64,
    pub imphash_exact: f64,
    pub import_jaccard: f64,
    pub section_entropy: f64,
    pub string_overlap: f64,
    pub rich_hash_exact: f64,
    pub compile_time_proximity: f64,
}

impl Default for CorrelationWeights {
    fn default() -> Self {
        CorrelationWeights {
            tlsh: 0.30,
            imphash_exact: 0.25,
            import_jaccard: 0.15,
            section_entropy: 0.10,
            string_overlap: 0.10,
            rich_hash_exact: 0.05,
            compile_time_proximity: 0.05,
        }
    }
}

/// Individual feature scores for a sample pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureScores {
    pub tlsh_distance: Option<u32>,
    pub tlsh_score: f64,
    pub imphash_exact: bool,
    pub import_jaccard: f64,
    pub section_entropy: f64,
    pub string_overlap: f64,
    pub rich_hash_exact: bool,
    pub compile_time_diff_secs: Option<i64>,
    pub compile_time_score: f64,
    /// Combined weighted score (0.0..=1.0).
    pub combined: f64,
}

/// Compute pairwise correlation between two samples.
pub fn correlate_pair(
    a: &SampleDescriptor,
    b: &SampleDescriptor,
    weights: &CorrelationWeights,
) -> FeatureScores {
    // TLSH score: normalise distance (0 = perfect, ~200+ = unrelated).
    let (tlsh_dist, tlsh_score) = if a.tlsh.is_empty() || b.tlsh.is_empty() {
        (None, 0.0)
    } else {
        match tlsh_distance(&a.tlsh, &b.tlsh) {
            Some(d) => {
                let score = if d == 0 { 1.0 } else { (1.0 - d as f64 / 200.0).max(0.0) };
                (Some(d), score)
            }
            None => (None, 0.0),
        }
    };

    // Import hash exact match.
    let imphash_exact = !a.imphash.is_empty() && a.imphash == b.imphash;

    // Import Jaccard similarity.
    let imp_jac = import_jaccard(&a.imports, &b.imports);

    // Section entropy similarity.
    let sec_ent = section_entropy_similarity(&a.section_entropies, &b.section_entropies);

    // String overlap.
    let str_ov = string_overlap_score(&a.strings, &b.strings);

    // Rich header exact match.
    let rich_exact = !a.rich_hash.is_empty() && a.rich_hash == b.rich_hash;

    // Compile time proximity (within 7 days = score 1.0, 30 days = 0.5, >90 days = 0).
    let (ct_diff, ct_score) = if a.compile_time > 0 && b.compile_time > 0 {
        // Use abs_diff to avoid signed-unsigned confusion when compile_time
        // values exceed i64::MAX or when the cast would invert the sign.
        let diff = a.compile_time.abs_diff(b.compile_time) as i64;
        let score = if diff == 0 { 1.0 }
            else if diff < 7 * 86400 { 0.8 }
            else if diff < 30 * 86400 { 0.5 }
            else if diff < 90 * 86400 { 0.2 }
            else { 0.0 };
        (Some(diff), score)
    } else {
        (None, 0.0)
    };

    // Combined weighted score.
    let combined = weights.tlsh * tlsh_score
        + weights.imphash_exact * if imphash_exact { 1.0 } else { 0.0 }
        + weights.import_jaccard * imp_jac
        + weights.section_entropy * sec_ent
        + weights.string_overlap * str_ov
        + weights.rich_hash_exact * if rich_exact { 1.0 } else { 0.0 }
        + weights.compile_time_proximity * ct_score;

    FeatureScores {
        tlsh_distance: tlsh_dist,
        tlsh_score,
        imphash_exact,
        import_jaccard: imp_jac,
        section_entropy: sec_ent,
        string_overlap: str_ov,
        rich_hash_exact: rich_exact,
        compile_time_diff_secs: ct_diff,
        compile_time_score: ct_score,
        combined,
    }
}

// ---------------------------------------------------------------------------
// Distance matrix
// ---------------------------------------------------------------------------

/// A symmetric pairwise distance matrix for a set of samples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistanceMatrix {
    pub sample_ids: Vec<SampleId>,
    /// Row-major upper-triangular scores (combined 0.0..=1.0).
    scores: Vec<f64>,
    n: usize,
}

impl DistanceMatrix {
    /// Compute the full N×N correlation matrix (upper triangle stored).
    pub fn compute(samples: &[SampleDescriptor], weights: &CorrelationWeights) -> Self {
        let n = samples.len();
        let mut scores = vec![0.0f64; n * n];
        for i in 0..n {
            scores[i * n + i] = 1.0; // self-similarity = 1.0
            for j in (i+1)..n {
                let fs = correlate_pair(&samples[i], &samples[j], weights);
                scores[i * n + j] = fs.combined;
                scores[j * n + i] = fs.combined;
            }
        }
        DistanceMatrix {
            sample_ids: samples.iter().map(|s| s.id.clone()).collect(),
            scores,
            n,
        }
    }

    pub fn get(&self, i: usize, j: usize) -> f64 {
        if i >= self.n || j >= self.n { return 0.0; }
        self.scores[i * self.n + j]
    }

    /// Return the most similar samples for a given index.
    pub fn nearest_neighbors(&self, idx: usize, top_k: usize) -> Vec<(usize, f64)> {
        let mut neighbors: Vec<(usize, f64)> = (0..self.n)
            .filter(|&j| j != idx)
            .map(|j| (j, self.get(idx, j)))
            .collect();
        neighbors.sort_by(|a, b| b.1.total_cmp(&a.1));
        neighbors.truncate(top_k);
        neighbors
    }

    /// Find all pairs with combined score above threshold.
    pub fn similar_pairs(&self, threshold: f64) -> Vec<(usize, usize, f64)> {
        let mut pairs = Vec::new();
        for i in 0..self.n {
            for j in (i+1)..self.n {
                let s = self.get(i, j);
                if s >= threshold {
                    pairs.push((i, j, s));
                }
            }
        }
        pairs.sort_by(|a, b| b.2.total_cmp(&a.2));
        pairs
    }

    pub fn len(&self) -> usize { self.n }
    pub fn is_empty(&self) -> bool { self.n == 0 }
}

// ---------------------------------------------------------------------------
// Import-hash clustering
// ---------------------------------------------------------------------------

/// Cluster samples by exact import hash match.
///
/// Returns a map from imphash → list of sample indices with that hash.
pub fn cluster_by_imphash(samples: &[SampleDescriptor]) -> HashMap<String, Vec<usize>> {
    let mut clusters: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, sample) in samples.iter().enumerate() {
        if !sample.imphash.is_empty() {
            clusters.entry(sample.imphash.clone()).or_default().push(i);
        }
    }
    // Only keep clusters with ≥2 members.
    clusters.retain(|_, v| v.len() >= 2);
    clusters
}

// ---------------------------------------------------------------------------
// Simple hierarchical clustering (single-linkage)
// ---------------------------------------------------------------------------

/// A cluster of sample indices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleCluster {
    pub members: Vec<usize>,
    /// Average pairwise score within cluster.
    pub cohesion: f64,
    /// Representative sample index (highest average similarity to others).
    pub representative: usize,
}

impl SampleCluster {
    fn compute(members: Vec<usize>, matrix: &DistanceMatrix) -> Self {
        let n = members.len();
        if n == 1 {
            return SampleCluster { representative: members[0], members, cohesion: 1.0 };
        }
        let mut total = 0.0;
        let mut best_rep = members[0];
        let mut best_avg = 0.0;
        for (i, &a) in members.iter().enumerate() {
            let mut sum = 0.0;
            for (j, &b) in members.iter().enumerate() {
                if i != j { sum += matrix.get(a, b); }
            }
            let avg = sum / (n - 1) as f64;
            if avg > best_avg { best_avg = avg; best_rep = a; }
            total += sum;
        }
        let cohesion = total / (n * (n - 1)) as f64;
        SampleCluster { members, cohesion, representative: best_rep }
    }
}

/// Single-linkage hierarchical clustering: merge clusters whose maximum
/// pairwise score exceeds `threshold`.
pub fn cluster_samples(matrix: &DistanceMatrix, threshold: f64) -> Vec<SampleCluster> {
    let n = matrix.len();
    // Union-Find.
    let mut parent: Vec<usize> = (0..n).collect();

    fn find(parent: &mut Vec<usize>, x: usize) -> usize {
        if parent[x] != x { parent[x] = find(parent, parent[x]); }
        parent[x]
    }

    for i in 0..n {
        for j in (i+1)..n {
            if matrix.get(i, j) >= threshold {
                let pi = find(&mut parent, i);
                let pj = find(&mut parent, j);
                if pi != pj { parent[pi] = pj; }
            }
        }
    }

    // Group by root.
    let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
    for i in 0..n {
        let root = find(&mut parent, i);
        groups.entry(root).or_default().push(i);
    }

    let mut clusters: Vec<SampleCluster> = groups.into_values()
        .map(|members| SampleCluster::compute(members, matrix))
        .collect();
    clusters.sort_by(|a, b| b.members.len().cmp(&a.members.len()));
    clusters
}

// ---------------------------------------------------------------------------
// Full correlator
// ---------------------------------------------------------------------------

/// Configuration for the sample correlator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatorConfig {
    pub weights: CorrelationWeights,
    /// Score threshold for grouping samples into clusters.
    pub cluster_threshold: f64,
    /// Minimum cluster size to report.
    pub min_cluster_size: usize,
}

impl Default for CorrelatorConfig {
    fn default() -> Self {
        CorrelatorConfig {
            weights: CorrelationWeights::default(),
            cluster_threshold: 0.45,
            min_cluster_size: 2,
        }
    }
}

/// Output of a full correlation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationReport {
    pub total_samples: usize,
    pub clusters: Vec<SampleCluster>,
    pub imphash_groups: HashMap<String, Vec<usize>>,
    pub similar_pairs: Vec<(usize, usize, f64)>,
}

/// Run a full sample correlation analysis.
pub fn correlate_samples(
    samples: &[SampleDescriptor],
    config: &CorrelatorConfig,
) -> CorrelationReport {
    let matrix = DistanceMatrix::compute(samples, &config.weights);
    let mut clusters = cluster_samples(&matrix, config.cluster_threshold);
    clusters.retain(|c| c.members.len() >= config.min_cluster_size);
    let imphash_groups = cluster_by_imphash(samples);
    let similar_pairs = matrix.similar_pairs(config.cluster_threshold);

    CorrelationReport {
        total_samples: samples.len(),
        clusters,
        imphash_groups,
        similar_pairs,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sample(id: &str, imphash: &str, imports: &[&str], entropies: &[f64]) -> SampleDescriptor {
        SampleDescriptor {
            id: id.into(),
            filename: format!("{id}.exe"),
            md5: String::new(),
            sha1: String::new(),
            tlsh: String::new(),
            imphash: imphash.into(),
            imports: imports.iter().map(|s| s.to_string()).collect(),
            exports: vec![],
            strings: vec![],
            section_entropies: entropies.to_vec(),
            section_names: vec![],
            section_sizes: vec![],
            rich_hash: String::new(),
            file_size: 0,
            compile_time: 0,
            file_format: "PE32".into(),
            tags: vec![],
        }
    }

    #[test]
    fn test_import_jaccard() {
        let a = vec!["kernel32.dll!createfilew".to_string(), "ntdll.dll!ntcreatefile".to_string()];
        let b = vec!["kernel32.dll!createfilew".to_string(), "user32.dll!messagebox".to_string()];
        let score = import_jaccard(&a, &b);
        assert!((score - 1.0/3.0).abs() < 1e-9, "expected 1/3, got {score}");
    }

    #[test]
    fn test_section_entropy_similarity() {
        let a = vec![6.5, 7.2, 5.0];
        let b = vec![6.5, 7.2, 5.0];
        assert!((section_entropy_similarity(&a, &b) - 1.0).abs() < 1e-9);
        let c = vec![0.0, 0.0, 0.0];
        let score = section_entropy_similarity(&a, &c);
        assert!(score < 1.0);
    }

    #[test]
    fn test_imphash_clustering() {
        let samples = vec![
            make_sample("a", "hash1", &["kernel32.dll!createfile"], &[]),
            make_sample("b", "hash1", &["kernel32.dll!createfile"], &[]),
            make_sample("c", "hash2", &["ntdll.dll!ntopen"], &[]),
        ];
        let groups = cluster_by_imphash(&samples);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups["hash1"].len(), 2);
    }

    #[test]
    fn test_distance_matrix_self_similarity() {
        let samples = vec![
            make_sample("x", "h1", &["kernel32.dll!readfile"], &[6.0, 5.5]),
            make_sample("y", "h2", &["ntdll.dll!ntread"], &[3.0, 4.0]),
        ];
        let matrix = DistanceMatrix::compute(&samples, &CorrelationWeights::default());
        assert!((matrix.get(0, 0) - 1.0).abs() < 1e-9);
        assert!((matrix.get(1, 1) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_correlate_samples() {
        let imports_a = ["kernel32.dll!createfile", "kernel32.dll!readfile", "kernel32.dll!writefile"];
        let imports_b = ["kernel32.dll!createfile", "kernel32.dll!readfile", "kernel32.dll!closefile"];
        let samples = vec![
            make_sample("a1", "h1", &imports_a, &[6.0, 7.0]),
            make_sample("a2", "h1", &imports_a, &[6.1, 6.9]),
            make_sample("b1", "h2", &imports_b, &[3.0, 2.5]),
        ];
        let report = correlate_samples(&samples, &CorrelatorConfig::default());
        assert_eq!(report.total_samples, 3);
        // a1 and a2 share the same imphash and similar imports, should form a cluster.
        let has_pair = report.similar_pairs.iter().any(|&(i, j, s)| {
            ((i == 0 && j == 1) || (i == 1 && j == 0)) && s > 0.5
        });
        assert!(has_pair || !report.clusters.is_empty());
    }
}
