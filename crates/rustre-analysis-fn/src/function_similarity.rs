// rustre-analysis-fn/src/function_similarity.rs
//
// Function similarity: minhash signature from instruction opcodes,
// ssdeep-style fuzzy hash from bytes, LSH-based fast similarity lookup,
// cross-binary patch diffing, and cluster similar functions.

use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const MINHASH_NUM_HASHES: usize = 128;
const MINHASH_PRIME: u64 = 0xFFFF_FFFF_FFFF_FFEB; // large Mersenne-like prime
const MINHASH_MOD: u64 = 1 << 32;

const FUZZY_BLOCK_SIZE: usize = 64;
const LSH_BANDS: usize = 16;
const LSH_ROWS: usize = MINHASH_NUM_HASHES / LSH_BANDS; // 8

// ─────────────────────────────────────────────────────────────────────────────
// MinhashSig
// ─────────────────────────────────────────────────────────────────────────────

/// A `MinHash` signature computed from a function's opcode n-gram multiset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinhashSig {
    /// Function entry address.
    pub func_addr: u64,
    /// The N min-hash values.
    pub values: Vec<u32>,
}

impl MinhashSig {
    /// Compute an approximate Jaccard similarity ∈ [0.0, 1.0] with another signature.
    ///
    /// Returns `0.0` if the signatures have different lengths.
    #[must_use]
    pub fn jaccard(&self, other: &Self) -> f64 {
        if self.values.len() != other.values.len() || self.values.is_empty() {
            return 0.0;
        }
        let matches = self.values.iter().zip(&other.values).filter(|(a, b)| a == b).count();
        f64::from(u32::try_from(matches).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.values.len()).unwrap_or(u32::MAX))
    }

    /// Whether two signatures are similar above `threshold`.
    #[must_use]
    pub fn is_similar(&self, other: &Self, threshold: f64) -> bool {
        self.jaccard(other) >= threshold
    }
}

/// Compute a [`MinhashSig`] from a slice of decoded opcodes (u8 values).
///
/// We use 2-gram shingles over the opcode stream and apply N universal hash
/// functions to find the minimum hash value for each.
#[must_use]
pub fn compute_minhash(func_addr: u64, opcodes: &[u8]) -> MinhashSig {
    if opcodes.is_empty() {
        return MinhashSig { func_addr, values: vec![u32::MAX; MINHASH_NUM_HASHES] };
    }

    // Build 2-gram shingle set
    let shingles: Vec<u32> = if opcodes.len() >= 2 {
        opcodes.windows(2).map(|w| (u32::from(w[0]) << 8) | u32::from(w[1])).collect()
    } else {
        vec![u32::from(opcodes[0])]
    };

    let mut values = Vec::with_capacity(MINHASH_NUM_HASHES);
    for i in 0..MINHASH_NUM_HASHES {
        // Universal hash: h_i(x) = (a_i * x + b_i) mod p mod 2^32
        let a = hash_seed(i, 0);
        let b = hash_seed(i, 1);
        let min_val = shingles.iter()
            .map(|&s| universal_hash(u64::from(s), a, b))
            .min()
            .unwrap_or(u32::MAX);
        values.push(min_val);
    }

    MinhashSig { func_addr, values }
}

fn universal_hash(x: u64, a: u64, b: u64) -> u32 {
    // MINHASH_MOD = 2^32, so result always fits in u32.
    u32::try_from(a.wrapping_mul(x).wrapping_add(b) % MINHASH_PRIME % MINHASH_MOD)
        .unwrap_or(u32::MAX)
}

const fn hash_seed(hash_idx: usize, ab: usize) -> u64 {
    // Strong per-index seed via splitmix64 mixing. The previous version used a
    // single linear step `idx * MAGIC + ab * MAGIC2`, which produced weak,
    // mutually-correlated multipliers — most damagingly `hash_seed(0, 0) == 1`,
    // making hash function 0 the near-identity `h(x) = x + 1`, and other
    // low-index functions near-monotonic in the shingle value. Correlated /
    // near-identity hashes collapse the effective number of independent
    // minhashes, so the Jaccard estimate was biased HIGH by ~0.3 (≈7σ vs the
    // 128-hash sampling noise) — function-similarity detection over-reported
    // matches. splitmix64 gives high-entropy, independent (a, b) for every
    // (idx, ab), including idx == 0 (we offset by +1 and salt by `ab`).
    let mut z = (hash_idx as u64)
        .wrapping_add(1)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add((ab as u64).wrapping_mul(0xD1B5_4A32_D192_ED03));
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    z | 1 // ensure odd (valid multiplier for the universal hash)
}

// ─────────────────────────────────────────────────────────────────────────────
// FuzzyHash — ssdeep-inspired rolling hash
// ─────────────────────────────────────────────────────────────────────────────

/// An ssdeep-style fuzzy hash of a function's raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzyHash {
    /// Function address.
    pub func_addr: u64,
    /// Block size used.
    pub block_size: usize,
    /// First hash string (base64-like alphabet of 64 chars).
    pub hash1: String,
    /// Second hash string (double block size).
    pub hash2: String,
}

const FUZZY_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const FUZZY_HASH_LEN: usize = 64;

impl FuzzyHash {
    /// Compute the edit-distance similarity between two fuzzy hashes on [0, 100].
    #[must_use]
    pub fn similarity(&self, other: &Self) -> u32 {
        if self.hash1.is_empty() || other.hash1.is_empty() {
            return 0;
        }
        let s1 = edit_distance_similarity(&self.hash1, &other.hash1);
        let s2 = edit_distance_similarity(&self.hash2, &other.hash2);
        u32::midpoint(s1, s2)
    }

    /// Whether two fuzzy hashes are similar above `min_score` (0–100).
    #[must_use]
    pub fn is_similar(&self, other: &Self, min_score: u32) -> bool {
        self.similarity(other) >= min_score
    }
}

/// Compute an [`FuzzyHash`] from raw function bytes.
#[must_use]
pub fn compute_fuzzy_hash(func_addr: u64, bytes: &[u8]) -> FuzzyHash {
    let block_size = choose_block_size(bytes.len());

    let hash1 = rolling_hash_pass(bytes, block_size, FUZZY_HASH_LEN);
    let hash2 = rolling_hash_pass(bytes, block_size * 2, FUZZY_HASH_LEN / 2);

    FuzzyHash { func_addr, block_size, hash1, hash2 }
}

const fn choose_block_size(len: usize) -> usize {
    let mut bs = FUZZY_BLOCK_SIZE;
    while bs < len / FUZZY_HASH_LEN && bs < 0x8000 {
        bs *= 2;
    }
    bs
}

fn rolling_hash_pass(bytes: &[u8], block_size: usize, max_len: usize) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let mut result = Vec::new();
    let mut rolling = 0u32;
    for (i, &b) in bytes.iter().enumerate() {
        rolling = rolling.wrapping_mul(31).wrapping_add(u32::from(b));
        if (i + 1) % block_size.max(1) == 0 {
            let idx = (rolling as usize) % 64;
            result.push(FUZZY_ALPHABET[idx] as char);
            if result.len() >= max_len { break; }
        }
    }
    // ensure at least 1 char
    if result.is_empty() {
        let idx = bytes.last().copied().unwrap_or(0) as usize % 64;
        result.push(FUZZY_ALPHABET[idx] as char);
    }
    result.into_iter().collect()
}

/// Compute normalised edit-distance similarity in [0, 100].
fn edit_distance_similarity(a: &str, b: &str) -> u32 {
    let la = a.len();
    let lb = b.len();
    if la == 0 || lb == 0 { return 0; }
    let dist = edit_distance(a.as_bytes(), b.as_bytes());
    let max_len = u32::try_from(la.max(lb)).unwrap_or(u32::MAX);
    100u32.saturating_sub(dist * 100 / max_len)
}

fn edit_distance(a: &[u8], b: &[u8]) -> u32 {
    let (m, n) = (a.len(), b.len());
    if m == 0 { return u32::try_from(n).unwrap_or(u32::MAX); }
    if n == 0 { return u32::try_from(m).unwrap_or(u32::MAX); }
    let n32 = u32::try_from(n).unwrap_or(u32::MAX);
    let mut prev: Vec<u32> = (0..=n32).collect();
    let mut curr = vec![0u32; n + 1];
    for i in 1..=m {
        curr[0] = u32::try_from(i).unwrap_or(u32::MAX);
        for j in 1..=n {
            let cost = u32::from(a[i - 1] != b[j - 1]);
            curr[j] = (prev[j] + 1)
                .min(curr[j - 1] + 1)
                .min(prev[j - 1] + cost);
        }
        prev.clone_from(&curr);
    }
    prev[n]
}

// ─────────────────────────────────────────────────────────────────────────────
// LshBucket — Locality-Sensitive Hashing bucket
// ─────────────────────────────────────────────────────────────────────────────

/// A single LSH bucket key: band index + hash of the band's signature rows.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LshBucket {
    pub band: usize,
    pub band_hash: u64,
}

/// Compute all LSH bucket keys for a [`MinhashSig`].
#[must_use]
pub fn compute_lsh_buckets(sig: &MinhashSig) -> Vec<LshBucket> {
    let mut buckets = Vec::with_capacity(LSH_BANDS);
    for band in 0..LSH_BANDS {
        let start = band * LSH_ROWS;
        let end = (start + LSH_ROWS).min(sig.values.len());
        if start >= sig.values.len() { break; }
        let slice = &sig.values[start..end];
        let hash = fnv1a64_u32s(slice);
        buckets.push(LshBucket { band, band_hash: hash });
    }
    buckets
}

fn fnv1a64_u32s(vals: &[u32]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for &v in vals {
        for byte in v.to_le_bytes() {
            h ^= u64::from(byte);
            h = h.wrapping_mul(PRIME);
        }
    }
    h
}

// ─────────────────────────────────────────────────────────────────────────────
// LshIndex — fast approximate nearest-neighbour lookup
// ─────────────────────────────────────────────────────────────────────────────

/// LSH index that maps bucket keys to sets of function addresses.
#[derive(Debug, Default)]
pub struct LshIndex {
    /// bucket → list of (`func_addr`, `minhash_sig_index`)
    buckets: HashMap<LshBucket, Vec<u64>>,
    /// Stored signatures indexed by `func_addr`
    signatures: HashMap<u64, MinhashSig>,
}

impl LshIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a function signature into the index.
    pub fn insert(&mut self, sig: MinhashSig) {
        let buckets = compute_lsh_buckets(&sig);
        let addr = sig.func_addr;
        self.signatures.insert(addr, sig);
        for bucket in buckets {
            self.buckets.entry(bucket).or_default().push(addr);
        }
    }

    /// Query the index for functions similar to `query`.
    ///
    /// Returns a list of `(func_addr, jaccard_similarity)` pairs with
    /// similarity ≥ `min_similarity`, sorted by descending similarity.
    #[must_use]
    pub fn query(&self, query: &MinhashSig, min_similarity: f64) -> Vec<(u64, f64)> {
        let mut candidates: Vec<u64> = compute_lsh_buckets(query)
            .iter()
            .flat_map(|b| self.buckets.get(b).map_or(&[][..], Vec::as_slice))
            .copied()
            .collect();
        candidates.sort_unstable();
        candidates.dedup();
        // Remove self
        candidates.retain(|&a| a != query.func_addr);

        let mut results: Vec<(u64, f64)> = candidates
            .into_iter()
            .filter_map(|addr| {
                let sig = self.signatures.get(&addr)?;
                let j = query.jaccard(sig);
                if j >= min_similarity { Some((addr, j)) } else { None }
            })
            .collect();
        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        results
    }

    /// Number of functions indexed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SimilarFunction — pair of similar functions from two binaries
// ─────────────────────────────────────────────────────────────────────────────

/// A pair of functions from two binaries that have been identified as similar.
#[derive(Debug, Clone)]
pub struct SimilarFunction {
    /// Address in the first binary.
    pub addr_a: u64,
    /// Address in the second binary.
    pub addr_b: u64,
    /// `MinHash` Jaccard similarity.
    pub minhash_sim: f64,
    /// Fuzzy hash similarity (0–100).
    pub fuzzy_sim: u32,
    /// Combined score in [0.0, 1.0].
    pub combined_score: f64,
    /// Optional name from binary A.
    pub name_a: Option<String>,
    /// Optional name from binary B.
    pub name_b: Option<String>,
}

impl SimilarFunction {
    /// Compute `combined_score` from component similarities.
    #[must_use]
    pub fn new(addr_a: u64, addr_b: u64, minhash_sim: f64, fuzzy_sim: u32) -> Self {
        let combined_score = minhash_sim.mul_add(0.6, (f64::from(fuzzy_sim) / 100.0) * 0.4);
        Self {
            addr_a, addr_b, minhash_sim, fuzzy_sim, combined_score,
            name_a: None, name_b: None,
        }
    }
}

/// Find similar functions between two sets of signatures.
///
/// `sigs_a` — signatures from binary A.
/// `sigs_b` — signatures from binary B.
/// `min_sim` — minimum minhash Jaccard similarity.
#[must_use]
pub fn find_similar_across_binaries<SA, SB>(
    sigs_a: &[(u64, Vec<u8>)],   // (func_addr, opcodes)
    sigs_b: &[(u64, Vec<u8>)],
    bytes_a: &HashMap<u64, Vec<u8>, SA>, // func_addr → raw bytes
    bytes_b: &HashMap<u64, Vec<u8>, SB>,
    min_sim: f64,
) -> Vec<SimilarFunction>
where
    SA: std::hash::BuildHasher,
    SB: std::hash::BuildHasher,
{
    // Build index for B
    let mut index = LshIndex::new();
    let minhash_b: HashMap<u64, MinhashSig> = sigs_b
        .iter()
        .map(|(addr, opcodes)| (*addr, compute_minhash(*addr, opcodes)))
        .collect();
    for sig in minhash_b.values() {
        index.insert(sig.clone());
    }

    let mut results = Vec::new();
    for (addr_a, opcodes_a) in sigs_a {
        let query_sig = compute_minhash(*addr_a, opcodes_a);
        let candidates = index.query(&query_sig, min_sim);
        for (addr_b, minhash_sim) in candidates {
            let fuzzy_a = bytes_a.get(addr_a)
                .map_or_else(|| compute_fuzzy_hash(*addr_a, opcodes_a), |b| compute_fuzzy_hash(*addr_a, b));
            let empty = Vec::new();
            let bytes_b_val = bytes_b.get(&addr_b).unwrap_or(&empty);
            let fuzzy_b = compute_fuzzy_hash(addr_b, bytes_b_val);
            let fuzzy_sim = fuzzy_a.similarity(&fuzzy_b);
            results.push(SimilarFunction::new(*addr_a, addr_b, minhash_sim, fuzzy_sim));
        }
    }
    results.sort_by(|a, b| b.combined_score.partial_cmp(&a.combined_score)
        .unwrap_or(std::cmp::Ordering::Equal));
    results
}

// ─────────────────────────────────────────────────────────────────────────────
// FuncCluster — cluster of similar functions
// ─────────────────────────────────────────────────────────────────────────────

/// A cluster of functionally similar functions.
#[derive(Debug, Clone)]
pub struct FuncCluster {
    /// Cluster identifier (sequential).
    pub id: usize,
    /// Member function addresses and their similarities to the centroid.
    pub members: Vec<(u64, f64)>,
    /// The cluster centroid (address of the member with highest average similarity).
    pub centroid: u64,
}

impl FuncCluster {
    /// Number of functions in this cluster.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.members.len()
    }
}

/// Maximum number of functions accepted by [`cluster_similar_functions`].
///
/// The algorithm is O(n²) in both time and memory; beyond this bound an
/// untrusted-sized input would exhaust resources (dos-memory-exhaustion).
pub const CLUSTER_MAX_FUNCTIONS: usize = 4096;

// Iterative path-compressed find — avoids stack overflow on adversarially
// long parent chains when `n` is large (dos-unbounded-recursion).
fn uf_find(parent: &mut [usize], mut x: usize) -> usize {
    // Walk to root.
    let mut root = x;
    while parent[root] != root {
        root = parent[root];
    }
    // Path compression: point every node on the path directly to root.
    while parent[x] != root {
        let next = parent[x];
        parent[x] = root;
        x = next;
    }
    root
}

fn uf_union(parent: &mut [usize], x: usize, y: usize) {
    let rx = uf_find(parent, x);
    let ry = uf_find(parent, y);
    if rx != ry {
        parent[rx] = ry;
    }
}

/// Single-linkage clustering over a set of function signatures.
///
/// `sigs` — `(func_addr, opcodes)` pairs.
/// `min_sim` — minimum Jaccard similarity to place two functions in the same cluster.
#[must_use]
pub fn cluster_similar_functions(
    sigs: &[(u64, Vec<u8>)],
    min_sim: f64,
) -> Vec<FuncCluster> {
    // Cap the input to prevent O(n²) DoS from untrusted-length slices.
    let sigs = if sigs.len() > CLUSTER_MAX_FUNCTIONS {
        &sigs[..CLUSTER_MAX_FUNCTIONS]
    } else {
        sigs
    };
    let n = sigs.len();
    if n == 0 {
        return Vec::new();
    }

    // Compute all minhash signatures
    let all_sigs: Vec<MinhashSig> = sigs.iter()
        .map(|(addr, ops)| compute_minhash(*addr, ops))
        .collect();

    // Union-Find for single-linkage clustering
    let mut parent: Vec<usize> = (0..n).collect();

    for i in 0..n {
        for j in (i + 1)..n {
            let sim = all_sigs[i].jaccard(&all_sigs[j]);
            if sim >= min_sim {
                uf_union(&mut parent, i, j);
            }
        }
    }

    // Group by root
    let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
    for i in 0..n {
        let root = uf_find(&mut parent, i);
        groups.entry(root).or_default().push(i);
    }

    // `groups` is a HashMap, so its iteration order is nondeterministic
    // (hasher-seed/insertion dependent). Assigning `cluster_id` directly from
    // `.into_iter().enumerate()` would make the mapping from actual cluster
    // contents to `cluster_id` nondeterministic across runs, even though the
    // clustering itself is order-independent. Order groups by their smallest
    // member's function address (a stable, content-derived key) before
    // assigning ids so the output is fully deterministic.
    let mut ordered_groups: Vec<Vec<usize>> = groups.into_values().collect();
    ordered_groups.sort_by_key(|members| {
        members.iter().map(|&i| sigs[i].0).min().unwrap_or(u64::MAX)
    });

    let mut clusters = Vec::new();
    for (cluster_id, members) in ordered_groups.into_iter().enumerate() {
        if members.is_empty() { continue; }
        // Compute average similarity for each member to find centroid
        let mut best_avg = -1.0f64;
        let mut centroid = sigs[members[0]].0;
        let mut member_sims: Vec<(u64, f64)> = Vec::new();

        for &m in &members {
            let denom = f64::from(u32::try_from(members.len().saturating_sub(1).max(1)).unwrap_or(u32::MAX));
            let avg_sim: f64 = members.iter()
                .filter(|&&o| o != m)
                .map(|&o| all_sigs[m].jaccard(&all_sigs[o]))
                .sum::<f64>()
                / denom;
            member_sims.push((sigs[m].0, avg_sim));
            if avg_sim > best_avg {
                best_avg = avg_sim;
                centroid = sigs[m].0;
            }
        }
        clusters.push(FuncCluster {
            id: cluster_id,
            members: member_sims,
            centroid,
        });
    }

    clusters.sort_by_key(|c| c.id);
    clusters
}

// ─────────────────────────────────────────────────────────────────────────────
// Patch analysis helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Summary of differences between two similar functions (for patch analysis).
#[derive(Debug, Clone)]
pub struct PatchDiff {
    pub addr_a: u64,
    pub addr_b: u64,
    /// Bytes changed between the two functions.
    pub changed_bytes: usize,
    /// Bytes added in B but not in A.
    pub added_bytes: usize,
    /// Bytes removed in A but not in B.
    pub removed_bytes: usize,
    /// Whether the two functions are considered functionally equivalent.
    pub functionally_equivalent: bool,
}

/// Compute a byte-level diff summary between two function byte slices.
#[must_use]
pub fn compute_patch_diff(addr_a: u64, bytes_a: &[u8], addr_b: u64, bytes_b: &[u8]) -> PatchDiff {
    let min_len = bytes_a.len().min(bytes_b.len());
    let changed_bytes = bytes_a.iter().zip(bytes_b.iter())
        .filter(|(a, b)| a != b)
        .count();
    let added_bytes = bytes_b.len().saturating_sub(bytes_a.len());
    let removed_bytes = bytes_a.len().saturating_sub(bytes_b.len());

    let total = min_len.max(1);
    let change_ratio = f64::from(u32::try_from(changed_bytes + added_bytes + removed_bytes).unwrap_or(u32::MAX))
        / f64::from(u32::try_from(total).unwrap_or(u32::MAX));
    let functionally_equivalent = change_ratio < 0.05;

    PatchDiff { addr_a, addr_b, changed_bytes, added_bytes, removed_bytes, functionally_equivalent }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_opcodes(pattern: &[u8], repeat: usize) -> Vec<u8> {
        pattern.iter().cycle().take(pattern.len() * repeat).copied().collect()
    }

    #[test]
    fn minhash_identical_functions() {
        let opcodes = make_opcodes(&[0x55, 0x48, 0x89, 0xE5, 0xC3], 10);
        let sig_a = compute_minhash(0x1000, &opcodes);
        let sig_b = compute_minhash(0x2000, &opcodes);
        assert!((sig_a.jaccard(&sig_b) - 1.0).abs() < 1e-9);
    }

    /// Guards the fuzzy-hash + edit-distance siblings of the minhash (found
    /// buggy above): identical input ⇒ similarity 100 and deterministic hashes;
    /// `edit_distance` is a metric (identity of indiscernibles + symmetry).
    #[test]
    fn prop_fuzzy_hash_and_edit_distance_properties() {
        use crate::test_prng::xs;
        let mut state = 0x77a1_0f3e_5c28_9b46u64;
        for _ in 0..300 {
            let len = 1 + (xs(&mut state) % 200) as usize;
            let a: Vec<u8> = (0..len).map(|_| (xs(&mut state) & 0xFF) as u8).collect();
            // Fuzzy hash: identical input ⇒ 100, and deterministic.
            let fa = compute_fuzzy_hash(0x1000, &a);
            let fa2 = compute_fuzzy_hash(0x2000, &a);
            assert_eq!(fa.hash1, fa2.hash1, "fuzzy hash not deterministic");
            assert_eq!(fa.hash2, fa2.hash2);
            assert_eq!(fa.similarity(&fa2), 100, "identical fuzzy hashes must score 100");
            // edit_distance: metric identity + symmetry.
            let blen = (xs(&mut state) % 200) as usize;
            let b: Vec<u8> = (0..blen).map(|_| (xs(&mut state) & 0xFF) as u8).collect();
            assert_eq!(edit_distance(&a, &a), 0, "edit_distance(a,a) must be 0");
            assert_eq!(
                edit_distance(&a, &b),
                edit_distance(&b, &a),
                "edit_distance must be symmetric"
            );
            // Distance is bounded by the longer length.
            assert!(edit_distance(&a, &b) <= a.len().max(b.len()) as u32);
        }
    }

    /// Property: the minhash `jaccard` estimate approximates the TRUE Jaccard of
    /// the underlying 2-gram shingle sets (within statistical tolerance for
    /// 128 hashes, std ≈ 0.044), and the signature is deterministic. Guards the
    /// previously-untested similarity core against a biased-hash / wrong-min
    /// regression.
    #[test]
    fn prop_minhash_estimates_true_jaccard() {
        use std::collections::HashSet;
        use crate::test_prng::xs;
        // 2-gram shingle SET, computed exactly as `compute_minhash` does.
        fn shingles(ops: &[u8]) -> HashSet<u32> {
            if ops.len() >= 2 {
                ops.windows(2).map(|w| (u32::from(w[0]) << 8) | u32::from(w[1])).collect()
            } else if ops.len() == 1 {
                [u32::from(ops[0])].into_iter().collect()
            } else {
                HashSet::new()
            }
        }
        let mut state = 0x2b1c_9f77_0e51_a3d4u64;
        let mut worst = 0.0f64;
        for _ in 0..300 {
            // Build two opcode streams sharing a random prefix, so their
            // shingle sets have a controllable, non-trivial overlap.
            let shared = (xs(&mut state) % 20) as usize;
            let extra_a = (xs(&mut state) % 20) as usize;
            let extra_b = (xs(&mut state) % 20) as usize;
            let mut a: Vec<u8> = (0..shared).map(|_| (xs(&mut state) & 0xFF) as u8).collect();
            let mut b = a.clone();
            for _ in 0..extra_a { a.push((xs(&mut state) & 0xFF) as u8); }
            for _ in 0..extra_b { b.push((xs(&mut state) & 0xFF) as u8); }

            let sa = shingles(&a);
            let sb = shingles(&b);
            let union = sa.union(&sb).count();
            if union == 0 { continue; }
            let inter = sa.intersection(&sb).count();
            let true_j = inter as f64 / union as f64;

            let sig_a = compute_minhash(0x1000, &a);
            let sig_b = compute_minhash(0x2000, &b);
            // Determinism: recomputing is identical.
            assert_eq!(sig_a.values, compute_minhash(0x9999, &a).values);
            // Signatures are always full length (never short).
            assert_eq!(sig_a.values.len(), MINHASH_NUM_HASHES);

            let est = sig_a.jaccard(&sig_b);
            let err = (est - true_j).abs();
            worst = worst.max(err);
            assert!(
                err < 0.25,
                "minhash estimate {est:.3} far from true Jaccard {true_j:.3} (err {err:.3}); |A|={} |B|={} ∩={inter} ∪={union}",
                sa.len(), sb.len()
            );
        }
        // Sanity: across 300 trials the worst error stayed within tolerance.
        assert!(worst < 0.25, "worst-case error {worst:.3} exceeded tolerance");
    }

    /// Property: minhash similarity is symmetric, identical inputs give 1.0,
    /// disjoint shingle sets give near-0, and the estimate is always in [0,1].
    #[test]
    fn prop_minhash_symmetry_identity_disjoint() {
        use crate::test_prng::xs;
        let mut state = 0xaaaa_5555_1357_9bdfu64;
        for _ in 0..300 {
            let la = 1 + (xs(&mut state) % 60) as usize;
            let lb = 1 + (xs(&mut state) % 60) as usize;
            let a: Vec<u8> = (0..la).map(|_| (xs(&mut state) & 0xFF) as u8).collect();
            let b: Vec<u8> = (0..lb).map(|_| (xs(&mut state) & 0xFF) as u8).collect();
            let sa = compute_minhash(0x1000, &a);
            let sb = compute_minhash(0x2000, &b);
            // Symmetry
            assert!((sa.jaccard(&sb) - sb.jaccard(&sa)).abs() < 1e-12, "jaccard not symmetric");
            // Range
            let j = sa.jaccard(&sb);
            assert!((0.0..=1.0).contains(&j), "jaccard out of range: {j}");
            // Identity: same opcodes (different addr) → exactly 1.0
            let sa2 = compute_minhash(0x3000, &a);
            assert!((sa.jaccard(&sa2) - 1.0).abs() < 1e-12, "identical inputs must give 1.0");
        }
        // Disjoint shingle universes: bytes from {0} vs bytes from {255}
        // (2-gram shingle sets are disjoint) → near 0 within minhash noise.
        let zeros = vec![0u8; 64];
        let ffs = vec![0xFFu8; 64];
        let sz = compute_minhash(0x1, &zeros);
        let sf = compute_minhash(0x2, &ffs);
        assert!(sz.jaccard(&sf) < 0.1, "disjoint inputs must be near 0");
    }

    /// Property: LSH candidate recall. LSH banding guarantees that any pair
    /// with an IDENTICAL signature shares every band, so it is always a
    /// candidate; for merely-similar pairs recall is probabilistic BY DESIGN
    /// (16 bands x 8 rows: p(candidate) = 1-(1-j^8)^16), so we do NOT assert
    /// strict superset over a 0.8 threshold. Instead assert: (a) exact
    /// duplicates are always returned with similarity 1.0, (b) every returned
    /// pair truly satisfies `min_similarity` (no false positives past the
    /// verification step), (c) results sorted descending, (d) query never
    /// returns self, (e) determinism.
    #[test]
    fn prop_lsh_recall_and_precision() {
        use crate::test_prng::xs;
        let mut state = 0x0dd_ba11_dead_beefu64;
        for _ in 0..60 {
            // Small random corpus of 3..=10 functions.
            let m = 3 + (xs(&mut state) % 8);
            let mut sigs: Vec<MinhashSig> = Vec::new();
            for k in 0..m {
                let len = 2 + (xs(&mut state) % 40) as usize;
                let ops: Vec<u8> = (0..len).map(|_| (xs(&mut state) & 0xFF) as u8).collect();
                sigs.push(compute_minhash(0x1000 + k * 0x100, &ops));
            }
            // Plant an exact duplicate of sigs[0] at a new address.
            let mut dup = sigs[0].clone();
            dup.func_addr = 0xDD00;
            sigs.push(dup);

            let mut index = LshIndex::new();
            for s in &sigs {
                index.insert(s.clone());
            }
            let query = &sigs[0];
            let results = index.query(query, 0.8);
            // (a) exact duplicate always found with sim 1.0
            assert!(
                results.iter().any(|&(a, j)| a == 0xDD00 && (j - 1.0).abs() < 1e-12),
                "exact duplicate must always be an LSH candidate"
            );
            // (b) precision: everything returned really is >= threshold
            for &(a, j) in &results {
                assert!(j >= 0.8, "false positive {a:#x} with sim {j}");
                assert_ne!(a, query.func_addr, "query must not return self");
            }
            // (c) sorted descending
            for w in results.windows(2) {
                assert!(w[0].1 >= w[1].1, "results not sorted descending");
            }
            // (e) determinism
            assert_eq!(results, index.query(query, 0.8));
        }
    }

    #[test]
    fn minhash_different_functions_low_similarity() {
        let ops_a = make_opcodes(&[0x55, 0x48, 0x89, 0xE5, 0xC3], 8);
        let ops_b = make_opcodes(&[0xE8, 0x00, 0x00, 0x00, 0x00, 0x31, 0xC0, 0xC3], 8);
        let sig_a = compute_minhash(0x1000, &ops_a);
        let sig_b = compute_minhash(0x2000, &ops_b);
        assert!(sig_a.jaccard(&sig_b) < 0.9);
    }

    #[test]
    fn fuzzy_hash_identical_similarity() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        let h1 = compute_fuzzy_hash(0x1000, &bytes);
        let h2 = compute_fuzzy_hash(0x2000, &bytes);
        assert!(h1.similarity(&h2) > 90);
    }

    #[test]
    fn lsh_index_finds_similar() {
        let opcodes = make_opcodes(&[0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0xC3], 12);
        let sig_a = compute_minhash(0x1000, &opcodes);
        let sig_b = compute_minhash(0x2000, &opcodes);
        let mut index = LshIndex::new();
        index.insert(sig_b);
        let results = index.query(&sig_a, 0.8);
        assert!(!results.is_empty());
        assert_eq!(results[0].0, 0x2000);
    }

    #[test]
    fn lsh_index_empty_no_results() {
        let opcodes = make_opcodes(&[0xC3], 5);
        let sig = compute_minhash(0x1000, &opcodes);
        let index = LshIndex::new();
        let results = index.query(&sig, 0.5);
        assert!(results.is_empty());
    }

    #[test]
    fn cluster_single_function() {
        let sigs = vec![(0x1000u64, vec![0x55u8, 0x48, 0x89, 0xE5, 0xC3])];
        let clusters = cluster_similar_functions(&sigs, 0.5);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].size(), 1);
    }

    #[test]
    fn cluster_two_identical_functions() {
        let opcodes = make_opcodes(&[0x55, 0x48, 0x89, 0xE5, 0xC3], 10);
        let sigs = vec![
            (0x1000u64, opcodes.clone()),
            (0x2000u64, opcodes),
        ];
        let clusters = cluster_similar_functions(&sigs, 0.8);
        // Should be in the same cluster
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].size(), 2);
    }

    // ── cluster_similar_functions ────────────────────────────────────────────

    #[test]
    fn cluster_similar_functions_groups_identical_and_separates_distinct() {
        let group_a = make_opcodes(&[0x55, 0x48, 0x89, 0xE5, 0xC3], 10);
        let group_b = make_opcodes(&[0xE8, 0x00, 0x00, 0x00, 0x00, 0x31, 0xC0, 0xC3], 10);

        let sigs = vec![
            (0x1000u64, group_a.clone()),
            (0x1100u64, group_a.clone()),
            (0x2000u64, group_b.clone()),
            (0x2100u64, group_b.clone()),
        ];

        let clusters = cluster_similar_functions(&sigs, 0.9);
        assert_eq!(clusters.len(), 2, "expected two distinct clusters");
        for c in &clusters {
            assert_eq!(c.members.len(), 2);
        }
        // The two functions built from `group_a` must land in the same
        // cluster, and likewise for `group_b`.
        let cluster_of = |addr: u64| {
            clusters
                .iter()
                .find(|c| c.members.iter().any(|(a, _)| *a == addr))
                .map(|c| c.id)
        };
        assert_eq!(cluster_of(0x1000), cluster_of(0x1100));
        assert_eq!(cluster_of(0x2000), cluster_of(0x2100));
        assert_ne!(cluster_of(0x1000), cluster_of(0x2000));
    }

    #[test]
    fn cluster_similar_functions_empty_input() {
        assert!(cluster_similar_functions(&[], 0.5).is_empty());
    }

    #[test]
    fn cluster_similar_functions_deterministic_ids_across_runs() {
        // Regression test: cluster ids used to be assigned from HashMap
        // iteration order over the union-find groups, which is
        // nondeterministic across hasher seeds/insertion order. Verify that
        // repeated calls (fresh HashMap state each time) always assign the
        // same cluster id to the same set of member addresses.
        let group_a = make_opcodes(&[0x55, 0x48, 0x89, 0xE5, 0xC3], 10);
        let group_b = make_opcodes(&[0xE8, 0x00, 0x00, 0x00, 0x00, 0x31, 0xC0, 0xC3], 10);
        let group_c = make_opcodes(&[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90], 10);

        let sigs = vec![
            (0x1000u64, group_a.clone()),
            (0x1100u64, group_a.clone()),
            (0x2000u64, group_b.clone()),
            (0x2100u64, group_b.clone()),
            (0x3000u64, group_c.clone()),
            (0x3100u64, group_c.clone()),
        ];

        let first = cluster_similar_functions(&sigs, 0.9);
        for _ in 0..10 {
            let again = cluster_similar_functions(&sigs, 0.9);
            assert_eq!(
                first.iter().map(|c| (c.id, c.members.clone())).collect::<Vec<_>>(),
                again.iter().map(|c| (c.id, c.members.clone())).collect::<Vec<_>>(),
                "cluster_similar_functions must assign ids deterministically"
            );
        }
    }

    #[test]
    fn patch_diff_identical() {
        let bytes = vec![0x55u8, 0x48, 0x89, 0xE5, 0xC3];
        let diff = compute_patch_diff(0x1000, &bytes, 0x2000, &bytes);
        assert_eq!(diff.changed_bytes, 0);
        assert!(diff.functionally_equivalent);
    }

    #[test]
    fn patch_diff_one_byte_changed() {
        let a = vec![0x55u8, 0x48, 0x89, 0xE5, 0xC3];
        let mut b = a.clone();
        b[2] = 0x8B; // one byte change
        let diff = compute_patch_diff(0x1000, &a, 0x2000, &b);
        assert_eq!(diff.changed_bytes, 1);
    }

    #[test]
    fn lsh_buckets_consistent() {
        let sig = compute_minhash(0x1000, &[0x55, 0x48, 0x89, 0xE5, 0xC3]);
        let b1 = compute_lsh_buckets(&sig);
        let b2 = compute_lsh_buckets(&sig);
        assert_eq!(b1, b2);
    }

    #[test]
    fn minhash_empty_opcodes() {
        let sig = compute_minhash(0x1000, &[]);
        assert_eq!(sig.values.len(), MINHASH_NUM_HASHES);
        assert!(sig.values.iter().all(|&v| v == u32::MAX));
    }

    #[test]
    fn find_similar_across_binaries_basic() {
        let opcodes = make_opcodes(&[0x55, 0x48, 0x89, 0xE5, 0xC3, 0x31, 0xC0], 10);
        let sigs_a = vec![(0x1000u64, opcodes.clone())];
        let sigs_b = vec![(0x2000u64, opcodes.clone())];
        let bytes_a: HashMap<u64, Vec<u8>> = [(0x1000, opcodes.clone())].into();
        let bytes_b: HashMap<u64, Vec<u8>> = [(0x2000, opcodes)].into();
        let results = find_similar_across_binaries(&sigs_a, &sigs_b, &bytes_a, &bytes_b, 0.8);
        assert!(!results.is_empty());
        assert_eq!(results[0].addr_a, 0x1000);
        assert_eq!(results[0].addr_b, 0x2000);
    }
}
