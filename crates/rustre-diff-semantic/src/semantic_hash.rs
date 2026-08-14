//! Semantic hash — normalised per-function hash for binary diffing.
//!
//! Provides:
//! - `SemanticHash` — top-level per-function semantic hash
//! - `FunctionSemanticHash` — α-renamed, constant-normalised IL hash
//! - `BasicBlockHash` — hash for a single basic block
//! - `CallPatternHash` — hash of the call pattern (callee fingerprints)
//! - `SemanticNormalizer` — normalises an IL representation
//! - `HashCollision` — records and resolves hash collisions

use std::collections::HashMap;
use std::fmt;

fn count_as_f64(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

fn u64_as_f64(n: u64) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

// ── FNV-1a helper ─────────────────────────────────────────────────────────────

fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// FNV-1a hash of a single `u64` value, encoded little-endian.
#[must_use] 
pub fn fnv1a_u64(v: u64) -> u64 {
    fnv1a(&v.to_le_bytes())
}

const fn mix(a: u64, b: u64) -> u64 {
    a.wrapping_mul(0x517c_c1b7_2722_0a95).wrapping_add(b)
}

// ── BasicBlockHash ────────────────────────────────────────────────────────────

/// Hash of a single basic block's IL.
///
/// Computed from the sequence of normalised opcode identifiers in the block,
/// independent of operand values and register names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BasicBlockHash {
    /// The hash value.
    pub value: u64,
    /// Number of instructions in the block.
    pub instr_count: u32,
    /// Whether the block ends with a conditional branch.
    pub has_cond_branch: bool,
    /// Whether the block ends with an unconditional branch or return.
    pub has_term: bool,
}

impl BasicBlockHash {
    /// Compute a basic-block hash from a list of opcode identifiers.
    ///
    /// Each opcode is a small integer (e.g. mnemonic-to-number mapping).
    #[must_use]
    pub fn compute(opcodes: &[u32], has_cond_branch: bool, has_term: bool) -> Self {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &op in opcodes {
            h = mix(h, u64::from(op));
        }
        Self {
            value: h,
            // Saturate rather than wrapping if the caller passes an absurdly large block.
            instr_count: u32::try_from(opcodes.len()).unwrap_or(u32::MAX),
            has_cond_branch,
            has_term,
        }
    }

    /// Combine two block hashes (order-sensitive).
    #[must_use]
    pub const fn combine(&self, other: &Self) -> u64 {
        mix(self.value, other.value)
    }
}

impl fmt::Display for BasicBlockHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BBHash({:#016x} instrs={})",
            self.value, self.instr_count
        )
    }
}

// ── CallPatternHash ───────────────────────────────────────────────────────────

/// Hash encoding the call pattern of a function.
///
/// Independent of call-site order; uses a multiset (sorted call-target hashes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallPatternHash {
    /// Hash of the sorted call-target hash list.
    pub value: u64,
    /// Number of call sites.
    pub call_count: u32,
}

impl CallPatternHash {
    /// Compute from a list of call-target hashes.
    #[must_use]
    pub fn compute(callee_hashes: &[u64]) -> Self {
        let mut sorted = callee_hashes.to_vec();
        sorted.sort_unstable();
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for &c in &sorted {
            h = mix(h, c);
        }
        Self {
            value: h,
            call_count: u32::try_from(callee_hashes.len()).unwrap_or(u32::MAX),
        }
    }

    /// Empty call pattern (no callees).
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            value: 0,
            call_count: 0,
        }
    }

    /// Jaccard-like overlap similarity between two call patterns.
    ///
    /// Based on sorted arrays; O(n log n).
    #[must_use]
    pub fn similarity(a_hashes: &[u64], b_hashes: &[u64]) -> f64 {
        if a_hashes.is_empty() && b_hashes.is_empty() {
            return 1.0;
        }
        let mut a: Vec<u64> = a_hashes.to_vec();
        a.sort_unstable();
        let mut b: Vec<u64> = b_hashes.to_vec();
        b.sort_unstable();
        let mut i = 0;
        let mut j = 0;
        let mut intersection = 0usize;
        while i < a.len() && j < b.len() {
            match a[i].cmp(&b[j]) {
                std::cmp::Ordering::Equal => {
                    intersection += 1;
                    i += 1;
                    j += 1;
                }
                std::cmp::Ordering::Less => i += 1,
                std::cmp::Ordering::Greater => j += 1,
            }
        }
        let union = a.len() + b.len() - intersection;
        if union == 0 {
            1.0
        } else {
            count_as_f64(intersection) / count_as_f64(union)
        }
    }
}

// ── SemanticNormalizer ────────────────────────────────────────────────────────

/// Normalises an IL-like representation before hashing.
///
/// Performs:
/// - α-renaming: replaces all register/variable names with sequential ids.
/// - constant normalisation: replaces large constants (>= threshold) with 0.
/// - dead-store elimination: removes stores whose result is never used.
pub struct SemanticNormalizer {
    /// Constants >= this threshold are replaced with zero.
    pub const_threshold: u64,
    /// Whether to strip store-then-load of the same register.
    pub dead_store_elim: bool,
}

impl Default for SemanticNormalizer {
    fn default() -> Self {
        Self {
            const_threshold: 0x1000,
            dead_store_elim: true,
        }
    }
}

impl SemanticNormalizer {
    /// Create a normalizer with custom settings.
    #[must_use]
    pub const fn new(const_threshold: u64, dead_store_elim: bool) -> Self {
        Self {
            const_threshold,
            dead_store_elim,
        }
    }

    /// Normalise a sequence of `(opcode, operand1, operand2)` triples.
    ///
    /// - `opcode` is unchanged.
    /// - Operands that look like register ids are renamed sequentially.
    /// - Operands that are treated as constants (>= `const_threshold`) are zeroed.
    ///
    /// Returns the normalised sequence as a flat `Vec<u32>`.
    #[must_use]
    pub fn normalise(&self, triples: &[(u32, u64, u64)]) -> Vec<u32> {
        let mut reg_map: HashMap<u64, u32> = HashMap::new();
        let mut next_id: u32 = 0;
        let mut out = Vec::with_capacity(triples.len() * 3);

        let mut rename = |v: u64| -> u32 {
            if v >= self.const_threshold {
                return 0; // normalise large constants
            }
            if let Some(&id) = reg_map.get(&v) {
                return id;
            }
            let id = next_id;
            next_id += 1;
            reg_map.insert(v, id);
            id
        };

        for &(op, a, b) in triples {
            let na = rename(a);
            let nb = rename(b);
            out.push(op);
            out.push(na);
            out.push(nb);
        }

        if self.dead_store_elim {
            out = Self::eliminate_dead_stores(out);
        }

        out
    }

    /// Simple dead-store elimination: if op[i] == op[i+3] and operand1 is the same,
    /// drop op[i] (very conservative; only removes obviously overwritten registers).
    fn eliminate_dead_stores(ops: Vec<u32>) -> Vec<u32> {
        if ops.len() < 6 {
            return ops;
        }
        let mut result = Vec::with_capacity(ops.len());
        let mut i = 0;
        while i + 5 < ops.len() {
            // Check if next triple overwrites this one's destination
            let (op, dst, _) = (ops[i], ops[i + 1], ops[i + 2]);
            let (next_op, next_dst, _) = (ops[i + 3], ops[i + 4], ops[i + 5]);
            if !(op == next_op && dst == next_dst) {
                result.push(ops[i]);
                result.push(ops[i + 1]);
                result.push(ops[i + 2]);
            }
            i += 3;
        }
        // Push remaining
        while i < ops.len() {
            result.push(ops[i]);
            i += 1;
        }
        result
    }
}

// ── FunctionSemanticHash ──────────────────────────────────────────────────────

/// Normalised semantic hash for a single function.
///
/// Computed from:
/// 1. Normalised IL opcode sequence (α-renamed, constant-folded).
/// 2. Basic-block topology (block count, back-edge count).
/// 3. Call pattern (callee fingerprints).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSemanticHash {
    /// The final combined hash.
    pub hash: u64,
    /// Hash of the normalised IL opcode sequence.
    pub il_hash: u64,
    /// Hash of the basic-block topology.
    pub topology_hash: u64,
    /// Hash of the call pattern.
    pub call_hash: u64,
    /// Source address.
    pub address: u64,
    /// Block count.
    pub block_count: u32,
    /// Call count.
    pub call_count: u32,
}

impl FunctionSemanticHash {
    /// Build a hash from pre-computed components.
    #[must_use]
    pub fn from_components(
        address: u64,
        il_ops: &[u32],
        block_hashes: &[BasicBlockHash],
        callee_hashes: &[u64],
    ) -> Self {
        let il_hash = fnv1a(
            &il_ops
                .iter()
                .flat_map(|&v| v.to_le_bytes())
                .collect::<Vec<u8>>(),
        );
        let topology = block_hashes.iter().fold(0u64, |acc, bh| mix(acc, bh.value));
        let call_ph = CallPatternHash::compute(callee_hashes);

        let hash = mix(mix(il_hash, topology), call_ph.value);

        Self {
            hash,
            il_hash,
            topology_hash: topology,
            call_hash: call_ph.value,
            address,
            block_count: u32::try_from(block_hashes.len()).unwrap_or(u32::MAX),
            call_count: u32::try_from(callee_hashes.len()).unwrap_or(u32::MAX),
        }
    }

    /// Semantic similarity to another function hash.
    ///
    /// Combines IL hash equality, topology closeness, and call-pattern overlap.
    #[must_use]
    pub fn similarity(&self, other: &Self) -> f64 {
        let il_sim = if self.il_hash == other.il_hash {
            1.0
        } else {
            0.0
        }; // exact or miss for IL hash
        let topo_sim = if self.topology_hash == other.topology_hash {
            1.0
        } else {
            0.0
        };
        let call_sim = if self.call_count == 0 && other.call_count == 0 {
            1.0
        } else {
            let a = f64::from(self.call_count);
            let b = f64::from(other.call_count);
            a.min(b) / a.max(b).max(1.0)
        };
        0.20f64.mul_add(call_sim, 0.50f64.mul_add(il_sim, 0.30 * topo_sim))
    }

    /// Whether two function hashes are identical.
    #[must_use]
    pub const fn is_identical(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl fmt::Display for FunctionSemanticHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FuncHash[@{:#x}] {:#016x} blocks={} calls={}",
            self.address, self.hash, self.block_count, self.call_count
        )
    }
}

// ── SemanticHash ──────────────────────────────────────────────────────────────

/// Top-level per-function semantic hash, combining all sub-components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticHash {
    /// The function's semantic hash.
    pub func_hash: FunctionSemanticHash,
    /// The call-pattern hash.
    pub call_pattern: CallPatternHash,
    /// Symbol name.
    pub name: String,
}

impl SemanticHash {
    /// Build from a [`FunctionSemanticHash`] and a name.
    #[must_use]
    pub fn new(func_hash: FunctionSemanticHash, callee_hashes: &[u64], name: String) -> Self {
        let call_pattern = CallPatternHash::compute(callee_hashes);
        Self {
            func_hash,
            call_pattern,
            name,
        }
    }

    /// Similarity to another [`SemanticHash`].
    #[must_use]
    pub fn similarity(&self, other: &Self) -> f64 {
        self.func_hash.similarity(&other.func_hash)
    }

    /// Whether the two are byte-for-byte semantically identical.
    #[must_use]
    pub const fn is_identical(&self, other: &Self) -> bool {
        self.func_hash.is_identical(&other.func_hash)
    }
}

impl fmt::Display for SemanticHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SemanticHash[{}] {}", self.name, self.func_hash)
    }
}

// ── HashCollision ─────────────────────────────────────────────────────────────

/// Records a hash collision between two functions with the same hash value
/// but different byte content.
#[derive(Debug, Clone)]
pub struct HashCollision {
    /// The shared hash value.
    pub hash_value: u64,
    /// Address of function A.
    pub addr_a: u64,
    /// Address of function B.
    pub addr_b: u64,
    /// Name of function A.
    pub name_a: String,
    /// Name of function B.
    pub name_b: String,
    /// Whether the byte content was confirmed to differ (true = genuine collision).
    pub confirmed: bool,
}

impl HashCollision {
    /// Create a new collision record.
    #[must_use]
    pub const fn new(hash_value: u64, addr_a: u64, name_a: String, addr_b: u64, name_b: String) -> Self {
        Self {
            hash_value,
            addr_a,
            name_a,
            addr_b,
            name_b,
            confirmed: false,
        }
    }

    /// Confirm the collision by comparing raw bytes.
    pub fn confirm(&mut self, bytes_a: &[u8], bytes_b: &[u8]) {
        self.confirmed = bytes_a != bytes_b;
    }
}

impl fmt::Display for HashCollision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Collision({:#016x}): {} @ {:#x} vs {} @ {:#x} confirmed={}",
            self.hash_value, self.name_a, self.addr_a, self.name_b, self.addr_b, self.confirmed
        )
    }
}

// ── HashIndex ─────────────────────────────────────────────────────────────────

/// Index mapping hash values to function addresses, with collision detection.
#[derive(Debug, Default)]
pub struct HashIndex {
    /// hash → list of (addr, name)
    map: HashMap<u64, Vec<(u64, String)>>,
    pub collisions: Vec<HashCollision>,
}

impl HashIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a function hash into the index.
    pub fn insert(&mut self, hash: &SemanticHash) {
        let h = hash.func_hash.hash;
        let entry = self.map.entry(h).or_default();
        // Check for collision
        if !entry.is_empty() {
            for (ea, en) in entry.iter() {
                let coll = HashCollision::new(
                    h,
                    *ea,
                    en.clone(),
                    hash.func_hash.address,
                    hash.name.clone(),
                );
                self.collisions.push(coll);
            }
        }
        entry.push((hash.func_hash.address, hash.name.clone()));
    }

    /// Look up all functions with a given hash.
    #[must_use]
    pub fn lookup(&self, hash_value: u64) -> &[(u64, String)] {
        self.map
            .get(&hash_value)
            .map_or(&[], std::vec::Vec::as_slice)
    }

    /// Number of unique functions indexed (counts all inserted entries,
    /// since distinct functions may share a hash bucket).
    #[must_use]
    pub fn unique_count(&self) -> usize {
        self.map.values().map(std::vec::Vec::len).sum()
    }

    /// Number of collision records.
    #[must_use]
    pub const fn collision_count(&self) -> usize {
        self.collisions.len()
    }
}

// ── SemanticHashDb ────────────────────────────────────────────────────────────

/// Database of semantic hashes for an entire binary.
#[derive(Debug, Default)]
pub struct SemanticHashDb {
    pub hashes: HashMap<u64, SemanticHash>,
    pub index: HashIndex,
}

impl SemanticHashDb {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a function's semantic hash.
    pub fn insert(&mut self, hash: SemanticHash) {
        self.index.insert(&hash);
        self.hashes.insert(hash.func_hash.address, hash);
    }

    /// Look up by address.
    #[must_use]
    pub fn get(&self, address: u64) -> Option<&SemanticHash> {
        self.hashes.get(&address)
    }

    /// Find all functions semantically similar to `target` above `threshold`.
    #[must_use]
    pub fn similar_functions(&self, target: &SemanticHash, threshold: f64) -> Vec<(u64, f64)> {
        self.hashes
            .values()
            .filter_map(|h| {
                let sim = target.similarity(h);
                if sim >= threshold {
                    Some((h.func_hash.address, sim))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Count of indexed functions.
    #[must_use]
    pub fn function_count(&self) -> usize {
        self.hashes.len()
    }
}

// ── SemanticHashComparison ────────────────────────────────────────────────────

/// Compares two semantic hash databases and produces a diff result.
#[derive(Debug, Clone)]
pub struct SemanticHashComparison {
    pub same_count: usize,
    pub changed_count: usize,
    pub added_count: usize,
    pub removed_count: usize,
    pub mean_similarity: f64,
}

impl SemanticHashComparison {
    /// Run comparison.
    #[must_use]
    pub fn compare(db_a: &SemanticHashDb, db_b: &SemanticHashDb) -> Self {
        let (pairs, only_a, only_b) = diff_by_address(db_a, db_b);
        let same = pairs.iter().filter(|p| p.identical).count();
        let changed = pairs.iter().filter(|p| !p.identical).count();
        let mean_sim = if pairs.is_empty() {
            0.0
        } else {
            pairs.iter().map(|p| p.similarity).sum::<f64>() / count_as_f64(pairs.len())
        };
        Self {
            same_count: same,
            changed_count: changed,
            added_count: only_b.len(),
            removed_count: only_a.len(),
            mean_similarity: mean_sim,
        }
    }

    /// Overall binary similarity estimate.
    #[must_use]
    pub fn binary_similarity(&self) -> f64 {
        let total = self.same_count + self.changed_count + self.added_count + self.removed_count;
        if total == 0 {
            return 1.0;
        }
        count_as_f64(self.changed_count).mul_add(self.mean_similarity, count_as_f64(self.same_count)) / count_as_f64(total)
    }
}

// ── NormalizedILCache ─────────────────────────────────────────────────────────

/// Caches normalised IL sequences to avoid re-normalising the same IL.
#[derive(Debug, Default)]
pub struct NormalizedILCache {
    cache: std::collections::HashMap<u64, Vec<u32>>,
}

impl NormalizedILCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Normalise and cache, returning the cached result.
    pub fn get_or_insert(
        &mut self,
        key: u64,
        il: &[(u32, u64, u64)],
        norm: &SemanticNormalizer,
    ) -> &[u32] {
        self.cache.entry(key).or_insert_with(|| norm.normalise(il))
    }

    /// Cache size.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

// ── HashSimilarityMatrix ──────────────────────────────────────────────────────

/// Dense similarity matrix for a small set of semantic hashes.
#[derive(Debug, Clone)]
pub struct HashSimilarityMatrix {
    hashes: Vec<SemanticHash>,
    matrix: Vec<Vec<f64>>,
}

impl HashSimilarityMatrix {
    /// Compute a full pairwise similarity matrix.
    #[must_use]
    pub fn compute(hashes: Vec<SemanticHash>) -> Self {
        let n = hashes.len();
        let mut matrix = vec![vec![0.0f64; n]; n];
        for i in 0..n {
            for j in i..n {
                let sim = hashes[i].similarity(&hashes[j]);
                matrix[i][j] = sim;
                matrix[j][i] = sim;
            }
        }
        Self { hashes, matrix }
    }

    /// Similarity between two hashes by index.
    #[must_use]
    pub fn similarity(&self, i: usize, j: usize) -> f64 {
        self.matrix
            .get(i)
            .and_then(|row| row.get(j))
            .copied()
            .unwrap_or(0.0)
    }

    /// Find the most similar pair (i, j, similarity).
    #[must_use]
    pub fn most_similar_pair(&self) -> Option<(usize, usize, f64)> {
        let n = self.hashes.len();
        let mut best: Option<(usize, usize, f64)> = None;
        for i in 0..n {
            for j in (i + 1)..n {
                let sim = self.matrix[i][j];
                if best.as_ref().is_none_or(|b| sim > b.2) {
                    best = Some((i, j, sim));
                }
            }
        }
        best
    }

    /// Number of hashes in the matrix.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.hashes.len()
    }
}

// ── SemanticCluster ───────────────────────────────────────────────────────────

/// A cluster of semantically-similar functions.
#[derive(Debug, Clone)]
pub struct SemanticCluster {
    pub representative: u64,
    pub members: Vec<u64>,
    pub mean_similarity: f64,
}

impl SemanticCluster {
    /// Whether a hash belongs to this cluster (similarity >= threshold).
    #[must_use]
    pub fn contains(&self, addr: u64) -> bool {
        self.representative == addr || self.members.contains(&addr)
    }

    /// Number of members including the representative.
    #[must_use]
    pub const fn size(&self) -> usize {
        1 + self.members.len()
    }
}

/// Greedy single-link clustering over a set of semantic hashes.
#[must_use]
pub fn cluster_hashes(hashes: &[SemanticHash], threshold: f64) -> Vec<SemanticCluster> {
    let mut clusters: Vec<SemanticCluster> = Vec::new();
    let mut assigned = vec![false; hashes.len()];

    for (i, h) in hashes.iter().enumerate() {
        if assigned[i] {
            continue;
        }
        assigned[i] = true;
        let repr = h.func_hash.address;
        let mut members = Vec::new();
        let mut total_sim = 0.0f64;
        let mut count = 0usize;
        for (j, other) in hashes.iter().enumerate() {
            if assigned[j] {
                continue;
            }
            let sim = h.similarity(other);
            if sim >= threshold {
                assigned[j] = true;
                members.push(other.func_hash.address);
                total_sim += sim;
                count += 1;
            }
        }
        let mean_sim = if count > 0 {
            total_sim / count_as_f64(count)
        } else {
            1.0
        };
        clusters.push(SemanticCluster {
            representative: repr,
            members,
            mean_similarity: mean_sim,
        });
    }
    clusters
}

// ── SemanticHashBatch ─────────────────────────────────────────────────────────

/// Batch processor for computing semantic hashes across many functions.
pub struct SemanticHashBatch {
    pub normalizer: SemanticNormalizer,
    pub band_size: usize,
}

impl Default for SemanticHashBatch {
    fn default() -> Self {
        Self::new()
    }
}

/// Input tuple for `SemanticHashBatch::hash_all`:
/// `(address, name, il, blocks, callee_hashes)`.
pub type HashFunctionEntry = (
    u64,
    String,
    Vec<(u32, u64, u64)>,
    Vec<BasicBlockHash>,
    Vec<u64>,
);

impl SemanticHashBatch {
    #[must_use]
    pub fn new() -> Self {
        Self {
            normalizer: SemanticNormalizer::default(),
            band_size: 4,
        }
    }

    /// Hash one function from raw IL triples and block hashes.
    #[must_use]
    pub fn hash_function(
        &self,
        address: u64,
        name: String,
        il: &[(u32, u64, u64)],
        blocks: &[BasicBlockHash],
        callee_hashes: &[u64],
    ) -> SemanticHash {
        let normalized = self.normalizer.normalise(il);
        let func_hash =
            FunctionSemanticHash::from_components(address, &normalized, blocks, callee_hashes);
        SemanticHash::new(func_hash, callee_hashes, name)
    }

    /// Hash multiple functions and build a database.
    #[must_use]
    pub fn hash_all(
        &self,
        functions: &[HashFunctionEntry],
    ) -> SemanticHashDb {
        let mut db = SemanticHashDb::new();
        for (addr, name, il, blocks, callees) in functions {
            let h = self.hash_function(*addr, name.clone(), il, blocks, callees);
            db.insert(h);
        }
        db
    }
}

// ── DiffPair ──────────────────────────────────────────────────────────────────

/// A matched pair from semantic hash diffing.
#[derive(Debug, Clone)]
pub struct SemanticDiffPair {
    pub addr_a: u64,
    pub addr_b: u64,
    pub similarity: f64,
    pub identical: bool,
}

/// Diff two semantic hash databases by address-pairing.
#[must_use]
pub fn diff_by_address(
    db_a: &SemanticHashDb,
    db_b: &SemanticHashDb,
) -> (Vec<SemanticDiffPair>, Vec<u64>, Vec<u64>) {
    let mut pairs = Vec::new();
    let mut only_a = Vec::new();
    let mut only_b: Vec<u64> = db_b.hashes.keys().copied().collect();

    for (&addr, ha) in &db_a.hashes {
        if let Some(hb) = db_b.hashes.get(&addr) {
            let sim = ha.similarity(hb);
            pairs.push(SemanticDiffPair {
                addr_a: addr,
                addr_b: addr,
                similarity: sim,
                identical: ha.is_identical(hb),
            });
            only_b.retain(|&a| a != addr);
        } else {
            only_a.push(addr);
        }
    }
    only_a.sort_unstable();
    only_b.sort_unstable();
    (pairs, only_a, only_b)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bb(opcodes: &[u32]) -> BasicBlockHash {
        BasicBlockHash::compute(opcodes, false, false)
    }

    fn make_fsh(
        addr: u64,
        il: &[u32],
        bbs: &[BasicBlockHash],
        callees: &[u64],
    ) -> FunctionSemanticHash {
        FunctionSemanticHash::from_components(addr, il, bbs, callees)
    }

    fn make_sh(addr: u64, name: &str) -> SemanticHash {
        let fsh = make_fsh(addr, &[1, 2, 3], &[make_bb(&[1, 2])], &[]);
        SemanticHash::new(fsh, &[], name.to_string())
    }

    // --- BasicBlockHash ---

    #[test]
    fn test_bb_hash_deterministic() {
        let a = BasicBlockHash::compute(&[1, 2, 3], false, true);
        let b = BasicBlockHash::compute(&[1, 2, 3], false, true);
        assert_eq!(a.value, b.value);
    }

    #[test]
    fn test_bb_hash_different_opcodes() {
        let a = BasicBlockHash::compute(&[1, 2, 3], false, false);
        let b = BasicBlockHash::compute(&[4, 5, 6], false, false);
        assert_ne!(a.value, b.value);
    }

    #[test]
    fn test_bb_hash_instr_count() {
        let h = BasicBlockHash::compute(&[10, 20, 30, 40], true, false);
        assert_eq!(h.instr_count, 4);
        assert!(h.has_cond_branch);
    }

    #[test]
    fn test_bb_hash_combine() {
        let a = make_bb(&[1, 2]);
        let b = make_bb(&[3, 4]);
        let c1 = a.combine(&b);
        let c2 = a.combine(&b);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_bb_hash_display() {
        let h = make_bb(&[1]);
        let s = h.to_string();
        assert!(s.starts_with("BBHash("));
    }

    // --- CallPatternHash ---

    #[test]
    fn test_call_pattern_empty() {
        let p = CallPatternHash::empty();
        assert_eq!(p.call_count, 0);
    }

    #[test]
    fn test_call_pattern_deterministic() {
        let p1 = CallPatternHash::compute(&[100, 200, 300]);
        let p2 = CallPatternHash::compute(&[300, 100, 200]); // order shouldn't matter
        assert_eq!(p1.value, p2.value);
    }

    #[test]
    fn test_call_pattern_similarity_identical() {
        assert_eq!(CallPatternHash::similarity(&[1, 2, 3], &[1, 2, 3]), 1.0);
    }

    #[test]
    fn test_call_pattern_similarity_disjoint() {
        assert_eq!(CallPatternHash::similarity(&[1, 2], &[3, 4]), 0.0);
    }

    #[test]
    fn test_call_pattern_similarity_partial() {
        let s = CallPatternHash::similarity(&[1, 2, 3], &[2, 3, 4]);
        assert!((s - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_call_pattern_both_empty() {
        assert_eq!(CallPatternHash::similarity(&[], &[]), 1.0);
    }

    // --- SemanticNormalizer ---

    #[test]
    fn test_normalizer_const_above_threshold() {
        let n = SemanticNormalizer::new(0x1000, false);
        let triples = vec![(1u32, 0x2000u64, 0u64)]; // const above threshold → 0
        let out = n.normalise(&triples);
        assert_eq!(out[1], 0); // operand1 normalised to 0
    }

    #[test]
    fn test_normalizer_renames_regs() {
        let n = SemanticNormalizer::new(0x1000, false);
        // Two triples using same register 5 → same id
        let triples = vec![(1, 5, 0), (1, 5, 0)];
        let out = n.normalise(&triples);
        assert_eq!(out[1], out[4]); // same reg id
    }

    #[test]
    fn test_normalizer_dead_store() {
        let n = SemanticNormalizer::new(0x1000, true);
        // Two consecutive identical triples → first should be eliminated
        let triples = vec![(1, 0, 0), (1, 0, 0), (2, 1, 0)];
        let out = n.normalise(&triples);
        // With dead-store elim, first triple is dropped if next one overwrites it
        assert!(out.len() < 9);
    }

    #[test]
    fn test_normalizer_no_dead_store() {
        let n = SemanticNormalizer::new(0x1000, false);
        let triples = vec![(1, 0, 0), (2, 1, 0)];
        let out = n.normalise(&triples);
        assert_eq!(out.len(), 6);
    }

    // --- FunctionSemanticHash ---

    #[test]
    fn test_fsh_deterministic() {
        let bb = make_bb(&[1, 2, 3]);
        let a = FunctionSemanticHash::from_components(0x1000, &[1, 2], std::slice::from_ref(&bb), &[]);
        let b = FunctionSemanticHash::from_components(0x1000, &[1, 2], &[bb], &[]);
        assert_eq!(a.hash, b.hash);
    }

    #[test]
    fn test_fsh_different_il() {
        let bb = make_bb(&[1]);
        let a = FunctionSemanticHash::from_components(0x1000, &[1, 2], std::slice::from_ref(&bb), &[]);
        let b = FunctionSemanticHash::from_components(0x1000, &[3, 4], &[bb], &[]);
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn test_fsh_similarity_identical() {
        let bb = make_bb(&[1, 2]);
        let a = make_fsh(0, &[1, 2], &[bb], &[]);
        assert_eq!(a.similarity(&a), 1.0);
    }

    #[test]
    fn test_fsh_is_identical() {
        let bb = make_bb(&[1]);
        let a = make_fsh(0, &[1], std::slice::from_ref(&bb), &[]);
        let b = make_fsh(0x1000, &[1], &[bb], &[]);
        // Same IL, topology, callees → identical hash
        assert!(a.is_identical(&b));
    }

    #[test]
    fn test_fsh_display() {
        let h = make_fsh(0x1000, &[1], &[], &[]);
        let s = h.to_string();
        assert!(s.contains("0x1000"));
    }

    // --- SemanticHash ---

    #[test]
    fn test_sh_display() {
        let h = make_sh(0x1000, "main");
        assert!(h.to_string().contains("main"));
    }

    #[test]
    fn test_sh_is_identical_self() {
        let h = make_sh(0x1000, "f");
        assert!(h.is_identical(&h));
    }

    #[test]
    fn test_sh_similarity_self() {
        let h = make_sh(0x1000, "f");
        assert_eq!(h.similarity(&h), 1.0);
    }

    // --- HashCollision ---

    #[test]
    fn test_collision_confirm_different() {
        let mut c = HashCollision::new(0xAB, 0x1000, "f".to_string(), 0x2000, "g".to_string());
        c.confirm(&[1, 2, 3], &[1, 2, 4]);
        assert!(c.confirmed);
    }

    #[test]
    fn test_collision_confirm_identical() {
        let mut c = HashCollision::new(0xAB, 0x1000, "f".to_string(), 0x2000, "g".to_string());
        c.confirm(&[1, 2, 3], &[1, 2, 3]);
        assert!(!c.confirmed); // same bytes → not a genuine collision
    }

    #[test]
    fn test_collision_display() {
        let c = HashCollision::new(0xAB, 0, "f".to_string(), 1, "g".to_string());
        assert!(c.to_string().contains("Collision"));
    }

    // --- HashIndex ---

    #[test]
    fn test_hash_index_insert_lookup() {
        let mut idx = HashIndex::new();
        let h = make_sh(0x1000, "func1");
        let hash_val = h.func_hash.hash;
        idx.insert(&h);
        let hits = idx.lookup(hash_val);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_hash_index_collision_detected() {
        let mut idx = HashIndex::new();
        let h1 = make_sh(0x1000, "f1");
        let h2_hash = h1.func_hash.hash; // Same hash, different function
        let mut h2 = make_sh(0x2000, "f2");
        h2.func_hash.hash = h2_hash; // Force same hash
        idx.insert(&h1);
        idx.insert(&h2);
        assert_eq!(idx.collision_count(), 1);
    }

    #[test]
    fn test_hash_index_unique_count() {
        let mut idx = HashIndex::new();
        idx.insert(&make_sh(0x1000, "a"));
        idx.insert(&make_sh(0x2000, "b"));
        assert_eq!(idx.unique_count(), 2);
    }

    // --- SemanticHashDb ---

    #[test]
    fn test_db_insert_get() {
        let mut db = SemanticHashDb::new();
        let h = make_sh(0x1000, "main");
        db.insert(h);
        assert!(db.get(0x1000).is_some());
    }

    #[test]
    fn test_db_function_count() {
        let mut db = SemanticHashDb::new();
        db.insert(make_sh(0x1000, "f1"));
        db.insert(make_sh(0x2000, "f2"));
        assert_eq!(db.function_count(), 2);
    }

    #[test]
    fn test_db_similar_functions_self() {
        let mut db = SemanticHashDb::new();
        let h = make_sh(0x1000, "f");
        db.insert(h.clone());
        let results = db.similar_functions(&h, 0.9);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_db_similar_functions_none() {
        let db = SemanticHashDb::new();
        let h = make_sh(0x1000, "f");
        let results = db.similar_functions(&h, 0.5);
        assert!(results.is_empty());
    }

    // --- Additional BasicBlockHash tests ---

    #[test]
    fn test_bb_hash_empty_blocks_equal() {
        let a = BasicBlockHash::compute(&[], false, false);
        let b = BasicBlockHash::compute(&[], false, false);
        assert_eq!(a.value, b.value);
    }

    #[test]
    fn test_bb_hash_single_opcode() {
        let a = BasicBlockHash::compute(&[42], false, false);
        let b = BasicBlockHash::compute(&[43], false, false);
        assert_ne!(a.value, b.value);
    }

    #[test]
    fn test_bb_hash_has_term() {
        let h = BasicBlockHash::compute(&[1, 2], false, true);
        assert!(h.has_term);
    }

    // --- Additional FunctionSemanticHash tests ---

    #[test]
    fn test_fsh_block_count() {
        let bbs = vec![make_bb(&[1]), make_bb(&[2]), make_bb(&[3])];
        let h = make_fsh(0, &[1, 2], &bbs, &[]);
        assert_eq!(h.block_count, 3);
    }

    #[test]
    fn test_fsh_call_count() {
        let bb = make_bb(&[1]);
        let h = make_fsh(0, &[], &[bb], &[100, 200, 300]);
        assert_eq!(h.call_count, 3);
    }

    // --- Additional SemanticNormalizer tests ---

    #[test]
    fn test_normalizer_small_const_preserved() {
        let n = SemanticNormalizer::new(0x1000, false);
        let triples = vec![(1u32, 5u64, 0u64)]; // 5 < threshold
        let out = n.normalise(&triples);
        // reg 5 maps to id 0 (first seen)
        assert_eq!(out[1], 0); // first register id
    }

    #[test]
    fn test_normalizer_empty_input() {
        let n = SemanticNormalizer::default();
        assert!(n.normalise(&[]).is_empty());
    }

    // --- HashIndex additional ---

    #[test]
    fn test_hash_index_empty() {
        let idx = HashIndex::new();
        assert_eq!(idx.unique_count(), 0);
        assert_eq!(idx.collision_count(), 0);
    }

    #[test]
    fn test_hash_index_no_collision_different_hashes() {
        let mut idx = HashIndex::new();
        // Build two SemanticHashes with distinct IL content so their
        // FunctionSemanticHash.hash values differ (the hash ignores name/address).
        let fsh1 = make_fsh(0x1000, &[1, 2, 3], &[make_bb(&[1, 2])], &[]);
        let fsh2 = make_fsh(0x2000, &[9, 8, 7], &[make_bb(&[9, 8])], &[]);
        let h1 = SemanticHash::new(fsh1, &[], "f1".to_string());
        let h2 = SemanticHash::new(fsh2, &[], "f2".to_string());
        idx.insert(&h1);
        idx.insert(&h2);
        assert_eq!(idx.collision_count(), 0);
    }

    // --- SemanticHashDb additional ---

    #[test]
    fn test_db_overwrite_same_address() {
        let mut db = SemanticHashDb::new();
        let h1 = make_sh(0x1000, "f_v1");
        let h2 = make_sh(0x1000, "f_v2");
        db.insert(h1);
        db.insert(h2);
        // Second insert overwrites; count still 1 address but index may have 2
        assert!(db.get(0x1000).is_some());
    }

    // --- SemanticCluster tests ---

    #[test]
    fn test_cluster_contains_representative() {
        let c = SemanticCluster {
            representative: 0x1000,
            members: vec![],
            mean_similarity: 1.0,
        };
        assert!(c.contains(0x1000));
    }

    #[test]
    fn test_cluster_contains_member() {
        let c = SemanticCluster {
            representative: 0x1000,
            members: vec![0x2000],
            mean_similarity: 0.9,
        };
        assert!(c.contains(0x2000));
        assert!(!c.contains(0x3000));
    }

    #[test]
    fn test_cluster_size() {
        let c = SemanticCluster {
            representative: 0x1000,
            members: vec![0x2000, 0x3000],
            mean_similarity: 0.8,
        };
        assert_eq!(c.size(), 3);
    }

    #[test]
    fn test_cluster_empty_members() {
        let c = SemanticCluster {
            representative: 0x1000,
            members: vec![],
            mean_similarity: 1.0,
        };
        assert_eq!(c.size(), 1);
    }

    // --- cluster_hashes tests ---

    #[test]
    fn test_cluster_hashes_empty() {
        let clusters = cluster_hashes(&[], 0.8);
        assert!(clusters.is_empty());
    }

    #[test]
    fn test_cluster_hashes_single() {
        let h = make_sh(0x1000, "f");
        let clusters = cluster_hashes(&[h], 0.9);
        assert_eq!(clusters.len(), 1);
    }

    // --- SemanticHashComparison tests ---

    #[test]
    fn test_comparison_empty_dbs() {
        let db_a = SemanticHashDb::new();
        let db_b = SemanticHashDb::new();
        let c = SemanticHashComparison::compare(&db_a, &db_b);
        assert_eq!(c.same_count, 0);
        assert_eq!(c.added_count, 0);
    }

    #[test]
    fn test_comparison_binary_similarity_empty() {
        let db_a = SemanticHashDb::new();
        let db_b = SemanticHashDb::new();
        let c = SemanticHashComparison::compare(&db_a, &db_b);
        assert_eq!(c.binary_similarity(), 1.0);
    }

    // --- NormalizedILCache tests ---

    #[test]
    fn test_cache_empty() {
        let cache = NormalizedILCache::new();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_insert() {
        let mut cache = NormalizedILCache::new();
        let n = SemanticNormalizer::default();
        cache.get_or_insert(42, &[(1, 5, 0)], &n);
        assert_eq!(cache.len(), 1);
    }

    // --- HashSimilarityMatrix tests ---

    #[test]
    fn test_matrix_single_hash() {
        let h = make_sh(0x1000, "f");
        let m = HashSimilarityMatrix::compute(vec![h]);
        assert_eq!(m.count(), 1);
        assert_eq!(m.similarity(0, 0), 1.0);
    }

    #[test]
    fn test_matrix_no_pair() {
        let m = HashSimilarityMatrix::compute(vec![]);
        assert!(m.most_similar_pair().is_none());
    }

    // --- SemanticHashBatch tests ---

    #[test]
    fn test_batch_hash_function() {
        let batch = SemanticHashBatch::new();
        let il = vec![(1u32, 5u64, 0u64)];
        let bb = make_bb(&[1, 2]);
        let h = batch.hash_function(0x1000, "f".to_string(), &il, &[bb], &[]);
        assert_eq!(h.func_hash.address, 0x1000);
    }

    #[test]
    fn test_batch_hash_all_empty() {
        let batch = SemanticHashBatch::new();
        let db = batch.hash_all(&[]);
        assert_eq!(db.function_count(), 0);
    }

    // --- diff_by_address tests ---

    #[test]
    fn test_diff_by_address_same_function() {
        let mut db_a = SemanticHashDb::new();
        let mut db_b = SemanticHashDb::new();
        let h1 = make_sh(0x1000, "f");
        let h2 = make_sh(0x1000, "f");
        db_a.insert(h1);
        db_b.insert(h2);
        let (pairs, only_a, only_b) = diff_by_address(&db_a, &db_b);
        assert_eq!(pairs.len(), 1);
        assert!(only_a.is_empty());
        assert!(only_b.is_empty());
    }

    #[test]
    fn test_diff_by_address_added() {
        let db_a = SemanticHashDb::new();
        let mut db_b = SemanticHashDb::new();
        db_b.insert(make_sh(0x2000, "new_fn"));
        let (pairs, only_a, only_b) = diff_by_address(&db_a, &db_b);
        assert!(pairs.is_empty());
        assert!(only_a.is_empty());
        assert_eq!(only_b.len(), 1);
    }

    #[test]
    fn test_diff_by_address_removed() {
        let mut db_a = SemanticHashDb::new();
        let db_b = SemanticHashDb::new();
        db_a.insert(make_sh(0x1000, "old_fn"));
        let (pairs, only_a, only_b) = diff_by_address(&db_a, &db_b);
        assert!(pairs.is_empty());
        assert_eq!(only_a.len(), 1);
        assert!(only_b.is_empty());
    }
}

// ── SemanticHashStats ─────────────────────────────────────────────────────────

/// Statistics derived from a `SemanticHashDb`.
#[derive(Debug, Clone, Default)]
pub struct SemanticHashStats {
    pub total: usize,
    pub with_callees: usize,
    pub leaf_functions: usize,
    pub mean_call_count: f64,
    pub collision_count: usize,
}

impl SemanticHashStats {
    /// Compute from a database.
    #[must_use]
    pub fn compute(db: &SemanticHashDb) -> Self {
        let total = db.function_count();
        let mut with_callees = 0usize;
        let mut call_sum = 0u64;
        for h in db.hashes.values() {
            if h.func_hash.call_count > 0 {
                with_callees += 1;
                call_sum = call_sum.saturating_add(u64::from(h.func_hash.call_count));
            }
        }
        let leaf_functions = total - with_callees;
        let mean_call_count = if total > 0 {
            u64_as_f64(call_sum) / count_as_f64(total)
        } else {
            0.0_f64
        };
        let collision_count = db.index.collision_count();
        Self {
            total,
            with_callees,
            leaf_functions,
            mean_call_count,
            collision_count,
        }
    }
}

impl fmt::Display for SemanticHashStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SemanticHashStats: {} total, {} leaves, {:.1} mean_calls, {} collisions",
            self.total, self.leaf_functions, self.mean_call_count, self.collision_count
        )
    }
}

/// Check whether two semantic hashes could be the same function (fast pre-filter).
///
/// Uses call count and block count as a quick filter before more expensive comparison.
#[must_use]
pub fn quick_filter(a: &FunctionSemanticHash, b: &FunctionSemanticHash) -> bool {
    let call_ratio = if a.call_count == 0 && b.call_count == 0 {
        1.0
    } else if a.call_count == 0 || b.call_count == 0 {
        0.0
    } else {
        let lo = f64::from(a.call_count.min(b.call_count));
        let hi = f64::from(a.call_count.max(b.call_count));
        lo / hi
    };
    let block_ratio = if a.block_count == 0 && b.block_count == 0 {
        1.0
    } else if a.block_count == 0 || b.block_count == 0 {
        0.0
    } else {
        let lo = f64::from(a.block_count.min(b.block_count));
        let hi = f64::from(a.block_count.max(b.block_count));
        lo / hi
    };
    call_ratio > 0.5 && block_ratio > 0.5
}
