//! Coverage map — basic-block hit counts, edge coverage, call coverage,
//! per-seed breakdown, and delta coverage computation.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};


// ─── Basic block record ───────────────────────────────────────────────────────

/// Coverage data for a single basic block.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BbRecord {
    /// Total number of times this BB was executed across all seeds.
    pub total_hits: u64,
    /// Per-seed hit counts: `seed_id` → `hit_count`.
    pub per_seed: HashMap<u64, u64>,
    /// Whether this block has been hit at least once.
    pub covered: bool,
}

impl BbRecord {
    pub fn record_hit(&mut self, seed_id: u64, count: u64) {
        self.total_hits += count;
        *self.per_seed.entry(seed_id).or_insert(0) += count;
        self.covered = true;
    }

    /// Seeds that cover this block.
    #[must_use] 
    pub fn covering_seeds(&self) -> Vec<u64> {
        self.per_seed.keys().copied().collect()
    }
}

// ─── Edge record ─────────────────────────────────────────────────────────────

/// A directed control-flow edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EdgeKey {
    pub src: u64,
    pub dst: u64,
}

impl EdgeKey {
    #[must_use] 
    pub const fn new(src: u64, dst: u64) -> Self { Self { src, dst } }
}

/// Coverage data for a single CFG edge.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EdgeRecord {
    pub total_hits: u64,
    pub per_seed: HashMap<u64, u64>,
}

impl EdgeRecord {
    pub fn record_hit(&mut self, seed_id: u64, count: u64) {
        self.total_hits += count;
        *self.per_seed.entry(seed_id).or_insert(0) += count;
    }
}

// ─── Call record ─────────────────────────────────────────────────────────────

/// Coverage data for a call site (caller → callee).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CallRecord {
    pub caller: u64,
    pub callee: u64,
    pub total_hits: u64,
    pub per_seed: HashMap<u64, u64>,
}

impl CallRecord {
    pub fn record_hit(&mut self, seed_id: u64, count: u64) {
        self.total_hits += count;
        *self.per_seed.entry(seed_id).or_insert(0) += count;
    }
}

// ─── CoverageMap ─────────────────────────────────────────────────────────────

/// The central coverage map: holds BB, edge, and call coverage.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CoverageMap {
    /// Basic block coverage: address → record.
    pub bbs: BTreeMap<u64, BbRecord>,
    /// Edge coverage: (src,dst) → record.
    pub edges: HashMap<EdgeKey, EdgeRecord>,
    /// Call site coverage: (caller,callee) → record.
    pub calls: HashMap<(u64, u64), CallRecord>,
    /// Known total BB addresses (populated from the binary's CFG if available).
    pub known_bbs: HashSet<u64>,
}

impl CoverageMap {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    // ── Recording ──────────────────────────────────────────────────────────

    /// Record a basic-block hit.
    pub fn record_bb(&mut self, addr: u64, seed_id: u64, count: u64) {
        self.bbs.entry(addr).or_default().record_hit(seed_id, count);
    }

    /// Record an edge traversal.
    pub fn record_edge(&mut self, src: u64, dst: u64, seed_id: u64, count: u64) {
        self.edges.entry(EdgeKey::new(src, dst)).or_default().record_hit(seed_id, count);
        // Also record both endpoints as covered BBs
        self.bbs.entry(src).or_default().record_hit(seed_id, 0); // mark as reachable
        self.bbs.entry(dst).or_default().record_hit(seed_id, count);
    }

    /// Record a call site.
    pub fn record_call(&mut self, caller: u64, target: u64, seed_id: u64, count: u64) {
        let rec = self.calls.entry((caller, target)).or_insert_with(|| CallRecord { caller, callee: target, ..Default::default() });
        rec.record_hit(seed_id, count);
    }

    /// Register all known BBs (from binary analysis, before any fuzzing).
    pub fn register_known_bbs(&mut self, addrs: impl IntoIterator<Item = u64>) {
        for addr in addrs { self.known_bbs.insert(addr); }
    }

    // ── Query ──────────────────────────────────────────────────────────────

    /// Number of unique BBs hit.
    #[must_use] 
    pub fn covered_bb_count(&self) -> usize {
        self.bbs.values().filter(|r| r.covered).count()
    }

    /// Total known BBs (0 if unknown).
    #[must_use] 
    pub fn total_known_bbs(&self) -> usize { self.known_bbs.len() }

    /// Coverage percentage (0.0 if total unknown).
    #[must_use] 
    pub fn bb_coverage_pct(&self) -> f64 {
        let total = self.known_bbs.len();
        if total == 0 { return 0.0; }
        (crate::usize_to_f64(self.covered_bb_count()) / crate::usize_to_f64(total)) * 100.0
    }

    /// Number of unique edges hit.
    #[must_use] 
    pub fn edge_count(&self) -> usize { self.edges.len() }

    /// Return BBs never hit (requires `known_bbs` to be populated).
    #[must_use] 
    pub fn uncovered_bbs(&self) -> Vec<u64> {
        self.known_bbs
            .iter()
            .filter(|&&addr| !self.bbs.get(&addr).is_some_and(|r| r.covered))
            .copied()
            .collect()
    }

    // ── Per-seed analysis ─────────────────────────────────────────────────

    /// Compute the set of BB addresses covered by a specific seed.
    #[must_use] 
    pub fn bbs_for_seed(&self, seed_id: u64) -> HashSet<u64> {
        self.bbs
            .iter()
            .filter(|(_, r)| r.per_seed.contains_key(&seed_id))
            .map(|(&addr, _)| addr)
            .collect()
    }

    /// Compute delta coverage: BBs newly covered by `seed_id` not covered by any prior seed.
    #[must_use] 
    pub fn delta_coverage(&self, seed_id: u64) -> Vec<u64> {
        let prior_seeds: HashSet<u64> = self.bbs
            .values()
            .flat_map(|r| r.per_seed.keys().copied())
            .filter(|&s| s < seed_id)
            .collect();

        let prior_coverage: HashSet<u64> = self.bbs
            .iter()
            .filter(|(_, r)| r.per_seed.keys().any(|s| prior_seeds.contains(s)))
            .map(|(&addr, _)| addr)
            .collect();

        self.bbs_for_seed(seed_id)
            .into_iter()
            .filter(|addr| !prior_coverage.contains(addr))
            .collect()
    }

    // ── Merge ─────────────────────────────────────────────────────────────

    /// Merge another coverage map into self (union).
    pub fn merge(&mut self, other: &Self) {
        for (&addr, rec) in &other.bbs {
            let self_rec = self.bbs.entry(addr).or_default();
            for (&seed, &count) in &rec.per_seed {
                self_rec.record_hit(seed, count);
            }
        }
        for (&key, rec) in &other.edges {
            let self_rec = self.edges.entry(key).or_default();
            for (&seed, &count) in &rec.per_seed {
                self_rec.record_hit(seed, count);
            }
        }
        self.known_bbs.extend(&other.known_bbs);
    }

    // ── Export ────────────────────────────────────────────────────────────

    /// Export as sorted (addr, `hit_count`) pairs — used by the heatmap.
    #[must_use] 
    pub fn bb_heatmap_data(&self) -> Vec<(u64, u64)> {
        let mut v: Vec<(u64, u64)> = self.bbs.iter().map(|(&addr, r)| (addr, r.total_hits)).collect();
        v.sort_by_key(|a| a.0);
        v
    }

    /// Produce a compact coverage summary string.
    #[must_use] 
    pub fn summary(&self) -> String {
        let mut out = String::new();
        writeln!(out, "Coverage Map Summary").ok();
        writeln!(out, "  Covered BBs : {}", self.covered_bb_count()).ok();
        if !self.known_bbs.is_empty() {
            writeln!(out, "  Total BBs   : {}", self.known_bbs.len()).ok();
            writeln!(out, "  Coverage    : {:.1}%", self.bb_coverage_pct()).ok();
        }
        writeln!(out, "  Edges       : {}", self.edge_count()).ok();
        writeln!(out, "  Call sites  : {}", self.calls.len()).ok();

        // Top-10 hottest BBs
        let mut hot: Vec<(u64, u64)> = self.bbs.iter().map(|(&a, r)| (a, r.total_hits)).collect();
        hot.sort_by_key(|b| std::cmp::Reverse(b.1));
        if !hot.is_empty() {
            writeln!(out, "  Hot BBs (top 10):").ok();
            for (addr, hits) in hot.iter().take(10) {
                writeln!(out, "    {addr:#018x}  {hits} hits").ok();
            }
        }
        out
    }

    /// Export as JSON value.
    #[must_use] 
    pub fn to_json(&self) -> serde_json::Value {
        let bbs: Vec<_> = self.bbs.iter().map(|(&addr, r)| {
            serde_json::json!({ "addr": addr, "hits": r.total_hits, "covered": r.covered })
        }).collect();

        let edges: Vec<_> = self.edges.iter().map(|(k, r)| {
            serde_json::json!({ "src": k.src, "dst": k.dst, "hits": r.total_hits })
        }).collect();

        serde_json::json!({
            "bb_count": self.covered_bb_count(),
            "edge_count": self.edge_count(),
            "bbs": bbs,
            "edges": edges,
        })
    }
}

// ─── CoverageSession ─────────────────────────────────────────────────────────

/// Groups multiple seeds' coverage into a session with per-seed tracking.
pub struct CoverageSession {
    pub map: CoverageMap,
    pub seed_ids: Vec<u64>,
    pub seed_meta: HashMap<u64, SeedMeta>,
}

/// Metadata for one fuzz seed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedMeta {
    pub seed_id: u64,
    pub path: Option<String>,
    pub input_hash: u64,
    pub input_len: usize,
    pub new_bbs: usize,
    pub new_edges: usize,
}

impl CoverageSession {
    #[must_use] 
    pub fn new() -> Self {
        Self { map: CoverageMap::new(), seed_ids: Vec::new(), seed_meta: HashMap::new() }
    }

    /// Ingest raw BB hits from one seed execution.
    pub fn ingest_seed(
        &mut self,
        seed_id: u64,
        bb_hits: impl IntoIterator<Item = (u64, u64)>,
        edge_hits: impl IntoIterator<Item = (u64, u64, u64)>,
        meta: SeedMeta,
    ) {
        for (addr, count) in bb_hits {
            self.map.record_bb(addr, seed_id, count);
        }
        for (src, dst, count) in edge_hits {
            self.map.record_edge(src, dst, seed_id, count);
        }
        self.seed_ids.push(seed_id);
        self.seed_meta.insert(seed_id, meta);
    }

    /// Return the seed that contributed the most new BBs.
    #[must_use] 
    pub fn best_seed(&self) -> Option<u64> {
        self.seed_meta
            .values()
            .max_by_key(|m| m.new_bbs)
            .map(|m| m.seed_id)
    }
}

impl Default for CoverageSession {
    fn default() -> Self { Self::new() }
}

// ─── Coverage statistics ─────────────────────────────────────────────────────

/// Per-function coverage statistics derived from a `CoverageMap`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCovStats {
    pub address: u64,
    pub name: String,
    pub total_bbs: usize,
    pub covered_bbs: usize,
    pub total_edges: usize,
    pub covered_edges: usize,
    pub bb_coverage_pct: f64,
    pub edge_coverage_pct: f64,
    pub total_hits: u64,
    pub max_bb_hits: u64,
}

impl FunctionCovStats {
    /// Compute statistics for one function.
    pub fn compute(
        address: u64,
        name: impl Into<String>,
        bb_addrs: &[u64],
        cov: &CoverageMap,
    ) -> Self {
        let total_bbs = bb_addrs.len();
        let covered_bbs = bb_addrs.iter().filter(|&&a| cov.bbs.get(&a).is_some_and(|r| r.covered)).count();
        let total_hits: u64 = bb_addrs.iter().filter_map(|&a| cov.bbs.get(&a)).map(|r| r.total_hits).sum();
        let max_bb_hits: u64 = bb_addrs.iter().filter_map(|&a| cov.bbs.get(&a)).map(|r| r.total_hits).max().unwrap_or(0);

        // Count outgoing edges for this function's BBs
        let bb_set: HashSet<u64> = bb_addrs.iter().copied().collect();
        let total_edges = cov.edges.keys().filter(|k| bb_set.contains(&k.src)).count();
        let covered_edges = cov.edges.iter()
            .filter(|(k, r)| bb_set.contains(&k.src) && r.total_hits > 0)
            .count();

        let bb_cov = if total_bbs == 0 { 100.0 } else { crate::usize_to_f64(covered_bbs) / crate::usize_to_f64(total_bbs) * 100.0 };
        let edge_cov = if total_edges == 0 { 100.0 } else { crate::usize_to_f64(covered_edges) / crate::usize_to_f64(total_edges) * 100.0 };

        Self {
            address,
            name: name.into(),
            total_bbs,
            covered_bbs,
            total_edges,
            covered_edges,
            bb_coverage_pct: bb_cov,
            edge_coverage_pct: edge_cov,
            total_hits,
            max_bb_hits,
        }
    }

    #[must_use] 
    pub const fn is_dead(&self) -> bool { self.covered_bbs == 0 }
    #[must_use] 
    pub const fn is_fully_covered(&self) -> bool { self.total_bbs > 0 && self.covered_bbs == self.total_bbs }
}

impl std::fmt::Display for FunctionCovStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:#018x} {:40} BB: {}/{} ({:.1}%)  Edge: {}/{} ({:.1}%)  hits={}",
            self.address, self.name,
            self.covered_bbs, self.total_bbs, self.bb_coverage_pct,
            self.covered_edges, self.total_edges, self.edge_coverage_pct,
            self.total_hits,
        )
    }
}

// ─── Coverage export helpers ─────────────────────────────────────────────────

/// Build a flat sorted list of all (address, `hit_count`) pairs from a map.
#[must_use] 
pub fn flat_hit_list(cov: &CoverageMap) -> Vec<(u64, u64)> {
    let mut v: Vec<(u64, u64)> = cov.bbs.iter().map(|(&a, r)| (a, r.total_hits)).collect();
    v.sort_unstable_by_key(|(a, _)| *a);
    v
}

/// Compute per-bucket hit histogram (`bucket_size` = number of addresses per bucket).
///
/// Useful for generating dense heatmaps over large address ranges.
#[must_use] 
pub fn address_histogram(cov: &CoverageMap, bucket_size: u64) -> BTreeMap<u64, u64> {
    let bucket_size = bucket_size.max(1); // prevent division by zero on malformed input
    let mut hist: BTreeMap<u64, u64> = BTreeMap::new();
    for (&addr, rec) in &cov.bbs {
        if rec.covered {
            let bucket = (addr / bucket_size) * bucket_size;
            *hist.entry(bucket).or_insert(0) += rec.total_hits;
        }
    }
    hist
}

/// Find all edges that are "bridges" — their removal would disconnect the CFG.
/// (Simplified: edges where the destination has only one incoming covered edge.)
#[must_use] 
pub fn find_bridge_edges(cov: &CoverageMap) -> Vec<EdgeKey> {
    // Count incoming covered edges per destination
    let mut in_degree: HashMap<u64, usize> = HashMap::new();
    for (key, rec) in &cov.edges {
        if rec.total_hits > 0 {
            *in_degree.entry(key.dst).or_insert(0) += 1;
        }
    }
    cov.edges.iter()
        .filter(|(key, rec)| rec.total_hits > 0 && in_degree.get(&key.dst).copied().unwrap_or(0) == 1)
        .map(|(key, _)| *key)
        .collect()
}

/// Compute the "exploration score" for a seed: ratio of unique edges it alone
/// covers vs. the total edge corpus.
#[must_use] 
pub fn seed_exploration_score(cov: &CoverageMap, seed_id: u64) -> f64 {
    let seed_edges = cov.edges.iter().filter(|(_, r)| r.per_seed.contains_key(&seed_id)).count();
    let total_edges = cov.edges.len();
    if total_edges == 0 { return 0.0; }
    crate::usize_to_f64(seed_edges) / crate::usize_to_f64(total_edges)
}

/// Group coverage BBs by module (using address ranges).
#[must_use] 
pub fn coverage_by_module(cov: &CoverageMap, modules: &[(u64, u64, String)]) -> HashMap<String, (usize, usize)> {
    // modules: Vec of (base, end, name)
    let mut result: HashMap<String, (usize, usize)> = HashMap::new();
    for (&addr, rec) in &cov.bbs {
        for (base, end, name) in modules {
            if addr >= *base && addr < *end {
                let entry = result.entry(name.clone()).or_insert((0, 0));
                entry.0 += 1; // total
                if rec.covered { entry.1 += 1; } // covered
                break;
            }
        }
    }
    result
}

/// Serialize a `CoverageMap` to a compact binary format:
/// `[u64 addr][u64 total_hits]` pairs, little-endian.
#[must_use] 
pub fn serialize_compact(cov: &CoverageMap) -> Vec<u8> {
    let mut out = Vec::with_capacity(cov.bbs.len() * 16);
    for (&addr, rec) in &cov.bbs {
        if rec.covered {
            out.extend_from_slice(&addr.to_le_bytes());
            out.extend_from_slice(&rec.total_hits.to_le_bytes());
        }
    }
    out
}

/// Generate an SVG heatmap visualization of the coverage map.
///
/// Produces a horizontal bar chart of the top-N hottest basic blocks.
#[must_use] 
pub fn generate_svg_heatmap(cov: &CoverageMap, top_n: usize, width: u32, height: u32) -> String {
    let mut hot = cov.bb_heatmap_data();
    hot.sort_by_key(|b| std::cmp::Reverse(b.1));
    hot.truncate(top_n);

    let max_hits = hot.iter().map(|(_, h)| *h).max().unwrap_or(1);
    let bar_height = crate::f64_to_u32_clamp((f64::from(height) / crate::usize_to_f64(hot.len().max(1))).floor());
    let mut svg = format!(
        "<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{height}'>\n<rect width='100%' height='100%' fill='#1a1a1a'/>\n"
    );

    for (i, (addr, hits)) in hot.iter().enumerate() {
        let available_w = (f64::from(width) - 200.0).max(0.0);
        let bar_w = crate::f64_to_u32_clamp((crate::u64_to_f64(*hits) / crate::u64_to_f64(max_hits)) * available_w);
        let y = crate::usize_to_u32_sat(i) * (bar_height + 2);
        let red = crate::f64_to_u8_clamp((crate::u64_to_f64(*hits) / crate::u64_to_f64(max_hits)) * 255.0);
        let green = 128u8.saturating_sub(red / 2);
        writeln!(svg,
            "<rect x='150' y='{y}' width='{bar_w}' height='{bar_height}' fill='rgb({red},{green},50)'/>"
        ).ok();
        writeln!(svg,
            "<text x='5' y='{}' fill='#ccc' font-size='10' font-family='monospace'>{:#012x}</text>",
            y + bar_height, addr
        ).ok();
        writeln!(svg,
            "<text x='{}' y='{}' fill='#fff' font-size='10'>{}</text>",
            150 + bar_w + 4, y + bar_height, hits
        ).ok();
    }
    svg.push_str("</svg>");
    svg
}

/// Compute a "coverage score" for ranking seed quality across a session.
///
/// Score = (`unique_edges` / `total_edges`) * log2(1 + `total_hits`)
#[must_use] 
pub fn coverage_score(cov: &CoverageMap, total_known_edges: usize) -> f64 {
    let covered_edges = cov.edge_count();
    let total_hits: u64 = cov.bbs.values().map(|r| r.total_hits).sum();
    let edge_ratio = if total_known_edges == 0 { 1.0 } else { crate::usize_to_f64(covered_edges) / crate::usize_to_f64(total_known_edges) };
    edge_ratio * (1.0 + crate::u64_to_f64(total_hits)).log2()
}

/// Find "boundary BBs" — basic blocks at the frontier between covered and
/// uncovered territory (covered BB with at least one uncovered successor).
#[must_use] 
pub fn find_frontier_bbs(cov: &CoverageMap) -> Vec<u64> {
    let covered_set: HashSet<u64> = cov.bbs.iter().filter(|(_, r)| r.covered).map(|(&a, _)| a).collect();
    let mut frontier = Vec::new();
    for (&src, _) in cov.edges.iter().filter(|(_, r)| r.total_hits > 0) {
        // Check if dst is NOT covered
        if !covered_set.contains(&src.dst) && covered_set.contains(&src.src) {
            frontier.push(src.src); // src is covered but dst is not
        }
    }
    frontier.sort_unstable();
    frontier.dedup();
    frontier
}

/// Compute a "novelty score" for each BB: how many seeds have NOT covered it
/// vs. the total number of seeds (1.0 = only ever hit by one seed).
#[must_use] 
pub fn bb_novelty_scores(cov: &CoverageMap) -> BTreeMap<u64, f64> {
    let total_seeds: usize = cov.bbs.values()
        .flat_map(|r| r.per_seed.keys())
        .collect::<HashSet<_>>()
        .len();

    cov.bbs.iter()
        .filter(|(_, r)| r.covered)
        .map(|(&addr, r)| {
            let seeds_covering = r.per_seed.len();
            let novelty = if total_seeds == 0 { 0.0 } else { 1.0 - crate::usize_to_f64(seeds_covering) / crate::usize_to_f64(total_seeds) };
            (addr, novelty)
        })
        .collect()
}

/// Find BBs that are "rare" (novelty score above threshold).
#[must_use] 
pub fn find_rare_bbs(cov: &CoverageMap, threshold: f64) -> Vec<u64> {
    bb_novelty_scores(cov)
        .into_iter()
        .filter(|(_, score)| *score >= threshold)
        .map(|(addr, _)| addr)
        .collect()
}

/// Compute how many BBs are first covered at each corpus size (saturation curve data).
#[must_use] 
pub fn bb_saturation_curve(cov: &CoverageMap) -> Vec<(u64 /* seed_id */, usize /* cumulative_bbs */)> {
    // Collect all seeds ordered by ID
    let mut all_seeds: Vec<u64> = cov.bbs.values()
        .flat_map(|r| r.per_seed.keys().copied())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    all_seeds.sort_unstable();

    let mut cumulative = HashSet::new();
    all_seeds.iter().map(|&seed_id| {
        for (&addr, rec) in &cov.bbs {
            if rec.per_seed.contains_key(&seed_id) { cumulative.insert(addr); }
        }
        (seed_id, cumulative.len())
    }).collect()
}

/// Deserialize from the compact binary format produced by `serialize_compact`.
///
/// # Errors
/// Returns `CovError::ParseError` if the byte slice length is not a multiple of 16.
///
/// # Panics
/// Panics if an internal slice extraction fails (should never happen given the length check).
pub fn deserialize_compact(bytes: &[u8], seed_id: u64) -> Result<CoverageMap, crate::CovError> {
    if !bytes.len().is_multiple_of(16) {
        return Err(crate::CovError::ParseError(format!("invalid compact format: len {} not divisible by 16", bytes.len())));
    }
    let mut cov = CoverageMap::new();
    let mut i = 0;
    while i + 16 <= bytes.len() {
        let addr = u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap());
        let hits = u64::from_le_bytes(bytes[i + 8..i + 16].try_into().unwrap());
        cov.record_bb(addr, seed_id, hits);
        i += 16;
    }
    Ok(cov)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_query() {
        let mut m = CoverageMap::new();
        m.record_bb(0x1000, 1, 5);
        m.record_bb(0x1000, 2, 3);
        m.record_bb(0x2000, 1, 1);
        assert_eq!(m.covered_bb_count(), 2);
        assert_eq!(m.bbs[&0x1000].total_hits, 8);
    }

    #[test]
    fn test_delta_coverage() {
        let mut m = CoverageMap::new();
        m.record_bb(0x1000, 1, 1);  // covered by seed 1
        m.record_bb(0x2000, 1, 1);
        m.record_bb(0x3000, 2, 1);  // new for seed 2
        let delta = m.delta_coverage(2);
        assert!(delta.contains(&0x3000));
        assert!(!delta.contains(&0x1000));
    }

    #[test]
    fn test_uncovered_bbs() {
        let mut m = CoverageMap::new();
        m.register_known_bbs([0x1000, 0x2000, 0x3000]);
        m.record_bb(0x1000, 1, 1);
        let uncovered = m.uncovered_bbs();
        assert!(uncovered.contains(&0x2000));
        assert!(uncovered.contains(&0x3000));
        assert!(!uncovered.contains(&0x1000));
    }

    #[test]
    fn test_coverage_pct() {
        let mut m = CoverageMap::new();
        m.register_known_bbs(0u64..10);
        for i in 0u64..6 { m.record_bb(i, 1, 1); }
        let pct = m.bb_coverage_pct();
        assert!((pct - 60.0).abs() < 0.01, "expected 60% got {pct}");
    }

    #[test]
    fn test_merge() {
        let mut m1 = CoverageMap::new();
        m1.record_bb(0x1000, 1, 3);
        let mut m2 = CoverageMap::new();
        m2.record_bb(0x2000, 2, 7);
        m1.merge(&m2);
        assert_eq!(m1.covered_bb_count(), 2);
    }

    #[test]
    fn test_heatmap_data_sorted() {
        let mut m = CoverageMap::new();
        m.record_bb(0x3000, 1, 1);
        m.record_bb(0x1000, 1, 1);
        m.record_bb(0x2000, 1, 1);
        let data = m.bb_heatmap_data();
        assert_eq!(data[0].0, 0x1000);
        assert_eq!(data[1].0, 0x2000);
        assert_eq!(data[2].0, 0x3000);
    }
}
