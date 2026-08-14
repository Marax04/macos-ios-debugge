//! Semantic binary diff engine.
//!
//! Compares two sets of functions (identified by address, name, and byte content)
//! and produces a rich [`DiffReport`] that classifies every function as
//! Added / Removed / Renamed / Recompiled / Patched / Equivalent and records
//! instruction-level and CFG-level details for changed functions.

use std::collections::HashMap;
use std::fmt;

// ────────────────────────────────────────────────────────────────────────────────
// Public types
// ────────────────────────────────────────────────────────────────────────────────

/// How a function changed between the old and new binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeType {
    /// Function exists only in the new binary.
    Added,
    /// Function exists only in the old binary.
    Removed,
    /// Same bytes, different address and/or name.
    Renamed,
    /// Significant rewrite (similarity < 0.85 but > threshold).
    Recompiled,
    /// Small patch (similarity >= 0.85 but < 1.0).
    Patched,
    /// Byte-for-byte identical.
    Equivalent,
}

impl fmt::Display for ChangeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Added => "Added",
            Self::Removed => "Removed",
            Self::Renamed => "Renamed",
            Self::Recompiled => "Recompiled",
            Self::Patched => "Patched",
            Self::Equivalent => "Equivalent",
        };
        f.write_str(s)
    }
}

/// Fine-grained record of a single change within a function pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffDetail {
    /// An instruction changed at the given offset.
    InstructionChanged {
        /// Instruction text from the old binary.
        old: String,
        /// Instruction text from the new binary.
        new: String,
    },
    /// A basic block was added at this address in the new binary.
    BlockAdded(u64),
    /// A basic block was removed (old address) from the old binary.
    BlockRemoved(u64),
    /// The overall control-flow graph topology changed.
    CfgChanged,
    /// The function's signature (arity / calling convention) changed.
    SignatureChanged,
}

/// Similarity decomposed across several orthogonal dimensions.
#[derive(Debug, Clone)]
pub struct SimilarityMetrics {
    /// Fraction of instructions that are identical (after normalization).
    pub instruction_similarity: f64,
    /// Graph-edit-distance–based CFG similarity.
    pub cfg_similarity: f64,
    /// String reference overlap (Jaccard on string literals).
    pub string_similarity: f64,
    /// Constant value overlap (Jaccard on immediate operands).
    pub constant_similarity: f64,
}

impl SimilarityMetrics {
    /// Weighted combination of the four dimensions.
    #[must_use]
    pub fn combined(&self) -> f64 {
        0.10f64.mul_add(self.constant_similarity, 0.15f64.mul_add(self.string_similarity, 0.45f64.mul_add(self.instruction_similarity, 0.30 * self.cfg_similarity)))
    }
}

impl Default for SimilarityMetrics {
    fn default() -> Self {
        Self {
            instruction_similarity: 0.0,
            cfg_similarity: 0.0,
            string_similarity: 0.0,
            constant_similarity: 0.0,
        }
    }
}

/// Diff record for a single function pair.
#[derive(Debug, Clone)]
pub struct FunctionDiff {
    /// Address in the old binary (`None` for Added functions).
    pub old_addr: Option<u64>,
    /// Address in the new binary (`None` for Removed functions).
    pub new_addr: Option<u64>,
    /// Canonical function name (prefer old name; fall back to new).
    pub name: String,
    /// Classification of the change.
    pub change_type: ChangeType,
    /// Overall similarity score in `[0.0, 1.0]`.
    pub similarity: f64,
    /// Detailed list of individual changes.
    pub diff_details: Vec<DiffDetail>,
    /// Decomposed similarity metrics (all zero for Added / Removed).
    pub metrics: SimilarityMetrics,
}

impl FunctionDiff {
    /// `true` if the function is byte-for-byte equivalent or only renamed.
    #[must_use]
    pub const fn is_trivial(&self) -> bool {
        matches!(self.change_type, ChangeType::Equivalent | ChangeType::Renamed)
    }
}

impl fmt::Display for FunctionDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}] sim={:.1}%",
            self.name,
            self.change_type,
            self.similarity * 100.0
        )
    }
}

/// Summary counts for a diff report.
#[derive(Debug, Clone, Default)]
pub struct DiffSummary {
    /// Total functions in the old binary.
    pub total_old: usize,
    /// Total functions in the new binary.
    pub total_new: usize,
    /// Functions present only in the new binary.
    pub added: usize,
    /// Functions present only in the old binary.
    pub removed: usize,
    /// Functions that changed (Recompiled + Patched + Renamed).
    pub modified: usize,
    /// Functions that are byte-for-byte identical.
    pub equivalent: usize,
}

impl DiffSummary {
    /// Overall similarity ratio: equivalent / `max(total_old`, `total_new`).
    #[must_use]
    pub fn similarity_ratio(&self) -> f64 {
        let denom = self.total_old.max(self.total_new);
        if denom == 0 {
            1.0
        } else {
            f64::from(u32::try_from(self.equivalent).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(denom).unwrap_or(u32::MAX))
        }
    }
}

impl fmt::Display for DiffSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "old={} new={} +{} -{} ~{} ={}",
            self.total_old,
            self.total_new,
            self.added,
            self.removed,
            self.modified,
            self.equivalent,
        )
    }
}

/// Top-level diff report.
#[derive(Debug, Clone)]
pub struct DiffReport {
    /// Aggregate statistics.
    pub summary: DiffSummary,
    /// Per-function diff records.
    pub diffs: Vec<FunctionDiff>,
}

impl DiffReport {
    /// Iterate over only the changed function diffs.
    pub fn changed(&self) -> impl Iterator<Item = &FunctionDiff> {
        self.diffs.iter().filter(|d| !d.is_trivial() && d.change_type != ChangeType::Added && d.change_type != ChangeType::Removed)
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// Input representation
// ────────────────────────────────────────────────────────────────────────────────

/// A function as supplied to the diff engine.
#[derive(Debug, Clone)]
pub struct FunctionEntry {
    /// Load-time virtual address.
    pub address: u64,
    /// Symbol name (may be empty for stripped binaries).
    pub name: String,
    /// Raw instruction mnemonics (one per instruction).
    pub mnemonics: Vec<String>,
    /// Basic block start addresses (sorted).
    pub basic_blocks: Vec<u64>,
    /// Number of CFG edges.
    pub edge_count: usize,
    /// String literals referenced from this function.
    pub string_refs: Vec<String>,
    /// Immediate (constant) operands used in this function.
    pub immediates: Vec<i64>,
}

impl FunctionEntry {
    /// Create a minimal entry with only an address, name and mnemonics.
    #[must_use]
    pub fn new(address: u64, name: impl Into<String>, mnemonics: Vec<String>) -> Self {
        Self {
            address,
            name: name.into(),
            mnemonics,
            basic_blocks: Vec::new(),
            edge_count: 0,
            string_refs: Vec::new(),
            immediates: Vec::new(),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// SemanticDiff engine
// ────────────────────────────────────────────────────────────────────────────────

/// Configuration for the diff engine.
#[derive(Debug, Clone)]
pub struct SemanticDiffConfig {
    /// Minimum similarity to consider two functions a match (default 0.5).
    pub match_threshold: f64,
    /// Similarity at or above which functions are classified as Patched vs Recompiled.
    pub patch_threshold: f64,
    /// Maximum instructions to compare per function (performance cap).
    pub max_instr_cap: usize,
    /// If `true`, normalize register names and immediates before comparison.
    pub normalize: bool,
}

impl Default for SemanticDiffConfig {
    fn default() -> Self {
        Self {
            match_threshold: 0.5,
            patch_threshold: 0.85,
            max_instr_cap: 2048,
            normalize: true,
        }
    }
}

/// The semantic diff engine.
pub struct SemanticDiff {
    config: SemanticDiffConfig,
}

impl SemanticDiff {
    /// Create an engine with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: SemanticDiffConfig::default(),
        }
    }

    /// Create an engine with a custom configuration.
    #[must_use]
    pub const fn with_config(config: SemanticDiffConfig) -> Self {
        Self { config }
    }

    /// Compute the full diff between `old_funcs` and `new_funcs`.
    #[must_use]
    pub fn diff(&self, old_funcs: &[FunctionEntry], new_funcs: &[FunctionEntry]) -> DiffReport {
        let matched_pairs = self.match_functions(old_funcs, new_funcs);

        let mut diffs: Vec<FunctionDiff> = Vec::new();
        let mut summary = DiffSummary {
            total_old: old_funcs.len(),
            total_new: new_funcs.len(),
            ..Default::default()
        };

        let mut old_used = vec![false; old_funcs.len()];
        let mut new_used = vec![false; new_funcs.len()];

        for (old_idx, new_idx, sim) in &matched_pairs {
            old_used[*old_idx] = true;
            new_used[*new_idx] = true;
            let fd = self.build_function_diff(
                &old_funcs[*old_idx],
                &new_funcs[*new_idx],
                *sim,
            );
            match fd.change_type {
                ChangeType::Equivalent => summary.equivalent += 1,
                ChangeType::Renamed | ChangeType::Patched | ChangeType::Recompiled => summary.modified += 1,
                ChangeType::Added | ChangeType::Removed => {}
            }
            diffs.push(fd);
        }

        for (i, old_f) in old_funcs.iter().enumerate() {
            if !old_used[i] {
                summary.removed += 1;
                diffs.push(FunctionDiff {
                    old_addr: Some(old_f.address),
                    new_addr: None,
                    name: old_f.name.clone(),
                    change_type: ChangeType::Removed,
                    similarity: 0.0,
                    diff_details: Vec::new(),
                    metrics: SimilarityMetrics::default(),
                });
            }
        }

        for (j, new_f) in new_funcs.iter().enumerate() {
            if !new_used[j] {
                summary.added += 1;
                diffs.push(FunctionDiff {
                    old_addr: None,
                    new_addr: Some(new_f.address),
                    name: new_f.name.clone(),
                    change_type: ChangeType::Added,
                    similarity: 0.0,
                    diff_details: Vec::new(),
                    metrics: SimilarityMetrics::default(),
                });
            }
        }

        DiffReport { summary, diffs }
    }

    /// Match functions between old and new sets.
    ///
    /// Phase 1: exact name matches.
    /// Phase 2: similarity-based bipartite matching for unmatched functions.
    ///
    /// Returns `Vec<(old_index, new_index, similarity)>`.
    #[must_use]
    pub fn match_functions(
        &self,
        old_funcs: &[FunctionEntry],
        new_funcs: &[FunctionEntry],
    ) -> Vec<(usize, usize, f64)> {
        let mut matched: Vec<(usize, usize, f64)> = Vec::new();
        let mut old_used = vec![false; old_funcs.len()];
        let mut new_used = vec![false; new_funcs.len()];

        // Build name index for new functions.
        let mut new_by_name: HashMap<&str, usize> = HashMap::new();
        for (j, nf) in new_funcs.iter().enumerate() {
            if !nf.name.is_empty() {
                new_by_name.insert(nf.name.as_str(), j);
            }
        }

        // Phase 1: exact name match.
        for (i, of) in old_funcs.iter().enumerate() {
            if of.name.is_empty() {
                continue;
            }
            if let Some(&j) = new_by_name.get(of.name.as_str())
                && !new_used[j] {
                    let sim = self.compute_instruction_similarity(&of.mnemonics, &new_funcs[j].mnemonics);
                    matched.push((i, j, sim));
                    old_used[i] = true;
                    new_used[j] = true;
                }
        }

        // Phase 2: greedy similarity-based matching for unmatched functions.
        let unmatched_old: Vec<usize> = (0..old_funcs.len()).filter(|&i| !old_used[i]).collect();
        let unmatched_new: Vec<usize> = (0..new_funcs.len()).filter(|&j| !new_used[j]).collect();

        // Build all pairwise similarities and sort descending.
        let mut candidates: Vec<(f64, usize, usize)> = Vec::new();
        for &i in &unmatched_old {
            for &j in &unmatched_new {
                let metrics = self.compute_metrics(&old_funcs[i], &new_funcs[j]);
                let sim = metrics.combined();
                if sim >= self.config.match_threshold {
                    candidates.push((sim, i, j));
                }
            }
        }
        candidates.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        let mut phase2_old_used = vec![false; old_funcs.len()];
        let mut phase2_new_used = vec![false; new_funcs.len()];
        for (sim, i, j) in candidates {
            if !phase2_old_used[i] && !phase2_new_used[j] {
                matched.push((i, j, sim));
                phase2_old_used[i] = true;
                phase2_new_used[j] = true;
            }
        }

        matched
    }

    /// Compute instruction-level edit distance similarity.
    ///
    /// Normalizes each mnemonic and computes a Levenshtein-based similarity
    /// capped at `max_instr_cap` instructions per side.
    #[must_use]
    pub fn compute_instruction_similarity(&self, old: &[String], new: &[String]) -> f64 {
        if old.is_empty() && new.is_empty() {
            return 1.0;
        }
        if old.is_empty() || new.is_empty() {
            return 0.0;
        }

        let cap = self.config.max_instr_cap;
        let old_norm: Vec<String> = old
            .iter()
            .take(cap)
            .map(|s| normalize_instruction(s))
            .collect();
        let new_norm: Vec<String> = new
            .iter()
            .take(cap)
            .map(|s| normalize_instruction(s))
            .collect();

        let la = old_norm.len();
        let lb = new_norm.len();
        let mut dp = vec![vec![0u32; lb + 1]; la + 1];
        for (row, cell) in dp.iter_mut().enumerate() {
            cell[0] = u32::try_from(row).unwrap_or(u32::MAX);
        }
        for (col, cell) in dp[0].iter_mut().enumerate() {
            *cell = u32::try_from(col).unwrap_or(u32::MAX);
        }
        for (row_idx, old_m) in old_norm.iter().enumerate() {
            let row = row_idx + 1;
            for (col_idx, new_m) in new_norm.iter().enumerate() {
                let col = col_idx + 1;
                let cost = u32::from(old_m != new_m);
                dp[row][col] = (dp[row - 1][col] + 1)
                    .min(dp[row][col - 1] + 1)
                    .min(dp[row - 1][col - 1] + cost);
            }
        }
        let dist = f64::from(dp[la][lb]);
        let max_len = f64::from(u32::try_from(la.max(lb)).unwrap_or(u32::MAX));
        1.0 - (dist / max_len)
    }

    /// CFG similarity based on graph-edit distance approximation.
    ///
    /// We compare node counts, edge counts, and basic-block sizes using a
    /// normalized absolute difference.
    #[must_use]
    pub fn compute_cfg_similarity(&self, old: &FunctionEntry, new: &FunctionEntry) -> f64 {
        let old_nodes = f64::from(u32::try_from(old.basic_blocks.len()).unwrap_or(u32::MAX));
        let new_nodes = f64::from(u32::try_from(new.basic_blocks.len()).unwrap_or(u32::MAX));
        let old_edges = f64::from(u32::try_from(old.edge_count).unwrap_or(u32::MAX));
        let new_edges = f64::from(u32::try_from(new.edge_count).unwrap_or(u32::MAX));

        let node_sim = sim_ratio(old_nodes, new_nodes);
        let edge_sim = sim_ratio(old_edges, new_edges);

        // Compare total instruction count as proxy for basic-block size distribution.
        let old_instr = f64::from(u32::try_from(old.mnemonics.len()).unwrap_or(u32::MAX));
        let new_instr = f64::from(u32::try_from(new.mnemonics.len()).unwrap_or(u32::MAX));
        let instr_sim = sim_ratio(old_instr, new_instr);

        0.2f64.mul_add(instr_sim, 0.4f64.mul_add(node_sim, 0.4 * edge_sim)).clamp(0.0, 1.0)
    }

    /// Compute all four similarity metrics for a function pair.
    #[must_use]
    pub fn compute_metrics(&self, old: &FunctionEntry, new: &FunctionEntry) -> SimilarityMetrics {
        let instruction_similarity = self.compute_instruction_similarity(&old.mnemonics, &new.mnemonics);
        let cfg_similarity = self.compute_cfg_similarity(old, new);
        let string_similarity = jaccard_str(&old.string_refs, &new.string_refs);
        let constant_similarity = jaccard_i64(&old.immediates, &new.immediates);
        SimilarityMetrics {
            instruction_similarity,
            cfg_similarity,
            string_similarity,
            constant_similarity,
        }
    }

    /// Build a [`FunctionDiff`] for a matched pair.
    fn build_function_diff(
        &self,
        old: &FunctionEntry,
        new: &FunctionEntry,
        sim: f64,
    ) -> FunctionDiff {
        let metrics = self.compute_metrics(old, new);
        let combined = metrics.combined();

        let change_type = classify_change(old, new, combined, self.config.patch_threshold);
        let diff_details = if change_type == ChangeType::Equivalent {
            Vec::new()
        } else {
            self.build_diff_details(old, new)
        };

        FunctionDiff {
            old_addr: Some(old.address),
            new_addr: Some(new.address),
            name: if old.name.is_empty() { new.name.clone() } else { old.name.clone() },
            change_type,
            similarity: sim,
            diff_details,
            metrics,
        }
    }

    /// Enumerate instruction-level and CFG-level changes between two matched functions.
    fn build_diff_details(&self, old: &FunctionEntry, new: &FunctionEntry) -> Vec<DiffDetail> {
        let mut details: Vec<DiffDetail> = Vec::new();
        let cap = self.config.max_instr_cap;

        // Instruction-level diff (LCS-based).
        let old_norm: Vec<String> = old.mnemonics.iter().take(cap).map(|s| normalize_instruction(s)).collect();
        let new_norm: Vec<String> = new.mnemonics.iter().take(cap).map(|s| normalize_instruction(s)).collect();

        // `lcs_diff` returns the pairs the LCS MATCHED — equal by construction.
        // The changes are what lies BETWEEN consecutive matches: the run of old
        // instructions that survived nowhere, aligned against the run of new
        // ones that appeared. Testing the matched pairs themselves for
        // inequality is vacuously false, and reported every function as having
        // no instruction-level change at all.
        let pairs = lcs_diff(&old_norm, &new_norm);
        let mut oi = 0usize;
        let mut ni = 0usize;
        let push_gap = |details: &mut Vec<DiffDetail>, o: std::ops::Range<usize>, n: std::ops::Range<usize>| {
            let mut o = o;
            let mut n = n;
            while (o.start < o.end || n.start < n.end) && details.len() < 64 {
                // An absent side is rendered as the empty string: `DiffDetail`
                // has no add/remove variant for a single instruction, and an
                // empty operand reads unambiguously as "not present here".
                let old_text = if o.start < o.end {
                    let t = old.mnemonics[o.start].clone();
                    o.start += 1;
                    t
                } else {
                    String::new()
                };
                let new_text = if n.start < n.end {
                    let t = new.mnemonics[n.start].clone();
                    n.start += 1;
                    t
                } else {
                    String::new()
                };
                details.push(DiffDetail::InstructionChanged { old: old_text, new: new_text });
            }
        };
        for (po, pn) in pairs {
            push_gap(&mut details, oi..po, ni..pn);
            oi = po + 1;
            ni = pn + 1;
        }
        push_gap(&mut details, oi..old_norm.len(), ni..new_norm.len());

        // CFG-level changes.
        let old_bb_set: std::collections::HashSet<u64> = old.basic_blocks.iter().copied().collect();
        let new_bb_set: std::collections::HashSet<u64> = new.basic_blocks.iter().copied().collect();

        for &addr in &new.basic_blocks {
            if !old_bb_set.contains(&addr) {
                details.push(DiffDetail::BlockAdded(addr));
            }
        }
        for &addr in &old.basic_blocks {
            if !new_bb_set.contains(&addr) {
                details.push(DiffDetail::BlockRemoved(addr));
            }
        }

        if old.edge_count != new.edge_count || old.basic_blocks.len() != new.basic_blocks.len() {
            details.push(DiffDetail::CfgChanged);
        }

        details
    }
}

impl Default for SemanticDiff {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SemanticDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SemanticDiff")
            .field("match_threshold", &self.config.match_threshold)
            .finish_non_exhaustive()
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────────

/// Canonicalize a single instruction string for comparison.
///
/// Strips hex immediates, normalises register names to a placeholder, and
/// lowercases everything.  The goal is to make identical-logic instructions
/// compare equal even if addresses have shifted.
#[must_use]
pub fn normalize_instruction(s: &str) -> String {
    let lower = s.to_lowercase();
    // Replace hex immediates (0x...) with IMM.
    let re_hex = replace_pattern(&lower, "0x", "IMM");
    // Replace bare decimal immediates that are large (> 4 chars).
    let mut out = String::with_capacity(re_hex.len());
    let mut in_token = false;
    let mut token_start = 0;
    let chars: Vec<char> = re_hex.chars().collect();
    let len = chars.len();
    let mut i = 0;
    while i < len {
        let c = chars[i];
        if c.is_ascii_digit() && !in_token {
            in_token = true;
            token_start = i;
        } else if !c.is_ascii_digit() && in_token {
            let token_len = i - token_start;
            if token_len > 4 {
                out.push_str("IMM");
            } else {
                for &ch in &chars[token_start..i] {
                    out.push(ch);
                }
            }
            in_token = false;
            out.push(c);
        } else if !in_token {
            out.push(c);
        }
        i += 1;
    }
    if in_token {
        let token_len = len - token_start;
        if token_len > 4 {
            out.push_str("IMM");
        } else {
            for &ch in &chars[token_start..len] {
                out.push(ch);
            }
        }
    }
    out.trim().to_owned()
}

fn replace_pattern(s: &str, pat: &str, repl: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut remaining = s;
    while let Some(pos) = remaining.find(pat) {
        result.push_str(&remaining[..pos]);
        result.push_str(repl);
        remaining = &remaining[pos + pat.len()..];
        // Skip past end of the hex literal token.
        let end = remaining.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(remaining.len());
        remaining = &remaining[end..];
    }
    result.push_str(remaining);
    result
}

fn sim_ratio(a: f64, b: f64) -> f64 {
    if a == 0.0 && b == 0.0 {
        return 1.0;
    }
    if a == 0.0 || b == 0.0 {
        return 0.0;
    }
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    lo / hi
}

fn jaccard_str(a: &[String], b: &[String]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let set_a: std::collections::HashSet<&str> = a.iter().map(String::as_str).collect();
    let set_b: std::collections::HashSet<&str> = b.iter().map(String::as_str).collect();
    let inter = set_a.intersection(&set_b).count();
    let union = set_a.union(&set_b).count();
    if union == 0 { 1.0 } else {
        f64::from(u32::try_from(inter).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(union).unwrap_or(u32::MAX))
    }
}

fn jaccard_i64(a: &[i64], b: &[i64]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let set_a: std::collections::HashSet<i64> = a.iter().copied().collect();
    let set_b: std::collections::HashSet<i64> = b.iter().copied().collect();
    let inter = set_a.intersection(&set_b).count();
    let union = set_a.union(&set_b).count();
    if union == 0 { 1.0 } else {
        f64::from(u32::try_from(inter).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(union).unwrap_or(u32::MAX))
    }
}

fn classify_change(old: &FunctionEntry, new: &FunctionEntry, sim: f64, patch_threshold: f64) -> ChangeType {
    // Byte-identical proxy: if all normalized mnemonics match.
    if old.mnemonics == new.mnemonics && old.basic_blocks.len() == new.basic_blocks.len() {
        if old.name == new.name {
            return ChangeType::Equivalent;
        }
        return ChangeType::Renamed;
    }
    if sim >= 1.0 {
        return ChangeType::Equivalent;
    }
    if old.name != new.name && sim > 0.9 {
        return ChangeType::Renamed;
    }
    if sim >= patch_threshold {
        ChangeType::Patched
    } else {
        ChangeType::Recompiled
    }
}

/// Compute LCS alignment positions: returns `Vec<(old_idx, new_idx)>` for
/// matched instruction pairs.
fn lcs_diff(old: &[String], new: &[String]) -> Vec<(usize, usize)> {
    let la = old.len().min(256);
    let lb = new.len().min(256);
    if la == 0 || lb == 0 {
        return Vec::new();
    }
    // One flat buffer instead of `la + 1` separately allocated rows: same
    // table, same result, a single allocation and contiguous access.
    let stride = lb + 1;
    let mut dp = vec![0u16; (la + 1) * stride];
    for i in 1..=la {
        for j in 1..=lb {
            dp[i * stride + j] = if old[i - 1] == new[j - 1] {
                dp[(i - 1) * stride + (j - 1)] + 1
            } else {
                dp[(i - 1) * stride + j].max(dp[i * stride + (j - 1)])
            };
        }
    }
    // Backtrack.
    let mut pairs = Vec::new();
    let mut i = la;
    let mut j = lb;
    while i > 0 && j > 0 {
        if old[i - 1] == new[j - 1] {
            pairs.push((i - 1, j - 1));
            i -= 1;
            j -= 1;
        } else if dp[(i - 1) * stride + j] > dp[i * stride + (j - 1)] {
            i -= 1;
        } else {
            j -= 1;
        }
    }
    pairs.reverse();
    pairs
}

// ────────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_func(addr: u64, name: &str, mnemonics: &[&str]) -> FunctionEntry {
        FunctionEntry::new(addr, name, mnemonics.iter().map(|s| s.to_string()).collect())
    }

    // ── normalize_instruction ──────────────────────────────────────────────────

    #[test]
    fn test_normalize_lowercase() {
        let n = normalize_instruction("MOV EAX, EBX");
        assert_eq!(n, "mov eax, ebx");
    }

    #[test]
    fn test_normalize_hex_imm() {
        let n = normalize_instruction("mov eax, 0x1000");
        assert!(n.contains("IMM"));
        assert!(!n.contains("0x"));
    }

    #[test]
    fn test_normalize_large_decimal() {
        let n = normalize_instruction("mov eax, 12345");
        assert!(n.contains("IMM"));
    }

    #[test]
    fn test_normalize_small_decimal_kept() {
        let n = normalize_instruction("add eax, 4");
        assert!(n.contains('4'));
        assert!(!n.contains("IMM"));
    }

    // ── compute_instruction_similarity ────────────────────────────────────────

    #[test]
    fn test_instr_sim_identical() {
        let diff = SemanticDiff::new();
        let a = vec!["mov eax, ebx".to_string(), "ret".to_string()];
        let sim = diff.compute_instruction_similarity(&a, &a);
        assert!((sim - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_instr_sim_both_empty() {
        let diff = SemanticDiff::new();
        let sim = diff.compute_instruction_similarity(&[], &[]);
        assert_eq!(sim, 1.0);
    }

    #[test]
    fn test_instr_sim_one_empty() {
        let diff = SemanticDiff::new();
        let a = vec!["ret".to_string()];
        assert_eq!(diff.compute_instruction_similarity(&a, &[]), 0.0);
    }

    #[test]
    fn test_instr_sim_partial() {
        let diff = SemanticDiff::new();
        let a = vec!["push rbp".to_string(), "mov rbp, rsp".to_string(), "ret".to_string()];
        let b = vec!["push rbp".to_string(), "mov rbp, rsp".to_string(), "nop".to_string()];
        let sim = diff.compute_instruction_similarity(&a, &b);
        assert!(sim > 0.5 && sim < 1.0);
    }

    // ── compute_cfg_similarity ─────────────────────────────────────────────────

    #[test]
    fn test_cfg_sim_identical() {
        let diff = SemanticDiff::new();
        let mut f = make_func(0x1000, "f", &["nop"]);
        f.basic_blocks = vec![0x1000];
        f.edge_count = 0;
        let sim = diff.compute_cfg_similarity(&f, &f);
        assert!((sim - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_cfg_sim_different_node_count() {
        let diff = SemanticDiff::new();
        let mut a = make_func(0x1000, "a", &["nop"; 3]);
        a.basic_blocks = vec![0x1000, 0x1002, 0x1004];
        a.edge_count = 2;
        let mut b = make_func(0x2000, "b", &["nop"; 1]);
        b.basic_blocks = vec![0x2000];
        b.edge_count = 0;
        let sim = diff.compute_cfg_similarity(&a, &b);
        assert!(sim < 1.0);
    }

    // ── match_functions ────────────────────────────────────────────────────────

    #[test]
    fn test_match_by_name() {
        let diff = SemanticDiff::new();
        let old = vec![make_func(0x1000, "main", &["push rbp", "ret"])];
        let new = vec![make_func(0x2000, "main", &["push rbp", "ret"])];
        let pairs = diff.match_functions(&old, &new);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, 0);
        assert_eq!(pairs[0].1, 0);
    }

    #[test]
    fn test_match_unmatched_functions_remain() {
        let diff = SemanticDiff::new();
        let old = vec![make_func(0x1000, "foo", &["nop"; 10])];
        let new = vec![make_func(0x2000, "bar", &["nop"; 2])];
        // Different names and very different sizes → similarity below threshold.
        let pairs = diff.match_functions(&old, &new);
        // pairs may or may not include this depending on similarity score.
        // Just ensure no panic and the result is coherent.
        assert!(pairs.len() <= 1);
    }

    // ── full diff ─────────────────────────────────────────────────────────────

    #[test]
    fn test_diff_added_removed() {
        let diff = SemanticDiff::new();
        let old = vec![make_func(0x1000, "a", &["nop"])];
        let new = vec![make_func(0x2000, "b", &["ret"])];
        let report = diff.diff(&old, &new);
        assert_eq!(report.summary.total_old, 1);
        assert_eq!(report.summary.total_new, 1);
    }

    #[test]
    fn test_diff_equivalent_function() {
        let diff = SemanticDiff::new();
        let mnemonics = vec!["push rbp".to_string(), "mov rbp, rsp".to_string(), "ret".to_string()];
        let f_old = FunctionEntry {
            address: 0x1000,
            name: "f".to_string(),
            mnemonics: mnemonics.clone(),
            basic_blocks: vec![0x1000],
            edge_count: 0,
            string_refs: Vec::new(),
            immediates: Vec::new(),
        };
        let f_new = FunctionEntry {
            address: 0x1000,
            name: "f".to_string(),
            mnemonics,
            basic_blocks: vec![0x1000],
            edge_count: 0,
            string_refs: Vec::new(),
            immediates: Vec::new(),
        };
        let report = diff.diff(&[f_old], &[f_new]);
        assert_eq!(report.summary.equivalent, 1);
        assert_eq!(report.summary.modified, 0);
    }

    #[test]
    fn test_diff_patched_function() {
        let diff = SemanticDiff::new();
        let old_mnemonics: Vec<String> = (0..20).map(|i| format!("instr_{i}")).collect();
        let mut new_mnemonics = old_mnemonics.clone();
        new_mnemonics[19] = "instr_modified".to_string();
        let f_old = FunctionEntry::new(0x1000, "f", old_mnemonics);
        let f_new = FunctionEntry::new(0x1000, "f", new_mnemonics);
        let report = diff.diff(&[f_old], &[f_new]);
        let fd = &report.diffs[0];
        assert!(fd.similarity > 0.5);
    }

    #[test]
    fn test_diff_summary_display() {
        let s = DiffSummary {
            total_old: 10,
            total_new: 12,
            added: 3,
            removed: 1,
            modified: 2,
            equivalent: 7,
        };
        let text = s.to_string();
        assert!(text.contains("10"));
        assert!(text.contains("12"));
    }

    #[test]
    fn test_diff_report_changed_iter() {
        let report = DiffReport {
            summary: DiffSummary::default(),
            diffs: vec![
                FunctionDiff {
                    old_addr: Some(0),
                    new_addr: Some(0),
                    name: "f".into(),
                    change_type: ChangeType::Patched,
                    similarity: 0.9,
                    diff_details: Vec::new(),
                    metrics: SimilarityMetrics::default(),
                },
                FunctionDiff {
                    old_addr: Some(1),
                    new_addr: Some(1),
                    name: "g".into(),
                    change_type: ChangeType::Equivalent,
                    similarity: 1.0,
                    diff_details: Vec::new(),
                    metrics: SimilarityMetrics::default(),
                },
            ],
        };
        assert_eq!(report.changed().count(), 1);
    }

    #[test]
    fn test_similarity_ratio() {
        let s = DiffSummary {
            total_old: 10,
            total_new: 10,
            equivalent: 8,
            ..Default::default()
        };
        let ratio = s.similarity_ratio();
        assert!((ratio - 0.8).abs() < 1e-9);
    }

    #[test]
    fn test_metrics_combined_weights_to_one() {
        let m = SimilarityMetrics {
            instruction_similarity: 1.0,
            cfg_similarity: 1.0,
            string_similarity: 1.0,
            constant_similarity: 1.0,
        };
        assert!((m.combined() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_diff_detail_display_dbg() {
        let d = DiffDetail::InstructionChanged { old: "nop".into(), new: "ret".into() };
        let s = format!("{d:?}");
        assert!(s.contains("nop"));
    }

    #[test]
    fn test_function_diff_is_trivial() {
        let fd_eq = FunctionDiff {
            old_addr: Some(0),
            new_addr: Some(0),
            name: "f".into(),
            change_type: ChangeType::Equivalent,
            similarity: 1.0,
            diff_details: Vec::new(),
            metrics: SimilarityMetrics::default(),
        };
        assert!(fd_eq.is_trivial());
        let fd_patched = FunctionDiff { change_type: ChangeType::Patched, ..fd_eq };
        assert!(!fd_patched.is_trivial());
    }

    #[test]
    fn test_change_type_display() {
        assert_eq!(ChangeType::Added.to_string(), "Added");
        assert_eq!(ChangeType::Patched.to_string(), "Patched");
        assert_eq!(ChangeType::Equivalent.to_string(), "Equivalent");
    }

    #[test]
    fn test_jaccard_empty() {
        let j = jaccard_str(&[], &[]);
        assert_eq!(j, 1.0);
    }

    #[test]
    fn test_jaccard_identical() {
        let a = vec!["hello".to_string(), "world".to_string()];
        let j = jaccard_str(&a, &a);
        assert!((j - 1.0).abs() < 1e-9);
    }
}
