//! Structural function diffing (`BinDiff` / Diaphora style).
//!
//! This module provides a self-contained, structure-aware comparison pipeline
//! that does not depend on heavy core types.  Functions are modelled by the
//! lightweight [`DiffFunction`] struct which carries only the features needed
//! for structural matching: basic-block count, control-flow edge count, the
//! in/out-degree distribution of the CFG, an instruction-mnemonic histogram
//! and the set of call targets.
//!
//! The matching pipeline mirrors the classic `BinDiff` approach:
//!
//! 1. **Exact structural hash** — functions whose [`md_index`](DiffFunction::md_index)
//!    "MD-index" fingerprints collide are matched immediately.
//! 2. **Name match** — remaining functions with identical names are paired.
//! 3. **Fuzzy structural similarity** — a greedy best-match assignment over the
//!    leftovers, scoring each candidate pair in `0.0..=1.0`.
//!
//! The result is bucketed into matched / added / removed entries and summarised
//! by a [`DiffReport`].

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// DiffFunction
// ---------------------------------------------------------------------------

/// A lightweight, self-contained description of a function for structural
/// diffing.
///
/// Unlike [`crate::FuncFingerprint`], this type does not carry the raw bytes of
/// the function; instead it captures the structural and semantic *features*
/// required by the BinDiff-style matching pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffFunction {
    /// Symbolic name of the function.
    pub name: String,
    /// Start address of the function in its binary.
    pub address: u64,
    /// Number of basic blocks in the control-flow graph.
    pub bb_count: usize,
    /// Number of control-flow edges in the control-flow graph.
    pub edge_count: usize,
    /// Histogram mapping instruction mnemonic to occurrence count.
    pub mnemonics: BTreeMap<String, usize>,
    /// Set of call-target addresses invoked by this function.
    pub call_targets: Vec<u64>,
    /// Out-degree of each basic block (number of outgoing edges).
    ///
    /// When left empty the structural hash falls back to a degree-agnostic
    /// approximation derived from [`bb_count`](Self::bb_count) and
    /// [`edge_count`](Self::edge_count).
    pub out_degrees: Vec<usize>,
    /// In-degree of each basic block (number of incoming edges).
    pub in_degrees: Vec<usize>,
}

impl DiffFunction {
    /// Create a new [`DiffFunction`] from a mnemonic list.
    ///
    /// The mnemonic histogram is built by counting occurrences in `mnemonics`.
    /// Degree distributions are left empty (the structural hash degrades
    /// gracefully in that case).
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        address: u64,
        bb_count: usize,
        edge_count: usize,
        mnemonics: &[String],
        call_targets: Vec<u64>,
    ) -> Self {
        let mut histogram: BTreeMap<String, usize> = BTreeMap::new();
        for m in mnemonics {
            *histogram.entry(m.clone()).or_insert(0) += 1;
        }
        Self {
            name: name.into(),
            address,
            bb_count,
            edge_count,
            mnemonics: histogram,
            call_targets,
            out_degrees: Vec::new(),
            in_degrees: Vec::new(),
        }
    }

    /// Attach the in/out-degree distributions of the CFG, returning `self`.
    ///
    /// This enables the richer "MD-index" structural hash that distinguishes
    /// functions with identical block/edge counts but different topology.
    #[must_use]
    pub fn with_degrees(mut self, in_degrees: Vec<usize>, out_degrees: Vec<usize>) -> Self {
        self.in_degrees = in_degrees;
        self.out_degrees = out_degrees;
        self
    }

    /// Total instruction count, derived from the mnemonic histogram.
    #[must_use]
    pub fn instruction_count(&self) -> usize {
        self.mnemonics.values().sum()
    }

    /// Compute an "MD-index"-style structural fingerprint of the function.
    ///
    /// The hash combines the basic-block count, edge count, the cyclomatic
    /// complexity (`edges - blocks + 2`) and the sorted in/out-degree
    /// distribution of the control-flow graph.  Two functions that share the
    /// same fingerprint are extremely likely to be structurally identical, which
    /// makes this a strong exact-match key.
    ///
    /// The fingerprint is intentionally independent of addresses, names and
    /// concrete instruction operands so that it is stable across recompilation.
    #[must_use]
    pub fn md_index(&self) -> u64 {
        // FNV-1a accumulation over a canonical feature encoding.
        const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
        const PRIME: u64 = 0x0000_0100_0000_01b3;
        let mut h = OFFSET_BASIS;
        let mut mix = |value: u64| {
            for byte in value.to_le_bytes() {
                h ^= u64::from(byte);
                h = h.wrapping_mul(PRIME);
            }
        };

        mix(self.bb_count as u64);
        mix(self.edge_count as u64);
        mix(self.cyclomatic_complexity());

        // Sorted degree multisets make the hash invariant to block ordering.
        let mut outs = self.out_degrees.clone();
        outs.sort_unstable();
        mix(0xD00D);
        for d in &outs {
            mix(*d as u64);
        }

        let mut ins = self.in_degrees.clone();
        ins.sort_unstable();
        mix(0xF00D);
        for d in &ins {
            mix(*d as u64);
        }

        h
    }

    /// Cyclomatic complexity `edges - blocks + 2`, saturating at the floor of 1.
    ///
    /// For a connected single-entry/single-exit CFG this equals the number of
    /// independent paths through the function.
    #[must_use]
    pub fn cyclomatic_complexity(&self) -> u64 {
        // edges - nodes + 2; computed with saturating arithmetic so degenerate
        // inputs (more nodes than edges) never underflow.
        let edges = self.edge_count as u64;
        let nodes = self.bb_count as u64;
        let c = edges.saturating_add(2).saturating_sub(nodes);
        c.max(1)
    }

    /// Structural similarity to another function in `0.0..=1.0`.
    ///
    /// The score is a weighted blend of four independent components:
    ///
    /// * basic-block count ratio (weight 0.25),
    /// * edge count ratio (weight 0.25),
    /// * cosine similarity of the mnemonic histograms (weight 0.35),
    /// * Jaccard similarity of the call-target sets (weight 0.15).
    ///
    /// Identical features yield exactly `1.0`; functions that share no features
    /// score near `0.0`.
    #[must_use]
    pub fn similarity(&self, other: &Self) -> f64 {
        const W_BB: f64 = 0.25;
        const W_EDGE: f64 = 0.25;
        const W_MNEM: f64 = 0.35;
        const W_CALL: f64 = 0.15;

        let bb = ratio(self.bb_count, other.bb_count);
        let edge = ratio(self.edge_count, other.edge_count);
        let mnem = histogram_cosine(&self.mnemonics, &other.mnemonics);
        let call = jaccard(&self.call_targets, &other.call_targets);

        let score = W_CALL.mul_add(call, W_MNEM.mul_add(mnem, W_BB.mul_add(bb, W_EDGE * edge)));
        score.clamp(0.0, 1.0)
    }
}

impl fmt::Display for DiffFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}@{:#x} bb={} edges={} cc={}",
            self.name,
            self.address,
            self.bb_count,
            self.edge_count,
            self.cyclomatic_complexity()
        )
    }
}

// ---------------------------------------------------------------------------
// Similarity helpers
// ---------------------------------------------------------------------------

/// Ratio of the smaller to the larger of two counts, in `0.0..=1.0`.
///
/// Returns `1.0` when both counts are zero (vacuously equal).
#[must_use]
pub fn ratio(a: usize, b: usize) -> f64 {
    if a == 0 && b == 0 {
        return 1.0;
    }
    let lo = a.min(b);
    let hi = a.max(b);
    // hi is non-zero here because not both are zero.
    f64::from(u32::try_from(lo).unwrap_or(u32::MAX))
        / f64::from(u32::try_from(hi).unwrap_or(u32::MAX))
}

/// Cosine similarity of two mnemonic histograms in `0.0..=1.0`.
///
/// Each histogram is treated as a sparse vector over the union of mnemonics.
/// Two empty histograms are considered identical (`1.0`); one empty and one
/// non-empty score `0.0`.
#[must_use]
pub fn histogram_cosine(a: &BTreeMap<String, usize>, b: &BTreeMap<String, usize>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let mut dot = 0.0f64;
    for (key, &av) in a {
        if let Some(&bv) = b.get(key) {
            let fav = f64::from(u32::try_from(av).unwrap_or(u32::MAX));
            let fbv = f64::from(u32::try_from(bv).unwrap_or(u32::MAX));
            dot = fav.mul_add(fbv, dot);
        }
    }
    let norm_a: f64 = a
        .values()
        .map(|&v| { let fv = f64::from(u32::try_from(v).unwrap_or(u32::MAX)); fv * fv })
        .sum::<f64>()
        .sqrt();
    let norm_b: f64 = b
        .values()
        .map(|&v| { let fv = f64::from(u32::try_from(v).unwrap_or(u32::MAX)); fv * fv })
        .sum::<f64>()
        .sqrt();
    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }
    (dot / (norm_a * norm_b)).clamp(0.0, 1.0)
}

/// Jaccard similarity of two sets (presented as slices) in `0.0..=1.0`.
///
/// Duplicate elements are ignored.  Two empty sets are considered identical
/// (`1.0`).
#[must_use]
pub fn jaccard<T: Ord + Clone>(a: &[T], b: &[T]) -> f64 {
    use std::collections::BTreeSet;
    let sa: BTreeSet<&T> = a.iter().collect();
    let sb: BTreeSet<&T> = b.iter().collect();
    if sa.is_empty() && sb.is_empty() {
        return 1.0;
    }
    let intersection = sa.intersection(&sb).count();
    let union = sa.union(&sb).count();
    if union == 0 {
        return 1.0;
    }
    f64::from(u32::try_from(intersection).unwrap_or(u32::MAX))
        / f64::from(u32::try_from(union).unwrap_or(u32::MAX))
}

// ---------------------------------------------------------------------------
// StructuralMatchKind / StructuralMatch
// ---------------------------------------------------------------------------

/// How a [`StructuralMatch`] pair was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StructuralMatchKind {
    /// Matched by identical MD-index structural fingerprint.
    ExactHash,
    /// Matched by identical symbolic name.
    Name,
    /// Matched by fuzzy structural similarity.
    Fuzzy,
    /// Present only in the new function set.
    Added,
    /// Present only in the old function set.
    Removed,
}

impl fmt::Display for StructuralMatchKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A single pairing (or unpaired entry) produced by [`StructuralDiffer`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuralMatch {
    /// Function from the old set, if present.
    pub old: Option<DiffFunction>,
    /// Function from the new set, if present.
    pub new: Option<DiffFunction>,
    /// How the pair was established.
    pub kind: StructuralMatchKind,
    /// Structural similarity score in `0.0..=1.0`.
    pub similarity: f64,
}

impl StructuralMatch {
    /// Create a matched pair with the given kind and similarity.
    #[must_use]
    pub const fn paired(
        old: DiffFunction,
        new: DiffFunction,
        kind: StructuralMatchKind,
        similarity: f64,
    ) -> Self {
        Self {
            old: Some(old),
            new: Some(new),
            kind,
            similarity,
        }
    }

    /// Create an "added" entry (present only in the new set).
    #[must_use]
    pub const fn added(new: DiffFunction) -> Self {
        Self {
            old: None,
            new: Some(new),
            kind: StructuralMatchKind::Added,
            similarity: 0.0,
        }
    }

    /// Create a "removed" entry (present only in the old set).
    #[must_use]
    pub const fn removed(old: DiffFunction) -> Self {
        Self {
            old: Some(old),
            new: None,
            kind: StructuralMatchKind::Removed,
            similarity: 0.0,
        }
    }

    /// Return `true` if both sides are present and byte-equivalent in structure
    /// (similarity is exactly `1.0`).
    #[must_use]
    pub fn is_identical(&self) -> bool {
        self.old.is_some() && self.new.is_some() && (self.similarity - 1.0).abs() < f64::EPSILON
    }

    /// Return `true` if both sides are present but differ structurally.
    #[must_use]
    pub fn is_changed(&self) -> bool {
        self.old.is_some() && self.new.is_some() && !self.is_identical()
    }
}

impl fmt::Display for StructuralMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let old = self.old.as_ref().map_or("<none>", |o| o.name.as_str());
        let new = self.new.as_ref().map_or("<none>", |n| n.name.as_str());
        write!(
            f,
            "{} \u{2194} {} ({} {:.1}%)",
            old,
            new,
            self.kind,
            self.similarity * 100.0
        )
    }
}

// ---------------------------------------------------------------------------
// DiffReport
// ---------------------------------------------------------------------------

/// Summary of a structural diff between two function sets.
///
/// Holds every [`StructuralMatch`] plus aggregate counts and a binary-wide
/// similarity ratio.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    /// Every match / unpaired entry produced by the pipeline.
    pub matches: Vec<StructuralMatch>,
    /// Function count in the old set.
    pub total_old: usize,
    /// Function count in the new set.
    pub total_new: usize,
}

impl DiffReport {
    /// Create a report from a set of matches and the two input cardinalities.
    #[must_use]
    pub const fn new(matches: Vec<StructuralMatch>, total_old: usize, total_new: usize) -> Self {
        Self {
            matches,
            total_old,
            total_new,
        }
    }

    /// Count of structurally identical pairs (similarity `== 1.0`).
    #[must_use]
    pub fn identical_count(&self) -> usize {
        self.matches.iter().filter(|m| m.is_identical()).count()
    }

    /// Count of paired-but-similar functions (matched via fuzzy/exact/name but
    /// not exactly identical).
    #[must_use]
    pub fn similar_count(&self) -> usize {
        self.matches
            .iter()
            .filter(|m| m.is_changed() && m.similarity >= 0.5)
            .count()
    }

    /// Count of paired functions whose similarity fell below `0.5`.
    #[must_use]
    pub fn changed_count(&self) -> usize {
        self.matches
            .iter()
            .filter(|m| m.is_changed() && m.similarity < 0.5)
            .count()
    }

    /// Count of functions present only in the new set.
    #[must_use]
    pub fn added_count(&self) -> usize {
        self.matches
            .iter()
            .filter(|m| m.kind == StructuralMatchKind::Added)
            .count()
    }

    /// Count of functions present only in the old set.
    #[must_use]
    pub fn removed_count(&self) -> usize {
        self.matches
            .iter()
            .filter(|m| m.kind == StructuralMatchKind::Removed)
            .count()
    }

    /// Total number of matched pairs (both sides present).
    #[must_use]
    pub fn matched_count(&self) -> usize {
        self.matches
            .iter()
            .filter(|m| m.old.is_some() && m.new.is_some())
            .count()
    }

    /// Whole-binary similarity ratio in `0.0..=1.0`.
    ///
    /// Computed as the mean similarity of all matched pairs, weighted down by
    /// the fraction of functions that could be paired at all.  A binary diffed
    /// against itself returns `1.0`; two binaries that share nothing return
    /// `0.0`.
    #[must_use]
    pub fn similarity_ratio(&self) -> f64 {
        let paired: Vec<f64> = self
            .matches
            .iter()
            .filter(|m| m.old.is_some() && m.new.is_some())
            .map(|m| m.similarity)
            .collect();
        if paired.is_empty() {
            return 0.0;
        }
        let mean_pair_sim = paired.iter().sum::<f64>()
            / f64::from(u32::try_from(paired.len()).unwrap_or(u32::MAX));
        let total = self.total_old.max(self.total_new);
        if total == 0 {
            return mean_pair_sim;
        }
        let coverage = f64::from(u32::try_from(paired.len()).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(total).unwrap_or(u32::MAX));
        (mean_pair_sim * coverage).clamp(0.0, 1.0)
    }
}

impl DiffReport {
    /// Generate a simple colored HTML diff report.
    ///
    /// Each function match is rendered as a table row color-coded by status:
    /// green (identical), yellow (similar/changed), red (removed), blue (added).
    #[must_use]
    pub fn generate_html(&self) -> String {
        let mut rows = String::new();
        for m in &self.matches {
            let (old_name, new_name, status, color) = match (&m.old, &m.new) {
                (Some(o), Some(n)) if m.is_identical() => (
                    o.name.clone(),
                    n.name.clone(),
                    "Identical".to_string(),
                    "#d4edda",
                ),
                (Some(o), Some(n)) => (
                    o.name.clone(),
                    n.name.clone(),
                    format!("Modified ({:.1}%)", m.similarity * 100.0),
                    "#fff3cd",
                ),
                (Some(o), None) => (
                    o.name.clone(),
                    String::new(),
                    "Removed".to_string(),
                    "#f8d7da",
                ),
                (None, Some(n)) => (
                    String::new(),
                    n.name.clone(),
                    "Added".to_string(),
                    "#cce5ff",
                ),
                (None, None) => continue,
            };
            {
                use std::fmt::Write as _;
                writeln!(
                    rows,
                    "<tr style=\"background:{color}\">\
                      <td>{old_name}</td>\
                      <td>{new_name}</td>\
                      <td>{status}</td>\
                      <td>{:.1}%</td>\
                    </tr>",
                    m.similarity * 100.0
                ).unwrap_or_default();
            }
        }

        format!(
            r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Binary Diff Report</title>
  <style>
    body {{ font-family: monospace; margin: 1em; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ccc; padding: 4px 8px; text-align: left; }}
    th {{ background: #333; color: #fff; }}
    .summary {{ margin-bottom: 1em; }}
  </style>
</head>
<body>
  <h2>Binary Diff Report</h2>
  <div class="summary">
    <b>Old:</b> {total_old} functions &nbsp;|&nbsp;
    <b>New:</b> {total_new} functions &nbsp;|&nbsp;
    <b>Binary similarity:</b> {sim:.1}%<br/>
    <span style="color:green">&#9632; Identical: {identical}</span> &nbsp;
    <span style="color:goldenrod">&#9632; Modified: {similar}</span> &nbsp;
    <span style="color:red">&#9632; Removed: {removed}</span> &nbsp;
    <span style="color:blue">&#9632; Added: {added}</span>
  </div>
  <table>
    <tr><th>Old Function</th><th>New Function</th><th>Status</th><th>Similarity</th></tr>
    {rows}
  </table>
</body>
</html>"#,
            total_old = self.total_old,
            total_new = self.total_new,
            sim = self.similarity_ratio() * 100.0,
            identical = self.identical_count(),
            similar = self.similar_count() + self.changed_count(),
            removed = self.removed_count(),
            added = self.added_count(),
            rows = rows,
        )
    }

    /// Generate a machine-readable JSON diff report.
    ///
    /// Returns a [`serde_json::Value`] with summary statistics and a `matches`
    /// array, each entry containing `old_name`, `new_name`, `kind`, `similarity`.
    #[must_use]
    pub fn generate_json(&self) -> Value {
        let matches_arr: Vec<Value> = self
            .matches
            .iter()
            .map(|m| {
                json!({
                    "old_name": m.old.as_ref().map(|o| &o.name),
                    "old_address": m.old.as_ref().map(|o| o.address),
                    "new_name": m.new.as_ref().map(|n| &n.name),
                    "new_address": m.new.as_ref().map(|n| n.address),
                    "kind": format!("{}", m.kind),
                    "similarity": m.similarity,
                    "is_identical": m.is_identical(),
                    "is_changed": m.is_changed(),
                })
            })
            .collect();

        json!({
            "summary": {
                "total_old": self.total_old,
                "total_new": self.total_new,
                "identical": self.identical_count(),
                "similar": self.similar_count(),
                "changed": self.changed_count(),
                "added": self.added_count(),
                "removed": self.removed_count(),
                "matched": self.matched_count(),
                "binary_similarity": self.similarity_ratio(),
            },
            "matches": matches_arr,
        })
    }
}

impl fmt::Display for DiffReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DiffReport: {} old / {} new — identical={} similar={} changed={} added={} removed={} (binary similarity {:.1}%)",
            self.total_old,
            self.total_new,
            self.identical_count(),
            self.similar_count(),
            self.changed_count(),
            self.added_count(),
            self.removed_count(),
            self.similarity_ratio() * 100.0,
        )
    }
}

// ---------------------------------------------------------------------------
// StructuralDiffer — the matching pipeline
// ---------------------------------------------------------------------------

/// Structural matching engine.
///
/// Runs the three-stage pipeline (exact hash → name → fuzzy greedy assignment)
/// over two function sets and produces a [`DiffReport`].
#[derive(Debug, Clone)]
pub struct StructuralDiffer {
    /// Minimum similarity required to accept a fuzzy match.
    fuzzy_threshold: f64,
}

impl StructuralDiffer {
    /// Create a differ with the given fuzzy-match threshold (`0.0..=1.0`).
    #[must_use]
    pub const fn new(fuzzy_threshold: f64) -> Self {
        Self {
            fuzzy_threshold: fuzzy_threshold.clamp(0.0, 1.0),
        }
    }

    /// The configured fuzzy-match threshold.
    #[must_use]
    pub const fn fuzzy_threshold(&self) -> f64 {
        self.fuzzy_threshold
    }

    /// Diff two function sets, returning a [`DiffReport`].
    ///
    /// The two slices are consumed by clone; the originals are left untouched.
    /// The greedy fuzzy pass produces a stable, deterministic assignment: it is
    /// not globally optimal (a Hungarian-algorithm assignment is a future
    /// optimization) but is a clean approximation that runs in
    /// `O(n_a * n_b)` similarity evaluations.
    #[must_use]
    pub fn diff(&self, old: &[DiffFunction], new: &[DiffFunction]) -> DiffReport {
        let total_old = old.len();
        let total_new = new.len();

        let mut used_old = vec![false; old.len()];
        let mut used_new = vec![false; new.len()];
        let mut matches: Vec<StructuralMatch> = Vec::new();

        // Pass 1: exact MD-index hash match.
        let mut hash_index: HashMap<u64, Vec<usize>> = HashMap::new();
        for (i, f) in new.iter().enumerate() {
            hash_index.entry(f.md_index()).or_default().push(i);
        }
        for (oi, of) in old.iter().enumerate() {
            if used_old[oi] {
                continue;
            }
            if let Some(candidates) = hash_index.get(&of.md_index())
                && let Some(&ni) = candidates.iter().find(|&&ni| !used_new[ni])
            {
                let sim = of.similarity(&new[ni]);
                used_old[oi] = true;
                used_new[ni] = true;
                matches.push(StructuralMatch::paired(
                    of.clone(),
                    new[ni].clone(),
                    StructuralMatchKind::ExactHash,
                    sim,
                ));
            }
        }

        // Pass 2: name match over the remainder.
        let mut name_index: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, f) in new.iter().enumerate() {
            if !used_new[i] {
                name_index.entry(f.name.as_str()).or_default().push(i);
            }
        }
        for (oi, of) in old.iter().enumerate() {
            if used_old[oi] {
                continue;
            }
            if let Some(candidates) = name_index.get(of.name.as_str())
                && let Some(&ni) = candidates.iter().find(|&&ni| !used_new[ni])
            {
                let sim = of.similarity(&new[ni]);
                used_old[oi] = true;
                used_new[ni] = true;
                matches.push(StructuralMatch::paired(
                    of.clone(),
                    new[ni].clone(),
                    StructuralMatchKind::Name,
                    sim,
                ));
            }
        }

        // Pass 3: greedy fuzzy assignment.
        //
        // Compute every candidate pair score above threshold, sort descending,
        // and greedily commit the best available pairs.
        let mut candidates: Vec<(f64, usize, usize)> = Vec::new();
        for (oi, of) in old.iter().enumerate() {
            if used_old[oi] {
                continue;
            }
            for (ni, nf) in new.iter().enumerate() {
                if used_new[ni] {
                    continue;
                }
                let sim = of.similarity(nf);
                if sim >= self.fuzzy_threshold {
                    candidates.push((sim, oi, ni));
                }
            }
        }
        // Highest similarity first; ties broken by address for determinism.
        candidates.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.1.cmp(&b.1))
                .then_with(|| a.2.cmp(&b.2))
        });
        for (sim, oi, ni) in candidates {
            if used_old[oi] || used_new[ni] {
                continue;
            }
            used_old[oi] = true;
            used_new[ni] = true;
            matches.push(StructuralMatch::paired(
                old[oi].clone(),
                new[ni].clone(),
                StructuralMatchKind::Fuzzy,
                sim,
            ));
        }

        // Leftovers: removed (old) and added (new).
        for (oi, of) in old.iter().enumerate() {
            if !used_old[oi] {
                matches.push(StructuralMatch::removed(of.clone()));
            }
        }
        for (ni, nf) in new.iter().enumerate() {
            if !used_new[ni] {
                matches.push(StructuralMatch::added(nf.clone()));
            }
        }

        DiffReport::new(matches, total_old, total_new)
    }
}

impl Default for StructuralDiffer {
    fn default() -> Self {
        Self::new(0.5)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mnem(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    fn func(
        name: &str,
        addr: u64,
        bb: usize,
        edges: usize,
        mnems: &[&str],
        calls: Vec<u64>,
    ) -> DiffFunction {
        DiffFunction::new(name, addr, bb, edges, &mnem(mnems), calls)
    }

    // ---- ratio -------------------------------------------------------------

    #[test]
    fn test_ratio_both_zero() {
        assert!((ratio(0, 0) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_ratio_equal() {
        assert!((ratio(7, 7) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_ratio_one_zero() {
        assert!((ratio(0, 5)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_ratio_half() {
        assert!((ratio(5, 10) - 0.5).abs() < f64::EPSILON);
    }

    // ---- histogram_cosine --------------------------------------------------

    #[test]
    fn test_cosine_both_empty() {
        let a = BTreeMap::new();
        let b = BTreeMap::new();
        assert!((histogram_cosine(&a, &b) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cosine_one_empty() {
        let mut a = BTreeMap::new();
        a.insert("mov".to_string(), 3);
        let b = BTreeMap::new();
        assert!((histogram_cosine(&a, &b)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cosine_identical() {
        let mut a = BTreeMap::new();
        a.insert("mov".to_string(), 3);
        a.insert("call".to_string(), 1);
        let b = a.clone();
        assert!((histogram_cosine(&a, &b) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn test_cosine_disjoint() {
        let mut a = BTreeMap::new();
        a.insert("mov".to_string(), 3);
        let mut b = BTreeMap::new();
        b.insert("xor".to_string(), 3);
        assert!((histogram_cosine(&a, &b)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cosine_partial() {
        let mut a = BTreeMap::new();
        a.insert("mov".to_string(), 2);
        a.insert("add".to_string(), 2);
        let mut b = BTreeMap::new();
        b.insert("mov".to_string(), 2);
        b.insert("sub".to_string(), 2);
        let s = histogram_cosine(&a, &b);
        assert!(s > 0.0 && s < 1.0);
    }

    // ---- jaccard -----------------------------------------------------------

    #[test]
    fn test_jaccard_both_empty() {
        let a: Vec<u64> = vec![];
        let b: Vec<u64> = vec![];
        assert!((jaccard(&a, &b) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_jaccard_one_empty() {
        let a: Vec<u64> = vec![1, 2, 3];
        let b: Vec<u64> = vec![];
        assert!((jaccard(&a, &b)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_jaccard_identical() {
        let a = vec![1u64, 2, 3];
        let b = vec![3u64, 2, 1];
        assert!((jaccard(&a, &b) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_jaccard_half() {
        let a = vec![1u64, 2];
        let b = vec![2u64, 3];
        // intersection {2} = 1, union {1,2,3} = 3
        assert!((jaccard(&a, &b) - (1.0 / 3.0)).abs() < 1e-12);
    }

    #[test]
    fn test_jaccard_ignores_duplicates() {
        let a = vec![1u64, 1, 1];
        let b = vec![1u64];
        assert!((jaccard(&a, &b) - 1.0).abs() < f64::EPSILON);
    }

    // ---- md_index / cyclomatic --------------------------------------------

    #[test]
    fn test_md_index_deterministic() {
        let f = func("f", 0x1000, 4, 5, &["mov", "call"], vec![0x2000]);
        assert_eq!(f.md_index(), f.md_index());
    }

    #[test]
    fn test_md_index_same_structure_matches() {
        let a = func("a", 0x1000, 4, 5, &["mov"], vec![]);
        let b = func("b", 0x9000, 4, 5, &["xor"], vec![]);
        // MD-index ignores names, addresses and mnemonics → same fingerprint.
        assert_eq!(a.md_index(), b.md_index());
    }

    #[test]
    fn test_md_index_differs_on_structure() {
        let a = func("a", 0x1000, 4, 5, &["mov"], vec![]);
        let b = func("a", 0x1000, 6, 9, &["mov"], vec![]);
        assert_ne!(a.md_index(), b.md_index());
    }

    #[test]
    fn test_md_index_degree_sensitivity() {
        let base = func("a", 0x1000, 3, 3, &["mov"], vec![]);
        let a = base.clone().with_degrees(vec![0, 1, 2], vec![2, 1, 0]);
        let b = base.with_degrees(vec![1, 1, 1], vec![1, 1, 1]);
        assert_ne!(a.md_index(), b.md_index());
    }

    #[test]
    fn test_cyclomatic_complexity() {
        // 5 edges, 4 nodes → 5 - 4 + 2 = 3
        let f = func("f", 0, 4, 5, &[], vec![]);
        assert_eq!(f.cyclomatic_complexity(), 3);
    }

    #[test]
    fn test_cyclomatic_floor() {
        // degenerate: 0 edges, 5 nodes → would be negative → clamped to 1
        let f = func("f", 0, 5, 0, &[], vec![]);
        assert_eq!(f.cyclomatic_complexity(), 1);
    }

    // ---- DiffFunction::similarity -----------------------------------------

    #[test]
    fn test_similarity_identical() {
        let a = func("f", 0x1000, 4, 5, &["mov", "mov", "call"], vec![0x2000]);
        let b = func("f", 0x1000, 4, 5, &["mov", "mov", "call"], vec![0x2000]);
        assert!((a.similarity(&b) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_similarity_completely_different() {
        let a = func("a", 0x1000, 1, 0, &["mov"], vec![0x10]);
        let b = func(
            "b",
            0x9000,
            50,
            80,
            &["xor", "xor", "xor"],
            vec![0x99, 0x98],
        );
        let s = a.similarity(&b);
        assert!(s < 0.2, "expected near-zero similarity, got {s}");
    }

    #[test]
    fn test_similarity_in_range() {
        let a = func("a", 0, 4, 5, &["mov", "add"], vec![1]);
        let b = func("b", 0, 3, 4, &["mov", "sub"], vec![2]);
        let s = a.similarity(&b);
        assert!((0.0..=1.0).contains(&s));
    }

    #[test]
    fn test_instruction_count() {
        let f = func("f", 0, 1, 0, &["mov", "mov", "call"], vec![]);
        assert_eq!(f.instruction_count(), 3);
    }

    #[test]
    fn test_diff_function_display() {
        let f = func("main", 0x401000, 4, 5, &["mov"], vec![]);
        let s = f.to_string();
        assert!(s.contains("main"));
        assert!(s.contains("0x401000"));
        assert!(s.contains("cc=3"));
    }

    // ---- StructuralMatch ---------------------------------------------------

    #[test]
    fn test_structural_match_added_removed() {
        let f = func("f", 0, 1, 0, &["ret"], vec![]);
        let added = StructuralMatch::added(f.clone());
        let removed = StructuralMatch::removed(f);
        assert_eq!(added.kind, StructuralMatchKind::Added);
        assert!(added.old.is_none());
        assert_eq!(removed.kind, StructuralMatchKind::Removed);
        assert!(removed.new.is_none());
    }

    #[test]
    fn test_structural_match_identical_changed() {
        let func_a = func("f", 0, 4, 5, &["mov"], vec![]);
        let func_b = func_a.clone();
        let pair_same = StructuralMatch::paired(func_a, func_b, StructuralMatchKind::ExactHash, 1.0);
        assert!(pair_same.is_identical());
        assert!(!pair_same.is_changed());

        let func_c = func("f", 0, 4, 5, &["mov"], vec![]);
        let func_d = func("f", 0, 3, 4, &["sub"], vec![]);
        let sim = func_c.similarity(&func_d);
        let pair_diff = StructuralMatch::paired(func_c, func_d, StructuralMatchKind::Fuzzy, sim);
        assert!(pair_diff.is_changed());
        assert!(!pair_diff.is_identical());
    }

    #[test]
    fn test_structural_match_display() {
        let a = func("alpha", 0, 1, 0, &["ret"], vec![]);
        let m = StructuralMatch::removed(a);
        let s = m.to_string();
        assert!(s.contains("alpha"));
        assert!(s.contains("Removed"));
    }

    #[test]
    fn test_structural_match_kind_display() {
        assert_eq!(StructuralMatchKind::ExactHash.to_string(), "ExactHash");
        assert_eq!(StructuralMatchKind::Fuzzy.to_string(), "Fuzzy");
        assert_eq!(StructuralMatchKind::Name.to_string(), "Name");
    }

    // ---- StructuralDiffer --------------------------------------------------

    #[test]
    fn test_differ_identical_sets() {
        let set = vec![
            func("main", 0x1000, 4, 5, &["mov", "call"], vec![0x2000]),
            func("helper", 0x2000, 2, 1, &["ret"], vec![]),
        ];
        let report = StructuralDiffer::default().diff(&set, &set);
        assert_eq!(report.identical_count(), 2);
        assert_eq!(report.added_count(), 0);
        assert_eq!(report.removed_count(), 0);
        assert!((report.similarity_ratio() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_differ_added_function() {
        let old = vec![func("main", 0x1000, 4, 5, &["mov"], vec![])];
        let mut new = old.clone();
        new.push(func(
            "brand_new",
            0x3000,
            8,
            12,
            &["xor", "jmp"],
            vec![0x40],
        ));
        let report = StructuralDiffer::default().diff(&old, &new);
        assert_eq!(report.added_count(), 1);
        assert_eq!(report.removed_count(), 0);
        assert_eq!(report.identical_count(), 1);
    }

    #[test]
    fn test_differ_removed_function() {
        let mut old = vec![func("main", 0x1000, 4, 5, &["mov"], vec![])];
        old.push(func("gone", 0x3000, 8, 12, &["xor", "jmp"], vec![0x40]));
        let new = vec![func("main", 0x1000, 4, 5, &["mov"], vec![])];
        let report = StructuralDiffer::default().diff(&old, &new);
        assert_eq!(report.removed_count(), 1);
        assert_eq!(report.added_count(), 0);
    }

    #[test]
    fn test_differ_name_match_changed_body() {
        // Same name, different structure → matched by name pass, but changed.
        let old = vec![func("compute", 0x1000, 4, 5, &["mov", "add"], vec![0x2000])];
        let new = vec![func(
            "compute",
            0x1500,
            6,
            9,
            &["mov", "sub", "mul"],
            vec![0x2000, 0x3000],
        )];
        let report = StructuralDiffer::new(0.99).diff(&old, &new);
        assert_eq!(report.matched_count(), 1);
        assert_eq!(report.matches[0].kind, StructuralMatchKind::Name);
        assert!(report.matches[0].is_changed());
    }

    #[test]
    fn test_differ_fuzzy_match() {
        // Different names, no exact-hash collision, but high structural overlap.
        let old = vec![func(
            "old_name",
            0x1000,
            4,
            6,
            &["mov", "mov", "call", "ret"],
            vec![0x2000],
        )];
        let new = vec![func(
            "new_name",
            0x5000,
            4,
            6,
            &["mov", "mov", "call", "ret"],
            vec![0x2000],
        )];
        let report = StructuralDiffer::new(0.5).diff(&old, &new);
        assert_eq!(report.matched_count(), 1);
        // exact-hash on identical structure wins before fuzzy.
        assert!(matches!(
            report.matches[0].kind,
            StructuralMatchKind::ExactHash | StructuralMatchKind::Fuzzy
        ));
    }

    #[test]
    fn test_differ_no_match_below_threshold() {
        let old = vec![func("a", 0x1000, 1, 0, &["mov"], vec![0x10])];
        let new = vec![func("b", 0x9000, 40, 70, &["xor", "xor"], vec![0x99])];
        let report = StructuralDiffer::new(0.6).diff(&old, &new);
        assert_eq!(report.added_count(), 1);
        assert_eq!(report.removed_count(), 1);
        assert_eq!(report.matched_count(), 0);
    }

    #[test]
    fn test_differ_empty_inputs() {
        let report = StructuralDiffer::default().diff(&[], &[]);
        assert_eq!(report.matched_count(), 0);
        assert_eq!(report.added_count(), 0);
        assert_eq!(report.removed_count(), 0);
        assert!((report.similarity_ratio()).abs() < f64::EPSILON);
    }

    #[test]
    fn test_differ_greedy_picks_best() {
        // old A should pair with the structurally closest new function.
        let old = vec![func(
            "A",
            0x1000,
            10,
            14,
            &["mov", "mov", "mov", "call"],
            vec![0x10, 0x20],
        )];
        let new = vec![
            func("X", 0x2000, 2, 1, &["ret"], vec![]),
            func(
                "Y",
                0x3000,
                10,
                14,
                &["mov", "mov", "mov", "call"],
                vec![0x10, 0x20],
            ),
        ];
        let report = StructuralDiffer::new(0.4).diff(&old, &new);
        let matched = report
            .matches
            .iter()
            .find(|m| m.old.is_some() && m.new.is_some())
            .unwrap();
        assert_eq!(matched.new.as_ref().unwrap().name, "Y");
    }

    // ---- DiffReport --------------------------------------------------------

    #[test]
    fn test_diff_report_counts_and_display() {
        let old = vec![
            func("keep", 0x1000, 4, 5, &["mov"], vec![]),
            func("changed", 0x2000, 4, 5, &["mov", "add"], vec![0x9]),
            func("removed", 0x3000, 7, 10, &["jmp"], vec![]),
        ];
        let new = vec![
            func("keep", 0x1000, 4, 5, &["mov"], vec![]),
            func("changed", 0x2200, 4, 5, &["mov", "sub"], vec![0x9]),
            func("added", 0x4000, 9, 14, &["xor"], vec![]),
        ];
        let report = StructuralDiffer::new(0.99).diff(&old, &new);
        assert_eq!(report.total_old, 3);
        assert_eq!(report.total_new, 3);
        assert_eq!(report.added_count(), 1);
        assert_eq!(report.removed_count(), 1);
        assert!(report.matched_count() >= 1);
        let s = report.to_string();
        assert!(s.contains("DiffReport"));
        assert!(s.contains("added=1"));
        assert!(s.contains("removed=1"));
    }

    #[test]
    fn test_diff_report_similarity_ratio_no_pairs() {
        let report = DiffReport::new(vec![], 0, 0);
        assert!((report.similarity_ratio()).abs() < f64::EPSILON);
    }

    #[test]
    fn test_diff_report_serialization() {
        let old = vec![func("f", 0x1000, 4, 5, &["mov"], vec![])];
        let report = StructuralDiffer::default().diff(&old, &old);
        let json = serde_json::to_string(&report).unwrap();
        let decoded: DiffReport = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.total_old, 1);
        assert_eq!(decoded.matched_count(), 1);
    }

    #[test]
    fn test_differ_threshold_clamped() {
        let d = StructuralDiffer::new(5.0);
        assert!((d.fuzzy_threshold() - 1.0).abs() < f64::EPSILON);
        let d2 = StructuralDiffer::new(-1.0);
        assert!((d2.fuzzy_threshold()).abs() < f64::EPSILON);
    }

    #[test]
    fn test_diff_function_serialization() {
        let f = func("f", 0x1000, 4, 5, &["mov", "call"], vec![0x2000]);
        let json = serde_json::to_string(&f).unwrap();
        let decoded: DiffFunction = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.name, "f");
        assert_eq!(decoded.bb_count, 4);
    }
}
