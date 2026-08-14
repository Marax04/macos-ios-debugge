//! `diff_algorithm` — Core diff algorithms for byte sequences.
//!
//! Provides [`DiffAlgorithm`], [`DiffResult`], and [`EditScript`] along with
//! a proper Myers diff implementation ([`myers_diff`]) and supporting helpers.

use std::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by diff algorithm operations.
#[derive(Debug, Error)]
pub enum DiffAlgorithmError {
    /// Inputs are both empty and nothing to diff.
    #[error("both inputs are empty")]
    BothEmpty,
    /// A configuration parameter is out of range.
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),
}

// ---------------------------------------------------------------------------
// EditKind
// ---------------------------------------------------------------------------

/// The kind of a single edit operation in an edit script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EditKind {
    /// Element is equal in both sequences (no change needed).
    Equal,
    /// Element was inserted into the new sequence.
    Insert,
    /// Element was deleted from the old sequence.
    Delete,
    /// Element was replaced (delete old, insert new).
    Replace,
}

impl fmt::Display for EditKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Equal => write!(f, "="),
            Self::Insert => write!(f, "+"),
            Self::Delete => write!(f, "-"),
            Self::Replace => write!(f, "~"),
        }
    }
}

// ---------------------------------------------------------------------------
// EditOp
// ---------------------------------------------------------------------------

/// A single operation in an edit script.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EditOp {
    /// The kind of this edit.
    pub kind: EditKind,
    /// Index in the old (left) sequence, if applicable.
    pub old_index: Option<usize>,
    /// Index in the new (right) sequence, if applicable.
    pub new_index: Option<usize>,
    /// The byte value from the old sequence (for Delete/Replace/Equal).
    pub old_value: Option<u8>,
    /// The byte value from the new sequence (for Insert/Replace/Equal).
    pub new_value: Option<u8>,
}

impl EditOp {
    /// Create an Equal operation.
    #[must_use]
    pub const fn equal(old_index: usize, new_index: usize, value: u8) -> Self {
        Self {
            kind: EditKind::Equal,
            old_index: Some(old_index),
            new_index: Some(new_index),
            old_value: Some(value),
            new_value: Some(value),
        }
    }

    /// Create an Insert operation.
    #[must_use]
    pub const fn insert(new_index: usize, value: u8) -> Self {
        Self {
            kind: EditKind::Insert,
            old_index: None,
            new_index: Some(new_index),
            old_value: None,
            new_value: Some(value),
        }
    }

    /// Create a Delete operation.
    #[must_use]
    pub const fn delete(old_index: usize, value: u8) -> Self {
        Self {
            kind: EditKind::Delete,
            old_index: Some(old_index),
            new_index: None,
            old_value: Some(value),
            new_value: None,
        }
    }

    /// Create a Replace operation.
    #[must_use]
    pub const fn replace(old_index: usize, new_index: usize, old_value: u8, new_value: u8) -> Self {
        Self {
            kind: EditKind::Replace,
            old_index: Some(old_index),
            new_index: Some(new_index),
            old_value: Some(old_value),
            new_value: Some(new_value),
        }
    }
}

impl fmt::Display for EditOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            EditKind::Equal => write!(
                f, "= old[{}] == new[{}] ({:#04x})",
                self.old_index.unwrap_or(0),
                self.new_index.unwrap_or(0),
                self.old_value.unwrap_or(0)
            ),
            EditKind::Insert => write!(
                f, "+ new[{}] ({:#04x})",
                self.new_index.unwrap_or(0),
                self.new_value.unwrap_or(0)
            ),
            EditKind::Delete => write!(
                f, "- old[{}] ({:#04x})",
                self.old_index.unwrap_or(0),
                self.old_value.unwrap_or(0)
            ),
            EditKind::Replace => write!(
                f, "~ old[{}]={:#04x} -> new[{}]={:#04x}",
                self.old_index.unwrap_or(0),
                self.old_value.unwrap_or(0),
                self.new_index.unwrap_or(0),
                self.new_value.unwrap_or(0)
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// EditScript
// ---------------------------------------------------------------------------

/// An ordered sequence of edit operations transforming `old` into `new`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditScript {
    /// The individual edit operations.
    pub ops: Vec<EditOp>,
}

impl EditScript {
    /// Create an empty edit script.
    #[must_use]
    pub const fn new() -> Self {
        Self { ops: Vec::new() }
    }

    /// Number of edit operations in the script.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.ops.len()
    }

    /// Returns `true` if the script has no operations.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Count of insert operations.
    #[must_use]
    pub fn insert_count(&self) -> usize {
        self.ops.iter().filter(|o| o.kind == EditKind::Insert).count()
    }

    /// Count of delete operations.
    #[must_use]
    pub fn delete_count(&self) -> usize {
        self.ops.iter().filter(|o| o.kind == EditKind::Delete).count()
    }

    /// Count of replace operations.
    #[must_use]
    pub fn replace_count(&self) -> usize {
        self.ops.iter().filter(|o| o.kind == EditKind::Replace).count()
    }

    /// Count of equal operations (unchanged bytes).
    #[must_use]
    pub fn equal_count(&self) -> usize {
        self.ops.iter().filter(|o| o.kind == EditKind::Equal).count()
    }

    /// Total edit distance (inserts + deletes + replaces).
    #[must_use]
    pub fn edit_distance(&self) -> usize {
        self.insert_count() + self.delete_count() + self.replace_count()
    }

    /// Apply the script to `old` bytes, producing the reconstructed `new` bytes.
    /// Returns `None` if the script is inconsistent with the provided slice.
    #[must_use]
    pub fn apply(&self, old: &[u8]) -> Option<Vec<u8>> {
        let mut result = Vec::new();
        for op in &self.ops {
            match op.kind {
                EditKind::Equal => {
                    let idx = op.old_index?;
                    if idx >= old.len() {
                        return None;
                    }
                    result.push(old[idx]);
                }
                EditKind::Insert | EditKind::Replace => {
                    result.push(op.new_value?);
                }
                EditKind::Delete => {
                    // Nothing to push — element is removed.
                }
            }
        }
        Some(result)
    }
}

impl Default for EditScript {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for EditScript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EditScript(+{} -{} ~{} ={})",
            self.insert_count(),
            self.delete_count(),
            self.replace_count(),
            self.equal_count()
        )
    }
}

// ---------------------------------------------------------------------------
// DiffResult
// ---------------------------------------------------------------------------

/// The result of running a diff algorithm over two byte slices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    /// The edit script that transforms `old` into `new`.
    pub script: EditScript,
    /// Similarity ratio in `0.0..=1.0`.
    pub similarity: f64,
    /// Edit distance (number of single-element changes).
    pub edit_distance: usize,
    /// Length of the old sequence.
    pub old_len: usize,
    /// Length of the new sequence.
    pub new_len: usize,
    /// Name of the algorithm used.
    pub algorithm: String,
}

impl DiffResult {
    /// Returns `true` if the two sequences are identical.
    #[must_use]
    pub const fn is_identical(&self) -> bool {
        self.edit_distance == 0
    }

    /// Fraction of elements that were changed.
    #[must_use]
    pub fn change_ratio(&self) -> f64 {
        1.0 - self.similarity
    }
}

impl fmt::Display for DiffResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DiffResult[{}] old={} new={} dist={} sim={:.1}%",
            self.algorithm,
            self.old_len,
            self.new_len,
            self.edit_distance,
            self.similarity * 100.0
        )
    }
}

// ---------------------------------------------------------------------------
// DiffAlgorithm
// ---------------------------------------------------------------------------

/// Algorithm selector for byte-sequence diffing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derive(Default)]
pub enum DiffAlgorithm {
    /// Myers' O(ND) diff algorithm — optimal edit distance.
    #[default]
    Myers,
    /// Patience diff — better for code-like sequences with unique anchors.
    Patience,
    /// Histogram diff — improved patience variant used by git.
    Histogram,
    /// Simple LCS-based diff.
    Lcs,
}

impl DiffAlgorithm {
    /// Human-readable name of the algorithm.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Myers => "myers",
            Self::Patience => "patience",
            Self::Histogram => "histogram",
            Self::Lcs => "lcs",
        }
    }

    /// Run the algorithm on two byte slices, producing a [`DiffResult`].
    ///
    /// # Errors
    ///
    /// Returns [`DiffAlgorithmError::BothEmpty`] when both slices are empty.
    pub fn run(self, old: &[u8], new: &[u8]) -> Result<DiffResult, DiffAlgorithmError> {
        if old.is_empty() && new.is_empty() {
            return Err(DiffAlgorithmError::BothEmpty);
        }
        let script = match self {
            Self::Myers => myers_diff(old, new),
            Self::Patience => patience_diff(old, new),
            Self::Histogram => histogram_diff(old, new),
            Self::Lcs => lcs_diff(old, new),
        };
        let edit_distance = script.edit_distance();
        let total = old.len().max(new.len());
        let similarity = if total == 0 {
            1.0
        } else {
            let equal = script.equal_count();
            f64::from(u32::try_from(equal).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
        };
        Ok(DiffResult {
            old_len: old.len(),
            new_len: new.len(),
            edit_distance,
            similarity,
            script,
            algorithm: self.name().to_string(),
        })
    }
}

impl fmt::Display for DiffAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}


// ---------------------------------------------------------------------------
// myers_diff — Myers O(ND) diff on byte slices
// ---------------------------------------------------------------------------

/// Run the Myers O(ND) diff algorithm on two byte slices.
///
/// Returns an [`EditScript`] encoding the transformation from `old` to `new`.
/// This is the reference implementation; it handles the full general case
/// without the space-optimised divide-and-conquer variant.
#[must_use]
pub fn myers_diff(old: &[u8], new: &[u8]) -> EditScript {
    let n = old.len();
    let m = new.len();

    if n == 0 && m == 0 {
        return EditScript::new();
    }
    if n == 0 {
        let ops = new
            .iter()
            .enumerate()
            .map(|(j, &v)| EditOp::insert(j, v))
            .collect();
        return EditScript { ops };
    }
    if m == 0 {
        let ops = old
            .iter()
            .enumerate()
            .map(|(i, &v)| EditOp::delete(i, v))
            .collect();
        return EditScript { ops };
    }

    // Myers O(ND) algorithm: build frontier trace then backtrack.
    let max_edit = n + m;
    let offset = max_edit.cast_signed();
    let frontier_size = 2 * max_edit + 1;
    let mut frontier = vec![0isize; frontier_size];
    let mut trace: Vec<Vec<isize>> = Vec::with_capacity(max_edit + 1);
    let mut found_depth: Option<usize> = None;

    'outer: for depth in 0..=(max_edit.cast_signed()) {
        trace.push(frontier.clone());
        let mut diag = -depth;
        while diag <= depth {
            let fidx = usize::try_from(diag + offset).unwrap_or(0);
            let from_above = diag == -depth
                || (diag != depth
                    && frontier.get(fidx.wrapping_sub(1)).copied().unwrap_or(0)
                        < frontier.get(fidx + 1).copied().unwrap_or(0));
            let mut cur_x = if from_above {
                frontier.get(fidx + 1).copied().unwrap_or(0)
            } else {
                frontier.get(fidx.wrapping_sub(1)).copied().unwrap_or(0) + 1
            };
            let mut cur_y = cur_x - diag;
            while cur_x < n.cast_signed() && cur_y < m.cast_signed() {
                let ox = usize::try_from(cur_x).unwrap_or(0);
                let ny = usize::try_from(cur_y).unwrap_or(0);
                let old_byte = old[ox];
                if old_byte != new[ny] { break; }
                cur_x += 1;
                cur_y += 1;
            }
            if fidx < frontier.len() { frontier[fidx] = cur_x; }
            if cur_x >= n.cast_signed() && cur_y >= m.cast_signed() {
                found_depth = Some(usize::try_from(depth).unwrap_or(0));
                break 'outer;
            }
            diag += 2;
        }
    }

    found_depth.map_or_else(
        || lcs_diff(old, new),
        |depth| backtrack_myers(old, new, &trace[..=depth], offset),
    )
}

/// Backtrack through Myers trace snapshots and reconstruct the edit script.
fn backtrack_myers(old: &[u8], new: &[u8], trace: &[Vec<isize>], offset: isize) -> EditScript {
    let old_len: isize = old.len().cast_signed();
    let new_len: isize = new.len().cast_signed();
    let mut cur_x = old_len;
    let mut cur_y = new_len;
    let mut ops: Vec<EditOp> = Vec::new();

    for (depth_idx, frontier) in trace.iter().enumerate().rev() {
        let depth = depth_idx.cast_signed();
        let diag = cur_x - cur_y;

        let prev_diag = if diag == -depth
            || (diag != depth
                && frontier[usize::try_from(diag - 1 + offset).unwrap_or(0)]
                    < frontier[usize::try_from(diag + 1 + offset).unwrap_or(0)])
        {
            diag + 1
        } else {
            diag - 1
        };
        let prev_x = frontier[usize::try_from(prev_diag + offset).unwrap_or(0)];
        let prev_y = prev_x - prev_diag;

        // Replay the snake (equal elements, in reverse)
        let mut snake_x = cur_x;
        let mut snake_y = cur_y;
        // Standard Myers backtracking replays the snake while x > prev_x and
        // y > prev_y. The previous `prev_x + 1` / `prev_y + 1` bounds stopped one
        // element early, so the last equal element of every snake was dropped —
        // `myers_diff(x, x)` reported len-1 equals instead of len.
        while snake_x > prev_x && snake_y > prev_y {
            snake_x -= 1;
            snake_y -= 1;
            ops.push(EditOp::equal(
                snake_x.cast_unsigned(),
                snake_y.cast_unsigned(),
                old[snake_x.cast_unsigned()],
            ));
        }

        if depth > 0 {
            if prev_diag == diag - 1 {
                // We moved right (deleted from old)
                if prev_x >= 0 && prev_x < old_len {
                    ops.push(EditOp::delete(prev_x.cast_unsigned(), old[prev_x.cast_unsigned()]));
                }
            } else {
                // We moved down (inserted from new)
                if prev_y >= 0 && prev_y < new_len {
                    ops.push(EditOp::insert(prev_y.cast_unsigned(), new[prev_y.cast_unsigned()]));
                }
            }
        }
        cur_x = prev_x;
        cur_y = prev_y;
    }

    // Any remaining equal prefix
    while cur_x > 0 && cur_y > 0 {
        cur_x -= 1;
        cur_y -= 1;
        ops.push(EditOp::equal(cur_x.cast_unsigned(), cur_y.cast_unsigned(), old[cur_x.cast_unsigned()]));
    }

    ops.reverse();
    // Post-process: merge adjacent Delete+Insert into Replace
    let ops = merge_replace(ops);
    EditScript { ops }
}

/// Merge adjacent Delete immediately followed by Insert at the same logical
/// position into a single Replace operation.
fn merge_replace(ops: Vec<EditOp>) -> Vec<EditOp> {
    let mut result: Vec<EditOp> = Vec::with_capacity(ops.len());
    let mut iter = ops.into_iter().peekable();
    while let Some(op) = iter.next() {
        if op.kind == EditKind::Delete
            && let Some(next) = iter.peek()
                && next.kind == EditKind::Insert {
                    let ins = iter.next().unwrap();
                    result.push(EditOp::replace(
                        op.old_index.unwrap_or(0),
                        ins.new_index.unwrap_or(0),
                        op.old_value.unwrap_or(0),
                        ins.new_value.unwrap_or(0),
                    ));
                    continue;
                }
        result.push(op);
    }
    result
}

// ---------------------------------------------------------------------------
// patience_diff
// ---------------------------------------------------------------------------

/// Patience diff on byte slices.
///
/// Identifies unique common elements as anchors, then recurses between them.
/// Falls back to LCS diff for segments without unique anchors.
#[must_use]
pub fn patience_diff(old: &[u8], new: &[u8]) -> EditScript {
    patience_diff_range(old, 0, old.len(), new, 0, new.len())
}

fn patience_diff_range(
    old: &[u8], oi: usize, oj: usize,
    new: &[u8], ni: usize, nj: usize,
) -> EditScript {
    // Strip common prefix
    let mut ai = oi;
    let mut bi = ni;
    let mut prefix_ops: Vec<EditOp> = Vec::new();
    while ai < oj && bi < nj {
        let old_byte = old[ai];
        let new_byte = new[bi];
        if old_byte != new_byte { break; }
        prefix_ops.push(EditOp::equal(ai, bi, old_byte));
        ai += 1;
        bi += 1;
    }
    // Strip common suffix
    let mut aj = oj;
    let mut bj = nj;
    let mut suffix_ops: Vec<EditOp> = Vec::new();
    while aj > ai && bj > bi {
        let old_byte = old[aj - 1];
        let new_byte = new[bj - 1];
        if old_byte != new_byte { break; }
        aj -= 1;
        bj -= 1;
        suffix_ops.push(EditOp::equal(aj, bj, old_byte));
    }
    suffix_ops.reverse();

    if ai == aj {
        // Old side exhausted — everything remaining in new is an insert
        let mut ops = prefix_ops;
        for (d, &byte) in new[bi..bj].iter().enumerate() {
            ops.push(EditOp::insert(bi + d, byte));
        }
        ops.extend(suffix_ops);
        return EditScript { ops };
    }
    if bi == bj {
        // New side exhausted — everything remaining in old is a delete
        let mut ops = prefix_ops;
        for (d, &byte) in old[ai..aj].iter().enumerate() {
            ops.push(EditOp::delete(ai + d, byte));
        }
        ops.extend(suffix_ops);
        return EditScript { ops };
    }

    // Find unique common bytes as anchors
    let anchors = find_unique_common_anchors(old, ai, aj, new, bi, bj);

    if anchors.is_empty() {
        // No unique anchors — fall back to simple LCS
        let mut ops = prefix_ops;
        let inner = lcs_diff_range(old, ai, aj, new, bi, bj);
        ops.extend(inner.ops);
        ops.extend(suffix_ops);
        return EditScript { ops };
    }

    let mut ops = prefix_ops;
    let mut prev_i = ai;
    let mut prev_j = bi;
    for (anchor_i, anchor_j) in anchors {
        let inner = patience_diff_range(old, prev_i, anchor_i, new, prev_j, anchor_j);
        ops.extend(inner.ops);
        ops.push(EditOp::equal(anchor_i, anchor_j, old[anchor_i]));
        prev_i = anchor_i + 1;
        prev_j = anchor_j + 1;
    }
    let tail = patience_diff_range(old, prev_i, aj, new, prev_j, bj);
    ops.extend(tail.ops);
    ops.extend(suffix_ops);
    EditScript { ops }
}

/// Find unique bytes that appear exactly once in each range and are common.
fn find_unique_common_anchors(
    old: &[u8], oi: usize, oj: usize,
    new: &[u8], ni: usize, nj: usize,
) -> Vec<(usize, usize)> {
    use std::collections::HashMap;
    let mut old_unique: HashMap<u8, Option<usize>> = HashMap::new();
    for (d, &byte) in old[oi..oj].iter().enumerate() {
        let idx = oi + d;
        let entry = old_unique.entry(byte).or_insert(Some(idx));
        if *entry != Some(idx) {
            *entry = None; // duplicate
        }
    }
    let mut new_unique: HashMap<u8, Option<usize>> = HashMap::new();
    for (d, &byte) in new[ni..nj].iter().enumerate() {
        let idx = ni + d;
        let entry = new_unique.entry(byte).or_insert(Some(idx));
        if *entry != Some(idx) {
            *entry = None;
        }
    }
    let mut anchors: Vec<(usize, usize)> = Vec::new();
    for (byte, old_idx) in &old_unique {
        if let (Some(i), Some(Some(j))) = (old_idx, new_unique.get(byte)) {
            anchors.push((*i, *j));
        }
    }
    anchors.sort_unstable();
    // Keep only LIS (longest increasing subsequence) on j to maintain order
    lis_filter(anchors)
}

/// Filter to the longest increasing subsequence by second coordinate.
fn lis_filter(pairs: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    if pairs.is_empty() {
        return pairs;
    }
    let mut dp: Vec<usize> = vec![1; pairs.len()];
    let mut parent: Vec<Option<usize>> = vec![None; pairs.len()];
    let mut best = 0;
    let mut best_idx = 0;
    for i in 1..pairs.len() {
        for j in 0..i {
            if pairs[j].1 < pairs[i].1 && dp[j] + 1 > dp[i] {
                dp[i] = dp[j] + 1;
                parent[i] = Some(j);
            }
        }
        if dp[i] > best {
            best = dp[i];
            best_idx = i;
        }
    }
    let mut result = Vec::with_capacity(best);
    let mut idx = Some(best_idx);
    while let Some(i) = idx {
        result.push(pairs[i]);
        idx = parent[i];
    }
    result.reverse();
    result
}

// ---------------------------------------------------------------------------
// histogram_diff
// ---------------------------------------------------------------------------

/// Frequency tables for histogram diff.
struct FreqTables {
    old: [u32; 256],
    new: [u32; 256],
}

/// Histogram diff — frequency-weighted variant of patience diff.
///
/// Prefers to anchor on low-frequency (more unique) bytes first.
#[must_use]
pub fn histogram_diff(old: &[u8], new: &[u8]) -> EditScript {
    if old.is_empty() && new.is_empty() {
        return EditScript::new();
    }
    // Build frequency tables
    let mut freq = FreqTables { old: [0u32; 256], new: [0u32; 256] };
    for &b in old {
        freq.old[b as usize] += 1;
    }
    for &b in new {
        freq.new[b as usize] += 1;
    }
    // Score = min(freq_old, freq_new) for each byte; lower = rarer = better anchor
    histogram_diff_range(old, 0, old.len(), new, 0, new.len(), &freq)
}

fn histogram_diff_range(
    old: &[u8], oi: usize, oj: usize,
    new: &[u8], ni: usize, nj: usize,
    freq: &FreqTables,
) -> EditScript {
    // Common prefix
    let mut ai = oi;
    let mut bi = ni;
    let mut prefix_ops: Vec<EditOp> = Vec::new();
    while ai < oj && bi < nj {
        let old_byte = old[ai];
        let new_byte = new[bi];
        if old_byte != new_byte { break; }
        prefix_ops.push(EditOp::equal(ai, bi, old_byte));
        ai += 1;
        bi += 1;
    }
    // Common suffix
    let mut aj = oj;
    let mut bj = nj;
    let mut suffix_ops: Vec<EditOp> = Vec::new();
    while aj > ai && bj > bi {
        let old_byte = old[aj - 1];
        let new_byte = new[bj - 1];
        if old_byte != new_byte { break; }
        aj -= 1;
        bj -= 1;
        suffix_ops.push(EditOp::equal(aj, bj, old_byte));
    }
    suffix_ops.reverse();

    if ai == aj {
        let mut ops = prefix_ops;
        for (d, &byte) in new[bi..bj].iter().enumerate() {
            ops.push(EditOp::insert(bi + d, byte));
        }
        ops.extend(suffix_ops);
        return EditScript { ops };
    }
    if bi == bj {
        let mut ops = prefix_ops;
        for (d, &byte) in old[ai..aj].iter().enumerate() {
            ops.push(EditOp::delete(ai + d, byte));
        }
        ops.extend(suffix_ops);
        return EditScript { ops };
    }

    // Find the rarest common byte as pivot
    let pivot = find_rarest_common(old, ai, aj, new, bi, bj, freq);

    let mut ops = prefix_ops;
    if let Some((pi, pj)) = pivot {
        let left = histogram_diff_range(old, ai, pi, new, bi, pj, freq);
        ops.extend(left.ops);
        ops.push(EditOp::equal(pi, pj, old[pi]));
        let right = histogram_diff_range(old, pi + 1, aj, new, pj + 1, bj, freq);
        ops.extend(right.ops);
    } else {
        // No common bytes — generate delete/insert for entire range
        for (d, &byte) in old[ai..aj].iter().enumerate() {
            ops.push(EditOp::delete(ai + d, byte));
        }
        for (d, &byte) in new[bi..bj].iter().enumerate() {
            ops.push(EditOp::insert(bi + d, byte));
        }
    }
    ops.extend(suffix_ops);
    EditScript { ops }
}

/// Find the occurrence of the rarest byte common to both ranges.
fn find_rarest_common(
    old: &[u8], oi: usize, oj: usize,
    new: &[u8], ni: usize, nj: usize,
    freq: &FreqTables,
) -> Option<(usize, usize)> {
    let mut best_score = u32::MAX;
    let mut best: Option<(usize, usize)> = None;
    for (d, &b) in old[oi..oj].iter().enumerate() {
        let score = freq.old[b as usize].saturating_add(freq.new[b as usize]);
        if score < best_score {
            // Find first occurrence of b in new range
            if let Some(j) = new[ni..nj].iter().position(|&x| x == b) {
                best_score = score;
                best = Some((oi + d, ni + j));
            }
        }
    }
    best
}

// ---------------------------------------------------------------------------
// lcs_diff
// ---------------------------------------------------------------------------

/// LCS-based diff on byte slices.
///
/// Builds the full LCS dynamic-programming table and backtracks.
/// Complexity: O(n*m) time, O(n*m) space — only suitable for small inputs.
#[must_use]
pub fn lcs_diff(old: &[u8], new: &[u8]) -> EditScript {
    lcs_diff_range(old, 0, old.len(), new, 0, new.len())
}

fn lcs_diff_range(old: &[u8], oi: usize, oj: usize, new: &[u8], ni: usize, nj: usize) -> EditScript {
    let n = oj - oi;
    let m = nj - ni;
    if n == 0 && m == 0 {
        return EditScript::new();
    }
    if n == 0 {
        let ops = (ni..nj).map(|j| EditOp::insert(j, new[j])).collect();
        return EditScript { ops };
    }
    if m == 0 {
        let ops = (oi..oj).map(|i| EditOp::delete(i, old[i])).collect();
        return EditScript { ops };
    }

    // Build LCS table
    let mut dp = vec![vec![0u32; m + 1]; n + 1];
    for i in 1..=n {
        for j in 1..=m {
            dp[i][j] = if old[oi + i - 1] == new[ni + j - 1] {
                dp[i - 1][j - 1] + 1
            } else {
                dp[i - 1][j].max(dp[i][j - 1])
            };
        }
    }

    // Backtrack
    let mut ops: Vec<EditOp> = Vec::new();
    let mut i = n;
    let mut j = m;
    while i > 0 || j > 0 {
        if i > 0 && j > 0 && old[oi + i - 1] == new[ni + j - 1] {
            i -= 1;
            j -= 1;
            ops.push(EditOp::equal(oi + i, ni + j, old[oi + i]));
        } else if j > 0 && (i == 0 || dp[i][j - 1] >= dp[i - 1][j]) {
            j -= 1;
            ops.push(EditOp::insert(ni + j, new[ni + j]));
        } else {
            i -= 1;
            ops.push(EditOp::delete(oi + i, old[oi + i]));
        }
    }
    ops.reverse();
    let ops = merge_replace(ops);
    EditScript { ops }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edit_kind_display() {
        assert_eq!(EditKind::Equal.to_string(), "=");
        assert_eq!(EditKind::Insert.to_string(), "+");
        assert_eq!(EditKind::Delete.to_string(), "-");
        assert_eq!(EditKind::Replace.to_string(), "~");
    }

    #[test]
    fn test_myers_identical() {
        let data = b"hello";
        let script = myers_diff(data, data);
        assert_eq!(script.edit_distance(), 0);
        assert_eq!(script.equal_count(), data.len());
    }

    #[test]
    fn test_myers_empty_old() {
        let script = myers_diff(b"", b"abc");
        assert_eq!(script.insert_count(), 3);
        assert_eq!(script.delete_count(), 0);
    }

    #[test]
    fn test_myers_empty_new() {
        let script = myers_diff(b"abc", b"");
        assert_eq!(script.delete_count(), 3);
        assert_eq!(script.insert_count(), 0);
    }

    #[test]
    fn test_myers_apply() {
        let old = b"abcde";
        let new = b"abxde";
        let script = myers_diff(old, new);
        let reconstructed = script.apply(old).expect("apply failed");
        assert_eq!(reconstructed, new);
    }

    #[test]
    fn test_lcs_diff_identical() {
        let data = b"ABCDE";
        let script = lcs_diff(data, data);
        assert_eq!(script.edit_distance(), 0);
    }

    #[test]
    fn test_lcs_diff_apply() {
        let old = b"ABCDE";
        let new = b"AXCYE";
        let script = lcs_diff(old, new);
        let result = script.apply(old).unwrap();
        assert_eq!(result, new);
    }

    #[test]
    fn test_patience_diff_identical() {
        let data = b"hello world";
        let script = patience_diff(data, data);
        assert_eq!(script.edit_distance(), 0);
    }

    #[test]
    fn test_histogram_diff_identical() {
        let data = b"test data 1234";
        let script = histogram_diff(data, data);
        assert_eq!(script.edit_distance(), 0);
    }

    #[test]
    fn test_diff_algorithm_run_both_empty_error() {
        let err = DiffAlgorithm::Myers.run(b"", b"");
        assert!(err.is_err());
    }

    #[test]
    fn test_diff_algorithm_myers_similarity_one() {
        let data = b"same bytes";
        let result = DiffAlgorithm::Myers.run(data, data).unwrap();
        assert!(result.similarity > 0.99);
        assert!(result.is_identical());
    }

    #[test]
    fn test_diff_algorithm_all_variants() {
        let old = b"the quick brown fox";
        let new = b"the slow brown cat";
        for alg in [
            DiffAlgorithm::Myers,
            DiffAlgorithm::Patience,
            DiffAlgorithm::Histogram,
            DiffAlgorithm::Lcs,
        ] {
            let result = alg.run(old, new).unwrap();
            assert!(!result.is_identical());
            assert!(result.similarity < 1.0);
        }
    }

    #[test]
    fn test_edit_script_display() {
        let old = b"abc";
        let new = b"axc";
        let script = myers_diff(old, new);
        let s = script.to_string();
        assert!(s.contains("EditScript"));
    }

    #[test]
    fn test_diff_result_change_ratio() {
        let old = b"abcdef";
        let new = b"abcxyz";
        let result = DiffAlgorithm::Lcs.run(old, new).unwrap();
        assert!(result.change_ratio() > 0.0);
        assert!((result.similarity + result.change_ratio() - 1.0).abs() < 1e-9);
    }
}
