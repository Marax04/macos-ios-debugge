//! `function_diff` — Myers / LCS diffing on normalized instruction sequences.
//!
//! Compares two functions token-by-token (opcode + operand-class) and classifies
//! the delta as Identical / Renamed / Modified / Added / Deleted with a
//! floating-point similarity score.

use std::fmt;

// ---------------------------------------------------------------------------
// Normalised instruction token

/// An instruction reduced to its semantic essence for diffing purposes.
/// Operand values are replaced by their class (register / immediate / memory)
/// so that minor constant changes don't dominate the diff.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NormInsn {
    /// Mnemonic string (lower-case, e.g. "mov", "call", "je").
    pub mnemonic: String,
    /// Operand classes in order.
    pub operand_classes: Vec<OperandClass>,
    /// Original bytes (for display / patching).
    pub raw_bytes: Vec<u8>,
    /// Virtual address in the owning binary (0 if unknown).
    pub va: u64,
}

impl NormInsn {
    pub fn new(mnemonic: impl Into<String>, operand_classes: Vec<OperandClass>, va: u64) -> Self {
        Self { mnemonic: mnemonic.into(), operand_classes, raw_bytes: Vec::new(), va }
    }

    /// Equality ignoring address (used in LCS computation).
    #[must_use] 
    pub fn semantic_eq(&self, other: &Self) -> bool {
        self.mnemonic == other.mnemonic && self.operand_classes == other.operand_classes
    }
}

impl fmt::Display for NormInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.mnemonic)?;
        for (i, op) in self.operand_classes.iter().enumerate() {
            if i == 0 { write!(f, " ")?; } else { write!(f, ", ")?; }
            write!(f, "{op}")?;
        }
        Ok(())
    }
}

/// Operand class — coarsely describes what kind of operand is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperandClass {
    /// General-purpose register (rax, rbx, …).
    Reg,
    /// XMM / YMM / ZMM register.
    Xmm,
    /// Segment register.
    Seg,
    /// Integer immediate (exact value not significant).
    Imm,
    /// Memory operand: `[base + index*scale + disp]`.
    Mem,
    /// IP-relative memory (RIP-relative on x64).
    RipRel,
    /// Condition code (for Jcc).
    Cond,
    /// Label / branch target (treated as opaque for diffing).
    Label,
}

impl fmt::Display for OperandClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Reg    => "reg",
            Self::Xmm    => "xmm",
            Self::Seg    => "seg",
            Self::Imm    => "imm",
            Self::Mem    => "mem",
            Self::RipRel => "riprel",
            Self::Cond   => "cond",
            Self::Label  => "lbl",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// EditOp

/// One edit operation in a Myers diff script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditOp {
    /// Instruction present in both old and new (unchanged).
    Equal(NormInsn, NormInsn),
    /// Instruction removed from old (not in new).
    Delete(NormInsn),
    /// Instruction added in new (not in old).
    Insert(NormInsn),
    /// Instruction changed — semantically different but at the same logical position.
    Replace(NormInsn, NormInsn),
}

impl EditOp {
    #[must_use] 
    pub const fn is_change(&self) -> bool {
        !matches!(self, Self::Equal(..))
    }
}

impl fmt::Display for EditOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Equal(a, _)   => write!(f, "  {a}"),
            Self::Delete(a)     => write!(f, "- {a}"),
            Self::Insert(b)     => write!(f, "+ {b}"),
            Self::Replace(a, b) => write!(f, "~ {a} → {b}"),
        }
    }
}

// ---------------------------------------------------------------------------
// SimilarityScore

/// Floating-point similarity in [0.0, 1.0].
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct SimilarityScore(pub f64);

impl SimilarityScore {
    #[must_use] 
    pub const fn identical() -> Self { Self(1.0) }
    #[must_use] 
    pub const fn no_match()  -> Self { Self(0.0) }

    /// Compute from edit counts: (equal) / (equal + delete + insert + replace).
    #[must_use] 
    pub fn from_edit_ops(ops: &[EditOp]) -> Self {
        let equal   = ops.iter().filter(|o| matches!(o, EditOp::Equal(..))).count();
        let total   = ops.len();
        if total == 0 { return Self::identical(); }
        Self(f64::from(u32::try_from(equal).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(total).unwrap_or(u32::MAX)))
    }

    #[must_use] 
    pub const fn value(&self) -> f64 { self.0 }
    #[must_use] 
    pub fn is_identical(&self) -> bool { self.0 >= 1.0 }
    #[must_use] 
    pub fn is_similar(&self, threshold: f64) -> bool { self.0 >= threshold }
}

impl fmt::Display for SimilarityScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.2}%", self.0 * 100.0)
    }
}

// ---------------------------------------------------------------------------
// DiffClassification

/// Classification of a function pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffClassification {
    /// Byte-for-byte identical.
    Identical,
    /// Same code but different address (rebased or renamed).
    Renamed,
    /// Same structure with minor changes (> threshold similarity).
    Modified,
    /// Present only in the new binary.
    Added,
    /// Present only in the old binary.
    Deleted,
    /// Too dissimilar to be considered the same function.
    Unrelated,
}

impl fmt::Display for DiffClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Identical => "IDENTICAL",
            Self::Renamed   => "RENAMED",
            Self::Modified  => "MODIFIED",
            Self::Added     => "ADDED",
            Self::Deleted   => "DELETED",
            Self::Unrelated => "UNRELATED",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// DiffResult

/// Complete diff result for a function pair.
#[derive(Debug, Clone)]
pub struct DiffResult {
    /// Name of the function in the old binary (empty if new-only).
    pub old_name: String,
    /// Name of the function in the new binary (empty if old-only).
    pub new_name: String,
    pub old_addr: u64,
    pub new_addr: u64,
    /// The sequence of edit operations.
    pub edit_script: Vec<EditOp>,
    /// Summary similarity score.
    pub score: SimilarityScore,
    /// Human classification.
    pub classification: DiffClassification,
}

impl DiffResult {
    /// Count instructions changed (delete + insert + replace).
    #[must_use] 
    pub fn changed_count(&self) -> usize {
        self.edit_script.iter().filter(|o| o.is_change()).count()
    }

    /// Count instructions unchanged.
    #[must_use] 
    pub fn equal_count(&self) -> usize {
        self.edit_script.iter().filter(|o| matches!(o, EditOp::Equal(..))).count()
    }
}

impl fmt::Display for DiffResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Function diff: {} ({:#x}) vs {} ({:#x})  [{}]  score={}",
            self.old_name, self.old_addr,
            self.new_name, self.new_addr,
            self.classification, self.score)?;
        for op in &self.edit_script {
            writeln!(f, "  {op}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FunctionDiff — the actual differ

/// Computes the normalised LCS/Myers diff between two instruction sequences.
///
/// Uses the simple O(nd) Myers algorithm for correctness.  For very large
/// functions (> `max_insns`) it falls back to a ratio-based heuristic.
pub struct FunctionDiff {
    /// If either sequence exceeds this length, use fast heuristic. Default: 2000.
    pub max_insns: usize,
    /// Similarity threshold above which functions are `Modified` vs `Unrelated`.
    pub modified_threshold: f64,
    /// Threshold above which functions are `Renamed` (identical code, different addr).
    pub renamed_threshold: f64,
}

impl Default for FunctionDiff {
    fn default() -> Self {
        Self { max_insns: 2000, modified_threshold: 0.5, renamed_threshold: 0.95 }
    }
}

impl FunctionDiff {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    /// Diff two instruction sequences and return a full [`DiffResult`].
    #[must_use] 
    pub fn diff(
        &self,
        old: &[NormInsn],
        new: &[NormInsn],
        old_name: &str,
        new_name: &str,
        old_addr: u64,
        new_addr: u64,
    ) -> DiffResult {
        let edit_script = if old.len() > self.max_insns || new.len() > self.max_insns {
            Self::heuristic_diff(old, new)
        } else {
            Self::myers_diff(old, new)
        };

        let score = SimilarityScore::from_edit_ops(&edit_script);
        let classification = self.classify(score, old_addr, new_addr, &edit_script);

        DiffResult {
            old_name: old_name.to_string(),
            new_name: new_name.to_string(),
            old_addr, new_addr,
            edit_script, score, classification,
        }
    }

    /// Classify based on score and address relationship.
    fn classify(&self, score: SimilarityScore, old_addr: u64, new_addr: u64, ops: &[EditOp]) -> DiffClassification {
        if ops.is_empty() { return DiffClassification::Identical; }
        if score.is_identical() {
            if old_addr == new_addr { DiffClassification::Identical }
            else { DiffClassification::Renamed }
        } else if score.value() >= self.renamed_threshold {
            DiffClassification::Renamed
        } else if score.value() >= self.modified_threshold {
            DiffClassification::Modified
        } else {
            DiffClassification::Unrelated
        }
    }

    /// O(nd) Myers diff algorithm.
    fn myers_diff(old: &[NormInsn], new: &[NormInsn]) -> Vec<EditOp> {
        let old_len = old.len();
        let new_len = new.len();
        let max_edit = old_len + new_len;
        if max_edit == 0 { return Vec::new(); }

        // frontier[diag + max_edit] = furthest x reached along diagonal diag
        let frontier_size = 2 * max_edit + 1;
        let mut frontier = vec![0usize; frontier_size];
        // edit_trace[depth] = frontier snapshot AFTER depth steps.
        let mut edit_trace: Vec<Vec<usize>> = Vec::new();
        let mut found_depth = max_edit;

        'outer: for depth in 0..=max_edit {
            let diag_start = depth.cast_signed().wrapping_neg();
            let diag_end   = depth.cast_signed();
            let mut diag   = diag_start;
            while diag <= diag_end {
                let fidx = (diag + max_edit.cast_signed()).cast_unsigned();
                let from_above = diag == diag_start
                    || (diag != diag_end
                        && frontier[(fidx + 1) % frontier_size]
                            > frontier[(fidx.wrapping_sub(1)) % frontier_size]);
                let mut cur_x = if from_above {
                    frontier[(fidx + 1) % frontier_size]
                } else {
                    frontier[(fidx.wrapping_sub(1)) % frontier_size] + 1
                };
                let mut cur_y = (cur_x.cast_signed() - diag).cast_unsigned();
                while cur_x < old_len && cur_y < new_len && old[cur_x].semantic_eq(&new[cur_y]) {
                    cur_x += 1;
                    cur_y += 1;
                }
                frontier[fidx] = cur_x;
                if cur_x >= old_len && cur_y >= new_len {
                    found_depth = depth;
                    edit_trace.push(frontier.clone());
                    break 'outer;
                }
                diag += 2;
            }
            edit_trace.push(frontier.clone());
        }

        if found_depth == 0 {
            return old.iter().zip(new.iter())
                .map(|(oi, ni)| EditOp::Equal(oi.clone(), ni.clone()))
                .collect();
        }

        // Safety fallback to LCS when trace is huge (memory protection).
        if edit_trace.len() > 10_000 {
            return Self::lcs_edit_script(old, new);
        }

        Self::myers_backtrack(old, new, &edit_trace, max_edit, found_depth)
    }

    /// Reconstruct edit script from Myers frontier trace.
    fn myers_backtrack(
        old: &[NormInsn],
        new: &[NormInsn],
        edit_trace: &[Vec<usize>],
        max_edit: usize,
        found_depth: usize,
    ) -> Vec<EditOp> {
        let mut ops = Vec::new();
        let mut cur_x = old.len();
        let mut cur_y = new.len();

        for step in (1..=found_depth).rev() {
            let prev_frontier = &edit_trace[step - 1];
            let diag   = cur_x.cast_signed() - cur_y.cast_signed();
            let step_i = step.cast_signed();
            let minus_idx = usize::try_from(diag - 1 + max_edit.cast_signed()).unwrap_or(0);
            let plus_idx  = usize::try_from(diag + 1 + max_edit.cast_signed()).unwrap_or(0);
            let prev_diag = if diag == -step_i
                || (diag != step_i && prev_frontier[minus_idx] < prev_frontier[plus_idx])
            {
                diag + 1 // came from above (insert)
            } else {
                diag - 1 // came from left (delete)
            };
            let prev_x = prev_frontier[usize::try_from(prev_diag + max_edit.cast_signed()).unwrap_or(0)];
            let prev_y = usize::try_from(prev_x.cast_signed() - prev_diag).unwrap_or(0);

            // Follow snake backwards (equal elements between edit ops)
            let snake_base_x = if prev_diag == diag - 1 { prev_x + 1 } else { prev_x };
            let snake_base_y = if prev_diag == diag + 1 { prev_y + 1 } else { prev_y };
            while cur_x > snake_base_x && cur_y > snake_base_y {
                cur_x -= 1;
                cur_y -= 1;
                ops.push(EditOp::Equal(old[cur_x].clone(), new[cur_y].clone()));
            }

            if prev_diag == diag - 1 {
                // came from left: delete old[prev_x]
                if cur_x > 0 {
                    cur_x -= 1;
                    ops.push(EditOp::Delete(old[cur_x].clone()));
                }
            } else {
                // came from above: insert new[prev_y]
                if cur_y > 0 {
                    cur_y -= 1;
                    ops.push(EditOp::Insert(new[cur_y].clone()));
                }
            }
            cur_x = prev_x;
            cur_y = prev_y;
        }

        // Remaining equal prefix
        while cur_x > 0 && cur_y > 0 {
            cur_x -= 1;
            cur_y -= 1;
            ops.push(EditOp::Equal(old[cur_x].clone(), new[cur_y].clone()));
        }

        ops.reverse();
        Self::merge_replace_slice(&ops)
    }

    /// Classic LCS edit script via dynamic programming (fallback for huge diffs).
    fn lcs_edit_script(old: &[NormInsn], new: &[NormInsn]) -> Vec<EditOp> {
        let old_len = old.len();
        let new_len = new.len();
        let mut dp = vec![vec![0u32; new_len + 1]; old_len + 1];
        for oi in (0..old_len).rev() {
            for ni in (0..new_len).rev() {
                if old[oi].semantic_eq(&new[ni]) {
                    dp[oi][ni] = dp[oi+1][ni+1] + 1;
                } else {
                    dp[oi][ni] = dp[oi+1][ni].max(dp[oi][ni+1]);
                }
            }
        }

        let mut ops = Vec::new();
        let mut old_pos = 0;
        let mut new_pos = 0;
        while old_pos < old_len && new_pos < new_len {
            if old[old_pos].semantic_eq(&new[new_pos]) {
                ops.push(EditOp::Equal(old[old_pos].clone(), new[new_pos].clone()));
                old_pos += 1; new_pos += 1;
            } else if dp[old_pos+1][new_pos] >= dp[old_pos][new_pos+1] {
                ops.push(EditOp::Delete(old[old_pos].clone()));
                old_pos += 1;
            } else {
                ops.push(EditOp::Insert(new[new_pos].clone()));
                new_pos += 1;
            }
        }
        while old_pos < old_len {
            ops.push(EditOp::Delete(old[old_pos].clone()));
            old_pos += 1;
        }
        while new_pos < new_len {
            ops.push(EditOp::Insert(new[new_pos].clone()));
            new_pos += 1;
        }

        Self::merge_replace_slice(&ops)
    }

    fn merge_replace_slice(ops: &[EditOp]) -> Vec<EditOp> {
        let mut out: Vec<EditOp> = Vec::with_capacity(ops.len());
        let mut idx = 0;
        while idx < ops.len() {
            if idx + 1 < ops.len()
                && let (EditOp::Delete(del_op), EditOp::Insert(ins_op)) = (&ops[idx], &ops[idx+1]) {
                    out.push(EditOp::Replace(del_op.clone(), ins_op.clone()));
                    idx += 2;
                    continue;
                }
            out.push(ops[idx].clone());
            idx += 1;
        }
        out
    }

    /// Fast heuristic for very long functions: mnemonic frequency comparison.
    fn heuristic_diff(old: &[NormInsn], new: &[NormInsn]) -> Vec<EditOp> {
        let mut old_map: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        let mut new_map: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for insn in old { *old_map.entry(insn.mnemonic.as_str()).or_insert(0) += 1; }
        for insn in new { *new_map.entry(insn.mnemonic.as_str()).or_insert(0) += 1; }

        // If the functions share no common mnemonics, emit all as delete+insert.
        let has_overlap = old_map.keys().any(|mnemonic| new_map.contains_key(mnemonic));
        if !has_overlap && !old.is_empty() && !new.is_empty() {
            return old.iter().map(|oi| EditOp::Delete(oi.clone()))
                .chain(new.iter().map(|ni| EditOp::Insert(ni.clone())))
                .collect();
        }

        let mut ops = Vec::new();
        let pairs = old.len().min(new.len());
        for pair_idx in 0..pairs {
            if old[pair_idx].semantic_eq(&new[pair_idx]) {
                ops.push(EditOp::Equal(old[pair_idx].clone(), new[pair_idx].clone()));
            } else {
                ops.push(EditOp::Replace(old[pair_idx].clone(), new[pair_idx].clone()));
            }
        }
        for item in old.iter().skip(pairs) { ops.push(EditOp::Delete(item.clone())); }
        for item in new.iter().skip(pairs) { ops.push(EditOp::Insert(item.clone())); }
        ops
    }
}

// ---------------------------------------------------------------------------
// Tests

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(m: &str) -> NormInsn {
        NormInsn::new(m, vec![], 0)
    }

    fn _insn_reg(m: &str) -> NormInsn {
        NormInsn::new(m, vec![OperandClass::Reg], 0)
    }

    #[test]
    fn test_identical_diff() {
        let seq: Vec<NormInsn> = vec![insn("push"), insn("mov"), insn("ret")];
        let differ = FunctionDiff::new();
        let result = differ.diff(&seq, &seq, "f", "f", 0x1000, 0x1000);
        assert_eq!(result.classification, DiffClassification::Identical);
        assert!(result.score.is_identical());
    }

    #[test]
    fn test_added_insn() {
        let old = vec![insn("push"), insn("ret")];
        let new = vec![insn("push"), insn("nop"), insn("ret")];
        let differ = FunctionDiff::new();
        let result = differ.diff(&old, &new, "f", "f", 0x1000, 0x2000);
        assert!(result.changed_count() > 0);
        assert!(result.score.value() < 1.0);
    }

    #[test]
    fn test_replace_detection() {
        let old = vec![insn("jz"), insn("ret")];
        let new = vec![insn("jnz"), insn("ret")];
        let differ = FunctionDiff::new();
        let result = differ.diff(&old, &new, "f", "f", 0x1000, 0x2000);
        let has_replace = result.edit_script.iter().any(|o| matches!(o, EditOp::Replace(..)));
        assert!(has_replace || result.changed_count() > 0);
    }

    #[test]
    fn test_similarity_score() {
        let ops = vec![
            EditOp::Equal(insn("a"), insn("a")),
            EditOp::Equal(insn("b"), insn("b")),
            EditOp::Delete(insn("c")),
        ];
        let s = SimilarityScore::from_edit_ops(&ops);
        assert!((s.value() - 2.0/3.0).abs() < 0.01);
    }

    #[test]
    fn test_diff_classification_modified() {
        let differ = FunctionDiff { modified_threshold: 0.4, renamed_threshold: 0.95, max_insns: 2000 };
        let old: Vec<NormInsn> = (0..10).map(|i| insn(&format!("op{}", i))).collect();
        let new: Vec<NormInsn> = (0..7).map(|i| insn(&format!("op{}", i)))
            .chain((7..10).map(|i| insn(&format!("new{}", i))))
            .collect();
        let result = differ.diff(&old, &new, "f", "f", 0x1000, 0x2000);
        assert!(matches!(result.classification, DiffClassification::Modified | DiffClassification::Renamed));
    }
}
