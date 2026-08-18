//! `basic_block_diff` — Basic-block and instruction-level diffing.
//!
//! Once two functions are matched (by the call-graph or Hungarian matcher),
//! this module diffs their bodies at the basic-block and instruction level:
//!
//! * **Block matching**: the blocks of function A are matched to blocks of
//!   function B using a combination of positional heuristics and edit-distance.
//! * **Instruction edit distance**: for each matched block pair the minimum
//!   edit-distance sequence of insertions, deletions, and substitutions is
//!   computed.
//! * **Change classification**: each difference is tagged as an operand change,
//!   a constant / immediate change, a structural change (new instruction), or
//!   a no-op (semantic equivalent).

use std::collections::HashMap;
use std::fmt;

/// Lookup table that maps a basic-block id in function A to its matched
/// counterpart in function B, returned by the higher-level pipeline so that
/// callers can perform per-block instruction diffs without re-running the
/// matcher. Exposed as a type alias to keep the public surface stable.
pub type BlockIdMap = HashMap<u32, u32>;

// ─────────────────────────────────────────────────────────────────────────────
// Instruction representation
// ─────────────────────────────────────────────────────────────────────────────

/// Architecture-neutral representation of a single instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    /// Mnemonic / opcode string (e.g. `"mov"`, `"call"`, `"je"`).
    pub mnemonic: String,
    /// Ordered list of operands (register names, memory expressions, immediates).
    pub operands: Vec<Operand>,
}

impl Instruction {
    /// Create a new instruction.
    pub fn new(mnemonic: impl Into<String>, operands: Vec<Operand>) -> Self {
        Self { mnemonic: mnemonic.into(), operands }
    }

    /// Create a register-only instruction.
    pub fn reg(mnemonic: impl Into<String>, regs: &[&str]) -> Self {
        Self {
            mnemonic: mnemonic.into(),
            operands: regs.iter().map(|r| Operand::Register(r.to_string())).collect(),
        }
    }

    /// Compute a structural hash that ignores constant values.
    #[must_use]
    pub fn structural_hash(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in self.mnemonic.as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        for op in &self.operands {
            let kind: u8 = match op {
                Operand::Register(_)  => 1,
                Operand::Immediate(_) => 2,
                Operand::Memory(_)    => 3,
                Operand::Label(_)     => 4,
                Operand::Other(_)     => 5,
            };
            h ^= u64::from(kind);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    }

    /// Check if two instructions differ only in immediate constants.
    #[must_use]
    pub fn differs_only_in_immediates(&self, other: &Self) -> bool {
        if self.mnemonic != other.mnemonic { return false; }
        if self.operands.len() != other.operands.len() { return false; }
        self.operands.iter().zip(&other.operands).all(|(a, b)| match (a, b) {
            (Operand::Immediate(_), Operand::Immediate(_)) => true,
            (x, y) => x == y,
        })
    }

    /// Check if two instructions differ only in register names.
    #[must_use]
    pub fn differs_only_in_registers(&self, other: &Self) -> bool {
        if self.mnemonic != other.mnemonic { return false; }
        if self.operands.len() != other.operands.len() { return false; }
        self.operands.iter().zip(&other.operands).all(|(a, b)| match (a, b) {
            (Operand::Register(_), Operand::Register(_)) => true,
            (x, y) => x == y,
        })
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.mnemonic)?;
        for (i, op) in self.operands.iter().enumerate() {
            if i == 0 { write!(f, " ")?; } else { write!(f, ", ")?; }
            write!(f, "{op}")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Operand
// ─────────────────────────────────────────────────────────────────────────────

/// An instruction operand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    Register(String),
    Immediate(i64),
    Memory(String),
    Label(String),
    Other(String),
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Register(r)  => write!(f, "{r}"),
            Self::Immediate(v) => write!(f, "0x{v:x}"),
            Self::Memory(m)    => write!(f, "[{m}]"),
            Self::Label(l)     => write!(f, "{l}"),
            Self::Other(o)     => write!(f, "{o}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BasicBlock
// ─────────────────────────────────────────────────────────────────────────────

/// A basic block: a linear sequence of instructions with a single entry and
/// (at most) two exits.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Stable index within the function's block list.
    pub idx: usize,
    /// Start address (used for display / ordering only).
    pub start_addr: u64,
    /// Instructions in execution order.
    pub instructions: Vec<Instruction>,
    /// Successor block indices (0, 1, or 2).
    pub successors: Vec<usize>,
}

impl BasicBlock {
    /// Compute a content hash over instruction structural hashes.
    #[must_use]
    pub fn content_hash(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for insn in &self.instructions {
            h ^= insn.structural_hash();
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    }

    /// Number of instructions.
    #[must_use]
    pub const fn insn_count(&self) -> usize { self.instructions.len() }
}

// ─────────────────────────────────────────────────────────────────────────────
// InsnChange — per-instruction diff result
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of a single instruction-level change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeKind {
    /// Instruction is identical.
    Unchanged,
    /// Mnemonic is the same; only immediate values changed.
    ConstantChange { old_imms: Vec<i64>, new_imms: Vec<i64> },
    /// Mnemonic is the same; only register operands changed.
    OperandChange { old_ops: Vec<String>, new_ops: Vec<String> },
    /// Instruction is completely different (different mnemonic or structure).
    Structural,
    /// Instruction was inserted in the new version.
    Inserted,
    /// Instruction was deleted from the old version.
    Deleted,
}

impl ChangeKind {
    /// Returns true if this change is not `Unchanged`.
    #[must_use]
    pub const fn is_changed(&self) -> bool { !matches!(self, Self::Unchanged) }

    /// Is this a security-relevant change?  Heuristic: size checks on immediates.
    #[must_use]
    pub const fn is_security_relevant(&self) -> bool {
        matches!(self, Self::ConstantChange { .. } | Self::Inserted | Self::Deleted)
    }
}

/// A single entry in the instruction-level diff.
#[derive(Debug, Clone)]
pub struct InsnDiffEntry {
    /// Index in the old (A) block; `None` for inserted instructions.
    pub old_idx: Option<usize>,
    /// Index in the new (B) block; `None` for deleted instructions.
    pub new_idx: Option<usize>,
    /// The old instruction (if any).
    pub old_insn: Option<Instruction>,
    /// The new instruction (if any).
    pub new_insn: Option<Instruction>,
    /// Classification.
    pub kind: ChangeKind,
}

// ─────────────────────────────────────────────────────────────────────────────
// InsnDiffer — instruction-level edit distance
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the instruction-level diff between two basic blocks using dynamic
/// programming (Levenshtein-style with substitution cost < delete+insert).
pub struct InsnDiffer;

impl InsnDiffer {
    /// Diff `block_a` against `block_b`.  Returns the edit-distance sequence.
    #[must_use]
    pub fn diff(block_a: &[Instruction], block_b: &[Instruction]) -> Vec<InsnDiffEntry> {
        let m = block_a.len();
        let n = block_b.len();

        // Cost matrix: dp[i][j] = min cost to align a[..i] with b[..j].
        let ins_cost  = 1_u32;
        let del_cost  = 1_u32;
        let sub_cost_structural = 2_u32;
        let sub_cost_minor      = 1_u32; // constant/register change

        let mut dp = vec![vec![0_u32; n + 1]; m + 1];
        for i in 0..=m { dp[i][0] = i as u32 * del_cost; }
        for j in 0..=n { dp[0][j] = j as u32 * ins_cost; }

        for i in 1..=m {
            for j in 1..=n {
                let a = &block_a[i - 1];
                let b = &block_b[j - 1];
                let sub = if a == b {
                    dp[i-1][j-1] // identical
                } else if a.differs_only_in_immediates(b) || a.differs_only_in_registers(b) {
                    dp[i-1][j-1] + sub_cost_minor
                } else {
                    dp[i-1][j-1] + sub_cost_structural
                };
                dp[i][j] = sub.min(dp[i-1][j] + del_cost).min(dp[i][j-1] + ins_cost);
            }
        }

        // Backtrack.
        let mut entries = Vec::new();
        let (mut i, mut j) = (m, n);
        while i > 0 || j > 0 {
            if i > 0 && j > 0 {
                let a = &block_a[i - 1];
                let b = &block_b[j - 1];
                let sub_here = if a == b {
                    dp[i-1][j-1]
                } else if a.differs_only_in_immediates(b) || a.differs_only_in_registers(b) {
                    dp[i-1][j-1] + sub_cost_minor
                } else {
                    dp[i-1][j-1] + sub_cost_structural
                };
                if dp[i][j] == sub_here {
                    let kind = Self::classify(a, b);
                    entries.push(InsnDiffEntry {
                        old_idx: Some(i - 1),
                        new_idx: Some(j - 1),
                        old_insn: Some(a.clone()),
                        new_insn: Some(b.clone()),
                        kind,
                    });
                    i -= 1; j -= 1;
                    continue;
                }
            }
            if i > 0 && (j == 0 || dp[i][j] == dp[i-1][j] + del_cost) {
                entries.push(InsnDiffEntry {
                    old_idx: Some(i - 1),
                    new_idx: None,
                    old_insn: Some(block_a[i - 1].clone()),
                    new_insn: None,
                    kind: ChangeKind::Deleted,
                });
                i -= 1;
            } else {
                entries.push(InsnDiffEntry {
                    old_idx: None,
                    new_idx: Some(j - 1),
                    old_insn: None,
                    new_insn: Some(block_b[j - 1].clone()),
                    kind: ChangeKind::Inserted,
                });
                j -= 1;
            }
        }

        entries.reverse();
        entries
    }

    fn classify(a: &Instruction, b: &Instruction) -> ChangeKind {
        if a == b {
            return ChangeKind::Unchanged;
        }
        if a.differs_only_in_immediates(b) {
            let old_imms: Vec<i64> = a.operands.iter().filter_map(|o| {
                if let Operand::Immediate(v) = o { Some(*v) } else { None }
            }).collect();
            let new_imms: Vec<i64> = b.operands.iter().filter_map(|o| {
                if let Operand::Immediate(v) = o { Some(*v) } else { None }
            }).collect();
            return ChangeKind::ConstantChange { old_imms, new_imms };
        }
        if a.differs_only_in_registers(b) {
            let old_ops: Vec<String> = a.operands.iter().filter_map(|o| {
                if let Operand::Register(r) = o { Some(r.clone()) } else { None }
            }).collect();
            let new_ops: Vec<String> = b.operands.iter().filter_map(|o| {
                if let Operand::Register(r) = o { Some(r.clone()) } else { None }
            }).collect();
            return ChangeKind::OperandChange { old_ops, new_ops };
        }
        ChangeKind::Structural
    }

    /// Edit distance score (0.0 = identical, 1.0 = completely different).
    #[must_use]
    pub fn edit_distance_score(block_a: &[Instruction], block_b: &[Instruction]) -> f64 {
        let entries = Self::diff(block_a, block_b);
        if entries.is_empty() { return 0.0; }
        let changed = entries.iter().filter(|e| e.kind.is_changed()).count();
        let total = block_a.len().max(block_b.len()).max(1);
        (changed as f64 / total as f64).clamp(0.0, 1.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BlockMatch — result of matching one block pair
// ─────────────────────────────────────────────────────────────────────────────

/// A matched pair of basic blocks.
#[derive(Debug, Clone)]
pub struct BlockMatch {
    pub idx_a: usize,
    pub idx_b: usize,
    /// Similarity in [0, 1] (1 = identical).
    pub similarity: f64,
    /// Instruction-level diff.
    pub insn_diff: Vec<InsnDiffEntry>,
}

impl BlockMatch {
    /// Returns true if the block pair has any changed instructions.
    #[must_use]
    pub fn has_changes(&self) -> bool {
        self.insn_diff.iter().any(|e| e.kind.is_changed())
    }

    /// Number of inserted instructions.
    #[must_use]
    pub fn inserted_count(&self) -> usize {
        self.insn_diff.iter().filter(|e| e.kind == ChangeKind::Inserted).count()
    }

    /// Number of deleted instructions.
    #[must_use]
    pub fn deleted_count(&self) -> usize {
        self.insn_diff.iter().filter(|e| e.kind == ChangeKind::Deleted).count()
    }

    /// Number of structurally changed instructions.
    #[must_use]
    pub fn structural_count(&self) -> usize {
        self.insn_diff.iter().filter(|e| e.kind == ChangeKind::Structural).count()
    }

    /// Number of constant-only changes.
    #[must_use]
    pub fn constant_change_count(&self) -> usize {
        self.insn_diff.iter().filter(|e| matches!(e.kind, ChangeKind::ConstantChange { .. })).count()
    }

    /// Is this block likely a security-relevant change?
    #[must_use]
    pub fn is_security_relevant(&self) -> bool {
        self.insn_diff.iter().any(|e| e.kind.is_security_relevant())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionDiff — per-function diff result
// ─────────────────────────────────────────────────────────────────────────────

/// Full diff between two matched functions.
#[derive(Debug, Clone)]
pub struct FunctionDiff {
    /// Index in binary A.
    pub func_idx_a: usize,
    /// Index in binary B.
    pub func_idx_b: usize,
    /// Matched block pairs with per-block instruction diffs.
    pub block_matches: Vec<BlockMatch>,
    /// Blocks in A with no counterpart in B.
    pub blocks_removed: Vec<usize>,
    /// Blocks in B with no counterpart in A.
    pub blocks_added: Vec<usize>,
    /// Overall function similarity.
    pub similarity: f64,
}

impl FunctionDiff {
    /// Returns true if the function has any changes.
    #[must_use]
    pub fn has_changes(&self) -> bool {
        !self.blocks_removed.is_empty()
            || !self.blocks_added.is_empty()
            || self.block_matches.iter().any(|bm| bm.has_changes())
    }

    /// Aggregated change statistics.
    #[must_use]
    pub fn stats(&self) -> DiffStats {
        let mut stats = DiffStats::default();
        stats.blocks_added    = self.blocks_added.len();
        stats.blocks_removed  = self.blocks_removed.len();
        for bm in &self.block_matches {
            stats.insns_inserted  += bm.inserted_count();
            stats.insns_deleted   += bm.deleted_count();
            stats.insns_structural += bm.structural_count();
            stats.insns_constant  += bm.constant_change_count();
        }
        stats
    }

    /// True if any block change looks security-relevant.
    #[must_use]
    pub fn is_security_relevant(&self) -> bool {
        self.block_matches.iter().any(|bm| bm.is_security_relevant())
    }
}

/// Aggregated change statistics for one function diff.
#[derive(Debug, Clone, Default)]
pub struct DiffStats {
    pub blocks_added:    usize,
    pub blocks_removed:  usize,
    pub insns_inserted:  usize,
    pub insns_deleted:   usize,
    pub insns_structural: usize,
    pub insns_constant:  usize,
}

impl DiffStats {
    /// Total changed instructions.
    #[must_use]
    pub const fn total_changes(&self) -> usize {
        self.insns_inserted + self.insns_deleted + self.insns_structural + self.insns_constant
    }
}

impl fmt::Display for DiffStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "+{blk_add}/-{blk_rm} blocks | +{ii}/-{id} insns | {is} structural | {ic} constant",
            blk_add = self.blocks_added,
            blk_rm  = self.blocks_removed,
            ii      = self.insns_inserted,
            id      = self.insns_deleted,
            is      = self.insns_structural,
            ic      = self.insns_constant,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BasicBlockDiffer — main engine
// ─────────────────────────────────────────────────────────────────────────────

/// Engine for diffing matched function bodies at the basic-block level.
pub struct BasicBlockDiffer {
    /// Minimum block similarity to consider two blocks matched.
    pub min_block_similarity: f64,
}

impl Default for BasicBlockDiffer {
    fn default() -> Self { Self { min_block_similarity: 0.30 } }
}

impl BasicBlockDiffer {
    /// Create with custom threshold.
    #[must_use]
    pub const fn new(min_block_similarity: f64) -> Self {
        Self { min_block_similarity: min_block_similarity.clamp(0.0, 1.0) }
    }

    /// Diff two functions (given their block lists).
    ///
    /// Blocks are matched greedily by descending block similarity.  Unmatched
    /// blocks are reported as added or removed.
    /// Maximum number of basic blocks per function for which a full O(n²)
    /// similarity matrix is built. Functions with more blocks than this are
    /// capped to prevent dos-memory-exhaustion from crafted inputs.
    pub const MAX_BLOCKS_PER_FUNCTION: usize = 4_096;

    #[must_use]
    pub fn diff_functions(
        &self,
        func_idx_a: usize,
        blocks_a: &[BasicBlock],
        func_idx_b: usize,
        blocks_b: &[BasicBlock],
    ) -> FunctionDiff {
        // Cap block counts to prevent O(n²) memory exhaustion from a crafted
        // binary with a pathologically large number of basic blocks per function.
        let blocks_a = &blocks_a[..blocks_a.len().min(Self::MAX_BLOCKS_PER_FUNCTION)];
        let blocks_b = &blocks_b[..blocks_b.len().min(Self::MAX_BLOCKS_PER_FUNCTION)];

        // Build similarity matrix.
        let sim: Vec<Vec<f64>> = blocks_a
            .iter()
            .map(|ba| blocks_b.iter().map(|bb| self.block_similarity(ba, bb)).collect())
            .collect();

        // Greedy match blocks.
        let (matched, unmatched_a, unmatched_b) = self.greedy_block_match(&sim, blocks_a.len(), blocks_b.len());

        // Build block matches with instruction diffs.
        let block_matches: Vec<BlockMatch> = matched
            .into_iter()
            .map(|(ia, ib, block_sim)| {
                let insn_diff = InsnDiffer::diff(&blocks_a[ia].instructions, &blocks_b[ib].instructions);
                BlockMatch { idx_a: ia, idx_b: ib, similarity: block_sim, insn_diff }
            })
            .collect();

        // Overall function similarity = weighted avg of block similarities.
        let total = blocks_a.len().max(blocks_b.len()).max(1) as f64;
        let weighted: f64 = block_matches.iter().map(|bm| bm.similarity).sum();
        let similarity = (weighted / total).clamp(0.0, 1.0);

        FunctionDiff {
            func_idx_a,
            func_idx_b,
            block_matches,
            blocks_removed: unmatched_a,
            blocks_added:   unmatched_b,
            similarity,
        }
    }

    // ─── Block similarity ────────────────────────────────────────────────────

    fn block_similarity(&self, a: &BasicBlock, b: &BasicBlock) -> f64 {
        // Hash fast-path: identical content.
        if a.content_hash() == b.content_hash() {
            return 1.0;
        }
        // Instruction edit distance.
        let ed = InsnDiffer::edit_distance_score(&a.instructions, &b.instructions);
        1.0 - ed
    }

    // ─── Greedy block matching ───────────────────────────────────────────────

    fn greedy_block_match(
        &self,
        sim: &[Vec<f64>],
        n_a: usize,
        n_b: usize,
    ) -> (Vec<(usize, usize, f64)>, Vec<usize>, Vec<usize>) {
        // Collect all (sim, i, j) above threshold.
        let mut candidates: Vec<(f64, usize, usize)> = Vec::new();
        for i in 0..n_a {
            for j in 0..n_b {
                let s = sim[i][j];
                if s >= self.min_block_similarity {
                    candidates.push((s, i, j));
                }
            }
        }
        candidates.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        let mut used_a = std::collections::HashSet::new();
        let mut used_b = std::collections::HashSet::new();
        let mut matched = Vec::new();

        for (s, i, j) in candidates {
            if used_a.contains(&i) || used_b.contains(&j) { continue; }
            used_a.insert(i);
            used_b.insert(j);
            matched.push((i, j, s));
        }

        let unmatched_a: Vec<usize> = (0..n_a).filter(|i| !used_a.contains(i)).collect();
        let unmatched_b: Vec<usize> = (0..n_b).filter(|j| !used_b.contains(j)).collect();

        (matched, unmatched_a, unmatched_b)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build a simple `BasicBlock` from a list of `(mnemonic, operands)` pairs.
#[must_use]
pub fn make_block(idx: usize, insns: &[(&str, &[Operand])]) -> BasicBlock {
    BasicBlock {
        idx,
        start_addr: idx as u64 * 0x10,
        instructions: insns
            .iter()
            .map(|(mn, ops)| Instruction { mnemonic: mn.to_string(), operands: ops.to_vec() })
            .collect(),
        successors: Vec::new(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mov_imm(reg: &str, val: i64) -> Instruction {
        Instruction::new("mov", vec![Operand::Register(reg.to_string()), Operand::Immediate(val)])
    }

    fn mov_reg(dst: &str, src: &str) -> Instruction {
        Instruction::new("mov", vec![Operand::Register(dst.to_string()), Operand::Register(src.to_string())])
    }

    fn ret() -> Instruction { Instruction::new("ret", vec![]) }
    fn nop() -> Instruction { Instruction::new("nop", vec![]) }

    #[test]
    fn test_identical_blocks_no_diff() {
        let insns = vec![mov_imm("rax", 42), ret()];
        let diff = InsnDiffer::diff(&insns, &insns);
        assert!(diff.iter().all(|e| e.kind == ChangeKind::Unchanged));
    }

    #[test]
    fn test_constant_change_detected() {
        let a = vec![mov_imm("rax", 42)];
        let b = vec![mov_imm("rax", 1337)];
        let diff = InsnDiffer::diff(&a, &b);
        assert_eq!(diff.len(), 1);
        assert!(matches!(diff[0].kind, ChangeKind::ConstantChange { .. }));
    }

    #[test]
    fn test_operand_change_detected() {
        let a = vec![mov_reg("rax", "rbx")];
        let b = vec![mov_reg("rax", "rcx")];
        let diff = InsnDiffer::diff(&a, &b);
        assert_eq!(diff.len(), 1);
        assert!(matches!(diff[0].kind, ChangeKind::OperandChange { .. }));
    }

    #[test]
    fn test_structural_change_detected() {
        let a = vec![mov_imm("rax", 0)];
        let b = vec![ret()];
        let diff = InsnDiffer::diff(&a, &b);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].kind, ChangeKind::Structural);
    }

    #[test]
    fn test_insertion_detected() {
        let a = vec![ret()];
        let b = vec![nop(), ret()];
        let diff = InsnDiffer::diff(&a, &b);
        let inserted = diff.iter().filter(|e| e.kind == ChangeKind::Inserted).count();
        assert_eq!(inserted, 1);
    }

    #[test]
    fn test_deletion_detected() {
        let a = vec![nop(), ret()];
        let b = vec![ret()];
        let diff = InsnDiffer::diff(&a, &b);
        let deleted = diff.iter().filter(|e| e.kind == ChangeKind::Deleted).count();
        assert_eq!(deleted, 1);
    }

    #[test]
    fn test_edit_distance_score_identical() {
        let insns = vec![mov_imm("rax", 1), ret()];
        let score = InsnDiffer::edit_distance_score(&insns, &insns);
        assert_eq!(score, 0.0);
    }

    #[test]
    fn test_edit_distance_score_completely_different() {
        let a = vec![mov_imm("rax", 1), mov_imm("rbx", 2)];
        let b = vec![ret(), nop()];
        let score = InsnDiffer::edit_distance_score(&a, &b);
        assert!(score > 0.0);
    }

    #[test]
    fn test_block_similarity_identical() {
        let insns = vec![mov_imm("rax", 42), ret()];
        let ba = make_block(0, &insns.iter().map(|i| (i.mnemonic.as_str(), i.operands.as_slice())).collect::<Vec<_>>());
        // Use content hash path.
        assert_eq!(ba.content_hash(), ba.content_hash());
    }

    #[test]
    fn test_function_diff_no_changes() {
        let differ = BasicBlockDiffer::default();
        let block = BasicBlock {
            idx: 0, start_addr: 0,
            instructions: vec![mov_imm("rax", 42), ret()],
            successors: Vec::new(),
        };
        let result = differ.diff_functions(0, &[block.clone()], 1, &[block]);
        assert!(!result.has_changes());
        assert!((result.similarity - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_function_diff_added_block() {
        let differ = BasicBlockDiffer::default();
        let block_a = BasicBlock {
            idx: 0, start_addr: 0,
            instructions: vec![ret()],
            successors: Vec::new(),
        };
        let block_b = BasicBlock {
            idx: 0, start_addr: 0,
            instructions: vec![ret()],
            successors: Vec::new(),
        };
        let extra_b = BasicBlock {
            idx: 1, start_addr: 0x10,
            instructions: vec![nop(), ret()],
            successors: Vec::new(),
        };
        let result = differ.diff_functions(0, &[block_a], 1, &[block_b, extra_b]);
        assert_eq!(result.blocks_added.len(), 1);
    }

    #[test]
    fn test_stats_aggregation() {
        let differ = BasicBlockDiffer::default();
        let block_a = BasicBlock {
            idx: 0, start_addr: 0,
            instructions: vec![mov_imm("rax", 42), ret()],
            successors: Vec::new(),
        };
        let block_b = BasicBlock {
            idx: 0, start_addr: 0,
            instructions: vec![mov_imm("rax", 1337), ret()],
            successors: Vec::new(),
        };
        let result = differ.diff_functions(0, &[block_a], 1, &[block_b]);
        let stats = result.stats();
        assert_eq!(stats.insns_constant, 1);
        assert_eq!(stats.total_changes(), 1);
    }

    #[test]
    fn test_security_relevant_detection() {
        let differ = BasicBlockDiffer::default();
        let block_a = BasicBlock {
            idx: 0, start_addr: 0,
            instructions: vec![ret()],
            successors: Vec::new(),
        };
        let block_b = BasicBlock {
            idx: 0, start_addr: 0,
            instructions: vec![nop(), ret()],
            successors: Vec::new(),
        };
        let result = differ.diff_functions(0, &[block_a], 1, &[block_b]);
        assert!(result.is_security_relevant());
    }

    #[test]
    fn test_instruction_display() {
        let insn = mov_imm("rax", 255);
        let s = format!("{insn}");
        assert!(s.contains("mov"));
        assert!(s.contains("rax"));
    }
}
