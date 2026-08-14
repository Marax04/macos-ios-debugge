//! Instruction-level binary diff.
//!
//! Compares two sequences of decoded instructions and produces a fine-grained
//! diff at instruction granularity, including operand-level changes.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Instruction representation
// ---------------------------------------------------------------------------

/// A simplified decoded instruction for diffing purposes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffInstr {
    /// Byte offset from function start.
    pub offset: u64,
    /// Mnemonic (e.g. `mov`, `call`, `ret`).
    pub mnemonic: String,
    /// Text representation of operands.
    pub operands: String,
    /// Raw bytes of this instruction.
    pub bytes: Vec<u8>,
    /// Instruction size in bytes.
    pub size: u8,
}

impl DiffInstr {
    /// Create a new instruction.
    #[must_use]
    pub fn new(
        offset: u64,
        mnemonic: impl Into<String>,
        operands: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Self {
        let size = u8::try_from(bytes.len()).unwrap_or(u8::MAX);
        Self {
            offset,
            mnemonic: mnemonic.into(),
            operands: operands.into(),
            bytes,
            size,
        }
    }

    /// Return `true` if this is a call instruction.
    #[must_use]
    pub fn is_call(&self) -> bool {
        self.mnemonic.starts_with("call")
    }

    /// Return `true` if this is a branch instruction.
    #[must_use]
    pub fn is_branch(&self) -> bool {
        let m = self.mnemonic.as_str();
        matches!(
            m,
            "jmp"
                | "je"
                | "jne"
                | "jz"
                | "jnz"
                | "jl"
                | "jle"
                | "jg"
                | "jge"
                | "ja"
                | "jb"
                | "jae"
                | "jbe"
                | "js"
                | "jns"
                | "jc"
                | "jnc"
                | "jo"
                | "jno"
        )
    }

    /// Return `true` if this is a return instruction.
    #[must_use]
    pub fn is_return(&self) -> bool {
        self.mnemonic.starts_with("ret")
    }

    /// Full text representation: `mnemonic operands`.
    #[must_use]
    pub fn text(&self) -> String {
        if self.operands.is_empty() {
            self.mnemonic.clone()
        } else {
            format!("{} {}", self.mnemonic, self.operands)
        }
    }
}

impl fmt::Display for DiffInstr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#06x}  {}", self.offset, self.text())
    }
}

// ---------------------------------------------------------------------------
// InstrDiffKind
// ---------------------------------------------------------------------------

/// How a single instruction changed between the two versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstrDiffKind {
    /// Instruction is unchanged.
    Unchanged,
    /// Instruction was added in the new version.
    Added,
    /// Instruction was removed from the old version.
    Removed,
    /// Instruction mnemonic changed.
    MnemonicChanged,
    /// Instruction mnemonic is the same but operands differ.
    OperandsChanged,
    /// Both mnemonic and operands changed.
    FullyChanged,
}

impl fmt::Display for InstrDiffKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ---------------------------------------------------------------------------
// InstrDiffEntry
// ---------------------------------------------------------------------------

/// A single entry in an instruction-level diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstrDiffEntry {
    /// How this line changed.
    pub kind: InstrDiffKind,
    /// Instruction from the old version (absent if added).
    pub old_instr: Option<DiffInstr>,
    /// Instruction from the new version (absent if removed).
    pub new_instr: Option<DiffInstr>,
}

impl InstrDiffEntry {
    /// Create an unchanged entry.
    #[must_use]
    pub fn unchanged(instr: DiffInstr) -> Self {
        Self {
            kind: InstrDiffKind::Unchanged,
            old_instr: Some(instr.clone()),
            new_instr: Some(instr),
        }
    }

    /// Create an added entry.
    #[must_use]
    pub const fn added(instr: DiffInstr) -> Self {
        Self {
            kind: InstrDiffKind::Added,
            old_instr: None,
            new_instr: Some(instr),
        }
    }

    /// Create a removed entry.
    #[must_use]
    pub const fn removed(instr: DiffInstr) -> Self {
        Self {
            kind: InstrDiffKind::Removed,
            old_instr: Some(instr),
            new_instr: None,
        }
    }

    /// Create a changed entry.
    #[must_use]
    pub fn changed(old: DiffInstr, new: DiffInstr) -> Self {
        let kind = if old.mnemonic == new.mnemonic {
            InstrDiffKind::OperandsChanged
        } else if old.operands == new.operands {
            InstrDiffKind::MnemonicChanged
        } else {
            InstrDiffKind::FullyChanged
        };
        Self {
            kind,
            old_instr: Some(old),
            new_instr: Some(new),
        }
    }

    /// Return `true` if this entry represents a change.
    #[must_use]
    pub const fn is_changed(&self) -> bool {
        !matches!(self.kind, InstrDiffKind::Unchanged)
    }
}

impl fmt::Display for InstrDiffEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            InstrDiffKind::Unchanged => {
                write!(
                    f,
                    "  {}",
                    self.old_instr
                        .as_ref()
                        .map(DiffInstr::text)
                        .unwrap_or_default()
                )
            }
            InstrDiffKind::Added => {
                write!(
                    f,
                    "+ {}",
                    self.new_instr
                        .as_ref()
                        .map(DiffInstr::text)
                        .unwrap_or_default()
                )
            }
            InstrDiffKind::Removed => {
                write!(
                    f,
                    "- {}",
                    self.old_instr
                        .as_ref()
                        .map(DiffInstr::text)
                        .unwrap_or_default()
                )
            }
            InstrDiffKind::MnemonicChanged
            | InstrDiffKind::OperandsChanged
            | InstrDiffKind::FullyChanged => {
                write!(
                    f,
                    "~ {} → {}",
                    self.old_instr
                        .as_ref()
                        .map(DiffInstr::text)
                        .unwrap_or_default(),
                    self.new_instr
                        .as_ref()
                        .map(DiffInstr::text)
                        .unwrap_or_default()
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// InstrDiff (the full diff result)
// ---------------------------------------------------------------------------

/// Complete instruction-level diff between two function bodies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstrDiff {
    /// Name of the function diffed.
    pub function_name: String,
    /// Diff entries.
    pub entries: Vec<InstrDiffEntry>,
}

impl InstrDiff {
    /// Compute the count of each change kind.
    #[must_use]
    pub fn added_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.kind == InstrDiffKind::Added)
            .count()
    }

    /// Count of removed instructions.
    #[must_use]
    pub fn removed_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.kind == InstrDiffKind::Removed)
            .count()
    }

    /// Count of changed instructions.
    #[must_use]
    pub fn changed_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    InstrDiffKind::MnemonicChanged
                        | InstrDiffKind::OperandsChanged
                        | InstrDiffKind::FullyChanged
                )
            })
            .count()
    }

    /// Count of unchanged instructions.
    #[must_use]
    pub fn unchanged_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.kind == InstrDiffKind::Unchanged)
            .count()
    }

    /// Total number of instructions in the diff.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.entries.len()
    }

    /// Return the similarity fraction (unchanged / total).
    #[must_use]
    pub fn similarity(&self) -> f64 {
        if self.total() == 0 {
            1.0
        } else {
            f64::from(u32::try_from(self.unchanged_count()).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(self.total()).unwrap_or(u32::MAX))
        }
    }

    /// Return only the changed entries.
    #[must_use]
    pub fn changed_entries(&self) -> Vec<&InstrDiffEntry> {
        self.entries.iter().filter(|e| e.is_changed()).collect()
    }
}

impl fmt::Display for InstrDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Diff for '{}':", self.function_name)?;
        for entry in &self.entries {
            writeln!(f, "  {entry}")?;
        }
        write!(
            f,
            "Summary: +{} -{} ~{} ={} (similarity={:.0}%)",
            self.added_count(),
            self.removed_count(),
            self.changed_count(),
            self.unchanged_count(),
            self.similarity() * 100.0,
        )
    }
}

// ---------------------------------------------------------------------------
// InstrDiffer — the LCS-based instruction differ
// ---------------------------------------------------------------------------

/// Computes an instruction-level diff using a longest-common-subsequence (LCS)
/// approach on instruction text representations.
#[derive(Debug, Default)]
pub struct InstrDiffer;

impl InstrDiffer {
    /// Create a new instruction differ.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Compute an instruction diff between `old` and `new` for `function_name`.
    #[must_use]
    pub fn diff(
        &self,
        function_name: impl Into<String>,
        old: &[DiffInstr],
        new: &[DiffInstr],
    ) -> InstrDiff {
        let entries = Self::lcs_diff(old, new);
        InstrDiff {
            function_name: function_name.into(),
            entries,
        }
    }

    /// LCS-based diff algorithm.
    fn lcs_diff(old: &[DiffInstr], new: &[DiffInstr]) -> Vec<InstrDiffEntry> {
        let n = old.len();
        let m = new.len();

        // Build LCS table
        let mut dp = vec![vec![0usize; m + 1]; n + 1];
        for i in 1..=n {
            for j in 1..=m {
                if old[i - 1].mnemonic == new[j - 1].mnemonic {
                    dp[i][j] = dp[i - 1][j - 1] + 1;
                } else {
                    dp[i][j] = dp[i - 1][j].max(dp[i][j - 1]);
                }
            }
        }

        // Traceback
        let mut entries = Vec::with_capacity(n + m);
        let mut i = n;
        let mut j = m;
        while i > 0 || j > 0 {
            if i > 0 && j > 0 && old[i - 1].mnemonic == new[j - 1].mnemonic {
                // Same mnemonic — check if operands changed too
                if old[i - 1] == new[j - 1] {
                    entries.push(InstrDiffEntry::unchanged(old[i - 1].clone()));
                } else {
                    entries.push(InstrDiffEntry::changed(
                        old[i - 1].clone(),
                        new[j - 1].clone(),
                    ));
                }
                i -= 1;
                j -= 1;
            } else if j > 0 && (i == 0 || dp[i][j - 1] >= dp[i - 1][j]) {
                entries.push(InstrDiffEntry::added(new[j - 1].clone()));
                j -= 1;
            } else {
                entries.push(InstrDiffEntry::removed(old[i - 1].clone()));
                i -= 1;
            }
        }

        entries.reverse();
        entries
    }
}

// ---------------------------------------------------------------------------
// OperandDiff
// ---------------------------------------------------------------------------

/// Detailed operand-level change between two instructions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperandDiff {
    /// Operand index (0-based).
    pub index: usize,
    /// Old operand text.
    pub old: String,
    /// New operand text.
    pub new: String,
}

/// Decompose operand changes between two instructions.
///
/// Operands are split by comma+space.
#[must_use]
pub fn operand_changes(old: &DiffInstr, new: &DiffInstr) -> Vec<OperandDiff> {
    let old_ops: Vec<&str> = old.operands.split(", ").collect();
    let new_ops: Vec<&str> = new.operands.split(", ").collect();
    let len = old_ops.len().max(new_ops.len());
    let mut changes = Vec::with_capacity(len);
    for i in 0..len {
        let o = old_ops.get(i).copied().unwrap_or("");
        let n = new_ops.get(i).copied().unwrap_or("");
        if o != n {
            changes.push(OperandDiff {
                index: i,
                old: o.to_string(),
                new: n.to_string(),
            });
        }
    }
    changes
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_instr(offset: u64, mnem: &str, ops: &str) -> DiffInstr {
        DiffInstr::new(offset, mnem, ops, vec![0x90])
    }

    fn make_nop(offset: u64) -> DiffInstr {
        DiffInstr::new(offset, "nop", "", vec![0x90])
    }

    fn make_mov(offset: u64, dst: &str, src: &str) -> DiffInstr {
        DiffInstr::new(offset, "mov", format!("{dst}, {src}"), vec![0x48, 0x89])
    }

    fn differ() -> InstrDiffer {
        InstrDiffer::new()
    }

    #[test]
    fn test_diffinstr_new() {
        let i = make_instr(0, "push", "rbp");
        assert_eq!(i.mnemonic, "push");
        assert_eq!(i.operands, "rbp");
        assert_eq!(i.size, 1);
        assert_eq!(i.offset, 0);
    }

    #[test]
    fn test_diffinstr_is_call() {
        assert!(make_instr(0, "call", "rax").is_call());
        assert!(!make_instr(0, "mov", "rax, rbx").is_call());
    }

    #[test]
    fn test_diffinstr_is_branch() {
        assert!(make_instr(0, "jmp", "0x1000").is_branch());
        assert!(make_instr(0, "je", "0x1000").is_branch());
        assert!(!make_instr(0, "mov", "rax, rbx").is_branch());
    }

    #[test]
    fn test_diffinstr_is_return() {
        assert!(make_instr(0, "ret", "").is_return());
        assert!(make_instr(0, "retn", "").is_return());
        assert!(!make_instr(0, "jmp", "rax").is_return());
    }

    #[test]
    fn test_diffinstr_text_no_ops() {
        let i = make_nop(0);
        assert_eq!(i.text(), "nop");
    }

    #[test]
    fn test_diffinstr_text_with_ops() {
        let i = make_mov(0, "rax", "rbx");
        assert_eq!(i.text(), "mov rax, rbx");
    }

    #[test]
    fn test_diffinstr_display() {
        let i = make_mov(0x10, "rax", "rbx");
        let s = i.to_string();
        assert!(s.contains("0x0010"));
        assert!(s.contains("mov"));
    }

    #[test]
    fn test_instr_diff_entry_unchanged() {
        let i = make_nop(0);
        let e = InstrDiffEntry::unchanged(i);
        assert!(!e.is_changed());
        assert_eq!(e.kind, InstrDiffKind::Unchanged);
    }

    #[test]
    fn test_instr_diff_entry_added() {
        let i = make_nop(0);
        let e = InstrDiffEntry::added(i);
        assert!(e.is_changed());
        assert_eq!(e.kind, InstrDiffKind::Added);
        assert!(e.old_instr.is_none());
    }

    #[test]
    fn test_instr_diff_entry_removed() {
        let i = make_nop(0);
        let e = InstrDiffEntry::removed(i);
        assert!(e.is_changed());
        assert_eq!(e.kind, InstrDiffKind::Removed);
        assert!(e.new_instr.is_none());
    }

    #[test]
    fn test_instr_diff_entry_mnemonic_changed() {
        let old = make_instr(0, "add", "rax, 1");
        let new = make_instr(0, "sub", "rax, 1");
        let e = InstrDiffEntry::changed(old, new);
        assert_eq!(e.kind, InstrDiffKind::MnemonicChanged);
    }

    #[test]
    fn test_instr_diff_entry_operands_changed() {
        let old = make_instr(0, "mov", "rax, rbx");
        let new = make_instr(0, "mov", "rax, rcx");
        let e = InstrDiffEntry::changed(old, new);
        assert_eq!(e.kind, InstrDiffKind::OperandsChanged);
    }

    #[test]
    fn test_instr_diff_entry_fully_changed() {
        let old = make_instr(0, "add", "rax, rbx");
        let new = make_instr(0, "xor", "rdi, rsi");
        let e = InstrDiffEntry::changed(old, new);
        assert_eq!(e.kind, InstrDiffKind::FullyChanged);
    }

    #[test]
    fn test_instr_diff_entry_display_added() {
        let e = InstrDiffEntry::added(make_nop(0));
        let s = e.to_string();
        assert!(s.starts_with('+'));
    }

    #[test]
    fn test_instr_diff_entry_display_removed() {
        let e = InstrDiffEntry::removed(make_nop(0));
        let s = e.to_string();
        assert!(s.starts_with('-'));
    }

    #[test]
    fn test_differ_identical_sequences() {
        let seq = vec![make_nop(0), make_mov(1, "rax", "rbx")];
        let diff = differ().diff("test_fn", &seq, &seq);
        assert_eq!(diff.unchanged_count(), 2);
        assert_eq!(diff.added_count(), 0);
        assert_eq!(diff.removed_count(), 0);
        assert!((diff.similarity() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_differ_added_instruction() {
        let old = vec![make_nop(0)];
        let new = vec![make_nop(0), make_mov(1, "rax", "rbx")];
        let diff = differ().diff("test_fn", &old, &new);
        assert_eq!(diff.added_count(), 1);
        assert_eq!(diff.removed_count(), 0);
    }

    #[test]
    fn test_differ_removed_instruction() {
        let old = vec![make_nop(0), make_mov(1, "rax", "rbx")];
        let new = vec![make_nop(0)];
        let diff = differ().diff("test_fn", &old, &new);
        assert_eq!(diff.removed_count(), 1);
        assert_eq!(diff.added_count(), 0);
    }

    #[test]
    fn test_differ_changed_operands() {
        let old = vec![make_mov(0, "rax", "rbx")];
        let new = vec![make_mov(0, "rax", "rcx")];
        let diff = differ().diff("fn", &old, &new);
        assert_eq!(diff.changed_count(), 1);
    }

    #[test]
    fn test_differ_empty_inputs() {
        let diff = differ().diff("empty", &[], &[]);
        assert_eq!(diff.total(), 0);
        assert!((diff.similarity() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_differ_old_empty() {
        let new = vec![make_nop(0), make_nop(1)];
        let diff = differ().diff("fn", &[], &new);
        assert_eq!(diff.added_count(), 2);
        assert_eq!(diff.unchanged_count(), 0);
    }

    #[test]
    fn test_differ_new_empty() {
        let old = vec![make_nop(0), make_nop(1)];
        let diff = differ().diff("fn", &old, &[]);
        assert_eq!(diff.removed_count(), 2);
    }

    #[test]
    fn test_instr_diff_similarity_partial() {
        let old = vec![make_nop(0), make_mov(1, "rax", "rbx"), make_nop(2)];
        let new = vec![make_nop(0), make_mov(1, "rax", "rcx"), make_nop(2)];
        let diff = differ().diff("fn", &old, &new);
        assert!(diff.similarity() > 0.0);
        assert!(diff.similarity() < 1.0);
    }

    #[test]
    fn test_instr_diff_display() {
        let old = vec![make_nop(0)];
        let new = vec![make_nop(0), make_mov(1, "rax", "0")];
        let diff = differ().diff("my_func", &old, &new);
        let s = diff.to_string();
        assert!(s.contains("my_func"));
        assert!(s.contains('+'));
    }

    #[test]
    fn test_instr_diff_changed_entries() {
        let old = vec![make_nop(0), make_mov(1, "rax", "rbx")];
        let new = vec![make_nop(0), make_mov(1, "rax", "rcx")];
        let diff = differ().diff("fn", &old, &new);
        assert_eq!(diff.changed_entries().len(), 1);
    }

    #[test]
    fn test_operand_changes_same() {
        let a = make_mov(0, "rax", "rbx");
        let b = make_mov(0, "rax", "rbx");
        assert!(operand_changes(&a, &b).is_empty());
    }

    #[test]
    fn test_operand_changes_different() {
        let a = make_mov(0, "rax", "rbx");
        let b = make_mov(0, "rax", "rcx");
        let changes = operand_changes(&a, &b);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].index, 1);
        assert_eq!(changes[0].old, "rbx");
        assert_eq!(changes[0].new, "rcx");
    }

    #[test]
    fn test_instr_diff_kind_display() {
        assert_eq!(InstrDiffKind::Added.to_string(), "Added");
        assert_eq!(InstrDiffKind::Unchanged.to_string(), "Unchanged");
    }

    #[test]
    fn test_diffinstr_serialization() {
        let i = make_nop(0);
        let json = serde_json::to_string(&i).unwrap();
        let decoded: DiffInstr = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.mnemonic, "nop");
    }

    #[test]
    fn test_instr_diff_entry_serialization() {
        let e = InstrDiffEntry::added(make_nop(0));
        let json = serde_json::to_string(&e).unwrap();
        let decoded: InstrDiffEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.kind, InstrDiffKind::Added);
    }
}
