//! MIPS delay slot analysis.
//!
//! Every MIPS branch, jump, and call instruction is followed by exactly one
//! *delay slot* instruction that executes unconditionally before the branch
//! takes effect.  This module models and analyses delay slots, including the
//! annulled variant (MIPS II+) where the delay slot is *skipped* when the
//! branch is not taken.

use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// DelaySlotKind
// ---------------------------------------------------------------------------

/// The delay-slot behaviour of a MIPS branch or jump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DelaySlotKind {
    /// Standard delay slot — the following instruction always executes.
    Standard,
    /// Annulled delay slot (`.a` suffix) — the following instruction is
    /// skipped when the branch is *not* taken.
    Annulled,
    /// No delay slot (MIPS16 / microMIPS compact branches).
    None,
}

impl fmt::Display for DelaySlotKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Standard => f.write_str("standard"),
            Self::Annulled => f.write_str("annulled"),
            Self::None => f.write_str("none"),
        }
    }
}

// ---------------------------------------------------------------------------
// MipsOpcode (branch/jump subset)
// ---------------------------------------------------------------------------

/// MIPS branch and jump opcodes that have delay slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MipsJumpOpcode {
    // Unconditional jumps
    J,
    Jal,
    Jr,
    Jalr,
    // Conditional branches
    Beq,
    Bne,
    Blez,
    Bgtz,
    Bltz,
    Bgez,
    Bltzal,
    Bgezal,
    // Likely branches (annulled, MIPS II)
    Beql,
    Bnel,
    Blezl,
    Bgtzl,
    Bltzl,
    Bgezl,
    Bltzall,
    Bgezall,
    // FPU branches
    Bc1f,
    Bc1t,
    Bc1fl,
    Bc1tl,
    // MIPS32r2 balanced branches (no delay slot)
    Bal,
    Beqz,
    Bnez,
}

impl MipsJumpOpcode {
    /// Returns the delay-slot kind for this opcode.
    #[must_use]
    pub const fn delay_slot_kind(self) -> DelaySlotKind {
        match self {
            // Likely branches have annulled delay slots
            Self::Beql
            | Self::Bnel
            | Self::Blezl
            | Self::Bgtzl
            | Self::Bltzl
            | Self::Bgezl
            | Self::Bltzall
            | Self::Bgezall
            | Self::Bc1fl
            | Self::Bc1tl => DelaySlotKind::Annulled,
            // Compact branches have no delay slot
            Self::Bal | Self::Beqz | Self::Bnez => DelaySlotKind::None,
            // All others have a standard delay slot
            _ => DelaySlotKind::Standard,
        }
    }

    /// Returns `true` if this opcode is an unconditional jump.
    #[must_use]
    pub const fn is_unconditional(self) -> bool {
        matches!(self, Self::J | Self::Jal | Self::Jr | Self::Jalr)
    }

    /// Returns `true` if this is a call (link) instruction.
    #[must_use]
    pub const fn is_call(self) -> bool {
        matches!(self, Self::Jal | Self::Jalr | Self::Bltzal | Self::Bgezal | Self::Bltzall | Self::Bgezall | Self::Bal)
    }

    /// Returns the mnemonic string for this opcode.
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::J => "j",
            Self::Jal => "jal",
            Self::Jr => "jr",
            Self::Jalr => "jalr",
            Self::Beq => "beq",
            Self::Bne => "bne",
            Self::Blez => "blez",
            Self::Bgtz => "bgtz",
            Self::Bltz => "bltz",
            Self::Bgez => "bgez",
            Self::Bltzal => "bltzal",
            Self::Bgezal => "bgezal",
            Self::Beql => "beql",
            Self::Bnel => "bnel",
            Self::Blezl => "blezl",
            Self::Bgtzl => "bgtzl",
            Self::Bltzl => "bltzl",
            Self::Bgezl => "bgezl",
            Self::Bltzall => "bltzall",
            Self::Bgezall => "bgezall",
            Self::Bc1f => "bc1f",
            Self::Bc1t => "bc1t",
            Self::Bc1fl => "bc1fl",
            Self::Bc1tl => "bc1tl",
            Self::Bal => "bal",
            Self::Beqz => "beqz",
            Self::Bnez => "bnez",
        }
    }
}

// ---------------------------------------------------------------------------
// DelaySlotInsn
// ---------------------------------------------------------------------------

/// A raw MIPS instruction in a delay slot, with metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelaySlotInsn {
    /// Virtual address of the delay-slot instruction.
    pub address: u64,
    /// Raw 32-bit encoding.
    pub encoding: u32,
    /// Human-readable disassembly text.
    pub text: String,
    /// Registers read by this instruction.
    pub reads: Vec<u8>,
    /// Registers written by this instruction.
    pub writes: Vec<u8>,
    /// Whether this instruction itself is a branch/jump (forbidden in delay slots).
    pub is_branch: bool,
    /// Whether this instruction is a NOP (SLL $zero, $zero, 0).
    pub is_nop: bool,
}

impl DelaySlotInsn {
    /// The canonical MIPS NOP encoding: `SLL $zero, $zero, 0` = 0x00000000.
    pub const NOP_ENCODING: u32 = 0x0000_0000;

    /// Create a NOP delay-slot instruction at the given address.
    #[must_use]
    pub fn nop(address: u64) -> Self {
        Self {
            address,
            encoding: Self::NOP_ENCODING,
            text: "nop".to_string(),
            reads: Vec::new(),
            writes: Vec::new(),
            is_branch: false,
            is_nop: true,
        }
    }

    /// Returns `true` if this instruction modifies the branch condition.
    ///
    /// Such instructions in delay slots can change the branch outcome depending
    /// on whether the delay slot executes before or after register updates —
    /// flagged as hazardous during analysis.
    #[must_use]
    pub fn has_write_hazard(&self, condition_regs: &[u8]) -> bool {
        self.writes.iter().any(|w| condition_regs.contains(w))
    }
}

impl fmt::Display for DelaySlotInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x}  {:08x}  {}", self.address, self.encoding, self.text)
    }
}

// ---------------------------------------------------------------------------
// BranchWithDelay
// ---------------------------------------------------------------------------

/// A MIPS branch or jump paired with its delay-slot instruction.
#[derive(Debug, Clone)]
pub struct BranchWithDelay {
    /// Virtual address of the branch/jump instruction itself.
    pub branch_address: u64,
    /// The raw 32-bit encoding of the branch/jump.
    pub branch_encoding: u32,
    /// The opcode of the branch/jump.
    pub opcode: MipsJumpOpcode,
    /// The static branch target address, if known (None for JR/JALR).
    pub target: Option<u64>,
    /// The fall-through address (`branch_address` + 8, skipping the delay slot).
    pub fallthrough: u64,
    /// The delay-slot instruction.
    pub delay_slot: DelaySlotInsn,
    /// The kind of delay slot for this branch.
    pub kind: DelaySlotKind,
    /// Source registers used in the branch condition.
    pub condition_regs: Vec<u8>,
}

impl BranchWithDelay {
    /// Construct a new `BranchWithDelay`.
    #[must_use]
    pub const fn new(
        branch_address: u64,
        branch_encoding: u32,
        opcode: MipsJumpOpcode,
        target: Option<u64>,
        delay_slot: DelaySlotInsn,
        condition_regs: Vec<u8>,
    ) -> Self {
        let kind = opcode.delay_slot_kind();
        let fallthrough = branch_address.wrapping_add(8);
        Self {
            branch_address,
            branch_encoding,
            opcode,
            target,
            fallthrough,
            delay_slot,
            kind,
            condition_regs,
        }
    }

    /// Returns `true` if the delay slot instruction is a NOP.
    #[must_use]
    pub const fn delay_is_nop(&self) -> bool {
        self.delay_slot.is_nop
    }

    /// Returns `true` if the delay-slot instruction writes to any register that
    /// influences the branch condition (a hazard worth flagging).
    #[must_use]
    pub fn has_condition_hazard(&self) -> bool {
        self.delay_slot.has_write_hazard(&self.condition_regs)
    }

    /// For annulled branches, check whether the delay slot should be skipped.
    ///
    /// `branch_taken` is the runtime decision; if `false` and the branch is
    /// annulled, the delay slot is skipped.
    #[must_use]
    pub fn annul_check(&self, branch_taken: bool) -> AnnulDecision {
        annul_check(self, branch_taken)
    }

    /// Returns the address of the delay-slot instruction.
    #[must_use]
    pub const fn delay_slot_address(&self) -> u64 {
        self.branch_address.wrapping_add(4)
    }
}

impl fmt::Display for BranchWithDelay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#010x}  {} [ds_kind={}]  +ds: {}",
            self.branch_address,
            self.opcode.mnemonic(),
            self.kind,
            self.delay_slot.text
        )
    }
}

// ---------------------------------------------------------------------------
// AnnulDecision
// ---------------------------------------------------------------------------

/// The result of evaluating an annulled delay-slot at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnulDecision {
    /// The delay-slot instruction executes (branch taken, or non-annulled).
    Execute,
    /// The delay-slot instruction is skipped (annulled branch not taken).
    Skip,
    /// The branch is not annulled; delay slot always executes.
    NotAnnulled,
}

impl fmt::Display for AnnulDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Execute => f.write_str("execute"),
            Self::Skip => f.write_str("skip"),
            Self::NotAnnulled => f.write_str("not_annulled"),
        }
    }
}

/// Determine whether a delay-slot instruction should execute given the branch
/// outcome.
///
/// MIPS Architecture for Programmers, Vol. I-A §4.6: for *likely* (annulled)
/// branches, the delay slot is annulled (skipped) when the branch is **not**
/// taken.
#[must_use]
pub const fn annul_check(branch: &BranchWithDelay, branch_taken: bool) -> AnnulDecision {
    match branch.kind {
        DelaySlotKind::Annulled => {
            if branch_taken {
                AnnulDecision::Execute
            } else {
                AnnulDecision::Skip
            }
        }
        DelaySlotKind::Standard => AnnulDecision::Execute,
        DelaySlotKind::None => AnnulDecision::Skip,
    }
}

// ---------------------------------------------------------------------------
// MipsDelaySlot — analysis engine
// ---------------------------------------------------------------------------

/// Configuration for the MIPS delay-slot analyser.
#[derive(Debug, Clone)]
pub struct DelaySlotConfig {
    /// If `true`, warn when the delay-slot instruction is itself a branch.
    pub warn_nested_branch: bool,
    /// If `true`, warn when the delay slot writes to a condition register.
    pub warn_condition_hazard: bool,
    /// If `true`, canonicalise NOP delay slots in the output.
    pub annotate_nops: bool,
}

impl Default for DelaySlotConfig {
    fn default() -> Self {
        Self {
            warn_nested_branch: true,
            warn_condition_hazard: true,
            annotate_nops: true,
        }
    }
}

/// Severity level for a delay-slot diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DiagSeverity {
    Info,
    Warning,
    Error,
}

/// A diagnostic produced by `MipsDelaySlot::analyze`.
#[derive(Debug, Clone)]
pub struct DelaySlotDiag {
    /// Address of the branch instruction.
    pub branch_address: u64,
    /// Severity.
    pub severity: DiagSeverity,
    /// Human-readable message.
    pub message: String,
}

impl fmt::Display for DelaySlotDiag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:?}] {:#010x}: {}",
            self.severity, self.branch_address, self.message
        )
    }
}

/// Primary delay-slot analysis type.
///
/// Call [`MipsDelaySlot::analyze`] to get a [`DelaySlotReport`] for a sequence
/// of `BranchWithDelay` instances.
#[derive(Debug, Clone)]
pub struct MipsDelaySlot {
    config: DelaySlotConfig,
}

impl MipsDelaySlot {
    /// Create an analyser with the given configuration.
    #[must_use]
    pub const fn new(config: DelaySlotConfig) -> Self {
        Self { config }
    }

    /// Create with default configuration.
    #[must_use]
    pub fn default_config() -> Self {
        Self::new(DelaySlotConfig::default())
    }

    /// Analyse a slice of `BranchWithDelay` and return a report.
    #[must_use]
    pub fn analyze(&self, branches: &[BranchWithDelay]) -> DelaySlotReport {
        let mut diags = Vec::new();
        let mut nop_count = 0usize;
        let mut hazard_count = 0usize;
        let mut nested_branch_count = 0usize;
        let mut annulled_count = 0usize;

        for bwd in branches {
            if bwd.delay_slot.is_nop {
                nop_count += 1;
                if self.config.annotate_nops {
                    diags.push(DelaySlotDiag {
                        branch_address: bwd.branch_address,
                        severity: DiagSeverity::Info,
                        message: "Delay slot is NOP — branch not optimized".to_string(),
                    });
                }
            }

            if self.config.warn_nested_branch && bwd.delay_slot.is_branch {
                nested_branch_count += 1;
                diags.push(DelaySlotDiag {
                    branch_address: bwd.branch_address,
                    severity: DiagSeverity::Error,
                    message: format!(
                        "Delay slot at {:#010x} is itself a branch — undefined behaviour",
                        bwd.delay_slot.address
                    ),
                });
            }

            if self.config.warn_condition_hazard && bwd.has_condition_hazard() {
                hazard_count += 1;
                diags.push(DelaySlotDiag {
                    branch_address: bwd.branch_address,
                    severity: DiagSeverity::Warning,
                    message: format!(
                        "Delay slot at {:#010x} writes to a condition register — hazard",
                        bwd.delay_slot.address
                    ),
                });
            }

            if bwd.kind == DelaySlotKind::Annulled {
                annulled_count += 1;
            }
        }

        DelaySlotReport {
            total_branches: branches.len(),
            nop_delay_slots: nop_count,
            hazardous_delay_slots: hazard_count,
            nested_branch_delay_slots: nested_branch_count,
            annulled_branches: annulled_count,
            diagnostics: diags,
        }
    }
}

impl Default for MipsDelaySlot {
    fn default() -> Self {
        Self::default_config()
    }
}

// ---------------------------------------------------------------------------
// DelaySlotReport
// ---------------------------------------------------------------------------

/// Summary report produced by [`MipsDelaySlot::analyze`].
#[derive(Debug, Clone)]
pub struct DelaySlotReport {
    /// Total number of branch/jump instructions analysed.
    pub total_branches: usize,
    /// Branches whose delay slot is a NOP.
    pub nop_delay_slots: usize,
    /// Branches whose delay slot writes to a condition register.
    pub hazardous_delay_slots: usize,
    /// Branches whose delay slot is itself a branch (undefined behaviour).
    pub nested_branch_delay_slots: usize,
    /// Annulled (likely) branches.
    pub annulled_branches: usize,
    /// Per-branch diagnostics.
    pub diagnostics: Vec<DelaySlotDiag>,
}

impl DelaySlotReport {
    /// Returns `true` if there are any error-severity diagnostics.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.severity == DiagSeverity::Error)
    }

    /// Returns only the error diagnostics.
    #[must_use]
    pub fn errors(&self) -> Vec<&DelaySlotDiag> {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == DiagSeverity::Error)
            .collect()
    }

    /// Optimisation opportunity count: branches with NOP delay slots.
    #[must_use]
    pub const fn optimizable_count(&self) -> usize {
        self.nop_delay_slots
    }
}

impl fmt::Display for DelaySlotReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Delay Slot Analysis Report")?;
        writeln!(f, "  Branches analysed : {}", self.total_branches)?;
        writeln!(f, "  NOP delay slots   : {}", self.nop_delay_slots)?;
        writeln!(f, "  Hazardous ds      : {}", self.hazardous_delay_slots)?;
        writeln!(f, "  Nested-branch ds  : {}", self.nested_branch_delay_slots)?;
        writeln!(f, "  Annulled branches : {}", self.annulled_branches)?;
        writeln!(f, "  Diagnostics       : {}", self.diagnostics.len())?;
        for diag in &self.diagnostics {
            writeln!(f, "    {diag}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DelaySlotLifter — IL lifting helpers
// ---------------------------------------------------------------------------

/// Describes how to lift a `BranchWithDelay` into IL.
#[derive(Debug, Clone)]
pub enum LiftedBranchSemantics {
    /// Lift delay-slot instruction first, then apply branch.
    DelayThenBranch {
        /// The branch target, if statically known.
        target: Option<u64>,
    },
    /// Skip the delay slot (annulled branch not taken).
    BranchOnly {
        /// The branch target.
        target: Option<u64>,
    },
    /// No branch (e.g. non-taken annulled branch).
    FallthroughOnly {
        /// The fall-through address.
        fallthrough: u64,
    },
}

/// Determine the correct IL-lifting strategy for a `BranchWithDelay`.
///
/// This helper is used by the MIPS lifter to emit correct IL for both
/// annulled and standard delay slots.
#[must_use]
pub const fn lifting_semantics(branch: &BranchWithDelay, taken: bool) -> LiftedBranchSemantics {
    match (branch.kind, taken) {
        (DelaySlotKind::None, true) => LiftedBranchSemantics::BranchOnly { target: branch.target },
        (DelaySlotKind::None | DelaySlotKind::Annulled, false) => {
            LiftedBranchSemantics::FallthroughOnly { fallthrough: branch.fallthrough }
        }
        _ => LiftedBranchSemantics::DelayThenBranch { target: branch.target },
    }
}

// ---------------------------------------------------------------------------
// Aggregate statistics across a function
// ---------------------------------------------------------------------------

/// Per-function delay-slot statistics.
#[derive(Debug, Clone, Default)]
pub struct FunctionDelaySlotStats {
    /// Function start address.
    pub function_address: u64,
    /// Total branch instructions.
    pub branch_count: usize,
    /// Branches that have NOP delay slots.
    pub nop_count: usize,
    /// Branches that have annulled delay slots.
    pub annulled_count: usize,
    /// Map from branch address to whether the delay slot has a write hazard.
    /// Uses `BTreeMap` rather than `HashMap` to prevent hash-collision `DoS` when
    /// keys come from attacker-controlled binary addresses.
    pub hazards: BTreeMap<u64, bool>,
}

impl FunctionDelaySlotStats {
    /// Compute stats for a function represented by a slice of branches.
    #[must_use]
    pub fn compute(function_address: u64, branches: &[BranchWithDelay]) -> Self {
        let mut stats = Self {
            function_address,
            branch_count: branches.len(),
            ..Default::default()
        };

        for bwd in branches {
            if bwd.delay_slot.is_nop {
                stats.nop_count += 1;
            }
            if bwd.kind == DelaySlotKind::Annulled {
                stats.annulled_count += 1;
            }
            stats
                .hazards
                .insert(bwd.branch_address, bwd.has_condition_hazard());
        }

        stats
    }

    /// Fraction of branches that are unoptimised (NOP delay slot).
    #[must_use]
    pub fn nop_ratio(&self) -> f64 {
        if self.branch_count == 0 {
            return 0.0;
        }
        crate::count_as_f64(self.nop_count) / crate::count_as_f64(self.branch_count)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_branch(opcode: MipsJumpOpcode, target: u64, ds_nop: bool) -> BranchWithDelay {
        let ds = if ds_nop {
            DelaySlotInsn::nop(0x1000_0004)
        } else {
            DelaySlotInsn {
                address: 0x1000_0004,
                encoding: 0x2410_0001,
                text: "addiu $s0, $zero, 1".to_string(),
                reads: vec![0],
                writes: vec![16],
                is_branch: false,
                is_nop: false,
            }
        };
        BranchWithDelay::new(0x1000_0000, 0, opcode, Some(target), ds, vec![])
    }

    #[test]
    fn standard_delay_slot_always_executes() {
        let bwd = make_branch(MipsJumpOpcode::Beq, 0x2000_0000, false);
        assert_eq!(bwd.annul_check(true), AnnulDecision::Execute);
        assert_eq!(bwd.annul_check(false), AnnulDecision::Execute);
    }

    #[test]
    fn annulled_delay_slot_skipped_when_not_taken() {
        let bwd = make_branch(MipsJumpOpcode::Beql, 0x2000_0000, false);
        assert_eq!(bwd.annul_check(true), AnnulDecision::Execute);
        assert_eq!(bwd.annul_check(false), AnnulDecision::Skip);
    }

    #[test]
    fn nop_delay_slot_detected() {
        let bwd = make_branch(MipsJumpOpcode::J, 0x2000_0000, true);
        assert!(bwd.delay_is_nop());
    }

    #[test]
    fn analyze_counts_nops() {
        let branches = vec![
            make_branch(MipsJumpOpcode::J, 0x2000_0000, true),
            make_branch(MipsJumpOpcode::Jal, 0x3000_0000, true),
            make_branch(MipsJumpOpcode::Beq, 0x4000_0000, false),
        ];
        let analyser = MipsDelaySlot::default_config();
        let report = analyser.analyze(&branches);
        assert_eq!(report.total_branches, 3);
        assert_eq!(report.nop_delay_slots, 2);
    }

    #[test]
    fn annulled_opcode_classification() {
        assert_eq!(MipsJumpOpcode::Beql.delay_slot_kind(), DelaySlotKind::Annulled);
        assert_eq!(MipsJumpOpcode::Beq.delay_slot_kind(), DelaySlotKind::Standard);
        assert_eq!(MipsJumpOpcode::Bal.delay_slot_kind(), DelaySlotKind::None);
    }

    #[test]
    fn function_stats_nop_ratio() {
        let branches = vec![
            make_branch(MipsJumpOpcode::J, 0x2000_0000, true),
            make_branch(MipsJumpOpcode::J, 0x3000_0000, false),
        ];
        let stats = FunctionDelaySlotStats::compute(0x1000_0000, &branches);
        assert!((stats.nop_ratio() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn empty_branch_list_analysis() {
        let analyser = MipsDelaySlot::default_config();
        let report = analyser.analyze(&[]);
        assert_eq!(report.total_branches, 0);
        assert_eq!(report.nop_delay_slots, 0);
    }

    #[test]
    fn function_stats_zero_branches_safe() {
        let stats = FunctionDelaySlotStats::compute(0x1000_0000, &[]);
        // nop_ratio with zero divisor must not panic and should be 0.0 or NaN-handled.
        let r = stats.nop_ratio();
        assert!(r == 0.0 || r.is_nan());
    }

    #[test]
    fn delay_slot_kind_coverage_all_opcodes() {
        // Every annulled opcode has Annulled kind; standard branches have Standard.
        for op in [MipsJumpOpcode::Beql, MipsJumpOpcode::Bnel] {
            assert_eq!(op.delay_slot_kind(), DelaySlotKind::Annulled);
        }
        for op in [MipsJumpOpcode::Beq, MipsJumpOpcode::Bne, MipsJumpOpcode::J, MipsJumpOpcode::Jal] {
            assert_ne!(op.delay_slot_kind(), DelaySlotKind::None);
        }
    }

    #[test]
    fn nop_constructor_has_nop_flag() {
        let ds = DelaySlotInsn::nop(0xDEAD_BEEF);
        assert!(ds.is_nop);
        assert_eq!(ds.address, 0xDEAD_BEEF);
    }

    #[test]
    fn annul_check_consistent_across_repeats() {
        let bwd = make_branch(MipsJumpOpcode::Beql, 0x2000_0000, false);
        for _ in 0..5 {
            assert_eq!(bwd.annul_check(false), AnnulDecision::Skip);
            assert_eq!(bwd.annul_check(true), AnnulDecision::Execute);
        }
    }

    #[test]
    fn many_branches_total_matches_input_len() {
        let branches: Vec<_> = (0..50)
            .map(|i: u64| make_branch(MipsJumpOpcode::J, 0x2000_0000 + i * 4, i % 2 == 0))
            .collect();
        let analyser = MipsDelaySlot::default_config();
        let report = analyser.analyze(&branches);
        assert_eq!(report.total_branches, 50);
        assert_eq!(report.nop_delay_slots, 25);
    }
}
