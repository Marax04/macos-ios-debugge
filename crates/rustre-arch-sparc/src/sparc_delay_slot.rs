//! `sparc_delay_slot` — SPARC branch delay-slot analysis.
//!
//! Every SPARC branch instruction has a mandatory delay slot: the instruction
//! immediately following the branch is always executed before control is
//! transferred.  If the `a` (annul) bit is set, the delay-slot instruction is
//! instead *squashed* when the branch is not taken.  This module provides types
//! and utilities for analysing delay-slot semantics in SPARC disassembly.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// AnnulBit
// ─────────────────────────────────────────────────────────────────────────────

/// Whether the annul bit (`a`) is set on a SPARC branch instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnnulBit {
    /// Delay slot always executes (normal branches).
    NotSet,
    /// Delay slot is squashed when the branch is *not* taken.
    Set,
}

impl AnnulBit {
    /// Decode from the `a` bit of a SPARC instruction word.
    #[must_use]
    pub const fn from_word(word: u32) -> Self {
        // In format-2 (op=00) branches the annul bit is bit 29.
        if (word >> 29) & 1 == 1 { Self::Set } else { Self::NotSet }
    }

    /// Returns `true` if the annul bit is set.
    #[must_use]
    pub fn is_set(self) -> bool {
        self == Self::Set
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BranchCondition
// ─────────────────────────────────────────────────────────────────────────────

/// SPARC branch condition code (icc/fcc).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BranchCondition {
    Never,
    Equal,
    LessOrEqual,
    Less,
    LessOrEqualUnsigned,
    CarrySet,
    Negative,
    OverflowSet,
    Always,
    NotEqual,
    Greater,
    GreaterOrEqual,
    GreaterUnsigned,
    CarryClear,
    PositiveOrZero,
    OverflowClear,
}

impl BranchCondition {
    /// Decode from bits [28:25] (cond field) of a format-2 SPARC branch.
    #[must_use]
    pub const fn from_cond_bits(bits: u8) -> Self {
        match bits & 0xF {
            0b0000 => Self::Never,
            0b0001 => Self::Equal,
            0b0010 => Self::LessOrEqual,
            0b0011 => Self::Less,
            0b0100 => Self::LessOrEqualUnsigned,
            0b0101 => Self::CarrySet,
            0b0110 => Self::Negative,
            0b0111 => Self::OverflowSet,
            0b1000 => Self::Always,
            0b1001 => Self::NotEqual,
            0b1010 => Self::Greater,
            0b1011 => Self::GreaterOrEqual,
            0b1100 => Self::GreaterUnsigned,
            0b1101 => Self::CarryClear,
            0b1110 => Self::PositiveOrZero,
            _      => Self::OverflowClear,
        }
    }

    /// Return the mnemonic suffix (e.g. `"ne"`, `"ge"`, `"a"`).
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Never => "n",
            Self::Equal => "e",
            Self::LessOrEqual => "le",
            Self::Less => "l",
            Self::LessOrEqualUnsigned => "leu",
            Self::CarrySet => "cs",
            Self::Negative => "neg",
            Self::OverflowSet => "vs",
            Self::Always => "a",
            Self::NotEqual => "ne",
            Self::Greater => "g",
            Self::GreaterOrEqual => "ge",
            Self::GreaterUnsigned => "gu",
            Self::CarryClear => "cc",
            Self::PositiveOrZero => "pos",
            Self::OverflowClear => "vc",
        }
    }

    /// Returns `true` if the condition is unconditional (`Always`) or `Never`.
    #[must_use]
    pub const fn is_unconditional(self) -> bool {
        matches!(self, Self::Always | Self::Never)
    }

    /// Returns the logical negation.
    #[must_use]
    pub const fn negate(self) -> Self {
        match self {
            Self::Equal => Self::NotEqual,
            Self::NotEqual => Self::Equal,
            Self::Less => Self::GreaterOrEqual,
            Self::GreaterOrEqual => Self::Less,
            Self::LessOrEqual => Self::Greater,
            Self::Greater => Self::LessOrEqual,
            Self::Always => Self::Never,
            Self::Never => Self::Always,
            Self::CarrySet => Self::CarryClear,
            Self::CarryClear => Self::CarrySet,
            Self::Negative => Self::PositiveOrZero,
            Self::PositiveOrZero => Self::Negative,
            Self::OverflowSet => Self::OverflowClear,
            Self::OverflowClear => Self::OverflowSet,
            Self::LessOrEqualUnsigned => Self::GreaterUnsigned,
            Self::GreaterUnsigned => Self::LessOrEqualUnsigned,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BranchKind
// ─────────────────────────────────────────────────────────────────────────────

/// The type of SPARC branch/control-flow instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BranchKind {
    /// Integer condition-code branch (`Bicc`).
    IntCondBranch,
    /// Floating-point condition-code branch (`FBfcc`).
    FpCondBranch,
    /// Co-processor condition-code branch (`CBccc`).
    CpCondBranch,
    /// Call and link (`CALL`).
    Call,
    /// Jump and link (`JMPL`).
    Jmpl,
    /// Return from trap (`RETT`).
    Rett,
}

// ─────────────────────────────────────────────────────────────────────────────
// DelayEffect — what happens to the delay-slot instruction
// ─────────────────────────────────────────────────────────────────────────────

/// Describes the effect of the delay slot under branch taken/not-taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DelayEffect {
    /// Delay slot always executes (annul=0).
    AlwaysExecutes,
    /// Delay slot executes only when branch *is* taken (annul=1, taken path).
    ExecutesIfTaken,
    /// Delay slot is squashed when branch is not taken (annul=1, not-taken path).
    SquashedIfNotTaken,
    /// Delay slot is always squashed (JMPL, CALL — no annul concept).
    AlwaysExecutesNoAnnul,
}

impl DelayEffect {
    /// Compute the effect for a given annul bit and whether the branch is taken.
    #[must_use]
    pub const fn evaluate(annul: AnnulBit, taken: bool) -> bool {
        match annul {
            AnnulBit::NotSet => true,          // always executes
            AnnulBit::Set => taken,            // squashed if not taken
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SparcDelaySlot — the primary analysis structure
// ─────────────────────────────────────────────────────────────────────────────

/// Full description of a SPARC branch and its delay slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparcDelaySlot {
    /// PC of the branch instruction.
    pub branch_pc: u32,
    /// PC of the delay-slot instruction (always `branch_pc + 4`).
    pub delay_pc: u32,
    /// PC of the branch target (relative + `branch_pc`, computed).
    pub target_pc: u32,
    /// The branch kind.
    pub kind: BranchKind,
    /// Condition code tested (for conditional branches).
    pub condition: BranchCondition,
    /// Annul bit.
    pub annul: AnnulBit,
    /// Delay-slot instruction word.
    pub delay_word: u32,
    /// Decoded name of the delay-slot instruction (heuristic).
    pub delay_instr_name: String,
    /// Whether the delay slot is a `NOP` (no-operation, `sethi %g0, 0`).
    pub delay_is_nop: bool,
    /// Whether the delay slot writes a register that is also read by the branch.
    pub delay_has_hazard: bool,
    /// Human-readable disassembly of the branch instruction.
    pub branch_text: String,
}

impl SparcDelaySlot {
    /// Return the delay effect for this branch.
    #[must_use]
    pub fn effect(&self) -> DelayEffect {
        match self.kind {
            BranchKind::Call | BranchKind::Jmpl | BranchKind::Rett => {
                DelayEffect::AlwaysExecutesNoAnnul
            }
            _ => {
                if self.annul.is_set() {
                    DelayEffect::SquashedIfNotTaken
                } else {
                    DelayEffect::AlwaysExecutes
                }
            }
        }
    }

    /// Whether the delay slot is useful (not NOP, actually does work).
    #[must_use]
    pub const fn is_useful_delay(&self) -> bool {
        !self.delay_is_nop
    }

    /// Produce a single-line textual description.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{:#010x}: {:<20} [delay_slot={:#010x}: {}{}]",
            self.branch_pc,
            self.branch_text,
            self.delay_pc,
            self.delay_instr_name,
            if self.delay_is_nop { " (NOP)" } else { "" },
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// analyze_branch — decode a branch instruction word
// ─────────────────────────────────────────────────────────────────────────────

/// Analyse a SPARC branch instruction word and its delay-slot word.
///
/// # Arguments
/// * `pc` – Address of the branch instruction.
/// * `branch_word` – The 32-bit instruction word at `pc`.
/// * `delay_word` – The 32-bit instruction word at `pc + 4`.
///
/// # Returns
/// `Some(SparcDelaySlot)` if `branch_word` is a recognised branch,
/// `None` otherwise.
#[must_use]
pub fn analyze_branch(pc: u32, branch_word: u32, delay_word: u32) -> Option<SparcDelaySlot> {
    let op = (branch_word >> 30) & 0x3;
    let op2 = (branch_word >> 22) & 0x7;

    let kind = match (op, op2) {
        (0b00, 0b010) => BranchKind::IntCondBranch,  // Bicc
        (0b00, 0b110) => BranchKind::FpCondBranch,   // FBfcc
        (0b00, 0b111) => BranchKind::CpCondBranch,   // CBccc
        (0b01, _)     => BranchKind::Call,
        _ => return None,
    };

    let annul = AnnulBit::from_word(branch_word);
    let cond_bits = ((branch_word >> 25) & 0xF) as u8;
    let condition = BranchCondition::from_cond_bits(cond_bits);

    // Sign-extend the 22-bit displacement (in words) for Bicc/FBfcc
    let disp22 = branch_word & 0x003F_FFFF;
    let disp_signed = if disp22 & 0x0020_0000 != 0 {
        (disp22 | 0xFFC0_0000).cast_signed()
    } else {
        (disp22).cast_signed()
    };

    let target_pc = match kind {
        BranchKind::Call => {
            // 30-bit displacement
            let d30 = (branch_word & 0x3FFF_FFFF).cast_signed();
            let d30s = if d30 & 0x2000_0000 != 0 { d30 | -0x4000_0000i32 } else { d30 };
            pc.wrapping_add((d30s * 4).cast_unsigned())
        }
        _ => pc.wrapping_add((disp_signed * 4).cast_unsigned()),
    };

    let delay_is_nop = is_nop(delay_word);
    let delay_instr_name = heuristic_instr_name(delay_word).to_owned();
    let delay_has_hazard = false; // full hazard detection would require full decode

    let cond_str = match kind {
        BranchKind::Call => String::new(),
        _ => condition.mnemonic().to_owned(),
    };
    let annul_str = if annul.is_set() { ",a" } else { "" };
    let branch_text = match kind {
        BranchKind::Call => format!("call {target_pc:#010x}"),
        BranchKind::IntCondBranch => format!("b{cond_str}{annul_str} {target_pc:#010x}"),
        BranchKind::FpCondBranch  => format!("fb{cond_str}{annul_str} {target_pc:#010x}"),
        BranchKind::CpCondBranch  => format!("cb{cond_str}{annul_str} {target_pc:#010x}"),
        BranchKind::Jmpl | BranchKind::Rett => format!("jmpl/rett {target_pc:#010x}"),
    };

    Some(SparcDelaySlot {
        branch_pc: pc,
        delay_pc: pc + 4,
        target_pc,
        kind,
        condition,
        annul,
        delay_word,
        delay_instr_name,
        delay_is_nop,
        delay_has_hazard,
        branch_text,
    })
}

/// Returns `true` if the word is a SPARC NOP (`sethi %g0, 0` = `0x01000000`).
#[must_use]
pub const fn is_nop(word: u32) -> bool {
    word == 0x0100_0000
}

const fn heuristic_instr_name(word: u32) -> &'static str {
    if is_nop(word) { return "nop"; }
    let op = (word >> 30) & 3;
    let op3 = (word >> 19) & 0x3F;
    match op {
        0b00 => match (word >> 22) & 7 {
            0b100 => "sethi",
            _ => "br/ba",
        },
        0b01 => "call",
        0b10 => match op3 {
            0x00 => "add",  0x01 => "and",  0x02 => "or",   0x03 => "xor",
            0x04 => "sub",  0x05 => "andn", 0x06 => "orn",  0x07 => "xnor",
            0x08 => "addx", 0x0C => "subx", 0x10 => "addcc",0x14 => "subcc",
            0x20 => "taddcc",0x24 => "tsubcc",
            0x38 => "jmpl", 0x39 => "rett", 0x3A => "ticc",
            0x3C => "save", 0x3D => "restore",
            0x11 => "andcc",0x12 => "orcc", 0x13 => "xorcc",
            0x28 => "rd",   0x30 => "wr",
            0x15 => "andncc",0x16 => "orncc",0x17 => "xnorcc",
            _ => "alu",
        },
        _ => match op3 {
            0x00 => "ld",   0x01 => "ldub", 0x02 => "lduh",
            0x03 => "ldd",  0x04 => "st",   0x05 => "stb",
            0x06 => "sth",  0x07 => "std",
            0x09 => "ldsb", 0x0A => "ldsh",
            0x13 => "lddc",
            _ => "mem",
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DelaySlotScanner — scan a binary for all branches and their delay slots
// ─────────────────────────────────────────────────────────────────────────────

/// Scans a buffer of SPARC instruction words for all branch/delay-slot pairs.
#[derive(Debug, Clone, Default)]
pub struct DelaySlotScanner {
    /// If true, report branches whose delay slots are NOPs.
    pub report_nop_delays: bool,
    /// If true, report branches with annul bit set.
    pub report_annulled: bool,
}

impl DelaySlotScanner {
    /// Create a new scanner with all reporting enabled.
    #[must_use]
    pub const fn new() -> Self {
        Self { report_nop_delays: true, report_annulled: true }
    }

    /// Scan a slice of bytes (little-endian SPARC words) starting at `base_pc`.
    #[must_use]
    pub fn scan(&self, data: &[u8], base_pc: u32) -> Vec<SparcDelaySlot> {
        let mut out = Vec::new();
        let n = data.len() / 4;
        for i in 0..n {
            if i + 1 >= n { break; }
            let off = i * 4;
            let bw = u32::from_be_bytes([data[off], data[off+1], data[off+2], data[off+3]]);
            let dw = u32::from_be_bytes([data[off+4], data[off+5], data[off+6], data[off+7]]);
            let pc = base_pc + crate::sparc_narrow::low_u32_of_usize(off);
            if let Some(ds) = analyze_branch(pc, bw, dw) {
                if !self.report_nop_delays && ds.delay_is_nop { continue; }
                if !self.report_annulled && ds.annul.is_set() { continue; }
                out.push(ds);
            }
        }
        out
    }

    /// Return only branches with NOP delay slots (optimisation candidates).
    #[must_use]
    pub fn nop_delay_branches(&self, data: &[u8], base_pc: u32) -> Vec<SparcDelaySlot> {
        self.scan(data, base_pc)
            .into_iter()
            .filter(|ds| ds.delay_is_nop)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a format-2 branch word: op=00, cond, annul, op2=010 (Bicc), disp22.
    fn make_bicc(cond: u8, annul: bool, disp22: i32) -> u32 {
        let a: u32 = u32::from(annul);
        let d = (disp22).cast_unsigned() & 0x003F_FFFF;
        (a << 29) | (u32::from(cond) << 25) | (0b010 << 22) | d
    }

    #[test]
    fn test_analyze_branch_ba() {
        let word = make_bicc(0b1000, false, 10); // BA, disp=10
        let ds = analyze_branch(0x1000, word, 0x0100_0000 /* NOP */).unwrap();
        assert_eq!(ds.condition, BranchCondition::Always);
        assert_eq!(ds.annul, AnnulBit::NotSet);
        assert_eq!(ds.target_pc, 0x1000u32.wrapping_add(10 * 4));
        assert!(ds.delay_is_nop);
    }

    #[test]
    fn test_analyze_branch_annul() {
        let word = make_bicc(0b0001, true, 5); // BE,a
        let ds = analyze_branch(0x2000, word, 0x0100_0000).unwrap();
        assert_eq!(ds.annul, AnnulBit::Set);
        assert_eq!(ds.condition, BranchCondition::Equal);
    }

    #[test]
    fn test_analyze_non_branch_returns_none() {
        // ADD %g0, %g0, %g0: op=10, op3=0
        let word: u32 = 0b10 << 30;
        assert!(analyze_branch(0, word, 0).is_none());
    }

    #[test]
    fn test_is_nop() {
        assert!(is_nop(0x0100_0000));
        assert!(!is_nop(0x0200_0000));
    }

    #[test]
    fn test_annul_from_word_set() {
        let word: u32 = 1 << 29;
        assert_eq!(AnnulBit::from_word(word), AnnulBit::Set);
    }

    #[test]
    fn test_annul_from_word_clear() {
        assert_eq!(AnnulBit::from_word(0), AnnulBit::NotSet);
    }

    #[test]
    fn test_condition_mnemonic() {
        assert_eq!(BranchCondition::Equal.mnemonic(), "e");
        assert_eq!(BranchCondition::NotEqual.mnemonic(), "ne");
        assert_eq!(BranchCondition::Always.mnemonic(), "a");
        assert_eq!(BranchCondition::Never.mnemonic(), "n");
    }

    #[test]
    fn test_condition_negate() {
        assert_eq!(BranchCondition::Equal.negate(), BranchCondition::NotEqual);
        assert_eq!(BranchCondition::Always.negate(), BranchCondition::Never);
        assert_eq!(BranchCondition::Less.negate(), BranchCondition::GreaterOrEqual);
    }

    #[test]
    fn test_condition_from_bits() {
        assert_eq!(BranchCondition::from_cond_bits(0b0001), BranchCondition::Equal);
        assert_eq!(BranchCondition::from_cond_bits(0b1000), BranchCondition::Always);
        assert_eq!(BranchCondition::from_cond_bits(0b0000), BranchCondition::Never);
    }

    #[test]
    fn test_delay_effect_no_annul() {
        let ds = SparcDelaySlot {
            branch_pc: 0, delay_pc: 4, target_pc: 0x100,
            kind: BranchKind::IntCondBranch,
            condition: BranchCondition::Equal,
            annul: AnnulBit::NotSet,
            delay_word: 0x0100_0000,
            delay_instr_name: "nop".into(),
            delay_is_nop: true,
            delay_has_hazard: false,
            branch_text: "be 0x00000100".into(),
        };
        assert_eq!(ds.effect(), DelayEffect::AlwaysExecutes);
    }

    #[test]
    fn test_delay_effect_annulled() {
        let ds = SparcDelaySlot {
            branch_pc: 0, delay_pc: 4, target_pc: 0x100,
            kind: BranchKind::IntCondBranch,
            condition: BranchCondition::Equal,
            annul: AnnulBit::Set,
            delay_word: 0, delay_instr_name: "add".into(),
            delay_is_nop: false, delay_has_hazard: false,
            branch_text: "be,a 0x00000100".into(),
        };
        assert_eq!(ds.effect(), DelayEffect::SquashedIfNotTaken);
    }

    #[test]
    fn test_delay_effect_evaluate_not_annulled() {
        assert!(DelayEffect::evaluate(AnnulBit::NotSet, false));
        assert!(DelayEffect::evaluate(AnnulBit::NotSet, true));
    }

    #[test]
    fn test_delay_effect_evaluate_annulled() {
        assert!(DelayEffect::evaluate(AnnulBit::Set, true));
        assert!(!DelayEffect::evaluate(AnnulBit::Set, false));
    }

    #[test]
    fn test_scanner_scan_empty() {
        let scanner = DelaySlotScanner::new();
        let result = scanner.scan(&[], 0x1000);
        assert!(result.is_empty());
    }

    #[test]
    fn test_scanner_scan_nop_pair() {
        // two NOPs — neither is a branch
        let data: Vec<u8> = (0..8).flat_map(|_| 0x0100_0000u32.to_be_bytes()).collect();
        let scanner = DelaySlotScanner::new();
        let result = scanner.scan(&data, 0);
        assert!(result.is_empty());
    }

    #[test]
    fn test_summary_output() {
        let word = make_bicc(0b1000, false, 10);
        let ds = analyze_branch(0x1000, word, 0x0100_0000).unwrap();
        let s = ds.summary();
        assert!(s.contains("0x00001000"));
        assert!(s.contains("nop"));
    }

    #[test]
    fn test_is_unconditional() {
        assert!(BranchCondition::Always.is_unconditional());
        assert!(BranchCondition::Never.is_unconditional());
        assert!(!BranchCondition::Equal.is_unconditional());
    }

    #[test]
    fn test_negative_disp() {
        // Negative displacement: disp22 = -1 (all ones in 22 bits)
        let word = make_bicc(0b1000, false, 0x3F_FFFFi32);
        let ds = analyze_branch(0x1000, word, 0x0100_0000).unwrap();
        // target = 0x1000 + (-1 * 4) = 0xFFC
        assert_eq!(ds.target_pc, 0x0FFC);
    }
}
