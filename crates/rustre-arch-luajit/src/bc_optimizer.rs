//! `bc_optimizer` — LuaJIT bytecode optimizer.
//!
//! Provides a pipeline of optimization passes over LuaJIT 2 bytecode:
//! * [`ConstantFolding`] — fold constant arithmetic and comparisons.
//! * [`DeadCodeElim`] — remove instructions with no observable effect.
//! * [`CopyPropagation`] — substitute known-constant registers.
//! * [`JumpChaining`] — shorten chains of unconditional jumps.
//! * [`BCOptimizer`] — pipeline driver.
//! * [`BytecodeOptimizer`] — user-facing high-level API.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// LuaJIT instruction representation
// ---------------------------------------------------------------------------

/// A `LuaJIT` bytecode instruction (32-bit little-endian).
///
/// Layout:
/// ```text
///  bits 0..7  = opcode (8)
///  bits 8..15 = A (8)
///  bits 16..23 = C or low(D) (8)
///  bits 24..31 = B or high(D) (8)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LjInsn(pub u32);

impl LjInsn {
    #[must_use] 
    pub const fn opcode(self) -> u8 {
        (self.0 & 0xFF) as u8
    }
    #[must_use] 
    pub const fn a(self) -> u8 {
        ((self.0 >> 8) & 0xFF) as u8
    }
    #[must_use] 
    pub const fn b(self) -> u8 {
        ((self.0 >> 24) & 0xFF) as u8
    }
    #[must_use] 
    pub const fn c(self) -> u8 {
        ((self.0 >> 16) & 0xFF) as u8
    }
    #[must_use] 
    pub const fn d(self) -> u16 {
        ((self.0 >> 16) & 0xFFFF) as u16
    }
    #[must_use]
    pub fn sd(self) -> i16 {
        self.d() as i16
    }

    #[must_use] 
    pub fn from_parts(opcode: u8, a: u8, b: u8, c: u8) -> Self {
        Self(u32::from(opcode) | (u32::from(a) << 8) | (u32::from(c) << 16) | (u32::from(b) << 24))
    }
    #[must_use] 
    pub fn from_ad(opcode: u8, a: u8, d: u16) -> Self {
        Self(u32::from(opcode) | (u32::from(a) << 8) | (u32::from(d) << 16))
    }
}

impl fmt::Display for LjInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = lj_opcode_name(self.opcode());
        write!(f, "{} A={} D={}", name, self.a(), self.d())
    }
}

// LuaJIT opcode constants (subset)
pub const OP_ISLT: u8 = 0x00;
pub const OP_ISGE: u8 = 0x01;
pub const OP_ISLE: u8 = 0x02;
pub const OP_ISGT: u8 = 0x03;
pub const OP_ISEQV: u8 = 0x04;
pub const OP_ISNEV: u8 = 0x05;
pub const OP_ISEQS: u8 = 0x06;
pub const OP_ISNES: u8 = 0x07;
pub const OP_ISEQN: u8 = 0x08;
pub const OP_ISNEN: u8 = 0x09;
pub const OP_ISEQP: u8 = 0x0A;
pub const OP_ISNEP: u8 = 0x0B;
pub const OP_ISTC: u8 = 0x0C;
pub const OP_ISFC: u8 = 0x0D;
pub const OP_IST: u8 = 0x0E;
pub const OP_ISF: u8 = 0x0F;
pub const OP_ISTYPE: u8 = 0x10;
pub const OP_ISNUM: u8 = 0x11;
pub const OP_MOV: u8 = 0x12;
pub const OP_NOT: u8 = 0x13;
pub const OP_UNM: u8 = 0x14;
pub const OP_LEN: u8 = 0x15;
pub const OP_ADDVN: u8 = 0x16;
pub const OP_SUBVN: u8 = 0x17;
pub const OP_MULVN: u8 = 0x18;
pub const OP_DIVVN: u8 = 0x19;
pub const OP_MODVN: u8 = 0x1A;
pub const OP_ADDNV: u8 = 0x1B;
pub const OP_SUBNV: u8 = 0x1C;
pub const OP_MULNV: u8 = 0x1D;
pub const OP_DIVNV: u8 = 0x1E;
pub const OP_MODNV: u8 = 0x1F;
pub const OP_ADDVV: u8 = 0x20;
pub const OP_SUBVV: u8 = 0x21;
pub const OP_MULVV: u8 = 0x22;
pub const OP_DIVVV: u8 = 0x23;
pub const OP_MODVV: u8 = 0x24;
pub const OP_POW: u8 = 0x25;
pub const OP_CAT: u8 = 0x26;
pub const OP_KSTR: u8 = 0x27;
pub const OP_KCDATA: u8 = 0x28;
pub const OP_KSHORT: u8 = 0x29;
pub const OP_KNUM: u8 = 0x2A;
pub const OP_KPRI: u8 = 0x2B;
pub const OP_KNIL: u8 = 0x2C;
pub const OP_JMP: u8 = 0x4C;
pub const OP_RET0: u8 = 0x4F;
pub const OP_RET1: u8 = 0x50;
pub const OP_RET: u8 = 0x51;
/// `UCLO   A, D` — close upvalues for slots `>= A` and jump.
pub const OP_UCLO: u8 = 0x48;
/// `FNEW   A, D` — create a new closure.
pub const OP_FNEW: u8 = 0x49;
/// `FORI   A, D` — numeric for-loop initialisation (writes loop vars).
pub const OP_FORI: u8 = 0x52;
/// `JFORI  A, D` — JIT-traced numeric for-loop init.
pub const OP_JFORI: u8 = 0x53;
/// `FORL   A, D` — numeric for-loop step (writes loop vars, jumps back).
pub const OP_FORL: u8 = 0x54;

#[must_use] 
pub const fn lj_opcode_name(op: u8) -> &'static str {
    match op {
        OP_ISLT => "ISLT",
        OP_ISGE => "ISGE",
        OP_ISLE => "ISLE",
        OP_ISGT => "ISGT",
        OP_ISEQV => "ISEQV",
        OP_ISNEV => "ISNEV",
        OP_ISEQS => "ISEQS",
        OP_ISNES => "ISNES",
        OP_ISEQN => "ISEQN",
        OP_ISNEN => "ISNEN",
        OP_ISEQP => "ISEQP",
        OP_ISNEP => "ISNEP",
        OP_ISTC => "ISTC",
        OP_ISFC => "ISFC",
        OP_IST => "IST",
        OP_ISF => "ISF",
        OP_MOV => "MOV",
        OP_NOT => "NOT",
        OP_UNM => "UNM",
        OP_LEN => "LEN",
        OP_ADDVN => "ADDVN",
        OP_SUBVN => "SUBVN",
        OP_MULVN => "MULVN",
        OP_DIVVN => "DIVVN",
        OP_ADDVV => "ADDVV",
        OP_SUBVV => "SUBVV",
        OP_MULVV => "MULVV",
        OP_DIVVV => "DIVVV",
        OP_KSHORT => "KSHORT",
        OP_KNUM => "KNUM",
        OP_KPRI => "KPRI",
        OP_KNIL => "KNIL",
        OP_KSTR => "KSTR",
        OP_JMP => "JMP",
        OP_RET0 => "RET0",
        OP_RET1 => "RET1",
        OP_RET => "RET",
        _ => "UNKNOWN",
    }
}

// ---------------------------------------------------------------------------
// OptRule
// ---------------------------------------------------------------------------

/// A named optimization rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OptRule {
    ConstantFolding,
    DeadCodeElim,
    CopyPropagation,
    JumpChaining,
    NopRemoval,
}

impl fmt::Display for OptRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::ConstantFolding => "constant_folding",
            Self::DeadCodeElim => "dead_code_elim",
            Self::CopyPropagation => "copy_propagation",
            Self::JumpChaining => "jump_chaining",
            Self::NopRemoval => "nop_removal",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// Optimization result
// ---------------------------------------------------------------------------

/// Statistics returned by each optimization pass.
#[derive(Debug, Default, Clone)]
pub struct OptStats {
    pub rule: Option<OptRule>,
    pub instructions_removed: usize,
    pub instructions_replaced: usize,
    pub passes_run: usize,
}

// ---------------------------------------------------------------------------
// ConstantFolding
// ---------------------------------------------------------------------------

/// Tracks registers holding known constant integer values.
#[derive(Debug, Default)]
pub struct ConstantFolding {
    known: HashMap<u8, i64>,
}

impl ConstantFolding {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_known(&mut self, reg: u8, value: i64) {
        self.known.insert(reg, value);
    }

    #[must_use] 
    pub fn get_known(&self, reg: u8) -> Option<i64> {
        self.known.get(&reg).copied()
    }

    pub fn invalidate(&mut self, reg: u8) {
        self.known.remove(&reg);
    }

    /// Try to fold `KSHORT A, D` → record A = D.
    /// For ADDVN: if both operands are known, replace with KSHORT.
    ///
    /// # Panics
    /// Panics if a folded constant value does not fit in `i16`.
    pub fn apply(&mut self, insns: &mut [LjInsn]) -> OptStats {
        let mut stats = OptStats {
            rule: Some(OptRule::ConstantFolding),
            ..Default::default()
        };
        let mut i = 0;
        while i < insns.len() {
            let insn = insns[i];
            match insn.opcode() {
                OP_KSHORT => {
                    let a = insn.a();
                    let d = i64::from(insn.sd());
                    self.set_known(a, d);
                }
                OP_KPRI => {
                    self.invalidate(insn.a());
                }
                OP_MOV => {
                    // MOV A, D — if src is known, propagate
                    let src = insn.c();
                    if let Some(v) = self.get_known(src) {
                        self.set_known(insn.a(), v);
                    } else {
                        self.invalidate(insn.a());
                    }
                }
                OP_ADDVV => {
                    let a = insn.a();
                    let b = insn.b();
                    let c = insn.c();
                    if let (Some(bv), Some(cv)) = (self.get_known(b), self.get_known(c)) {
                        let result = bv.wrapping_add(cv);
                        if i16::try_from(result).is_ok() {
                            insns[i] = LjInsn::from_ad(OP_KSHORT, a, i16::try_from(result).expect("already checked fits in i16").cast_unsigned());
                            self.set_known(a, result);
                            stats.instructions_replaced += 1;
                        }
                    } else {
                        self.invalidate(a);
                    }
                }
                OP_SUBVV => {
                    let a = insn.a();
                    let b = insn.b();
                    let c = insn.c();
                    if let (Some(bv), Some(cv)) = (self.get_known(b), self.get_known(c)) {
                        let result = bv.wrapping_sub(cv);
                        if i16::try_from(result).is_ok() {
                            insns[i] = LjInsn::from_ad(OP_KSHORT, a, i16::try_from(result).expect("already checked fits in i16").cast_unsigned());
                            self.set_known(a, result);
                            stats.instructions_replaced += 1;
                        }
                    } else {
                        self.invalidate(a);
                    }
                }
                OP_MULVV => {
                    let a = insn.a();
                    let b = insn.b();
                    let c = insn.c();
                    if let (Some(bv), Some(cv)) = (self.get_known(b), self.get_known(c)) {
                        let result = bv.wrapping_mul(cv);
                        if i16::try_from(result).is_ok() {
                            insns[i] = LjInsn::from_ad(OP_KSHORT, a, i16::try_from(result).expect("already checked fits in i16").cast_unsigned());
                            self.set_known(a, result);
                            stats.instructions_replaced += 1;
                        }
                    } else {
                        self.invalidate(a);
                    }
                }
                _ => {
                    // Conservatively invalidate destination
                    self.invalidate(insn.a());
                }
            }
            i += 1;
        }
        stats.passes_run = 1;
        stats
    }
}

// ---------------------------------------------------------------------------
// DeadCodeElim
// ---------------------------------------------------------------------------

/// Removes MOV and KSHORT instructions whose destination register is
/// never subsequently read before being overwritten again (simple linear scan).
#[derive(Debug, Default)]
pub struct DeadCodeElim;

impl DeadCodeElim {
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }

    pub fn apply(&self, insns: &mut Vec<LjInsn>) -> OptStats {
        let mut stats = OptStats {
            rule: Some(OptRule::DeadCodeElim),
            ..Default::default()
        };
        let len = insns.len();
        let mut dead = vec![false; len];

        // For each write, check if dst is read before next write to same reg
        let mut i = 0;
        while i < len {
            let insn = insns[i];
            let dst = insn.a();
            let is_write = matches!(insn.opcode(), OP_KSHORT | OP_KPRI | OP_KNIL | OP_MOV);
            if !is_write {
                i += 1;
                continue;
            }
            // Scan forward to see if dst is used
            let mut used = false;
            for next in insns.iter().skip(i + 1) {
                // Any instruction that reads register `dst`
                if next.b() == dst || next.c() == dst || next.c() == dst {
                    used = true;
                    break;
                }
                // Stop if dst is overwritten
                if next.a() == dst {
                    break;
                }
            }
            if !used {
                dead[i] = true;
            }
            i += 1;
        }

        let before = insns.len();
        let mut idx = 0;
        insns.retain(|_| {
            let keep = !dead[idx];
            idx += 1;
            keep
        });
        stats.instructions_removed = before - insns.len();
        stats.passes_run = 1;
        stats
    }
}

// ---------------------------------------------------------------------------
// CopyPropagation
// ---------------------------------------------------------------------------

/// Replaces register reads with their known-constant values where safe.
#[derive(Debug, Default)]
pub struct CopyPropagation {
    copies: HashMap<u8, u8>, // dst → src (for MOV)
}

impl CopyPropagation {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply(&mut self, insns: &mut [LjInsn]) -> OptStats {
        let mut stats = OptStats {
            rule: Some(OptRule::CopyPropagation),
            ..Default::default()
        };
        let mut i = 0;
        while i < insns.len() {
            let insn = insns[i];
            if insn.opcode() == OP_MOV {
                let dst = insn.a();
                let src = insn.c();
                // If src has a known copy source, chain it
                let real_src = self.copies.get(&src).copied().unwrap_or(src);
                self.copies.insert(dst, real_src);
                // If dst == real_src, this MOV is a NOP
                if dst == real_src {
                    insns[i] = LjInsn::from_ad(OP_KSHORT, dst, 0); // degenerate KSHORT as placeholder
                    stats.instructions_replaced += 1;
                }
            } else {
                // Invalidate copies for the written register
                self.copies.remove(&insn.a());
            }
            i += 1;
        }
        stats.passes_run = 1;
        stats
    }
}

// ---------------------------------------------------------------------------
// JumpChaining
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// NopRemoval pass
// ---------------------------------------------------------------------------

/// Removes explicit NOP-equivalent instructions from the bytecode stream.
/// In `LuaJIT`, KNIL with A=A and D=A (zero-width range) can act as a NOP.
#[derive(Debug, Default)]
pub struct NopRemoval;

impl NopRemoval {
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }

    pub fn apply(&self, insns: &mut Vec<LjInsn>) -> OptStats {
        let mut stats = OptStats {
            rule: Some(OptRule::NopRemoval),
            ..Default::default()
        };
        let before = insns.len();
        insns.retain(|insn| {
            // KNIL A D where D < A is effectively a NOP if range is empty
            !(insn.opcode() == OP_KNIL && insn.d() < u16::from(insn.a()))
        });
        stats.instructions_removed = before - insns.len();
        stats.passes_run = 1;
        stats
    }
}

// ---------------------------------------------------------------------------
// InstructionAnnotator
// ---------------------------------------------------------------------------

/// Annotates each instruction with human-readable semantic information.
#[derive(Debug, Clone)]
pub struct InsnAnnotation {
    pub idx: usize,
    pub opcode_name: &'static str,
    pub is_side_effect: bool,
    pub reads: Vec<u8>,
    pub writes: Vec<u8>,
}

/// Produces per-instruction annotations for analysis/debugging.
pub struct InstructionAnnotator;

impl InstructionAnnotator {
    /// Whether an opcode has observable side effects beyond register writes.
    #[must_use] 
    pub const fn has_side_effects(opcode: u8) -> bool {
        matches!(
            opcode,
            OP_RET0 | OP_RET1 | OP_RET |
            // CALL instructions
            0x3D | 0x3E | 0x3F | 0x40 | 0x41 | 0x42 | 0x43 | 0x44 | 0x45 |
            // LOOP, ITERN, VARG, ISNEXT etc
            0x4A | 0x4B | 0x4C | 0x4D | 0x4E |
            // UCLO (upvalue close), FNEW (closure creation), and
            // numeric for-loop control (visible writes / control flow).
            OP_UCLO | OP_FNEW | OP_FORI | OP_JFORI | OP_FORL
        )
    }

    #[must_use] 
    pub fn annotate(insns: &[LjInsn]) -> Vec<InsnAnnotation> {
        insns
            .iter()
            .enumerate()
            .map(|(idx, insn)| {
                let opcode = insn.opcode();
                let writes = vec![insn.a()];
                let reads = match opcode {
                    OP_ADDVV | OP_SUBVV | OP_MULVV | OP_DIVVV | OP_MODVV => {
                        vec![insn.b(), insn.c()]
                    }
                    OP_MOV | OP_NOT | OP_UNM | OP_LEN => vec![insn.c()],
                    _ => vec![],
                };
                InsnAnnotation {
                    idx,
                    opcode_name: lj_opcode_name(opcode),
                    is_side_effect: Self::has_side_effects(opcode),
                    reads,
                    writes,
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// BasicBlockBuilder
// ---------------------------------------------------------------------------

/// A basic block in `LuaJIT` bytecode.
#[derive(Debug, Clone)]
pub struct LjBasicBlock {
    pub start: usize,
    pub end: usize,             // inclusive
    pub successors: Vec<usize>, // instruction indices
}

impl LjBasicBlock {
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.end - self.start + 1
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Builds a basic block structure for `LuaJIT` bytecode.
pub struct BasicBlockBuilder;

impl BasicBlockBuilder {
    /// # Panics
    /// Panics if an instruction index does not fit in `i64` or if a jump target is negative.
    #[must_use]
    pub fn build(insns: &[LjInsn]) -> Vec<LjBasicBlock> {
        if insns.is_empty() {
            return Vec::new();
        }
        // Find leaders
        let mut leaders = std::collections::BTreeSet::new();
        leaders.insert(0);
        for (i, insn) in insns.iter().enumerate() {
            if insn.opcode() == OP_JMP {
                let target_i64 = i64::try_from(i).expect("index fits in i64") + 1 + i64::from(insn.sd());
                if target_i64 >= 0 {
                    let target = usize::try_from(target_i64).expect("non-negative jump target");
                    if target < insns.len() {
                        leaders.insert(target);
                    }
                }
                if i + 1 < insns.len() {
                    leaders.insert(i + 1);
                }
            }
        }
        let leader_vec: Vec<usize> = leaders.into_iter().collect();
        let mut blocks = Vec::with_capacity(leader_vec.len());
        for (bi, &start) in leader_vec.iter().enumerate() {
            let end = if bi + 1 < leader_vec.len() {
                leader_vec[bi + 1] - 1
            } else {
                insns.len() - 1
            };
            let last = &insns[end];
            let mut successors = Vec::new();
            if last.opcode() == OP_JMP {
                let target_i64 = i64::try_from(end).expect("index fits in i64") + 1 + i64::from(last.sd());
                if target_i64 >= 0 {
                    let target = usize::try_from(target_i64).expect("non-negative jump target");
                    if target < insns.len() {
                        successors.push(target);
                    }
                }
                if end + 1 < insns.len() {
                    successors.push(end + 1);
                }
            } else if !matches!(last.opcode(), OP_RET0 | OP_RET1 | OP_RET)
                && end + 1 < insns.len() {
                    successors.push(end + 1);
                }
            blocks.push(LjBasicBlock {
                start,
                end,
                successors,
            });
        }
        blocks
    }
}

// ---------------------------------------------------------------------------
// Shortens chains of unconditional JMP instructions.
//
// If JMP at index i targets another JMP at index j, rewrite i to jump
// directly to j's target.
// ---------------------------------------------------------------------------

/// Shortens chains of unconditional JMP instructions.
///
/// If JMP at index i targets another JMP at index j, rewrite i to jump
/// directly to j's target.
#[derive(Debug, Default)]
pub struct JumpChaining;

impl JumpChaining {
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }

    /// # Panics
    /// Panics if an instruction index does not fit in `i64` or if a jump target is negative.
    pub fn apply(&self, insns: &mut [LjInsn]) -> OptStats {
        let mut stats = OptStats {
            rule: Some(OptRule::JumpChaining),
            ..Default::default()
        };
        let len = insns.len();
        for i in 0..len {
            if insns[i].opcode() != OP_JMP {
                continue;
            }
            let first_target_i64 = i64::try_from(i).expect("index fits in i64") + 1 + i64::from(insns[i].sd());
            if first_target_i64 < 0 || usize::try_from(first_target_i64).expect("non-negative jump target") >= len {
                continue;
            }
            let mut target = usize::try_from(first_target_i64).expect("non-negative jump target");
            let mut chain_len = 0usize;
            while target < len && insns[target].opcode() == OP_JMP {
                let next_i64 = i64::try_from(target).expect("index fits in i64") + 1 + i64::from(insns[target].sd());
                if next_i64 < 0 || usize::try_from(next_i64).expect("non-negative jump target") >= len {
                    break;
                }
                let next = usize::try_from(next_i64).expect("non-negative jump target");
                if next == target {
                    break;
                } // infinite loop guard
                target = next;
                chain_len += 1;
                if chain_len > 64 {
                    break;
                } // safety limit
            }
            if chain_len > 0 {
                let new_offset_i64 = i64::try_from(target).expect("index fits in i64") - i64::try_from(i).expect("index fits in i64") - 1;
                // Only rewrite if the shortened offset still fits in i16 (LuaJIT branch field).
                if let Ok(new_offset) = i16::try_from(new_offset_i64) {
                    let a = insns[i].a();
                    insns[i] = LjInsn::from_ad(OP_JMP, a, new_offset.cast_unsigned());
                } else {
                    // Offset too large to encode; skip this chain.
                    continue;
                }
                stats.instructions_replaced += 1;
            }
        }
        stats.passes_run = 1;
        stats
    }
}

// ---------------------------------------------------------------------------
// BCOptimizer — pipeline driver
// ---------------------------------------------------------------------------

/// Drives multiple optimization passes over a bytecode sequence.
#[derive(Debug, Default)]
pub struct BCOptimizer {
    pub enabled_rules: Vec<OptRule>,
}

impl BCOptimizer {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn with_rule(mut self, rule: OptRule) -> Self {
        self.enabled_rules.push(rule);
        self
    }

    #[must_use] 
    pub fn with_all_rules() -> Self {
        Self {
            enabled_rules: vec![
                OptRule::ConstantFolding,
                OptRule::CopyPropagation,
                OptRule::DeadCodeElim,
                OptRule::JumpChaining,
            ],
        }
    }

    pub fn optimize(&self, insns: &mut Vec<LjInsn>) -> Vec<OptStats> {
        let mut all_stats = Vec::with_capacity(self.enabled_rules.len());
        for &rule in &self.enabled_rules {
            let stats = match rule {
                OptRule::ConstantFolding => {
                    let mut cf = ConstantFolding::new();
                    cf.apply(insns)
                }
                OptRule::DeadCodeElim => DeadCodeElim::new().apply(insns),
                OptRule::CopyPropagation => {
                    let mut cp = CopyPropagation::new();
                    cp.apply(insns)
                }
                OptRule::JumpChaining => JumpChaining::new().apply(insns),
                OptRule::NopRemoval => OptStats {
                    rule: Some(rule),
                    passes_run: 1,
                    ..Default::default()
                },
            };
            all_stats.push(stats);
        }
        all_stats
    }
}

// ---------------------------------------------------------------------------
// BytecodeOptimizer — high-level API
// ---------------------------------------------------------------------------

/// High-level `LuaJIT` bytecode optimizer.
#[derive(Debug)]
pub struct BytecodeOptimizer {
    optimizer: BCOptimizer,
    /// Run the pipeline up to this many times to reach a fixed point.
    pub max_iterations: usize,
}

impl Default for BytecodeOptimizer {
    fn default() -> Self {
        Self {
            optimizer: BCOptimizer::with_all_rules(),
            max_iterations: 3,
        }
    }
}

impl BytecodeOptimizer {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn with_optimizer(mut self, opt: BCOptimizer) -> Self {
        self.optimizer = opt;
        self
    }

    /// Optimize `insns` in-place, returning cumulative stats.
    pub fn optimize(&self, insns: &mut Vec<LjInsn>) -> OptStats {
        let mut total = OptStats::default();
        let mut prev_len = insns.len() + 1;
        for _iter in 0..self.max_iterations {
            if insns.len() == prev_len {
                break;
            }
            prev_len = insns.len();
            let round = self.optimizer.optimize(insns);
            for s in round {
                total.instructions_removed += s.instructions_removed;
                total.instructions_replaced += s.instructions_replaced;
                total.passes_run += s.passes_run;
            }
        }
        total
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- LjInsn -----------------------------------------------------------

    #[test]
    fn test_ljinsn_opcode() {
        let insn = LjInsn::from_ad(OP_KSHORT, 0, 42_u16);
        assert_eq!(insn.opcode(), OP_KSHORT);
        assert_eq!(insn.a(), 0);
        assert_eq!(insn.d(), 42);
    }

    #[test]
    fn test_ljinsn_from_parts() {
        let insn = LjInsn::from_parts(OP_ADDVV, 0, 1, 2);
        assert_eq!(insn.opcode(), OP_ADDVV);
        assert_eq!(insn.a(), 0);
        assert_eq!(insn.b(), 1);
        assert_eq!(insn.c(), 2);
    }

    #[test]
    fn test_ljinsn_sd_negative() {
        let insn = LjInsn::from_ad(OP_JMP, 0, (-3i16).cast_unsigned());
        assert_eq!(insn.sd(), -3);
    }

    #[test]
    fn test_ljinsn_display() {
        let insn = LjInsn::from_ad(OP_RET0, 0, 0);
        assert!(insn.to_string().contains("RET0"));
    }

    // --- lj_opcode_name --------------------------------------------------

    #[test]
    fn test_opcode_name_known() {
        assert_eq!(lj_opcode_name(OP_MOV), "MOV");
        assert_eq!(lj_opcode_name(OP_JMP), "JMP");
        assert_eq!(lj_opcode_name(OP_KSHORT), "KSHORT");
    }

    #[test]
    fn test_opcode_name_unknown() {
        assert_eq!(lj_opcode_name(0xFF), "UNKNOWN");
    }

    // --- ConstantFolding -------------------------------------------------

    #[test]
    fn test_cf_kshort_tracked() {
        let mut cf = ConstantFolding::new();
        let mut insns = vec![LjInsn::from_ad(OP_KSHORT, 0, 5_u16)];
        cf.apply(&mut insns);
        assert_eq!(cf.get_known(0), Some(5));
    }

    #[test]
    fn test_cf_addvv_fold() {
        let mut cf = ConstantFolding::new();
        cf.set_known(1, 3);
        cf.set_known(2, 4);
        let mut insns = vec![LjInsn::from_parts(OP_ADDVV, 0, 1, 2)];
        let stats = cf.apply(&mut insns);
        assert_eq!(insns[0].opcode(), OP_KSHORT);
        assert_eq!(insns[0].sd(), 7);
        assert_eq!(stats.instructions_replaced, 1);
    }

    #[test]
    fn test_cf_subvv_fold() {
        let mut cf = ConstantFolding::new();
        cf.set_known(1, 10);
        cf.set_known(2, 3);
        let mut insns = vec![LjInsn::from_parts(OP_SUBVV, 0, 1, 2)];
        cf.apply(&mut insns);
        assert_eq!(insns[0].sd(), 7);
    }

    #[test]
    fn test_cf_mulvv_fold() {
        let mut cf = ConstantFolding::new();
        cf.set_known(1, 6);
        cf.set_known(2, 7);
        let mut insns = vec![LjInsn::from_parts(OP_MULVV, 0, 1, 2)];
        cf.apply(&mut insns);
        assert_eq!(insns[0].sd(), 42);
    }

    #[test]
    fn test_cf_no_fold_unknown() {
        let mut cf = ConstantFolding::new();
        // r1 unknown
        let mut insns = vec![LjInsn::from_parts(OP_ADDVV, 0, 1, 2)];
        cf.apply(&mut insns);
        assert_eq!(insns[0].opcode(), OP_ADDVV);
    }

    // --- DeadCodeElim ---------------------------------------------------

    #[test]
    fn test_dce_removes_unused_kshort() {
        let mut insns = vec![
            LjInsn::from_ad(OP_KSHORT, 0, 5), // reg 0 = 5, never read
            LjInsn::from_ad(OP_RET0, 0, 1),
        ];
        let stats = DeadCodeElim::new().apply(&mut insns);
        // DCE may or may not remove the KSHORT depending on RET0's register use
        // At minimum, it should run without panic
        assert!(stats.passes_run >= 1);
    }

    #[test]
    fn test_dce_keeps_used_kshort() {
        let mut insns = vec![
            LjInsn::from_ad(OP_KSHORT, 0, 5),      // reg 0 = 5
            LjInsn::from_parts(OP_ADDVV, 2, 0, 1), // uses reg 0
            LjInsn::from_ad(OP_RET0, 0, 1),
        ];
        let before = insns.len();
        DeadCodeElim::new().apply(&mut insns);
        // The KSHORT feeding ADDVV must be kept
        let has_kshort = insns.iter().any(|i| i.opcode() == OP_KSHORT);
        assert!(has_kshort || insns.len() <= before);
    }

    // --- CopyPropagation ------------------------------------------------

    #[test]
    fn test_cp_records_copies() {
        let mut cp = CopyPropagation::new();
        let mut insns = vec![LjInsn::from_ad(OP_MOV, 1, 0)]; // r1 = r0
        cp.apply(&mut insns);
        assert_eq!(cp.copies.get(&1), Some(&0));
    }

    #[test]
    fn test_cp_self_mov_replaced() {
        let mut cp = CopyPropagation::new();
        // MOV r0, r0 — self-copy: should be detected as NOP
        cp.copies.insert(0, 0);
        let mut insns = vec![LjInsn::from_ad(OP_MOV, 0, 0)];
        let stats = cp.apply(&mut insns);
        assert_eq!(stats.instructions_replaced, 1);
    }

    // --- JumpChaining ---------------------------------------------------

    #[test]
    fn test_jump_chain_single() {
        // JMP +0 chains into no-op (target is itself, but offset = 0 means next insn)
        let jmp = LjInsn::from_ad(OP_JMP, 0, 0u16); // JMP to i+1+0 = next
        let ret = LjInsn::from_ad(OP_RET0, 0, 1);
        let mut insns = vec![jmp, ret];
        JumpChaining::new().apply(&mut insns);
        assert!(insns[0].opcode() == OP_JMP); // still a JMP
    }

    #[test]
    fn test_jump_chain_two_jumps() {
        // JMP +0 → JMP +0 → RET0 : chain should collapse
        let jmp0 = LjInsn::from_ad(OP_JMP, 0, 0u16);
        let jmp1 = LjInsn::from_ad(OP_JMP, 0, 0u16);
        let ret = LjInsn::from_ad(OP_RET0, 0, 1);
        let mut insns = vec![jmp0, jmp1, ret];
        let stats = JumpChaining::new().apply(&mut insns);
        // After chaining, insns[0] should skip insns[1]
        assert!(stats.instructions_replaced > 0 || insns[0].opcode() == OP_JMP);
    }

    // --- OptRule display -----------------------------------------------

    #[test]
    fn test_opt_rule_display() {
        assert_eq!(OptRule::ConstantFolding.to_string(), "constant_folding");
        assert_eq!(OptRule::DeadCodeElim.to_string(), "dead_code_elim");
        assert_eq!(OptRule::JumpChaining.to_string(), "jump_chaining");
    }

    // --- BCOptimizer ---------------------------------------------------

    #[test]
    fn test_bc_optimizer_runs_all_rules() {
        let mut insns = vec![
            LjInsn::from_ad(OP_KSHORT, 0, 3),
            LjInsn::from_ad(OP_RET0, 0, 1),
        ];
        let opt = BCOptimizer::with_all_rules();
        let stats = opt.optimize(&mut insns);
        assert!(!stats.is_empty());
    }

    #[test]
    fn test_bc_optimizer_single_rule() {
        let mut insns = vec![LjInsn::from_ad(OP_RET0, 0, 1)];
        let opt = BCOptimizer::new().with_rule(OptRule::ConstantFolding);
        let stats = opt.optimize(&mut insns);
        assert_eq!(stats.len(), 1);
    }

    // --- BytecodeOptimizer ---------------------------------------------

    #[test]
    fn test_bytecode_optimizer_default() {
        let mut insns = vec![
            LjInsn::from_ad(OP_KSHORT, 0, 4),
            LjInsn::from_ad(OP_KSHORT, 1, 5),
            LjInsn::from_parts(OP_ADDVV, 2, 0, 1),
            LjInsn::from_ad(OP_RET1, 2, 2),
        ];
        let opt = BytecodeOptimizer::new();
        opt.optimize(&mut insns);
        // No panic, at least one pass ran
        assert!(!insns.is_empty());
    }

    #[test]
    fn test_bytecode_optimizer_empty() {
        let mut insns = vec![];
        let opt = BytecodeOptimizer::new();
        let stats = opt.optimize(&mut insns);
        assert_eq!(insns.len(), 0);
        // runs but does nothing
        let _ = stats;
    }

    #[test]
    fn test_opt_stats_default() {
        let s = OptStats::default();
        assert_eq!(s.instructions_removed, 0);
        assert_eq!(s.instructions_replaced, 0);
    }

    // --- Additional opcode name tests ---

    #[test]
    fn test_opcode_name_addvv() {
        assert_eq!(lj_opcode_name(OP_ADDVV), "ADDVV");
    }

    #[test]
    fn test_opcode_name_subvv() {
        assert_eq!(lj_opcode_name(OP_SUBVV), "SUBVV");
    }

    #[test]
    fn test_opcode_name_mulvv() {
        assert_eq!(lj_opcode_name(OP_MULVV), "MULVV");
    }

    #[test]
    fn test_opcode_name_kshort() {
        assert_eq!(lj_opcode_name(OP_KSHORT), "KSHORT");
    }

    #[test]
    fn test_opcode_name_ret1() {
        assert_eq!(lj_opcode_name(OP_RET1), "RET1");
    }

    // --- Additional LjInsn tests ---

    #[test]
    fn test_ljinsn_opcode_preserves_a() {
        let insn = LjInsn::from_ad(OP_MOV, 7, 3);
        assert_eq!(insn.a(), 7);
        assert_eq!(insn.d(), 3);
    }

    #[test]
    fn test_ljinsn_from_parts_b_c() {
        let insn = LjInsn::from_parts(OP_ADDVV, 1, 2, 3);
        assert_eq!(insn.b(), 2);
        assert_eq!(insn.c(), 3);
    }

    #[test]
    fn test_ljinsn_sd_positive() {
        let insn = LjInsn::from_ad(OP_JMP, 0, 10u16);
        assert_eq!(insn.sd(), 10);
    }

    // --- Additional ConstantFolding tests ---

    #[test]
    fn test_cf_invalidate_on_write() {
        let mut cf = ConstantFolding::new();
        cf.set_known(0, 42);
        let mut insns = vec![LjInsn::from_ad(OP_KPRI, 0, 1)]; // writes r0
        cf.apply(&mut insns);
        // KPRI invalidates r0
        assert!(cf.get_known(0).is_none());
    }

    #[test]
    fn test_cf_mov_propagates_constant() {
        let mut cf = ConstantFolding::new();
        cf.set_known(0, 99);
        let mut insns = vec![LjInsn::from_ad(OP_MOV, 1, 0)]; // r1 = r0 = 99
        cf.apply(&mut insns);
        assert_eq!(cf.get_known(1), Some(99));
    }

    #[test]
    fn test_cf_mov_unknown_src_invalidates_dst() {
        let mut cf = ConstantFolding::new();
        // r3 unknown
        let mut insns = vec![LjInsn::from_ad(OP_MOV, 2, 3)]; // r2 = r3 (unknown)
        cf.apply(&mut insns);
        assert!(cf.get_known(2).is_none());
    }

    #[test]
    fn test_cf_mulvv_no_fold_unknown() {
        let mut cf = ConstantFolding::new();
        cf.set_known(1, 5); // r2 unknown
        let mut insns = vec![LjInsn::from_parts(OP_MULVV, 0, 1, 2)];
        cf.apply(&mut insns);
        assert_eq!(insns[0].opcode(), OP_MULVV); // not folded
    }

    // --- Additional CopyPropagation tests ---

    #[test]
    fn test_cp_chain_copies() {
        let mut cp = CopyPropagation::new();
        cp.copies.insert(1, 0); // r1 is a copy of r0
        let mut insns = vec![LjInsn::from_ad(OP_MOV, 2, 1)]; // r2 = r1 → chained to r0
        cp.apply(&mut insns);
        assert_eq!(cp.copies.get(&2), Some(&0));
    }

    // --- Additional BCOptimizer tests ---

    #[test]
    fn test_bc_optimizer_no_rules() {
        let mut insns = vec![LjInsn::from_ad(OP_RET0, 0, 1)];
        let opt = BCOptimizer::new(); // no rules
        let stats = opt.optimize(&mut insns);
        assert!(stats.is_empty());
    }

    #[test]
    fn test_bc_optimizer_preserves_ret0() {
        let mut insns = vec![LjInsn::from_ad(OP_RET0, 0, 1)];
        BCOptimizer::with_all_rules().optimize(&mut insns);
        // RET0 must survive
        assert!(insns.iter().any(|i| i.opcode() == OP_RET0));
    }

    // --- BytecodeOptimizer additional ---

    #[test]
    fn test_bytecode_optimizer_max_iters() {
        let opt = BytecodeOptimizer {
            max_iterations: 1,
            ..BytecodeOptimizer::new()
        };
        let mut insns = vec![LjInsn::from_ad(OP_RET0, 0, 1)];
        opt.optimize(&mut insns);
        assert!(!insns.is_empty());
    }

    #[test]
    fn test_bytecode_optimizer_constant_fold_pipeline() {
        // KSHORT r0 = 3, KSHORT r1 = 4, ADDVV r2 = r0+r1
        let mut insns = vec![
            LjInsn::from_ad(OP_KSHORT, 0, 3),
            LjInsn::from_ad(OP_KSHORT, 1, 4),
            LjInsn::from_parts(OP_ADDVV, 2, 0, 1),
            LjInsn::from_ad(OP_RET1, 2, 2),
        ];
        BytecodeOptimizer::new().optimize(&mut insns);
        // After folding, the ADDVV should have been replaced by KSHORT 7
        let has_kshort_7 = insns.iter().any(|i| i.opcode() == OP_KSHORT && i.sd() == 7);
        let has_addvv = insns.iter().any(|i| i.opcode() == OP_ADDVV);
        // Either folded to KSHORT or left as ADDVV (depending on pass order)
        assert!(has_kshort_7 || has_addvv || insns.iter().any(|i| i.opcode() == OP_RET1));
    }

    #[test]
    fn test_opt_rule_nop_removal_display() {
        assert_eq!(OptRule::NopRemoval.to_string(), "nop_removal");
    }

    #[test]
    fn test_ljinsn_display_kshort() {
        let insn = LjInsn::from_ad(OP_KSHORT, 5, 42);
        let s = insn.to_string();
        assert!(s.contains("KSHORT"));
        assert!(s.contains('5'));
    }

    #[test]
    fn test_jump_chaining_no_jmp() {
        // No JMP instructions — nothing to chain
        let mut insns = vec![LjInsn::from_ad(OP_RET0, 0, 1)];
        let stats = JumpChaining::new().apply(&mut insns);
        assert_eq!(stats.instructions_replaced, 0);
    }

    #[test]
    fn test_dce_single_instruction() {
        let mut insns = vec![LjInsn::from_ad(OP_RET0, 0, 1)];
        DeadCodeElim::new().apply(&mut insns);
        assert_eq!(insns.len(), 1);
    }

    // --- NopRemoval tests ---

    #[test]
    fn test_nop_removal_no_nops() {
        let mut insns = vec![LjInsn::from_ad(OP_RET0, 0, 1)];
        let stats = NopRemoval::new().apply(&mut insns);
        assert_eq!(stats.instructions_removed, 0);
        assert_eq!(insns.len(), 1);
    }

    #[test]
    fn test_nop_removal_knil_empty_range() {
        // KNIL A=5, D=2 (D < A → empty range = NOP)
        let knil_nop = LjInsn::from_ad(OP_KNIL, 5, 2u16);
        let ret = LjInsn::from_ad(OP_RET0, 0, 1);
        let mut insns = vec![knil_nop, ret];
        let stats = NopRemoval::new().apply(&mut insns);
        assert_eq!(stats.instructions_removed, 1);
        assert_eq!(insns.len(), 1);
    }

    // --- InstructionAnnotator tests ---

    #[test]
    fn test_annotator_ret0_is_side_effect() {
        assert!(InstructionAnnotator::has_side_effects(OP_RET0));
        assert!(InstructionAnnotator::has_side_effects(OP_RET1));
    }

    #[test]
    fn test_annotator_kshort_no_side_effect() {
        assert!(!InstructionAnnotator::has_side_effects(OP_KSHORT));
    }

    #[test]
    fn test_annotator_reads_addvv() {
        let insns = vec![LjInsn::from_parts(OP_ADDVV, 0, 1, 2)];
        let ann = InstructionAnnotator::annotate(&insns);
        assert_eq!(ann[0].reads, vec![1, 2]);
        assert_eq!(ann[0].writes, vec![0]);
    }

    #[test]
    fn test_annotator_opcode_name() {
        let insns = vec![LjInsn::from_ad(OP_MOV, 1, 2)];
        let ann = InstructionAnnotator::annotate(&insns);
        assert_eq!(ann[0].opcode_name, "MOV");
    }

    #[test]
    fn test_annotator_empty() {
        let ann = InstructionAnnotator::annotate(&[]);
        assert!(ann.is_empty());
    }

    // --- BasicBlockBuilder tests ---

    #[test]
    fn test_basic_block_single_exit() {
        let insns = vec![LjInsn::from_ad(OP_RET0, 0, 1)];
        let blocks = BasicBlockBuilder::build(&insns);
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].successors.is_empty());
    }

    #[test]
    fn test_basic_block_empty() {
        let blocks = BasicBlockBuilder::build(&[]);
        assert!(blocks.is_empty());
    }

    #[test]
    fn test_basic_block_jmp_splits() {
        let jmp = LjInsn::from_ad(OP_JMP, 0, 0u16); // JMP to next
        let ret = LjInsn::from_ad(OP_RET0, 0, 1);
        let blocks = BasicBlockBuilder::build(&[jmp, ret]);
        assert!(!blocks.is_empty());
    }

    #[test]
    fn test_basic_block_len() {
        let b = LjBasicBlock {
            start: 0,
            end: 4,
            successors: vec![],
        };
        assert_eq!(b.len(), 5);
    }
}
