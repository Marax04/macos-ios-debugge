//! Lua bytecode optimizer.
//!
//! Constant folding for arithmetic/comparisons, dead code elimination,
//! copy propagation, strength reduction (power to multiplication),
//! and peephole optimisations.

use std::collections::{HashMap, HashSet};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Optimizable instruction representation
// ─────────────────────────────────────────────────────────────────────────────

/// A generic instruction that the optimizer can manipulate.
#[derive(Debug, Clone, PartialEq)]
pub struct OptInstr {
    /// Mnemonic (lowercase).
    pub mnemonic: String,
    /// Destination register (None for instructions with no output).
    pub dst: Option<u32>,
    /// First source register or constant index.
    pub src_a: Option<u32>,
    /// Second source register or constant index.
    pub src_b: Option<u32>,
    /// Immediate integer value.
    pub imm_int: Option<i64>,
    /// Immediate float value.
    pub imm_float: Option<f64>,
    /// Immediate string value.
    pub imm_str: Option<String>,
    /// k-flag: when set, `src_b` refers to a constant, not a register.
    pub k_flag: bool,
    /// Whether this instruction has been marked dead.
    pub dead: bool,
    /// Byte offset in the original function (for diagnostics).
    pub offset: u32,
}

impl OptInstr {
    /// Create a minimal instruction with mnemonic and destination.
    pub fn simple(mnemonic: impl Into<String>, dst: u32) -> Self {
        Self {
            mnemonic: mnemonic.into(),
            dst: Some(dst),
            src_a: None,
            src_b: None,
            imm_int: None,
            imm_float: None,
            imm_str: None,
            k_flag: false,
            dead: false,
            offset: 0,
        }
    }

    /// Create a load-integer instruction.
    #[must_use] 
    pub fn loadi(dst: u32, val: i64) -> Self {
        Self {
            mnemonic: "loadi".into(),
            dst: Some(dst),
            src_a: None,
            src_b: None,
            imm_int: Some(val),
            imm_float: None,
            imm_str: None,
            k_flag: false,
            dead: false,
            offset: 0,
        }
    }

    /// Create a load-float instruction.
    #[must_use] 
    pub fn loadf(dst: u32, val: f64) -> Self {
        Self {
            mnemonic: "loadf".into(),
            dst: Some(dst),
            src_a: None,
            src_b: None,
            imm_int: None,
            imm_float: Some(val),
            imm_str: None,
            k_flag: false,
            dead: false,
            offset: 0,
        }
    }

    /// Create a move instruction.
    #[must_use] 
    pub fn mov(dst: u32, src: u32) -> Self {
        Self {
            mnemonic: "move".into(),
            dst: Some(dst),
            src_a: Some(src),
            src_b: None,
            imm_int: None,
            imm_float: None,
            imm_str: None,
            k_flag: false,
            dead: false,
            offset: 0,
        }
    }

    /// Returns true if this instruction has no observable side effects.
    #[must_use] 
    pub fn is_pure(&self) -> bool {
        !matches!(
            self.mnemonic.as_str(),
            "call" | "tailcall" | "return" | "return0" | "return1"
                | "settable" | "settabup" | "setfield" | "seti"
                | "setupval" | "setglobal" | "jmp" | "forloop"
                | "forprep" | "tforprep" | "tforcall" | "tforloop"
                | "setlist" | "close" | "tbc"
        )
    }

    /// Returns true if this instruction is a load of a constant value.
    #[must_use] 
    pub fn is_const_load(&self) -> bool {
        matches!(
            self.mnemonic.as_str(),
            "loadi" | "loadf" | "loadk" | "loadkx"
                | "loadtrue" | "loadfalse" | "loadbool" | "loadnil"
        )
    }
}

impl fmt::Display for OptInstr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dead = if self.dead { "[DEAD] " } else { "" };
        write!(f, "{dead}{}", self.mnemonic)?;
        if let Some(d) = self.dst {
            write!(f, " R{d}")?;
        }
        if let Some(a) = self.src_a {
            write!(f, ", R{a}")?;
        }
        if let Some(b) = self.src_b {
            if self.k_flag {
                write!(f, ", K{b}")?;
            } else {
                write!(f, ", R{b}")?;
            }
        }
        if let Some(i) = self.imm_int {
            write!(f, ", #{i}")?;
        }
        if let Some(fl) = self.imm_float {
            write!(f, ", #{fl}")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Constant value representation
// ─────────────────────────────────────────────────────────────────────────────

/// A compile-time constant value.
#[derive(Debug, Clone, PartialEq)]
pub enum ConstVal {
    Nil,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
}

impl ConstVal {
    /// Try to add two constants.
    #[must_use] 
    pub fn try_add(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::Int(a), Self::Int(b)) => Some(Self::Int(a.wrapping_add(*b))),
            (Self::Float(a), Self::Float(b)) => Some(Self::Float(a + b)),
            (Self::Int(a), Self::Float(b)) => Some(Self::Float(*a as f64 + b)),
            (Self::Float(a), Self::Int(b)) => Some(Self::Float(a + *b as f64)),
            _ => None,
        }
    }

    /// Try to subtract.
    #[must_use] 
    pub fn try_sub(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::Int(a), Self::Int(b)) => Some(Self::Int(a.wrapping_sub(*b))),
            (Self::Float(a), Self::Float(b)) => Some(Self::Float(a - b)),
            (Self::Int(a), Self::Float(b)) => Some(Self::Float(*a as f64 - b)),
            (Self::Float(a), Self::Int(b)) => Some(Self::Float(a - *b as f64)),
            _ => None,
        }
    }

    /// Try to multiply.
    #[must_use] 
    pub fn try_mul(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::Int(a), Self::Int(b)) => Some(Self::Int(a.wrapping_mul(*b))),
            (Self::Float(a), Self::Float(b)) => Some(Self::Float(a * b)),
            (Self::Int(a), Self::Float(b)) => Some(Self::Float(*a as f64 * b)),
            (Self::Float(a), Self::Int(b)) => Some(Self::Float(a * *b as f64)),
            _ => None,
        }
    }

    /// Try to divide (always float).
    #[must_use] 
    pub fn try_div(&self, other: &Self) -> Option<Self> {
        let b = match other {
            Self::Int(b) => *b as f64,
            Self::Float(b) => *b,
            _ => return None,
        };
        if b == 0.0 {
            return None;
        }
        let a = match self {
            Self::Int(a) => *a as f64,
            Self::Float(a) => *a,
            _ => return None,
        };
        Some(Self::Float(a / b))
    }

    /// Try to compute power (always float).
    #[must_use] 
    pub fn try_pow(&self, other: &Self) -> Option<Self> {
        let b = match other {
            Self::Int(b) => *b as f64,
            Self::Float(b) => *b,
            _ => return None,
        };
        let a = match self {
            Self::Int(a) => *a as f64,
            Self::Float(a) => *a,
            _ => return None,
        };
        Some(Self::Float(a.powf(b)))
    }

    /// Try integer floor division.
    #[must_use] 
    pub fn try_idiv(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::Int(a), Self::Int(b)) if *b != 0 => {
                Some(Self::Int(a.wrapping_div(*b)))
            }
            (Self::Float(a), Self::Float(b)) if *b != 0.0 => {
                Some(Self::Float((a / b).floor()))
            }
            _ => None,
        }
    }

    /// Try modulo.
    #[must_use] 
    pub const fn try_mod(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::Int(a), Self::Int(b)) if *b != 0 => {
                Some(Self::Int(a.wrapping_rem(*b)))
            }
            _ => None,
        }
    }

    /// Try unary negation.
    #[must_use] 
    pub fn try_neg(&self) -> Option<Self> {
        match self {
            Self::Int(a) => Some(Self::Int(a.wrapping_neg())),
            Self::Float(a) => Some(Self::Float(-a)),
            _ => None,
        }
    }

    /// Try bitwise NOT.
    #[must_use] 
    pub fn try_bnot(&self) -> Option<Self> {
        if let Self::Int(a) = self {
            Some(Self::Int(!a))
        } else {
            None
        }
    }

    /// Convert to an `OptInstr` that loads this value into `dst`.
    #[must_use] 
    pub fn to_load_instr(&self, dst: u32) -> OptInstr {
        match self {
            Self::Int(v) => OptInstr::loadi(dst, *v),
            Self::Float(v) => OptInstr::loadf(dst, *v),
            Self::Bool(b) => {
                let mnemonic = if *b { "loadtrue" } else { "loadfalse" };
                OptInstr::simple(mnemonic, dst)
            }
            Self::Nil => OptInstr::simple("loadnil", dst),
            Self::Str(s) => OptInstr {
                mnemonic: "loadk".into(),
                dst: Some(dst),
                imm_str: Some(s.clone()),
                ..OptInstr::simple("loadk", dst)
            },
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OptPass
// ─────────────────────────────────────────────────────────────────────────────

/// Identifies an optimization pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OptPass {
    ConstantFolding,
    CopyPropagation,
    DeadCodeElimination,
    StrengthReduction,
    PeepholeOptimizer,
}

impl fmt::Display for OptPass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConstantFolding => write!(f, "ConstantFolding"),
            Self::CopyPropagation => write!(f, "CopyPropagation"),
            Self::DeadCodeElimination => write!(f, "DeadCodeElimination"),
            Self::StrengthReduction => write!(f, "StrengthReduction"),
            Self::PeepholeOptimizer => write!(f, "PeepholeOptimizer"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OptResult
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks what changed during an optimization run.
#[derive(Debug, Default)]
pub struct OptResult {
    /// Number of instructions eliminated.
    pub eliminated: usize,
    /// Number of instructions simplified (constant fold, etc.).
    pub simplified: usize,
    /// Number of copy propagations applied.
    pub copies_propagated: usize,
    /// Number of strength reductions applied.
    pub strength_reductions: usize,
    /// Passes that made changes.
    pub changed_passes: Vec<OptPass>,
}

impl OptResult {
    /// Total number of changes.
    #[must_use] 
    pub const fn total_changes(&self) -> usize {
        self.eliminated + self.simplified + self.copies_propagated + self.strength_reductions
    }

    fn record_pass(&mut self, pass: OptPass) {
        if !self.changed_passes.contains(&pass) {
            self.changed_passes.push(pass);
        }
    }
}

impl fmt::Display for OptResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OptResult: eliminated={}, simplified={}, copies={}, strength_red={}, total={}",
            self.eliminated,
            self.simplified,
            self.copies_propagated,
            self.strength_reductions,
            self.total_changes()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstFolder
// ─────────────────────────────────────────────────────────────────────────────

/// Constant-folding pass: replaces arithmetic on known constants with load instructions.
#[derive(Default)]
pub struct ConstFolder {
    /// Constant lattice: register → known constant value.
    consts: HashMap<u32, ConstVal>,
}


impl ConstFolder {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Run constant folding over a sequence of instructions.
    ///
    /// Returns the modified instruction list and an `OptResult`.
    pub fn run(&mut self, instrs: Vec<OptInstr>) -> (Vec<OptInstr>, OptResult) {
        let mut result = OptResult::default();
        let mut out = Vec::with_capacity(instrs.len());
        self.consts.clear();

        for instr in instrs {
            // First, seed the constant map from load instructions.
            self.update_consts_from_load(&instr);

            let folded = self.try_fold(&instr, &mut result);
            out.push(folded);
        }

        out
            .iter_mut()
            .for_each(|i| self.update_consts_from_load(i));

        (out, result)
    }

    fn update_consts_from_load(&mut self, instr: &OptInstr) {
        let dst = match instr.dst {
            Some(d) => d,
            None => return,
        };
        match instr.mnemonic.as_str() {
            "loadi" => {
                if let Some(v) = instr.imm_int {
                    self.consts.insert(dst, ConstVal::Int(v));
                }
            }
            "loadf" => {
                if let Some(v) = instr.imm_float {
                    self.consts.insert(dst, ConstVal::Float(v));
                }
            }
            "loadtrue" => {
                self.consts.insert(dst, ConstVal::Bool(true));
            }
            "loadfalse" | "loadbool" => {
                self.consts.insert(dst, ConstVal::Bool(false));
            }
            "loadnil" => {
                self.consts.insert(dst, ConstVal::Nil);
            }
            "move" => {
                if let Some(src) = instr.src_a {
                    if let Some(cv) = self.consts.get(&src).cloned() {
                        self.consts.insert(dst, cv);
                    } else {
                        self.consts.remove(&dst);
                    }
                }
            }
            _ => {
                // Any non-const instruction invalidates the destination.
                self.consts.remove(&dst);
            }
        }
    }

    fn try_fold(&self, instr: &OptInstr, result: &mut OptResult) -> OptInstr {
        let dst = match instr.dst {
            Some(d) => d,
            None => return instr.clone(),
        };

        // Get constants for source registers.
        let ca = instr.src_a.and_then(|r| self.consts.get(&r));
        let cb = instr.src_b.and_then(|r| self.consts.get(&r));

        let folded: Option<ConstVal> = match instr.mnemonic.as_str() {
            "add" => ca.zip(cb).and_then(|(a, b)| a.try_add(b)),
            "sub" => ca.zip(cb).and_then(|(a, b)| a.try_sub(b)),
            "mul" => ca.zip(cb).and_then(|(a, b)| a.try_mul(b)),
            "div" => ca.zip(cb).and_then(|(a, b)| a.try_div(b)),
            "pow" => ca.zip(cb).and_then(|(a, b)| a.try_pow(b)),
            "idiv" => ca.zip(cb).and_then(|(a, b)| a.try_idiv(b)),
            "mod" => ca.zip(cb).and_then(|(a, b)| a.try_mod(b)),
            "unm" => ca.and_then(ConstVal::try_neg),
            "bnot" => ca.and_then(ConstVal::try_bnot),
            "addi" => {
                if let (Some(a), Some(v)) = (ca, instr.imm_int) {
                    a.try_add(&ConstVal::Int(v))
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some(cv) = folded {
            let mut new_instr = cv.to_load_instr(dst);
            new_instr.offset = instr.offset;
            result.simplified += 1;
            result.record_pass(OptPass::ConstantFolding);
            new_instr
        } else {
            instr.clone()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CopyProp
// ─────────────────────────────────────────────────────────────────────────────

/// Copy propagation: replaces uses of copied registers with their original source.
#[derive(Default)]
pub struct CopyProp {
    /// Map from register to its copy source.
    copies: HashMap<u32, u32>,
}


impl CopyProp {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Run copy propagation over a sequence of instructions.
    pub fn run(&mut self, instrs: Vec<OptInstr>) -> (Vec<OptInstr>, OptResult) {
        let mut result = OptResult::default();
        self.copies.clear();

        let out: Vec<OptInstr> = instrs
            .into_iter()
            .map(|mut instr| {
                // Rewrite sources.
                let a_changed = self.propagate_reg(&mut instr.src_a);
                let b_changed = self.propagate_reg(&mut instr.src_b);
                if a_changed || b_changed {
                    result.copies_propagated += 1;
                    result.record_pass(OptPass::CopyPropagation);
                }

                // Update copy map.
                if instr.mnemonic == "move" {
                    if let (Some(dst), Some(src)) = (instr.dst, instr.src_a) {
                        self.copies.insert(dst, src);
                    }
                } else if let Some(dst) = instr.dst {
                    // Any non-move definition invalidates the copy for dst.
                    self.copies.remove(&dst);
                }

                instr
            })
            .collect();

        (out, result)
    }

    fn propagate_reg(&self, reg: &mut Option<u32>) -> bool {
        if let Some(r) = reg
            && let Some(&src) = self.copies.get(r) {
                *r = src;
                return true;
            }
        false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeadCodeElim
// ─────────────────────────────────────────────────────────────────────────────

/// Dead code elimination: removes instructions whose results are never used.
pub struct DeadCodeElim;

impl DeadCodeElim {
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }

    /// Run dead code elimination.
    ///
    /// An instruction is dead if:
    /// 1. It has a destination register.
    /// 2. That register is never used as a source by any subsequent instruction.
    /// 3. The instruction is pure (no side effects).
    #[must_use] 
    pub fn run(&self, instrs: Vec<OptInstr>) -> (Vec<OptInstr>, OptResult) {
        let mut result = OptResult::default();

        // Build liveness: which registers are used.
        let mut used: HashSet<u32> = instrs
            .iter()
            .flat_map(|i| {
                [i.src_a, i.src_b]
                    .into_iter()
                    .flatten()
            })
            .collect();
        // Treat the final destination in the block as live-out (it represents
        // the observable result of the basic block).
        if let Some(last_dst) = instrs.iter().rev().find_map(|i| i.dst) {
            used.insert(last_dst);
        }

        let out: Vec<OptInstr> = instrs
            .into_iter()
            .filter_map(|mut instr| {
                if let Some(dst) = instr.dst
                    && !used.contains(&dst) && instr.is_pure() {
                        result.eliminated += 1;
                        result.record_pass(OptPass::DeadCodeElimination);
                        return None;
                    }
                // Dead flag for diagnostics.
                instr.dead = false;
                Some(instr)
            })
            .collect();

        (out, result)
    }

    /// Mark dead instructions in-place without removing them (diagnostic mode).
    pub fn mark_dead(&self, instrs: &mut Vec<OptInstr>) -> usize {
        let mut used: HashSet<u32> = instrs
            .iter()
            .flat_map(|i| [i.src_a, i.src_b].into_iter().flatten())
            .collect();
        // The last destination in the block is considered live-out.
        if let Some(last_dst) = instrs.iter().rev().find_map(|i| i.dst) {
            used.insert(last_dst);
        }

        let mut count = 0;
        for instr in instrs.iter_mut() {
            if let Some(dst) = instr.dst
                && !used.contains(&dst) && instr.is_pure() {
                    instr.dead = true;
                    count += 1;
                }
        }
        count
    }
}

impl Default for DeadCodeElim {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StrengthReducer
// ─────────────────────────────────────────────────────────────────────────────

/// Strength reduction: replaces expensive operations with cheaper equivalents.
///
/// Examples:
/// - `pow(x, 2)` → `mul(x, x)`
/// - `mul(x, 1)` → `move(x)`
/// - `add(x, 0)` → `move(x)`
/// - `mul(x, 0)` → `loadi(0)`
/// - `sub(x, 0)` → `move(x)`
/// - `idiv(x, 1)` → `move(x)`
#[derive(Default)]
pub struct StrengthReducer {
    consts: HashMap<u32, ConstVal>,
}


impl StrengthReducer {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Run strength reduction.
    pub fn run(&mut self, instrs: Vec<OptInstr>) -> (Vec<OptInstr>, OptResult) {
        let mut result = OptResult::default();
        self.consts.clear();

        let out: Vec<OptInstr> = instrs
            .into_iter()
            .map(|instr| {
                // Update constant tracking.
                if let Some(dst) = instr.dst {
                    match instr.mnemonic.as_str() {
                        "loadi" => {
                            if let Some(v) = instr.imm_int {
                                self.consts.insert(dst, ConstVal::Int(v));
                            }
                        }
                        "loadf" => {
                            if let Some(v) = instr.imm_float {
                                self.consts.insert(dst, ConstVal::Float(v));
                            }
                        }
                        _ => {
                            self.consts.remove(&dst);
                        }
                    }
                }

                self.try_reduce(&instr, &mut result).map_or(instr, |reduced| reduced)
            })
            .collect();

        (out, result)
    }

    fn try_reduce(&self, instr: &OptInstr, result: &mut OptResult) -> Option<OptInstr> {
        let dst = instr.dst?;
        let src_a = instr.src_a?;

        let reduced = match instr.mnemonic.as_str() {
            "pow" | "powk" => {
                // pow(x, 2) → mul(x, x)
                let exp = instr
                    .src_b
                    .and_then(|r| self.consts.get(&r))
                    .or_else(|| instr.imm_float.map(|_| &ConstVal::Float(0.0)));
                let exp_int = instr
                    .src_b
                    .and_then(|r| self.consts.get(&r))
                    .and_then(|c| match c {
                        ConstVal::Int(n) => Some(*n),
                        _ => None,
                    })
                    .or(instr.imm_int);
                let _ = exp;
                if exp_int == Some(2) {
                    // x^2 → x*x
                    let mut new_instr = OptInstr {
                        mnemonic: "mul".into(),
                        dst: Some(dst),
                        src_a: Some(src_a),
                        src_b: Some(src_a),
                        ..instr.clone()
                    };
                    new_instr.imm_int = None;
                    new_instr.imm_float = None;
                    new_instr.k_flag = false;
                    Some(new_instr)
                } else {
                    None
                }
            }
            "mul" | "mulk" => {
                let b_const = instr
                    .src_b
                    .and_then(|r| self.consts.get(&r))
                    .or_else(|| instr.imm_int.map(|_| &ConstVal::Nil)); // placeholder
                let b_int = instr
                    .src_b
                    .and_then(|r| self.consts.get(&r))
                    .and_then(|c| match c { ConstVal::Int(n) => Some(*n), _ => None })
                    .or(instr.imm_int);
                let _ = b_const;
                match b_int {
                    Some(1) => Some(OptInstr::mov(dst, src_a)),
                    Some(0) => Some(OptInstr::loadi(dst, 0)),
                    Some(-1) => {
                        Some(OptInstr {
                            mnemonic: "unm".into(),
                            dst: Some(dst),
                            src_a: Some(src_a),
                            src_b: None,
                            imm_int: None,
                            ..instr.clone()
                        })
                    }
                    _ => None,
                }
            }
            "add" | "addk" | "addi" => {
                let b_int = instr
                    .src_b
                    .and_then(|r| self.consts.get(&r))
                    .and_then(|c| match c { ConstVal::Int(n) => Some(*n), _ => None })
                    .or(instr.imm_int);
                if b_int == Some(0) {
                    Some(OptInstr::mov(dst, src_a))
                } else {
                    None
                }
            }
            "sub" | "subk" => {
                let b_int = instr
                    .src_b
                    .and_then(|r| self.consts.get(&r))
                    .and_then(|c| match c { ConstVal::Int(n) => Some(*n), _ => None })
                    .or(instr.imm_int);
                if b_int == Some(0) {
                    Some(OptInstr::mov(dst, src_a))
                } else {
                    None
                }
            }
            "idiv" | "idivk" => {
                let b_int = instr
                    .src_b
                    .and_then(|r| self.consts.get(&r))
                    .and_then(|c| match c { ConstVal::Int(n) => Some(*n), _ => None })
                    .or(instr.imm_int);
                if b_int == Some(1) {
                    Some(OptInstr::mov(dst, src_a))
                } else {
                    None
                }
            }
            _ => None,
        };

        if reduced.is_some() {
            result.strength_reductions += 1;
            result.record_pass(OptPass::StrengthReduction);
        }
        reduced
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PeepholeOptimizer
// ─────────────────────────────────────────────────────────────────────────────

/// Peephole optimizations: small window transformations.
pub struct PeepholeOptimizer {
    window: usize,
}

impl Default for PeepholeOptimizer {
    fn default() -> Self {
        Self { window: 4 }
    }
}

impl PeepholeOptimizer {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub const fn with_window(mut self, w: usize) -> Self {
        self.window = w;
        self
    }

    /// Run peephole optimizations.
    #[must_use] 
    pub fn run(&self, instrs: Vec<OptInstr>) -> (Vec<OptInstr>, OptResult) {
        let mut result = OptResult::default();
        let mut out = instrs;

        // Pass 1: move-to-self elimination (move R0, R0).
        out.retain(|i| {
            let keep = !(i.mnemonic == "move"
                && i.dst.is_some()
                && i.src_a == i.dst);
            if !keep {
                result.eliminated += 1;
                result.record_pass(OptPass::PeepholeOptimizer);
            }
            keep
        });

        // Pass 2: redundant move pairs (move Rb, Ra followed by move Ra, Rb).
        let mut i = 0;
        while i + 1 < out.len() {
            let (a, b) = (&out[i], &out[i + 1]);
            if a.mnemonic == "move"
                && b.mnemonic == "move"
                && a.dst == b.src_a
                && a.src_a == b.dst
            {
                // Second move is redundant; remove it.
                out.remove(i + 1);
                result.eliminated += 1;
                result.record_pass(OptPass::PeepholeOptimizer);
            } else {
                i += 1;
            }
        }

        // Pass 3: loadnil followed by move from that nil register.
        let mut i = 0;
        while i + 1 < out.len() {
            if out[i].mnemonic == "loadnil"
                && let Some(nil_dst) = out[i].dst
                    && out[i + 1].mnemonic == "move"
                        && out[i + 1].src_a == Some(nil_dst)
                        && let Some(mv_dst) = out[i + 1].dst {
                            out[i + 1] = OptInstr::simple("loadnil", mv_dst);
                            result.simplified += 1;
                            result.record_pass(OptPass::PeepholeOptimizer);
                        }
            i += 1;
        }

        (out, result)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaOptimizer — combined optimizer
// ─────────────────────────────────────────────────────────────────────────────

/// Main optimizer: runs multiple passes in sequence.
pub struct LuaOptimizer {
    pub enabled_passes: Vec<OptPass>,
    pub max_iterations: u32,
}

impl Default for LuaOptimizer {
    fn default() -> Self {
        Self {
            enabled_passes: vec![
                OptPass::ConstantFolding,
                OptPass::CopyPropagation,
                OptPass::StrengthReduction,
                OptPass::DeadCodeElimination,
                OptPass::PeepholeOptimizer,
            ],
            max_iterations: 4,
        }
    }
}

impl LuaOptimizer {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn with_passes(mut self, passes: Vec<OptPass>) -> Self {
        self.enabled_passes = passes;
        self
    }

    #[must_use] 
    pub const fn with_max_iterations(mut self, n: u32) -> Self {
        self.max_iterations = n;
        self
    }

    /// Optimize a sequence of instructions, running all enabled passes up to
    /// `max_iterations` times until no further changes occur.
    #[must_use] 
    pub fn optimize(&self, instrs: Vec<OptInstr>) -> (Vec<OptInstr>, OptResult) {
        let mut current = instrs;
        let mut total_result = OptResult::default();

        for _iter in 0..self.max_iterations {
            let before_len = current.len();
            let before_simplified = total_result.simplified;

            for &pass in &self.enabled_passes {
                let (new_instrs, pass_result) = self.run_pass(pass, current);
                current = new_instrs;
                total_result.eliminated += pass_result.eliminated;
                total_result.simplified += pass_result.simplified;
                total_result.copies_propagated += pass_result.copies_propagated;
                total_result.strength_reductions += pass_result.strength_reductions;
                for p in pass_result.changed_passes {
                    total_result.record_pass(p);
                }
            }

            // Check for fixed point.
            if current.len() == before_len
                && total_result.simplified == before_simplified
            {
                break;
            }
        }

        (current, total_result)
    }

    fn run_pass(&self, pass: OptPass, instrs: Vec<OptInstr>) -> (Vec<OptInstr>, OptResult) {
        match pass {
            OptPass::ConstantFolding => ConstFolder::new().run(instrs),
            OptPass::CopyPropagation => CopyProp::new().run(instrs),
            OptPass::DeadCodeElimination => DeadCodeElim::new().run(instrs),
            OptPass::StrengthReduction => StrengthReducer::new().run(instrs),
            OptPass::PeepholeOptimizer => PeepholeOptimizer::new().run(instrs),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn add_instrs(dst: u32, a: u32, b: u32) -> OptInstr {
        OptInstr {
            mnemonic: "add".into(),
            dst: Some(dst),
            src_a: Some(a),
            src_b: Some(b),
            imm_int: None,
            imm_float: None,
            imm_str: None,
            k_flag: false,
            dead: false,
            offset: 0,
        }
    }

    #[test]
    fn test_const_fold_add() {
        let instrs = vec![
            OptInstr::loadi(0, 3),
            OptInstr::loadi(1, 4),
            add_instrs(2, 0, 1),
        ];
        let mut folder = ConstFolder::new();
        let (out, result) = folder.run(instrs);
        // Result register 2 should be loadi 7.
        let r2 = out.iter().find(|i| i.dst == Some(2)).unwrap();
        assert_eq!(r2.mnemonic, "loadi");
        assert_eq!(r2.imm_int, Some(7));
        assert_eq!(result.simplified, 1);
    }

    #[test]
    fn test_const_fold_mul_by_zero() {
        let instrs = vec![
            OptInstr::loadi(0, 5),
            OptInstr::loadi(1, 0),
            {
                let mut i = add_instrs(2, 0, 1);
                i.mnemonic = "mul".into();
                i
            },
        ];
        let mut reducer = StrengthReducer::new();
        let (out, result) = reducer.run(instrs);
        let r2 = out.iter().find(|i| i.dst == Some(2)).unwrap();
        assert_eq!(r2.mnemonic, "loadi");
        assert_eq!(r2.imm_int, Some(0));
        assert_eq!(result.strength_reductions, 1);
    }

    #[test]
    fn test_copy_prop() {
        let instrs = vec![
            OptInstr::loadi(0, 42),
            OptInstr::mov(1, 0),
            add_instrs(2, 1, 1),
        ];
        let mut cp = CopyProp::new();
        let (out, result) = cp.run(instrs);
        // After copy propagation, the add should use R0 instead of R1.
        let add = out.iter().find(|i| i.mnemonic == "add").unwrap();
        assert_eq!(add.src_a, Some(0));
        assert!(result.copies_propagated > 0);
    }

    #[test]
    fn test_dead_code_elim_removes_unused() {
        let instrs = vec![
            OptInstr::loadi(0, 1),
            OptInstr::loadi(1, 2), // R1 never used.
            add_instrs(2, 0, 0),
        ];
        let dce = DeadCodeElim::new();
        let (out, result) = dce.run(instrs);
        assert!(!out.iter().any(|i| i.dst == Some(1)));
        assert_eq!(result.eliminated, 1);
    }

    /// Probe for the classic backward-liveness gen/kill ordering bug:
    /// `live_in = (live_out U use) - def` would let the read-modify-write
    /// `r0 = r0 + r1` kill its own use of r0, making the initialising
    /// `loadi r0, 5` look dead-on-entry and get deleted (silent
    /// miscompilation: the add then reads an uninitialised r0).
    #[test]
    fn test_dce_keeps_accumulator_init() {
        let instrs = vec![
            OptInstr::loadi(0, 5),   // r0 = 5      <- must survive
            OptInstr::loadi(1, 1),   // r1 = 1
            add_instrs(0, 0, 1),     // r0 = r0 + r1  (read-modify-write)
        ];
        let dce = DeadCodeElim::new();
        let (out, result) = dce.run(instrs);
        assert!(
            out.iter().any(|i| i.mnemonic == "loadi" && i.dst == Some(0)),
            "accumulator init `loadi r0, 5` was wrongly eliminated: {out:?}"
        );
        assert_eq!(result.eliminated, 0);
    }

    #[test]
    fn test_strength_reduction_pow2() {
        let instrs = vec![
            OptInstr::loadi(1, 2),
            OptInstr {
                mnemonic: "pow".into(),
                dst: Some(2),
                src_a: Some(0),
                src_b: Some(1),
                imm_int: None,
                imm_float: None,
                imm_str: None,
                k_flag: false,
                dead: false,
                offset: 0,
            },
        ];
        let mut sr = StrengthReducer::new();
        let (out, result) = sr.run(instrs);
        let pow_instr = out.iter().find(|i| i.dst == Some(2)).unwrap();
        assert_eq!(pow_instr.mnemonic, "mul");
        assert_eq!(pow_instr.src_a, Some(0));
        assert_eq!(pow_instr.src_b, Some(0));
        assert_eq!(result.strength_reductions, 1);
    }

    #[test]
    fn test_peephole_move_self() {
        let instrs = vec![OptInstr::mov(3, 3)];
        let ph = PeepholeOptimizer::new();
        let (out, result) = ph.run(instrs);
        assert!(out.is_empty());
        assert_eq!(result.eliminated, 1);
    }

    #[test]
    fn test_optimizer_full_pipeline() {
        let instrs = vec![
            OptInstr::loadi(0, 10),
            OptInstr::loadi(1, 0),
            {
                 // add 10+0 → 10
                add_instrs(2, 0, 1)
            },
            OptInstr::mov(3, 2),
        ];
        let optimizer = LuaOptimizer::new();
        let (out, result) = optimizer.optimize(instrs);
        assert!(result.total_changes() > 0);
        // R2 should fold to 10.
        let r2 = out.iter().find(|i| i.dst == Some(2));
        if let Some(r2) = r2
            && r2.mnemonic == "loadi" {
                assert_eq!(r2.imm_int, Some(10));
            }
    }

    #[test]
    fn test_const_val_add_int() {
        let a = ConstVal::Int(3);
        let b = ConstVal::Int(4);
        assert_eq!(a.try_add(&b), Some(ConstVal::Int(7)));
    }

    #[test]
    fn test_const_val_pow() {
        let a = ConstVal::Float(2.0);
        let b = ConstVal::Float(3.0);
        assert_eq!(a.try_pow(&b), Some(ConstVal::Float(8.0)));
    }

    #[test]
    fn test_dead_mark_in_place() {
        let mut instrs = vec![
            OptInstr::loadi(0, 1),
            OptInstr::loadi(1, 99), // R1 unused
            add_instrs(2, 0, 0),
        ];
        let dce = DeadCodeElim::new();
        let count = dce.mark_dead(&mut instrs);
        assert_eq!(count, 1);
        assert!(instrs[1].dead);
    }
}
