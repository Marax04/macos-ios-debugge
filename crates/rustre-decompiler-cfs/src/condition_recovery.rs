// rustre-decompiler-cfs/src/condition_recovery.rs
//
// Condition recovery and boolean expression reconstruction from MLIL patterns.

use std::collections::{HashMap, HashSet};
use std::fmt;

// ---------------------------------------------------------------------------
// CPU flags
// ---------------------------------------------------------------------------

/// Individual x86 / ARM status flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Flag {
    ZF,
    CF,
    SF,
    OF,
    PF,
    AF,
    DF,
}

impl fmt::Display for Flag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZF => write!(f, "ZF"),
            Self::CF => write!(f, "CF"),
            Self::SF => write!(f, "SF"),
            Self::OF => write!(f, "OF"),
            Self::PF => write!(f, "PF"),
            Self::AF => write!(f, "AF"),
            Self::DF => write!(f, "DF"),
        }
    }
}

// ---------------------------------------------------------------------------
// Comparison operator
// ---------------------------------------------------------------------------

/// Comparison operator used in a CMP+JCC pattern.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CmpOp {
    /// Signed / bitwise equal.
    Eq,
    /// Not equal.
    Ne,
    /// Unsigned less-than.
    Ult,
    /// Unsigned greater-than-or-equal.
    Uge,
    /// Unsigned less-than-or-equal.
    Ule,
    /// Unsigned greater-than.
    Ugt,
    /// Signed less-than.
    Slt,
    /// Signed greater-than-or-equal.
    Sge,
    /// Signed less-than-or-equal.
    Sle,
    /// Signed greater-than.
    Sgt,
    /// Result is negative (SF = 1).
    Neg,
    /// Result is non-negative (SF = 0).
    Pos,
    /// Overflow occurred (OF = 1).
    Ovf,
    /// No overflow (OF = 0).
    NoOvf,
    /// Parity even.
    ParityEven,
    /// Parity odd.
    ParityOdd,
}

impl CmpOp {
    /// Return the logical negation of this operator.
    #[must_use] 
    pub const fn negate(self) -> Self {
        match self {
            Self::Eq => Self::Ne,
            Self::Ne => Self::Eq,
            Self::Ult => Self::Uge,
            Self::Uge => Self::Ult,
            Self::Ule => Self::Ugt,
            Self::Ugt => Self::Ule,
            Self::Slt => Self::Sge,
            Self::Sge => Self::Slt,
            Self::Sle => Self::Sgt,
            Self::Sgt => Self::Sle,
            Self::Neg => Self::Pos,
            Self::Pos => Self::Neg,
            Self::Ovf => Self::NoOvf,
            Self::NoOvf => Self::Ovf,
            Self::ParityEven => Self::ParityOdd,
            Self::ParityOdd => Self::ParityEven,
        }
    }

    /// C-like representation of the operator.
    #[must_use] 
    pub const fn as_c_str(self) -> &'static str {
        match self {
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Ult | Self::Slt => "<",
            Self::Uge | Self::Sge => ">=",
            Self::Ule | Self::Sle => "<=",
            Self::Ugt | Self::Sgt => ">",
            Self::Neg => "<0",
            Self::Pos => ">=0",
            Self::Ovf => "overflow",
            Self::NoOvf => "!overflow",
            Self::ParityEven => "parity_even",
            Self::ParityOdd => "parity_odd",
        }
    }
}

impl fmt::Display for CmpOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_c_str())
    }
}

// ---------------------------------------------------------------------------
// Flag-to-condition mapping (x86)
// ---------------------------------------------------------------------------

/// A description of which flags a JCC instruction tests.
#[derive(Clone, Debug)]
pub struct JccFlagPattern {
    /// Human-readable mnemonic (e.g. "je", "jne", "jl").
    pub mnemonic: &'static str,
    /// The resulting condition if the branch is taken.
    pub condition: CmpOp,
}

/// Complete table of x86 conditional-jump flag patterns.
#[must_use] 
pub fn x86_jcc_table() -> Vec<JccFlagPattern> {
    vec![
        // ZF = 1
        JccFlagPattern { mnemonic: "je",  condition: CmpOp::Eq },
        JccFlagPattern { mnemonic: "jz",  condition: CmpOp::Eq },
        // ZF = 0
        JccFlagPattern { mnemonic: "jne", condition: CmpOp::Ne },
        JccFlagPattern { mnemonic: "jnz", condition: CmpOp::Ne },
        // CF = 1
        JccFlagPattern { mnemonic: "jb",  condition: CmpOp::Ult },
        JccFlagPattern { mnemonic: "jc",  condition: CmpOp::Ult },
        JccFlagPattern { mnemonic: "jnae",condition: CmpOp::Ult },
        // CF = 0
        JccFlagPattern { mnemonic: "jae", condition: CmpOp::Uge },
        JccFlagPattern { mnemonic: "jnb", condition: CmpOp::Uge },
        JccFlagPattern { mnemonic: "jnc", condition: CmpOp::Uge },
        // CF=1 | ZF=1
        JccFlagPattern { mnemonic: "jbe", condition: CmpOp::Ule },
        JccFlagPattern { mnemonic: "jna", condition: CmpOp::Ule },
        // CF=0 & ZF=0
        JccFlagPattern { mnemonic: "ja",  condition: CmpOp::Ugt },
        JccFlagPattern { mnemonic: "jnbe",condition: CmpOp::Ugt },
        // SF ≠ OF
        JccFlagPattern { mnemonic: "jl",  condition: CmpOp::Slt },
        JccFlagPattern { mnemonic: "jnge",condition: CmpOp::Slt },
        // SF = OF
        JccFlagPattern { mnemonic: "jge", condition: CmpOp::Sge },
        JccFlagPattern { mnemonic: "jnl", condition: CmpOp::Sge },
        // ZF=1 | SF≠OF
        JccFlagPattern { mnemonic: "jle", condition: CmpOp::Sle },
        JccFlagPattern { mnemonic: "jng", condition: CmpOp::Sle },
        // ZF=0 & SF=OF
        JccFlagPattern { mnemonic: "jg",  condition: CmpOp::Sgt },
        JccFlagPattern { mnemonic: "jnle",condition: CmpOp::Sgt },
        // SF = 1
        JccFlagPattern { mnemonic: "js",  condition: CmpOp::Neg },
        // SF = 0
        JccFlagPattern { mnemonic: "jns", condition: CmpOp::Pos },
        // OF = 1
        JccFlagPattern { mnemonic: "jo",  condition: CmpOp::Ovf },
        // OF = 0
        JccFlagPattern { mnemonic: "jno", condition: CmpOp::NoOvf },
        // PF = 1
        JccFlagPattern { mnemonic: "jp",  condition: CmpOp::ParityEven },
        JccFlagPattern { mnemonic: "jpe", condition: CmpOp::ParityEven },
        // PF = 0
        JccFlagPattern { mnemonic: "jnp", condition: CmpOp::ParityOdd },
        JccFlagPattern { mnemonic: "jpo", condition: CmpOp::ParityOdd },
    ]
}

/// Look up the condition for a given JCC mnemonic (case-insensitive).
#[must_use] 
pub fn jcc_to_condition(mnemonic: &str) -> Option<CmpOp> {
    let lower = mnemonic.to_lowercase();
    x86_jcc_table()
        .into_iter()
        .find(|p| p.mnemonic == lower.as_str())
        .map(|p| p.condition)
}

// ---------------------------------------------------------------------------
// MLIL value / expression representation
// ---------------------------------------------------------------------------

/// A simplified MLIL expression used in condition recovery.
#[derive(Clone, Debug, PartialEq)]
pub enum MlilExpr {
    Var(String),
    Const(i64),
    Add(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
    Mul(Box<Self>, Box<Self>),
    Div(Box<Self>, Box<Self>),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Xor(Box<Self>, Box<Self>),
    Shl(Box<Self>, Box<Self>),
    Shr(Box<Self>, Box<Self>),
    Neg(Box<Self>),
    Not(Box<Self>),
    ZeroExtend(Box<Self>),
    SignExtend(Box<Self>),
    Load { addr: Box<Self>, size: u8 },
    Unknown,
}

impl fmt::Display for MlilExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Var(v) => write!(f, "{v}"),
            Self::Const(c) => write!(f, "{c}"),
            Self::Add(a, b) => write!(f, "({a} + {b})"),
            Self::Sub(a, b) => write!(f, "({a} - {b})"),
            Self::Mul(a, b) => write!(f, "({a} * {b})"),
            Self::Div(a, b) => write!(f, "({a} / {b})"),
            Self::And(a, b) => write!(f, "({a} & {b})"),
            Self::Or(a, b)  => write!(f, "({a} | {b})"),
            Self::Xor(a, b) => write!(f, "({a} ^ {b})"),
            Self::Shl(a, b) => write!(f, "({a} << {b})"),
            Self::Shr(a, b) => write!(f, "({a} >> {b})"),
            Self::Neg(a)    => write!(f, "(-{a})"),
            Self::Not(a)    => write!(f, "(~{a})"),
            Self::ZeroExtend(a) => write!(f, "zext({a})"),
            Self::SignExtend(a) => write!(f, "sext({a})"),
            Self::Load { addr, size } => write!(f, "mem{}[{}]", size * 8, addr),
            Self::Unknown => write!(f, "?"),
        }
    }
}

impl MlilExpr {
    /// Heuristic complexity score (smaller = simpler, used for normalization).
    #[must_use] 
    pub fn complexity(&self) -> usize {
        match self {
            Self::Const(_) => 0,
            Self::Var(_)   => 1,
            Self::Neg(a) | Self::Not(a)
            | Self::ZeroExtend(a) | Self::SignExtend(a) => 1 + a.complexity(),
            Self::Load { addr, .. } => 2 + addr.complexity(),
            Self::Add(a, b) | Self::Sub(a, b) | Self::Mul(a, b)
            | Self::Div(a, b) | Self::And(a, b) | Self::Or(a, b)
            | Self::Xor(a, b) | Self::Shl(a, b) | Self::Shr(a, b) => {
                1 + a.complexity() + b.complexity()
            }
            Self::Unknown => 100,
        }
    }
}

// ---------------------------------------------------------------------------
// Boolean expression tree (BoolExpr)
// ---------------------------------------------------------------------------

/// A structured boolean expression recovered from the binary.
#[derive(Clone, Debug, PartialEq)]
pub enum BoolExpr {
    /// Logical AND of two sub-expressions.
    And(Box<Self>, Box<Self>),
    /// Logical OR of two sub-expressions.
    Or(Box<Self>, Box<Self>),
    /// Logical NOT of a sub-expression.
    Not(Box<Self>),
    /// Comparison: left op right.
    Cmp { op: CmpOp, left: MlilExpr, right: MlilExpr },
    /// Constant true.
    True,
    /// Constant false.
    False,
}

impl BoolExpr {
    #[must_use] 
    pub fn and(a: Self, b: Self) -> Self {
        Self::And(Box::new(a), Box::new(b))
    }
    #[must_use] 
    pub fn or(a: Self, b: Self) -> Self {
        Self::Or(Box::new(a), Box::new(b))
    }
    #[must_use]
    pub fn not_of(a: Self) -> Self {
        Self::Not(Box::new(a))
    }
    #[must_use] 
    pub const fn cmp(op: CmpOp, left: MlilExpr, right: MlilExpr) -> Self {
        Self::Cmp { op, left, right }
    }

    /// Negate this boolean expression (De Morgan / push negation down one level).
    #[must_use] 
    pub fn negate(self) -> Self {
        match self {
            Self::Not(inner) => *inner,
            Self::And(a, b) => {
                Self::or(a.negate(), b.negate())
            }
            Self::Or(a, b) => {
                Self::and(a.negate(), b.negate())
            }
            Self::Cmp { op, left, right } => {
                Self::cmp(op.negate(), left, right)
            }
            Self::True  => Self::False,
            Self::False => Self::True,
        }
    }

    /// Normalize: ensure the simpler sub-expression is on the left of a Cmp.
    #[must_use] 
    pub fn normalize(self) -> Self {
        match self {
            Self::Cmp { op, left, right } => {
                if left.complexity() <= right.complexity() {
                    Self::Cmp { op, left, right }
                } else {
                    // Swap sides and flip operator direction.
                    let flipped_op = flip_cmp_sides(op);
                    Self::Cmp { op: flipped_op, left: right, right: left }
                }
            }
            Self::And(a, b) => {
                Self::and(a.normalize(), b.normalize())
            }
            Self::Or(a, b) => {
                Self::or(a.normalize(), b.normalize())
            }
            Self::Not(inner) => Self::not_of(inner.normalize()),
            other => other,
        }
    }

    /// Simplify the expression: remove double negations, tautologies,
    /// contradictions, and apply absorption law.
    #[must_use] 
    pub fn simplify(self) -> Self {
        match self {
            // Double negation elimination: !!A → A
            Self::Not(inner) => {
                let inner = inner.simplify();
                match inner {
                    Self::Not(x) => *x,
                    Self::True   => Self::False,
                    Self::False  => Self::True,
                    other => Self::not_of(other),
                }
            }
            Self::And(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                match (&a, &b) {
                    (Self::True,  _) => b,
                    (_, Self::True)  => a,
                    (Self::False, _) | (_, Self::False) => Self::False,
                    // Absorption: A & (A | B) → A
                    _ if absorption_applies(&a, &b) => a,
                    _ => Self::and(a, b),
                }
            }
            Self::Or(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                match (&a, &b) {
                    (Self::False, _) => b,
                    (_, Self::False) => a,
                    (Self::True, _) | (_, Self::True) => Self::True,
                    // Absorption: A | (A & B) → A
                    _ if absorption_applies_or(&a, &b) => a,
                    _ => Self::or(a, b),
                }
            }
            other => other,
        }
    }

    /// Convert to Negation Normal Form (negation pushed to leaves).
    #[must_use] 
    pub fn to_nnf(self) -> Self {
        match self {
            Self::Not(inner) => {
                // Push negation inward.
                inner.negate().to_nnf()
            }
            Self::And(a, b) => Self::and(a.to_nnf(), b.to_nnf()),
            Self::Or(a, b)  => Self::or(a.to_nnf(), b.to_nnf()),
            leaf => leaf,
        }
    }

    /// Convert to Conjunctive Normal Form (AND of ORs).
    #[must_use] 
    pub fn to_cnf(self) -> Self {
        let nnf = self.to_nnf();
        distribute_and_over_or(nnf)
    }

    /// Convert to Disjunctive Normal Form (OR of ANDs).
    #[must_use] 
    pub fn to_dnf(self) -> Self {
        let nnf = self.to_nnf();
        distribute_or_over_and(nnf)
    }

    /// Check if this is a tautology (always true).  Heuristic only.
    #[must_use] 
    pub const fn is_tautology(&self) -> bool {
        matches!(self, Self::True)
    }

    /// Check if this is a contradiction (always false).  Heuristic only.
    #[must_use] 
    pub const fn is_contradiction(&self) -> bool {
        matches!(self, Self::False)
    }

    /// Format as C-like boolean expression with correct precedence.
    #[must_use] 
    pub fn to_c_string(&self) -> String {
        self.to_c_prec(0)
    }

    fn to_c_prec(&self, parent_prec: u8) -> String {
        match self {
            Self::True  => "1".to_string(),
            Self::False => "0".to_string(),
            Self::Cmp { op, left, right } => {
                match op {
                    CmpOp::Neg  => format!("({left} < 0)"),
                    CmpOp::Pos  => format!("({left} >= 0)"),
                    CmpOp::Ovf  => format!("__overflow({left})"),
                    CmpOp::NoOvf=> format!("!__overflow({left})"),
                    CmpOp::ParityEven => format!("__parity_even({left})"),
                    CmpOp::ParityOdd  => format!("__parity_odd({left})"),
                    _ => format!("({} {} {})", left, op.as_c_str(), right),
                }
            }
            Self::Not(inner) => format!("!({})", inner.to_c_prec(10)),
            Self::And(a, b) => {
                let s = format!("{} && {}", a.to_c_prec(2), b.to_c_prec(2));
                if parent_prec > 2 { format!("({s})") } else { s }
            }
            Self::Or(a, b) => {
                let s = format!("{} || {}", a.to_c_prec(1), b.to_c_prec(1));
                if parent_prec > 1 { format!("({s})") } else { s }
            }
        }
    }
}

impl fmt::Display for BoolExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_c_string())
    }
}

// ---------------------------------------------------------------------------
// Helper: flip CmpOp when operands are swapped
// ---------------------------------------------------------------------------

const fn flip_cmp_sides(op: CmpOp) -> CmpOp {
    match op {
        CmpOp::Eq  => CmpOp::Eq,
        CmpOp::Ne  => CmpOp::Ne,
        CmpOp::Ult => CmpOp::Ugt,
        CmpOp::Ugt => CmpOp::Ult,
        CmpOp::Ule => CmpOp::Uge,
        CmpOp::Uge => CmpOp::Ule,
        CmpOp::Slt => CmpOp::Sgt,
        CmpOp::Sgt => CmpOp::Slt,
        CmpOp::Sle => CmpOp::Sge,
        CmpOp::Sge => CmpOp::Sle,
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Absorption law helpers
// ---------------------------------------------------------------------------

fn absorption_applies(a: &BoolExpr, b: &BoolExpr) -> bool {
    // A & (A | B) → true if b = Or(a, _) or b = Or(_, a)
    if let BoolExpr::Or(b1, b2) = b
        && (a == b1.as_ref() || a == b2.as_ref()) {
            return true;
        }
    false
}

fn absorption_applies_or(a: &BoolExpr, b: &BoolExpr) -> bool {
    // A | (A & B) → true if b = And(a, _) or b = And(_, a)
    if let BoolExpr::And(b1, b2) = b
        && (a == b1.as_ref() || a == b2.as_ref()) {
            return true;
        }
    false
}

// ---------------------------------------------------------------------------
// CNF / DNF distribution
// ---------------------------------------------------------------------------

fn distribute_and_over_or(expr: BoolExpr) -> BoolExpr {
    match expr {
        BoolExpr::Or(a, b) => {
            let a = distribute_and_over_or(*a);
            let b = distribute_and_over_or(*b);
            // If either side is an And, distribute.
            match (a, b) {
                (BoolExpr::And(a1, a2), b) => {
                    BoolExpr::and(
                        distribute_and_over_or(BoolExpr::or(*a1, b.clone())),
                        distribute_and_over_or(BoolExpr::or(*a2, b)),
                    )
                }
                (a, BoolExpr::And(b1, b2)) => {
                    BoolExpr::and(
                        distribute_and_over_or(BoolExpr::or(a.clone(), *b1)),
                        distribute_and_over_or(BoolExpr::or(a, *b2)),
                    )
                }
                (a, b) => BoolExpr::or(a, b),
            }
        }
        BoolExpr::And(a, b) => {
            BoolExpr::and(distribute_and_over_or(*a), distribute_and_over_or(*b))
        }
        leaf => leaf,
    }
}

fn distribute_or_over_and(expr: BoolExpr) -> BoolExpr {
    match expr {
        BoolExpr::And(a, b) => {
            let a = distribute_or_over_and(*a);
            let b = distribute_or_over_and(*b);
            match (a, b) {
                (BoolExpr::Or(a1, a2), b) => {
                    BoolExpr::or(
                        distribute_or_over_and(BoolExpr::and(*a1, b.clone())),
                        distribute_or_over_and(BoolExpr::and(*a2, b)),
                    )
                }
                (a, BoolExpr::Or(b1, b2)) => {
                    BoolExpr::or(
                        distribute_or_over_and(BoolExpr::and(a.clone(), *b1)),
                        distribute_or_over_and(BoolExpr::and(a, *b2)),
                    )
                }
                (a, b) => BoolExpr::and(a, b),
            }
        }
        BoolExpr::Or(a, b) => {
            BoolExpr::or(distribute_or_over_and(*a), distribute_or_over_and(*b))
        }
        leaf => leaf,
    }
}

// ---------------------------------------------------------------------------
// CMP+JCC pattern extractor
// ---------------------------------------------------------------------------

/// Represents one x86 CMP instruction.
#[derive(Clone, Debug)]
pub struct CmpInstr {
    pub left: MlilExpr,
    pub right: MlilExpr,
}

/// Represents one x86 JCC instruction.
#[derive(Clone, Debug)]
pub struct JccInstr {
    pub mnemonic: String,
    /// True = branch-taken target.
    pub target_taken: u64,
    /// False = fall-through target.
    pub target_fallthrough: u64,
}

/// Extract a `BoolExpr` from a (CMP, JCC) pair.
#[must_use] 
pub fn extract_condition_from_cmp_jcc(
    cmp: &CmpInstr,
    jcc: &JccInstr,
) -> Option<BoolExpr> {
    let op = jcc_to_condition(&jcc.mnemonic)?;
    Some(
        BoolExpr::cmp(op, cmp.left.clone(), cmp.right.clone())
            .normalize()
    )
}

// ---------------------------------------------------------------------------
// Short-circuit pattern detection
// ---------------------------------------------------------------------------

/// A basic block in a simplified CFG for short-circuit analysis.
#[derive(Clone, Debug)]
pub struct CondBlock {
    pub id: u32,
    /// The condition tested in this block (if any).
    pub cond: Option<BoolExpr>,
    /// True-branch successor.
    pub true_succ: Option<u32>,
    /// False-branch successor.
    pub false_succ: Option<u32>,
}

/// Detect whether two consecutive if-blocks form an `&&` compound condition.
///
/// Pattern: block A tests `cond_a`.  If `cond_a` is true → block B (tests `cond_b`).
/// If `cond_b` is true → merge node M.  If `cond_a` is false → M.  If `cond_b` is
/// false → M.  Result: `cond_a` && `cond_b`.
#[must_use] 
pub fn detect_short_circuit_and(
    a: &CondBlock,
    b: &CondBlock,
    merge_id: u32,
) -> Option<BoolExpr> {
    // a.true_succ == b.id, a.false_succ == merge_id, b.true_succ == merge_id
    if a.true_succ == Some(b.id)
        && a.false_succ == Some(merge_id)
        && b.false_succ == Some(merge_id)
    {
        let ca = a.cond.clone()?;
        let cb = b.cond.clone()?;
        Some(BoolExpr::and(ca, cb).simplify())
    } else {
        None
    }
}

/// Detect whether two consecutive if-blocks form an `||` compound condition.
///
/// Pattern: block A tests `cond_a`.  If `cond_a` is false → block B (tests `cond_b`).
/// If `cond_a` is true → merge node M.  If `cond_b` is true → M.  If `cond_b` is
/// false → M.  Result: `cond_a` || `cond_b`.
#[must_use] 
pub fn detect_short_circuit_or(
    a: &CondBlock,
    b: &CondBlock,
    merge_id: u32,
) -> Option<BoolExpr> {
    if a.false_succ == Some(b.id)
        && a.true_succ == Some(merge_id)
        && b.true_succ == Some(merge_id)
    {
        let ca = a.cond.clone()?;
        let cb = b.cond.clone()?;
        Some(BoolExpr::or(ca, cb).simplify())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Compound condition builder
// ---------------------------------------------------------------------------

/// Walk a list of `CondBlock`s and fold short-circuit patterns into compound
/// `BoolExpr` nodes, returning a map from block-id to recovered compound condition.
///
/// # Panics
///
/// Panics if internal invariants about CFG shape are violated during folding
/// (e.g. an indexed block referenced during folding cannot be found).
#[must_use]
pub fn recover_compound_conditions(
    blocks: &[CondBlock],
) -> HashMap<u32, BoolExpr> {
    let id_to_block: HashMap<u32, &CondBlock> =
        blocks.iter().map(|b| (b.id, b)).collect();

    let mut result: HashMap<u32, BoolExpr> = HashMap::new();

    for block in blocks {
        // Only look at blocks that already have a simple condition.
        if block.cond.is_none() {
            continue;
        }

        // Try &&: block.true_succ is another cond block, and the two share a
        // false merge.
        if let Some(true_id) = block.true_succ
            && let Some(next) = id_to_block.get(&true_id)
                && let Some(merge) = block.false_succ
                    && let Some(compound) =
                        detect_short_circuit_and(block, next, merge)
                    {
                        result.insert(block.id, compound);
                        continue;
                    }

        // Try ||: block.false_succ is another cond block, and the two share a
        // true merge.
        if let Some(false_id) = block.false_succ
            && let Some(next) = id_to_block.get(&false_id)
                && let Some(merge) = block.true_succ
                    && let Some(compound) =
                        detect_short_circuit_or(block, next, merge)
                    {
                        result.insert(block.id, compound);
                        continue;
                    }

        // No short-circuit pattern: just copy the simple condition.
        result.insert(block.id, block.cond.clone().unwrap());
    }

    result
}

// ---------------------------------------------------------------------------
// Distributive-law rewriter
// ---------------------------------------------------------------------------

/// Apply the distributive law: A & (B | C) → (A & B) | (A & C).
#[must_use] 
pub fn distribute_and(
    a: BoolExpr,
    b_or_c: BoolExpr,
) -> BoolExpr {
    match b_or_c {
        BoolExpr::Or(b, c) => BoolExpr::or(
            BoolExpr::and(a.clone(), *b),
            BoolExpr::and(a, *c),
        ),
        other => BoolExpr::and(a, other),
    }
}

/// Apply the distributive law: A | (B & C) → (A | B) & (A | C).
#[must_use] 
pub fn distribute_or(
    a: BoolExpr,
    b_and_c: BoolExpr,
) -> BoolExpr {
    match b_and_c {
        BoolExpr::And(b, c) => BoolExpr::and(
            BoolExpr::or(a.clone(), *b),
            BoolExpr::or(a, *c),
        ),
        other => BoolExpr::or(a, other),
    }
}

// ---------------------------------------------------------------------------
// Condition normalization pass
// ---------------------------------------------------------------------------

/// Full normalization pipeline: NNF → simplify → normalize comparisons.
#[must_use] 
pub fn normalize_condition(expr: BoolExpr) -> BoolExpr {
    expr.to_nnf().simplify().normalize()
}

// ---------------------------------------------------------------------------
// Condition display helpers
// ---------------------------------------------------------------------------

/// Wrap an expression in a C `if` header string.
#[must_use] 
pub fn condition_to_if_stmt(cond: &BoolExpr) -> String {
    format!("if ({}) {{", cond.to_c_string())
}

/// Wrap an expression in a C `while` header string.
#[must_use] 
pub fn condition_to_while_stmt(cond: &BoolExpr) -> String {
    format!("while ({}) {{", cond.to_c_string())
}

/// Wrap an expression in a C `do { } while ()` tail.
#[must_use] 
pub fn condition_to_do_while_tail(cond: &BoolExpr) -> String {
    format!("}} while ({});", cond.to_c_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jcc_lookup() {
        assert_eq!(jcc_to_condition("je"), Some(CmpOp::Eq));
        assert_eq!(jcc_to_condition("JNE"), Some(CmpOp::Ne));
        assert_eq!(jcc_to_condition("jl"), Some(CmpOp::Slt));
        assert_eq!(jcc_to_condition("ja"), Some(CmpOp::Ugt));
        assert_eq!(jcc_to_condition("jxyz"), None);
    }

    #[test]
    fn test_cmp_op_negate() {
        assert_eq!(CmpOp::Eq.negate(), CmpOp::Ne);
        assert_eq!(CmpOp::Ult.negate(), CmpOp::Uge);
        assert_eq!(CmpOp::Slt.negate(), CmpOp::Sge);
        assert_eq!(CmpOp::Neg.negate(), CmpOp::Pos);
    }

    #[test]
    fn test_bool_expr_display_cmp() {
        let e = BoolExpr::cmp(
            CmpOp::Slt,
            MlilExpr::Var("x".to_string()),
            MlilExpr::Const(10),
        );
        assert_eq!(e.to_c_string(), "(x < 10)");
    }

    #[test]
    fn test_bool_expr_and_or_display() {
        let a = BoolExpr::cmp(CmpOp::Eq, MlilExpr::Var("a".into()), MlilExpr::Const(0));
        let b = BoolExpr::cmp(CmpOp::Ne, MlilExpr::Var("b".into()), MlilExpr::Const(1));
        let expr = BoolExpr::and(a, b);
        let s = expr.to_c_string();
        assert!(s.contains("&&"));
    }

    #[test]
    fn test_double_negation_elimination() {
        let a = BoolExpr::cmp(CmpOp::Eq, MlilExpr::Var("x".into()), MlilExpr::Const(0));
        let dn = BoolExpr::not_of(BoolExpr::not_of(a.clone()));
        assert_eq!(dn.simplify(), a);
    }

    #[test]
    fn test_de_morgan_and() {
        let a = BoolExpr::cmp(CmpOp::Eq, MlilExpr::Var("a".into()), MlilExpr::Const(0));
        let b = BoolExpr::cmp(CmpOp::Ne, MlilExpr::Var("b".into()), MlilExpr::Const(1));
        let neg_and = BoolExpr::and(a, b).negate();
        // Should become Or(Not(a), Not(b)) i.e. Or(Ne, Eq)
        match neg_and {
            BoolExpr::Or(_, _) => {}
            _ => panic!("De Morgan AND should give OR"),
        }
    }

    #[test]
    fn test_nnf_not_and() {
        let a = BoolExpr::cmp(CmpOp::Slt, MlilExpr::Var("x".into()), MlilExpr::Const(5));
        let b = BoolExpr::cmp(CmpOp::Sgt, MlilExpr::Var("y".into()), MlilExpr::Const(2));
        // !(a && b) in NNF → (!a || !b) → (x>=5 || y<=2)
        let expr = BoolExpr::not_of(BoolExpr::and(a, b)).to_nnf();
        match expr {
            BoolExpr::Or(_, _) => {}
            _ => panic!("NNF of !(a&&b) should be Or"),
        }
    }

    #[test]
    fn test_short_circuit_and_detection() {
        let cond_a = BoolExpr::cmp(CmpOp::Slt, MlilExpr::Var("x".into()), MlilExpr::Const(10));
        let cond_b = BoolExpr::cmp(CmpOp::Sgt, MlilExpr::Var("y".into()), MlilExpr::Const(0));
        let block_a = CondBlock {
            id: 1,
            cond: Some(cond_a),
            true_succ: Some(2),
            false_succ: Some(3),
        };
        let block_b = CondBlock {
            id: 2,
            cond: Some(cond_b),
            true_succ: Some(3),
            false_succ: Some(3),
        };
        let result = detect_short_circuit_and(&block_a, &block_b, 3);
        assert!(result.is_some());
        match result.unwrap() {
            BoolExpr::And(_, _) => {}
            _ => panic!("Expected And"),
        }
    }

    #[test]
    fn test_short_circuit_or_detection() {
        let cond_a = BoolExpr::cmp(CmpOp::Eq, MlilExpr::Var("x".into()), MlilExpr::Const(0));
        let cond_b = BoolExpr::cmp(CmpOp::Eq, MlilExpr::Var("y".into()), MlilExpr::Const(0));
        let block_a = CondBlock {
            id: 1,
            cond: Some(cond_a),
            true_succ: Some(3),
            false_succ: Some(2),
        };
        let block_b = CondBlock {
            id: 2,
            cond: Some(cond_b),
            true_succ: Some(3),
            false_succ: Some(3),
        };
        let result = detect_short_circuit_or(&block_a, &block_b, 3);
        assert!(result.is_some());
        match result.unwrap() {
            BoolExpr::Or(_, _) => {}
            _ => panic!("Expected Or"),
        }
    }

    #[test]
    fn test_normalize_puts_simpler_left() {
        // Swap: complex expression on left, constant on right → constant should go left.
        let complex = MlilExpr::Add(
            Box::new(MlilExpr::Var("x".into())),
            Box::new(MlilExpr::Const(1)),
        );
        let simple = MlilExpr::Const(5);
        let e = BoolExpr::cmp(CmpOp::Eq, complex, simple).normalize();
        match e {
            BoolExpr::Cmp { left, .. } => {
                // After normalization, the simpler (Const) should be on the left.
                assert!(left.complexity() <= 1);
            }
            _ => panic!("Expected Cmp"),
        }
    }

    #[test]
    fn test_tautology_simplification() {
        let e = BoolExpr::True;
        let result = BoolExpr::and(e.clone(), e).simplify();
        assert_eq!(result, BoolExpr::True);
    }

    #[test]
    fn test_contradiction_simplification() {
        let a = BoolExpr::cmp(CmpOp::Eq, MlilExpr::Var("x".into()), MlilExpr::Const(0));
        let result = BoolExpr::and(BoolExpr::False, a).simplify();
        assert_eq!(result, BoolExpr::False);
    }

    #[test]
    fn test_if_stmt_display() {
        let cond = BoolExpr::cmp(CmpOp::Slt, MlilExpr::Var("i".into()), MlilExpr::Const(10));
        let s = condition_to_if_stmt(&cond);
        assert!(s.starts_with("if ("));
        assert!(s.ends_with('{'));
    }

    #[test]
    fn test_complexity_ordering() {
        let c = MlilExpr::Const(0);
        let v = MlilExpr::Var("x".into());
        let add = MlilExpr::Add(Box::new(v.clone()), Box::new(c.clone()));
        assert!(c.complexity() < v.complexity());
        assert!(v.complexity() < add.complexity());
    }

    #[test]
    fn test_cnf_distribution() {
        let a = BoolExpr::cmp(CmpOp::Eq, MlilExpr::Var("a".into()), MlilExpr::Const(0));
        let b = BoolExpr::cmp(CmpOp::Eq, MlilExpr::Var("b".into()), MlilExpr::Const(0));
        let c = BoolExpr::cmp(CmpOp::Eq, MlilExpr::Var("c".into()), MlilExpr::Const(0));
        // (a & b) | c → CNF: (a | c) & (b | c)
        let expr = BoolExpr::or(BoolExpr::and(a, b), c);
        let cnf = expr.to_cnf();
        match cnf {
            BoolExpr::And(_, _) => {}
            _ => panic!("CNF of (a&b)|c should be And"),
        }
    }
}

// ===========================================================================
// Extended: condition propagation and folding
// ===========================================================================

/// A map from variable name to a known constant value (used for constant folding).
pub type ConstantEnv = HashMap<String, i64>;

/// Fold a `BoolExpr` given a set of known constant values.
/// If an operand's variable has a known constant, substitute and evaluate.
#[must_use] 
pub fn constant_fold_bool(expr: BoolExpr, env: &ConstantEnv) -> BoolExpr {
    match expr {
        BoolExpr::Cmp { op, left, right } => {
            let left_val = eval_mlil(&left, env);
            let right_val = eval_mlil(&right, env);
            match (left_val, right_val) {
                (Some(l), Some(r)) => {
                    let result = eval_cmp(op, l, r);
                    if result { BoolExpr::True } else { BoolExpr::False }
                }
                _ => BoolExpr::Cmp { op, left, right },
            }
        }
        BoolExpr::And(a, b) => {
            let a = constant_fold_bool(*a, env);
            let b = constant_fold_bool(*b, env);
            BoolExpr::and(a, b).simplify()
        }
        BoolExpr::Or(a, b) => {
            let a = constant_fold_bool(*a, env);
            let b = constant_fold_bool(*b, env);
            BoolExpr::or(a, b).simplify()
        }
        BoolExpr::Not(inner) => {
            let inner = constant_fold_bool(*inner, env);
            BoolExpr::not_of(inner).simplify()
        }
        other => other,
    }
}

fn eval_mlil(expr: &MlilExpr, env: &ConstantEnv) -> Option<i64> {
    match expr {
        MlilExpr::Const(c) => Some(*c),
        MlilExpr::Var(v) => env.get(v).copied(),
        MlilExpr::Add(a, b) => Some(eval_mlil(a, env)? + eval_mlil(b, env)?),
        MlilExpr::Sub(a, b) => Some(eval_mlil(a, env)? - eval_mlil(b, env)?),
        MlilExpr::Mul(a, b) => Some(eval_mlil(a, env)?.wrapping_mul(eval_mlil(b, env)?)),
        MlilExpr::Neg(a) => Some(-eval_mlil(a, env)?),
        _ => None,
    }
}

const fn eval_cmp(op: CmpOp, l: i64, r: i64) -> bool {
    match op {
        CmpOp::Eq  => l == r,
        CmpOp::Ne  => l != r,
        CmpOp::Slt => l < r,
        CmpOp::Sle => l <= r,
        CmpOp::Sgt => l > r,
        CmpOp::Sge => l >= r,
        CmpOp::Ult => l.cast_unsigned() < r.cast_unsigned(),
        CmpOp::Ule => l.cast_unsigned() <= r.cast_unsigned(),
        CmpOp::Ugt => l.cast_unsigned() > r.cast_unsigned(),
        CmpOp::Uge => l.cast_unsigned() >= r.cast_unsigned(),
        CmpOp::Neg => l < 0,
        CmpOp::Pos => l >= 0,
        _ => false,
    }
}

// ===========================================================================
// Extended: ARM condition codes
// ===========================================================================

/// ARM conditional suffix (used after any instruction).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ArmCond {
    Eq,  // Z=1
    Ne,  // Z=0
    Cs,  // C=1
    Cc,  // C=0
    Mi,  // N=1
    Pl,  // N=0
    Vs,  // V=1
    Vc,  // V=0
    Hi,  // C=1 & Z=0
    Ls,  // C=0 | Z=1
    Ge,  // N=V
    Lt,  // N!=V
    Gt,  // Z=0 & N=V
    Le,  // Z=1 | N!=V
    Al,  // always
    Nv,  // never (reserved)
}

impl ArmCond {
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "eq" => Some(Self::Eq),
            "ne" => Some(Self::Ne),
            "cs" | "hs" => Some(Self::Cs),
            "cc" | "lo" => Some(Self::Cc),
            "mi" => Some(Self::Mi),
            "pl" => Some(Self::Pl),
            "vs" => Some(Self::Vs),
            "vc" => Some(Self::Vc),
            "hi" => Some(Self::Hi),
            "ls" => Some(Self::Ls),
            "ge" => Some(Self::Ge),
            "lt" => Some(Self::Lt),
            "gt" => Some(Self::Gt),
            "le" => Some(Self::Le),
            "al" => Some(Self::Al),
            "nv" => Some(Self::Nv),
            _ => None,
        }
    }

    /// Convert to a `CmpOp` for the true-branch.
    #[must_use] 
    pub const fn to_cmp_op(self) -> Option<CmpOp> {
        match self {
            Self::Eq => Some(CmpOp::Eq),
            Self::Ne => Some(CmpOp::Ne),
            Self::Cs => Some(CmpOp::Uge), // carry set = unsigned ≥
            Self::Cc => Some(CmpOp::Ult), // carry clear = unsigned <
            Self::Mi => Some(CmpOp::Neg),
            Self::Pl => Some(CmpOp::Pos),
            Self::Vs => Some(CmpOp::Ovf),
            Self::Vc => Some(CmpOp::NoOvf),
            Self::Hi => Some(CmpOp::Ugt),
            Self::Ls => Some(CmpOp::Ule),
            Self::Ge => Some(CmpOp::Sge),
            Self::Lt => Some(CmpOp::Slt),
            Self::Gt => Some(CmpOp::Sgt),
            Self::Le => Some(CmpOp::Sle),
            Self::Al | Self::Nv => None,
            }
    }

    #[must_use] 
    pub const fn negate(self) -> Self {
        match self {
            Self::Eq => Self::Ne,
            Self::Ne => Self::Eq,
            Self::Cs => Self::Cc,
            Self::Cc => Self::Cs,
            Self::Mi => Self::Pl,
            Self::Pl => Self::Mi,
            Self::Vs => Self::Vc,
            Self::Vc => Self::Vs,
            Self::Hi => Self::Ls,
            Self::Ls => Self::Hi,
            Self::Ge => Self::Lt,
            Self::Lt => Self::Ge,
            Self::Gt => Self::Le,
            Self::Le => Self::Gt,
            Self::Al => Self::Nv,
            Self::Nv => Self::Al,
        }
    }
}

// ===========================================================================
// Extended: condition region analysis
// ===========================================================================

/// A "condition region" groups a set of basic blocks that collectively
/// evaluate one compound boolean expression.  Useful for reconstructing
/// if-else chains from short-circuit patterns.
#[derive(Debug, Clone)]
pub struct ConditionRegion {
    pub blocks: Vec<u32>,           // block ids participating
    pub merged_condition: BoolExpr, // the compound condition
    pub true_target: u32,           // merge point on true
    pub false_target: u32,          // merge point on false
}

/// Walk the CFG backward from a merge node and collect all blocks that
/// contribute to a single compound condition.
#[must_use] 
pub fn extract_condition_region(
    merge_id: u32,
    blocks: &[CondBlock],
) -> Option<ConditionRegion> {
    let id_to_block: HashMap<u32, &CondBlock> =
        blocks.iter().map(|b| (b.id, b)).collect();

    // Walk backward: find blocks that have `merge_id` as one of their successors.
    let contributing: Vec<u32> = blocks
        .iter()
        .filter(|b| b.true_succ == Some(merge_id) || b.false_succ == Some(merge_id))
        .map(|b| b.id)
        .collect();

    if contributing.is_empty() {
        return None;
    }

    // Recover compound conditions.
    let compound_map = recover_compound_conditions(blocks);

    // Find the outermost block: the one whose predecessor is not another
    // condition block in this region.
    let region_set: HashSet<u32> = contributing.iter().copied().collect();
    let outermost = contributing.iter().find(|&&id| {
        // No block in the region has this as its true_succ or false_succ.
        !blocks.iter().any(|b| {
            region_set.contains(&b.id)
                && b.id != id
                && (b.true_succ == Some(id) || b.false_succ == Some(id))
        })
    });

    let outer_id = *outermost?;
    let merged_condition = compound_map.get(&outer_id)?.clone();

    let outer_block = id_to_block.get(&outer_id)?;
    let true_target  = outer_block.true_succ?;
    let false_target = outer_block.false_succ?;

    Some(ConditionRegion {
        blocks: contributing,
        merged_condition,
        true_target,
        false_target,
    })
}

// ===========================================================================
// Extended: range condition analysis
// ===========================================================================

/// A range constraint: lo ≤ var ≤ hi (or var < hi etc.).
#[derive(Debug, Clone)]
pub struct RangeConstraint {
    pub var: String,
    pub lo: Option<i64>,
    pub hi: Option<i64>,
    pub lo_strict: bool,
    pub hi_strict: bool,
}

impl RangeConstraint {
    pub fn unbounded(var: impl Into<String>) -> Self {
        Self { var: var.into(), lo: None, hi: None, lo_strict: false, hi_strict: false }
    }

    #[must_use] 
    pub fn intersect(&self, other: &Self) -> Option<Self> {
        if self.var != other.var {
            return None;
        }
        let lo = match (self.lo, other.lo) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None)    => Some(a),
            (None, Some(b))    => Some(b),
            (None, None)       => None,
        };
        let hi = match (self.hi, other.hi) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None)    => Some(a),
            (None, Some(b))    => Some(b),
            (None, None)       => None,
        };
        // Check non-empty.
        if let (Some(l), Some(h)) = (lo, hi)
            && l > h { return None; }
        Some(Self { var: self.var.clone(), lo, hi, lo_strict: false, hi_strict: false })
    }
}

/// Extract range constraints from a boolean expression.
#[must_use] 
pub fn extract_range_constraints(expr: &BoolExpr) -> Vec<RangeConstraint> {
    let mut result = Vec::new();
    extract_range_inner(expr, false, &mut result);
    result
}

fn extract_range_inner(expr: &BoolExpr, negated: bool, out: &mut Vec<RangeConstraint>) {
    match expr {
        BoolExpr::Cmp { op, left: MlilExpr::Var(v), right: MlilExpr::Const(c) } => {
            let effective_op = if negated { op.negate() } else { *op };
            let mut rc = RangeConstraint::unbounded(v.clone());
            match effective_op {
                CmpOp::Slt => { rc.hi = Some(*c); rc.hi_strict = true; }
                CmpOp::Sle => { rc.hi = Some(*c); }
                CmpOp::Sgt => { rc.lo = Some(*c); rc.lo_strict = true; }
                CmpOp::Sge => { rc.lo = Some(*c); }
                CmpOp::Eq  => { rc.lo = Some(*c); rc.hi = Some(*c); }
                _ => {}
            }
            out.push(rc);
        }
        BoolExpr::And(a, b) if !negated => {
            extract_range_inner(a, false, out);
            extract_range_inner(b, false, out);
        }
        BoolExpr::Not(inner) => {
            extract_range_inner(inner, !negated, out);
        }
        _ => {}
    }
}

// ===========================================================================
// Extended: condition pretty-printer with precedence awareness
// ===========================================================================

/// Configuration for the C condition printer.
#[derive(Debug, Clone)]
pub struct PrintConfig {
    /// Use `&&` / `||` vs `&` / `|`.
    pub logical_operators: bool,
    /// Emit extra parentheses for clarity.
    pub extra_parens: bool,
    /// Emit unsigned suffixes (e.g., `(unsigned)x`).
    pub show_unsigned_casts: bool,
}

impl Default for PrintConfig {
    fn default() -> Self {
        Self {
            logical_operators: true,
            extra_parens: false,
            show_unsigned_casts: false,
        }
    }
}

/// Print a `BoolExpr` according to the given configuration.
#[must_use] 
pub fn print_condition(expr: &BoolExpr, cfg: &PrintConfig) -> String {
    match expr {
        BoolExpr::True  => "1".to_string(),
        BoolExpr::False => "0".to_string(),
        BoolExpr::Cmp { op, left, right } => {
            let cast = if cfg.show_unsigned_casts {
                match op {
                    CmpOp::Ult | CmpOp::Ule | CmpOp::Ugt | CmpOp::Uge => "(unsigned)",
                    _ => "",
                }
            } else {
                ""
            };
            format!("({}{} {} {})", cast, left, op.as_c_str(), right)
        }
        BoolExpr::Not(inner) => format!("!({})", print_condition(inner, cfg)),
        BoolExpr::And(a, b) => {
            let op = if cfg.logical_operators { "&&" } else { "&" };
            let la = print_condition(a, cfg);
            let lb = print_condition(b, cfg);
            if cfg.extra_parens {
                format!("({la} {op} {lb})")
            } else {
                format!("{la} {op} {lb}")
            }
        }
        BoolExpr::Or(a, b) => {
            let op = if cfg.logical_operators { "||" } else { "|" };
            let la = print_condition(a, cfg);
            let lb = print_condition(b, cfg);
            if cfg.extra_parens {
                format!("({la} {op} {lb})")
            } else {
                format!("{la} {op} {lb}")
            }
        }
    }
}

// ===========================================================================
// Extended: condition graph
// ===========================================================================

/// A node in the condition DAG.
#[derive(Clone, Debug)]
pub struct CondNode {
    pub id: usize,
    pub expr: BoolExpr,
    pub children: Vec<usize>,
    pub is_root: bool,
}

/// A DAG of boolean expressions (for sharing sub-expressions).
#[derive(Default, Debug)]
pub struct CondDag {
    pub nodes: Vec<CondNode>,
}

impl CondDag {
    /// Insert a condition, deduplicating identical sub-expressions.
    pub fn insert(&mut self, expr: BoolExpr) -> usize {
        // Linear search for existing node (sufficient for small DAGs).
        for (i, node) in self.nodes.iter().enumerate() {
            if node.expr == expr {
                return i;
            }
        }
        let id = self.nodes.len();
        let children = match &expr {
            BoolExpr::And(a, b) | BoolExpr::Or(a, b) => {
                let ia = self.insert(*a.clone());
                let ib = self.insert(*b.clone());
                vec![ia, ib]
            }
            BoolExpr::Not(inner) => {
                let ii = self.insert(*inner.clone());
                vec![ii]
            }
            _ => vec![],
        };
        self.nodes.push(CondNode { id, expr, children, is_root: false });
        id
    }

    pub fn mark_root(&mut self, id: usize) {
        if let Some(node) = self.nodes.get_mut(id) {
            node.is_root = true;
        }
    }
}

// ===========================================================================
// Extended tests
// ===========================================================================

#[cfg(test)]
mod extended_tests {
    use super::*;

    #[test]
    fn test_constant_fold_true() {
        let mut env = ConstantEnv::new();
        env.insert("x".to_string(), 5);
        let expr = BoolExpr::cmp(CmpOp::Slt, MlilExpr::Var("x".into()), MlilExpr::Const(10));
        let result = constant_fold_bool(expr, &env);
        assert_eq!(result, BoolExpr::True);
    }

    #[test]
    fn test_constant_fold_false() {
        let mut env = ConstantEnv::new();
        env.insert("x".to_string(), 15);
        let expr = BoolExpr::cmp(CmpOp::Slt, MlilExpr::Var("x".into()), MlilExpr::Const(10));
        let result = constant_fold_bool(expr, &env);
        assert_eq!(result, BoolExpr::False);
    }

    #[test]
    fn test_arm_cond_from_str() {
        assert_eq!(ArmCond::parse("eq"), Some(ArmCond::Eq));
        assert_eq!(ArmCond::parse("cs"), Some(ArmCond::Cs));
        assert_eq!(ArmCond::parse("hs"), Some(ArmCond::Cs)); // alias
        assert_eq!(ArmCond::parse("gt"), Some(ArmCond::Gt));
        assert_eq!(ArmCond::parse("zz"), None);
    }

    #[test]
    fn test_arm_cond_negate() {
        assert_eq!(ArmCond::Eq.negate(), ArmCond::Ne);
        assert_eq!(ArmCond::Ge.negate(), ArmCond::Lt);
        assert_eq!(ArmCond::Hi.negate(), ArmCond::Ls);
    }

    #[test]
    fn test_arm_cond_to_cmp_op() {
        assert_eq!(ArmCond::Eq.to_cmp_op(), Some(CmpOp::Eq));
        assert_eq!(ArmCond::Cs.to_cmp_op(), Some(CmpOp::Uge));
        assert_eq!(ArmCond::Al.to_cmp_op(), None);
    }

    #[test]
    fn test_range_constraint_from_bool() {
        let expr = BoolExpr::and(
            BoolExpr::cmp(CmpOp::Sge, MlilExpr::Var("x".into()), MlilExpr::Const(0)),
            BoolExpr::cmp(CmpOp::Slt, MlilExpr::Var("x".into()), MlilExpr::Const(10)),
        );
        let ranges = extract_range_constraints(&expr);
        
        assert_eq!(ranges.iter().filter(|r| r.var == "x").count(), 2);
    }

    #[test]
    fn test_range_constraint_intersect() {
        let r1 = RangeConstraint { var: "x".into(), lo: Some(0), hi: Some(10), lo_strict: false, hi_strict: false };
        let r2 = RangeConstraint { var: "x".into(), lo: Some(5), hi: Some(20), lo_strict: false, hi_strict: false };
        let r3 = r1.intersect(&r2).unwrap();
        assert_eq!(r3.lo, Some(5));
        assert_eq!(r3.hi, Some(10));
    }

    #[test]
    fn test_range_constraint_empty_intersect() {
        let r1 = RangeConstraint { var: "x".into(), lo: Some(0), hi: Some(5), lo_strict: false, hi_strict: false };
        let r2 = RangeConstraint { var: "x".into(), lo: Some(6), hi: Some(10), lo_strict: false, hi_strict: false };
        assert!(r1.intersect(&r2).is_none());
    }

    #[test]
    fn test_print_config_logical_ops() {
        let a = BoolExpr::cmp(CmpOp::Eq, MlilExpr::Var("a".into()), MlilExpr::Const(0));
        let b = BoolExpr::cmp(CmpOp::Ne, MlilExpr::Var("b".into()), MlilExpr::Const(1));
        let expr = BoolExpr::and(a, b);
        let s = print_condition(&expr, &PrintConfig::default());
        assert!(s.contains("&&"));
    }

    #[test]
    fn test_print_config_bitwise_ops() {
        let a = BoolExpr::cmp(CmpOp::Eq, MlilExpr::Var("a".into()), MlilExpr::Const(0));
        let b = BoolExpr::cmp(CmpOp::Ne, MlilExpr::Var("b".into()), MlilExpr::Const(1));
        let expr = BoolExpr::or(a, b);
        let cfg = PrintConfig { logical_operators: false, ..Default::default() };
        let s = print_condition(&expr, &cfg);
        assert!(s.contains(" | "));
    }

    #[test]
    fn test_cond_dag_dedup() {
        let mut dag = CondDag::default();
        let a = BoolExpr::cmp(CmpOp::Eq, MlilExpr::Var("a".into()), MlilExpr::Const(0));
        let id1 = dag.insert(a.clone());
        let id2 = dag.insert(a);
        assert_eq!(id1, id2, "Duplicate conditions should map to the same node");
    }

    #[test]
    fn test_recover_compound_multiple_blocks() {
        // Build a chain: block 1 (&&) → block 2 → merge 3
        let cond_a = BoolExpr::cmp(CmpOp::Slt, MlilExpr::Var("x".into()), MlilExpr::Const(10));
        let cond_b = BoolExpr::cmp(CmpOp::Sgt, MlilExpr::Var("y".into()), MlilExpr::Const(0));
        let cond_c = BoolExpr::cmp(CmpOp::Eq, MlilExpr::Var("z".into()), MlilExpr::Const(0));
        let blocks = vec![
            CondBlock { id: 1, cond: Some(cond_a), true_succ: Some(2), false_succ: Some(3) },
            CondBlock { id: 2, cond: Some(cond_b), true_succ: Some(4), false_succ: Some(3) },
            CondBlock { id: 4, cond: Some(cond_c), true_succ: Some(3), false_succ: Some(3) },
        ];
        let map = recover_compound_conditions(&blocks);
        // Block 1 should have a compound condition.
        assert!(map.contains_key(&1));
    }

    #[test]
    fn test_dnf_conversion() {
        let a = BoolExpr::cmp(CmpOp::Eq, MlilExpr::Var("a".into()), MlilExpr::Const(0));
        let b = BoolExpr::cmp(CmpOp::Eq, MlilExpr::Var("b".into()), MlilExpr::Const(0));
        let c = BoolExpr::cmp(CmpOp::Eq, MlilExpr::Var("c".into()), MlilExpr::Const(0));
        // a | (b & c) → already DNF
        let expr = BoolExpr::or(a, BoolExpr::and(b, c));
        let dnf = expr.to_dnf();
        match dnf {
            BoolExpr::Or(_, _) | BoolExpr::And(_, _) | BoolExpr::Cmp { .. } => {} // single term is ok
            _ => panic!("Unexpected DNF form"),
        }
    }
}
