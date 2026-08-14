//! SMT formula generation from symbolic expressions.
//!
//! Converts [`SymExpr`] trees to SMT-LIB 2.6 strings for use with external
//! solvers (Z3, CVC5, Boolector, etc.).

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

use crate::{SymExpr, SymType};

// ---------------------------------------------------------------------------
// SmtFormula
// ---------------------------------------------------------------------------

/// A complete SMT-LIB 2.6 formula ready for solver submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtFormula {
    /// SMT-LIB logic declaration (e.g. `QF_BV`, `QF_ABV`).
    pub logic: SmtLogic,
    /// Variable declarations (name → sort).
    pub declarations: Vec<SmtDeclaration>,
    /// Assertion constraints.
    pub assertions: Vec<String>,
}

impl SmtFormula {
    /// Create an empty formula with the given logic.
    #[must_use]
    pub const fn new(logic: SmtLogic) -> Self {
        Self {
            logic,
            declarations: Vec::new(),
            assertions: Vec::new(),
        }
    }

    /// Add a variable declaration.
    pub fn declare(&mut self, name: impl Into<String>, sort: SmtSort) {
        self.declarations.push(SmtDeclaration {
            name: name.into(),
            sort,
        });
    }

    /// Add an assertion.
    pub fn assert(&mut self, expr: impl Into<String>) {
        self.assertions.push(expr.into());
    }

    /// Render the full SMT-LIB 2.6 script as a string.
    #[must_use]
    pub fn to_smtlib(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let _ = writeln!(out, "(set-logic {})", self.logic.as_str());
        for decl in &self.declarations {
            let _ = writeln!(
                out,
                "(declare-const {} {})",
                decl.name,
                decl.sort.to_smtlib()
            );
        }
        for assertion in &self.assertions {
            let _ = writeln!(out, "(assert {assertion})");
        }
        out.push_str("(check-sat)\n(get-model)\n");
        out
    }

    /// Number of assertions.
    #[must_use]
    pub const fn assertion_count(&self) -> usize {
        self.assertions.len()
    }

    /// Number of declared variables.
    #[must_use]
    pub const fn declaration_count(&self) -> usize {
        self.declarations.len()
    }
}

impl fmt::Display for SmtFormula {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_smtlib())
    }
}

// ---------------------------------------------------------------------------
// SmtLogic
// ---------------------------------------------------------------------------

/// SMT-LIB logic identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmtLogic {
    /// Quantifier-free bitvectors.
    QfBv,
    /// Quantifier-free arrays + bitvectors.
    QfAbv,
    /// Quantifier-free linear integer arithmetic.
    QfLia,
    /// Quantifier-free non-linear arithmetic.
    QfNia,
    /// All supported theories.
    All,
}

impl SmtLogic {
    /// SMT-LIB 2.6 string identifier.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::QfBv => "QF_BV",
            Self::QfAbv => "QF_ABV",
            Self::QfLia => "QF_LIA",
            Self::QfNia => "QF_NIA",
            Self::All => "ALL",
        }
    }
}

impl fmt::Display for SmtLogic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SmtSort
// ---------------------------------------------------------------------------

/// An SMT-LIB sort.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmtSort {
    /// Bitvector of given width.
    BitVec(u32),
    /// Boolean sort.
    Bool,
    /// Array from index sort to element sort.
    Array(Box<Self>, Box<Self>),
}

impl SmtSort {
    /// Return the SMT-LIB string representation.
    #[must_use]
    pub fn to_smtlib(&self) -> String {
        match self {
            Self::BitVec(w) => format!("(_ BitVec {w})"),
            Self::Bool => "Bool".to_string(),
            Self::Array(idx, elem) => {
                format!("(Array {} {})", idx.to_smtlib(), elem.to_smtlib())
            }
        }
    }
}

impl fmt::Display for SmtSort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_smtlib())
    }
}

// ---------------------------------------------------------------------------
// SmtDeclaration
// ---------------------------------------------------------------------------

/// A constant declaration in an SMT-LIB script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtDeclaration {
    /// Variable name.
    pub name: String,
    /// Variable sort.
    pub sort: SmtSort,
}

// ---------------------------------------------------------------------------
// SymExpr → SMT-LIB translator
// ---------------------------------------------------------------------------

/// Translates [`SymExpr`] trees into SMT-LIB 2.6 expression strings.
#[derive(Debug, Default)]
pub struct ExprToSmtLib {
    /// Variables encountered during translation (name → width).
    pub vars: Vec<(String, u32)>,
}

impl ExprToSmtLib {
    /// Create a new translator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Translate `expr` to a SMT-LIB 2.6 expression string.
    ///
    /// Variables are collected into `self.vars` for later declaration.
    #[must_use]
    pub fn translate(&mut self, expr: &SymExpr) -> String {
        match expr {
            SymExpr::ConstBv { val, width } => {
                format!("(_ bv{val} {width})")
            }
            SymExpr::ConstBool(b) => {
                if *b {
                    "true".to_string()
                } else {
                    "false".to_string()
                }
            }
            SymExpr::Var { name, ty } => {
                let width = match ty {
                    SymType::BitVec(w) => *w,
                    SymType::Pointer | SymType::Array { .. } => 64,
                    SymType::Bool => {
                        self.vars.push((name.clone(), 0));
                        return name.clone();
                    }
                };
                // Check if already declared
                let already = self.vars.iter().any(|(n, _)| n == name);
                if !already {
                    self.vars.push((name.clone(), width));
                }
                name.clone()
            }
            SymExpr::Add(l, r) => format!("(bvadd {} {})", self.translate(l), self.translate(r)),
            SymExpr::Sub(l, r) => format!("(bvsub {} {})", self.translate(l), self.translate(r)),
            SymExpr::Mul(l, r) => format!("(bvmul {} {})", self.translate(l), self.translate(r)),
            SymExpr::UDiv(l, r) => format!("(bvudiv {} {})", self.translate(l), self.translate(r)),
            SymExpr::SDiv(l, r) => format!("(bvsdiv {} {})", self.translate(l), self.translate(r)),
            SymExpr::URem(l, r) => format!("(bvurem {} {})", self.translate(l), self.translate(r)),
            SymExpr::SRem(l, r) => format!("(bvsrem {} {})", self.translate(l), self.translate(r)),
            SymExpr::And(l, r) => format!("(bvand {} {})", self.translate(l), self.translate(r)),
            SymExpr::Or(l, r) => format!("(bvor {} {})", self.translate(l), self.translate(r)),
            SymExpr::Xor(l, r) => format!("(bvxor {} {})", self.translate(l), self.translate(r)),
            SymExpr::Not(e) => format!("(bvnot {})", self.translate(e)),
            SymExpr::Neg(e) => format!("(bvneg {})", self.translate(e)),
            SymExpr::Shl(l, r) => format!("(bvshl {} {})", self.translate(l), self.translate(r)),
            SymExpr::LShr(l, r) => format!("(bvlshr {} {})", self.translate(l), self.translate(r)),
            SymExpr::AShr(l, r) => format!("(bvashr {} {})", self.translate(l), self.translate(r)),
            SymExpr::Concat(hi, lo) => {
                format!("(concat {} {})", self.translate(hi), self.translate(lo))
            }
            SymExpr::Extract { expr, hi, lo } => {
                format!("((_ extract {hi} {lo}) {})", self.translate(expr))
            }
            SymExpr::ZExt { expr, target_width } => {
                // Compute extend amount
                let inner_smt = self.translate(expr);
                format!("((_ zero_extend {target_width}) {inner_smt})")
            }
            SymExpr::SExt { expr, target_width } => {
                let inner_smt = self.translate(expr);
                format!("((_ sign_extend {target_width}) {inner_smt})")
            }
            SymExpr::Eq(l, r) => format!("(= {} {})", self.translate(l), self.translate(r)),
            SymExpr::Ne(l, r) => {
                format!("(not (= {} {}))", self.translate(l), self.translate(r))
            }
            SymExpr::ULt(l, r) => format!("(bvult {} {})", self.translate(l), self.translate(r)),
            SymExpr::ULe(l, r) => format!("(bvule {} {})", self.translate(l), self.translate(r)),
            SymExpr::UGt(l, r) => format!("(bvugt {} {})", self.translate(l), self.translate(r)),
            SymExpr::UGe(l, r) => format!("(bvuge {} {})", self.translate(l), self.translate(r)),
            SymExpr::SLt(l, r) => format!("(bvslt {} {})", self.translate(l), self.translate(r)),
            SymExpr::SLe(l, r) => format!("(bvsle {} {})", self.translate(l), self.translate(r)),
            SymExpr::SGt(l, r) => format!("(bvsgt {} {})", self.translate(l), self.translate(r)),
            SymExpr::SGe(l, r) => format!("(bvsge {} {})", self.translate(l), self.translate(r)),
            SymExpr::BoolAnd(l, r) => {
                format!("(and {} {})", self.translate(l), self.translate(r))
            }
            SymExpr::BoolOr(l, r) => format!("(or {} {})", self.translate(l), self.translate(r)),
            SymExpr::BoolNot(e) => format!("(not {})", self.translate(e)),
            SymExpr::Ite { cond, then_, else_ } => {
                format!(
                    "(ite {} {} {})",
                    self.translate(cond),
                    self.translate(then_),
                    self.translate(else_)
                )
            }
            SymExpr::Load { addr, size } => {
                format!("(select mem{}b {})", size, self.translate(addr))
            }
            SymExpr::Store { mem, addr, val } => {
                format!(
                    "(store {} {} {})",
                    self.translate(mem),
                    self.translate(addr),
                    self.translate(val)
                )
            }
        }
    }

    /// Build a complete [`SmtFormula`] from a list of path constraints.
    #[must_use]
    pub fn build_formula(&mut self, constraints: &[SymExpr]) -> SmtFormula {
        // Translate all constraints first so that self.vars is fully populated
        // before we start declaring variables.
        let translated: Vec<String> = constraints.iter().map(|e| self.translate(e)).collect();

        let mut formula = SmtFormula::new(SmtLogic::QfBv);

        // Collect unique variable widths
        let mut seen: HashSet<&str> = HashSet::with_capacity(self.vars.len());
        for (name, width) in &self.vars {
            if seen.insert(name.as_str()) {
                if *width == 0 {
                    formula.declare(name, SmtSort::Bool);
                } else {
                    formula.declare(name, SmtSort::BitVec(*width));
                }
            }
        }

        for t in translated {
            formula.assert(t);
        }
        formula
    }
}

// ---------------------------------------------------------------------------
// SymType → SmtSort helpers
// ---------------------------------------------------------------------------

/// Convert a [`SymType`] to an [`SmtSort`].
#[must_use]
pub fn sym_type_to_sort(ty: &SymType) -> SmtSort {
    match ty {
        SymType::Bool => SmtSort::Bool,
        SymType::BitVec(w) => SmtSort::BitVec(*w),
        SymType::Pointer => SmtSort::BitVec(64),
        SymType::Array { elem_ty, .. } => SmtSort::Array(
            Box::new(SmtSort::BitVec(64)),
            Box::new(sym_type_to_sort(elem_ty)),
        ),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SymExpr, SymType};

    fn bv(val: u64, w: u32) -> SymExpr {
        SymExpr::ConstBv { val, width: w }
    }

    fn var(n: &str) -> SymExpr {
        SymExpr::var(n, SymType::BitVec(64))
    }

    fn var32(n: &str) -> SymExpr {
        SymExpr::var(n, SymType::BitVec(32))
    }

    fn translator() -> ExprToSmtLib {
        ExprToSmtLib::new()
    }

    #[test]
    fn test_translate_const_bv() {
        let mut t = translator();
        assert_eq!(t.translate(&bv(42, 32)), "(_ bv42 32)");
    }

    #[test]
    fn test_translate_const_bool_true() {
        let mut t = translator();
        assert_eq!(t.translate(&SymExpr::ConstBool(true)), "true");
    }

    #[test]
    fn test_translate_const_bool_false() {
        let mut t = translator();
        assert_eq!(t.translate(&SymExpr::ConstBool(false)), "false");
    }

    #[test]
    fn test_translate_var() {
        let mut t = translator();
        let out = t.translate(&var("x"));
        assert_eq!(out, "x");
        assert_eq!(t.vars.len(), 1);
        assert_eq!(t.vars[0].0, "x");
        assert_eq!(t.vars[0].1, 64);
    }

    #[test]
    fn test_translate_add() {
        let mut t = translator();
        let e = SymExpr::add_expr(var("x"), bv(1, 64));
        let out = t.translate(&e);
        assert!(out.contains("bvadd"));
        assert!(out.contains('x'));
        assert!(out.contains("bv1"));
    }

    #[test]
    fn test_translate_sub() {
        let mut t = translator();
        let out = t.translate(&SymExpr::sub_expr(var("a"), bv(2, 64)));
        assert!(out.contains("bvsub"));
    }

    #[test]
    fn test_translate_eq() {
        let mut t = translator();
        let out = t.translate(&SymExpr::eq(var("x"), bv(0, 64)));
        assert!(out.starts_with("(="));
    }

    #[test]
    fn test_translate_ne() {
        let mut t = translator();
        let out = t.translate(&SymExpr::Ne(Box::new(var("x")), Box::new(bv(0, 64))));
        assert!(out.contains("not"));
        assert!(out.contains('='));
    }

    #[test]
    fn test_translate_bool_and() {
        let mut t = translator();
        let e = SymExpr::BoolAnd(
            Box::new(SymExpr::ConstBool(true)),
            Box::new(SymExpr::ConstBool(false)),
        );
        let out = t.translate(&e);
        assert!(out.starts_with("(and"));
    }

    #[test]
    fn test_translate_ite() {
        let mut t = translator();
        let e = SymExpr::ite(SymExpr::ConstBool(true), bv(1, 32), bv(2, 32));
        let out = t.translate(&e);
        assert!(out.starts_with("(ite"));
    }

    #[test]
    fn test_translate_extract() {
        let mut t = translator();
        let e = SymExpr::Extract {
            expr: Box::new(var32("y")),
            hi: 7,
            lo: 0,
        };
        let out = t.translate(&e);
        assert!(out.contains("extract"));
        assert!(out.contains('7'));
        assert!(out.contains('0'));
    }

    #[test]
    fn test_translate_zext() {
        let mut t = translator();
        let e = SymExpr::ZExt {
            expr: Box::new(bv(0xFF, 8)),
            target_width: 32,
        };
        let out = t.translate(&e);
        assert!(out.contains("zero_extend"));
    }

    #[test]
    fn test_translate_sext() {
        let mut t = translator();
        let e = SymExpr::SExt {
            expr: Box::new(bv(0xFF, 8)),
            target_width: 32,
        };
        let out = t.translate(&e);
        assert!(out.contains("sign_extend"));
    }

    #[test]
    fn test_translate_concat() {
        let mut t = translator();
        let e = SymExpr::Concat(Box::new(bv(0xAB, 8)), Box::new(bv(0xCD, 8)));
        let out = t.translate(&e);
        assert!(out.contains("concat"));
    }

    #[test]
    fn test_build_formula_collects_vars() {
        let mut t = translator();
        let constraints = vec![
            SymExpr::eq(var("x"), bv(42, 64)),
            SymExpr::ULt(Box::new(var("y")), Box::new(bv(100, 64))),
        ];
        let formula = t.build_formula(&constraints);
        assert_eq!(formula.assertion_count(), 2);
        assert_eq!(formula.declaration_count(), 2);
    }

    #[test]
    fn test_formula_to_smtlib() {
        let mut formula = SmtFormula::new(SmtLogic::QfBv);
        formula.declare("x", SmtSort::BitVec(32));
        formula.assert("(= x (_ bv0 32))");
        let s = formula.to_smtlib();
        assert!(s.contains("QF_BV"));
        assert!(s.contains("declare-const"));
        assert!(s.contains("check-sat"));
        assert!(s.contains("get-model"));
    }

    #[test]
    fn test_smt_sort_bitvec_display() {
        assert_eq!(SmtSort::BitVec(32).to_smtlib(), "(_ BitVec 32)");
    }

    #[test]
    fn test_smt_sort_bool_display() {
        assert_eq!(SmtSort::Bool.to_smtlib(), "Bool");
    }

    #[test]
    fn test_smt_sort_array_display() {
        let s = SmtSort::Array(Box::new(SmtSort::BitVec(64)), Box::new(SmtSort::BitVec(8)));
        assert_eq!(s.to_smtlib(), "(Array (_ BitVec 64) (_ BitVec 8))");
    }

    #[test]
    fn test_smt_logic_display() {
        assert_eq!(SmtLogic::QfBv.as_str(), "QF_BV");
        assert_eq!(SmtLogic::QfAbv.as_str(), "QF_ABV");
        assert_eq!(SmtLogic::All.as_str(), "ALL");
    }

    #[test]
    fn test_sym_type_to_sort_bool() {
        assert_eq!(sym_type_to_sort(&SymType::Bool), SmtSort::Bool);
    }

    #[test]
    fn test_sym_type_to_sort_bitvec() {
        assert_eq!(sym_type_to_sort(&SymType::BitVec(16)), SmtSort::BitVec(16));
    }

    #[test]
    fn test_sym_type_to_sort_pointer() {
        assert_eq!(sym_type_to_sort(&SymType::Pointer), SmtSort::BitVec(64));
    }

    #[test]
    fn test_formula_display() {
        let formula = SmtFormula::new(SmtLogic::QfBv);
        let s = formula.to_string();
        assert!(s.contains("QF_BV"));
    }

    #[test]
    fn test_formula_serialization() {
        let formula = SmtFormula::new(SmtLogic::QfBv);
        let json = serde_json::to_string(&formula).unwrap();
        let decoded: SmtFormula = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.logic, SmtLogic::QfBv);
    }

    #[test]
    fn test_translate_not() {
        let mut t = translator();
        let e = SymExpr::Not(Box::new(bv(0xFF, 8)));
        let out = t.translate(&e);
        assert!(out.contains("bvnot"));
    }

    #[test]
    fn test_translate_neg() {
        let mut t = translator();
        let e = SymExpr::Neg(Box::new(bv(1, 32)));
        let out = t.translate(&e);
        assert!(out.contains("bvneg"));
    }

    #[test]
    fn test_var_deduplication_in_formula() {
        let mut t = translator();
        // Same variable used twice — should only be declared once
        let constraints = vec![
            SymExpr::eq(var("z"), bv(0, 64)),
            SymExpr::UGt(Box::new(var("z")), Box::new(bv(0, 64))),
        ];
        let formula = t.build_formula(&constraints);
        assert_eq!(formula.declaration_count(), 1);
    }

    #[test]
    fn test_translate_udiv() {
        let mut t = translator();
        let out = t.translate(&SymExpr::UDiv(Box::new(var("a")), Box::new(bv(4, 64))));
        assert!(out.contains("bvudiv"));
    }
}
