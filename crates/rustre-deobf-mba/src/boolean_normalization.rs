//! `boolean_normalization` — Conversion from MBA to pure Boolean, NNF/CNF/DNF,
//! BDD-based simplification, XOR splitting, and AND-OR balancing.

use crate::MbaExpr;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Boolean literal and clause types
// ─────────────────────────────────────────────────────────────────────────────

/// A Boolean literal: a variable or its negation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Literal {
    pub var: String,
    pub negated: bool,
}

impl Literal {
    #[must_use]
    pub fn pos(var: impl Into<String>) -> Self {
        Self { var: var.into(), negated: false }
    }

    #[must_use]
    pub fn neg(var: impl Into<String>) -> Self {
        Self { var: var.into(), negated: true }
    }

    #[must_use]
    pub fn negate(&self) -> Self {
        Self { var: self.var.clone(), negated: !self.negated }
    }

    #[must_use]
    pub fn display(&self) -> String {
        if self.negated {
            format!("~{}", self.var)
        } else {
            self.var.clone()
        }
    }
}

/// A disjunctive clause (OR of literals).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Clause {
    pub literals: Vec<Literal>,
}

impl Clause {
    #[must_use]
    pub fn unit(lit: Literal) -> Self {
        Self { literals: vec![lit] }
    }

    #[must_use]
    pub fn is_tautology(&self) -> bool {
        // A clause is a tautology if it contains both x and ~x
        for lit in &self.literals {
            if self.literals.contains(&lit.negate()) {
                return true;
            }
        }
        false
    }

    #[must_use]
    pub fn display(&self) -> String {
        self.literals.iter().map(Literal::display).collect::<Vec<_>>().join(" | ")
    }
}

/// A CNF formula: AND of clauses.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CnfFormula {
    pub clauses: Vec<Clause>,
}

impl CnfFormula {
    /// Remove tautological clauses.
    pub fn simplify(&mut self) {
        self.clauses.retain(|c| !c.is_tautology());
    }

    #[must_use]
    pub fn display(&self) -> String {
        self.clauses
            .iter()
            .map(|c| format!("({})", c.display()))
            .collect::<Vec<_>>()
            .join(" & ")
    }
}

/// A DNF formula: OR of conjunctive terms.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnfFormula {
    pub terms: Vec<Vec<Literal>>,
}

impl DnfFormula {
    #[must_use]
    pub fn display(&self) -> String {
        self.terms
            .iter()
            .map(|t| {
                format!(
                    "({})",
                    t.iter().map(Literal::display).collect::<Vec<_>>().join(" & ")
                )
            })
            .collect::<Vec<_>>()
            .join(" | ")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BDD (Binary Decision Diagram) — simplified
// ─────────────────────────────────────────────────────────────────────────────

/// Node in a Reduced Ordered BDD.
#[derive(Debug, Clone)]
pub enum BddNode {
    /// Terminal FALSE leaf.
    False,
    /// Terminal TRUE leaf.
    True,
    /// Decision node: if `var` is true go `high`, else go `low`.
    Node {
        var: String,
        low: Box<Self>,
        high: Box<Self>,
    },
}

impl BddNode {
    /// Evaluate the BDD given a variable assignment.
    #[must_use]
    pub fn eval(&self, assignment: &HashMap<String, bool>) -> bool {
        match self {
            Self::False => false,
            Self::True => true,
            Self::Node { var, low, high } => {
                let val = assignment.get(var).copied().unwrap_or(false);
                if val { high.eval(assignment) } else { low.eval(assignment) }
            }
        }
    }

    /// Count nodes (for complexity measurement).
    #[must_use]
    pub fn size(&self) -> usize {
        match self {
            Self::False | Self::True => 1,
            Self::Node { low, high, .. } => 1 + low.size() + high.size(),
        }
    }

    /// Apply Shannon expansion to build BDD from an MBA expression.
    #[must_use]
    pub fn from_expr(expr: &MbaExpr, variable_order: &[String]) -> Self {
        if variable_order.is_empty() {
            // Base: evaluate constant
            return match expr {
                MbaExpr::Const(0) => Self::False,
                MbaExpr::Const(_) => Self::True,
                _ => Self::False, // conservative
            };
        }

        let var = &variable_order[0];
        let rest = &variable_order[1..];

        let low_expr = substitute(expr, var, false);
        let high_expr = substitute(expr, var, true);

        let low = Self::from_expr(&low_expr, rest);
        let high = Self::from_expr(&high_expr, rest);

        // Reduce: if low == high, eliminate this node
        if format!("{low:?}") == format!("{high:?}") {
            return low;
        }

        Self::Node {
            var: var.clone(),
            low: Box::new(low),
            high: Box::new(high),
        }
    }
}

/// Substitute `var = value` into an expression (for BDD Shannon expansion).
fn substitute(expr: &MbaExpr, var: &str, value: bool) -> MbaExpr {
    let val = if value { MbaExpr::Const(1) } else { MbaExpr::Const(0) };
    match expr {
        MbaExpr::Var(v) if v == var => val,
        MbaExpr::Not(e) => MbaExpr::Not(Box::new(substitute(e, var, value))),
        MbaExpr::Neg(e) => MbaExpr::Neg(Box::new(substitute(e, var, value))),
        MbaExpr::And(a, b) => MbaExpr::And(
            Box::new(substitute(a, var, value)),
            Box::new(substitute(b, var, value)),
        ),
        MbaExpr::Or(a, b) => MbaExpr::Or(
            Box::new(substitute(a, var, value)),
            Box::new(substitute(b, var, value)),
        ),
        MbaExpr::Xor(a, b) => MbaExpr::Xor(
            Box::new(substitute(a, var, value)),
            Box::new(substitute(b, var, value)),
        ),
        MbaExpr::Add(a, b) => MbaExpr::Add(
            Box::new(substitute(a, var, value)),
            Box::new(substitute(b, var, value)),
        ),
        MbaExpr::Sub(a, b) => MbaExpr::Sub(
            Box::new(substitute(a, var, value)),
            Box::new(substitute(b, var, value)),
        ),
        MbaExpr::Mul(a, b) => MbaExpr::Mul(
            Box::new(substitute(a, var, value)),
            Box::new(substitute(b, var, value)),
        ),
        MbaExpr::Shl(e, n) => MbaExpr::Shl(Box::new(substitute(e, var, value)), *n),
        MbaExpr::Shr(e, n) => MbaExpr::Shr(Box::new(substitute(e, var, value)), *n),
        _ => expr.clone(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NNF converter
// ─────────────────────────────────────────────────────────────────────────────

/// Convert an expression to Negation Normal Form (negations pushed inward).
#[must_use]
pub fn to_nnf(expr: MbaExpr) -> MbaExpr {
    match expr {
        // Push NOT inward using De Morgan's laws
        MbaExpr::Not(inner) => match *inner {
            MbaExpr::Not(e) => to_nnf(*e), // double negation
            MbaExpr::And(a, b) => MbaExpr::Or(
                Box::new(to_nnf(MbaExpr::Not(a))),
                Box::new(to_nnf(MbaExpr::Not(b))),
            ),
            MbaExpr::Or(a, b) => MbaExpr::And(
                Box::new(to_nnf(MbaExpr::Not(a))),
                Box::new(to_nnf(MbaExpr::Not(b))),
            ),
            other => MbaExpr::Not(Box::new(to_nnf(other))),
        },
        MbaExpr::And(a, b) => MbaExpr::And(Box::new(to_nnf(*a)), Box::new(to_nnf(*b))),
        MbaExpr::Or(a, b) => MbaExpr::Or(Box::new(to_nnf(*a)), Box::new(to_nnf(*b))),
        MbaExpr::Xor(a, b) => {
            // x XOR y = (x | y) & (~x | ~y)
            let a_nnf = to_nnf(*a);
            let b_nnf = to_nnf(*b);
            MbaExpr::And(
                Box::new(MbaExpr::Or(Box::new(a_nnf.clone()), Box::new(b_nnf.clone()))),
                Box::new(MbaExpr::Or(
                    Box::new(MbaExpr::Not(Box::new(a_nnf))),
                    Box::new(MbaExpr::Not(Box::new(b_nnf))),
                )),
            )
        }
        other => other,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CNF converter (Tseitin-style)
// ─────────────────────────────────────────────────────────────────────────────

/// Convert an expression (already in NNF) to CNF via distribution.
///
/// Note: this is exponential in the worst case; use Tseitin for large formulae.
#[must_use]
pub fn nnf_to_cnf(expr: &MbaExpr) -> CnfFormula {
    match expr {
        MbaExpr::Var(v) => CnfFormula {
            clauses: vec![Clause::unit(Literal::pos(v))],
        },
        MbaExpr::Not(e) => {
            if let MbaExpr::Var(v) = e.as_ref() {
                CnfFormula {
                    clauses: vec![Clause::unit(Literal::neg(v))],
                }
            } else {
                CnfFormula::default()
            }
        }
        MbaExpr::And(a, b) => {
            let mut cnf_a = nnf_to_cnf(a);
            let cnf_b = nnf_to_cnf(b);
            cnf_a.clauses.extend(cnf_b.clauses);
            cnf_a
        }
        MbaExpr::Or(a, b) => {
            let cnf_a = nnf_to_cnf(a);
            let cnf_b = nnf_to_cnf(b);
            // Distribute: (A1 & A2 & …) | (B1 & B2 & …) = all combinations
            let mut result = CnfFormula::default();
            for ca in &cnf_a.clauses {
                for cb in &cnf_b.clauses {
                    let mut lits = ca.literals.clone();
                    lits.extend_from_slice(&cb.literals);
                    lits.dedup();
                    result.clauses.push(Clause { literals: lits });
                }
            }
            result
        }
        _ => CnfFormula::default(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DNF converter
// ─────────────────────────────────────────────────────────────────────────────

/// Convert an expression (already in NNF) to DNF.
#[must_use]
pub fn nnf_to_dnf(expr: &MbaExpr) -> DnfFormula {
    match expr {
        MbaExpr::Var(v) => DnfFormula {
            terms: vec![vec![Literal::pos(v)]],
        },
        MbaExpr::Not(e) => {
            if let MbaExpr::Var(v) = e.as_ref() {
                DnfFormula {
                    terms: vec![vec![Literal::neg(v)]],
                }
            } else {
                DnfFormula::default()
            }
        }
        MbaExpr::Or(a, b) => {
            let mut dnf_a = nnf_to_dnf(a);
            let dnf_b = nnf_to_dnf(b);
            dnf_a.terms.extend(dnf_b.terms);
            dnf_a
        }
        MbaExpr::And(a, b) => {
            let dnf_a = nnf_to_dnf(a);
            let dnf_b = nnf_to_dnf(b);
            let mut result = DnfFormula::default();
            for ta in &dnf_a.terms {
                for tb in &dnf_b.terms {
                    let mut term = ta.clone();
                    term.extend_from_slice(tb);
                    term.dedup();
                    result.terms.push(term);
                }
            }
            result
        }
        _ => DnfFormula::default(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XOR splitter
// ─────────────────────────────────────────────────────────────────────────────

/// Split XOR expressions into equivalent AND/OR/NOT forms for easier analysis.
#[must_use]
pub fn split_xor(expr: MbaExpr) -> MbaExpr {
    match expr {
        MbaExpr::Xor(a, b) => {
            // x ^ y = (x | y) & ~(x & y)
            let a2 = split_xor(*a);
            let b2 = split_xor(*b);
            MbaExpr::And(
                Box::new(MbaExpr::Or(Box::new(a2.clone()), Box::new(b2.clone()))),
                Box::new(MbaExpr::Not(Box::new(MbaExpr::And(
                    Box::new(a2),
                    Box::new(b2),
                )))),
            )
        }
        MbaExpr::And(a, b) => MbaExpr::And(Box::new(split_xor(*a)), Box::new(split_xor(*b))),
        MbaExpr::Or(a, b) => MbaExpr::Or(Box::new(split_xor(*a)), Box::new(split_xor(*b))),
        MbaExpr::Not(e) => MbaExpr::Not(Box::new(split_xor(*e))),
        other => other,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AND-OR balancer
// ─────────────────────────────────────────────────────────────────────────────

/// Collect all operands of a flat AND/OR chain.
fn collect_and_operands(expr: &MbaExpr) -> Vec<MbaExpr> {
    match expr {
        MbaExpr::And(a, b) => {
            let mut ops = collect_and_operands(a);
            ops.extend(collect_and_operands(b));
            ops
        }
        other => vec![other.clone()],
    }
}

fn collect_or_operands(expr: &MbaExpr) -> Vec<MbaExpr> {
    match expr {
        MbaExpr::Or(a, b) => {
            let mut ops = collect_or_operands(a);
            ops.extend(collect_or_operands(b));
            ops
        }
        other => vec![other.clone()],
    }
}

fn build_balanced_and(mut ops: Vec<MbaExpr>) -> MbaExpr {
    if ops.len() == 1 {
        return ops.remove(0);
    }
    if ops.len() == 2 {
        let b = ops.remove(1);
        let a = ops.remove(0);
        return MbaExpr::And(Box::new(a), Box::new(b));
    }
    let mid = ops.len() / 2;
    let right = ops.split_off(mid);
    MbaExpr::And(
        Box::new(build_balanced_and(ops)),
        Box::new(build_balanced_and(right)),
    )
}

fn build_balanced_or(mut ops: Vec<MbaExpr>) -> MbaExpr {
    if ops.len() == 1 {
        return ops.remove(0);
    }
    if ops.len() == 2 {
        let b = ops.remove(1);
        let a = ops.remove(0);
        return MbaExpr::Or(Box::new(a), Box::new(b));
    }
    let mid = ops.len() / 2;
    let right = ops.split_off(mid);
    MbaExpr::Or(
        Box::new(build_balanced_or(ops)),
        Box::new(build_balanced_or(right)),
    )
}

/// Balance deeply nested AND/OR chains into a balanced binary tree.
#[must_use]
pub fn balance_and_or(expr: MbaExpr) -> MbaExpr {
    match expr {
        MbaExpr::And(_, _) => {
            let ops: Vec<MbaExpr> = collect_and_operands(&expr)
                .into_iter()
                .map(balance_and_or)
                .collect();
            build_balanced_and(ops)
        }
        MbaExpr::Or(_, _) => {
            let ops: Vec<MbaExpr> = collect_or_operands(&expr)
                .into_iter()
                .map(balance_and_or)
                .collect();
            build_balanced_or(ops)
        }
        MbaExpr::Not(e) => MbaExpr::Not(Box::new(balance_and_or(*e))),
        MbaExpr::Xor(a, b) => {
            MbaExpr::Xor(Box::new(balance_and_or(*a)), Box::new(balance_and_or(*b)))
        }
        other => other,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BooleanNormalizer — high-level API
// ─────────────────────────────────────────────────────────────────────────────

/// Result of Boolean normalisation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizationResult {
    pub is_pure_boolean: bool,
    pub cnf: Option<String>,
    pub dnf: Option<String>,
    pub bdd_size: Option<usize>,
    pub variable_count: usize,
    pub steps: Vec<String>,
}

/// High-level Boolean normaliser.
#[derive(Default)]
pub struct BooleanNormalizer {
    /// Whether to build the BDD (expensive for >15 variables).
    pub build_bdd: bool,
    /// Variable order for BDD construction.
    pub variable_order: Vec<String>,
}


impl BooleanNormalizer {
    /// Normalise the given expression, returning a [`NormalizationResult`].
    #[must_use] 
    pub fn normalize(&self, expr: MbaExpr) -> (MbaExpr, NormalizationResult) {
        let mut steps = Vec::new();

        // Step 1: convert to NNF
        let nnf_expr = to_nnf(expr);
        steps.push("converted to NNF".into());

        // Step 2: split XOR
        let split = split_xor(nnf_expr);
        steps.push("XOR splitting applied".into());

        // Step 3: balance AND/OR
        let balanced = balance_and_or(split);
        steps.push("AND/OR balanced".into());

        // Step 4: CNF
        let cnf = nnf_to_cnf(&balanced);
        let cnf_str = cnf.display();
        steps.push("converted to CNF".into());

        // Step 5: DNF
        let dnf = nnf_to_dnf(&balanced);
        let dnf_str = dnf.display();
        steps.push("converted to DNF".into());

        // Step 6: BDD (optional)
        let bdd_size = if self.build_bdd && !self.variable_order.is_empty() {
            let bdd = BddNode::from_expr(&balanced, &self.variable_order);
            Some(bdd.size())
        } else {
            None
        };

        let variable_count = self.variable_order.len();
        let is_pure_boolean = !contains_arithmetic(&balanced);

        let result = NormalizationResult {
            is_pure_boolean,
            cnf: Some(cnf_str),
            dnf: Some(dnf_str),
            bdd_size,
            variable_count,
            steps,
        };

        (balanced, result)
    }
}

/// Check whether an expression contains arithmetic operations.
fn contains_arithmetic(expr: &MbaExpr) -> bool {
    match expr {
        MbaExpr::Add(_, _) | MbaExpr::Sub(_, _) | MbaExpr::Mul(_, _) | MbaExpr::Neg(_) => true,
        MbaExpr::And(a, b) | MbaExpr::Or(a, b) | MbaExpr::Xor(a, b) => {
            contains_arithmetic(a) || contains_arithmetic(b)
        }
        MbaExpr::Not(e) => contains_arithmetic(e),
        _ => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_de_morgan_and() {
        // NOT (x AND y) should become (NOT x) OR (NOT y)
        let expr = MbaExpr::Not(Box::new(MbaExpr::And(
            Box::new(MbaExpr::Var("x".into())),
            Box::new(MbaExpr::Var("y".into())),
        )));
        let nnf = to_nnf(expr);
        assert!(matches!(nnf, MbaExpr::Or(_, _)));
    }

    #[test]
    fn test_double_negation_nnf() {
        let expr = MbaExpr::Not(Box::new(MbaExpr::Not(Box::new(MbaExpr::Var("x".into())))));
        let nnf = to_nnf(expr);
        assert_eq!(nnf, MbaExpr::Var("x".into()));
    }

    #[test]
    fn test_xor_split() {
        let expr = MbaExpr::Xor(
            Box::new(MbaExpr::Var("x".into())),
            Box::new(MbaExpr::Var("y".into())),
        );
        let split = split_xor(expr);
        // Result should be AND(OR(x,y), NOT(AND(x,y)))
        assert!(matches!(split, MbaExpr::And(_, _)));
    }

    #[test]
    fn test_cnf_and_clause() {
        let expr = MbaExpr::And(
            Box::new(MbaExpr::Var("x".into())),
            Box::new(MbaExpr::Var("y".into())),
        );
        let cnf = nnf_to_cnf(&expr);
        assert_eq!(cnf.clauses.len(), 2);
    }

    #[test]
    fn test_clause_tautology() {
        let clause = Clause {
            literals: vec![Literal::pos("x"), Literal::neg("x")],
        };
        assert!(clause.is_tautology());
    }
}
