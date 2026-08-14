//! Taint propagator: propagate taint through arithmetic, logical, and memory operations.
//!
//! `TaintPropagator` applies `PropagationRule`s to transform a `TaintSet` based on
//! the operation being performed. It handles the conservative semantics (any tainted
//! operand taints the result) as well as sanitizer-aware AND propagation.

use std::collections::HashMap;

use rustre_symb::symbolic_state::SymbolicState;
use serde::{Deserialize, Serialize};

use crate::{TaintId, TaintLocation, PropagationOp, taint_bits};

// ─── TaintTransfer ───────────────────────────────────────────────────────────

/// Result of applying a propagation rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintTransfer {
    /// The destination location that receives taint.
    pub destination: TaintLocation,
    /// The taint mask written to the destination.
    pub result_taint: TaintId,
    /// Which operand taints were involved.
    pub operand_taints: Vec<TaintId>,
    /// The operation that was applied.
    pub operation: PropagationOp,
    /// Whether the transfer was sanitized.
    pub sanitized: bool,
}

impl TaintTransfer {
    pub fn new(dest: TaintLocation, result: TaintId, op: PropagationOp) -> Self {
        Self {
            destination: dest,
            result_taint: result,
            operand_taints: Vec::new(),
            operation: op,
            sanitized: result == taint_bits::NONE,
        }
    }

    pub fn is_tainted(&self) -> bool {
        taint_bits::is_tainted(self.result_taint)
    }
}

// ─── PropagationRule ─────────────────────────────────────────────────────────

/// A rule that maps a set of operand taints + operation → result taint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationRule {
    pub name: String,
    /// Which operations this rule applies to.
    pub operations: Vec<PropagationOp>,
    /// Rule kind.
    pub kind: RuleKind,
}

/// The semantic of how the rule combines operand taints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleKind {
    /// Result = union of all operand taints (default for most ops).
    UnionAll,
    /// Result = NONE (sanitizing: output is always clean).
    Sanitize,
    /// Result = union only if the condition operand (index 0) is tainted.
    ConditionalOnFirst,
    /// Result = intersection of all operand taints.
    IntersectAll,
    /// Retain only taint bits that pass through a mask.
    Masked { mask: u64 },
}

impl PropagationRule {
    /// Create a union-all rule covering the given operations.
    pub fn union_all(name: &str, ops: Vec<PropagationOp>) -> Self {
        Self { name: name.into(), operations: ops, kind: RuleKind::UnionAll }
    }

    /// Create a sanitizing rule.
    pub fn sanitize(name: &str, ops: Vec<PropagationOp>) -> Self {
        Self { name: name.into(), operations: ops, kind: RuleKind::Sanitize }
    }

    /// Create a masked propagation rule.
    pub fn masked(name: &str, ops: Vec<PropagationOp>, mask: u64) -> Self {
        Self { name: name.into(), operations: ops, kind: RuleKind::Masked { mask } }
    }

    /// Return true if this rule applies to the given operation.
    pub fn applies_to(&self, op: PropagationOp) -> bool {
        self.operations.contains(&op)
    }

    /// Apply the rule to a list of operand taints.
    pub fn apply(&self, operands: &[TaintId]) -> TaintId {
        match &self.kind {
            RuleKind::UnionAll => operands.iter().fold(taint_bits::NONE, |acc, &t| acc | t),
            RuleKind::Sanitize => taint_bits::NONE,
            RuleKind::ConditionalOnFirst => {
                if operands.first().copied().map(taint_bits::is_tainted).unwrap_or(false) {
                    operands.iter().fold(taint_bits::NONE, |acc, &t| acc | t)
                } else {
                    taint_bits::NONE
                }
            }
            RuleKind::IntersectAll => {
                if operands.is_empty() {
                    return taint_bits::NONE;
                }
                operands.iter().fold(taint_bits::ALL, |acc, &t| acc & t)
            }
            RuleKind::Masked { mask } => {
                let union = operands.iter().fold(taint_bits::NONE, |acc, &t| acc | t);
                union & mask
            }
        }
    }
}

// ─── TaintPropagator ─────────────────────────────────────────────────────────

/// Applies propagation rules to compute result taints from operand taints.
///
/// Rules are matched by operation type; the first matching rule wins.
/// Falls back to `UnionAll` semantics if no rule matches.
pub struct TaintPropagator {
    rules: Vec<PropagationRule>,
    /// History of transfers, for auditing.
    history: Vec<TaintTransfer>,
    /// Whether to record history.
    pub record_history: bool,
    /// Count of total propagations performed.
    pub propagation_count: u64,
}

impl TaintPropagator {
    /// Create a propagator with an empty rule set.
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            history: Vec::new(),
            record_history: false,
            propagation_count: 0,
        }
    }

    /// Create a propagator with the standard RustRE ruleset pre-loaded.
    pub fn with_default_rules() -> Self {
        let mut p = Self::new();
        p.load_default_rules();
        p
    }

    /// Add a rule to the propagator.
    pub fn add_rule(&mut self, rule: PropagationRule) {
        self.rules.push(rule);
    }

    /// Propagate taint through an operation.
    ///
    /// * `op` — the LLIL/IR operation being executed.
    /// * `operand_taints` — taint masks of each operand.
    /// * `dest` — where the result is written.
    pub fn propagate(
        &mut self,
        op: PropagationOp,
        operand_taints: &[TaintId],
        dest: TaintLocation,
    ) -> TaintTransfer {
        self.propagation_count += 1;
        let result = self.compute_result(op, operand_taints);
        let mut transfer = TaintTransfer::new(dest, result, op);
        transfer.operand_taints = operand_taints.to_vec();
        if self.record_history {
            self.history.push(transfer.clone());
        }
        transfer
    }

    /// Compute the result taint without recording.
    pub fn compute_result(&self, op: PropagationOp, operand_taints: &[TaintId]) -> TaintId {
        for rule in &self.rules {
            if rule.applies_to(op) {
                return rule.apply(operand_taints);
            }
        }
        // Default: union all operands.
        operand_taints.iter().fold(taint_bits::NONE, |acc, &t| acc | t)
    }

    /// Return the transfer history.
    pub fn history(&self) -> &[TaintTransfer] {
        &self.history
    }

    /// Clear the history.
    pub fn clear_history(&mut self) {
        self.history.clear();
    }

    /// Return rules that match the given operation.
    pub fn rules_for(&self, op: PropagationOp) -> Vec<&PropagationRule> {
        self.rules.iter().filter(|r| r.applies_to(op)).collect()
    }

    /// Load the standard conservative-but-practical RustRE rules.
    fn load_default_rules(&mut self) {
        use PropagationOp::*;
        // Arithmetic: union operands
        self.add_rule(PropagationRule::union_all(
            "arithmetic_union",
            vec![ArithAdd, ArithSub, ArithMul, Shift],
        ));
        // Bitwise OR: union
        self.add_rule(PropagationRule::union_all("bitwise_or", vec![BitwiseOr]));
        // Bitwise AND: conservative union (AND with constant 0 sanitizes, but
        // without concrete-value analysis we cannot prove that).
        self.add_rule(PropagationRule::union_all("bitwise_and", vec![BitwiseAnd]));
        // Assign/Load/Store/Return: union
        self.add_rule(PropagationRule::union_all(
            "data_flow",
            vec![Assign, Load, Store, Return, PhiNode],
        ));
        // Call: union all args (conservative)
        self.add_rule(PropagationRule::union_all("call_union", vec![Call]));
    }

    /// Propagate taint through an operation, but only if the current symbolic
    /// path condition is feasible.
    ///
    /// Uses [`SymbolicState::path_condition`] from `rustre-symb` to detect
    /// trivially infeasible paths (e.g. a branch constraint that is concretely
    /// `false`). On an infeasible path, no taint is propagated and the
    /// destination is left clean, eliminating false positives that would arise
    /// from dead branches in over-approximate analysis.
    ///
    /// Falls back to ordinary [`Self::propagate`] when the path is feasible or
    /// when feasibility cannot be determined without an SMT solver.
    pub fn propagate_with_path_condition(
        &mut self,
        op: PropagationOp,
        operand_taints: &[TaintId],
        dest: TaintLocation,
        state: &SymbolicState,
    ) -> TaintTransfer {
        // If the path condition is trivially false, this branch is dead code —
        // return a clean (untainted) transfer without recording it.
        if state.path_condition.is_trivially_false() {
            return TaintTransfer::new(dest, taint_bits::NONE, op);
        }
        // Path is feasible (or unknown): use standard propagation.
        self.propagate(op, operand_taints, dest)
    }
}

impl Default for TaintPropagator {
    fn default() -> Self {
        Self::new()
    }
}

// ─── DataFlowTaintMap ────────────────────────────────────────────────────────

/// Tracks taint for a set of named locations, updated via a `TaintPropagator`.
pub struct DataFlowTaintMap {
    /// Current taint per location.
    taints: HashMap<TaintLocation, TaintId>,
    propagator: TaintPropagator,
}

impl DataFlowTaintMap {
    pub fn new() -> Self {
        Self {
            taints: HashMap::new(),
            propagator: TaintPropagator::with_default_rules(),
        }
    }

    /// Mark a location as directly tainted.
    pub fn mark_tainted(&mut self, loc: TaintLocation, taint: TaintId) {
        *self.taints.entry(loc).or_insert(taint_bits::NONE) |= taint;
    }

    /// Sanitize a location.
    pub fn sanitize(&mut self, loc: &TaintLocation) {
        if let Some(t) = self.taints.get_mut(loc) {
            *t = taint_bits::NONE;
        }
    }

    /// Return the current taint of a location.
    pub fn taint_of(&self, loc: &TaintLocation) -> TaintId {
        self.taints.get(loc).copied().unwrap_or(taint_bits::NONE)
    }

    /// Return true if the location is tainted.
    pub fn is_tainted(&self, loc: &TaintLocation) -> bool {
        taint_bits::is_tainted(self.taint_of(loc))
    }

    /// Apply an operation: compute result taint from source locations and write to dest.
    pub fn apply_op(
        &mut self,
        op: PropagationOp,
        sources: &[TaintLocation],
        dest: TaintLocation,
    ) -> TaintTransfer {
        let operand_taints: Vec<TaintId> = sources.iter().map(|s| self.taint_of(s)).collect();
        let transfer = self.propagator.propagate(op, &operand_taints, dest.clone());
        *self.taints.entry(dest).or_insert(taint_bits::NONE) |= transfer.result_taint;
        transfer
    }

    /// Return all tainted locations.
    pub fn tainted_locations(&self) -> Vec<TaintLocation> {
        self.taints
            .iter()
            .filter(|&(_, &t)| taint_bits::is_tainted(t))
            .map(|(l, _)| l.clone())
            .collect()
    }

    /// Return total count of tracked locations.
    pub fn location_count(&self) -> usize {
        self.taints.len()
    }

    /// Return the taint map snapshot.
    pub fn snapshot(&self) -> HashMap<TaintLocation, TaintId> {
        self.taints.clone()
    }

    /// Merge another map's taints into this one (union semantics).
    pub fn merge(&mut self, other: &Self) {
        for (loc, &taint) in &other.taints {
            *self.taints.entry(loc.clone()).or_insert(taint_bits::NONE) |= taint;
        }
    }
}

impl Default for DataFlowTaintMap {
    fn default() -> Self {
        Self::new()
    }
}

// ─── TaintPropagationSummary ─────────────────────────────────────────────────

/// Summary statistics of a propagation pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPropagationSummary {
    pub total_propagations: u64,
    pub tainted_locations: usize,
    pub sanitized_locations: usize,
    pub source_bits_seen: TaintId,
}

impl TaintPropagationSummary {
    pub fn from_map(map: &DataFlowTaintMap) -> Self {
        let tainted: Vec<_> = map.taints.values().filter(|&&t| taint_bits::is_tainted(t)).collect();
        let sanitized = map.taints.values().filter(|&&t| !taint_bits::is_tainted(t)).count();
        let source_bits = tainted.iter().fold(taint_bits::NONE, |acc, &&t| acc | t);
        Self {
            total_propagations: map.propagator.propagation_count,
            tainted_locations: tainted.len(),
            sanitized_locations: sanitized,
            source_bits_seen: source_bits,
        }
    }

    pub fn has_taint(&self) -> bool {
        taint_bits::is_tainted(self.source_bits_seen)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(name: &str) -> TaintLocation {
        TaintLocation::Register(name.into())
    }

    fn mem(addr: u64) -> TaintLocation {
        TaintLocation::Memory(addr)
    }

    #[test]
    fn test_rule_union_all() {
        let rule = PropagationRule::union_all("test", vec![PropagationOp::ArithAdd]);
        let result = rule.apply(&[taint_bits::USER_INPUT, taint_bits::NETWORK]);
        assert_eq!(result, taint_bits::USER_INPUT | taint_bits::NETWORK);
    }

    #[test]
    fn test_rule_sanitize() {
        let rule = PropagationRule::sanitize("test", vec![PropagationOp::ArithAdd]);
        let result = rule.apply(&[taint_bits::USER_INPUT]);
        assert_eq!(result, taint_bits::NONE);
    }

    #[test]
    fn test_rule_masked() {
        let rule = PropagationRule::masked("test", vec![PropagationOp::BitwiseAnd], taint_bits::USER_INPUT);
        let result = rule.apply(&[taint_bits::USER_INPUT | taint_bits::NETWORK]);
        assert_eq!(result, taint_bits::USER_INPUT);
        assert!(!taint_bits::has_bit(result, taint_bits::NETWORK));
    }

    #[test]
    fn test_rule_intersect_all() {
        let rule = PropagationRule {
            name: "intersect".into(),
            operations: vec![PropagationOp::BitwiseAnd],
            kind: RuleKind::IntersectAll,
        };
        let result = rule.apply(&[taint_bits::USER_INPUT | taint_bits::NETWORK, taint_bits::NETWORK]);
        assert_eq!(result, taint_bits::NETWORK);
    }

    #[test]
    fn test_rule_applies_to() {
        let rule = PropagationRule::union_all("r", vec![PropagationOp::Assign]);
        assert!(rule.applies_to(PropagationOp::Assign));
        assert!(!rule.applies_to(PropagationOp::ArithAdd));
    }

    #[test]
    fn test_propagator_default_rules_union() {
        let mut p = TaintPropagator::with_default_rules();
        let transfer = p.propagate(
            PropagationOp::ArithAdd,
            &[taint_bits::USER_INPUT, taint_bits::NONE],
            reg("rax"),
        );
        assert_eq!(transfer.result_taint, taint_bits::USER_INPUT);
    }

    #[test]
    fn test_propagator_no_operands() {
        let mut p = TaintPropagator::with_default_rules();
        let transfer = p.propagate(PropagationOp::Assign, &[], reg("rbx"));
        assert_eq!(transfer.result_taint, taint_bits::NONE);
    }

    #[test]
    fn test_propagator_history_recording() {
        let mut p = TaintPropagator::with_default_rules();
        p.record_history = true;
        p.propagate(PropagationOp::Assign, &[taint_bits::FILE], reg("rcx"));
        p.propagate(PropagationOp::ArithAdd, &[taint_bits::NETWORK], reg("rdx"));
        assert_eq!(p.history().len(), 2);
        p.clear_history();
        assert!(p.history().is_empty());
    }

    #[test]
    fn test_propagator_count() {
        let mut p = TaintPropagator::with_default_rules();
        for _ in 0..10 {
            p.propagate(PropagationOp::Assign, &[taint_bits::USER_INPUT], reg("rax"));
        }
        assert_eq!(p.propagation_count, 10);
    }

    #[test]
    fn test_propagator_custom_rule_first_wins() {
        let mut p = TaintPropagator::new();
        // Add sanitize rule before union rule
        p.add_rule(PropagationRule::sanitize("sanitize_add", vec![PropagationOp::ArithAdd]));
        p.add_rule(PropagationRule::union_all("union_add", vec![PropagationOp::ArithAdd]));
        let result = p.compute_result(PropagationOp::ArithAdd, &[taint_bits::USER_INPUT]);
        assert_eq!(result, taint_bits::NONE); // sanitize wins
    }

    #[test]
    fn test_dataflow_map_mark_and_query() {
        let mut map = DataFlowTaintMap::new();
        map.mark_tainted(reg("rax"), taint_bits::USER_INPUT);
        assert!(map.is_tainted(&reg("rax")));
        assert!(!map.is_tainted(&reg("rbx")));
    }

    #[test]
    fn test_dataflow_map_sanitize() {
        let mut map = DataFlowTaintMap::new();
        map.mark_tainted(reg("rdi"), taint_bits::NETWORK);
        map.sanitize(&reg("rdi"));
        assert!(!map.is_tainted(&reg("rdi")));
    }

    #[test]
    fn test_dataflow_map_apply_op_propagates() {
        let mut map = DataFlowTaintMap::new();
        map.mark_tainted(reg("rax"), taint_bits::USER_INPUT);
        map.apply_op(PropagationOp::Assign, &[reg("rax")], reg("rbx"));
        assert!(map.is_tainted(&reg("rbx")));
        assert_eq!(map.taint_of(&reg("rbx")), taint_bits::USER_INPUT);
    }

    #[test]
    fn test_dataflow_map_merge() {
        let mut a = DataFlowTaintMap::new();
        let mut b = DataFlowTaintMap::new();
        a.mark_tainted(reg("rax"), taint_bits::USER_INPUT);
        b.mark_tainted(reg("rbx"), taint_bits::NETWORK);
        a.merge(&b);
        assert!(a.is_tainted(&reg("rax")));
        assert!(a.is_tainted(&reg("rbx")));
    }

    #[test]
    fn test_dataflow_map_tainted_locations() {
        let mut map = DataFlowTaintMap::new();
        map.mark_tainted(reg("rax"), taint_bits::USER_INPUT);
        map.mark_tainted(mem(0x1000), taint_bits::FILE);
        map.mark_tainted(reg("rbx"), taint_bits::NONE);
        let tainted = map.tainted_locations();
        assert_eq!(tainted.len(), 2);
    }

    #[test]
    fn test_taint_transfer_is_tainted() {
        let t = TaintTransfer::new(reg("rax"), taint_bits::USER_INPUT, PropagationOp::Assign);
        assert!(t.is_tainted());
        let clean = TaintTransfer::new(reg("rbx"), taint_bits::NONE, PropagationOp::Assign);
        assert!(!clean.is_tainted());
    }

    #[test]
    fn test_propagation_summary() {
        let mut map = DataFlowTaintMap::new();
        map.mark_tainted(reg("rax"), taint_bits::USER_INPUT);
        map.mark_tainted(reg("rbx"), taint_bits::NONE);
        let summary = TaintPropagationSummary::from_map(&map);
        assert_eq!(summary.tainted_locations, 1);
        assert!(summary.has_taint());
        assert_eq!(summary.source_bits_seen, taint_bits::USER_INPUT);
    }
}
