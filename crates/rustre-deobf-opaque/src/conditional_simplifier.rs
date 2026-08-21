//! Opaque conditional simplifier.
//!
//! Consumes the output of the [`predicate_evaluator`] and replaces
//! always-true / always-false conditional branches with unconditional jumps or
//! NOPs, exposing the *live* branch and marking the *dead* branch for removal.
//!
//! The simplifier works on a lightweight basic-block representation.  It does
//! not depend on any external IR library; callers supply blocks as
//! `ConditionalBranch` descriptors and receive `SimplifyResult` values.

use std::collections::HashMap;
use std::fmt;

use crate::predicate_evaluator::{AlwaysFalse, AlwaysTrue, PredicateResult};

// ── DeadBranch ────────────────────────────────────────────────────────────────

/// Identifies a branch that will never be taken.
#[derive(Debug, Clone)]
pub struct DeadBranch {
    /// Address of the conditional branch instruction.
    pub branch_address: u64,
    /// Target address of the dead (never-taken) branch.
    pub dead_target: u64,
    /// Target address of the live (always-taken) branch.
    pub live_target: u64,
    /// Human-readable reason.
    pub reason: String,
}

impl fmt::Display for DeadBranch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DeadBranch @ {:#x}: dead={:#x} live={:#x} ({})",
            self.branch_address, self.dead_target, self.live_target, self.reason
        )
    }
}

// ── SimplifyResult ────────────────────────────────────────────────────────────

/// The outcome of simplifying one conditional branch.
#[derive(Debug, Clone)]
pub enum SimplifyResult {
    /// The branch was always taken; the false-target is dead.
    AlwaysTaken {
        /// Witness from the predicate evaluator.
        witness: AlwaysTrue,
        /// The dead (false) target.
        dead_branch: DeadBranch,
    },
    /// The branch was never taken; the true-target is dead.
    NeverTaken {
        /// Witness from the predicate evaluator.
        witness: AlwaysFalse,
        /// The dead (true) target.
        dead_branch: DeadBranch,
    },
    /// Cannot be simplified; predicate is indeterminate.
    Indeterminate {
        /// Address of the branch.
        branch_address: u64,
    },
}

impl SimplifyResult {
    /// Returns `true` if the branch was simplified.
    #[must_use]
    pub const fn is_simplified(&self) -> bool {
        matches!(self, Self::AlwaysTaken { .. } | Self::NeverTaken { .. })
    }

    /// Return the live branch target, if determined.
    #[must_use]
    pub const fn live_branch(&self) -> Option<u64> {
        match self {
            Self::AlwaysTaken { dead_branch, .. } | Self::NeverTaken { dead_branch, .. } => Some(dead_branch.live_target),
            Self::Indeterminate { .. } => None,
        }
    }

    /// Return the dead branch target, if determined.
    #[must_use]
    pub const fn dead_target(&self) -> Option<u64> {
        match self {
            Self::AlwaysTaken { dead_branch, .. } | Self::NeverTaken { dead_branch, .. } => {
                Some(dead_branch.dead_target)
            }
            Self::Indeterminate { .. } => None,
        }
    }
}

impl fmt::Display for SimplifyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlwaysTaken { dead_branch, .. } => {
                write!(f, "AlwaysTaken: {dead_branch}")
            }
            Self::NeverTaken { dead_branch, .. } => {
                write!(f, "NeverTaken: {dead_branch}")
            }
            Self::Indeterminate { branch_address } => {
                write!(f, "Indeterminate @ {branch_address:#x}")
            }
        }
    }
}

// ── ConditionalBranch ─────────────────────────────────────────────────────────

/// A conditional branch site to be simplified.
#[derive(Debug, Clone)]
pub struct ConditionalBranch {
    /// Address of the branch instruction.
    pub address: u64,
    /// Target when the condition is true (branch taken).
    pub true_target: u64,
    /// Target when the condition is false (fall-through).
    pub false_target: u64,
    /// Pre-evaluated predicate result (from the predicate evaluator).
    pub predicate: PredicateResult,
    /// Optional explanation from the evaluator.
    pub predicate_reason: Option<String>,
}

// ── ConditionalSimplifier ─────────────────────────────────────────────────────

/// Simplifies a set of conditional branches based on opaque predicate results.
///
/// Keeps track of which branches were simplified and records the set of dead
/// targets for downstream passes.
pub struct ConditionalSimplifier {
    /// Results keyed by branch address.
    results: HashMap<u64, SimplifyResult>,
    /// Addresses identified as dead branch targets.
    dead_targets: Vec<u64>,
    /// Number of branches simplified.
    simplified_count: usize,
    /// Number of indeterminate branches.
    indeterminate_count: usize,
}

impl ConditionalSimplifier {
    /// Create a new, empty simplifier.
    #[must_use]
    pub fn new() -> Self {
        Self {
            results: HashMap::new(),
            dead_targets: Vec::new(),
            simplified_count: 0,
            indeterminate_count: 0,
        }
    }

    /// Simplify a single conditional branch and store the result.
    pub fn simplify_branch(&mut self, branch: &ConditionalBranch) -> &SimplifyResult {
        let result = match branch.predicate {
            PredicateResult::AlwaysTrue => {
                let reason = branch
                    .predicate_reason
                    .clone()
                    .unwrap_or_else(|| "opaque predicate always true".to_owned());
                let dead = DeadBranch {
                    branch_address: branch.address,
                    dead_target: branch.false_target,
                    live_target: branch.true_target,
                    reason: reason.clone(),
                };
                self.dead_targets.push(branch.false_target);
                self.simplified_count += 1;
                SimplifyResult::AlwaysTaken {
                    witness: AlwaysTrue {
                        reason,
                        branch_address: branch.address,
                    },
                    dead_branch: dead,
                }
            }
            PredicateResult::AlwaysFalse => {
                let reason = branch
                    .predicate_reason
                    .clone()
                    .unwrap_or_else(|| "opaque predicate always false".to_owned());
                let dead = DeadBranch {
                    branch_address: branch.address,
                    dead_target: branch.true_target,
                    live_target: branch.false_target,
                    reason: reason.clone(),
                };
                self.dead_targets.push(branch.true_target);
                self.simplified_count += 1;
                SimplifyResult::NeverTaken {
                    witness: AlwaysFalse {
                        reason,
                        branch_address: branch.address,
                    },
                    dead_branch: dead,
                }
            }
            PredicateResult::Indeterminate => {
                self.indeterminate_count += 1;
                SimplifyResult::Indeterminate {
                    branch_address: branch.address,
                }
            }
        };
        self.results.insert(branch.address, result);
        self.results.get(&branch.address).unwrap()
    }

    /// Simplify a batch of conditional branches and return the results.
    pub fn simplify_all(
        &mut self,
        branches: &[ConditionalBranch],
    ) -> Vec<&SimplifyResult> {
        for b in branches {
            self.simplify_branch(b);
        }
        branches
            .iter()
            .filter_map(|b| self.results.get(&b.address))
            .collect()
    }

    /// Retrieve the simplification result for a branch address.
    #[must_use]
    pub fn result_for(&self, branch_address: u64) -> Option<&SimplifyResult> {
        self.results.get(&branch_address)
    }

    /// All known dead-branch targets (may contain duplicates).
    #[must_use]
    pub fn dead_targets(&self) -> &[u64] {
        &self.dead_targets
    }

    /// Number of branches simplified.
    #[must_use]
    pub const fn simplified_count(&self) -> usize {
        self.simplified_count
    }

    /// Number of indeterminate branches.
    #[must_use]
    pub const fn indeterminate_count(&self) -> usize {
        self.indeterminate_count
    }

    /// All simplification results.
    #[must_use]
    pub fn all_results(&self) -> impl Iterator<Item = &SimplifyResult> {
        self.results.values()
    }
}

impl Default for ConditionalSimplifier {
    fn default() -> Self {
        Self::new()
    }
}

// ── Free function: live_branch ────────────────────────────────────────────────

/// Return the live branch target for a given `ConditionalBranch`.
///
/// Returns `None` when the predicate is indeterminate.
///
/// ```rust
/// use rustre_deobf_opaque::conditional_simplifier::{
///     ConditionalBranch, live_branch,
/// };
/// use rustre_deobf_opaque::predicate_evaluator::PredicateResult;
/// let b = ConditionalBranch {
///     address: 0x1000,
///     true_target: 0x1100,
///     false_target: 0x1200,
///     predicate: PredicateResult::AlwaysTrue,
///     predicate_reason: None,
/// };
/// assert_eq!(live_branch(&b), Some(0x1100));
/// ```
#[must_use]
pub const fn live_branch(branch: &ConditionalBranch) -> Option<u64> {
    match branch.predicate {
        PredicateResult::AlwaysTrue => Some(branch.true_target),
        PredicateResult::AlwaysFalse => Some(branch.false_target),
        PredicateResult::Indeterminate => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_branch(addr: u64, pred: PredicateResult) -> ConditionalBranch {
        ConditionalBranch {
            address: addr,
            true_target: addr + 0x100,
            false_target: addr + 0x200,
            predicate: pred,
            predicate_reason: Some("test".to_owned()),
        }
    }

    // ── live_branch free fn ───────────────────────────────────────────────────

    #[test]
    fn live_branch_always_true() {
        let b = make_branch(0x1000, PredicateResult::AlwaysTrue);
        assert_eq!(live_branch(&b), Some(0x1100));
    }

    #[test]
    fn live_branch_always_false() {
        let b = make_branch(0x1000, PredicateResult::AlwaysFalse);
        assert_eq!(live_branch(&b), Some(0x1200));
    }

    #[test]
    fn live_branch_indeterminate() {
        let b = make_branch(0x1000, PredicateResult::Indeterminate);
        assert_eq!(live_branch(&b), None);
    }

    // ── ConditionalSimplifier::simplify_branch ────────────────────────────────

    #[test]
    fn simplify_always_true() {
        let mut s = ConditionalSimplifier::new();
        let b = make_branch(0x2000, PredicateResult::AlwaysTrue);
        let r = s.simplify_branch(&b);
        assert!(r.is_simplified());
        assert_eq!(r.live_branch(), Some(0x2100));
        assert_eq!(r.dead_target(), Some(0x2200));
    }

    #[test]
    fn simplify_always_false() {
        let mut s = ConditionalSimplifier::new();
        let b = make_branch(0x3000, PredicateResult::AlwaysFalse);
        let r = s.simplify_branch(&b);
        assert!(r.is_simplified());
        assert_eq!(r.live_branch(), Some(0x3200));
        assert_eq!(r.dead_target(), Some(0x3100));
    }

    #[test]
    fn simplify_indeterminate() {
        let mut s = ConditionalSimplifier::new();
        let b = make_branch(0x4000, PredicateResult::Indeterminate);
        let r = s.simplify_branch(&b);
        assert!(!r.is_simplified());
        assert_eq!(r.live_branch(), None);
    }

    // ── dead_targets ─────────────────────────────────────────────────────────

    #[test]
    fn dead_targets_collected() {
        let mut s = ConditionalSimplifier::new();
        s.simplify_branch(&make_branch(0x1000, PredicateResult::AlwaysTrue));
        s.simplify_branch(&make_branch(0x2000, PredicateResult::AlwaysFalse));
        assert_eq!(s.dead_targets().len(), 2);
    }

    // ── counts ───────────────────────────────────────────────────────────────

    #[test]
    fn counts() {
        let mut s = ConditionalSimplifier::new();
        s.simplify_branch(&make_branch(0x1000, PredicateResult::AlwaysTrue));
        s.simplify_branch(&make_branch(0x2000, PredicateResult::Indeterminate));
        assert_eq!(s.simplified_count(), 1);
        assert_eq!(s.indeterminate_count(), 1);
    }

    // ── simplify_all ─────────────────────────────────────────────────────────

    #[test]
    fn simplify_all_batch() {
        let branches = vec![
            make_branch(0x1000, PredicateResult::AlwaysTrue),
            make_branch(0x2000, PredicateResult::AlwaysFalse),
            make_branch(0x3000, PredicateResult::Indeterminate),
        ];
        let mut s = ConditionalSimplifier::new();
        let results = s.simplify_all(&branches);
        assert_eq!(results.len(), 3);
        assert_eq!(s.simplified_count(), 2);
    }

    // ── result_for ────────────────────────────────────────────────────────────

    #[test]
    fn result_for_lookup() {
        let mut s = ConditionalSimplifier::new();
        let b = make_branch(0x5000, PredicateResult::AlwaysTrue);
        s.simplify_branch(&b);
        assert!(s.result_for(0x5000).is_some());
        assert!(s.result_for(0x9999).is_none());
    }

    // ── DeadBranch display ────────────────────────────────────────────────────

    #[test]
    fn dead_branch_display() {
        let d = DeadBranch {
            branch_address: 0x1000,
            dead_target: 0x1200,
            live_target: 0x1100,
            reason: "always true".to_owned(),
        };
        let s = d.to_string();
        assert!(s.contains("0x1000"));
        assert!(s.contains("0x1200"));
    }

    // ── SimplifyResult display ────────────────────────────────────────────────

    #[test]
    fn simplify_result_display_always_taken() {
        let mut s = ConditionalSimplifier::new();
        let b = make_branch(0x6000, PredicateResult::AlwaysTrue);
        let r = s.simplify_branch(&b).clone();
        assert!(r.to_string().contains("AlwaysTaken"));
    }

    #[test]
    fn simplify_result_display_indeterminate() {
        let r = SimplifyResult::Indeterminate { branch_address: 0x7000 };
        assert!(r.to_string().contains("Indeterminate"));
    }

    // ── all_results iterator ──────────────────────────────────────────────────

    #[test]
    fn all_results_count() {
        let mut s = ConditionalSimplifier::new();
        s.simplify_branch(&make_branch(0xA000, PredicateResult::AlwaysTrue));
        s.simplify_branch(&make_branch(0xB000, PredicateResult::AlwaysFalse));
        assert_eq!(s.all_results().count(), 2);
    }
}
