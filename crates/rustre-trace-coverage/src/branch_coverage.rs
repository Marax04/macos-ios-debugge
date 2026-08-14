//! Branch coverage analysis: track taken/not-taken for each conditional
//! branch, compute branch coverage percentage, find uncovered branches,
//! detect unreachable branches, generate branch coverage report.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

// ── BranchPoint ───────────────────────────────────────────────────────────────

/// A single conditional branch point in the binary.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BranchPoint {
    /// Address of the branch instruction.
    pub address: u64,
    /// Address taken when branch is taken.
    pub taken_target: u64,
    /// Address taken when branch is not taken (fall-through).
    pub not_taken_target: u64,
    /// Optional disassembly of the branch instruction.
    pub disasm: String,
    /// Optional source line number.
    pub source_line: Option<u32>,
    /// Optional function name this branch belongs to.
    pub function_name: Option<String>,
}

impl BranchPoint {
    /// Create a new branch point.
    #[must_use]
    pub const fn new(address: u64, taken_target: u64, not_taken_target: u64) -> Self {
        Self {
            address,
            taken_target,
            not_taken_target,
            disasm: String::new(),
            source_line: None,
            function_name: None,
        }
    }

    /// Set disassembly.
    #[must_use]
    pub fn with_disasm(mut self, d: impl Into<String>) -> Self {
        self.disasm = d.into();
        self
    }

    /// Set function name.
    #[must_use]
    pub fn with_function(mut self, f: impl Into<String>) -> Self {
        self.function_name = Some(f.into());
        self
    }

    /// Set source line.
    #[must_use]
    pub const fn with_line(mut self, line: u32) -> Self {
        self.source_line = Some(line);
        self
    }
}

impl fmt::Display for BranchPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Branch@0x{:x} taken->0x{:x} not_taken->0x{:x}",
            self.address, self.taken_target, self.not_taken_target)
    }
}

// ── BranchOutcome ─────────────────────────────────────────────────────────────

/// Records whether a branch was taken and/or not-taken.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BranchOutcome {
    /// Number of times the branch was taken.
    pub taken_count: u64,
    /// Number of times the branch was not taken.
    pub not_taken_count: u64,
}

impl BranchOutcome {
    /// Create a new outcome.
    #[must_use]
    pub const fn new() -> Self { Self { taken_count: 0, not_taken_count: 0 } }

    /// Record a taken execution.
    pub const fn record_taken(&mut self) { self.taken_count += 1; }

    /// Record a not-taken execution.
    pub const fn record_not_taken(&mut self) { self.not_taken_count += 1; }

    /// Total executions.
    #[must_use]
    pub const fn total(&self) -> u64 { self.taken_count + self.not_taken_count }

    /// Returns `true` if the taken path was executed at least once.
    #[must_use]
    pub const fn taken_covered(&self) -> bool { self.taken_count > 0 }

    /// Returns `true` if the not-taken path was executed at least once.
    #[must_use]
    pub const fn not_taken_covered(&self) -> bool { self.not_taken_count > 0 }

    /// Returns `true` if both paths are covered.
    #[must_use]
    pub const fn fully_covered(&self) -> bool {
        self.taken_covered() && self.not_taken_covered()
    }

    /// Taken ratio (0.0 if never executed).
    #[must_use]
    pub fn taken_ratio(&self) -> f64 {
        let t = self.total();
        if t == 0 { 0.0 } else { crate::u64_to_f64(self.taken_count) / crate::u64_to_f64(t) }
    }
}

// ── UnreachedBranch ───────────────────────────────────────────────────────────

/// A branch arm that was never executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnreachedBranch {
    /// The branch point.
    pub branch: BranchPoint,
    /// Which arm was missed: `true` = taken, `false` = not-taken.
    pub missed_arm_taken: bool,
    /// Target address of the missed arm.
    pub target: u64,
}

impl UnreachedBranch {
    /// Create for the taken arm.
    #[must_use]
    pub const fn missed_taken(branch: BranchPoint) -> Self {
        let target = branch.taken_target;
        Self { branch, missed_arm_taken: true, target }
    }

    /// Create for the not-taken arm.
    #[must_use]
    pub const fn missed_not_taken(branch: BranchPoint) -> Self {
        let target = branch.not_taken_target;
        Self { branch, missed_arm_taken: false, target }
    }

    /// Description of the missed arm.
    #[must_use]
    pub const fn arm_name(&self) -> &'static str {
        if self.missed_arm_taken { "taken" } else { "not-taken" }
    }
}

impl fmt::Display for UnreachedBranch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Uncovered {} arm of {} -> 0x{:x}", self.arm_name(), self.branch, self.target)
    }
}

// ── CoverageReport ────────────────────────────────────────────────────────────

/// Branch coverage report for a single analysis run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    /// Total number of branch points.
    pub total_branches: usize,
    /// Branches where both arms are covered.
    pub fully_covered: usize,
    /// Branches where only one arm is covered.
    pub partially_covered: usize,
    /// Branches where neither arm was ever executed.
    pub uncovered: usize,
    /// Branch coverage percentage (both arms, 0-100).
    pub coverage_pct: f64,
    /// Arm-level coverage percentage (individual arms, 0-100).
    pub arm_coverage_pct: f64,
    /// List of uncovered branches.
    pub unreached: Vec<UnreachedBranch>,
    /// Per-function statistics: name -> (`total_branches`, `fully_covered_branches`).
    pub per_function: HashMap<String, (usize, usize)>,
}

impl CoverageReport {
    /// Generate a formatted text report.
    #[must_use]
    pub fn format_text(&self) -> String {
        let mut out = String::new();
        write!(out,
            "Branch Coverage Report\n{}\n",
            "-".repeat(50)
        ).ok();
        write!(out,
            "Total branches:    {}\n\
             Fully covered:     {} ({:.1}%)\n\
             Partially covered: {}\n\
             Uncovered:         {}\n\
             Arm coverage:      {:.1}%\n",
            self.total_branches, self.fully_covered, self.coverage_pct,
            self.partially_covered, self.uncovered, self.arm_coverage_pct
        ).ok();
        if !self.unreached.is_empty() {
            writeln!(out, "\nUnreached branches ({}):", self.unreached.len()).ok();
            for ub in &self.unreached {
                writeln!(out, "  {ub}").ok();
            }
        }
        if !self.per_function.is_empty() {
            out.push_str("\nPer-function coverage:\n");
            let mut fns: Vec<(&String, &(usize, usize))> = self.per_function.iter().collect();
            fns.sort_by_key(|(name, _)| name.as_str());
            for (name, (total, covered)) in fns {
                let pct = if *total > 0 { crate::usize_to_f64(*covered) / crate::usize_to_f64(*total) * 100.0 } else { 100.0 };
                writeln!(out, "  {name}: {covered}/{total} ({pct:.1}%)").ok();
            }
        }
        out
    }
}

// ── BranchCoverage ────────────────────────────────────────────────────────────

/// Branch coverage tracker.
///
/// Register all known branch points, then record executed edges as the
/// trace is replayed. Finally, generate a `CoverageReport`.
pub struct BranchCoverage {
    /// All registered branch points, keyed by address.
    branches: HashMap<u64, BranchPoint>,
    /// Outcomes per branch address.
    outcomes: HashMap<u64, BranchOutcome>,
}

impl BranchCoverage {
    /// Create an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self { branches: HashMap::new(), outcomes: HashMap::new() }
    }

    /// Register a branch point.
    pub fn register_branch(&mut self, bp: BranchPoint) {
        let addr = bp.address;
        self.branches.insert(addr, bp);
        self.outcomes.entry(addr).or_default();
    }

    /// Register multiple branch points.
    pub fn register_branches(&mut self, bps: impl IntoIterator<Item = BranchPoint>) {
        for bp in bps { self.register_branch(bp); }
    }

    /// Record that a branch at `branch_addr` was taken (next PC = `next_pc`).
    ///
    /// Determines taken vs not-taken by comparing `next_pc` with the branch's
    /// `taken_target`.
    pub fn record_execution(&mut self, branch_addr: u64, next_pc: u64) {
        let bp = match self.branches.get(&branch_addr) {
            Some(b) => b.clone(),
            None => return,
        };
        let outcome = self.outcomes.entry(branch_addr).or_default();
        if next_pc == bp.taken_target {
            outcome.record_taken();
        } else {
            outcome.record_not_taken();
        }
    }

    /// Record a taken execution by address.
    pub fn record_taken(&mut self, branch_addr: u64) {
        self.outcomes.entry(branch_addr).or_default().record_taken();
    }

    /// Record a not-taken execution.
    pub fn record_not_taken(&mut self, branch_addr: u64) {
        self.outcomes.entry(branch_addr).or_default().record_not_taken();
    }

    /// Get the outcome for a branch.
    #[must_use]
    pub fn outcome(&self, branch_addr: u64) -> Option<&BranchOutcome> {
        self.outcomes.get(&branch_addr)
    }

    /// All registered branch points.
    #[must_use]
    pub fn branch_points(&self) -> Vec<&BranchPoint> {
        let mut v: Vec<&BranchPoint> = self.branches.values().collect();
        v.sort_by_key(|b| b.address);
        v
    }

    /// Number of registered branches.
    #[must_use]
    pub fn branch_count(&self) -> usize { self.branches.len() }

    /// Number of fully covered branches (both arms executed).
    #[must_use]
    pub fn fully_covered_count(&self) -> usize {
        self.branches.keys()
            .filter(|&&addr| {
                self.outcomes.get(&addr).is_some_and(BranchOutcome::fully_covered)
            })
            .count()
    }

    /// Number of uncovered branches (neither arm executed).
    #[must_use]
    pub fn uncovered_count(&self) -> usize {
        self.branches.keys()
            .filter(|&&addr| {
                let o = self.outcomes.get(&addr);
                o.is_none_or(|o| o.total() == 0)
            })
            .count()
    }

    /// Branch coverage percentage (fully covered / total).
    #[must_use]
    pub fn coverage_pct(&self) -> f64 {
        let total = self.branches.len();
        if total == 0 { return 100.0; }
        crate::usize_to_f64(self.fully_covered_count()) / crate::usize_to_f64(total) * 100.0
    }

    /// Arm-level coverage: each branch has 2 arms; count covered arms.
    #[must_use]
    pub fn arm_coverage_pct(&self) -> f64 {
        let total_arms = self.branches.len() * 2;
        if total_arms == 0 { return 100.0; }
        let covered_arms: usize = self.branches.keys().filter_map(|addr| {
            self.outcomes.get(addr)
        }).map(|o| usize::from(o.taken_covered()) + usize::from(o.not_taken_covered())).sum();
        crate::usize_to_f64(covered_arms) / crate::usize_to_f64(total_arms) * 100.0
    }

    /// Collect all unreached branch arms.
    #[must_use]
    pub fn unreached_branches(&self) -> Vec<UnreachedBranch> {
        let mut result = Vec::new();
        for (addr, bp) in &self.branches {
            let Some(outcome) = self.outcomes.get(addr) else {
                result.push(UnreachedBranch::missed_taken(bp.clone()));
                result.push(UnreachedBranch::missed_not_taken(bp.clone()));
                continue;
            };
            if !outcome.taken_covered() {
                result.push(UnreachedBranch::missed_taken(bp.clone()));
            }
            if !outcome.not_taken_covered() {
                result.push(UnreachedBranch::missed_not_taken(bp.clone()));
            }
        }
        result.sort_by_key(|u| u.branch.address);
        result
    }

    /// Detect likely unreachable branches: never executed even though the function
    /// appears in the trace (`function_addr` -> some BB was executed, but not this arm).
    ///
    /// Requires a set of executed addresses to check against.
    #[must_use]
    pub fn detect_likely_unreachable(&self, executed_addresses: &std::collections::HashSet<u64>) -> Vec<UnreachedBranch> {
        self.unreached_branches()
            .into_iter()
            .filter(|ub| {
                // The branch itself was executed (its address appears in the trace).
                executed_addresses.contains(&ub.branch.address)
            })
            .collect()
    }

    /// Per-function branch coverage: `function_name` -> (total, `fully_covered`).
    #[must_use]
    pub fn per_function_coverage(&self) -> HashMap<String, (usize, usize)> {
        let mut map: HashMap<String, (usize, usize)> = HashMap::new();
        for (addr, bp) in &self.branches {
            let fn_name = bp.function_name.clone().unwrap_or_else(|| "unknown".to_string());
            let e = map.entry(fn_name).or_insert((0, 0));
            e.0 += 1;
            if self.outcomes.get(addr).is_some_and(BranchOutcome::fully_covered) {
                e.1 += 1;
            }
        }
        map
    }

    /// Generate a full `CoverageReport`.
    #[must_use]
    pub fn generate_report(&self) -> CoverageReport {
        let total = self.branches.len();
        let fully = self.fully_covered_count();
        let unc = self.uncovered_count();
        let partial = total.saturating_sub(fully).saturating_sub(unc);
        CoverageReport {
            total_branches: total,
            fully_covered: fully,
            partially_covered: partial,
            uncovered: unc,
            coverage_pct: self.coverage_pct(),
            arm_coverage_pct: self.arm_coverage_pct(),
            unreached: self.unreached_branches(),
            per_function: self.per_function_coverage(),
        }
    }

    /// Merge another `BranchCoverage` into this one (union of outcomes).
    pub fn merge(&mut self, other: &Self) {
        for (addr, bp) in &other.branches {
            self.branches.entry(*addr).or_insert_with(|| bp.clone());
        }
        for (addr, outcome) in &other.outcomes {
            let e = self.outcomes.entry(*addr).or_default();
            e.taken_count += outcome.taken_count;
            e.not_taken_count += outcome.not_taken_count;
        }
    }

    /// Clear all outcome data (keep registered branch points).
    pub fn reset_outcomes(&mut self) {
        for v in self.outcomes.values_mut() {
            v.taken_count = 0;
            v.not_taken_count = 0;
        }
    }
}

impl Default for BranchCoverage {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bc() -> BranchCoverage {
        let mut bc = BranchCoverage::new();
        bc.register_branch(BranchPoint::new(0x1000, 0x1010, 0x1020).with_function("foo"));
        bc.register_branch(BranchPoint::new(0x2000, 0x2010, 0x2020).with_function("bar"));
        bc
    }

    #[test]
    fn test_record_taken() {
        let mut bc = make_bc();
        bc.record_taken(0x1000);
        assert!(bc.outcome(0x1000).unwrap().taken_covered());
        assert!(!bc.outcome(0x1000).unwrap().not_taken_covered());
    }

    #[test]
    fn test_fully_covered() {
        let mut bc = make_bc();
        bc.record_taken(0x1000);
        bc.record_not_taken(0x1000);
        assert_eq!(bc.fully_covered_count(), 1);
    }

    #[test]
    fn test_coverage_pct_zero() {
        let bc = make_bc();
        assert_eq!(bc.coverage_pct(), 0.0);
    }

    #[test]
    fn test_coverage_pct_full() {
        let mut bc = make_bc();
        bc.record_taken(0x1000); bc.record_not_taken(0x1000);
        bc.record_taken(0x2000); bc.record_not_taken(0x2000);
        assert!((bc.coverage_pct() - 100.0).abs() < 1e-9);
    }

    #[test]
    fn test_unreached_branches() {
        let mut bc = make_bc();
        bc.record_taken(0x1000);
        let unreached = bc.unreached_branches();
        // 0x1000 not-taken is missed, and 0x2000 both arms are missed.
        let missed_addrs: Vec<u64> = unreached.iter().map(|u| u.branch.address).collect();
        assert!(missed_addrs.contains(&0x1000));
        assert!(missed_addrs.contains(&0x2000));
    }

    #[test]
    fn test_arm_coverage_pct() {
        let mut bc = make_bc();
        bc.record_taken(0x1000);
        // 1 out of 4 arms covered.
        assert!((bc.arm_coverage_pct() - 25.0).abs() < 1e-9);
    }

    #[test]
    fn test_per_function_coverage() {
        let mut bc = make_bc();
        bc.record_taken(0x1000); bc.record_not_taken(0x1000);
        let pf = bc.per_function_coverage();
        assert_eq!(pf["foo"], (1, 1));
        assert_eq!(pf["bar"], (1, 0));
    }

    #[test]
    fn test_generate_report() {
        let mut bc = make_bc();
        bc.record_taken(0x1000); bc.record_not_taken(0x1000);
        let report = bc.generate_report();
        assert_eq!(report.total_branches, 2);
        assert_eq!(report.fully_covered, 1);
        assert_eq!(report.uncovered, 1);
        assert!(!report.format_text().is_empty());
    }

    #[test]
    fn test_merge() {
        let mut a = make_bc();
        let mut b = BranchCoverage::new();
        b.register_branch(BranchPoint::new(0x1000, 0x1010, 0x1020));
        b.register_branch(BranchPoint::new(0x3000, 0x3010, 0x3020));
        a.record_taken(0x1000);
        b.record_not_taken(0x1000);
        b.record_taken(0x3000);
        a.merge(&b);
        assert!(a.outcome(0x1000).unwrap().fully_covered());
        assert!(a.outcome(0x3000).is_some());
    }

    #[test]
    fn test_reset_outcomes() {
        let mut bc = make_bc();
        bc.record_taken(0x1000);
        bc.reset_outcomes();
        assert_eq!(bc.outcome(0x1000).unwrap().total(), 0);
    }
}
