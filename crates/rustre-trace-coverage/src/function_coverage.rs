//! Function-level coverage: which functions were called, call count per
//! function, uncalled functions (dead code detection), coverage percentage
//! per module, generate coverage diff between two runs.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

// ── FunctionStats ─────────────────────────────────────────────────────────────

/// Coverage statistics for a single function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionStats {
    /// Function name.
    pub name: String,
    /// Start address.
    pub start_addr: u64,
    /// End address (exclusive), or 0 if unknown.
    pub end_addr: u64,
    /// Module/binary name this function belongs to.
    pub module: String,
    /// Number of times this function was called.
    pub call_count: u64,
    /// Total basic blocks in the function.
    pub total_bbs: usize,
    /// Covered basic blocks — derived from `covered_bb_addrs`, never counted
    /// once per execution.
    pub covered_bbs: usize,
    /// Distinct basic-block addresses actually reached.
    ///
    /// The type previously had no way to express WHICH blocks were reached,
    /// only how many, which is why `record_bb_execution` discarded the address
    /// outright. Extending the model is what makes the correct count
    /// expressible at all.
    #[serde(default)]
    pub covered_bb_addrs: HashSet<u64>,
    /// Whether at least one instruction in the function was executed.
    pub was_executed: bool,
    /// Unique callees: set of addresses this function called.
    pub callees: HashSet<u64>,
}

impl FunctionStats {
    /// Create a new stats record.
    #[must_use]
    pub fn new(name: impl Into<String>, start_addr: u64, module: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            start_addr,
            end_addr: 0,
            module: module.into(),
            call_count: 0,
            total_bbs: 0,
            covered_bbs: 0,
            covered_bb_addrs: HashSet::new(),
            was_executed: false,
            callees: HashSet::new(),
        }
    }

    /// Set end address.
    #[must_use]
    pub const fn with_end(mut self, end: u64) -> Self {
        self.end_addr = end;
        self
    }

    /// Set total basic blocks.
    #[must_use]
    pub const fn with_total_bbs(mut self, n: usize) -> Self {
        self.total_bbs = n;
        self
    }

    /// BB coverage percentage (0-100).
    #[must_use]
    pub fn bb_coverage_pct(&self) -> f64 {
        if self.total_bbs == 0 { return if self.was_executed { 100.0 } else { 0.0 }; }
        crate::usize_to_f64(self.covered_bbs) / crate::usize_to_f64(self.total_bbs) * 100.0
    }

    /// Returns `true` if neither this function nor any of its BBs were executed.
    #[must_use]
    pub const fn is_dead_code(&self) -> bool {
        !self.was_executed && self.call_count == 0
    }

    /// Returns `true` if all basic blocks are covered.
    #[must_use]
    pub const fn is_fully_covered(&self) -> bool {
        self.covered_bbs >= self.total_bbs && self.total_bbs > 0 && self.was_executed
    }

    /// Number of unique functions this function calls.
    #[must_use]
    pub fn callee_count(&self) -> usize { self.callees.len() }
}

impl fmt::Display for FunctionStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@0x{:x} calls={} bbs={}/{} ({:.1}%)",
            self.name, self.start_addr, self.call_count,
            self.covered_bbs, self.total_bbs, self.bb_coverage_pct())
    }
}

// ── ModuleCoverage ────────────────────────────────────────────────────────────

/// Coverage statistics for an entire module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleCoverage {
    /// Module name.
    pub name: String,
    /// Total functions in the module.
    pub total_functions: usize,
    /// Functions that were called at least once.
    pub called_functions: usize,
    /// Functions with 100% BB coverage.
    pub fully_covered_functions: usize,
    /// Dead code functions (never executed).
    pub dead_functions: usize,
    /// Total basic blocks.
    pub total_bbs: usize,
    /// Covered basic blocks.
    pub covered_bbs: usize,
    /// Per-function stats.
    pub functions: Vec<FunctionStats>,
}

impl ModuleCoverage {
    /// Create a new empty module coverage.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            total_functions: 0,
            called_functions: 0,
            fully_covered_functions: 0,
            dead_functions: 0,
            total_bbs: 0,
            covered_bbs: 0,
            functions: Vec::new(),
        }
    }

    /// Function coverage percentage (called / total).
    #[must_use]
    pub fn function_coverage_pct(&self) -> f64 {
        if self.total_functions == 0 { return 100.0; }
        crate::usize_to_f64(self.called_functions) / crate::usize_to_f64(self.total_functions) * 100.0
    }

    /// BB coverage percentage.
    #[must_use]
    pub fn bb_coverage_pct(&self) -> f64 {
        if self.total_bbs == 0 { return 100.0; }
        crate::usize_to_f64(self.covered_bbs) / crate::usize_to_f64(self.total_bbs) * 100.0
    }

    /// Recompute all derived counts from `self.functions`.
    pub fn recompute(&mut self) {
        self.total_functions = self.functions.len();
        self.called_functions = self.functions.iter().filter(|f| f.was_executed).count();
        self.fully_covered_functions = self.functions.iter().filter(|f| f.is_fully_covered()).count();
        self.dead_functions = self.functions.iter().filter(|f| f.is_dead_code()).count();
        self.total_bbs = self.functions.iter().map(|f| f.total_bbs).sum();
        self.covered_bbs = self.functions.iter().map(|f| f.covered_bbs).sum();
    }
}

impl fmt::Display for ModuleCoverage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Module({}) fns={}/{} ({:.1}%) bbs={}/{} ({:.1}%) dead={}",
            self.name,
            self.called_functions, self.total_functions, self.function_coverage_pct(),
            self.covered_bbs, self.total_bbs, self.bb_coverage_pct(),
            self.dead_functions)
    }
}

// ── CoverageRun ───────────────────────────────────────────────────────────────

/// A named function-level coverage run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageRun {
    /// Run name/label.
    pub name: String,
    /// Per-function stats, keyed by start address.
    pub functions: HashMap<u64, FunctionStats>,
    /// Unix timestamp.
    pub timestamp: u64,
    /// Optional description.
    pub description: String,
}

impl CoverageRun {
    /// Create an empty run.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            functions: HashMap::new(),
            timestamp: 0,
            description: String::new(),
        }
    }

    /// Register a function.
    pub fn register_function(&mut self, stats: FunctionStats) {
        self.functions.insert(stats.start_addr, stats);
    }

    /// Record a call to function at `addr`.
    ///
    /// Creates a stub entry if the function was not previously registered.
    pub fn record_call(&mut self, addr: u64) {
        let e = self.functions.entry(addr).or_insert_with(|| {
            FunctionStats::new(format!("sub_{addr:x}"), addr, "unknown")
        });
        e.call_count += 1;
        e.was_executed = true;
    }

    /// Record BB execution for a function.
    pub fn record_bb_execution(&mut self, fn_addr: u64, bb_addr: u64) {
        let e = self.functions.entry(fn_addr).or_insert_with(|| {
            FunctionStats::new(format!("sub_{fn_addr:x}"), fn_addr, "unknown")
        });
        e.was_executed = true;
        // Record WHICH block was reached, not how many times. Discarding the
        // address and incrementing on every execution counted executions as
        // coverage: a loop header entered five times reported five covered
        // blocks out of four, i.e. 125% — a percentage above its own ceiling.
        if e.covered_bb_addrs.insert(bb_addr) {
            e.covered_bbs = e.covered_bb_addrs.len();
        }
    }

    /// Number of functions called (`was_executed` == true).
    #[must_use]
    pub fn called_count(&self) -> usize {
        self.functions.values().filter(|f| f.was_executed).count()
    }

    /// Number of uncalled functions.
    #[must_use]
    pub fn uncalled_count(&self) -> usize {
        self.functions.values().filter(|f| !f.was_executed).count()
    }

    /// Total number of registered functions.
    #[must_use]
    pub fn total_functions(&self) -> usize { self.functions.len() }

    /// Function coverage percentage.
    #[must_use]
    pub fn function_coverage_pct(&self) -> f64 {
        let total = self.total_functions();
        if total == 0 { return 100.0; }
        crate::usize_to_f64(self.called_count()) / crate::usize_to_f64(total) * 100.0
    }

    /// Dead code functions (never called, `was_executed` == false).
    #[must_use]
    pub fn dead_code_functions(&self) -> Vec<&FunctionStats> {
        let mut v: Vec<&FunctionStats> = self.functions.values()
            .filter(|f| f.is_dead_code())
            .collect();
        v.sort_by_key(|f| f.start_addr);
        v
    }

    /// Top-N most-called functions.
    #[must_use]
    pub fn top_called(&self, n: usize) -> Vec<&FunctionStats> {
        let mut v: Vec<&FunctionStats> = self.functions.values()
            .filter(|f| f.call_count > 0)
            .collect();
        v.sort_by(|a, b| b.call_count.cmp(&a.call_count));
        v.truncate(n);
        v
    }

    /// Compute module-level coverage from this run.
    #[must_use]
    pub fn module_coverage(&self) -> HashMap<String, ModuleCoverage> {
        let mut modules: HashMap<String, ModuleCoverage> = HashMap::new();
        for f in self.functions.values() {
            let mc = modules.entry(f.module.clone()).or_insert_with(|| ModuleCoverage::new(&f.module));
            mc.functions.push(f.clone());
        }
        for mc in modules.values_mut() { mc.recompute(); }
        modules
    }

    /// Look up stats for a specific function address.
    #[must_use]
    pub fn get(&self, addr: u64) -> Option<&FunctionStats> { self.functions.get(&addr) }
}

// ── CoverageDiff ──────────────────────────────────────────────────────────────

/// Diff between two coverage runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageDiff {
    /// Functions newly called in B that weren't called in A.
    pub gained: Vec<FunctionStats>,
    /// Functions called in A but not in B (regressions).
    pub lost: Vec<FunctionStats>,
    /// Functions present in both with changed call counts.
    pub changed: Vec<FunctionChange>,
    /// Net change in called function count.
    pub delta_called: i64,
    /// Net change in total function count.
    pub delta_total: i64,
}

/// A function whose call count changed between two runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionChange {
    pub name: String,
    pub addr: u64,
    pub calls_a: u64,
    pub calls_b: u64,
    pub delta: i64,
}

impl CoverageDiff {
    /// Compute the diff between runs `a` and `b`.
    #[must_use]
    pub fn compute(a: &CoverageRun, b: &CoverageRun) -> Self {
        let addrs_a: HashSet<u64> = a.functions.keys().copied().collect();
        let addrs_b: HashSet<u64> = b.functions.keys().copied().collect();

        let gained: Vec<FunctionStats> = addrs_b.difference(&addrs_a)
            .filter_map(|addr| b.functions.get(addr).filter(|f| f.was_executed))
            .cloned().collect();

        let lost: Vec<FunctionStats> = addrs_a.difference(&addrs_b)
            .filter_map(|addr| a.functions.get(addr).filter(|f| f.was_executed))
            .cloned().collect();

        // Newly called in B (present in both but B called it and A didn't).
        let mut gained_v = gained;
        let mut lost_v = lost;
        for addr in addrs_a.intersection(&addrs_b) {
            let fa = &a.functions[addr];
            let fb = &b.functions[addr];
            if !fa.was_executed && fb.was_executed {
                gained_v.push(fb.clone());
            }
            if fa.was_executed && !fb.was_executed {
                lost_v.push(fa.clone());
            }
        }

        let mut changed: Vec<FunctionChange> = Vec::new();
        for addr in addrs_a.intersection(&addrs_b) {
            let fa = &a.functions[addr];
            let fb = &b.functions[addr];
            if fa.call_count != fb.call_count {
                changed.push(FunctionChange {
                    name: fb.name.clone(),
                    addr: *addr,
                    calls_a: fa.call_count,
                    calls_b: fb.call_count,
                    delta: crate::u64_to_i64_sat(fb.call_count) - crate::u64_to_i64_sat(fa.call_count),
                });
            }
        }
        changed.sort_by(|x, y| y.delta.abs().cmp(&x.delta.abs()));

        let lost_count = crate::usize_to_i64_sat(lost_v.len());
        let gained_count = crate::usize_to_i64_sat(gained_v.len());

        Self {
            gained: gained_v,
            lost: lost_v,
            changed,
            delta_called: gained_count - lost_count,
            delta_total: crate::usize_to_i64_sat(b.total_functions()) - crate::usize_to_i64_sat(a.total_functions()),
        }
    }

    /// Summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "CoverageDiff: +{} gained, -{} lost, {} changed, net_called={:+}",
            self.gained.len(), self.lost.len(), self.changed.len(), self.delta_called
        )
    }

    /// Returns `true` if there was any regression (functions lost).
    #[must_use]
    pub const fn has_regression(&self) -> bool { !self.lost.is_empty() }

    /// Returns `true` if there was any gain.
    #[must_use]
    pub const fn has_gain(&self) -> bool { !self.gained.is_empty() }
}

// ── FunctionCoverage (high-level API) ─────────────────────────────────────────

/// High-level function-level coverage analysis engine.
pub struct FunctionCoverage {
    /// Current accumulation run.
    pub current: CoverageRun,
    /// Symbol table: addr -> name.
    pub symbols: HashMap<u64, String>,
    /// Module assignment: addr -> `module_name`.
    pub addr_to_module: HashMap<u64, String>,
}

impl FunctionCoverage {
    /// Create a new tracker.
    #[must_use]
    pub fn new(run_name: impl Into<String>) -> Self {
        Self {
            current: CoverageRun::new(run_name),
            symbols: HashMap::new(),
            addr_to_module: HashMap::new(),
        }
    }

    /// Register a known function.
    pub fn register_function(&mut self, addr: u64, name: impl Into<String>, module: impl Into<String>, total_bbs: usize) {
        let name = name.into();
        let module = module.into();
        self.symbols.insert(addr, name.clone());
        self.addr_to_module.insert(addr, module.clone());
        let stats = FunctionStats::new(name, addr, module).with_total_bbs(total_bbs);
        self.current.register_function(stats);
    }

    /// Record a call to function at `addr`.
    pub fn record_call(&mut self, addr: u64) {
        // Resolve name and module if known.
        let name = self.symbols.get(&addr).cloned()
            .unwrap_or_else(|| format!("sub_{addr:x}"));
        let module = self.addr_to_module.get(&addr).cloned()
            .unwrap_or_else(|| "unknown".to_string());
        let e = self.current.functions.entry(addr).or_insert_with(|| {
            FunctionStats::new(name, addr, module)
        });
        e.call_count += 1;
        e.was_executed = true;
    }

    /// Record BB execution at `bb_addr` belonging to function `fn_addr`.
    pub fn record_bb(&mut self, fn_addr: u64, bb_addr: u64) {
        let _ = bb_addr;
        let name = self.symbols.get(&fn_addr).cloned()
            .unwrap_or_else(|| format!("sub_{fn_addr:x}"));
        let module = self.addr_to_module.get(&fn_addr).cloned()
            .unwrap_or_else(|| "unknown".to_string());
        let e = self.current.functions.entry(fn_addr).or_insert_with(|| {
            FunctionStats::new(name, fn_addr, module)
        });
        e.was_executed = true;
        e.covered_bbs += 1;
    }

    /// Compute module coverage breakdown.
    #[must_use]
    pub fn module_coverage(&self) -> HashMap<String, ModuleCoverage> {
        self.current.module_coverage()
    }

    /// Generate a text report.
    #[must_use]
    pub fn generate_report(&self) -> String {
        let total = self.current.total_functions();
        let called = self.current.called_count();
        let pct = self.current.function_coverage_pct();
        let mut out = format!(
            "Function Coverage Report: {}/{} ({:.1}%)\n{}\n",
            called, total, pct, "-".repeat(60)
        );

        let mut fns: Vec<&FunctionStats> = self.current.functions.values().collect();
        fns.sort_by_key(|f| f.start_addr);
        for f in &fns {
            let status = if f.was_executed { "COVERED" } else { "DEAD" };
            writeln!(out, "  [{status:<7}] {f}").ok();
        }

        let dead = self.current.dead_code_functions();
        if !dead.is_empty() {
            writeln!(out, "\nDead code ({}):", dead.len()).ok();
            for f in dead {
                writeln!(out, "  0x{:x}  {}", f.start_addr, f.name).ok();
            }
        }
        out
    }

    /// Diff this run against a baseline.
    #[must_use]
    pub fn diff_against(&self, baseline: &CoverageRun) -> CoverageDiff {
        CoverageDiff::compute(baseline, &self.current)
    }

    /// Total functions registered.
    #[must_use]
    pub fn total_functions(&self) -> usize { self.current.total_functions() }

    /// Called functions count.
    #[must_use]
    pub fn called_count(&self) -> usize { self.current.called_count() }

    /// Dead code count.
    #[must_use]
    pub fn dead_code_count(&self) -> usize { self.current.uncalled_count() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_run(name: &str, calls: &[(u64, &str, u64)]) -> CoverageRun {
        let mut run = CoverageRun::new(name);
        for &(addr, sym, count) in calls {
            let mut f = FunctionStats::new(sym, addr, "libc");
            f.call_count = count;
            f.was_executed = count > 0;
            f.total_bbs = 3;
            f.covered_bbs = if count > 0 { 3 } else { 0 };
            run.register_function(f);
        }
        run
    }

    #[test]
    fn test_function_stats_dead_code() {
        let f = FunctionStats::new("never_called", 0x9000, "test");
        assert!(f.is_dead_code());
    }

    #[test]
    fn test_function_stats_bb_coverage() {
        let mut f = FunctionStats::new("foo", 0x1000, "test").with_total_bbs(4);
        f.covered_bbs = 2;
        assert!((f.bb_coverage_pct() - 50.0).abs() < 1e-9);
    }

    #[test]
    fn test_run_record_call() {
        let mut fc = FunctionCoverage::new("test");
        fc.register_function(0x1000, "foo", "libc", 3);
        fc.record_call(0x1000);
        fc.record_call(0x1000);
        assert_eq!(fc.current.get(0x1000).unwrap().call_count, 2);
    }

    #[test]
    fn test_dead_code_detection() {
        let run = make_run("r", &[(0x1000, "active", 5), (0x2000, "dead", 0)]);
        let dead = run.dead_code_functions();
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].name, "dead");
    }

    #[test]
    fn test_top_called() {
        let run = make_run("r", &[
            (0x1000, "a", 10), (0x2000, "b", 5), (0x3000, "c", 1),
        ]);
        let top = run.top_called(2);
        assert_eq!(top[0].name, "a");
        assert_eq!(top[1].name, "b");
    }

    #[test]
    fn test_coverage_diff_gained_lost() {
        let a = make_run("a", &[(0x1000, "foo", 3), (0x2000, "bar", 0)]);
        let b = make_run("b", &[(0x1000, "foo", 0), (0x2000, "bar", 5), (0x3000, "baz", 2)]);
        let diff = CoverageDiff::compute(&a, &b);
        let lost_names: Vec<&str> = diff.lost.iter().map(|f| f.name.as_str()).collect();
        let gained_names: Vec<&str> = diff.gained.iter().map(|f| f.name.as_str()).collect();
        assert!(lost_names.contains(&"foo"));
        assert!(gained_names.contains(&"bar") || gained_names.contains(&"baz"));
    }

    #[test]
    fn test_module_coverage() {
        let mut run = CoverageRun::new("r");
        let mut f1 = FunctionStats::new("foo", 0x1000, "libc");
        f1.was_executed = true; f1.total_bbs = 2; f1.covered_bbs = 2;
        let f2 = FunctionStats::new("bar", 0x2000, "libc");
        run.register_function(f1); run.register_function(f2);
        let mc = run.module_coverage();
        assert!(mc.contains_key("libc"));
        assert_eq!(mc["libc"].total_functions, 2);
        assert_eq!(mc["libc"].called_functions, 1);
    }

    #[test]
    fn test_function_coverage_report() {
        let mut fc = FunctionCoverage::new("test");
        fc.register_function(0x1000, "main", "app", 4);
        fc.register_function(0x2000, "helper", "app", 2);
        fc.record_call(0x1000);
        let report = fc.generate_report();
        assert!(report.contains("COVERED"));
        assert!(report.contains("DEAD"));
    }

    #[test]
    fn test_coverage_pct() {
        let run = make_run("r", &[(0x1000, "a", 3), (0x2000, "b", 0), (0x3000, "c", 1)]);
        let pct = run.function_coverage_pct();
        assert!((pct - 200.0 / 3.0).abs() < 1.0);
    }
}
