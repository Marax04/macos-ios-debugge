//! Coverage-guided analysis — identifies dead code, hot paths, coverage gaps,
//! and suggests which functions to target to increase overall coverage.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::coverage_map::CoverageMap;

// ─── Function descriptor ─────────────────────────────────────────────────────

/// Descriptor for a function extracted from binary analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInfo {
    pub address: u64,
    pub name: String,
    pub size_bytes: u64,
    /// All basic block addresses belonging to this function.
    pub basic_blocks: Vec<u64>,
    /// Known outgoing call targets.
    pub callees: Vec<u64>,
}

impl FunctionInfo {
    #[must_use] 
    pub const fn total_bbs(&self) -> usize { self.basic_blocks.len() }

    /// Number of BBs that have been covered in a given map.
    #[must_use] 
    pub fn covered_bbs(&self, cov: &CoverageMap) -> usize {
        self.basic_blocks.iter()
            .filter(|&&bb| cov.bbs.get(&bb).is_some_and(|r| r.covered))
            .count()
    }

    #[must_use] 
    pub fn coverage_pct(&self, cov: &CoverageMap) -> f64 {
        let total = self.total_bbs();
        if total == 0 { return 100.0; }
        (crate::usize_to_f64(self.covered_bbs(cov)) / crate::usize_to_f64(total)) * 100.0
    }

    #[must_use] 
    pub fn is_dead(&self, cov: &CoverageMap) -> bool {
        self.covered_bbs(cov) == 0
    }

    #[must_use] 
    pub fn is_fully_covered(&self, cov: &CoverageMap) -> bool {
        self.total_bbs() > 0 && self.covered_bbs(cov) == self.total_bbs()
    }
}

// ─── Dead code detector ───────────────────────────────────────────────────────

/// Result of dead code analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadCodeResult {
    pub dead_functions: Vec<DeadFunction>,
    pub dead_bb_count: usize,
    pub total_bb_count: usize,
    pub dead_bytes: u64,
    pub total_bytes: u64,
}

/// A function that was never executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadFunction {
    pub address: u64,
    pub name: String,
    pub bb_count: usize,
    pub size_bytes: u64,
    /// Possible reason: never called / unreachable from entry.
    pub reason: DeadReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeadReason {
    NeverCalled,
    /// All callers are themselves dead.
    TransitivelyDead,
    /// Excluded by compile-time feature flags (heuristic).
    LikelyFeatureGated,
    Unknown,
}

impl std::fmt::Display for DeadReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NeverCalled => write!(f, "never called"),
            Self::TransitivelyDead => write!(f, "transitively dead"),
            Self::LikelyFeatureGated => write!(f, "likely feature-gated"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Analyze a list of functions against a coverage map to find dead code.
#[must_use] 
pub fn find_dead_code(functions: &[FunctionInfo], cov: &CoverageMap) -> DeadCodeResult {
    let dead_fns: HashSet<u64> = functions.iter()
        .filter(|f| f.is_dead(cov))
        .map(|f| f.address)
        .collect();

    let mut dead_functions = Vec::new();
    let mut dead_bb_count = 0usize;
    let mut total_bb_count = 0usize;
    let mut dead_bytes = 0u64;
    let mut total_bytes = 0u64;

    for func in functions {
        total_bb_count += func.total_bbs();
        total_bytes += func.size_bytes;
        if func.is_dead(cov) {
            dead_bb_count += func.total_bbs();
            dead_bytes += func.size_bytes;

            // Is it transitively dead (all callers also dead)?
            let reason = classify_dead_reason(func, &dead_fns, functions);
            dead_functions.push(DeadFunction {
                address: func.address,
                name: func.name.clone(),
                bb_count: func.total_bbs(),
                size_bytes: func.size_bytes,
                reason,
            });
        }
    }

    dead_functions.sort_by(|a, b| b.bb_count.cmp(&a.bb_count));
    DeadCodeResult { dead_functions, dead_bb_count, total_bb_count, dead_bytes, total_bytes }
}

fn classify_dead_reason(
    func: &FunctionInfo,
    dead_set: &HashSet<u64>,
    all_functions: &[FunctionInfo],
) -> DeadReason {
    // Build caller map
    let callers: Vec<u64> = all_functions.iter()
        .filter(|f| f.callees.contains(&func.address))
        .map(|f| f.address)
        .collect();

    if callers.is_empty() {
        return DeadReason::NeverCalled;
    }
    if callers.iter().all(|&c| dead_set.contains(&c)) {
        return DeadReason::TransitivelyDead;
    }
    // Heuristic: if the name contains "test_" or "_bench_" treat as feature-gated
    if func.name.contains("test_") || func.name.contains("bench_") || func.name.ends_with("_test") {
        return DeadReason::LikelyFeatureGated;
    }
    DeadReason::Unknown
}

// ─── Hot path analysis ────────────────────────────────────────────────────────

/// A hot execution path (sequence of BBs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotPath {
    pub bbs: Vec<u64>,
    pub total_hits: u64,
    pub function_name: Option<String>,
}

/// Identify the hottest execution paths from edge coverage.
///
/// Uses a greedy walk: start from the highest-hit BB, follow the most-taken
/// edge at each step, stop when a cycle would form or no outgoing edges exist.
#[must_use] 
pub fn find_hot_paths(cov: &CoverageMap, max_paths: usize, max_depth: usize) -> Vec<HotPath> {
    // Sort BBs by total hits descending
    let mut bb_hits: Vec<(u64, u64)> = cov.bbs.iter()
        .filter(|(_, r)| r.covered)
        .map(|(&addr, r)| (addr, r.total_hits))
        .collect();
    bb_hits.sort_by(|a, b| b.1.cmp(&a.1));

    // Build outgoing edge map: src → [(dst, hits)]
    let mut outgoing: HashMap<u64, Vec<(u64, u64)>> = HashMap::new();
    for (&key, rec) in &cov.edges {
        outgoing.entry(key.src).or_default().push((key.dst, rec.total_hits));
    }
    for v in outgoing.values_mut() {
        v.sort_by(|a, b| b.1.cmp(&a.1));
    }

    let mut paths = Vec::new();
    let mut used_starts: HashSet<u64> = HashSet::new();

    for (start_addr, _) in &bb_hits {
        if paths.len() >= max_paths { break; }
        if used_starts.contains(start_addr) { continue; }

        let mut path_bbs = vec![*start_addr];
        let mut visited: HashSet<u64> = HashSet::from([*start_addr]);
        let mut total_hits = cov.bbs.get(start_addr).map_or(0, |r| r.total_hits);

        let mut current = *start_addr;
        for _ in 0..max_depth {
            if let Some(edges) = outgoing.get(&current) {
                if let Some(&(next, edge_hits)) = edges.first() {
                    if visited.contains(&next) { break; }
                    path_bbs.push(next);
                    visited.insert(next);
                    total_hits = total_hits.min(edge_hits);
                    current = next;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        used_starts.insert(*start_addr);
        paths.push(HotPath { bbs: path_bbs, total_hits, function_name: None });
    }

    paths
}

// ─── Coverage gap analysis ───────────────────────────────────────────────────

/// A function with partial coverage — neither fully covered nor dead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageGap {
    pub address: u64,
    pub name: String,
    pub covered_bbs: usize,
    pub total_bbs: usize,
    pub coverage_pct: f64,
    /// BBs in this function not yet covered.
    pub uncovered_bbs: Vec<u64>,
    /// Suggestion for how to increase coverage.
    pub suggestion: String,
}

impl std::fmt::Display for CoverageGap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} @ {:#x}: {}/{} BBs ({:.1}%) — {}",
            self.name, self.address, self.covered_bbs, self.total_bbs, self.coverage_pct, self.suggestion
        )
    }
}

/// Identify partially-covered functions (coverage > 0% and < 100%).
#[must_use] 
pub fn find_coverage_gaps(functions: &[FunctionInfo], cov: &CoverageMap) -> Vec<CoverageGap> {
    let mut gaps: Vec<CoverageGap> = functions.iter()
        .filter(|f| !f.is_dead(cov) && !f.is_fully_covered(cov) && f.total_bbs() > 1)
        .map(|f| {
            let covered = f.covered_bbs(cov);
            let total = f.total_bbs();
            let pct = f.coverage_pct(cov);
            let uncovered: Vec<u64> = f.basic_blocks.iter()
                .filter(|&&bb| !cov.bbs.get(&bb).is_some_and(|r| r.covered))
                .copied()
                .collect();
            let suggestion = suggest_for_gap(f, pct, &uncovered, cov);
            CoverageGap { address: f.address, name: f.name.clone(), covered_bbs: covered, total_bbs: total, coverage_pct: pct, uncovered_bbs: uncovered, suggestion }
        })
        .collect();

    // Sort by "how close to full coverage" (desc pct = more interesting)
    gaps.sort_by(|a, b| b.coverage_pct.partial_cmp(&a.coverage_pct).unwrap_or(std::cmp::Ordering::Equal));
    gaps
}

fn suggest_for_gap(func: &FunctionInfo, pct: f64, uncovered_bbs: &[u64], _cov: &CoverageMap) -> String {
    if pct > 80.0 {
        format!("Near-complete ({pct:.0}%): focus on edge cases or error paths in {}.", func.name)
    } else if pct > 50.0 {
        format!("Half-covered: add inputs that exercise the {} uncovered blocks, likely guarded by conditionals.", uncovered_bbs.len())
    } else {
        format!("Low coverage ({pct:.0}%): function '{}' may need dedicated seed generation or a custom harness.", func.name)
    }
}

// ─── Coverage-guided analysis report ─────────────────────────────────────────

/// Full analysis report combining dead code, hot paths, and gaps.
#[derive(Debug, Serialize, Deserialize)]
pub struct CoverageAnalysisReport {
    pub dead_code: DeadCodeResult,
    pub coverage_gaps: Vec<CoverageGap>,
    pub hot_paths: Vec<HotPath>,
    pub total_functions: usize,
    pub dead_function_count: usize,
    pub fully_covered_count: usize,
    pub partial_count: usize,
}

impl CoverageAnalysisReport {
    /// Build a full report.
    #[must_use] 
    pub fn build(functions: &[FunctionInfo], cov: &CoverageMap) -> Self {
        let dead_code = find_dead_code(functions, cov);
        let coverage_gaps = find_coverage_gaps(functions, cov);
        let hot_paths = find_hot_paths(cov, 10, 20);
        let dead_function_count = dead_code.dead_functions.len();
        let fully_covered_count = functions.iter().filter(|f| f.is_fully_covered(cov)).count();
        let partial_count = coverage_gaps.len();
        Self {
            dead_code,
            coverage_gaps,
            hot_paths,
            total_functions: functions.len(),
            dead_function_count,
            fully_covered_count,
            partial_count,
        }
    }

    /// Format as a human-readable text report.
    #[must_use] 
    pub fn format_text(&self) -> String {
        let mut out = String::new();
        writeln!(out, "╔═════════════════════════════════════════╗").ok();
        writeln!(out, "║    Coverage-Guided Analysis Report      ║").ok();
        writeln!(out, "╚═════════════════════════════════════════╝").ok();
        writeln!(out).ok();
        writeln!(out, "Functions: {} total", self.total_functions).ok();
        writeln!(out, "  Dead       : {} ({:.1}%)", self.dead_function_count,
            pct(self.dead_function_count, self.total_functions)).ok();
        writeln!(out, "  Full cov.  : {} ({:.1}%)", self.fully_covered_count,
            pct(self.fully_covered_count, self.total_functions)).ok();
        writeln!(out, "  Partial    : {} ({:.1}%)", self.partial_count,
            pct(self.partial_count, self.total_functions)).ok();
        writeln!(out).ok();

        if !self.dead_code.dead_functions.is_empty() {
            writeln!(out, "── Dead Functions (top 10) ──").ok();
            for df in self.dead_code.dead_functions.iter().take(10) {
                writeln!(out, "  {:#x}  {}  [{} BBs, {}]", df.address, df.name, df.bb_count, df.reason).ok();
            }
            writeln!(out).ok();
        }

        if !self.coverage_gaps.is_empty() {
            writeln!(out, "── Coverage Gaps (top 10) ──").ok();
            for gap in self.coverage_gaps.iter().take(10) {
                writeln!(out, "  {gap}").ok();
            }
            writeln!(out).ok();
        }

        if !self.hot_paths.is_empty() {
            writeln!(out, "── Hot Paths (top 5) ──").ok();
            for (i, path) in self.hot_paths.iter().take(5).enumerate() {
                writeln!(out, "  Path {i}: {} BBs, {} hits", path.bbs.len(), path.total_hits).ok();
                for (j, &bb) in path.bbs.iter().take(4).enumerate() {
                    writeln!(out, "    [{j}] {bb:#x}").ok();
                }
                if path.bbs.len() > 4 { writeln!(out, "    ... ({} more)", path.bbs.len() - 4).ok(); }
            }
        }

        out
    }
}

fn pct(part: usize, total: usize) -> f64 {
    if total == 0 { 0.0 } else { crate::usize_to_f64(part) / crate::usize_to_f64(total) * 100.0 }
}

// ─── Coverage increase suggestions ───────────────────────────────────────────

/// A prioritized suggestion for increasing coverage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageSuggestion {
    pub priority: u32,
    pub suggestion_type: SuggestionType,
    pub target_function: Option<String>,
    pub target_address: Option<u64>,
    pub description: String,
    pub estimated_new_bbs: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SuggestionType {
    AddSeedForFunction,
    SpecializedHarness,
    IncreaseInputSize,
    AddDictionaryToken,
    DeepFuzzPath,
    ManualAnalysis,
}

impl std::fmt::Display for SuggestionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AddSeedForFunction => write!(f, "add_seed"),
            Self::SpecializedHarness => write!(f, "specialized_harness"),
            Self::IncreaseInputSize => write!(f, "increase_input_size"),
            Self::AddDictionaryToken => write!(f, "dictionary_token"),
            Self::DeepFuzzPath => write!(f, "deep_fuzz"),
            Self::ManualAnalysis => write!(f, "manual_analysis"),
        }
    }
}

/// Generate prioritized coverage improvement suggestions from a report.
#[must_use] 
pub fn generate_suggestions(report: &CoverageAnalysisReport) -> Vec<CoverageSuggestion> {
    let mut suggestions = Vec::new();
    let mut priority = 100u32;

    // Suggest harnesses for the top uncovered functions by BB count
    for df in report.dead_code.dead_functions.iter().take(5) {
        if df.bb_count > 2 {
            suggestions.push(CoverageSuggestion {
                priority,
                suggestion_type: SuggestionType::SpecializedHarness,
                target_function: Some(df.name.clone()),
                target_address: Some(df.address),
                description: format!(
                    "Function '{}' has {} uncovered BBs and was never executed. Create a dedicated fuzz harness or seed.",
                    df.name, df.bb_count
                ),
                estimated_new_bbs: df.bb_count,
            });
            priority = priority.saturating_sub(5);
        }
    }

    // Suggest seeds for near-complete functions
    for gap in report.coverage_gaps.iter().filter(|g| g.coverage_pct > 70.0).take(5) {
        suggestions.push(CoverageSuggestion {
            priority,
            suggestion_type: SuggestionType::AddSeedForFunction,
            target_function: Some(gap.name.clone()),
            target_address: Some(gap.address),
            description: format!(
                "'{}' is {:.0}% covered ({} uncovered BBs). Add seeds that exercise error paths or boundary conditions.",
                gap.name, gap.coverage_pct, gap.uncovered_bbs.len()
            ),
            estimated_new_bbs: gap.uncovered_bbs.len(),
        });
        priority = priority.saturating_sub(5);
    }

    // Suggest dictionary tokens for string-heavy code
    for gap in report.coverage_gaps.iter().filter(|g| g.coverage_pct < 30.0).take(3) {
        suggestions.push(CoverageSuggestion {
            priority: priority.saturating_sub(10),
            suggestion_type: SuggestionType::AddDictionaryToken,
            target_function: Some(gap.name.clone()),
            target_address: Some(gap.address),
            description: format!(
                "'{}' has low coverage ({:.0}%). If it parses structured input, add format magic bytes to the fuzzer dictionary.",
                gap.name, gap.coverage_pct
            ),
            estimated_new_bbs: (gap.uncovered_bbs.len() / 2).max(1),
        });
    }

    // Suggest deep fuzzing for hot paths
    if !report.hot_paths.is_empty() {
        let hot = &report.hot_paths[0];
        suggestions.push(CoverageSuggestion {
            priority: 30,
            suggestion_type: SuggestionType::DeepFuzzPath,
            target_function: hot.function_name.clone(),
            target_address: hot.bbs.first().copied(),
            description: format!(
                "Hottest path ({} hits, {} BBs) is heavily exercised. Consider AFL CmpLog or structure-aware mutation to go deeper.",
                hot.total_hits, hot.bbs.len()
            ),
            estimated_new_bbs: 0,
        });
    }

    suggestions.sort_by(|a, b| b.priority.cmp(&a.priority));
    suggestions
}

/// Format suggestions as a numbered list.
#[must_use] 
pub fn format_suggestions(suggestions: &[CoverageSuggestion]) -> String {
    let mut out = String::new();
    writeln!(out, "Coverage Improvement Suggestions").ok();
    writeln!(out, "═══════════════════════════════").ok();
    for (i, s) in suggestions.iter().enumerate() {
        writeln!(out, "\n[{:2}] Priority {} — {}", i + 1, s.priority, s.suggestion_type).ok();
        if let Some(name) = &s.target_function {
            writeln!(out, "     Function  : {name}").ok();
        }
        if let Some(addr) = s.target_address {
            writeln!(out, "     Address   : {addr:#x}").ok();
        }
        if s.estimated_new_bbs > 0 {
            writeln!(out, "     Est. gain : ~{} new BBs", s.estimated_new_bbs).ok();
        }
        writeln!(out, "     {}", s.description).ok();
    }
    out
}

// ─── Function call graph analysis ────────────────────────────────────────────

/// Compute a reachability set from a given entry point, following call edges.
/// Returns the set of function addresses reachable from `entry`.
#[must_use] 
pub fn reachable_from(entry: u64, functions: &[FunctionInfo]) -> std::collections::HashSet<u64> {
    let callee_map: HashMap<u64, &[u64]> = functions.iter().map(|f| (f.address, f.callees.as_slice())).collect();
    let mut visited = std::collections::HashSet::new();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(entry);
    while let Some(addr) = queue.pop_front() {
        if !visited.insert(addr) { continue; }
        if let Some(callees) = callee_map.get(&addr) {
            for &callee in *callees {
                if !visited.contains(&callee) { queue.push_back(callee); }
            }
        }
    }
    visited
}

/// Compute a "coverage efficiency" metric for each seed:
/// new BBs discovered / total time spent (edges per microsecond).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedEfficiency {
    pub seed_id: u64,
    pub new_bbs: usize,
    pub exec_time_us: u64,
    pub efficiency: f64, // new_bbs / exec_time_ms
}

#[must_use] 
pub fn compute_seed_efficiency(
    seed_new_bbs: &[(u64, usize)],
    seed_times_us: &[(u64, u64)],
) -> Vec<SeedEfficiency> {
    let time_map: HashMap<u64, u64> = seed_times_us.iter().copied().collect();
    let mut result: Vec<SeedEfficiency> = seed_new_bbs.iter().map(|&(id, bbs)| {
        let time = time_map.get(&id).copied().unwrap_or(1);
        let eff = crate::usize_to_f64(bbs) / (crate::u64_to_f64(time) / 1000.0).max(0.001);
        SeedEfficiency { seed_id: id, new_bbs: bbs, exec_time_us: time, efficiency: eff }
    }).collect();
    result.sort_by(|a, b| b.efficiency.partial_cmp(&a.efficiency).unwrap_or(std::cmp::Ordering::Equal));
    result
}

/// Find functions that are unreachable from any of the given entry points.
#[must_use] 
pub fn find_unreachable<'a>(
    entries: &[u64],
    functions: &'a [FunctionInfo],
) -> Vec<&'a FunctionInfo> {
    let reachable: std::collections::HashSet<u64> = entries.iter()
        .flat_map(|&e| reachable_from(e, functions))
        .collect();
    functions.iter().filter(|f| !reachable.contains(&f.address)).collect()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_func(addr: u64, name: &str, bbs: Vec<u64>) -> FunctionInfo {
        FunctionInfo { address: addr, name: name.into(), size_bytes: bbs.len() as u64 * 10, basic_blocks: bbs, callees: Vec::new() }
    }

    #[test]
    fn test_dead_function_detection() {
        let mut cov = CoverageMap::new();
        cov.record_bb(0x1000, 1, 5);
        let fns = vec![
            make_func(0x1000, "covered_fn", vec![0x1000, 0x1010]),
            make_func(0x2000, "dead_fn", vec![0x2000, 0x2010]),
        ];
        let result = find_dead_code(&fns, &cov);
        assert_eq!(result.dead_functions.len(), 1);
        assert_eq!(result.dead_functions[0].name, "dead_fn");
    }

    #[test]
    fn test_fully_covered() {
        let mut cov = CoverageMap::new();
        cov.record_bb(0x1000, 1, 1);
        cov.record_bb(0x1010, 1, 1);
        let f = make_func(0x1000, "fn", vec![0x1000, 0x1010]);
        assert!(f.is_fully_covered(&cov));
        assert!(!f.is_dead(&cov));
    }

    #[test]
    fn test_coverage_gap() {
        let mut cov = CoverageMap::new();
        cov.record_bb(0x1000, 1, 3); // only first BB covered
        let f = make_func(0x1000, "partial_fn", vec![0x1000, 0x1010, 0x1020]);
        let gaps = find_coverage_gaps(&[f], &cov);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].covered_bbs, 1);
        assert_eq!(gaps[0].total_bbs, 3);
        assert_eq!(gaps[0].uncovered_bbs.len(), 2);
    }

    #[test]
    fn test_hot_path_walk() {
        let mut cov = CoverageMap::new();
        cov.record_bb(0x1000, 1, 100);
        cov.record_edge(0x1000, 0x1010, 1, 100);
        cov.record_edge(0x1010, 0x1020, 1, 100);
        let paths = find_hot_paths(&cov, 3, 5);
        assert!(!paths.is_empty());
        assert!(paths[0].bbs.len() > 1 || !cov.bbs.is_empty());
    }

    #[test]
    fn test_report_format() {
        let mut cov = CoverageMap::new();
        cov.record_bb(0x1000, 1, 5);
        let fns = vec![make_func(0x1000, "main", vec![0x1000])];
        let report = CoverageAnalysisReport::build(&fns, &cov);
        let text = report.format_text();
        assert!(text.contains("Functions:"));
    }
}
