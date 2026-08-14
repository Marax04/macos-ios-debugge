//! `trace_diff_engine` — Compare two execution traces, find divergence points,
//! classify differences (new calls, missing calls, changed args), and produce
//! a detailed [`TraceDiff`] report.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{Address, EntryKind, ExecutionTrace, RegId, TraceEntry};

// ─── DivergenceKind ──────────────────────────────────────────────────────────

/// Classification of a divergence between two traces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DivergenceKind {
    /// A CALL instruction was present in trace A but absent at the same sequence
    /// position in trace B.
    MissingCallInB {
        /// Target address of the call that was absent.
        target: Address,
    },
    /// A CALL instruction was present in trace B but absent at the same position
    /// in trace A.
    NewCallInB {
        /// Target address of the call that appeared in B.
        target: Address,
    },
    /// Both traces had a CALL at the same position but to different targets.
    ChangedCallTarget {
        /// Call target in trace A.
        target_a: Address,
        /// Call target in trace B.
        target_b: Address,
    },
    /// Both traces had a CALL to the same target but different register snapshots
    /// (potential argument difference).
    ChangedCallArgs {
        /// Target address of the call.
        target: Address,
        /// Registers that differed: (`reg_id`, `value_in_a`, `value_in_b`).
        changed_regs: Vec<(RegId, u64, u64)>,
    },
    /// The program counter diverged: the two traces visited different addresses
    /// at the same instruction index.
    PcDivergence {
        /// PC in trace A.
        pc_a: Address,
        /// PC in trace B.
        pc_b: Address,
    },
    /// A memory write value differed at the same instruction index and address.
    MemWriteDifference {
        /// Address that was written.
        addr: Address,
        /// Bytes written by trace A.
        value_a: Vec<u8>,
        /// Bytes written by trace B.
        value_b: Vec<u8>,
    },
    /// Trace A ended before trace B reached the same index.
    TraceATruncated {
        /// Index at which A ended.
        end_idx: usize,
    },
    /// Trace B ended before trace A reached the same index.
    TraceBTruncated {
        /// Index at which B ended.
        end_idx: usize,
    },
}

impl std::fmt::Display for DivergenceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingCallInB { target } => {
                write!(f, "missing call to 0x{target:x} in B")
            }
            Self::NewCallInB { target } => {
                write!(f, "new call to 0x{target:x} in B")
            }
            Self::ChangedCallTarget { target_a, target_b } => {
                write!(f, "call target changed: 0x{target_a:x} -> 0x{target_b:x}")
            }
            Self::ChangedCallArgs { target, changed_regs } => {
                write!(
                    f,
                    "call args changed for 0x{target:x}: {} reg(s) differ",
                    changed_regs.len()
                )
            }
            Self::PcDivergence { pc_a, pc_b } => {
                write!(f, "PC divergence: A=0x{pc_a:x} B=0x{pc_b:x}")
            }
            Self::MemWriteDifference { addr, .. } => {
                write!(f, "mem write difference at 0x{addr:x}")
            }
            Self::TraceATruncated { end_idx } => {
                write!(f, "trace A truncated at idx={end_idx}")
            }
            Self::TraceBTruncated { end_idx } => {
                write!(f, "trace B truncated at idx={end_idx}")
            }
        }
    }
}

// ─── DivergencePoint ─────────────────────────────────────────────────────────

/// A single divergence event between two traces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DivergencePoint {
    /// Instruction index in trace A where the divergence was detected.
    pub idx_a: usize,
    /// Instruction index in trace B where the divergence was detected.
    pub idx_b: usize,
    /// PC in trace A at the divergence point.
    pub pc_a: Address,
    /// PC in trace B at the divergence point.
    pub pc_b: Address,
    /// Classification of the divergence.
    pub kind: DivergenceKind,
    /// Severity: 0 = info, 1 = warning, 2 = critical.
    pub severity: u8,
}

impl DivergencePoint {
    const fn new(idx_a: usize, idx_b: usize, pc_a: Address, pc_b: Address, kind: DivergenceKind) -> Self {
        let severity = match &kind {
            DivergenceKind::ChangedCallTarget { .. } => 2,
            DivergenceKind::MissingCallInB { .. } | DivergenceKind::NewCallInB { .. }
            | DivergenceKind::MemWriteDifference { .. }
            | DivergenceKind::ChangedCallArgs { .. } | DivergenceKind::PcDivergence { .. } => 1,
            DivergenceKind::TraceATruncated { .. } | DivergenceKind::TraceBTruncated { .. } => 0,
        };
        Self { idx_a, idx_b, pc_a, pc_b, kind, severity }
    }
}

// ─── CallSequence ─────────────────────────────────────────────────────────────

/// The ordered list of calls made in a trace, for LCS-based diffing.
#[derive(Debug, Clone)]
struct CallEvent {
    idx: usize,
    pc: Address,
    target: Address,
}

fn extract_call_sequence(trace: &ExecutionTrace) -> Vec<CallEvent> {
    trace
        .entries
        .iter()
        .filter_map(|e| {
            if let EntryKind::Call { target, .. } = e.kind {
                Some(CallEvent {
                    idx: e.idx,
                    pc: e.pc,
                    target,
                })
            } else {
                None
            }
        })
        .collect()
}

// ─── DiffStats ────────────────────────────────────────────────────────────────

/// Aggregate statistics about a trace diff.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiffStats {
    /// Total divergence points found.
    pub total_divergences: usize,
    /// Number of critical divergences (severity 2).
    pub critical: usize,
    /// Number of warning divergences (severity 1).
    pub warnings: usize,
    /// Number of informational events (severity 0).
    pub info: usize,
    /// Number of calls present in A but not B.
    pub calls_only_in_a: usize,
    /// Number of calls present in B but not A.
    pub calls_only_in_b: usize,
    /// Number of shared call targets.
    pub common_call_targets: usize,
    /// Jaccard similarity of call sequences [0.0, 1.0].
    pub call_sequence_similarity: f64,
    /// Jaccard similarity of PC coverage [0.0, 1.0].
    pub pc_coverage_similarity: f64,
}

// ─── TraceDiffReport ─────────────────────────────────────────────────────────

/// Full comparison report between two execution traces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDiffReport {
    /// Name of trace A.
    pub name_a: String,
    /// Name of trace B.
    pub name_b: String,
    /// All divergence points discovered during comparison.
    pub divergences: Vec<DivergencePoint>,
    /// Aggregate statistics.
    pub stats: DiffStats,
    /// Calls in A not matched in B (by target address).
    pub calls_only_in_a: Vec<Address>,
    /// Calls in B not matched in A (by target address).
    pub calls_only_in_b: Vec<Address>,
    /// Call targets present in both traces.
    pub common_call_targets: HashSet<Address>,
    /// Index of the first PC divergence, if any.
    pub first_pc_divergence_idx: Option<(usize, usize)>,
}

impl TraceDiffReport {
    /// Human-readable one-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Diff({} vs {}): {} divergence(s) [{} critical, {} warn], call sim={:.1}%, PC sim={:.1}%",
            self.name_a,
            self.name_b,
            self.stats.total_divergences,
            self.stats.critical,
            self.stats.warnings,
            self.stats.call_sequence_similarity * 100.0,
            self.stats.pc_coverage_similarity * 100.0,
        )
    }

    /// Return only critical divergences.
    #[must_use]
    pub fn critical_divergences(&self) -> Vec<&DivergencePoint> {
        self.divergences.iter().filter(|d| d.severity == 2).collect()
    }

    /// Return divergences of a specific kind name (debug-string prefix matching).
    #[must_use]
    pub fn divergences_by_kind(&self, prefix: &str) -> Vec<&DivergencePoint> {
        let upper = prefix.to_uppercase();
        self.divergences
            .iter()
            .filter(|d| format!("{:?}", d.kind).to_uppercase().starts_with(&upper))
            .collect()
    }
}

// ─── DiffOptions ─────────────────────────────────────────────────────────────

/// Options that control how the diff engine runs.
#[derive(Debug, Clone)]
pub struct DiffOptions {
    /// Maximum number of divergences to record before stopping.
    pub max_divergences: usize,
    /// If true, compare register snapshots at call sites to detect arg changes.
    pub compare_call_args: bool,
    /// If true, compare memory writes at matching instruction indices.
    pub compare_mem_writes: bool,
    /// If true, align traces by call sequence rather than instruction index.
    pub align_by_calls: bool,
    /// Minimum number of changed registers to report a `ChangedCallArgs` event.
    pub min_changed_regs: usize,
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self {
            max_divergences: 10_000,
            compare_call_args: true,
            compare_mem_writes: true,
            align_by_calls: false,
            min_changed_regs: 1,
        }
    }
}

// ─── TraceDiffEngine ─────────────────────────────────────────────────────────

/// Engine for comparing two execution traces.
struct CallComparisonData {
    calls_a: Vec<CallEvent>,
    calls_b: Vec<CallEvent>,
    common_targets: HashSet<Address>,
    only_in_a: Vec<Address>,
    only_in_b: Vec<Address>,
    call_sim: f64,
}

pub struct TraceDiffEngine {
    options: DiffOptions,
}

impl TraceDiffEngine {
    /// Create a new diff engine with default options.
    #[must_use]
    pub fn new() -> Self {
        Self { options: DiffOptions::default() }
    }

    /// Create a new diff engine with custom options.
    #[must_use]
    pub const fn with_options(options: DiffOptions) -> Self {
        Self { options }
    }

    /// Compare two traces and return a full diff report.
    /// # Panics
    /// Panics if invariants are violated.
    #[must_use]
    pub fn diff(&self, a: &ExecutionTrace, b: &ExecutionTrace) -> TraceDiffReport {
        let mut divergences: Vec<DivergencePoint> = Vec::new();
        let pc_sim = Self::compute_pc_similarity(a, b);
        let call_data = Self::compute_call_info(a, b);
        self.collect_missing_calls(&call_data.calls_a, &call_data.only_in_a, true, &mut divergences);
        self.collect_missing_calls(&call_data.calls_b, &call_data.only_in_b, false, &mut divergences);
        let first_pc_divergence_idx = self.scan_aligned_entries(a, b, &mut divergences);
        Self::add_truncation_events(a, b, &mut divergences);
        let stats = DiffStats {
            total_divergences: divergences.len(),
            critical: divergences.iter().filter(|d| d.severity == 2).count(),
            warnings: divergences.iter().filter(|d| d.severity == 1).count(),
            info: divergences.iter().filter(|d| d.severity == 0).count(),
            calls_only_in_a: call_data.only_in_a.len(),
            calls_only_in_b: call_data.only_in_b.len(),
            common_call_targets: call_data.common_targets.len(),
            call_sequence_similarity: call_data.call_sim,
            pc_coverage_similarity: pc_sim,
        };
        TraceDiffReport {
            name_a: a.binary_name.clone(),
            name_b: b.binary_name.clone(),
            divergences,
            stats,
            calls_only_in_a: call_data.only_in_a,
            calls_only_in_b: call_data.only_in_b,
            common_call_targets: call_data.common_targets,
            first_pc_divergence_idx,
        }
    }

    fn compute_pc_similarity(a: &ExecutionTrace, b: &ExecutionTrace) -> f64 {
        let pcs_a: HashSet<Address> = a.entries.iter().map(|e| e.pc).collect();
        let pcs_b: HashSet<Address> = b.entries.iter().map(|e| e.pc).collect();
        let common_pcs = pcs_a.intersection(&pcs_b).count();
        let union_pcs = pcs_a.union(&pcs_b).count();
        if union_pcs == 0 { 1.0 } else {
            f64::from(u32::try_from(common_pcs).unwrap_or(u32::MAX)) /
            f64::from(u32::try_from(union_pcs).unwrap_or(u32::MAX))
        }
    }

    fn compute_call_info(a: &ExecutionTrace, b: &ExecutionTrace) -> CallComparisonData {
        let calls_a = extract_call_sequence(a);
        let calls_b = extract_call_sequence(b);
        let targets_a: HashSet<Address> = calls_a.iter().map(|c| c.target).collect();
        let targets_b: HashSet<Address> = calls_b.iter().map(|c| c.target).collect();
        let common_targets: HashSet<Address> = targets_a.intersection(&targets_b).copied().collect();
        let only_in_a: Vec<Address> = targets_a.difference(&targets_b).copied().collect();
        let only_in_b: Vec<Address> = targets_b.difference(&targets_a).copied().collect();
        let union_targets = targets_a.union(&targets_b).count();
        let call_sim = if union_targets == 0 { 1.0 } else {
            f64::from(u32::try_from(common_targets.len()).unwrap_or(u32::MAX)) /
            f64::from(u32::try_from(union_targets).unwrap_or(u32::MAX))
        };
        CallComparisonData { calls_a, calls_b, common_targets, only_in_a, only_in_b, call_sim }
    }

    fn collect_missing_calls(&self, calls: &[CallEvent], addrs: &[Address], is_a: bool,
        divergences: &mut Vec<DivergencePoint>) {
        for addr in addrs {
            if divergences.len() >= self.options.max_divergences { break; }
            let event = calls.iter().find(|c| c.target == *addr).unwrap();
            let point = if is_a {
                DivergencePoint::new(event.idx, 0, event.pc, 0, DivergenceKind::MissingCallInB { target: *addr })
            } else {
                DivergencePoint::new(0, event.idx, 0, event.pc, DivergenceKind::NewCallInB { target: *addr })
            };
            divergences.push(point);
        }
    }

    fn scan_aligned_entries(&self, a: &ExecutionTrace, b: &ExecutionTrace,
        divergences: &mut Vec<DivergencePoint>) -> Option<(usize, usize)> {
        let mut first_pc_divergence_idx = None;
        let min_len = a.entries.len().min(b.entries.len());
        for idx in 0..min_len {
            if divergences.len() >= self.options.max_divergences { break; }
            let ea = &a.entries[idx];
            let eb = &b.entries[idx];
            if ea.pc != eb.pc {
                first_pc_divergence_idx.get_or_insert((ea.idx, eb.idx));
                divergences.push(DivergencePoint::new(ea.idx, eb.idx, ea.pc, eb.pc,
                    DivergenceKind::PcDivergence { pc_a: ea.pc, pc_b: eb.pc }));
                break;
            }
            if self.options.compare_call_args { self.compare_calls(ea, eb, divergences); }
            if self.options.compare_mem_writes { Self::compare_mem_writes(ea, eb, divergences); }
        }
        first_pc_divergence_idx
    }

    fn add_truncation_events(a: &ExecutionTrace, b: &ExecutionTrace,
        divergences: &mut Vec<DivergencePoint>) {
        if a.entries.len() < b.entries.len() {
            divergences.push(DivergencePoint::new(a.entries.len(), a.entries.len(), 0, 0,
                DivergenceKind::TraceATruncated { end_idx: a.entries.len() }));
        } else if b.entries.len() < a.entries.len() {
            divergences.push(DivergencePoint::new(b.entries.len(), b.entries.len(), 0, 0,
                DivergenceKind::TraceBTruncated { end_idx: b.entries.len() }));
        }
    }

    fn compare_calls(
        &self,
        ea: &TraceEntry,
        eb: &TraceEntry,
        divergences: &mut Vec<DivergencePoint>,
    ) {
        match (&ea.kind, &eb.kind) {
            (EntryKind::Call { target: ta, .. }, EntryKind::Call { target: tb, .. }) => {
                if ta == tb {
                    // Same target —" compare arg registers
                    let changed = Self::diff_regs(&ea.reg_snapshot, &eb.reg_snapshot);
                    if changed.len() >= self.options.min_changed_regs {
                        divergences.push(DivergencePoint::new(
                            ea.idx,
                            eb.idx,
                            ea.pc,
                            eb.pc,
                            DivergenceKind::ChangedCallArgs { target: *ta, changed_regs: changed },
                        ));
                    }
                } else {
                    divergences.push(DivergencePoint::new(
                        ea.idx,
                        eb.idx,
                        ea.pc,
                        eb.pc,
                        DivergenceKind::ChangedCallTarget { target_a: *ta, target_b: *tb },
                    ));
                }
            }
            (EntryKind::Call { target, .. }, _) => {
                divergences.push(DivergencePoint::new(
                    ea.idx,
                    eb.idx,
                    ea.pc,
                    eb.pc,
                    DivergenceKind::MissingCallInB { target: *target },
                ));
            }
            (_, EntryKind::Call { target, .. }) => {
                divergences.push(DivergencePoint::new(
                    ea.idx,
                    eb.idx,
                    ea.pc,
                    eb.pc,
                    DivergenceKind::NewCallInB { target: *target },
                ));
            }
            _ => {}
        }
    }

    fn compare_mem_writes(
        ea: &TraceEntry,
        eb: &TraceEntry,
        divergences: &mut Vec<DivergencePoint>,
    ) {
        let writes_a: HashMap<Address, &Vec<u8>> = ea.mem_writes.iter().map(|(a, b)| (*a, b)).collect();
        let writes_b: HashMap<Address, &Vec<u8>> = eb.mem_writes.iter().map(|(a, b)| (*a, b)).collect();

        for (addr, bytes_a) in &writes_a {
            if let Some(bytes_b) = writes_b.get(addr)
                && bytes_a != bytes_b {
                    divergences.push(DivergencePoint::new(
                        ea.idx,
                        eb.idx,
                        ea.pc,
                        eb.pc,
                        DivergenceKind::MemWriteDifference {
                            addr: *addr,
                            value_a: (*bytes_a).clone(),
                            value_b: (*bytes_b).clone(),
                        },
                    ));
                }
        }
    }

    fn diff_regs(
        regs_a: &[(RegId, u64)],
        regs_b: &[(RegId, u64)],
    ) -> Vec<(RegId, u64, u64)> {
        let map_a: HashMap<RegId, u64> = regs_a.iter().copied().collect();
        let map_b: HashMap<RegId, u64> = regs_b.iter().copied().collect();
        let mut changed = Vec::new();
        for (reg, val_a) in &map_a {
            if let Some(val_b) = map_b.get(reg)
                && val_a != val_b {
                    changed.push((*reg, *val_a, *val_b));
                }
        }
        changed.sort_by_key(|(r, _, _)| *r);
        changed
    }
}

impl Default for TraceDiffEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Convenience free function ────────────────────────────────────────────────

/// Compare two traces using default options. Returns a [`TraceDiffReport`].
#[must_use]
pub fn diff_traces(a: &ExecutionTrace, b: &ExecutionTrace) -> TraceDiffReport {
    TraceDiffEngine::new().diff(a, b)
}

// ─── CallSequenceLcs ──────────────────────────────────────────────────────────

/// Compute the longest common subsequence of call targets between two traces.
///
/// Returns the matched (`target_a_idx`, `target_b_idx`) pairs.
#[must_use]
pub fn call_lcs(trace_a: &ExecutionTrace, trace_b: &ExecutionTrace) -> Vec<(usize, usize)> {
    let seq_a = extract_call_sequence(trace_a);
    let seq_b = extract_call_sequence(trace_b);
    let len_a = seq_a.len();
    let len_b = seq_b.len();

    // DP table
    let mut dp = vec![vec![0u32; len_b + 1]; len_a + 1];
    for row in 1..=len_a {
        for col in 1..=len_b {
            dp[row][col] = if seq_a[row - 1].target == seq_b[col - 1].target {
                dp[row - 1][col - 1].saturating_add(1)
            } else {
                dp[row - 1][col].max(dp[row][col - 1])
            };
        }
    }

    // Backtrack
    let mut pairs = Vec::new();
    let (mut row, mut col) = (len_a, len_b);
    while row > 0 && col > 0 {
        if seq_a[row - 1].target == seq_b[col - 1].target {
            pairs.push((row - 1, col - 1));
            row -= 1;
            col -= 1;
        } else if dp[row - 1][col] > dp[row][col - 1] {
            row -= 1;
        } else {
            col -= 1;
        }
    }
    pairs.reverse();
    pairs
}

// ─── HeatmapDelta ─────────────────────────────────────────────────────────────

/// Per-address execution count delta between two traces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeatmapDelta {
    /// Address -> (`count_a`, `count_b`, delta).
    pub entries: Vec<(Address, usize, usize, i64)>,
}

impl HeatmapDelta {
    /// Compute the execution count delta between two traces.
    #[must_use]
    pub fn compute(a: &ExecutionTrace, b: &ExecutionTrace) -> Self {
        let mut counts_a: HashMap<Address, usize> = HashMap::new();
        let mut counts_b: HashMap<Address, usize> = HashMap::new();

        for e in &a.entries {
            *counts_a.entry(e.pc).or_default() += 1;
        }
        for e in &b.entries {
            *counts_b.entry(e.pc).or_default() += 1;
        }

        let all_addrs: HashSet<Address> = counts_a.keys().chain(counts_b.keys()).copied().collect();
        let mut entries: Vec<(Address, usize, usize, i64)> = all_addrs
            .into_iter()
            .map(|addr| {
                let ca = *counts_a.get(&addr).unwrap_or(&0);
                let cb = *counts_b.get(&addr).unwrap_or(&0);
                let delta = i64::try_from(cb).unwrap_or(i64::MAX) - i64::try_from(ca).unwrap_or(i64::MAX);
                (addr, ca, cb, delta)
            })
            .collect();
        entries.sort_by_key(|a| a.0);
        Self { entries }
    }

    /// Return addresses with the largest absolute delta.
    #[must_use]
    pub fn top_delta(&self, n: usize) -> Vec<(Address, i64)> {
        let mut sorted = self.entries.clone();
        sorted.sort_by(|a, b| b.3.unsigned_abs().cmp(&a.3.unsigned_abs()));
        sorted.truncate(n);
        sorted.into_iter().map(|(addr, _, _, d)| (addr, d)).collect()
    }
}
