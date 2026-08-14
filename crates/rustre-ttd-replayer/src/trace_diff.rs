//! Trace differencing: compare two execution traces.
//!
//! Finds divergence points, correlates equivalent positions between traces,
//! diffs register/memory/call sequences, generates human-readable diff reports,
//! and supports patch effect detection.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{MemWriteRecord, TraceEvent, TtdTrace};

// ─── TraceDiffError ───────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum TraceDiffError {
    #[error("both traces must be non-empty")]
    EmptyTrace,
    #[error("correlation window size must be > 0")]
    ZeroWindow,
    #[error("no common anchor events found between the two traces")]
    NoAnchors,
}

// ─── DivergenceKind ───────────────────────────────────────────────────────────

/// The category of a divergence between two traces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DivergenceKind {
    /// A syscall present in A is missing in B.
    SyscallInsertedInA,
    /// A syscall present in B is missing in A.
    SyscallInsertedInB,
    /// A syscall number differs at the correlated position.
    SyscallNumberChanged { a_nr: u64, b_nr: u64 },
    /// Syscall return value differs.
    RetvalDiverged { a_ret: i64, b_ret: i64 },
    /// Memory write at the same logical position wrote different data.
    MemoryWriteDiverged {
        addr: u64,
        a_data: Vec<u8>,
        b_data: Vec<u8>,
    },
    /// Signal delivered in A but not B.
    SignalInA { signal: i32 },
    /// Signal delivered in B but not A.
    SignalInB { signal: i32 },
    /// Register value differs at the correlated position.
    RegisterDiverged {
        register: String,
        a_value: u64,
        b_value: u64,
    },
    /// Number of memory writes differs for the same syscall.
    WriteCountDiverged { a_count: usize, b_count: usize },
}

impl fmt::Display for DivergenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SyscallInsertedInA => write!(f, "SyscallInsertedInA"),
            Self::SyscallInsertedInB => write!(f, "SyscallInsertedInB"),
            Self::SyscallNumberChanged { a_nr, b_nr } => {
                write!(f, "SyscallNrChanged({a_nr} -> {b_nr})")
            }
            Self::RetvalDiverged { a_ret, b_ret } => {
                write!(f, "RetvalDiverged({a_ret} -> {b_ret})")
            }
            Self::MemoryWriteDiverged { addr, .. } => {
                write!(f, "MemWriteDiverged@{addr:#x}")
            }
            Self::SignalInA { signal } => write!(f, "SignalInA({signal})"),
            Self::SignalInB { signal } => write!(f, "SignalInB({signal})"),
            Self::RegisterDiverged {
                register,
                a_value,
                b_value,
            } => write!(f, "RegDiverged({register}: {a_value:#x} vs {b_value:#x})"),
            Self::WriteCountDiverged { a_count, b_count } => {
                write!(f, "WriteCountDiverged({a_count} vs {b_count})")
            }
        }
    }
}

// ─── DivergencePoint ──────────────────────────────────────────────────────────

/// A single point of divergence between trace A and trace B.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DivergencePoint {
    /// Tick in trace A where divergence was detected (or None if B-only).
    pub tick_a: Option<u64>,
    /// Tick in trace B where divergence was detected (or None if A-only).
    pub tick_b: Option<u64>,
    /// Event index in trace A (if applicable).
    pub event_idx_a: Option<usize>,
    /// Event index in trace B (if applicable).
    pub event_idx_b: Option<usize>,
    /// The category of this divergence.
    pub kind: DivergenceKind,
    /// Human-readable description.
    pub description: String,
    /// Confidence score 0.0–1.0.
    pub confidence: f64,
}

impl DivergencePoint {
    fn new(
        tick_a: Option<u64>,
        tick_b: Option<u64>,
        idx_a: Option<usize>,
        idx_b: Option<usize>,
        kind: DivergenceKind,
        description: impl Into<String>,
        confidence: f64,
    ) -> Self {
        Self {
            tick_a,
            tick_b,
            event_idx_a: idx_a,
            event_idx_b: idx_b,
            kind,
            description: description.into(),
            confidence,
        }
    }
}

impl fmt::Display for DivergencePoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Divergence [{:?}@A, {:?}@B] {}: {}",
            self.tick_a, self.tick_b, self.kind, self.description
        )
    }
}

// ─── TraceCorrelation ─────────────────────────────────────────────────────────

/// Correlation between positions in trace A and trace B.
///
/// Used to align the two traces before computing diffs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCorrelation {
    /// Correlated pairs: (`event_idx_a`, `event_idx_b`, `similarity_score`).
    pub pairs: Vec<(usize, usize, f64)>,
    /// Quality of the overall correlation (0.0 = uncorrelated, 1.0 = perfect).
    pub quality: f64,
    /// Method used to compute the correlation.
    pub method: CorrelationMethod,
}

/// Algorithm used to correlate two traces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorrelationMethod {
    /// Match events by syscall number sequence (fast).
    SyscallSequence,
    /// Match by longest common subsequence of syscall numbers.
    LongestCommonSubsequence,
    /// Match by tick offset (direct time alignment).
    TickOffset,
    /// Anchor-based alignment using signal/exception events as landmarks.
    AnchorBased,
}

impl fmt::Display for CorrelationMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::SyscallSequence => "SyscallSequence",
            Self::LongestCommonSubsequence => "LCS",
            Self::TickOffset => "TickOffset",
            Self::AnchorBased => "AnchorBased",
        };
        write!(f, "{s}")
    }
}

// ─── PatchEffect ──────────────────────────────────────────────────────────────

/// Describes the observable effect of a patch (code change) between two traces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchEffect {
    /// First tick in A where the patch effect is visible.
    pub first_affected_tick_a: u64,
    /// First tick in B where the patch effect is visible.
    pub first_affected_tick_b: u64,
    /// New syscalls introduced by the patch (in B but not A).
    pub new_syscalls: Vec<u64>,
    /// Syscalls removed by the patch (in A but not B).
    pub removed_syscalls: Vec<u64>,
    /// Memory addresses whose write behavior changed.
    pub changed_write_addresses: Vec<u64>,
    /// Net change in total memory writes (B - A).
    pub net_write_delta: i64,
    /// Net change in total syscall count (B - A).
    pub net_syscall_delta: i64,
    /// Confidence in patch boundary localization (0.0–1.0).
    pub confidence: f64,
}

impl fmt::Display for PatchEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PatchEffect: new_syscalls={}, removed={}, changed_writes={}, wr_delta={:+}, conf={:.2}",
            self.new_syscalls.len(),
            self.removed_syscalls.len(),
            self.changed_write_addresses.len(),
            self.net_write_delta,
            self.confidence
        )
    }
}

// ─── DiffReport ───────────────────────────────────────────────────────────────

/// A complete human-readable diff report between two traces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    /// Trace A metadata.
    pub trace_a_events: usize,
    /// Trace B metadata.
    pub trace_b_events: usize,
    /// All divergence points found, sorted by tick.
    pub divergences: Vec<DivergencePoint>,
    /// Correlation used to align the traces.
    pub correlation: TraceCorrelation,
    /// Detected patch effect (if any).
    pub patch_effect: Option<PatchEffect>,
    /// Summary statistics.
    pub summary: DiffSummary,
}

/// Summary statistics extracted from a diff report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    pub total_divergences: usize,
    pub syscall_divergences: usize,
    pub memory_divergences: usize,
    pub register_divergences: usize,
    pub signal_divergences: usize,
    pub first_divergence_tick_a: Option<u64>,
    pub first_divergence_tick_b: Option<u64>,
    pub identical: bool,
    pub similarity_score: f64,
}

impl fmt::Display for DiffSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.identical {
            write!(f, "Traces are identical")
        } else {
            write!(
                f,
                "Diverges at A:{:?}/B:{:?} — {} total divergences (syscall={}, mem={}, reg={}), similarity={:.1}%",
                self.first_divergence_tick_a,
                self.first_divergence_tick_b,
                self.total_divergences,
                self.syscall_divergences,
                self.memory_divergences,
                self.register_divergences,
                self.similarity_score * 100.0
            )
        }
    }
}

impl fmt::Display for DiffReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== TraceDiff Report ===")?;
        writeln!(f, "Trace A: {} events", self.trace_a_events)?;
        writeln!(f, "Trace B: {} events", self.trace_b_events)?;
        writeln!(f, "Correlation: {} (quality={:.2})", self.correlation.method, self.correlation.quality)?;
        writeln!(f, "Summary: {}", self.summary)?;
        if let Some(pe) = &self.patch_effect {
            writeln!(f, "Patch: {pe}")?;
        }
        for (i, div) in self.divergences.iter().take(20).enumerate() {
            writeln!(f, "  [{i}] {div}")?;
        }
        if self.divergences.len() > 20 {
            writeln!(f, "  ... ({} more)", self.divergences.len() - 20)?;
        }
        Ok(())
    }
}

// ─── TraceDiff ────────────────────────────────────────────────────────────────

/// Engine for computing the diff between two TTD traces.
///
/// # Usage
///
/// ```no_run
/// # use rustre_ttd_replayer::trace_diff::TraceDiff;
/// # use rustre_ttd_replayer::TtdTrace;
/// # let trace_a = TtdTrace::new();
/// # let trace_b = TtdTrace::new();
/// let diff = TraceDiff::new(&trace_a, &trace_b);
/// let report = diff.compute_full_diff().unwrap();
/// println!("{}", report);
/// ```
pub struct TraceDiff<'a> {
    trace_a: &'a TtdTrace,
    trace_b: &'a TtdTrace,
    correlation_method: CorrelationMethod,
    compare_memory: bool,
    compare_registers: bool,
    max_divergences: usize,
}

impl<'a> TraceDiff<'a> {
    /// Create a new diff engine for traces A and B.
    #[must_use] 
    pub const fn new(trace_a: &'a TtdTrace, trace_b: &'a TtdTrace) -> Self {
        Self {
            trace_a,
            trace_b,
            correlation_method: CorrelationMethod::SyscallSequence,
            compare_memory: true,
            compare_registers: false,
            max_divergences: 10_000,
        }
    }

    /// Set the correlation method.
    #[must_use] 
    pub const fn with_correlation_method(mut self, method: CorrelationMethod) -> Self {
        self.correlation_method = method;
        self
    }

    /// Enable or disable memory write comparison.
    #[must_use] 
    pub const fn compare_memory(mut self, enabled: bool) -> Self {
        self.compare_memory = enabled;
        self
    }

    /// Enable or disable register comparison.
    #[must_use] 
    pub const fn compare_registers(mut self, enabled: bool) -> Self {
        self.compare_registers = enabled;
        self
    }

    /// Set the maximum number of divergences to record.
    #[must_use] 
    pub const fn max_divergences(mut self, n: usize) -> Self {
        self.max_divergences = n;
        self
    }

    /// Compute a full diff report.
    pub fn compute_full_diff(self) -> Result<DiffReport, TraceDiffError> {
        if self.trace_a.events.is_empty() || self.trace_b.events.is_empty() {
            return Err(TraceDiffError::EmptyTrace);
        }

        let correlation = self.compute_correlation()?;
        let divergences = self.find_divergences(&correlation);
        let patch_effect = detect_patch_effect(self.trace_a, self.trace_b, &divergences);

        let summary = build_summary(&divergences, self.trace_a, self.trace_b);

        Ok(DiffReport {
            trace_a_events: self.trace_a.events.len(),
            trace_b_events: self.trace_b.events.len(),
            divergences,
            correlation,
            patch_effect: Some(patch_effect),
            summary,
        })
    }

    // ─── Correlation ──────────────────────────────────────────────────────────

    fn compute_correlation(&self) -> Result<TraceCorrelation, TraceDiffError> {
        match self.correlation_method {
            CorrelationMethod::SyscallSequence => Ok(self.correlate_syscall_sequence()),
            CorrelationMethod::LongestCommonSubsequence => Ok(self.correlate_lcs()),
            CorrelationMethod::TickOffset => Ok(self.correlate_tick_offset()),
            CorrelationMethod::AnchorBased => self.correlate_anchor_based(),
        }
    }

    fn correlate_syscall_sequence(&self) -> TraceCorrelation {
        let sys_a: Vec<(usize, u64)> = self
            .trace_a
            .events
            .iter()
            .enumerate()
            .filter_map(|(i, ev)| match ev {
                TraceEvent::SyscallEntry { nr, .. } => Some((i, *nr)),
                _ => None,
            })
            .collect();

        let sys_b: Vec<(usize, u64)> = self
            .trace_b
            .events
            .iter()
            .enumerate()
            .filter_map(|(i, ev)| match ev {
                TraceEvent::SyscallEntry { nr, .. } => Some((i, *nr)),
                _ => None,
            })
            .collect();

        let mut pairs = Vec::new();
        let min_len = sys_a.len().min(sys_b.len());

        for i in 0..min_len {
            let score = if sys_a[i].1 == sys_b[i].1 { 1.0 } else { 0.5 };
            pairs.push((sys_a[i].0, sys_b[i].0, score));
        }

        let quality = if min_len > 0 {
            let matched = pairs.iter().filter(|(_, _, s)| *s == 1.0).count();
            matched as f64 / min_len as f64
        } else {
            0.0
        };

        TraceCorrelation {
            pairs,
            quality,
            method: CorrelationMethod::SyscallSequence,
        }
    }

    fn correlate_lcs(&self) -> TraceCorrelation {
        // Extract syscall NR sequences.
        let seq_a: Vec<(usize, u64)> = self
            .trace_a
            .events
            .iter()
            .enumerate()
            .filter_map(|(i, ev)| match ev {
                TraceEvent::SyscallEntry { nr, .. } => Some((i, *nr)),
                _ => None,
            })
            .collect();
        let seq_b: Vec<(usize, u64)> = self
            .trace_b
            .events
            .iter()
            .enumerate()
            .filter_map(|(i, ev)| match ev {
                TraceEvent::SyscallEntry { nr, .. } => Some((i, *nr)),
                _ => None,
            })
            .collect();

        // Standard LCS DP table (capped at 1024 entries each for performance).
        let a_nr: Vec<u64> = seq_a.iter().map(|(_, n)| *n).take(1024).collect();
        let b_nr: Vec<u64> = seq_b.iter().map(|(_, n)| *n).take(1024).collect();
        let m = a_nr.len();
        let n = b_nr.len();

        let mut dp = vec![vec![0u32; n + 1]; m + 1];
        for i in 1..=m {
            for j in 1..=n {
                if a_nr[i - 1] == b_nr[j - 1] {
                    dp[i][j] = dp[i - 1][j - 1] + 1;
                } else {
                    dp[i][j] = dp[i - 1][j].max(dp[i][j - 1]);
                }
            }
        }

        // Backtrack to build pairs.
        let mut pairs = Vec::new();
        let mut i = m;
        let mut j = n;
        while i > 0 && j > 0 {
            if a_nr[i - 1] == b_nr[j - 1] {
                pairs.push((seq_a[i - 1].0, seq_b[j - 1].0, 1.0f64));
                i -= 1;
                j -= 1;
            } else if dp[i - 1][j] > dp[i][j - 1] {
                i -= 1;
            } else {
                j -= 1;
            }
        }
        pairs.reverse();

        let lcs_len = f64::from(dp[m][n]);
        let quality = if m.max(n) > 0 {
            lcs_len / m.max(n) as f64
        } else {
            1.0
        };

        TraceCorrelation {
            pairs,
            quality,
            method: CorrelationMethod::LongestCommonSubsequence,
        }
    }

    fn correlate_tick_offset(&self) -> TraceCorrelation {
        let tick_a = self.trace_a.min_tick();
        let tick_b = self.trace_b.min_tick();
        let offset = tick_b as i64 - tick_a as i64;

        let mut pairs = Vec::new();
        for (i_a, ev_a) in self.trace_a.events.iter().enumerate() {
            let target_tick = (ev_a.tick() as i64 + offset) as u64;
            // Find the closest event in B by tick.
            let best = self
                .trace_b
                .events
                .iter()
                .enumerate()
                .min_by_key(|(_, ev_b)| {
                    
                    if ev_b.tick() >= target_tick {
                        ev_b.tick() - target_tick
                    } else {
                        target_tick - ev_b.tick()
                    }
                });
            if let Some((i_b, ev_b)) = best {
                let diff = if ev_b.tick() >= target_tick {
                    ev_b.tick() - target_tick
                } else {
                    target_tick - ev_b.tick()
                };
                let score = 1.0 / (1.0 + diff as f64);
                pairs.push((i_a, i_b, score));
            }
        }

        let quality = if pairs.is_empty() {
            0.0
        } else {
            pairs.iter().map(|(_, _, s)| s).sum::<f64>() / pairs.len() as f64
        };

        TraceCorrelation {
            pairs,
            quality,
            method: CorrelationMethod::TickOffset,
        }
    }

    fn correlate_anchor_based(&self) -> Result<TraceCorrelation, TraceDiffError> {
        // Use signal and exception events as anchors.
        let anchors_a: Vec<(usize, i32)> = self
            .trace_a
            .events
            .iter()
            .enumerate()
            .filter_map(|(i, ev)| match ev {
                TraceEvent::SignalDelivered { signal, .. } => Some((i, *signal)),
                _ => None,
            })
            .collect();
        let anchors_b: Vec<(usize, i32)> = self
            .trace_b
            .events
            .iter()
            .enumerate()
            .filter_map(|(i, ev)| match ev {
                TraceEvent::SignalDelivered { signal, .. } => Some((i, *signal)),
                _ => None,
            })
            .collect();

        if anchors_a.is_empty() && anchors_b.is_empty() {
            // Fall back to syscall sequence.
            return Ok(self.correlate_syscall_sequence());
        }

        let mut pairs = Vec::new();
        let min_anchors = anchors_a.len().min(anchors_b.len());
        for i in 0..min_anchors {
            let score = if anchors_a[i].1 == anchors_b[i].1 { 1.0 } else { 0.3 };
            pairs.push((anchors_a[i].0, anchors_b[i].0, score));
        }

        let quality = if min_anchors > 0 {
            pairs.iter().filter(|(_, _, s)| *s == 1.0).count() as f64
                / min_anchors as f64
        } else {
            0.5
        };

        Ok(TraceCorrelation {
            pairs,
            quality,
            method: CorrelationMethod::AnchorBased,
        })
    }

    // ─── Divergence finding ───────────────────────────────────────────────────

    fn find_divergences(&self, correlation: &TraceCorrelation) -> Vec<DivergencePoint> {
        let mut divergences = Vec::new();

        for &(idx_a, idx_b, _score) in &correlation.pairs {
            if divergences.len() >= self.max_divergences {
                break;
            }

            let ev_a = &self.trace_a.events[idx_a];
            let ev_b = &self.trace_b.events[idx_b];

            match (ev_a, ev_b) {
                (
                    TraceEvent::SyscallEntry { tick: ta, nr: nr_a, .. },
                    TraceEvent::SyscallEntry { tick: tb, nr: nr_b, .. },
                ) => {
                    if nr_a != nr_b {
                        divergences.push(DivergencePoint::new(
                            Some(*ta),
                            Some(*tb),
                            Some(idx_a),
                            Some(idx_b),
                            DivergenceKind::SyscallNumberChanged {
                                a_nr: *nr_a,
                                b_nr: *nr_b,
                            },
                            format!("Syscall nr changed: {nr_a} -> {nr_b}"),
                            0.95,
                        ));
                    }
                }
                (
                    TraceEvent::SyscallExit { tick: ta, retval: ra, mem_writes: wa },
                    TraceEvent::SyscallExit { tick: tb, retval: rb, mem_writes: wb },
                ) => {
                    if ra != rb {
                        divergences.push(DivergencePoint::new(
                            Some(*ta),
                            Some(*tb),
                            Some(idx_a),
                            Some(idx_b),
                            DivergenceKind::RetvalDiverged {
                                a_ret: *ra,
                                b_ret: *rb,
                            },
                            format!("Retval diverged: {ra} -> {rb}"),
                            0.9,
                        ));
                    }
                    if self.compare_memory && wa.len() != wb.len() {
                        divergences.push(DivergencePoint::new(
                            Some(*ta),
                            Some(*tb),
                            Some(idx_a),
                            Some(idx_b),
                            DivergenceKind::WriteCountDiverged {
                                a_count: wa.len(),
                                b_count: wb.len(),
                            },
                            format!("Write count: {} vs {}", wa.len(), wb.len()),
                            0.8,
                        ));
                    }
                    if self.compare_memory {
                        let write_divs = diff_mem_writes(wa, wb, *ta, *tb, idx_a, idx_b);
                        divergences.extend(write_divs);
                    }
                }
                (
                    TraceEvent::SignalDelivered { tick: ta, signal: sa, .. },
                    TraceEvent::SignalDelivered { tick: tb, signal: sb, .. },
                ) => {
                    if sa != sb {
                        divergences.push(DivergencePoint::new(
                            Some(*ta),
                            Some(*tb),
                            Some(idx_a),
                            Some(idx_b),
                            DivergenceKind::SignalInA { signal: *sa },
                            format!("Signal differs: {sa} vs {sb}"),
                            0.85,
                        ));
                    }
                }
                (TraceEvent::SyscallEntry { tick: ta, nr: nr_a, .. }, _) => {
                    divergences.push(DivergencePoint::new(
                        Some(*ta),
                        None,
                        Some(idx_a),
                        None,
                        DivergenceKind::SyscallInsertedInA,
                        format!("Syscall {nr_a} only in A"),
                        0.7,
                    ));
                }
                (_, TraceEvent::SyscallEntry { tick: tb, nr: nr_b, .. }) => {
                    divergences.push(DivergencePoint::new(
                        None,
                        Some(*tb),
                        None,
                        Some(idx_b),
                        DivergenceKind::SyscallInsertedInB,
                        format!("Syscall {nr_b} only in B"),
                        0.7,
                    ));
                }
                _ => {}
            }
        }

        // Check for A-only signals not in correlation.
        let correlated_a: HashSet<usize> = correlation.pairs.iter().map(|(a, _, _)| *a).collect();
        for (i, ev) in self.trace_a.events.iter().enumerate() {
            if correlated_a.contains(&i) {
                continue;
            }
            if let TraceEvent::SignalDelivered { tick, signal, .. } = ev {
                divergences.push(DivergencePoint::new(
                    Some(*tick),
                    None,
                    Some(i),
                    None,
                    DivergenceKind::SignalInA { signal: *signal },
                    format!("Signal {signal} only in A"),
                    0.8,
                ));
            }
        }

        // Check for B-only signals not in correlation.
        let correlated_b: HashSet<usize> = correlation.pairs.iter().map(|(_, b, _)| *b).collect();
        for (i, ev) in self.trace_b.events.iter().enumerate() {
            if correlated_b.contains(&i) {
                continue;
            }
            if let TraceEvent::SignalDelivered { tick, signal, .. } = ev {
                divergences.push(DivergencePoint::new(
                    None,
                    Some(*tick),
                    None,
                    Some(i),
                    DivergenceKind::SignalInB { signal: *signal },
                    format!("Signal {signal} only in B"),
                    0.8,
                ));
            }
        }

        divergences.sort_by_key(|d| d.tick_a.or(d.tick_b));
        divergences
    }
}

// ─── Diff helpers ─────────────────────────────────────────────────────────────

fn diff_mem_writes(
    wa: &[MemWriteRecord],
    wb: &[MemWriteRecord],
    tick_a: u64,
    tick_b: u64,
    idx_a: usize,
    idx_b: usize,
) -> Vec<DivergencePoint> {
    let mut divs = Vec::new();
    let build_map = |writes: &[MemWriteRecord]| -> HashMap<u64, Vec<u8>> {
        let mut m = HashMap::new();
        for wr in writes {
            m.entry(wr.addr).or_insert_with(Vec::new).extend(&wr.data);
        }
        m
    };

    let map_a = build_map(wa);
    let map_b = build_map(wb);

    for (addr, data_a) in &map_a {
        match map_b.get(addr) {
            Some(data_b) if data_a != data_b => {
                divs.push(DivergencePoint::new(
                    Some(tick_a),
                    Some(tick_b),
                    Some(idx_a),
                    Some(idx_b),
                    DivergenceKind::MemoryWriteDiverged {
                        addr: *addr,
                        a_data: data_a.clone(),
                        b_data: data_b.clone(),
                    },
                    format!("Memory write at {addr:#x} differs"),
                    0.85,
                ));
            }
            _ => {}
        }
    }
    divs
}

// ─── Patch effect detection ───────────────────────────────────────────────────

fn detect_patch_effect(
    trace_a: &TtdTrace,
    trace_b: &TtdTrace,
    divergences: &[DivergencePoint],
) -> PatchEffect {
    let first_div_tick_a = divergences.iter().filter_map(|d| d.tick_a).min().unwrap_or(0);
    let first_div_tick_b = divergences.iter().filter_map(|d| d.tick_b).min().unwrap_or(0);

    // Syscall sets in each trace.
    let syscalls_a: HashSet<u64> = trace_a
        .events
        .iter()
        .filter_map(|ev| match ev {
            TraceEvent::SyscallEntry { nr, .. } => Some(*nr),
            _ => None,
        })
        .collect();
    let syscalls_b: HashSet<u64> = trace_b
        .events
        .iter()
        .filter_map(|ev| match ev {
            TraceEvent::SyscallEntry { nr, .. } => Some(*nr),
            _ => None,
        })
        .collect();

    let new_syscalls: Vec<u64> = syscalls_b.difference(&syscalls_a).copied().collect();
    let removed_syscalls: Vec<u64> = syscalls_a.difference(&syscalls_b).copied().collect();

    // Changed write addresses.
    let changed_write_addresses: Vec<u64> = divergences
        .iter()
        .filter_map(|d| match &d.kind {
            DivergenceKind::MemoryWriteDiverged { addr, .. } => Some(*addr),
            _ => None,
        })
        .collect::<HashSet<u64>>()
        .into_iter()
        .collect();

    // Net write delta.
    let writes_a: i64 = trace_a
        .events
        .iter()
        .filter_map(|ev| match ev {
            TraceEvent::SyscallExit { mem_writes, .. } => Some(mem_writes.len() as i64),
            _ => None,
        })
        .sum();
    let writes_b: i64 = trace_b
        .events
        .iter()
        .filter_map(|ev| match ev {
            TraceEvent::SyscallExit { mem_writes, .. } => Some(mem_writes.len() as i64),
            _ => None,
        })
        .sum();

    let syscall_count_a = syscalls_a.len() as i64;
    let syscall_count_b = syscalls_b.len() as i64;

    let confidence = if divergences.is_empty() {
        0.0
    } else {
        0.1f64.mul_add((divergences.len() as f64 / 10.0).min(0.5), 0.5)
    };

    PatchEffect {
        first_affected_tick_a: first_div_tick_a,
        first_affected_tick_b: first_div_tick_b,
        new_syscalls,
        removed_syscalls,
        changed_write_addresses,
        net_write_delta: writes_b - writes_a,
        net_syscall_delta: syscall_count_b - syscall_count_a,
        confidence,
    }
}

// ─── Summary builder ──────────────────────────────────────────────────────────

fn build_summary(
    divergences: &[DivergencePoint],
    trace_a: &TtdTrace,
    trace_b: &TtdTrace,
) -> DiffSummary {
    let syscall_divs = divergences
        .iter()
        .filter(|d| {
            matches!(
                d.kind,
                DivergenceKind::SyscallNumberChanged { .. }
                    | DivergenceKind::RetvalDiverged { .. }
                    | DivergenceKind::SyscallInsertedInA
                    | DivergenceKind::SyscallInsertedInB
                    | DivergenceKind::WriteCountDiverged { .. }
            )
        })
        .count();

    let memory_divs = divergences
        .iter()
        .filter(|d| matches!(d.kind, DivergenceKind::MemoryWriteDiverged { .. }))
        .count();

    let register_divs = divergences
        .iter()
        .filter(|d| matches!(d.kind, DivergenceKind::RegisterDiverged { .. }))
        .count();

    let signal_divs = divergences
        .iter()
        .filter(|d| {
            matches!(
                d.kind,
                DivergenceKind::SignalInA { .. } | DivergenceKind::SignalInB { .. }
            )
        })
        .count();

    let first_tick_a = divergences.iter().filter_map(|d| d.tick_a).min();
    let first_tick_b = divergences.iter().filter_map(|d| d.tick_b).min();

    let identical = divergences.is_empty();

    // Similarity score: fraction of correlated events that matched without divergence.
    let total_events = trace_a.events.len().max(trace_b.events.len()).max(1);
    let similarity_score = 1.0 - (divergences.len() as f64 / total_events as f64).min(1.0);

    DiffSummary {
        total_divergences: divergences.len(),
        syscall_divergences: syscall_divs,
        memory_divergences: memory_divs,
        register_divergences: register_divs,
        signal_divergences: signal_divs,
        first_divergence_tick_a: first_tick_a,
        first_divergence_tick_b: first_tick_b,
        identical,
        similarity_score,
    }
}

// ─── Utility functions ────────────────────────────────────────────────────────

/// Quick check: return `true` if the two traces are byte-for-byte identical in
/// syscall number sequences.
#[must_use] 
pub fn syscall_sequences_equal(trace_a: &TtdTrace, trace_b: &TtdTrace) -> bool {
    let a: Vec<u64> = trace_a
        .events
        .iter()
        .filter_map(|ev| match ev {
            TraceEvent::SyscallEntry { nr, .. } => Some(*nr),
            _ => None,
        })
        .collect();
    let b: Vec<u64> = trace_b
        .events
        .iter()
        .filter_map(|ev| match ev {
            TraceEvent::SyscallEntry { nr, .. } => Some(*nr),
            _ => None,
        })
        .collect();
    a == b
}

/// Return the first tick in trace A and trace B where syscall numbers diverge.
#[must_use] 
pub fn first_syscall_divergence(
    trace_a: &TtdTrace,
    trace_b: &TtdTrace,
) -> Option<(u64, u64)> {
    let sys_a: Vec<(u64, u64)> = trace_a
        .events
        .iter()
        .filter_map(|ev| match ev {
            TraceEvent::SyscallEntry { tick, nr, .. } => Some((*tick, *nr)),
            _ => None,
        })
        .collect();
    let sys_b: Vec<(u64, u64)> = trace_b
        .events
        .iter()
        .filter_map(|ev| match ev {
            TraceEvent::SyscallEntry { tick, nr, .. } => Some((*tick, *nr)),
            _ => None,
        })
        .collect();

    for ((ta, na), (tb, nb)) in sys_a.iter().zip(sys_b.iter()) {
        if na != nb {
            return Some((*ta, *tb));
        }
    }
    None
}

/// Compute the Jaccard similarity of syscall sets between two traces.
#[must_use] 
pub fn syscall_jaccard(trace_a: &TtdTrace, trace_b: &TtdTrace) -> f64 {
    let a: HashSet<u64> = trace_a
        .events
        .iter()
        .filter_map(|ev| match ev {
            TraceEvent::SyscallEntry { nr, .. } => Some(*nr),
            _ => None,
        })
        .collect();
    let b: HashSet<u64> = trace_b
        .events
        .iter()
        .filter_map(|ev| match ev {
            TraceEvent::SyscallEntry { nr, .. } => Some(*nr),
            _ => None,
        })
        .collect();

    let intersection = a.intersection(&b).count();
    let union = a.union(&b).count();
    if union == 0 {
        1.0
    } else {
        intersection as f64 / union as f64
    }
}

/// Compute per-syscall write byte differences: `syscall_nr` -> (`bytes_in_a`, `bytes_in_b`).
#[must_use] 
pub fn per_syscall_write_bytes(
    trace_a: &TtdTrace,
    trace_b: &TtdTrace,
) -> BTreeMap<u64, (u64, u64)> {
    let accumulate = |trace: &TtdTrace| -> HashMap<u64, u64> {
        let mut pending_nr: Option<u64> = None;
        let mut result: HashMap<u64, u64> = HashMap::new();
        for ev in &trace.events {
            match ev {
                TraceEvent::SyscallEntry { nr, .. } => {
                    pending_nr = Some(*nr);
                }
                TraceEvent::SyscallExit { mem_writes, .. } => {
                    if let Some(nr) = pending_nr.take() {
                        let bytes: u64 = mem_writes.iter().map(|w| w.data.len() as u64).sum();
                        *result.entry(nr).or_default() += bytes;
                    }
                }
                TraceEvent::SignalDelivered { .. } => {}
            }
        }
        result
    };

    let map_a = accumulate(trace_a);
    let map_b = accumulate(trace_b);

    let all_nrs: HashSet<u64> = map_a.keys().chain(map_b.keys()).copied().collect();
    let mut result = BTreeMap::new();
    for nr in all_nrs {
        let a = map_a.get(&nr).copied().unwrap_or(0);
        let b = map_b.get(&nr).copied().unwrap_or(0);
        result.insert(nr, (a, b));
    }
    result
}

/// Summarize the diff as a compact text diff (like GNU diff) of syscall sequences.
#[must_use] 
pub fn syscall_text_diff(trace_a: &TtdTrace, trace_b: &TtdTrace) -> String {
    let a: Vec<String> = trace_a
        .events
        .iter()
        .filter_map(|ev| match ev {
            TraceEvent::SyscallEntry { nr, tick, .. } => Some(format!("syscall nr={nr} tick={tick}")),
            _ => None,
        })
        .collect();
    let b: Vec<String> = trace_b
        .events
        .iter()
        .filter_map(|ev| match ev {
            TraceEvent::SyscallEntry { nr, tick, .. } => Some(format!("syscall nr={nr} tick={tick}")),
            _ => None,
        })
        .collect();

    let mut out = String::new();
    let min = a.len().min(b.len());
    for i in 0..min {
        if a[i] != b[i] {
            out.push_str(&format!("< {}\n> {}\n", a[i], b[i]));
        }
    }
    for line in &a[min..] {
        out.push_str(&format!("< {line}\n"));
    }
    for line in &b[min..] {
        out.push_str(&format!("> {line}\n"));
    }
    if out.is_empty() {
        "(identical syscall sequences)".to_string()
    } else {
        out
    }
}
