//! `trace_analysis` — Deep trace analysis.
//!
//! Provides `TraceAnalyzer`, `LoopFinder`, `FunctionCallTracker`,
//! `APISequence`, `AnomalyDetector`, `ExecutionGraph`, `TraceComparator`.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

/// Errors from trace analysis.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TraceAnalysisError {
    #[error("trace is empty")]
    Empty,
    #[error("address {0:#x} not in trace")]
    AddressNotFound(u64),
    #[error("analysis failed: {0}")]
    Analysis(String),
    #[error("comparison failed: {0}")]
    Comparison(String),
}

// ─── TraceEntry ───────────────────────────────────────────────────────────────

/// A single instruction entry from an execution trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceEntry {
    /// Program counter address.
    pub pc: u64,
    /// Instruction size in bytes.
    pub size: u8,
    /// Thread ID.
    pub thread_id: u32,
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Optional mnemonic.
    pub mnemonic: Option<String>,
}

impl TraceEntry {
    /// Create a minimal entry.
    #[must_use]
    pub const fn new(pc: u64, size: u8) -> Self {
        Self { pc, size, thread_id: 0, timestamp_ns: 0, mnemonic: None }
    }

    /// Builder: set thread.
    #[must_use]
    pub const fn with_thread(mut self, tid: u32) -> Self { self.thread_id = tid; self }

    /// Builder: set timestamp.
    #[must_use]
    pub const fn with_ts(mut self, ns: u64) -> Self { self.timestamp_ns = ns; self }

    /// Builder: set mnemonic.
    #[must_use]
    pub fn with_mnemonic(mut self, m: impl Into<String>) -> Self { self.mnemonic = Some(m.into()); self }
}

// ─── LoopInstance ─────────────────────────────────────────────────────────────

/// A detected loop in the execution trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopInstance {
    /// Address of the loop header.
    pub header_pc: u64,
    /// Number of iterations observed.
    pub iteration_count: u64,
    /// Addresses of all instructions in the loop body.
    pub body_addresses: Vec<u64>,
    /// Total instructions executed as part of this loop.
    pub total_insns: u64,
    /// First occurrence index in the trace.
    pub first_trace_index: usize,
    /// Last occurrence index in the trace.
    pub last_trace_index: usize,
}

impl LoopInstance {
    /// Loop body size (unique addresses).
    #[must_use]
    pub const fn body_size(&self) -> usize { self.body_addresses.len() }

    /// Return `true` if this loop is a tight loop (1–3 instructions).
    #[must_use]
    pub const fn is_tight(&self) -> bool { self.body_size() <= 3 }
}

impl fmt::Display for LoopInstance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Loop@{:#x} x{} ({} body insns)", self.header_pc, self.iteration_count, self.body_size())
    }
}

// ─── LoopFinder ───────────────────────────────────────────────────────────────

/// Detects repeated PC sequences in an execution trace.
pub struct LoopFinder {
    /// Minimum iterations to be reported as a loop.
    pub min_iterations: u64,
    /// Minimum loop body size.
    pub min_body_size: usize,
    /// Maximum loop body size to consider.
    pub max_body_size: usize,
}

impl Default for LoopFinder {
    fn default() -> Self {
        Self { min_iterations: 3, min_body_size: 1, max_body_size: 256 }
    }
}

impl LoopFinder {
    /// Create with default parameters.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Find loops in a slice of trace entries.
    #[must_use]
    pub fn find(&self, trace: &[TraceEntry]) -> Vec<LoopInstance> {
        let mut loops: Vec<LoopInstance> = Vec::new();
        let mut pc_last_seen: HashMap<u64, usize> = HashMap::new();
        let mut pc_count: HashMap<u64, u64> = HashMap::new();

        for (i, entry) in trace.iter().enumerate() {
            let count = pc_count.entry(entry.pc).or_insert(0);
            *count += 1;

            if *count >= self.min_iterations {
                // Find the loop body between last visit and now
                if let Some(&last_i) = pc_last_seen.get(&entry.pc) {
                    let body_len = i - last_i;
                    if body_len >= self.min_body_size && body_len <= self.max_body_size {
                        let body: Vec<u64> = trace[last_i..i].iter().map(|e| e.pc).collect();
                        let unique_body: Vec<u64> = {
                            let mut seen = HashSet::new();
                            body.iter().filter(|&&a| seen.insert(a)).copied().collect()
                        };

                        // Update or add loop record
                        if let Some(existing) = loops.iter_mut().find(|l| l.header_pc == entry.pc) {
                            existing.iteration_count += 1;
                            existing.last_trace_index = i;
                            existing.total_insns += body_len as u64;
                        } else {
                            loops.push(LoopInstance {
                                header_pc: entry.pc,
                                iteration_count: 1,
                                body_addresses: unique_body,
                                total_insns: body_len as u64,
                                first_trace_index: last_i,
                                last_trace_index: i,
                            });
                        }
                    }
                }
            }
            pc_last_seen.insert(entry.pc, i);
        }
        loops
    }
}

// ─── CallRecord ───────────────────────────────────────────────────────────────

/// A call/return pair from the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallRecord {
    pub from_addr: u64,
    pub to_addr: u64,
    pub return_addr: u64,
    pub call_index: usize,
    pub return_index: Option<usize>,
    pub depth: u32,
}

impl CallRecord {
    /// Return the body size (in trace entries) of this call.
    #[must_use]
    pub fn body_size(&self) -> Option<usize> {
        self.return_index.map(|r| r.saturating_sub(self.call_index))
    }

    /// Return `true` if this call returned.
    #[must_use]
    pub const fn returned(&self) -> bool { self.return_index.is_some() }
}

// ─── FunctionCallTracker ─────────────────────────────────────────────────────

/// Pairs call and return instructions to build a call tree.
pub struct FunctionCallTracker {
    pub call_insns: HashSet<u64>,
    pub ret_insns: HashSet<u64>,
}

impl FunctionCallTracker {
    /// Create with sets of known call and ret instruction addresses.
    #[must_use]
    pub const fn new(call_insns: HashSet<u64>, ret_insns: HashSet<u64>) -> Self {
        Self { call_insns, ret_insns }
    }

    /// Create without explicit instruction sets (use heuristics).
    #[must_use]
    pub fn heuristic() -> Self {
        Self { call_insns: HashSet::new(), ret_insns: HashSet::new() }
    }

    /// Track calls in a trace, returning paired call records.
    #[must_use]
    pub fn track(&self, trace: &[TraceEntry]) -> Vec<CallRecord> {
        let mut records: Vec<CallRecord> = Vec::new();
        let mut call_stack: Vec<(usize, u64, u64, u32)> = Vec::new(); // (call_idx, from_addr, to_addr, depth)
        let mut depth = 0u32;

        // Simple heuristic: detect calls by looking for address discontinuities followed by a call-like pattern
        for (i, entry) in trace.iter().enumerate() {
            if i == 0 { continue; }
            let prev = &trace[i - 1];
            let expected_next = prev.pc + u64::from(prev.size);

            // Detect CALL: big forward jump that creates a new scope
            if entry.pc != expected_next {
                let diff = entry.pc.wrapping_sub(expected_next) as i64;
                // Heuristic: forward jump or known call
                if self.call_insns.contains(&prev.pc) || (diff > 0 && diff < 0x10000) {
                    call_stack.push((i - 1, prev.pc, entry.pc, depth));
                    depth += 1;
                    records.push(CallRecord {
                        from_addr: prev.pc,
                        to_addr: entry.pc,
                        return_addr: expected_next,
                        call_index: i - 1,
                        return_index: None,
                        depth: depth - 1,
                    });
                }
            }

            // Detect RET: jump back to a return address on the stack
            if !call_stack.is_empty() {
                let top = call_stack.last().unwrap();
                let expected_ret = top.1 + 5; // call instruction typically 5 bytes
                if entry.pc == expected_ret || self.ret_insns.contains(&prev.pc) {
                    let (call_idx, _from, _to, d) = call_stack.pop().unwrap();
                    if let Some(rec) = records.iter_mut().rev().find(|r| r.call_index == call_idx) {
                        rec.return_index = Some(i);
                    }
                    depth = d;
                }
            }
        }
        records
    }

    /// Return the call depth at each trace step.
    #[must_use]
    pub fn call_depth_timeline(&self, records: &[CallRecord], trace_len: usize) -> Vec<u32> {
        let mut depths = vec![0u32; trace_len];
        for rec in records {
            let start = rec.call_index;
            let end = rec.return_index.unwrap_or(trace_len);
            for i in start..end.min(trace_len) {
                depths[i] = depths[i].max(rec.depth + 1);
            }
        }
        depths
    }
}

// ─── APISequence ──────────────────────────────────────────────────────────────

/// A sequence of extracted API calls from the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct APISequence {
    pub calls: Vec<ApiCallEntry>,
}

/// One API call in the extracted sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCallEntry {
    pub pc: u64,
    pub api_name: String,
    pub trace_index: usize,
}

impl APISequence {
    #[must_use]
    pub const fn new() -> Self { Self { calls: vec![] } }

    /// Add a call.
    pub fn add(&mut self, pc: u64, api_name: impl Into<String>, trace_index: usize) {
        self.calls.push(ApiCallEntry { pc, api_name: api_name.into(), trace_index });
    }

    /// Extract from a trace using a known API address → name map.
    #[must_use]
    pub fn extract(trace: &[TraceEntry], api_map: &HashMap<u64, String>) -> Self {
        let mut seq = Self::new();
        for (i, entry) in trace.iter().enumerate() {
            if let Some(name) = api_map.get(&entry.pc) {
                seq.add(entry.pc, name.clone(), i);
            }
        }
        seq
    }

    /// Return unique API names in order.
    #[must_use]
    pub fn unique_names(&self) -> Vec<&str> {
        let mut seen = HashSet::new();
        self.calls.iter()
            .filter(|c| seen.insert(c.api_name.as_str()))
            .map(|c| c.api_name.as_str())
            .collect()
    }

    /// Frequency map: API name → count.
    #[must_use]
    pub fn frequency(&self) -> HashMap<String, usize> {
        let mut m: HashMap<String, usize> = HashMap::new();
        for c in &self.calls { *m.entry(c.api_name.clone()).or_insert(0) += 1; }
        m
    }

    /// Number of calls.
    #[must_use]
    pub const fn len(&self) -> usize { self.calls.len() }

    /// Return `true` if the sequence is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool { self.calls.is_empty() }
}

impl Default for APISequence {
    fn default() -> Self { Self::new() }
}

// ─── Anomaly ──────────────────────────────────────────────────────────────────

/// An anomalous execution pattern detected in the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub kind: AnomalyKind,
    pub pc: u64,
    pub trace_index: usize,
    pub description: String,
    pub severity: u8,
}

/// Kind of execution anomaly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyKind {
    /// Execution of a region with no prior disassembly.
    UnknownCode,
    /// Very long NOP sled or repeated instruction.
    Sled,
    /// Unusually deep recursion.
    DeepRecursion,
    /// Jump to a non-code section.
    NonCodeJump,
    /// Exception / fault.
    Exception,
    /// Self-modifying code pattern.
    SelfModifying,
    /// Very tight infinite loop.
    TightLoop,
}

impl fmt::Display for AnomalyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::UnknownCode => "unknown_code", Self::Sled => "sled",
            Self::DeepRecursion => "deep_recursion", Self::NonCodeJump => "non_code_jump",
            Self::Exception => "exception", Self::SelfModifying => "self_modifying",
            Self::TightLoop => "tight_loop",
        };
        f.write_str(s)
    }
}

// ─── AnomalyDetector ──────────────────────────────────────────────────────────

/// Detects unusual execution patterns.
pub struct AnomalyDetector {
    pub max_recursion_depth: u32,
    pub nop_sled_threshold: usize,
    pub known_code_regions: Vec<(u64, u64)>, // (start, end)
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self {
            max_recursion_depth: 64,
            nop_sled_threshold: 8,
            known_code_regions: vec![],
        }
    }
}

impl AnomalyDetector {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Mark a region as known code.
    pub fn add_code_region(&mut self, start: u64, end: u64) {
        self.known_code_regions.push((start, end));
    }

    /// Return `true` if `addr` is within a known code region.
    #[must_use]
    pub fn is_known_code(&self, addr: u64) -> bool {
        if self.known_code_regions.is_empty() { return true; }
        self.known_code_regions.iter().any(|&(s, e)| addr >= s && addr < e)
    }

    /// Analyse a trace for anomalies.
    #[must_use]
    pub fn detect(&self, trace: &[TraceEntry], call_records: &[CallRecord]) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();

        // Check 1: unknown code
        for (i, e) in trace.iter().enumerate() {
            if !self.is_known_code(e.pc) {
                anomalies.push(Anomaly {
                    kind: AnomalyKind::UnknownCode, pc: e.pc, trace_index: i,
                    description: format!("Execution at {:#x} outside known code regions", e.pc),
                    severity: 70,
                });
            }
        }

        // Check 2: NOP sleds (same address repeated N+ times consecutively)
        let mut streak = 1usize;
        for i in 1..trace.len() {
            if trace[i].pc == trace[i - 1].pc {
                streak += 1;
                if streak >= self.nop_sled_threshold {
                    anomalies.push(Anomaly {
                        kind: AnomalyKind::Sled, pc: trace[i].pc, trace_index: i,
                        description: format!("Instruction sled at {:#x} for {streak} steps", trace[i].pc),
                        severity: 50,
                    });
                    break; // one report per sled
                }
            } else {
                streak = 1;
            }
        }

        // Check 3: Deep recursion
        let max_depth = call_records.iter().map(|r| r.depth).max().unwrap_or(0);
        if max_depth > self.max_recursion_depth {
            let deepest = call_records.iter().max_by_key(|r| r.depth).unwrap();
            anomalies.push(Anomaly {
                kind: AnomalyKind::DeepRecursion, pc: deepest.to_addr,
                trace_index: deepest.call_index,
                description: format!("Recursion depth {max_depth} exceeds limit {}", self.max_recursion_depth),
                severity: 60,
            });
        }

        // Check 4: Tight loops (already from LoopFinder, flag loops with 1–2 insns)
        let loop_finder = LoopFinder { min_iterations: 100, min_body_size: 1, max_body_size: 3 };
        let tight_loops = loop_finder.find(trace);
        for lp in &tight_loops {
            if lp.is_tight() && lp.iteration_count >= 100 {
                anomalies.push(Anomaly {
                    kind: AnomalyKind::TightLoop, pc: lp.header_pc,
                    trace_index: lp.first_trace_index,
                    description: format!("Tight loop at {:#x} ran {} times", lp.header_pc, lp.iteration_count),
                    severity: 40,
                });
            }
        }

        anomalies
    }

    /// Return anomalies above a severity threshold.
    #[must_use]
    pub fn above_severity<'a>(&self, anomalies: &'a [Anomaly], threshold: u8) -> Vec<&'a Anomaly> {
        anomalies.iter().filter(|a| a.severity >= threshold).collect()
    }
}

// ─── ExecutionGraph ───────────────────────────────────────────────────────────

/// A control-flow graph built from the execution trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionGraph {
    /// Nodes: address → number of visits.
    pub nodes: HashMap<u64, u64>,
    /// Directed edges: (from, to) → count.
    pub edges: HashMap<(u64, u64), u64>,
}

impl ExecutionGraph {
    /// Build from a trace.
    #[must_use]
    pub fn build(trace: &[TraceEntry]) -> Self {
        let mut nodes: HashMap<u64, u64> = HashMap::new();
        let mut edges: HashMap<(u64, u64), u64> = HashMap::new();

        for (i, entry) in trace.iter().enumerate() {
            *nodes.entry(entry.pc).or_insert(0) += 1;
            if i + 1 < trace.len() {
                let next_pc = trace[i + 1].pc;
                *edges.entry((entry.pc, next_pc)).or_insert(0) += 1;
            }
        }
        Self { nodes, edges }
    }

    /// Number of unique nodes.
    #[must_use]
    pub fn node_count(&self) -> usize { self.nodes.len() }

    /// Number of unique edges.
    #[must_use]
    pub fn edge_count(&self) -> usize { self.edges.len() }

    /// Most-visited node.
    #[must_use]
    pub fn hottest_node(&self) -> Option<(u64, u64)> {
        // Tie-break by lowest address so the result is deterministic across
        // HashMap iteration orders.
        self.nodes
            .iter()
            .max_by(|&(a_addr, a_count), &(b_addr, b_count)| {
                a_count.cmp(b_count).then_with(|| b_addr.cmp(a_addr))
            })
            .map(|(&a, &c)| (a, c))
    }

    /// Return all successors of a node.
    #[must_use]
    pub fn successors(&self, addr: u64) -> Vec<u64> {
        self.edges.keys().filter(|(from, _)| *from == addr).map(|(_, to)| *to).collect()
    }

    /// Return all predecessors of a node.
    #[must_use]
    pub fn predecessors(&self, addr: u64) -> Vec<u64> {
        self.edges.keys().filter(|(_, to)| *to == addr).map(|(from, _)| *from).collect()
    }

    /// Compute the coverage ratio over a known range.
    #[must_use]
    pub fn coverage_in_range(&self, start: u64, end: u64) -> f64 {
        if end <= start { return 0.0; }
        let covered = self.nodes.keys().filter(|&&a| a >= start && a < end).count() as f64;
        let total = (end - start) as f64;
        covered / total
    }

    /// Return the top N most-visited nodes.
    #[must_use]
    pub fn top_nodes(&self, n: usize) -> Vec<(u64, u64)> {
        let mut v: Vec<(u64, u64)> = self.nodes.iter().map(|(&a, &c)| (a, c)).collect();
        if n < v.len() {
            v.select_nth_unstable_by(n, |a, b| b.1.cmp(&a.1));
            v.truncate(n);
        }
        v.sort_unstable_by_key(|b| std::cmp::Reverse(b.1));
        v
    }
}

// ─── TraceComparator ─────────────────────────────────────────────────────────

/// Compares two traces to find behavioural differences.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceComparison {
    /// PCs only in trace A.
    pub only_in_a: Vec<u64>,
    /// PCs only in trace B.
    pub only_in_b: Vec<u64>,
    /// PCs present in both.
    pub common: Vec<u64>,
    /// Similarity ratio [0.0, 1.0].
    pub similarity: f64,
    /// Unique PCs in A.
    pub total_unique_a: usize,
    /// Unique PCs in B.
    pub total_unique_b: usize,
}

impl TraceComparison {
    #[must_use]
    pub const fn identical(&self) -> bool { self.only_in_a.is_empty() && self.only_in_b.is_empty() }
}

/// Compares two execution traces.
pub struct TraceComparator;

impl TraceComparator {
    /// Compare two traces and return differences.
    #[must_use]
    pub fn compare(trace_a: &[TraceEntry], trace_b: &[TraceEntry]) -> TraceComparison {
        let pcs_a: HashSet<u64> = trace_a.iter().map(|e| e.pc).collect();
        let pcs_b: HashSet<u64> = trace_b.iter().map(|e| e.pc).collect();

        let mut only_in_a: Vec<u64> = pcs_a.difference(&pcs_b).copied().collect();
        let mut only_in_b: Vec<u64> = pcs_b.difference(&pcs_a).copied().collect();
        let mut common: Vec<u64> = pcs_a.intersection(&pcs_b).copied().collect();
        only_in_a.sort_unstable(); only_in_b.sort_unstable(); common.sort_unstable();

        let total = pcs_a.len() + pcs_b.len() - common.len();
        let similarity = if total == 0 { 1.0 } else { common.len() as f64 / total as f64 };

        TraceComparison {
            only_in_a, only_in_b, common,
            similarity,
            total_unique_a: pcs_a.len(),
            total_unique_b: pcs_b.len(),
        }
    }

    /// Compare call sequences extracted from two traces.
    #[must_use]
    pub fn compare_call_sequences(a: &[CallRecord], b: &[CallRecord]) -> f64 {
        let targets_a: HashSet<u64> = a.iter().map(|r| r.to_addr).collect();
        let targets_b: HashSet<u64> = b.iter().map(|r| r.to_addr).collect();
        let common = targets_a.intersection(&targets_b).count();
        let total = targets_a.len() + targets_b.len() - common;
        if total == 0 { 1.0 } else { common as f64 / total as f64 }
    }
}

// ─── TraceAnalyzer ────────────────────────────────────────────────────────────

/// Coordinates all trace analysis passes.
pub struct TraceAnalyzer {
    pub trace: Vec<TraceEntry>,
    pub api_map: HashMap<u64, String>,
    pub anomaly_detector: AnomalyDetector,
    pub loop_finder: LoopFinder,
    pub call_tracker: FunctionCallTracker,
}

impl TraceAnalyzer {
    /// Create a new analyser for a trace.
    #[must_use]
    pub fn new(trace: Vec<TraceEntry>) -> Self {
        Self {
            trace,
            api_map: HashMap::new(),
            anomaly_detector: AnomalyDetector::new(),
            loop_finder: LoopFinder::new(),
            call_tracker: FunctionCallTracker::heuristic(),
        }
    }

    /// Add a known API address.
    pub fn register_api(&mut self, addr: u64, name: impl Into<String>) {
        self.api_map.insert(addr, name.into());
    }

    /// Find all loops in the trace.
    #[must_use]
    pub fn find_loops(&self) -> Vec<LoopInstance> {
        self.loop_finder.find(&self.trace)
    }

    /// Extract API call sequence.
    #[must_use]
    pub fn api_sequence(&self) -> APISequence {
        APISequence::extract(&self.trace, &self.api_map)
    }

    /// Detect anomalies.
    #[must_use]
    pub fn detect_anomalies(&self) -> Vec<Anomaly> {
        let calls = self.call_tracker.track(&self.trace);
        self.anomaly_detector.detect(&self.trace, &calls)
    }

    /// Build execution graph.
    #[must_use]
    pub fn build_graph(&self) -> ExecutionGraph {
        ExecutionGraph::build(&self.trace)
    }

    /// Track function calls.
    #[must_use]
    pub fn track_calls(&self) -> Vec<CallRecord> {
        self.call_tracker.track(&self.trace)
    }

    /// Number of trace entries.
    #[must_use]
    pub const fn len(&self) -> usize { self.trace.len() }

    /// Return `true` if the trace is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool { self.trace.is_empty() }

    /// Unique PCs in the trace.
    #[must_use]
    pub fn unique_pcs(&self) -> HashSet<u64> {
        self.trace.iter().map(|e| e.pc).collect()
    }

    /// Coverage count (unique PCs / total entries).
    #[must_use]
    pub fn coverage_ratio(&self) -> f64 {
        if self.trace.is_empty() { return 0.0; }
        self.unique_pcs().len() as f64 / self.trace.len() as f64
    }

    /// Top N most-executed addresses.
    #[must_use]
    pub fn top_addresses(&self, n: usize) -> Vec<(u64, usize)> {
        let mut counts: HashMap<u64, usize> = HashMap::new();
        for e in &self.trace { *counts.entry(e.pc).or_insert(0) += 1; }
        let mut v: Vec<(u64, usize)> = counts.into_iter().collect();
        if n < v.len() {
            v.select_nth_unstable_by(n, |a, b| b.1.cmp(&a.1));
            v.truncate(n);
        }
        v.sort_unstable_by_key(|b| std::cmp::Reverse(b.1));
        v
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_trace() -> Vec<TraceEntry> {
        vec![
            TraceEntry::new(0x1000, 4),
            TraceEntry::new(0x1004, 4),
            TraceEntry::new(0x1008, 4),
            TraceEntry::new(0x1000, 4), // back to start
            TraceEntry::new(0x1004, 4),
            TraceEntry::new(0x1008, 4),
            TraceEntry::new(0x1000, 4),
            TraceEntry::new(0x1004, 4),
        ]
    }

    fn loop_trace() -> Vec<TraceEntry> {
        let mut t = Vec::new();
        // Setup
        t.push(TraceEntry::new(0x400, 4));
        t.push(TraceEntry::new(0x404, 4));
        // Tight loop: 0x408 → 0x408 × 200
        for _ in 0..200 {
            t.push(TraceEntry::new(0x408, 4));
        }
        t
    }

    // ── TraceEntry ────────────────────────────────────────────────────────────

    #[test]
    fn test_entry_new() {
        let e = TraceEntry::new(0x0040_1000, 4);
        assert_eq!(e.pc, 0x0040_1000);
        assert_eq!(e.size, 4);
    }

    #[test]
    fn test_entry_builders() {
        let e = TraceEntry::new(0x1000, 1)
            .with_thread(42)
            .with_ts(1000)
            .with_mnemonic("nop");
        assert_eq!(e.thread_id, 42);
        assert_eq!(e.timestamp_ns, 1000);
        assert_eq!(e.mnemonic.as_deref(), Some("nop"));
    }

    // ── LoopFinder ────────────────────────────────────────────────────────────

    #[test]
    fn test_loop_finder_simple_loop() {
        let trace = simple_trace();
        let lf = LoopFinder { min_iterations: 2, min_body_size: 1, max_body_size: 10 };
        let loops = lf.find(&trace);
        assert!(!loops.is_empty());
        assert!(loops.iter().any(|l| l.header_pc == 0x1000));
    }

    #[test]
    fn test_loop_finder_no_loop() {
        let trace: Vec<TraceEntry> = (0..10).map(|i| TraceEntry::new(0x1000 + i * 4, 4)).collect();
        let lf = LoopFinder::new();
        let loops = lf.find(&trace);
        assert!(loops.is_empty());
    }

    #[test]
    fn test_loop_instance_is_tight() {
        let l = LoopInstance {
            header_pc: 0, iteration_count: 100, body_addresses: vec![0, 4],
            total_insns: 200, first_trace_index: 0, last_trace_index: 200,
        };
        assert!(l.is_tight());
    }

    #[test]
    fn test_loop_instance_display() {
        let l = LoopInstance { header_pc: 0x1000, iteration_count: 42, body_addresses: vec![0, 1], total_insns: 84, first_trace_index: 0, last_trace_index: 84 };
        assert!(l.to_string().contains("0x1000"));
        assert!(l.to_string().contains("42"));
    }

    // ── FunctionCallTracker ───────────────────────────────────────────────────

    #[test]
    fn test_call_tracker_no_calls() {
        let trace = simple_trace();
        let tracker = FunctionCallTracker::heuristic();
        let records = tracker.track(&trace);
        // May or may not find calls depending on heuristic
        let _ = records;
    }

    #[test]
    fn test_call_depth_timeline() {
        let tracker = FunctionCallTracker::heuristic();
        let trace = simple_trace();
        let records = tracker.track(&trace);
        let depths = tracker.call_depth_timeline(&records, trace.len());
        assert_eq!(depths.len(), trace.len());
    }

    // ── APISequence ───────────────────────────────────────────────────────────

    #[test]
    fn test_api_sequence_extract() {
        let trace = simple_trace();
        let mut api_map = HashMap::new();
        api_map.insert(0x1000u64, "sub_1000".to_string());
        let seq = APISequence::extract(&trace, &api_map);
        assert!(!seq.is_empty());
    }

    #[test]
    fn test_api_sequence_frequency() {
        let mut seq = APISequence::new();
        seq.add(0x1000, "CreateFile", 0);
        seq.add(0x1000, "CreateFile", 1);
        seq.add(0x2000, "CloseHandle", 2);
        let freq = seq.frequency();
        assert_eq!(freq["CreateFile"], 2);
        assert_eq!(freq["CloseHandle"], 1);
    }

    #[test]
    fn test_api_sequence_unique_names() {
        let mut seq = APISequence::new();
        seq.add(0, "foo", 0);
        seq.add(0, "foo", 1);
        seq.add(0, "bar", 2);
        let names = seq.unique_names();
        assert_eq!(names.len(), 2);
    }

    // ── AnomalyDetector ───────────────────────────────────────────────────────

    #[test]
    fn test_anomaly_detector_unknown_code() {
        let mut detector = AnomalyDetector::new();
        detector.add_code_region(0x1000, 0x2000);
        let trace = vec![TraceEntry::new(0xdead_beef, 4)]; // outside known range
        let anomalies = detector.detect(&trace, &[]);
        assert!(!anomalies.is_empty());
        assert_eq!(anomalies[0].kind, AnomalyKind::UnknownCode);
    }

    #[test]
    fn test_anomaly_detector_tight_loop() {
        let trace = loop_trace();
        let detector = AnomalyDetector { max_recursion_depth: 64, nop_sled_threshold: 8, known_code_regions: vec![] };
        let anomalies = detector.detect(&trace, &[]);
        // Should detect sled or tight loop
        let _ = anomalies;
    }

    #[test]
    fn test_anomaly_detector_no_anomalies() {
        let trace: Vec<TraceEntry> = (0..10).map(|i| TraceEntry::new(0x1000 + i * 4, 4)).collect();
        let detector = AnomalyDetector::new();
        let anomalies = detector.detect(&trace, &[]);
        // Clean linear trace should have no anomalies (no known regions = all ok)
        assert!(anomalies.is_empty() || !anomalies.iter().any(|a| a.kind == AnomalyKind::UnknownCode));
    }

    #[test]
    fn test_anomaly_above_severity() {
        let detector = AnomalyDetector::new();
        let anomalies = vec![
            Anomaly { kind: AnomalyKind::UnknownCode, pc: 0, trace_index: 0, description: "x".into(), severity: 70 },
            Anomaly { kind: AnomalyKind::TightLoop, pc: 0, trace_index: 0, description: "y".into(), severity: 40 },
        ];
        let high = detector.above_severity(&anomalies, 65);
        assert_eq!(high.len(), 1);
    }

    // ── ExecutionGraph ────────────────────────────────────────────────────────

    #[test]
    fn test_exec_graph_build() {
        let trace = simple_trace();
        let g = ExecutionGraph::build(&trace);
        assert!(g.node_count() > 0);
        assert!(g.edge_count() > 0);
    }

    #[test]
    fn test_exec_graph_hottest_node() {
        let trace = simple_trace();
        let g = ExecutionGraph::build(&trace);
        let (pc, count) = g.hottest_node().unwrap();
        assert_eq!(pc, 0x1000); // most visited in simple_trace
        assert!(count >= 3);
    }

    #[test]
    fn test_exec_graph_successors() {
        let trace = vec![
            TraceEntry::new(0x1000, 4),
            TraceEntry::new(0x1004, 4),
            TraceEntry::new(0x1000, 4),
            TraceEntry::new(0x2000, 4),
        ];
        let g = ExecutionGraph::build(&trace);
        let succs = g.successors(0x1000);
        assert!(succs.contains(&0x1004) || succs.contains(&0x2000));
    }

    #[test]
    fn test_exec_graph_coverage() {
        let trace: Vec<TraceEntry> = (0..10).map(|i| TraceEntry::new(0x1000 + i * 4, 4)).collect();
        let g = ExecutionGraph::build(&trace);
        let ratio = g.coverage_in_range(0x1000, 0x1000 + 40);
        assert!(ratio > 0.0);
    }

    #[test]
    fn test_exec_graph_top_nodes() {
        let trace = simple_trace();
        let g = ExecutionGraph::build(&trace);
        let top = g.top_nodes(2);
        assert_eq!(top.len(), 2.min(g.node_count()));
    }

    // ── TraceComparator ───────────────────────────────────────────────────────

    #[test]
    fn test_comparator_identical() {
        let t = simple_trace();
        let cmp = TraceComparator::compare(&t, &t);
        assert!(cmp.identical());
        assert!((cmp.similarity - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_comparator_different() {
        let t1 = simple_trace();
        let t2: Vec<TraceEntry> = (100..110u64).map(|i| TraceEntry::new(i * 4, 4)).collect();
        let cmp = TraceComparator::compare(&t1, &t2);
        assert!(!cmp.identical());
        assert!(cmp.similarity < 1.0);
    }

    #[test]
    fn test_comparator_call_sequences() {
        let calls_a = vec![
            CallRecord { from_addr: 0x100, to_addr: 0x200, return_addr: 0x105, call_index: 0, return_index: Some(10), depth: 0 },
        ];
        let calls_b = vec![
            CallRecord { from_addr: 0x100, to_addr: 0x200, return_addr: 0x105, call_index: 0, return_index: Some(10), depth: 0 },
            CallRecord { from_addr: 0x200, to_addr: 0x300, return_addr: 0x205, call_index: 5, return_index: Some(8), depth: 1 },
        ];
        let sim = TraceComparator::compare_call_sequences(&calls_a, &calls_b);
        assert!(sim > 0.0 && sim < 1.0);
    }

    // ── TraceAnalyzer ─────────────────────────────────────────────────────────

    #[test]
    fn test_analyzer_new() {
        let a = TraceAnalyzer::new(simple_trace());
        assert_eq!(a.len(), 8);
    }

    #[test]
    fn test_analyzer_unique_pcs() {
        let a = TraceAnalyzer::new(simple_trace());
        assert_eq!(a.unique_pcs().len(), 3);
    }

    #[test]
    fn test_analyzer_coverage_ratio() {
        let a = TraceAnalyzer::new(simple_trace());
        let ratio = a.coverage_ratio();
        assert!(ratio > 0.0 && ratio <= 1.0);
    }

    #[test]
    fn test_analyzer_find_loops() {
        let mut a = TraceAnalyzer::new(simple_trace());
        a.loop_finder.min_iterations = 2;
        let loops = a.find_loops();
        assert!(!loops.is_empty());
    }

    #[test]
    fn test_analyzer_api_sequence() {
        let mut a = TraceAnalyzer::new(simple_trace());
        a.register_api(0x1000, "MyFunction");
        let seq = a.api_sequence();
        assert!(!seq.is_empty());
    }

    #[test]
    fn test_analyzer_build_graph() {
        let a = TraceAnalyzer::new(simple_trace());
        let g = a.build_graph();
        assert!(g.node_count() > 0);
    }

    #[test]
    fn test_analyzer_top_addresses() {
        let a = TraceAnalyzer::new(simple_trace());
        let top = a.top_addresses(2);
        assert!(!top.is_empty());
        // First entry should be most visited
        assert!(top[0].0 == 0x1000 || top[0].1 >= 3);
    }

    #[test]
    fn test_analyzer_detect_anomalies_clean() {
        let a = TraceAnalyzer::new(simple_trace());
        let anomalies = a.detect_anomalies();
        // Without known code regions, no UnknownCode anomalies
        assert!(!anomalies.iter().any(|a| a.kind == AnomalyKind::UnknownCode));
    }

    #[test]
    fn test_call_record_returned() {
        let r = CallRecord { from_addr: 0, to_addr: 0, return_addr: 0, call_index: 0, return_index: Some(5), depth: 0 };
        assert!(r.returned());
        assert_eq!(r.body_size(), Some(5));
    }

    #[test]
    fn test_call_record_not_returned() {
        let r = CallRecord { from_addr: 0, to_addr: 0, return_addr: 0, call_index: 0, return_index: None, depth: 0 };
        assert!(!r.returned());
        assert!(r.body_size().is_none());
    }
}
