//! `LuaJIT` profiler data analysis.
//!
//! Parses and analyses `LuaJIT` profiler output, hot function tables,
//! trace info, abort statistics, and call/hotspot trees.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// â”€â”€â”€ Error â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[derive(Debug, thiserror::Error)]
pub enum ProfilerError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("invalid profiler data: {0}")]
    InvalidData(String),
    #[error("io error: {0}")]
    Io(String),
}

// â”€â”€â”€ TraceType â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraceType {
    Root,
    Side,
    Stitch,
    Loop,
    Unknown,
}

impl fmt::Display for TraceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root => write!(f, "root"),
            Self::Side => write!(f, "side"),
            Self::Stitch => write!(f, "stitch"),
            Self::Loop => write!(f, "loop"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// â”€â”€â”€ HotFunction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A function identified as hot by the `LuaJIT` profiler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotFunction {
    /// Virtual address of the function (or 0 for unknown).
    pub function_addr: u64,
    /// Human-readable function name (from debug info or heuristic).
    pub name: String,
    /// Source file path (from debug info).
    pub source_file: Option<String>,
    /// First line of the function.
    pub line: u32,
    /// Number of times the function was called.
    pub call_count: u64,
    /// Total CPU time in microseconds.
    pub total_time_us: u64,
    /// Self time (excluding callees) in microseconds.
    pub self_time_us: u64,
    /// Whether a JIT trace has been compiled for this function.
    pub is_jit_compiled: bool,
    /// Number of JIT traces compiled for this function.
    pub trace_count: u32,
}

impl HotFunction {
    /// Average call time in microseconds.
    #[must_use]
    pub const fn avg_call_us(&self) -> u64 {
        if self.call_count == 0 {
            0
        } else {
            self.total_time_us / self.call_count
        }
    }

    /// Fraction of total time spent in self (vs callees).
    #[must_use]
    pub fn self_fraction(&self) -> f64 {
        if self.total_time_us == 0 {
            0.0
        } else {
            self.self_time_us as f64 / self.total_time_us as f64
        }
    }

    /// Returns `true` if this function is a leaf (most time is self time).
    #[must_use]
    pub fn is_leaf(&self) -> bool {
        self.self_fraction() > 0.8
    }
}

impl fmt::Display for HotFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} calls={} total={}Âµs self={}Âµs jit={}",
            self.name, self.call_count, self.total_time_us, self.self_time_us, self.is_jit_compiled,
        )
    }
}

// â”€â”€â”€ TraceInfo â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A compiled JIT trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceInfo {
    pub trace_id: u32,
    pub trace_type: TraceType,
    /// Start PC (native address of the trace entry point).
    pub pc_start: u64,
    /// End PC (native address of the trace exit point).
    pub pc_end: u64,
    /// Number of IR instructions in the trace.
    pub ir_count: u32,
    /// Number of machine code bytes emitted.
    pub mcode_size: u32,
    /// Whether the trace was flushed from the code cache.
    pub was_flushed: bool,
    /// Number of times the trace was executed.
    pub exec_count: u64,
    /// Parent trace ID (for side/stitch traces).
    pub parent_id: Option<u32>,
}

impl TraceInfo {
    /// PC range size in bytes.
    #[must_use]
    pub const fn pc_range_bytes(&self) -> u64 {
        self.pc_end.saturating_sub(self.pc_start)
    }

    /// Average machine code expansion ratio per IR instruction.
    #[must_use]
    pub fn mcode_per_ir(&self) -> f64 {
        if self.ir_count == 0 {
            0.0
        } else {
            f64::from(self.mcode_size) / f64::from(self.ir_count)
        }
    }
}

// â”€â”€â”€ AbortStats â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// JIT compilation abort statistics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AbortStats {
    /// Map from abort reason string to count.
    pub reasons: HashMap<String, u32>,
    /// Total abort events.
    pub total_aborts: u32,
}

impl AbortStats {
    /// Top-N abort reasons by frequency.
    #[must_use]
    pub fn top_reasons(&self, n: usize) -> Vec<(String, u32)> {
        let mut sorted: Vec<(String, u32)> =
            self.reasons.iter().map(|(k, &v)| (k.clone(), v)).collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(n);
        sorted
    }

    /// Most frequent abort reason.
    #[must_use]
    pub fn most_common(&self) -> Option<(&str, u32)> {
        self.reasons
            .iter()
            .max_by_key(|&(_, &v)| v)
            .map(|(k, &v)| (k.as_str(), v))
    }
}

// â”€â”€â”€ HotspotTree â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A node in the hotspot call-tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotspotNode {
    pub name: String,
    pub total_time_us: u64,
    pub self_time_us: u64,
    pub call_count: u64,
    pub children: Vec<Self>,
}

impl HotspotNode {
    /// Total inclusive time.
    #[must_use]
    pub const fn inclusive_time(&self) -> u64 {
        self.total_time_us
    }

    /// Depth-first flattened list of all nodes (self first, then children).
    #[must_use]
    pub fn flatten(&self) -> Vec<&Self> {
        let mut result = vec![self as &Self];
        for child in &self.children {
            result.extend(child.flatten());
        }
        result
    }
}

// â”€â”€â”€ CallTree â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A call tree derived from profiler samples.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CallTree {
    pub roots: Vec<HotspotNode>,
    pub total_samples: u64,
}

impl CallTree {
    /// All nodes across the entire call tree.
    #[must_use]
    pub fn all_nodes(&self) -> Vec<&HotspotNode> {
        self.roots.iter().flat_map(|r| r.flatten()).collect()
    }

    /// Top nodes by total time.
    #[must_use]
    pub fn top_by_time(&self, n: usize) -> Vec<&HotspotNode> {
        let mut nodes = self.all_nodes();
        nodes.sort_by(|a, b| b.total_time_us.cmp(&a.total_time_us));
        nodes.truncate(n);
        nodes
    }
}

// â”€â”€â”€ ProfilerReport â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Complete profiler data report for a `LuaJIT` run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilerReport {
    /// Hot functions ordered by total CPU time (desc).
    pub hot_functions: Vec<HotFunction>,
    /// Compiled JIT traces.
    pub traces: Vec<TraceInfo>,
    /// JIT abort statistics.
    pub abort_stats: AbortStats,
    /// Call tree derived from sampling.
    pub call_tree: CallTree,
    /// Total profiling duration in microseconds.
    pub duration_us: u64,
    /// Number of profiler samples collected.
    pub sample_count: u64,
    /// `LuaJIT` version used.
    pub luajit_version: String,
    /// Whether FFI was used during profiling.
    pub ffi_used: bool,
}

impl ProfilerReport {
    /// Build a mock report for testing.
    #[must_use]
    pub fn mock() -> Self {
        let hot_fns = vec![
            HotFunction {
                function_addr: 0x1000_4000,
                name: "compute_hash".into(),
                source_file: Some("crypto.lua".into()),
                line: 10,
                call_count: 100_000,
                total_time_us: 50_000,
                self_time_us: 45_000,
                is_jit_compiled: true,
                trace_count: 3,
            },
            HotFunction {
                function_addr: 0x1000_5000,
                name: "table_sort_impl".into(),
                source_file: Some("utils.lua".into()),
                line: 42,
                call_count: 5_000,
                total_time_us: 30_000,
                self_time_us: 5_000,
                is_jit_compiled: false,
                trace_count: 0,
            },
            HotFunction {
                function_addr: 0,
                name: "[C function]".into(),
                source_file: None,
                line: 0,
                call_count: 200_000,
                total_time_us: 20_000,
                self_time_us: 20_000,
                is_jit_compiled: false,
                trace_count: 0,
            },
        ];
        let traces = vec![
            TraceInfo {
                trace_id: 1,
                trace_type: TraceType::Root,
                pc_start: 0x4010_0000,
                pc_end: 0x4010_0200,
                ir_count: 80,
                mcode_size: 320,
                was_flushed: false,
                exec_count: 100_000,
                parent_id: None,
            },
            TraceInfo {
                trace_id: 2,
                trace_type: TraceType::Side,
                pc_start: 0x4010_0200,
                pc_end: 0x4010_0280,
                ir_count: 20,
                mcode_size: 64,
                was_flushed: false,
                exec_count: 1_000,
                parent_id: Some(1),
            },
        ];
        let mut abort_reasons = HashMap::new();
        abort_reasons.insert("inner loop in root trace".into(), 12u32);
        abort_reasons.insert("NYI: ffi.cdef".into(), 7u32);
        abort_reasons.insert("call unroll limit reached".into(), 5u32);
        let abort_stats = AbortStats {
            reasons: abort_reasons,
            total_aborts: 24,
        };

        let child = HotspotNode {
            name: "inner_loop".into(),
            total_time_us: 40_000,
            self_time_us: 40_000,
            call_count: 80_000,
            children: vec![],
        };
        let root = HotspotNode {
            name: "compute_hash".into(),
            total_time_us: 50_000,
            self_time_us: 10_000,
            call_count: 100_000,
            children: vec![child],
        };
        let call_tree = CallTree {
            roots: vec![root],
            total_samples: 10_000,
        };

        Self {
            hot_functions: hot_fns,
            traces,
            abort_stats,
            call_tree,
            duration_us: 1_000_000,
            sample_count: 10_000,
            luajit_version: "LuaJIT 2.1.0-beta3".into(),
            ffi_used: true,
        }
    }

    /// Return the hottest function by total time.
    #[must_use]
    pub fn hottest_function(&self) -> Option<&HotFunction> {
        self.hot_functions.iter().max_by_key(|f| f.total_time_us)
    }

    /// Return all JIT-compiled hot functions.
    #[must_use]
    pub fn jit_compiled_functions(&self) -> Vec<&HotFunction> {
        self.hot_functions
            .iter()
            .filter(|f| f.is_jit_compiled)
            .collect()
    }

    /// Fraction of time spent in JIT-compiled code.
    #[must_use]
    pub fn jit_fraction(&self) -> f64 {
        let total: u64 = self.hot_functions.iter().map(|f| f.total_time_us).sum();
        if total == 0 {
            return 0.0;
        }
        let jit: u64 = self
            .hot_functions
            .iter()
            .filter(|f| f.is_jit_compiled)
            .map(|f| f.total_time_us)
            .sum();
        jit as f64 / total as f64
    }

    /// Summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "ProfilerReport fns={} traces={} aborts={} jit_frac={:.1}% duration={}Âµs",
            self.hot_functions.len(),
            self.traces.len(),
            self.abort_stats.total_aborts,
            self.jit_fraction() * 100.0,
            self.duration_us,
        )
    }
}

impl fmt::Display for ProfilerReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// â”€â”€â”€ Tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;

    // â”€â”€ TraceType â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_trace_type_display() {
        assert_eq!(TraceType::Root.to_string(), "root");
        assert_eq!(TraceType::Side.to_string(), "side");
    }

    // â”€â”€ HotFunction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_hot_function_avg_call() {
        let r = ProfilerReport::mock();
        let f = &r.hot_functions[0];
        assert_eq!(f.avg_call_us(), 50_000 / 100_000);
    }

    #[test]
    fn test_hot_function_is_leaf() {
        let r = ProfilerReport::mock();
        let f = &r.hot_functions[0]; // 45000/50000 = 0.9 > 0.8
        assert!(f.is_leaf());
    }

    #[test]
    fn test_hot_function_not_leaf() {
        let r = ProfilerReport::mock();
        let f = &r.hot_functions[1]; // 5000/30000 = 0.17 < 0.8
        assert!(!f.is_leaf());
    }

    #[test]
    fn test_hot_function_self_fraction() {
        let f = HotFunction {
            function_addr: 0,
            name: "foo".into(),
            source_file: None,
            line: 0,
            call_count: 1,
            total_time_us: 100,
            self_time_us: 50,
            is_jit_compiled: false,
            trace_count: 0,
        };
        assert!((f.self_fraction() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_hot_function_display() {
        let r = ProfilerReport::mock();
        let s = r.hot_functions[0].to_string();
        assert!(s.contains("compute_hash"));
    }

    // â”€â”€ TraceInfo â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_trace_info_pc_range() {
        let r = ProfilerReport::mock();
        let t = &r.traces[0];
        assert_eq!(t.pc_range_bytes(), 0x200);
    }

    #[test]
    fn test_trace_info_mcode_per_ir() {
        let r = ProfilerReport::mock();
        let t = &r.traces[0];
        assert_eq!(t.mcode_per_ir(), 320.0 / 80.0);
    }

    // â”€â”€ AbortStats â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_abort_stats_most_common() {
        let r = ProfilerReport::mock();
        let (reason, count) = r.abort_stats.most_common().unwrap();
        assert_eq!(reason, "inner loop in root trace");
        assert_eq!(count, 12);
    }

    #[test]
    fn test_abort_stats_top_reasons() {
        let r = ProfilerReport::mock();
        let top = r.abort_stats.top_reasons(2);
        assert_eq!(top.len(), 2);
        assert!(top[0].1 >= top[1].1);
    }

    #[test]
    fn test_abort_stats_total() {
        let r = ProfilerReport::mock();
        assert_eq!(r.abort_stats.total_aborts, 24);
    }

    // â”€â”€ HotspotNode â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_hotspot_node_flatten() {
        let r = ProfilerReport::mock();
        let nodes = r.call_tree.roots[0].flatten();
        assert_eq!(nodes.len(), 2); // root + child
    }

    #[test]
    fn test_hotspot_node_inclusive_time() {
        let r = ProfilerReport::mock();
        assert_eq!(r.call_tree.roots[0].inclusive_time(), 50_000);
    }

    // â”€â”€ CallTree â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_call_tree_all_nodes() {
        let r = ProfilerReport::mock();
        let all = r.call_tree.all_nodes();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_call_tree_top_by_time() {
        let r = ProfilerReport::mock();
        let top = r.call_tree.top_by_time(1);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].name, "compute_hash");
    }

    // â”€â”€ ProfilerReport â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_profiler_report_hottest_function() {
        let r = ProfilerReport::mock();
        let f = r.hottest_function().unwrap();
        assert_eq!(f.name, "compute_hash");
    }

    #[test]
    fn test_profiler_report_jit_compiled_functions() {
        let r = ProfilerReport::mock();
        let jit = r.jit_compiled_functions();
        assert_eq!(jit.len(), 1);
        assert_eq!(jit[0].name, "compute_hash");
    }

    #[test]
    fn test_profiler_report_jit_fraction_positive() {
        let r = ProfilerReport::mock();
        assert!(r.jit_fraction() > 0.0 && r.jit_fraction() <= 1.0);
    }

    #[test]
    fn test_profiler_report_ffi_used() {
        let r = ProfilerReport::mock();
        assert!(r.ffi_used);
    }

    #[test]
    fn test_profiler_report_summary() {
        let r = ProfilerReport::mock();
        let s = r.summary();
        assert!(s.contains("ProfilerReport"));
    }

    #[test]
    fn test_profiler_report_display() {
        let r = ProfilerReport::mock();
        let s = format!("{r}");
        assert!(!s.is_empty());
    }

    #[test]
    fn test_profiler_report_serialization() {
        let r = ProfilerReport::mock();
        let json = serde_json::to_string(&r).unwrap();
        let back: ProfilerReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.luajit_version, r.luajit_version);
    }

    #[test]
    fn test_profiler_report_duration() {
        let r = ProfilerReport::mock();
        assert_eq!(r.duration_us, 1_000_000);
    }

    #[test]
    fn test_profiler_report_sample_count() {
        let r = ProfilerReport::mock();
        assert_eq!(r.sample_count, 10_000);
    }
    #[test]
    fn test_trace_type_side_display() {
        assert_eq!(TraceType::Side.to_string(), "side");
    }
    #[test]
    fn test_trace_type_loop_display() {
        assert_eq!(TraceType::Loop.to_string(), "loop");
    }
    #[test]
    fn test_hot_function_zero_avg() {
        let f = HotFunction {
            function_addr: 0,
            name: "f".into(),
            source_file: None,
            line: 0,
            call_count: 0,
            total_time_us: 0,
            self_time_us: 0,
            is_jit_compiled: false,
            trace_count: 0,
        };
        assert_eq!(f.avg_call_us(), 0);
    }
    #[test]
    fn test_hot_function_zero_self_frac() {
        let f = HotFunction {
            function_addr: 0,
            name: "f".into(),
            source_file: None,
            line: 0,
            call_count: 1,
            total_time_us: 0,
            self_time_us: 0,
            is_jit_compiled: false,
            trace_count: 0,
        };
        assert_eq!(f.self_fraction(), 0.0);
    }
    #[test]
    fn test_trace_info_no_parent() {
        let r = ProfilerReport::mock();
        assert!(r.traces[0].parent_id.is_none());
    }
    #[test]
    fn test_trace_info_has_parent() {
        let r = ProfilerReport::mock();
        assert_eq!(r.traces[1].parent_id, Some(1));
    }
    #[test]
    fn test_abort_stats_default_empty() {
        let a = AbortStats::default();
        assert_eq!(a.total_aborts, 0);
    }
    #[test]
    fn test_abort_stats_top_zero() {
        let a = AbortStats::default();
        assert!(a.top_reasons(5).is_empty());
    }
    #[test]
    fn test_hotspot_node_no_children() {
        let n = HotspotNode {
            name: "leaf".into(),
            total_time_us: 100,
            self_time_us: 100,
            call_count: 1,
            children: vec![],
        };
        assert_eq!(n.flatten().len(), 1);
    }
    #[test]
    fn test_call_tree_empty() {
        let ct = CallTree::default();
        assert!(ct.all_nodes().is_empty());
    }
    #[test]
    fn test_profiler_jit_fraction_zero_when_no_jit() {
        let mut r = ProfilerReport::mock();
        for f in &mut r.hot_functions {
            f.is_jit_compiled = false;
        }
        assert_eq!(r.jit_fraction(), 0.0);
    }
    #[test]
    fn test_profiler_hottest_none_when_empty() {
        let r = ProfilerReport {
            hot_functions: vec![],
            traces: vec![],
            abort_stats: AbortStats::default(),
            call_tree: CallTree::default(),
            duration_us: 0,
            sample_count: 0,
            luajit_version: String::new(),
            ffi_used: false,
        };
        assert!(r.hottest_function().is_none());
    }
    #[test]
    fn test_profiler_report_ffi_not_used() {
        let mut r = ProfilerReport::mock();
        r.ffi_used = false;
        assert!(!r.ffi_used);
    }
    #[test]
    fn test_profiler_report_luajit_version() {
        let r = ProfilerReport::mock();
        assert!(r.luajit_version.contains("LuaJIT"));
    }
    #[test]
    fn test_hotspot_node_flatten_depth_2() {
        let r = ProfilerReport::mock();
        let flat = r.call_tree.roots[0].flatten();
        assert_eq!(flat.len(), 2);
    }
    #[test]
    fn test_call_tree_top_empty_when_empty() {
        let ct = CallTree::default();
        assert!(ct.top_by_time(5).is_empty());
    }
}
