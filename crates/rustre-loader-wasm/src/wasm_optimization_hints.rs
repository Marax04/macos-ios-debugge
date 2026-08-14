//! WASM optimization hints: local variable patterns, memory access, hot
//! functions, tail call opportunities, SIMD, bulk memory.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ─── MemAccessPattern ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemAccessPattern {
    /// Sequential forward scan.
    Sequential,
    /// Stride-N access (e.g. every 4 bytes for f32 arrays).
    Strided(u32),
    /// Random / irregular access.
    Random,
    /// Unknown pattern.
    Unknown,
}

impl fmt::Display for MemAccessPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sequential => write!(f, "sequential"),
            Self::Strided(n) => write!(f, "stride-{n}"),
            Self::Random => write!(f, "random"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ─── LocalVarAnalysis ─────────────────────────────────────────────────────────

/// Analysis of local variable usage in a function.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalVarAnalysis {
    pub total_locals: u32,
    pub used_locals: u32,
    pub unused_locals: u32,
    pub most_used_local: Option<u32>,
    pub max_use_count: u32,
    /// Map from local index to use count.
    pub use_counts: HashMap<u32, u32>,
}

impl LocalVarAnalysis {
    #[must_use]
    pub fn from_use_counts(counts: HashMap<u32, u32>, total: u32) -> Self {
        let used = counts.values().filter(|&&c| c > 0).count() as u32;
        let (most_used, max_count) = counts
            .iter()
            .max_by_key(|&(_, &v)| v)
            .map_or((None, 0), |(&k, &v)| (Some(k), v));
        Self {
            total_locals: total,
            used_locals: used,
            unused_locals: total.saturating_sub(used),
            most_used_local: most_used,
            max_use_count: max_count,
            use_counts: counts,
        }
    }

    /// Returns `true` when there are unused locals that could be eliminated.
    #[must_use]
    pub const fn has_dead_locals(&self) -> bool {
        self.unused_locals > 0
    }
}

// ─── CallFrequency ────────────────────────────────────────────────────────────

/// Call frequency analysis for a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallFrequency {
    pub function_index: u32,
    pub call_count: u64,
    pub callee_counts: HashMap<u32, u64>,
    pub is_hot: bool,
}

impl CallFrequency {
    #[must_use]
    pub fn is_recursive(&self) -> bool {
        self.callee_counts.contains_key(&self.function_index)
    }

    /// Returns the most called callee function index.
    #[must_use]
    pub fn most_called_callee(&self) -> Option<u32> {
        self.callee_counts
            .iter()
            .max_by_key(|&(_, &v)| v)
            .map(|(&k, _)| k)
    }
}

// ─── TailCallOpportunity ──────────────────────────────────────────────────────

/// A tail-call optimisation opportunity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailCallOpportunity {
    pub caller_index: u32,
    pub callee_index: u32,
    /// Byte offset of the call instruction within the function body.
    pub call_offset: u32,
    /// Whether the call is a direct self-recursive call.
    pub is_self_recursive: bool,
    /// Estimated stack savings in bytes.
    pub stack_savings: u32,
}

// ─── SIMDOpportunity ─────────────────────────────────────────────────────────

/// A potential SIMD vectorisation opportunity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SIMDOpportunity {
    pub function_index: u32,
    /// Suggested SIMD instruction (e.g. `v128.load`, `i32x4.add`).
    pub suggested_instruction: String,
    /// Scalar instruction being replaced.
    pub original_instruction: String,
    /// Number of lanes (e.g. 4 for `i32x4`).
    pub vector_width: u32,
    /// Estimated speedup factor.
    pub speedup_estimate: f32,
}

// ─── BulkMemoryOpportunity ────────────────────────────────────────────────────

/// A `memory.copy` / `memory.fill` bulk-memory optimization opportunity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkMemoryOpportunity {
    pub function_index: u32,
    pub pattern: String,
    /// Suggested bulk-memory instruction.
    pub suggested: String,
    /// Byte offset of the pattern within the function body.
    pub offset: u32,
    pub estimated_bytes: u32,
}

// ─── WasmOptHints ────────────────────────────────────────────────────────────

/// All collected optimisation hints for a WASM module.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WasmOptHints {
    pub local_vars: HashMap<u32, LocalVarAnalysis>,
    pub mem_patterns: HashMap<u32, MemAccessPattern>,
    pub call_frequencies: HashMap<u32, CallFrequency>,
    pub tail_call_opportunities: Vec<TailCallOpportunity>,
    pub simd_opportunities: Vec<SIMDOpportunity>,
    pub bulk_memory_opportunities: Vec<BulkMemoryOpportunity>,
    pub hot_function_indices: Vec<u32>,
}

impl WasmOptHints {
    /// Build a mock hints object for testing.
    #[must_use]
    pub fn mock() -> Self {
        let mut local_vars = HashMap::new();
        let mut use_counts = HashMap::new();
        use_counts.insert(0u32, 10u32);
        use_counts.insert(1, 5);
        use_counts.insert(2, 0); // unused
        local_vars.insert(0u32, LocalVarAnalysis::from_use_counts(use_counts, 3));

        let mut mem_patterns = HashMap::new();
        mem_patterns.insert(0u32, MemAccessPattern::Sequential);
        mem_patterns.insert(1, MemAccessPattern::Strided(4));
        mem_patterns.insert(2, MemAccessPattern::Random);

        let mut callee_counts = HashMap::new();
        callee_counts.insert(1u32, 500u64);
        callee_counts.insert(2u32, 200u64);
        let mut call_freqs = HashMap::new();
        call_freqs.insert(
            0u32,
            CallFrequency {
                function_index: 0,
                call_count: 10_000,
                callee_counts,
                is_hot: true,
            },
        );

        let tco = vec![TailCallOpportunity {
            caller_index: 3,
            callee_index: 3,
            call_offset: 0x40,
            is_self_recursive: true,
            stack_savings: 32,
        }];
        let simd = vec![SIMDOpportunity {
            function_index: 0,
            suggested_instruction: "i32x4.add".into(),
            original_instruction: "i32.add".into(),
            vector_width: 4,
            speedup_estimate: 3.8,
        }];
        let bulk = vec![BulkMemoryOpportunity {
            function_index: 1,
            pattern: "byte-by-byte memcpy loop".into(),
            suggested: "memory.copy".into(),
            offset: 0x80,
            estimated_bytes: 1024,
        }];

        Self {
            local_vars,
            mem_patterns,
            call_frequencies: call_freqs,
            tail_call_opportunities: tco,
            simd_opportunities: simd,
            bulk_memory_opportunities: bulk,
            hot_function_indices: vec![0],
        }
    }

    /// Number of hot functions.
    #[must_use]
    pub const fn hot_function_count(&self) -> usize {
        self.hot_function_indices.len()
    }

    /// Returns `true` if function `idx` has any dead locals.
    #[must_use]
    pub fn has_dead_locals(&self, func_idx: u32) -> bool {
        self.local_vars
            .get(&func_idx)
            .is_some_and(LocalVarAnalysis::has_dead_locals)
    }

    /// Returns the memory access pattern for function `idx`.
    #[must_use]
    pub fn mem_pattern(&self, func_idx: u32) -> MemAccessPattern {
        self.mem_patterns
            .get(&func_idx)
            .copied()
            .unwrap_or(MemAccessPattern::Unknown)
    }

    /// Total number of optimisation opportunities.
    #[must_use]
    pub const fn total_opportunities(&self) -> usize {
        self.tail_call_opportunities.len()
            + self.simd_opportunities.len()
            + self.bulk_memory_opportunities.len()
    }
}

impl fmt::Display for WasmOptHints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WasmOptHints hot={} tco={} simd={} bulk_mem={} total_opp={}",
            self.hot_function_count(),
            self.tail_call_opportunities.len(),
            self.simd_opportunities.len(),
            self.bulk_memory_opportunities.len(),
            self.total_opportunities(),
        )
    }
}

// ─── WasmOptAnalyzer ─────────────────────────────────────────────────────────

/// Analyses a WASM function body for optimisation opportunities.
#[derive(Debug, Default)]
pub struct WasmOptAnalyzer;

impl WasmOptAnalyzer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Analyse `code_bytes` for local variable usage patterns.
    #[must_use]
    pub fn analyze_locals(&self, code_bytes: &[u8], total_locals: u32) -> LocalVarAnalysis {
        // Cap the zero-prefill: `total_locals` comes from attacker-controlled local
        // declaration counts and can be up to u32::MAX (alloc/time DoS). Locals beyond
        // the cap are still counted lazily via the `entry()` below.
        const MAX_PREFILL: u32 = 65_536;
        let prefill = total_locals.min(MAX_PREFILL);
        let mut use_counts: HashMap<u32, u32> =
            HashMap::with_capacity(prefill as usize);
        for i in 0..prefill {
            use_counts.insert(i, 0);
        }
        // Scan for local.get (0x20) and local.set (0x21) opcodes
        let mut pos = 0;
        while pos < code_bytes.len() {
            let op = code_bytes[pos];
            pos += 1;
            if op == 0x20 || op == 0x21 || op == 0x22 {
                // Read LEB128 local index
                let (idx, consumed) = read_uleb128(code_bytes, pos);
                pos += consumed;
                *use_counts.entry(idx as u32).or_insert(0) += 1;
            } else {
                // Skip operands for common instructions (simplified)
                match op {
                    0x28..=0x3E => {
                        pos += 2;
                    } // mem arg (align + offset)
                    0x41 => {
                        skip_leb128(code_bytes, &mut pos);
                    } // i32.const
                    0x10 => {
                        skip_leb128(code_bytes, &mut pos);
                    } // call
                    _ => {}
                }
            }
        }
        LocalVarAnalysis::from_use_counts(use_counts, total_locals)
    }

    /// Detect tail-call opportunities in a function body.
    #[must_use]
    pub fn find_tail_calls(&self, func_idx: u32, code_bytes: &[u8]) -> Vec<TailCallOpportunity> {
        let mut opps = Vec::new();
        let len = code_bytes.len();
        if len < 3 {
            return opps;
        }
        // Look for `call <func_idx>` (0x10) immediately followed by `end` (0x0B)
        let mut pos = 0;
        while pos + 2 < len {
            if code_bytes[pos] == 0x10 {
                let (callee, consumed) = read_uleb128(code_bytes, pos + 1);
                let after = pos + 1 + consumed;
                if after < len && code_bytes[after] == 0x0B {
                    opps.push(TailCallOpportunity {
                        caller_index: func_idx,
                        callee_index: callee as u32,
                        call_offset: pos as u32,
                        is_self_recursive: callee as u32 == func_idx,
                        stack_savings: 32,
                    });
                }
            }
            pos += 1;
        }
        opps
    }

    /// Detect sequential memory access in a function body.
    #[must_use]
    pub fn detect_mem_pattern(&self, code_bytes: &[u8]) -> MemAccessPattern {
        let load_count = code_bytes
            .iter()
            .filter(|&&b| matches!(b, 0x28..=0x35))
            .count();
        if load_count > 4 {
            MemAccessPattern::Sequential
        } else {
            MemAccessPattern::Unknown
        }
    }
}

fn read_uleb128(data: &[u8], pos: usize) -> (u64, usize) {
    let mut result = 0u64;
    let mut shift = 0u32;
    let mut i = pos;
    loop {
        if i >= data.len() {
            return (result, i - pos);
        }
        let byte = data[i];
        i += 1;
        result |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            break;
        }
    }
    (result, i - pos)
}

fn skip_leb128(data: &[u8], pos: &mut usize) {
    while *pos < data.len() {
        let b = data[*pos];
        *pos += 1;
        if b & 0x80 == 0 {
            break;
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── MemAccessPattern ──────────────────────────────────────────────────────

    #[test]
    fn test_mem_pattern_display() {
        assert_eq!(MemAccessPattern::Sequential.to_string(), "sequential");
        assert_eq!(MemAccessPattern::Strided(4).to_string(), "stride-4");
        assert_eq!(MemAccessPattern::Random.to_string(), "random");
    }

    // ── LocalVarAnalysis ──────────────────────────────────────────────────────

    #[test]
    fn test_local_var_analysis_dead_locals() {
        let hints = WasmOptHints::mock();
        assert!(hints.has_dead_locals(0));
    }

    #[test]
    fn test_local_var_analysis_used_count() {
        let hints = WasmOptHints::mock();
        let la = &hints.local_vars[&0];
        assert_eq!(la.used_locals, 2); // locals 0 and 1 used, local 2 unused
    }

    #[test]
    fn test_local_var_analysis_most_used() {
        let hints = WasmOptHints::mock();
        let la = &hints.local_vars[&0];
        assert_eq!(la.most_used_local, Some(0));
    }

    #[test]
    fn test_local_var_analysis_max_use() {
        let hints = WasmOptHints::mock();
        let la = &hints.local_vars[&0];
        assert_eq!(la.max_use_count, 10);
    }

    // ── CallFrequency ─────────────────────────────────────────────────────────

    #[test]
    fn test_call_frequency_is_hot() {
        let hints = WasmOptHints::mock();
        assert!(hints.call_frequencies[&0].is_hot);
    }

    #[test]
    fn test_call_frequency_most_called_callee() {
        let hints = WasmOptHints::mock();
        let cf = &hints.call_frequencies[&0];
        assert_eq!(cf.most_called_callee(), Some(1));
    }

    #[test]
    fn test_call_frequency_not_recursive() {
        let hints = WasmOptHints::mock();
        let cf = &hints.call_frequencies[&0];
        assert!(!cf.is_recursive());
    }

    // ── TailCallOpportunity ───────────────────────────────────────────────────

    #[test]
    fn test_tail_call_is_self_recursive() {
        let hints = WasmOptHints::mock();
        assert!(hints.tail_call_opportunities[0].is_self_recursive);
    }

    #[test]
    fn test_tail_call_stack_savings() {
        let hints = WasmOptHints::mock();
        assert_eq!(hints.tail_call_opportunities[0].stack_savings, 32);
    }

    // ── SIMDOpportunity ───────────────────────────────────────────────────────

    #[test]
    fn test_simd_opportunity_suggested() {
        let hints = WasmOptHints::mock();
        assert_eq!(
            hints.simd_opportunities[0].suggested_instruction,
            "i32x4.add"
        );
    }

    #[test]
    fn test_simd_opportunity_speedup() {
        let hints = WasmOptHints::mock();
        assert!(hints.simd_opportunities[0].speedup_estimate > 1.0);
    }

    // ── BulkMemoryOpportunity ─────────────────────────────────────────────────

    #[test]
    fn test_bulk_memory_suggested() {
        let hints = WasmOptHints::mock();
        assert_eq!(hints.bulk_memory_opportunities[0].suggested, "memory.copy");
    }

    // ── WasmOptHints ─────────────────────────────────────────────────────────

    #[test]
    fn test_hints_hot_function_count() {
        let hints = WasmOptHints::mock();
        assert_eq!(hints.hot_function_count(), 1);
    }

    #[test]
    fn test_hints_mem_pattern_sequential() {
        let hints = WasmOptHints::mock();
        assert_eq!(hints.mem_pattern(0), MemAccessPattern::Sequential);
    }

    #[test]
    fn test_hints_mem_pattern_strided() {
        let hints = WasmOptHints::mock();
        assert_eq!(hints.mem_pattern(1), MemAccessPattern::Strided(4));
    }

    #[test]
    fn test_hints_mem_pattern_unknown_missing() {
        let hints = WasmOptHints::mock();
        assert_eq!(hints.mem_pattern(99), MemAccessPattern::Unknown);
    }

    #[test]
    fn test_hints_total_opportunities() {
        let hints = WasmOptHints::mock();
        assert_eq!(hints.total_opportunities(), 3);
    }

    #[test]
    fn test_hints_display() {
        let hints = WasmOptHints::mock();
        let s = format!("{hints}");
        assert!(s.contains("WasmOptHints"));
    }

    #[test]
    fn test_hints_serialization() {
        let hints = WasmOptHints::mock();
        let json = serde_json::to_string(&hints).unwrap();
        let back: WasmOptHints = serde_json::from_str(&json).unwrap();
        assert_eq!(back.hot_function_count(), hints.hot_function_count());
    }

    // ── WasmOptAnalyzer ───────────────────────────────────────────────────────

    #[test]
    fn test_analyzer_locals_empty_code() {
        let az = WasmOptAnalyzer::new();
        let la = az.analyze_locals(&[], 3);
        assert_eq!(la.total_locals, 3);
        assert_eq!(la.used_locals, 0);
    }

    #[test]
    fn test_analyzer_locals_with_get() {
        let az = WasmOptAnalyzer::new();
        // local.get 0 (0x20 0x00)
        let code = vec![0x20u8, 0x00, 0x20, 0x01];
        let la = az.analyze_locals(&code, 3);
        assert!(la.use_counts.get(&0).copied().unwrap_or(0) > 0);
    }

    #[test]
    fn test_analyzer_find_tail_calls_empty() {
        let az = WasmOptAnalyzer::new();
        let opps = az.find_tail_calls(0, &[]);
        assert!(opps.is_empty());
    }

    #[test]
    fn test_analyzer_find_tail_calls_detects() {
        let az = WasmOptAnalyzer::new();
        // call 0 (0x10 0x00) then end (0x0B)
        let code = vec![0x10u8, 0x00, 0x0B];
        let opps = az.find_tail_calls(0, &code);
        assert!(!opps.is_empty());
        assert!(opps[0].is_self_recursive);
    }

    #[test]
    fn test_analyzer_detect_mem_pattern_sequential() {
        let az = WasmOptAnalyzer::new();
        // Five i32.load (0x28) instructions
        let code = vec![
            0x28u8, 0x00, 0x00, 0x28, 0x00, 0x00, 0x28, 0x00, 0x00, 0x28, 0x00, 0x00, 0x28, 0x00,
            0x00,
        ];
        let pat = az.detect_mem_pattern(&code);
        assert_eq!(pat, MemAccessPattern::Sequential);
    }

    #[test]
    fn test_analyzer_detect_mem_pattern_unknown() {
        let az = WasmOptAnalyzer::new();
        let code = vec![0x01u8]; // just nop
        let pat = az.detect_mem_pattern(&code);
        assert_eq!(pat, MemAccessPattern::Unknown);
    }
    #[test]
    fn test_mem_pattern_random_display() {
        assert_eq!(MemAccessPattern::Random.to_string(), "random");
    }
    #[test]
    fn test_local_var_no_dead_when_all_used() {
        let mut counts = HashMap::new();
        counts.insert(0u32, 5u32);
        counts.insert(1, 3);
        let la = LocalVarAnalysis::from_use_counts(counts, 2);
        assert!(!la.has_dead_locals());
    }
    #[test]
    fn test_local_var_total_locals() {
        let la = LocalVarAnalysis::from_use_counts(HashMap::new(), 10);
        assert_eq!(la.total_locals, 10);
    }
    #[test]
    fn test_call_freq_most_called_none_when_empty() {
        let cf = CallFrequency {
            function_index: 0,
            call_count: 0,
            callee_counts: HashMap::new(),
            is_hot: false,
        };
        assert!(cf.most_called_callee().is_none());
    }
    #[test]
    fn test_hints_default_empty() {
        let h = WasmOptHints::default();
        assert_eq!(h.hot_function_count(), 0);
    }
    #[test]
    fn test_hints_total_opp_zero_when_empty() {
        let h = WasmOptHints::default();
        assert_eq!(h.total_opportunities(), 0);
    }
    #[test]
    fn test_tail_call_non_recursive() {
        let tc = TailCallOpportunity {
            caller_index: 0,
            callee_index: 1,
            call_offset: 0,
            is_self_recursive: false,
            stack_savings: 16,
        };
        assert!(!tc.is_self_recursive);
    }
    #[test]
    fn test_simd_vector_width() {
        let h = WasmOptHints::mock();
        assert_eq!(h.simd_opportunities[0].vector_width, 4);
    }
    #[test]
    fn test_bulk_memory_func() {
        let h = WasmOptHints::mock();
        assert_eq!(h.bulk_memory_opportunities[0].function_index, 1);
    }
    #[test]
    fn test_hints_has_dead_locals_false_for_missing() {
        let h = WasmOptHints::mock();
        assert!(!h.has_dead_locals(99));
    }
    #[test]
    fn test_hints_serialization_roundtrip() {
        let h = WasmOptHints::mock();
        let j = serde_json::to_string(&h).unwrap();
        let b: WasmOptHints = serde_json::from_str(&j).unwrap();
        assert_eq!(b.hot_function_count(), h.hot_function_count());
    }
    #[test]
    fn test_analyzer_find_tail_calls_no_end() {
        let az = WasmOptAnalyzer::new();
        let code = vec![0x10u8, 0x00];
        let opps = az.find_tail_calls(0, &code);
        assert!(opps.is_empty());
    }
    #[test]
    fn test_analyzer_locals_count_total() {
        let az = WasmOptAnalyzer::new();
        let la = az.analyze_locals(&[], 5);
        assert_eq!(la.total_locals, 5);
    }
    #[test]
    fn test_mem_pattern_strided_display() {
        assert_eq!(MemAccessPattern::Strided(8).to_string(), "stride-8");
    }
    #[test]
    fn test_simd_speedup_positive() {
        let h = WasmOptHints::mock();
        assert!(h.simd_opportunities[0].speedup_estimate > 1.0);
    }
}
