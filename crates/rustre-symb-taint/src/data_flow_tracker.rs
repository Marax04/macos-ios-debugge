//! Data-flow taint tracker with forward propagation, backward slicing,
//! inter-procedural taint, and library function summarisation.
//!
//! Provides [`DataFlowTracker`], which maintains per-register and per-memory-cell
//! taint labels and exposes:
//!
//! - **Forward taint**: propagate taint from sources forward through the program.
//! - **Backward slice**: from a sink, walk backward through def-use edges to
//!   find the reaching definitions (and the taint path).
//! - **Intersection**: find all paths from a source to a sink.
//! - **Inter-procedural taint**: follow taint across call/return edges using
//!   per-function summaries.
//! - **Library summarisation**: model well-known libc functions without code.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::{TaintId, taint_bits};
use crate::taint_policy::{OperationClass, TaintPolicy};

// ─── Program location ─────────────────────────────────────────────────────────

/// A program point identified by its instruction address.
pub type ProgramPoint = u64;

// ─── Taint label ─────────────────────────────────────────────────────────────

/// Per-cell taint state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintLabel {
    /// Composite taint bitmask.
    pub mask: TaintId,
    /// The instruction address where this taint was introduced.
    pub origin_pc: ProgramPoint,
    /// Human-readable description of the taint source.
    pub source_name: String,
}

impl TaintLabel {
    pub fn new(mask: TaintId, origin_pc: ProgramPoint, source_name: impl Into<String>) -> Self {
        Self { mask, origin_pc, source_name: source_name.into() }
    }

    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.mask == taint_bits::NONE
    }

    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        Self {
            mask: self.mask | other.mask,
            origin_pc: self.origin_pc,
            source_name: if self.mask != 0 {
                self.source_name.clone()
            } else {
                other.source_name.clone()
            },
        }
    }
}

// ─── Taint state ─────────────────────────────────────────────────────────────

/// Complete taint state at a program point.
///
/// Tracks taint for registers and for memory cells (addressed by byte address).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TaintState {
    /// Per-register taint.
    pub registers: HashMap<String, TaintLabel>,
    /// Per-memory-byte taint (sparse).
    pub memory: HashMap<u64, TaintLabel>,
    /// Per-stack-slot taint (offset from frame base).
    pub stack: HashMap<i64, TaintLabel>,
}

impl TaintState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ─── Register access ─────────────────────────────────────────────────

    #[must_use]
    pub fn get_register(&self, reg: &str) -> TaintId {
        self.registers.get(reg).map_or(taint_bits::NONE, |l| l.mask)
    }

    pub fn set_register(&mut self, reg: impl Into<String>, label: TaintLabel) {
        let reg = reg.into();
        if label.is_clean() {
            self.registers.remove(&reg);
        } else {
            self.registers.insert(reg, label);
        }
    }

    pub fn clear_register(&mut self, reg: &str) {
        self.registers.remove(reg);
    }

    // ─── Memory access ────────────────────────────────────────────────────

    /// Get the taint for a range of bytes `[addr, addr + size)` (union).
    #[must_use]
    pub fn get_memory_range(&self, addr: u64, size: usize) -> TaintId {
        (addr..addr + size as u64)
            .map(|a| self.memory.get(&a).map_or(0, |l| l.mask))
            .fold(0, |acc, t| acc | t)
    }

    /// Set a byte range `[addr, addr + size)` to `label`.
    pub fn set_memory_range(&mut self, addr: u64, size: usize, label: &TaintLabel) {
        for a in addr..addr + size as u64 {
            if label.is_clean() {
                self.memory.remove(&a);
            } else {
                self.memory.insert(a, label.clone());
            }
        }
    }

    pub fn clear_memory_range(&mut self, addr: u64, size: usize) {
        for a in addr..addr + size as u64 {
            self.memory.remove(&a);
        }
    }

    // ─── Stack access ─────────────────────────────────────────────────────

    #[must_use]
    pub fn get_stack_slot(&self, offset: i64) -> TaintId {
        self.stack.get(&offset).map_or(0, |l| l.mask)
    }

    pub fn set_stack_slot(&mut self, offset: i64, label: TaintLabel) {
        if label.is_clean() {
            self.stack.remove(&offset);
        } else {
            self.stack.insert(offset, label);
        }
    }

    /// Return the total number of tainted cells (registers + memory bytes).
    #[must_use]
    pub fn tainted_cell_count(&self) -> usize {
        self.registers.len() + self.memory.len() + self.stack.len()
    }
}

// ─── Data-flow edge ───────────────────────────────────────────────────────────

/// A def-use edge in the data-flow graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowEdge {
    /// Definition point.
    pub def_pc: ProgramPoint,
    /// Use point.
    pub use_pc: ProgramPoint,
    /// The value (register name or memory address) flowing along this edge.
    pub value: String,
    /// Taint label on this edge.
    pub taint: TaintId,
}

// ─── Library function model ───────────────────────────────────────────────────

/// How a library function propagates taint from arguments to output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibraryModel {
    pub name: String,
    /// Indices of input arguments that are taint sources for the output.
    /// Empty = no taint propagation.
    pub taint_from_args: Vec<usize>,
    /// Index of the argument that receives taint (0 = return value).
    pub taint_to: usize,
    /// Fixed taint mask to add unconditionally (0 = none).
    pub inject_mask: TaintId,
    /// Whether this function clears taint from the output.
    pub sanitizes: bool,
}

impl LibraryModel {
    /// Compute the output taint given the argument taints.
    pub fn compute_output_taint(&self, arg_taints: &[TaintId]) -> TaintId {
        if self.sanitizes {
            return taint_bits::NONE;
        }
        let propagated: TaintId = self
            .taint_from_args
            .iter()
            .filter_map(|&i| arg_taints.get(i))
            .fold(0, |acc, &t| acc | t);
        propagated | self.inject_mask
    }
}

/// Built-in library models for common C functions.
#[must_use]
pub fn builtin_library_models() -> HashMap<String, LibraryModel> {
    let mut m = HashMap::new();

    let add = |m: &mut HashMap<String, LibraryModel>, name: &str, from: Vec<usize>, to: usize| {
        m.insert(
            name.into(),
            LibraryModel {
                name: name.into(),
                taint_from_args: from,
                taint_to: to,
                inject_mask: 0,
                sanitizes: false,
            },
        );
    };

    // memcpy(dst, src, n): taint propagates from src (arg1) to dst (arg0).
    add(&mut m, "memcpy", vec![1], 0);
    add(&mut m, "memmove", vec![1], 0);
    add(&mut m, "strcpy", vec![1], 0);
    add(&mut m, "strncpy", vec![1], 0);
    add(&mut m, "strcat", vec![0, 1], 0);
    add(&mut m, "strncat", vec![0, 1], 0);
    add(&mut m, "sprintf", vec![1, 2, 3, 4], 0);
    add(&mut m, "snprintf", vec![2, 3, 4], 0);
    // strlen returns an integer — taint from arg, but low risk.
    add(&mut m, "strlen", vec![0], 0);
    // strtol converts string to integer — propagates.
    add(&mut m, "strtol", vec![0], 0);
    add(&mut m, "atoi", vec![0], 0);

    // Sanitizers.
    m.insert(
        "isalnum".into(),
        LibraryModel {
            name: "isalnum".into(),
            taint_from_args: vec![0],
            taint_to: 0,
            inject_mask: 0,
            sanitizes: true,
        },
    );

    m
}

// ─── Interprocedural summary ──────────────────────────────────────────────────

/// Taint summary for a function (what taint propagates from args to return/output).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionTaintSummary {
    pub function_address: u64,
    pub function_name: Option<String>,
    /// Mapping: output register → set of input arg indices that may taint it.
    pub output_taints: HashMap<String, Vec<usize>>,
    /// Whether the function always returns clean data.
    pub always_clean: bool,
}

impl FunctionTaintSummary {
    #[must_use]
    pub fn new(addr: u64) -> Self {
        Self { function_address: addr, ..Default::default() }
    }

    #[must_use]
    pub fn compute_return_taint(&self, arg_taints: &[TaintId]) -> TaintId {
        if self.always_clean {
            return 0;
        }
        self.output_taints.get("rax").map_or_else(
            // Conservative: if no summary, propagate all.
            || arg_taints.iter().fold(0, |acc, &t| acc | t),
            |return_sources| return_sources.iter()
                .filter_map(|&i| arg_taints.get(i))
                .fold(0, |acc, &t| acc | t),
        )
    }
}

// ─── DataFlowTracker ─────────────────────────────────────────────────────────

/// Configuration for the data-flow tracker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowConfig {
    /// Maximum backward-slice depth.
    pub max_slice_depth: usize,
    /// Whether to follow taint across function call boundaries.
    pub interprocedural: bool,
    /// Whether to use built-in library models.
    pub use_library_models: bool,
}

impl Default for DataFlowConfig {
    fn default() -> Self {
        Self {
            max_slice_depth: 64,
            interprocedural: true,
            use_library_models: true,
        }
    }
}

/// The main data-flow tracker.
///
/// Maintains the taint state and a history of data-flow edges for slicing.
pub struct DataFlowTracker {
    config: DataFlowConfig,
    policy: TaintPolicy,
    state: TaintState,
    /// All data-flow edges observed (for backward slicing).
    edges: Vec<DataFlowEdge>,
    /// Known library models.
    library_models: HashMap<String, LibraryModel>,
    /// Inter-procedural summaries.
    function_summaries: HashMap<u64, FunctionTaintSummary>,
    /// Addresses marked as taint sources.
    source_points: HashSet<ProgramPoint>,
    /// Addresses marked as taint sinks.
    sink_points: HashSet<ProgramPoint>,
}

impl DataFlowTracker {
    #[must_use]
    pub fn new(config: DataFlowConfig, policy: TaintPolicy) -> Self {
        let library_models = if config.use_library_models {
            builtin_library_models()
        } else {
            HashMap::new()
        };
        Self {
            config,
            policy,
            state: TaintState::new(),
            edges: Vec::new(),
            library_models,
            function_summaries: HashMap::new(),
            source_points: HashSet::new(),
            sink_points: HashSet::new(),
        }
    }

    #[must_use]
    pub fn with_default_config(policy: TaintPolicy) -> Self {
        Self::new(DataFlowConfig::default(), policy)
    }

    // ─── Source / sink registration ───────────────────────────────────────

    /// Mark a register at `pc` as tainted with `mask`.
    pub fn mark_source_register(
        &mut self,
        pc: ProgramPoint,
        reg: impl Into<String>,
        mask: TaintId,
        source_name: impl Into<String>,
    ) {
        let reg = reg.into();
        let label = TaintLabel::new(mask, pc, source_name.into());
        self.state.set_register(reg.clone(), label);
        self.source_points.insert(pc);
        // Record a self-edge for the source.
        self.edges.push(DataFlowEdge {
            def_pc: pc,
            use_pc: pc,
            value: reg,
            taint: mask,
        });
    }

    /// Mark a memory range as tainted.
    pub fn mark_source_memory(
        &mut self,
        pc: ProgramPoint,
        addr: u64,
        size: usize,
        mask: TaintId,
        source_name: impl Into<String>,
    ) {
        let label = TaintLabel::new(mask, pc, source_name.into());
        self.state.set_memory_range(addr, size, &label);
        self.source_points.insert(pc);
    }

    // ─── Forward taint propagation ────────────────────────────────────────

    /// Propagate taint through a binary operation: `dst_reg = op(src1, src2)`.
    pub fn propagate_binop(
        &mut self,
        pc: ProgramPoint,
        dst: impl Into<String>,
        src1: &str,
        src2: &str,
        op_class: OperationClass,
    ) {
        let t1 = self.state.get_register(src1);
        let t2 = self.state.get_register(src2);
        let out = self.policy.propagate(op_class, &[t1, t2]);
        let dst = dst.into();
        let label = TaintLabel::new(out, pc, "propagated");
        self.state.set_register(dst, label);
        if out != 0 {
            for src in [src1, src2] {
                self.edges.push(DataFlowEdge {
                    def_pc: pc,
                    use_pc: pc,
                    value: src.into(),
                    taint: self.state.get_register(src),
                });
            }
        }
    }

    /// Propagate taint through a memory load: `dst_reg = MEM[addr]`.
    pub fn propagate_load(
        &mut self,
        pc: ProgramPoint,
        dst: impl Into<String>,
        addr: u64,
        size: usize,
    ) {
        let mem_taint = self.state.get_memory_range(addr, size);
        let dst = dst.into();
        let label = TaintLabel::new(mem_taint, pc, "memory_load");
        self.state.set_register(dst, label);
        if mem_taint != 0 {
            self.edges.push(DataFlowEdge {
                def_pc: pc,
                use_pc: pc,
                value: format!("mem[{addr:#x}+{size}]"),
                taint: mem_taint,
            });
        }
    }

    /// Propagate taint through a memory store: `MEM[addr] = src_reg`.
    pub fn propagate_store(
        &mut self,
        pc: ProgramPoint,
        src: &str,
        addr: u64,
        size: usize,
    ) {
        let taint = self.state.get_register(src);
        let label = TaintLabel::new(taint, pc, "memory_store");
        self.state.set_memory_range(addr, size, &label);
    }

    /// Propagate taint through a function call using a library model.
    ///
    /// `api_name` is the called function.  `arg_registers` are the argument
    /// registers in order.  `dst` is the output register (usually "rax").
    pub fn propagate_call(
        &mut self,
        pc: ProgramPoint,
        api_name: &str,
        arg_registers: &[&str],
        dst: impl Into<String>,
    ) {
        let arg_taints: Vec<TaintId> =
            arg_registers.iter().map(|r| self.state.get_register(r)).collect();

        let out_taint = if let Some(model) = self.library_models.get(api_name) {
            model.compute_output_taint(&arg_taints)
        } else if self.config.interprocedural {
            // Conservative: union of all arg taints.
            arg_taints.iter().fold(0, |acc, &t| acc | t)
        } else {
            0
        };

        let dst = dst.into();
        let label = TaintLabel::new(out_taint, pc, format!("call:{api_name}"));
        self.state.set_register(dst, label);
    }

    // ─── Backward slice ───────────────────────────────────────────────────

    /// Compute a backward slice from `sink_pc` (register `sink_reg`).
    ///
    /// Returns the set of (`pc`, `value`) pairs that contribute taint to the sink.
    #[must_use]
    pub fn backward_slice(
        &self,
        sink_pc: ProgramPoint,
        sink_reg: &str,
    ) -> Vec<(ProgramPoint, String)> {
        let mut result = Vec::new();
        let mut worklist: VecDeque<(ProgramPoint, String)> = VecDeque::new();
        let mut visited = HashSet::new();
        worklist.push_back((sink_pc, sink_reg.to_string()));

        let mut depth = 0;
        while let Some((pc, val)) = worklist.pop_front() {
            if depth >= self.config.max_slice_depth {
                break;
            }
            if !visited.insert((pc, val.clone())) {
                continue;
            }
            result.push((pc, val.clone()));
            depth += 1;

            // Find edges that define `val` at or before `pc`.
            for edge in self.edges.iter().rev() {
                if edge.use_pc <= pc && edge.value == val && edge.taint != 0 {
                    worklist.push_back((edge.def_pc, val.clone()));
                }
            }
        }
        result
    }

    // ─── Source-to-sink path ──────────────────────────────────────────────

    /// Find all paths from any source to any sink through the data-flow graph.
    ///
    /// Returns pairs of (`source_pc`, `sink_pc`) where a tainted path exists.
    #[must_use]
    pub fn find_source_to_sink_paths(&self) -> Vec<(ProgramPoint, ProgramPoint)> {
        let mut paths = Vec::new();

        // For each edge whose source is a source_point, walk forward.
        for source_pc in &self.source_points {
            for edge in &self.edges {
                if edge.def_pc == *source_pc && edge.taint != 0 {
                    // BFS forward through edges.
                    let mut worklist = VecDeque::new();
                    let mut visited = HashSet::new();
                    worklist.push_back(edge.use_pc);
                    while let Some(cur_pc) = worklist.pop_front() {
                        if !visited.insert(cur_pc) {
                            continue;
                        }
                        if self.sink_points.contains(&cur_pc) {
                            paths.push((*source_pc, cur_pc));
                        }
                        for e in &self.edges {
                            if e.def_pc == cur_pc && e.taint != 0 {
                                worklist.push_back(e.use_pc);
                            }
                        }
                    }
                }
            }
        }
        paths.dedup();
        paths
    }

    // ─── Sink checking ────────────────────────────────────────────────────

    /// Check whether a call to `api_name` with argument registers `arg_regs`
    /// is a tainted sink.
    ///
    /// Returns a list of (`sink_name`, `taint_mask`, `arg_index`) for each dangerous
    /// argument.
    #[must_use]
    pub fn check_sink_call(
        &self,
        _pc: ProgramPoint,
        api_name: &str,
        arg_regs: &[&str],
    ) -> Vec<(String, TaintId, usize)> {
        let mut alerts = Vec::new();
        for sink in self.policy.sinks_for_api(api_name) {
            let arg_idx = sink.sensitive_arg.saturating_sub(1).min(arg_regs.len());
            let t = arg_regs.get(arg_idx).map_or(0, |r| self.state.get_register(r));
            if sink.is_dangerous(t) {
                alerts.push((sink.name.clone(), t, arg_idx));
            }
        }
        alerts
    }

    // ─── Inter-procedural summary registration ────────────────────────────

    pub fn register_function_summary(&mut self, summary: FunctionTaintSummary) {
        self.function_summaries.insert(summary.function_address, summary);
    }

    pub fn register_sink_point(&mut self, pc: ProgramPoint) {
        self.sink_points.insert(pc);
    }

    // ─── Accessors ────────────────────────────────────────────────────────

    #[must_use]
    pub fn state(&self) -> &TaintState {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut TaintState {
        &mut self.state
    }

    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    #[must_use]
    pub fn source_count(&self) -> usize {
        self.source_points.len()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker() -> DataFlowTracker {
        DataFlowTracker::with_default_config(TaintPolicy::default_c_policy())
    }

    #[test]
    fn test_mark_source_and_get() {
        let mut t = tracker();
        t.mark_source_register(0x1000, "rdi", taint_bits::USER_INPUT, "argv");
        assert_ne!(t.state().get_register("rdi"), 0);
    }

    #[test]
    fn test_propagate_binop() {
        let mut t = tracker();
        t.mark_source_register(0x1000, "rdi", taint_bits::USER_INPUT, "argv");
        t.propagate_binop(0x1010, "rax", "rdi", "rsi", OperationClass::Arithmetic);
        assert_ne!(t.state().get_register("rax"), 0);
        assert_eq!(t.state().get_register("rsi"), 0); // rsi was clean
    }

    #[test]
    fn test_propagate_store_load() {
        let mut t = tracker();
        t.mark_source_register(0x1000, "rdi", taint_bits::NETWORK, "network");
        t.propagate_store(0x1010, "rdi", 0xDEAD_0000, 8);
        assert_ne!(t.state().get_memory_range(0xDEAD_0000, 8), 0);

        t.propagate_load(0x1020, "rcx", 0xDEAD_0000, 8);
        assert_ne!(t.state().get_register("rcx"), 0);
    }

    #[test]
    fn test_propagate_call_library_model() {
        let mut t = tracker();
        t.mark_source_register(0x1000, "rsi", taint_bits::FILE, "file");
        // strcpy(dst=rdi, src=rsi): taint from rsi → rdi
        t.propagate_call(0x1010, "strcpy", &["rdi", "rsi"], "rax");
        // Conservative: union of args
        assert_ne!(t.state().get_register("rax"), 0);
    }

    #[test]
    fn test_check_sink_call_dangerous() {
        let mut t = tracker();
        t.mark_source_register(0x1000, "rdi", taint_bits::USER_INPUT, "argv");
        let alerts = t.check_sink_call(0x2000, "execve", &["rdi", "rsi", "rdx"]);
        // execve with tainted rdi (arg0) should be flagged.
        assert!(!alerts.is_empty());
    }

    #[test]
    fn test_backward_slice() {
        let mut t = tracker();
        t.mark_source_register(0x1000, "rdi", taint_bits::USER_INPUT, "argv");
        t.propagate_binop(0x1010, "rax", "rdi", "rsi", OperationClass::Arithmetic);
        let slice = t.backward_slice(0x1010, "rdi");
        assert!(!slice.is_empty());
    }

    #[test]
    fn test_clean_register() {
        let mut t = tracker();
        t.mark_source_register(0x1000, "rax", taint_bits::ALL, "test");
        assert_ne!(t.state().get_register("rax"), 0);
        t.state_mut().clear_register("rax");
        assert_eq!(t.state().get_register("rax"), 0);
    }

    #[test]
    fn test_memory_range() {
        let mut t = tracker();
        let label = TaintLabel::new(taint_bits::FILE, 0x100, "file");
        t.state_mut().set_memory_range(0x4000, 4, &label);
        assert_ne!(t.state().get_memory_range(0x4000, 4), 0);
        assert_eq!(t.state().get_memory_range(0x5000, 4), 0);
    }

    #[test]
    fn test_library_model_sanitizer() {
        let model = LibraryModel {
            name: "isalnum".into(),
            taint_from_args: vec![0],
            taint_to: 0,
            inject_mask: 0,
            sanitizes: true,
        };
        assert_eq!(model.compute_output_taint(&[taint_bits::ALL]), 0);
    }
}
