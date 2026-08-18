//! `wasm_analysis` — WebAssembly binary analysis.
//!
//! Provides call graph, indirect call table analysis, data flow analysis,
//! loop detection, tail call analysis, memory access patterns, and import graph.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WasmAnalysisError {
    FunctionNotFound(u32),
    InvalidTableIndex(u32),
    MalformedModule(String),
    InsufficientData(String),
}

impl fmt::Display for WasmAnalysisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WasmAnalysisError::FunctionNotFound(id) => write!(f, "function not found: {id}"),
            WasmAnalysisError::InvalidTableIndex(i) => write!(f, "invalid table index: {i}"),
            WasmAnalysisError::MalformedModule(msg) => write!(f, "malformed module: {msg}"),
            WasmAnalysisError::InsufficientData(msg) => write!(f, "insufficient data: {msg}"),
        }
    }
}

impl std::error::Error for WasmAnalysisError {}

// ─── WasmFunctionRef ─────────────────────────────────────────────────────────

/// A reference to a WebAssembly function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WasmFunctionRef {
    pub index: u32,
    pub is_import: bool,
}

impl WasmFunctionRef {
    #[must_use]
    pub const fn func(index: u32) -> Self {
        Self {
            index,
            is_import: false,
        }
    }
    #[must_use]
    pub const fn import(index: u32) -> Self {
        Self {
            index,
            is_import: true,
        }
    }
}

// ─── FunctionCallGraph ────────────────────────────────────────────────────────

/// WebAssembly function call graph.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FunctionCallGraph {
    /// Function index → set of called function indices.
    pub calls: HashMap<u32, HashSet<u32>>,
    /// Function index → set of callers.
    pub callers: HashMap<u32, HashSet<u32>>,
    /// Total function count.
    pub function_count: u32,
}

impl FunctionCallGraph {
    #[must_use]
    pub fn new(function_count: u32) -> Self {
        Self {
            calls: HashMap::new(),
            callers: HashMap::new(),
            function_count,
        }
    }

    pub fn add_call(&mut self, caller: u32, callee: u32) {
        self.calls.entry(caller).or_default().insert(callee);
        self.callers.entry(callee).or_default().insert(caller);
    }

    #[must_use]
    pub fn callees_of(&self, fn_idx: u32) -> &HashSet<u32> {
        static EMPTY: std::sync::OnceLock<HashSet<u32>> = std::sync::OnceLock::new();
        self.calls
            .get(&fn_idx)
            .unwrap_or_else(|| EMPTY.get_or_init(HashSet::new))
    }

    #[must_use]
    pub fn callers_of(&self, fn_idx: u32) -> &HashSet<u32> {
        static EMPTY: std::sync::OnceLock<HashSet<u32>> = std::sync::OnceLock::new();
        self.callers
            .get(&fn_idx)
            .unwrap_or_else(|| EMPTY.get_or_init(HashSet::new))
    }

    /// BFS reachability from a function.
    #[must_use]
    pub fn reachable_from(&self, fn_idx: u32) -> HashSet<u32> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(fn_idx);
        while let Some(cur) = queue.pop_front() {
            if !visited.insert(cur) {
                continue;
            }
            for &callee in self.callees_of(cur) {
                if !visited.contains(&callee) {
                    queue.push_back(callee);
                }
            }
        }
        visited
    }

    /// Root functions (never called).
    #[must_use]
    pub fn roots(&self) -> Vec<u32> {
        (0..self.function_count)
            .filter(|&i| self.callers_of(i).is_empty())
            .collect()
    }

    /// Leaf functions (no callees).
    #[must_use]
    pub fn leaves(&self) -> Vec<u32> {
        (0..self.function_count)
            .filter(|&i| self.callees_of(i).is_empty())
            .collect()
    }

    /// Recursive functions (call themselves directly or indirectly).
    #[must_use]
    pub fn recursive_functions(&self) -> Vec<u32> {
        (0..self.function_count)
            .filter(|&i| self.callees_of(i).contains(&i))
            .collect()
    }

    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.calls.values().map(|s| s.len()).sum()
    }
}

// ─── IndirectCallTable ────────────────────────────────────────────────────────

/// The WebAssembly element section: function pointers in the table.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct IndirectCallTable {
    /// Table index (usually 0) → list of (`slot_index`, `function_index`).
    pub entries: Vec<(u32, u32)>,
    pub table_size: u32,
}

impl IndirectCallTable {
    #[must_use]
    pub const fn new(table_size: u32) -> Self {
        Self {
            entries: Vec::new(),
            table_size,
        }
    }

    pub fn add_entry(&mut self, slot: u32, fn_idx: u32) {
        self.entries.push((slot, fn_idx));
    }

    /// Resolve a `call_indirect` at table slot `idx`.
    #[must_use]
    pub fn resolve(&self, slot: u32) -> Option<u32> {
        self.entries
            .iter()
            .find(|(s, _)| *s == slot)
            .map(|(_, f)| *f)
    }

    /// All unique function indices in the table.
    #[must_use]
    pub fn function_indices(&self) -> HashSet<u32> {
        self.entries.iter().map(|(_, f)| *f).collect()
    }

    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

// ─── DataFlowAnalysis ─────────────────────────────────────────────────────────

/// WebAssembly local / global variable type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WasmValType {
    I32,
    I64,
    F32,
    F64,
    V128,
    FuncRef,
    ExternRef,
}

impl fmt::Display for WasmValType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WasmValType::I32 => write!(f, "i32"),
            WasmValType::I64 => write!(f, "i64"),
            WasmValType::F32 => write!(f, "f32"),
            WasmValType::F64 => write!(f, "f64"),
            WasmValType::V128 => write!(f, "v128"),
            WasmValType::FuncRef => write!(f, "funcref"),
            WasmValType::ExternRef => write!(f, "externref"),
        }
    }
}

/// A data flow fact: which locals/globals have known types or values.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DataFlowState {
    pub local_types: HashMap<u32, WasmValType>,
    pub global_types: HashMap<u32, WasmValType>,
    pub stack: Vec<WasmValType>,
}

impl DataFlowState {
    pub fn push(&mut self, ty: WasmValType) {
        self.stack.push(ty);
    }

    pub fn pop(&mut self) -> Option<WasmValType> {
        self.stack.pop()
    }

    pub fn set_local(&mut self, idx: u32, ty: WasmValType) {
        self.local_types.insert(idx, ty);
    }

    #[must_use]
    pub fn get_local(&self, idx: u32) -> WasmValType {
        self.local_types
            .get(&idx)
            .cloned()
            .unwrap_or(WasmValType::I32)
    }
}

/// Simple forward data flow analysis for a WebAssembly function.
#[derive(Debug, Default)]
pub struct DataFlowAnalysis {
    pub states: HashMap<u32, DataFlowState>,
}

impl DataFlowAnalysis {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a state at an instruction offset.
    pub fn record(&mut self, offset: u32, state: DataFlowState) {
        self.states.insert(offset, state);
    }

    #[must_use]
    pub fn get(&self, offset: u32) -> Option<&DataFlowState> {
        self.states.get(&offset)
    }
}

// ─── LoopDetector ─────────────────────────────────────────────────────────────

/// A detected loop in WebAssembly code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmLoop {
    pub start_offset: u32,
    pub end_offset: u32,
    /// Nesting depth.
    pub depth: u32,
    /// Number of iterations (if statically known).
    pub static_bound: Option<u64>,
}

/// Detects loops from block/loop/end structure.
pub struct LoopDetector;

impl LoopDetector {
    /// Detect loops from a list of (offset, opcode) pairs.
    /// Wasm `loop` opcode = 0x03.
    #[must_use]
    pub fn detect(opcodes: &[(u32, u8)]) -> Vec<WasmLoop> {
        let mut loops = Vec::new();
        let mut stack: Vec<(u32, u8)> = Vec::new();
        let mut depth = 0u32;

        for &(offset, opcode) in opcodes {
            match opcode {
                0x02 => {
                    // block
                    stack.push((offset, 0x02));
                    depth += 1;
                }
                0x03 => {
                    // loop
                    stack.push((offset, 0x03));
                    depth += 1;
                }
                0x0B => {
                    // end
                    if let Some((start_offset, block_type)) = stack.pop() {
                        depth = depth.saturating_sub(1);
                        if block_type == 0x03 {
                            loops.push(WasmLoop {
                                start_offset,
                                end_offset: offset,
                                depth,
                                static_bound: None,
                            });
                        }
                    }
                }
                _ => {}
            }
        }
        loops
    }
}

// ─── TailCallAnalyzer ─────────────────────────────────────────────────────────

/// A detected tail call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmTailCall {
    pub call_offset: u32,
    pub fn_idx: u32,
    pub is_indirect: bool,
}

/// Detects tail calls in WebAssembly.
/// WebAssembly tail call proposal: `return_call` (0x12) and `return_call_indirect` (0x13).
pub struct TailCallAnalyzer;

impl TailCallAnalyzer {
    #[must_use]
    pub fn detect(opcodes: &[(u32, u8, Option<u32>)]) -> Vec<WasmTailCall> {
        let mut tail_calls = Vec::new();
        for &(offset, opcode, fn_idx_opt) in opcodes {
            match opcode {
                0x12 => {
                    // return_call
                    tail_calls.push(WasmTailCall {
                        call_offset: offset,
                        fn_idx: fn_idx_opt.unwrap_or(0),
                        is_indirect: false,
                    });
                }
                0x13 => {
                    // return_call_indirect
                    tail_calls.push(WasmTailCall {
                        call_offset: offset,
                        fn_idx: fn_idx_opt.unwrap_or(0),
                        is_indirect: true,
                    });
                }
                _ => {}
            }
        }
        tail_calls
    }
}

// ─── MemoryAccessPattern ─────────────────────────────────────────────────────

/// A single memory access observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAccess {
    pub offset: u32,
    pub instruction_offset: u32,
    pub access_size: u8,
    pub is_store: bool,
    pub align: u8,
}

/// Tracks and summarises memory access patterns.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MemoryAccessPattern {
    pub accesses: Vec<MemoryAccess>,
}

impl MemoryAccessPattern {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, access: MemoryAccess) {
        self.accesses.push(access);
    }

    #[must_use]
    pub fn load_count(&self) -> usize {
        self.accesses.iter().filter(|a| !a.is_store).count()
    }

    #[must_use]
    pub fn store_count(&self) -> usize {
        self.accesses.iter().filter(|a| a.is_store).count()
    }

    /// Accesses with a static known offset (linear memory address).
    #[must_use]
    pub fn static_offsets(&self) -> Vec<u32> {
        self.accesses.iter().map(|a| a.offset).collect()
    }

    /// Detect potential out-of-bounds accesses (offset + size > assumed memory size,
    /// or static offset within the near-u32-max danger zone where wasm dynamic-offset
    /// addition would wrap into the high address range).
    #[must_use]
    pub fn potential_oob(&self, memory_size_bytes: u64) -> Vec<&MemoryAccess> {
        // Heuristic: any static offset within the top 256 bytes of the u32 address
        // space is treated as a potential OOB even if it nominally fits, since any
        // non-zero dynamic base will wrap or escape any realistic linear memory.
        const NEAR_U32_MAX_THRESHOLD: u32 = u32::MAX - 0xFF;
        self.accesses
            .iter()
            .filter(|a| {
                let end = u64::from(a.offset) + u64::from(a.access_size);
                end > memory_size_bytes || a.offset >= NEAR_U32_MAX_THRESHOLD
            })
            .collect()
    }
}

// ─── ImportGraph ─────────────────────────────────────────────────────────────

/// An imported function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmImport {
    pub module: String,
    pub name: String,
    pub fn_index: u32,
    pub type_idx: u32,
}

/// Tracks imports and their usage.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ImportGraph {
    pub imports: Vec<WasmImport>,
    /// import `fn_index` → set of callers.
    pub callers: HashMap<u32, HashSet<u32>>,
}

impl ImportGraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_import(&mut self, import: WasmImport) {
        self.imports.push(import);
    }

    pub fn record_call(&mut self, import_fn: u32, caller: u32) {
        self.callers.entry(import_fn).or_default().insert(caller);
    }

    #[must_use]
    pub fn import_by_name(&self, module: &str, name: &str) -> Option<&WasmImport> {
        self.imports
            .iter()
            .find(|i| i.module == module && i.name == name)
    }

    #[must_use]
    pub const fn import_count(&self) -> usize {
        self.imports.len()
    }

    /// Imports grouped by module.
    #[must_use]
    pub fn by_module(&self) -> HashMap<&str, Vec<&WasmImport>> {
        let mut map: HashMap<&str, Vec<&WasmImport>> = HashMap::new();
        for imp in &self.imports {
            map.entry(&imp.module).or_default().push(imp);
        }
        map
    }
}

// ─── WasmAnalyzer ────────────────────────────────────────────────────────────

/// Top-level WebAssembly analyser.
pub struct WasmAnalyzer {
    pub call_graph: FunctionCallGraph,
    pub indirect_table: IndirectCallTable,
    pub data_flow: DataFlowAnalysis,
    pub loops: Vec<WasmLoop>,
    pub tail_calls: Vec<WasmTailCall>,
    pub memory_patterns: MemoryAccessPattern,
    pub import_graph: ImportGraph,
}

impl WasmAnalyzer {
    #[must_use]
    pub fn new(function_count: u32, table_size: u32) -> Self {
        Self {
            call_graph: FunctionCallGraph::new(function_count),
            indirect_table: IndirectCallTable::new(table_size),
            data_flow: DataFlowAnalysis::new(),
            loops: Vec::new(),
            tail_calls: Vec::new(),
            memory_patterns: MemoryAccessPattern::new(),
            import_graph: ImportGraph::new(),
        }
    }

    #[must_use]
    pub fn stats(&self) -> WasmStats {
        WasmStats {
            function_count: self.call_graph.function_count,
            call_edges: self.call_graph.edge_count(),
            indirect_table_entries: self.indirect_table.entry_count(),
            loop_count: self.loops.len(),
            tail_call_count: self.tail_calls.len(),
            memory_accesses: self.memory_patterns.accesses.len(),
            import_count: self.import_graph.import_count(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmStats {
    pub function_count: u32,
    pub call_edges: usize,
    pub indirect_table_entries: usize,
    pub loop_count: usize,
    pub tail_call_count: usize,
    pub memory_accesses: usize,
    pub import_count: usize,
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_graph_add_call() {
        let mut cg = FunctionCallGraph::new(5);
        cg.add_call(0, 1);
        cg.add_call(0, 2);
        assert_eq!(cg.callees_of(0).len(), 2);
        assert!(cg.callers_of(1).contains(&0));
    }

    #[test]
    fn call_graph_reachable() {
        let mut cg = FunctionCallGraph::new(5);
        cg.add_call(0, 1);
        cg.add_call(1, 2);
        cg.add_call(1, 3);
        let reachable = cg.reachable_from(0);
        assert!(reachable.contains(&1));
        assert!(reachable.contains(&2));
        assert!(reachable.contains(&3));
    }

    #[test]
    fn call_graph_roots_and_leaves() {
        let mut cg = FunctionCallGraph::new(3);
        cg.add_call(0, 1);
        cg.add_call(1, 2);
        let roots = cg.roots();
        assert!(roots.contains(&0));
        let leaves = cg.leaves();
        assert!(leaves.contains(&2));
    }

    #[test]
    fn call_graph_recursive() {
        let mut cg = FunctionCallGraph::new(3);
        cg.add_call(1, 1); // self-recursive
        assert!(cg.recursive_functions().contains(&1));
    }

    #[test]
    fn indirect_table_add_resolve() {
        let mut table = IndirectCallTable::new(16);
        table.add_entry(5, 42);
        assert_eq!(table.resolve(5), Some(42));
        assert_eq!(table.resolve(0), None);
    }

    #[test]
    fn indirect_table_function_indices() {
        let mut table = IndirectCallTable::new(8);
        table.add_entry(0, 10);
        table.add_entry(1, 20);
        table.add_entry(2, 10); // duplicate
        let indices = table.function_indices();
        assert_eq!(indices.len(), 2); // 10 and 20
    }

    #[test]
    fn data_flow_state_push_pop() {
        let mut state = DataFlowState::default();
        state.push(WasmValType::I32);
        state.push(WasmValType::F64);
        assert_eq!(state.pop(), Some(WasmValType::F64));
    }

    #[test]
    fn data_flow_state_locals() {
        let mut state = DataFlowState::default();
        state.set_local(0, WasmValType::I64);
        assert_eq!(state.get_local(0), WasmValType::I64);
        assert_eq!(state.get_local(99), WasmValType::I32); // default
    }

    #[test]
    fn loop_detector_basic() {
        let opcodes = vec![
            (0, 0x03u8), // loop
            (1, 0x41),   // i32.const
            (2, 0x0B),   // end
        ];
        let loops = LoopDetector::detect(&opcodes);
        assert_eq!(loops.len(), 1);
        assert_eq!(loops[0].start_offset, 0);
        assert_eq!(loops[0].end_offset, 2);
    }

    #[test]
    fn loop_detector_nested() {
        let opcodes = vec![
            (0, 0x03), // loop
            (1, 0x03), // loop
            (2, 0x0B), // end inner
            (3, 0x0B), // end outer
        ];
        let loops = LoopDetector::detect(&opcodes);
        assert_eq!(loops.len(), 2);
    }

    #[test]
    fn loop_detector_no_loops() {
        let opcodes = vec![(0, 0x02u8), (1, 0x0Bu8)]; // block...end
        let loops = LoopDetector::detect(&opcodes);
        assert!(loops.is_empty());
    }

    #[test]
    fn tail_call_analyzer_return_call() {
        let opcodes = vec![(10, 0x12u8, Some(5u32))];
        let tcs = TailCallAnalyzer::detect(&opcodes);
        assert_eq!(tcs.len(), 1);
        assert_eq!(tcs[0].fn_idx, 5);
        assert!(!tcs[0].is_indirect);
    }

    #[test]
    fn tail_call_analyzer_return_call_indirect() {
        let opcodes = vec![(20, 0x13u8, Some(3u32))];
        let tcs = TailCallAnalyzer::detect(&opcodes);
        assert_eq!(tcs.len(), 1);
        assert!(tcs[0].is_indirect);
    }

    #[test]
    fn memory_access_pattern_counts() {
        let mut mp = MemoryAccessPattern::new();
        mp.record(MemoryAccess {
            offset: 0,
            instruction_offset: 10,
            access_size: 4,
            is_store: false,
            align: 2,
        });
        mp.record(MemoryAccess {
            offset: 4,
            instruction_offset: 20,
            access_size: 4,
            is_store: true,
            align: 2,
        });
        assert_eq!(mp.load_count(), 1);
        assert_eq!(mp.store_count(), 1);
    }

    #[test]
    fn memory_access_pattern_oob() {
        let mut mp = MemoryAccessPattern::new();
        mp.record(MemoryAccess {
            offset: 0xFFFF_FF00,
            instruction_offset: 0,
            access_size: 8,
            is_store: false,
            align: 2,
        });
        let oob = mp.potential_oob(0x1_0000_0000u64); // 4 GiB
        assert!(!oob.is_empty());
    }

    #[test]
    fn import_graph_add_and_find() {
        let mut ig = ImportGraph::new();
        ig.add_import(WasmImport {
            module: "env".into(),
            name: "malloc".into(),
            fn_index: 0,
            type_idx: 1,
        });
        let found = ig.import_by_name("env", "malloc");
        assert!(found.is_some());
        assert_eq!(ig.import_count(), 1);
    }

    #[test]
    fn import_graph_by_module() {
        let mut ig = ImportGraph::new();
        ig.add_import(WasmImport {
            module: "env".into(),
            name: "a".into(),
            fn_index: 0,
            type_idx: 0,
        });
        ig.add_import(WasmImport {
            module: "env".into(),
            name: "b".into(),
            fn_index: 1,
            type_idx: 0,
        });
        ig.add_import(WasmImport {
            module: "wasi".into(),
            name: "c".into(),
            fn_index: 2,
            type_idx: 0,
        });
        let by_mod = ig.by_module();
        assert_eq!(by_mod["env"].len(), 2);
        assert_eq!(by_mod["wasi"].len(), 1);
    }

    #[test]
    fn wasm_analyzer_stats() {
        let mut analyzer = WasmAnalyzer::new(10, 16);
        analyzer.call_graph.add_call(0, 1);
        analyzer.indirect_table.add_entry(0, 5);
        let stats = analyzer.stats();
        assert_eq!(stats.function_count, 10);
        assert_eq!(stats.call_edges, 1);
        assert_eq!(stats.indirect_table_entries, 1);
    }

    #[test]
    fn wasm_error_display() {
        let e = WasmAnalysisError::FunctionNotFound(42);
        assert!(e.to_string().contains("42"));
    }

    #[test]
    fn wasm_val_type_display() {
        assert_eq!(WasmValType::I32.to_string(), "i32");
        assert_eq!(WasmValType::V128.to_string(), "v128");
    }
}
