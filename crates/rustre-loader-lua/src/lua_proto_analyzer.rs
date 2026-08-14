//! `lua_proto_analyzer` — Deep analysis of Lua function prototypes.
//!
//! Computes complexity metrics (cyclomatic, instruction density), traces
//! upvalue chains, detects recursive calls, builds an inter-proto call graph,
//! and recognises common code patterns (table constructors, metatable idioms,
//! class definitions).

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use crate::lua_bytecode_parser::{LuaConstant, LuaProto, LuaVersion, UpvalueDesc};

// ─────────────────────────────────────────────────────────────────────────────
// ComplexityMetrics
// ─────────────────────────────────────────────────────────────────────────────

/// Cyclomatic complexity and related instruction-level metrics for one proto.
#[derive(Debug, Clone, Default)]
pub struct ComplexityMetrics {
    /// Total instruction count.
    pub insn_count: usize,
    /// Number of branch instructions (conditional and unconditional jumps).
    pub branch_count: usize,
    /// Number of call instructions (CALL, TAILCALL).
    pub call_count: usize,
    /// Number of return instructions.
    pub return_count: usize,
    /// Number of closure-creation instructions (CLOSURE).
    pub closure_count: usize,
    /// McCabe cyclomatic complexity: `branch_count - return_count + 2`.
    pub cyclomatic: u32,
    /// Instruction density: `insn_count / (last_line - first_line + 1)`.
    pub density: f64,
    /// Number of unique opcodes used.
    pub unique_opcodes: usize,
    /// Estimated number of basic blocks.
    pub basic_block_count: usize,
}

impl ComplexityMetrics {
    /// Compute metrics from a proto for the given Lua version.
    pub fn compute(proto: &LuaProto, ver: LuaVersion) -> Self {
        let mut m = ComplexityMetrics::default();
        m.insn_count = proto.insn_count();

        let mut opcodes_seen: HashSet<u8> = HashSet::new();
        let mut branch_targets: HashSet<usize> = HashSet::new();
        branch_targets.insert(0); // entry is always a block start

        for (i, &insn) in proto.instructions.iter().enumerate() {
            let op = proto.opcode_at(i, ver);
            opcodes_seen.insert(op);

            // Classify by opcode (Lua 5.1–5.4 common opcodes).
            match ver {
                LuaVersion::Lua51 | LuaVersion::Lua52 => classify_51(op, insn, i, &mut m, &mut branch_targets),
                LuaVersion::Lua53 => classify_53(op, insn, i, &mut m, &mut branch_targets),
                LuaVersion::Lua54 => classify_54(op, insn, i, &mut m, &mut branch_targets),
            }
        }

        m.unique_opcodes = opcodes_seen.len();
        m.basic_block_count = branch_targets.len();

        // McCabe: E - N + 2P where for a single function P=1.
        // Simplified: branches + 1 (each conditional branch adds one extra path).
        m.cyclomatic = (m.branch_count as u32).saturating_add(1);

        // Density: instructions per source line.
        let line_span = proto
            .last_line_defined
            .saturating_sub(proto.line_defined)
            .max(1) as f64;
        m.density = m.insn_count as f64 / line_span;

        m
    }
}

impl fmt::Display for ComplexityMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Complexity {{ insns={} branches={} calls={} cyclomatic={} density={:.2} }}",
            self.insn_count,
            self.branch_count,
            self.call_count,
            self.cyclomatic,
            self.density
        )
    }
}

// Opcode classification helpers (minimal — covers most common ops by number).

fn classify_51(op: u8, insn: u32, i: usize, m: &mut ComplexityMetrics, bts: &mut HashSet<usize>) {
    // Lua 5.1 opcodes: 0=MOVE 1=LOADK … 22=JMP 23=EQ 24=LT 25=LE … 28=CALL …
    match op {
        22 => { // JMP
            m.branch_count += 1;
            let sbx = ((insn >> 14) as i32) - 131_071;
            let target = (i as i32 + sbx + 1) as usize;
            bts.insert(target);
            bts.insert(i + 1);
        }
        23 | 24 | 25 | 26 | 27 => { // EQ LT LE TEST TESTSET
            m.branch_count += 1;
            bts.insert(i + 2);
        }
        28 | 29 => m.call_count += 1,  // CALL TAILCALL
        30 => m.return_count += 1,      // RETURN
        36 => m.closure_count += 1,     // CLOSURE
        _ => {}
    }
}

fn classify_53(op: u8, insn: u32, i: usize, m: &mut ComplexityMetrics, bts: &mut HashSet<usize>) {
    // Lua 5.3 opcodes differ slightly from 5.1.
    match op {
        23 => { // JMP
            m.branch_count += 1;
            let sbx = ((insn >> 14) as i32) - 131_071;
            let target = (i as i32 + sbx + 1).max(0) as usize;
            bts.insert(target);
            bts.insert(i + 1);
        }
        24 | 25 | 26 | 27 | 28 => { // EQ LT LE TEST TESTSET
            m.branch_count += 1;
            bts.insert(i + 2);
        }
        29 | 30 => m.call_count += 1,  // CALL TAILCALL
        31 => m.return_count += 1,      // RETURN
        44 => m.closure_count += 1,     // CLOSURE (5.3)
        _ => {}
    }
}

fn classify_54(op: u8, insn: u32, i: usize, m: &mut ComplexityMetrics, bts: &mut HashSet<usize>) {
    // Lua 5.4 opcodes (7-bit).
    match op {
        57 => { // JMP
            m.branch_count += 1;
            let sj = ((insn >> 10) as i32) - ((1 << 17) - 1);
            let target = (i as i32 + sj + 1).max(0) as usize;
            bts.insert(target);
            bts.insert(i + 1);
        }
        48 | 49 | 50 | 51 | 52 | 53 | 54 | 55 | 56 => { // various comparisons / test
            m.branch_count += 1;
            bts.insert(i + 2);
        }
        65 | 66 => m.call_count += 1,  // CALL TAILCALL
        67 => m.return_count += 1,      // RETURN
        80 => m.closure_count += 1,     // CLOSURE (approx)
        _ => {}
    }
    let _ = insn;
}

// ─────────────────────────────────────────────────────────────────────────────
// UpvalueChain
// ─────────────────────────────────────────────────────────────────────────────

/// A single step in an upvalue capture chain.
#[derive(Debug, Clone)]
pub struct UpvalueStep {
    /// Proto depth at which this step occurs (0 = outermost).
    pub depth: u32,
    /// The upvalue descriptor at this step.
    pub desc: UpvalueDesc,
}

/// The full chain from an innermost proto to the source register.
#[derive(Debug, Clone)]
pub struct UpvalueChain {
    /// Name of the captured variable (may be empty if stripped).
    pub name: String,
    /// Steps from innermost (index 0) to outermost.
    pub steps: Vec<UpvalueStep>,
    /// Whether the source was found (chain terminated at an in-stack capture).
    pub resolved: bool,
}

impl UpvalueChain {
    /// Build chains for all upvalues of `proto` within a proto tree.
    ///
    /// `ancestors`: list of ancestor protos from outermost (index 0) to the
    /// direct parent of `proto`.
    pub fn build_for_proto(proto: &LuaProto, ancestors: &[&LuaProto]) -> Vec<UpvalueChain> {
        proto
            .upvalues
            .iter()
            .map(|uv| UpvalueChain::trace(uv, ancestors))
            .collect()
    }

    /// Trace a single upvalue descriptor through the ancestor chain.
    fn trace(start: &UpvalueDesc, ancestors: &[&LuaProto]) -> UpvalueChain {
        let mut chain = UpvalueChain {
            name: start.name.clone(),
            steps: Vec::new(),
            resolved: false,
        };

        // Push the first step (the upvalue in the innermost proto).
        chain.steps.push(UpvalueStep { depth: ancestors.len() as u32 + 1, desc: start.clone() });

        if start.in_stack != 0 {
            chain.resolved = true;
            return chain;
        }

        // Walk up through ancestors following the upvalue index.
        let mut current_idx = start.idx as usize;
        for (anc_depth, ancestor) in ancestors.iter().rev().enumerate() {
            if let Some(uv) = ancestor.upvalues.get(current_idx) {
                let depth = ancestors.len() as u32 - anc_depth as u32;
                chain.steps.push(UpvalueStep { depth, desc: uv.clone() });
                if uv.in_stack != 0 {
                    chain.resolved = true;
                    break;
                }
                current_idx = uv.idx as usize;
            } else {
                break;
            }
        }

        chain
    }

    /// Depth of the chain (number of closure boundaries crossed).
    pub fn depth(&self) -> usize {
        self.steps.len()
    }
}

impl fmt::Display for UpvalueChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = if self.name.is_empty() { "<anon>" } else { &self.name };
        write!(
            f,
            "UpvalueChain({} depth={} resolved={})",
            name,
            self.depth(),
            self.resolved
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProtoPattern
// ─────────────────────────────────────────────────────────────────────────────

/// A recognized high-level code pattern in a proto.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProtoPattern {
    /// The proto builds a table with `NEWTABLE` followed by `SETLIST`.
    TableConstructor,
    /// The proto sets `__index` on a table (metatable idiom).
    Metatable,
    /// The proto assigns `self = {}` and returns it (class constructor).
    ClassConstructor,
    /// The proto calls `setmetatable`.
    SetMetatable,
    /// The proto is a simple getter (1 instruction + RETURN).
    SimpleGetter,
    /// The proto is a simple setter (1 store + RETURN).
    SimpleSetter,
    /// The proto tail-calls another function.
    TailCall,
    /// The proto contains a numeric for loop.
    NumericFor,
    /// The proto contains a generic for loop.
    GenericFor,
    /// The proto recursively calls itself.
    Recursive,
}

impl fmt::Display for ProtoPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ProtoPattern::TableConstructor => "table_constructor",
            ProtoPattern::Metatable => "metatable",
            ProtoPattern::ClassConstructor => "class_constructor",
            ProtoPattern::SetMetatable => "set_metatable",
            ProtoPattern::SimpleGetter => "simple_getter",
            ProtoPattern::SimpleSetter => "simple_setter",
            ProtoPattern::TailCall => "tail_call",
            ProtoPattern::NumericFor => "numeric_for",
            ProtoPattern::GenericFor => "generic_for",
            ProtoPattern::Recursive => "recursive",
        };
        f.write_str(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProtoCallGraph
// ─────────────────────────────────────────────────────────────────────────────

/// An edge in the inter-proto call graph.
#[derive(Debug, Clone)]
pub struct CallEdge {
    /// Caller proto index (depth-first pre-order within the chunk).
    pub caller: u32,
    /// Callee proto index.
    pub callee: u32,
    /// Whether this is a tail call.
    pub is_tail: bool,
    /// Number of such call sites from `caller` to `callee`.
    pub site_count: u32,
}

/// Call graph between Lua function prototypes within a single chunk.
#[derive(Debug, Clone)]
pub struct ProtoCallGraph {
    /// Directed edges.
    pub edges: Vec<CallEdge>,
    /// Adjacency list: caller proto index → list of callee indices.
    pub adj: HashMap<u32, Vec<u32>>,
}

impl ProtoCallGraph {
    /// Create an empty call graph.
    pub fn new() -> Self {
        ProtoCallGraph { edges: Vec::new(), adj: HashMap::new() }
    }

    /// Add an edge from `caller` to `callee`.
    pub fn add_edge(&mut self, caller: u32, callee_id: u32, is_tail: bool) {
        self.adj.entry(caller).or_default().push(callee_id);
        // Merge into existing edge or create new.
        if let Some(e) = self
            .edges
            .iter_mut()
            .find(|e| e.caller == caller && e.callee == callee_id)
        {
            e.site_count += 1;
        } else {
            self.edges.push(CallEdge { caller, callee: callee_id, is_tail, site_count: 1 });
        }
    }

    /// Recursively detects self-calls (caller == callee).
    pub fn recursive_protos(&self) -> Vec<u32> {
        self.edges
            .iter()
            .filter(|e| e.caller == e.callee)
            .map(|e| e.caller)
            .collect()
    }

    /// Returns all callees of `proto_id` in BFS order.
    pub fn reachable_from(&self, proto_id: u32) -> Vec<u32> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(proto_id);
        while let Some(id) = queue.pop_front() {
            if !visited.insert(id) {
                continue;
            }
            if let Some(callees) = self.adj.get(&id) {
                for &c in callees {
                    queue.push_back(c);
                }
            }
        }
        visited.into_iter().collect()
    }

    /// Number of unique call edges.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

impl Default for ProtoCallGraph {
    fn default() -> Self {
        ProtoCallGraph::new()
    }
}

impl fmt::Display for ProtoCallGraph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProtoCallGraph(edges={})", self.edge_count())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProtoAnalysis
// ─────────────────────────────────────────────────────────────────────────────

/// Full analysis result for a single Lua function prototype.
#[derive(Debug, Clone)]
pub struct ProtoAnalysis {
    /// Depth-first pre-order index (0 = main chunk proto).
    pub index: u32,
    /// Source name of this proto.
    pub source_name: String,
    /// Line range.
    pub line_range: (u32, u32),
    /// Number of parameters.
    pub num_params: u8,
    /// Whether the function is variadic.
    pub is_vararg: bool,
    /// Computed complexity metrics.
    pub metrics: ComplexityMetrics,
    /// Recognised patterns.
    pub patterns: Vec<ProtoPattern>,
    /// Upvalue chains.
    pub upvalue_chains: Vec<UpvalueChain>,
    /// Index of the parent proto (`None` for the main chunk).
    pub parent_index: Option<u32>,
    /// Indices of nested (child) protos.
    pub child_indices: Vec<u32>,
    /// Whether this proto was identified as recursive.
    pub is_recursive: bool,
    /// String constants used in this proto.
    pub string_consts: Vec<String>,
    /// Numeric constants used in this proto.
    pub numeric_consts: Vec<f64>,
}

impl ProtoAnalysis {
    /// Build a `ProtoAnalysis` from a proto at `index`.
    pub fn build(
        proto: &LuaProto,
        index: u32,
        parent_index: Option<u32>,
        ver: LuaVersion,
        ancestors: &[&LuaProto],
    ) -> Self {
        let metrics = ComplexityMetrics::compute(proto, ver);
        let patterns = detect_patterns(proto, ver);
        let upvalue_chains = UpvalueChain::build_for_proto(proto, ancestors);
        let is_recursive = patterns.contains(&ProtoPattern::Recursive);

        let child_count = proto.protos.len() as u32;
        let child_indices: Vec<u32> = (0..child_count).map(|i| index + 1 + i).collect();

        let string_consts: Vec<String> =
            proto.constants.iter().filter_map(|c| c.as_str().map(str::to_owned)).collect();

        let numeric_consts: Vec<f64> = proto
            .constants
            .iter()
            .filter_map(|c| match c {
                LuaConstant::Float(f) => Some(*f),
                LuaConstant::Integer(i) => Some(*i as f64),
                _ => None,
            })
            .collect();

        ProtoAnalysis {
            index,
            source_name: proto.source_name.clone(),
            line_range: (proto.line_defined, proto.last_line_defined),
            num_params: proto.num_params,
            is_vararg: proto.is_vararg,
            metrics,
            patterns,
            upvalue_chains,
            parent_index,
            child_indices,
            is_recursive,
            string_consts,
            numeric_consts,
        }
    }

    /// Returns `true` if the proto matches the given pattern.
    pub fn has_pattern(&self, p: &ProtoPattern) -> bool {
        self.patterns.contains(p)
    }

    /// Estimated complexity category.
    pub fn complexity_category(&self) -> &'static str {
        match self.metrics.cyclomatic {
            0..=3 => "simple",
            4..=7 => "moderate",
            8..=15 => "complex",
            _ => "very_complex",
        }
    }
}

impl fmt::Display for ProtoAnalysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProtoAnalysis[{}] {}:{}-{} {} patterns={} upvalues={}",
            self.index,
            self.source_name,
            self.line_range.0,
            self.line_range.1,
            self.complexity_category(),
            self.patterns.len(),
            self.upvalue_chains.len()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern detection
// ─────────────────────────────────────────────────────────────────────────────

/// Detect patterns in `proto` by scanning its instruction stream.
fn detect_patterns(proto: &LuaProto, ver: LuaVersion) -> Vec<ProtoPattern> {
    let mut found: HashSet<ProtoPattern> = HashSet::new();

    let has_newtable = proto.instructions.iter().enumerate().any(|(i, _)| {
        let op = proto.opcode_at(i, ver);
        is_newtable_op(op, ver)
    });
    let has_setlist = proto.instructions.iter().enumerate().any(|(i, _)| {
        let op = proto.opcode_at(i, ver);
        is_setlist_op(op, ver)
    });

    if has_newtable && has_setlist {
        found.insert(ProtoPattern::TableConstructor);
    }

    let mut has_tailcall = false;
    let mut has_numfor = false;
    let mut has_genfor = false;

    for i in 0..proto.insn_count() {
        let op = proto.opcode_at(i, ver);

        if is_tailcall_op(op, ver) {
            has_tailcall = true;
        }
        if is_numfor_op(op, ver) {
            has_numfor = true;
        }
        if is_genfor_op(op, ver) {
            has_genfor = true;
        }
    }

    if has_tailcall {
        found.insert(ProtoPattern::TailCall);
    }
    if has_numfor {
        found.insert(ProtoPattern::NumericFor);
    }
    if has_genfor {
        found.insert(ProtoPattern::GenericFor);
    }

    // Simple getter: ≤ 3 instructions.
    if proto.insn_count() <= 3 && !found.contains(&ProtoPattern::TableConstructor) {
        found.insert(ProtoPattern::SimpleGetter);
    }

    // Check string constants for metatable hints.
    let consts: Vec<&str> = proto.constants.iter().filter_map(|c| c.as_str()).collect();
    if consts.iter().any(|s| *s == "__index") {
        found.insert(ProtoPattern::Metatable);
    }
    if consts.iter().any(|s| *s == "setmetatable") {
        found.insert(ProtoPattern::SetMetatable);
    }
    if consts.iter().any(|s| *s == "new") && found.contains(&ProtoPattern::Metatable) {
        found.insert(ProtoPattern::ClassConstructor);
    }

    found.into_iter().collect()
}

fn is_newtable_op(op: u8, ver: LuaVersion) -> bool {
    match ver {
        LuaVersion::Lua51 | LuaVersion::Lua52 => op == 10,
        LuaVersion::Lua53 => op == 11,
        LuaVersion::Lua54 => op == 12,
    }
}

fn is_setlist_op(op: u8, ver: LuaVersion) -> bool {
    match ver {
        LuaVersion::Lua51 | LuaVersion::Lua52 => op == 34,
        LuaVersion::Lua53 => op == 38,
        LuaVersion::Lua54 => op == 48,
    }
}

fn is_tailcall_op(op: u8, ver: LuaVersion) -> bool {
    match ver {
        LuaVersion::Lua51 => op == 29,
        LuaVersion::Lua52 | LuaVersion::Lua53 => op == 30,
        LuaVersion::Lua54 => op == 66,
    }
}

fn is_numfor_op(op: u8, ver: LuaVersion) -> bool {
    match ver {
        LuaVersion::Lua51 => op == 31,
        LuaVersion::Lua52 => op == 32,
        LuaVersion::Lua53 => op == 33,
        LuaVersion::Lua54 => op == 69,
    }
}

fn is_genfor_op(op: u8, ver: LuaVersion) -> bool {
    match ver {
        LuaVersion::Lua51 => op == 33,
        LuaVersion::Lua52 => op == 34,
        LuaVersion::Lua53 => op == 35,
        LuaVersion::Lua54 => op == 71,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaProtoAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// Orchestrates analysis of all prototypes in a Lua chunk.
pub struct LuaProtoAnalyzer {
    /// Lua version to use for opcode classification.
    pub version: LuaVersion,
    /// Analysis results keyed by proto index.
    pub analyses: HashMap<u32, ProtoAnalysis>,
    /// Call graph between protos.
    pub call_graph: ProtoCallGraph,
}

impl LuaProtoAnalyzer {
    /// Create a new analyzer for the given Lua version.
    pub fn new(version: LuaVersion) -> Self {
        LuaProtoAnalyzer {
            version,
            analyses: HashMap::new(),
            call_graph: ProtoCallGraph::new(),
        }
    }

    /// Analyse the full proto tree starting at `root`, assigning sequential
    /// depth-first pre-order indices.
    pub fn analyze_tree(&mut self, root: &LuaProto) {
        let mut index_counter = 0u32;
        self.analyze_recursive(root, &mut index_counter, None, &mut Vec::new());
        self.build_call_graph(root, 0);
    }

    fn analyze_recursive<'a>(
        &mut self,
        proto: &'a LuaProto,
        counter: &mut u32,
        parent: Option<u32>,
        ancestors: &mut Vec<&'a LuaProto>,
    ) {
        let my_index = *counter;
        *counter += 1;

        let analysis = ProtoAnalysis::build(proto, my_index, parent, self.version, ancestors);
        self.analyses.insert(my_index, analysis);

        ancestors.push(proto);
        for child in &proto.protos {
            self.analyze_recursive(child, counter, Some(my_index), ancestors);
        }
        ancestors.pop();
    }

    /// Build the call graph by walking the proto tree.
    ///
    /// A CLOSURE instruction in proto P at depth D creates child proto (P+offset);
    /// here we approximate edges from the parent to each nested proto.
    fn build_call_graph(&mut self, root: &LuaProto, parent_idx: u32) {
        for (i, child) in root.protos.iter().enumerate() {
            let child_idx = parent_idx + 1 + i as u32;
            self.call_graph.add_edge(parent_idx, child_idx, false);
            self.build_call_graph(child, child_idx);
        }
    }

    /// Returns a reference to the analysis for the root proto.
    pub fn root_analysis(&self) -> Option<&ProtoAnalysis> {
        self.analyses.get(&0)
    }

    /// Returns all analyses sorted by index.
    pub fn sorted_analyses(&self) -> Vec<&ProtoAnalysis> {
        let mut v: Vec<&ProtoAnalysis> = self.analyses.values().collect();
        v.sort_by_key(|a| a.index);
        v
    }

    /// Count protos with a given pattern.
    pub fn count_with_pattern(&self, p: &ProtoPattern) -> usize {
        self.analyses.values().filter(|a| a.has_pattern(p)).count()
    }

    /// Return analyses for protos categorised as "complex" or above.
    pub fn complex_protos(&self) -> Vec<&ProtoAnalysis> {
        self.analyses
            .values()
            .filter(|a| matches!(a.complexity_category(), "complex" | "very_complex"))
            .collect()
    }

    /// Total number of protos analysed.
    pub fn total_protos(&self) -> usize {
        self.analyses.len()
    }

    /// Average cyclomatic complexity across all protos.
    pub fn average_cyclomatic(&self) -> f64 {
        if self.analyses.is_empty() {
            return 0.0;
        }
        let sum: u32 = self.analyses.values().map(|a| a.metrics.cyclomatic).sum();
        sum as f64 / self.analyses.len() as f64
    }

    /// Collect all unique string constants across all protos.
    pub fn all_strings(&self) -> Vec<&str> {
        let mut seen: HashSet<&str> = HashSet::new();
        let mut result = Vec::new();
        for a in self.analyses.values() {
            for s in &a.string_consts {
                if seen.insert(s.as_str()) {
                    result.push(s.as_str());
                }
            }
        }
        result
    }
}

impl fmt::Display for LuaProtoAnalyzer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LuaProtoAnalyzer [protos={} avg_cyclo={:.2} edges={}]",
            self.total_protos(),
            self.average_cyclomatic(),
            self.call_graph.edge_count()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lua_bytecode_parser::LuaProto;

    fn empty_proto() -> LuaProto {
        LuaProto::empty()
    }

    fn proto_with_insns(insns: Vec<u32>) -> LuaProto {
        let mut p = LuaProto::empty();
        p.instructions = insns;
        p.line_defined = 1;
        p.last_line_defined = 10;
        p
    }

    #[test]
    fn test_complexity_empty_proto() {
        let p = empty_proto();
        let m = ComplexityMetrics::compute(&p, LuaVersion::Lua51);
        assert_eq!(m.insn_count, 0);
        assert_eq!(m.cyclomatic, 1); // min cyclomatic is 1
    }

    #[test]
    fn test_complexity_with_branches() {
        // Opcode 22 (JMP) for Lua 5.1.
        let insns = vec![22u32, 22u32, 28u32]; // 2 JMPs + 1 CALL
        let p = proto_with_insns(insns);
        let m = ComplexityMetrics::compute(&p, LuaVersion::Lua51);
        assert_eq!(m.branch_count, 2);
        assert_eq!(m.call_count, 1);
        assert_eq!(m.cyclomatic, 3);
    }

    #[test]
    fn test_pattern_simple_getter() {
        let p = proto_with_insns(vec![0u32, 30u32]); // MOVE + RETURN
        let patterns = detect_patterns(&p, LuaVersion::Lua51);
        assert!(patterns.contains(&ProtoPattern::SimpleGetter));
    }

    #[test]
    fn test_pattern_metatable() {
        let mut p = empty_proto();
        p.constants.push(LuaConstant::String("__index".into()));
        let patterns = detect_patterns(&p, LuaVersion::Lua53);
        assert!(patterns.contains(&ProtoPattern::Metatable));
    }

    #[test]
    fn test_pattern_table_constructor() {
        // Lua 5.1: NEWTABLE=10, SETLIST=34
        let p = proto_with_insns(vec![10u32, 34u32]);
        let patterns = detect_patterns(&p, LuaVersion::Lua51);
        assert!(patterns.contains(&ProtoPattern::TableConstructor));
    }

    #[test]
    fn test_proto_call_graph_edge() {
        let mut cg = ProtoCallGraph::new();
        cg.add_edge(0, 1, false);
        cg.add_edge(0, 1, false);
        assert_eq!(cg.edges[0].site_count, 2);
    }

    #[test]
    fn test_reachable_from() {
        let mut cg = ProtoCallGraph::new();
        cg.add_edge(0, 1, false);
        cg.add_edge(1, 2, false);
        let reachable = cg.reachable_from(0);
        assert!(reachable.contains(&2));
    }

    #[test]
    fn test_upvalue_chain_in_stack() {
        let uv = UpvalueDesc::simple(1, 2);
        let chain = UpvalueChain::trace(&uv, &[]);
        assert!(chain.resolved);
        assert_eq!(chain.depth(), 1);
    }

    #[test]
    fn test_analyzer_single_proto() {
        let mut p = empty_proto();
        p.line_defined = 1;
        p.last_line_defined = 5;
        let mut analyzer = LuaProtoAnalyzer::new(LuaVersion::Lua51);
        analyzer.analyze_tree(&p);
        assert_eq!(analyzer.total_protos(), 1);
        assert!(analyzer.root_analysis().is_some());
    }

    #[test]
    fn test_analyzer_nested_protos() {
        let mut root = empty_proto();
        let child = empty_proto();
        root.protos.push(child);
        let mut analyzer = LuaProtoAnalyzer::new(LuaVersion::Lua53);
        analyzer.analyze_tree(&root);
        assert_eq!(analyzer.total_protos(), 2);
        assert_eq!(analyzer.call_graph.edge_count(), 1);
    }

    #[test]
    fn test_complexity_category() {
        let mut a = ProtoAnalysis::build(&empty_proto(), 0, None, LuaVersion::Lua51, &[]);
        a.metrics.cyclomatic = 2;
        assert_eq!(a.complexity_category(), "simple");
        a.metrics.cyclomatic = 10;
        assert_eq!(a.complexity_category(), "complex");
    }
}
