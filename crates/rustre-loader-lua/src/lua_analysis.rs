//! `lua_analysis` — Semantic analysis of Lua bytecode.
//!
//! Provides:
//! - `LuaAnalysis`: top-level façade coordinating all passes.
//! - `LuaUpvalueAnalysis`: tracks upvalue capture chains.
//! - `GlobalAccess`: identifies reads and writes to global variables.
//! - `TableSchema`: infers the schema of a Lua table from its field accesses.
//! - `LuaCallGraph`: builds a function-level call graph.
//! - `ClosureTree`: builds the closure / function nesting tree.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Common types
// ─────────────────────────────────────────────────────────────────────────────

/// Index of a function within a Lua chunk.
pub type FuncIdx = u32;

/// Index of a local variable / register within a function.
pub type LocalIdx = u16;

/// Index of an upvalue descriptor.
pub type UpvalIdx = u8;

// ─────────────────────────────────────────────────────────────────────────────
// LuaFunctionInfo — minimal IR of one Lua function
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal representation of a single Lua function used by the analysers.
#[derive(Debug, Clone, Default)]
pub struct LuaFunctionInfo {
    /// Function index in the chunk.
    pub index: FuncIdx,
    /// Name (debug info), if available.
    pub name: Option<String>,
    /// Number of parameters (fixed arity).
    pub num_params: u8,
    /// Whether this function accepts variable arguments.
    pub is_vararg: bool,
    /// Number of upvalues captured.
    pub num_upvalues: u8,
    /// Upvalue descriptors.
    pub upvalues: Vec<UpvalueDesc>,
    /// Names of local variables (debug info).
    pub locals: Vec<String>,
    /// Instructions (simplified: just opcode + operand A/B/C/Bx).
    pub instructions: Vec<LuaInstr>,
    /// Constants table (strings and numbers).
    pub constants: Vec<LuaConst>,
    /// Indices of nested function prototypes.
    pub nested: Vec<FuncIdx>,
    /// Index of parent function (`None` for top-level chunk).
    pub parent: Option<FuncIdx>,
}

/// A simplified Lua instruction (Lua 5.x format).
#[derive(Debug, Clone, Copy)]
pub struct LuaInstr {
    /// Opcode number.
    pub opcode: u8,
    /// Register A.
    pub a: u8,
    /// Register B (or high half of Bx).
    pub b: u16,
    /// Register C (or low half of Bx for sBx).
    pub c: u16,
}

impl LuaInstr {
    /// Bx = (B << 9) | C
    #[must_use]
    pub const fn bx(&self) -> u32 {
        (self.b as u32) << 9 | self.c as u32
    }

    /// `sBx` = `Bx` - (`MAXARG_Bx` >> 1)
    #[must_use]
    pub const fn sbx(&self) -> i32 {
        let bx = self.bx();
        bx.cast_signed() - ((1 << 17) - 1)
    }
}

/// A constant value in a Lua function's constant table.
#[derive(Debug, Clone)]
pub enum LuaConst {
    Nil,
    Boolean(bool),
    Integer(i64),
    Float(f64),
    String(String),
}

impl fmt::Display for LuaConst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nil => write!(f, "nil"),
            Self::Boolean(b) => write!(f, "{b}"),
            Self::Integer(n) => write!(f, "{n}"),
            Self::Float(x) => write!(f, "{x}"),
            Self::String(s) => write!(f, "\"{s}\""),
        }
    }
}

/// An upvalue descriptor.
#[derive(Debug, Clone)]
pub struct UpvalueDesc {
    /// Whether the upvalue is captured from an enclosing function's stack.
    pub in_stack: bool,
    /// Stack index (if `in_stack`) or upvalue index in the enclosing function.
    pub idx: u8,
    /// Debug name, if available.
    pub name: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaUpvalueAnalysis
// ─────────────────────────────────────────────────────────────────────────────

/// Analyses upvalue capture chains across all functions in a chunk.
#[derive(Debug, Default)]
pub struct LuaUpvalueAnalysis {
    /// Map from function index → list of upvalue descriptions with resolved names.
    pub upvalue_chains: HashMap<FuncIdx, Vec<ResolvedUpvalue>>,
}

/// An upvalue with the enclosing function and capture type.
#[derive(Debug, Clone)]
pub struct ResolvedUpvalue {
    /// Name of the upvalue.
    pub name: String,
    /// Function index that originally declared this as a local.
    pub origin_func: FuncIdx,
    /// Whether it was captured from the stack (open upvalue) or from
    /// another upvalue (closed).
    pub captured_from_stack: bool,
}

impl LuaUpvalueAnalysis {
    /// Create a new analyser.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run upvalue analysis over all functions in `functions`.
    pub fn analyse(&mut self, functions: &[LuaFunctionInfo]) {
        for func in functions {
            let resolved: Vec<ResolvedUpvalue> = func
                .upvalues
                .iter()
                .map(|uv| {
                    let name = uv
                        .name
                        .clone()
                        .unwrap_or_else(|| format!("upval@{}", uv.idx));
                    let origin = if uv.in_stack {
                        func.parent.unwrap_or(func.index)
                    } else {
                        func.parent.unwrap_or(0)
                    };
                    ResolvedUpvalue {
                        name,
                        origin_func: origin,
                        captured_from_stack: uv.in_stack,
                    }
                })
                .collect();
            self.upvalue_chains.insert(func.index, resolved);
        }
    }

    /// Return all upvalue names captured by function `func_idx`.
    #[must_use]
    pub fn upvalues_for(&self, func_idx: FuncIdx) -> Vec<&str> {
        self.upvalue_chains
            .get(&func_idx)
            .map(|uvs| uvs.iter().map(|u| u.name.as_str()).collect())
            .unwrap_or_default()
    }

    /// Return `true` if `func_idx` captures `_ENV` as an upvalue.
    #[must_use]
    pub fn captures_env(&self, func_idx: FuncIdx) -> bool {
        self.upvalues_for(func_idx).contains(&"_ENV")
    }

    /// Count total upvalue references across all functions.
    #[must_use]
    pub fn total_upvalue_refs(&self) -> usize {
        self.upvalue_chains.values().map(Vec::len).sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GlobalAccess
// ─────────────────────────────────────────────────────────────────────────────

/// Kind of global access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    Read,
    Write,
}

impl fmt::Display for AccessKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => write!(f, "READ"),
            Self::Write => write!(f, "WRITE"),
        }
    }
}

/// A single access to a global variable.
#[derive(Debug, Clone)]
pub struct GlobalAccessEntry {
    /// Name of the global.
    pub name: String,
    /// Whether this is a read or write.
    pub kind: AccessKind,
    /// Function index where the access occurs.
    pub func_index: FuncIdx,
    /// Instruction index within that function.
    pub instr_index: usize,
}

/// Collects and analyses all accesses to global variables.
#[derive(Debug, Default)]
pub struct GlobalAccess {
    pub entries: Vec<GlobalAccessEntry>,
}

impl GlobalAccess {
    /// Create a new tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan a function for GETGLOBAL/SETGLOBAL (Lua 5.1) or GETTABUP/SETTABUP
    /// (_ENV lookups in Lua 5.2+) patterns.
    ///
    /// Opcodes used (Lua 5.1 bytecode numbers):
    /// - 5: GETGLOBAL  A Bx → R(A) := Gbl[Kst(Bx)]
    /// - 7: SETGLOBAL  A Bx → Gbl[Kst(Bx)] := R(A)
    pub fn scan(&mut self, func: &LuaFunctionInfo) {
        for (instr_index, instr) in func.instructions.iter().enumerate() {
            match instr.opcode {
                // Lua 5.1: GETGLOBAL = 5, SETGLOBAL = 7
                5 => {
                    let name = func
                        .constants
                        .get(instr.bx() as usize)
                        .and_then(|c| {
                            if let LuaConst::String(s) = c {
                                Some(s.clone())
                            } else {
                                None
                            }
                        })
                        .unwrap_or_else(|| format!("Kst({})", instr.bx()));
                    self.entries.push(GlobalAccessEntry {
                        name,
                        kind: AccessKind::Read,
                        func_index: func.index,
                        instr_index,
                    });
                }
                7 => {
                    let name = func
                        .constants
                        .get(instr.bx() as usize)
                        .and_then(|c| {
                            if let LuaConst::String(s) = c {
                                Some(s.clone())
                            } else {
                                None
                            }
                        })
                        .unwrap_or_else(|| format!("Kst({})", instr.bx()));
                    self.entries.push(GlobalAccessEntry {
                        name,
                        kind: AccessKind::Write,
                        func_index: func.index,
                        instr_index,
                    });
                }
                _ => {}
            }
        }
    }

    /// Return all accesses to global `name`.
    #[must_use]
    pub fn accesses_to(&self, name: &str) -> Vec<&GlobalAccessEntry> {
        self.entries.iter().filter(|e| e.name == name).collect()
    }

    /// Return all globally-read names.
    #[must_use]
    pub fn read_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self
            .entries
            .iter()
            .filter(|e| e.kind == AccessKind::Read)
            .map(|e| e.name.as_str())
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    }

    /// Return all globally-written names.
    #[must_use]
    pub fn written_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self
            .entries
            .iter()
            .filter(|e| e.kind == AccessKind::Write)
            .map(|e| e.name.as_str())
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    }

    /// Return `true` if global `name` is ever written.
    #[must_use]
    pub fn is_written(&self, name: &str) -> bool {
        self.entries
            .iter()
            .any(|e| e.name == name && e.kind == AccessKind::Write)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TableSchema
// ─────────────────────────────────────────────────────────────────────────────

/// The inferred value type of a table field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValueType {
    Unknown,
    Number,
    String,
    Boolean,
    Table,
    Function,
    Mixed,
}

impl fmt::Display for FieldValueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::Number => write!(f, "number"),
            Self::String => write!(f, "string"),
            Self::Boolean => write!(f, "boolean"),
            Self::Table => write!(f, "table"),
            Self::Function => write!(f, "function"),
            Self::Mixed => write!(f, "mixed"),
        }
    }
}

/// Inferred schema for a Lua table (string-keyed fields only).
#[derive(Debug, Clone, Default)]
pub struct TableSchema {
    /// Table variable name or description.
    pub name: String,
    /// Field name → inferred value type.
    pub fields: HashMap<String, FieldValueType>,
    /// Fields that are read but never set.
    pub read_only_fields: HashSet<String>,
    /// Fields that are set but never read.
    pub write_only_fields: HashSet<String>,
}

impl TableSchema {
    /// Create a new schema for a named table.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            fields: HashMap::new(),
            read_only_fields: HashSet::new(),
            write_only_fields: HashSet::new(),
        }
    }

    /// Record a write to `field` with an inferred value type.
    pub fn record_set(&mut self, field: &str, ty: FieldValueType) {
        let entry = self
            .fields
            .entry(field.to_string())
            .or_insert(FieldValueType::Unknown);
        if *entry == FieldValueType::Unknown {
            *entry = ty;
        } else if *entry != ty {
            *entry = FieldValueType::Mixed;
        }
        self.write_only_fields.insert(field.to_string());
        self.read_only_fields.remove(field);
    }

    /// Record a read of `field`.
    pub fn record_get(&mut self, field: &str) {
        self.fields
            .entry(field.to_string())
            .or_insert(FieldValueType::Unknown);
        self.read_only_fields.insert(field.to_string());
        self.write_only_fields.remove(field);
    }

    /// Return `true` if `field` is a known field of this table.
    #[must_use]
    pub fn has_field(&self, field: &str) -> bool {
        self.fields.contains_key(field)
    }

    /// Return the inferred type of `field`, or `Unknown`.
    #[must_use]
    pub fn field_type(&self, field: &str) -> FieldValueType {
        self.fields
            .get(field)
            .cloned()
            .unwrap_or(FieldValueType::Unknown)
    }

    /// Total number of known fields.
    #[must_use]
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }
}

impl fmt::Display for TableSchema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "table {} {{ ", self.name)?;
        let mut fields: Vec<_> = self.fields.iter().collect();
        fields.sort_by_key(|(k, _)| k.as_str());
        for (i, (k, v)) in fields.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{k}: {v}")?;
        }
        write!(f, " }}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaCallGraph
// ─────────────────────────────────────────────────────────────────────────────

/// A directed edge in the call graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallEdge {
    /// Caller function index.
    pub caller: FuncIdx,
    /// Callee function index (or `0xFFFF_FFFF` for external/dynamic calls).
    pub callee: FuncIdx,
    /// Instruction index where the call occurs.
    pub instr_index: usize,
}

/// The function-level call graph of a Lua chunk.
#[derive(Debug, Default)]
pub struct LuaCallGraph {
    /// All call edges.
    pub edges: Vec<CallEdge>,
    /// Adjacency list: caller → set of callees.
    adjacency: HashMap<FuncIdx, HashSet<FuncIdx>>,
}

impl LuaCallGraph {
    /// Create a new call graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a call edge.
    pub fn add_edge(&mut self, caller: FuncIdx, callee_fn: FuncIdx, instr_index: usize) {
        self.edges.push(CallEdge {
            caller,
            callee: callee_fn,
            instr_index,
        });
        self.adjacency.entry(caller).or_default().insert(callee_fn);
    }

    /// Build a call graph from a slice of function prototypes.
    ///
    /// Lua 5.1 opcode 28 = CALL, opcode 29 = TAILCALL.
    /// We detect calls to nested closures via CLOSURE (opcode 36).
    pub fn build(&mut self, functions: &[LuaFunctionInfo]) {
        for func in functions {
            for (instr_index, instr) in func.instructions.iter().enumerate() {
                match instr.opcode {
                    28 | 29 => {
                        // CALL / TAILCALL — dynamic call, callee unknown
                        self.add_edge(func.index, u32::MAX, instr_index);
                    }
                    36 => {
                        // CLOSURE Bx — creates closure of proto[Bx]
                        let nested_idx = instr.bx();
                        if let Some(callee) = func.nested.get(nested_idx as usize) {
                            self.add_edge(func.index, *callee, instr_index);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Return all direct callees of `func_idx`.
    #[must_use]
    pub fn callees(&self, func_idx: FuncIdx) -> Vec<FuncIdx> {
        self.adjacency
            .get(&func_idx)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Return all functions that call `func_idx`.
    #[must_use]
    pub fn callers(&self, func_idx: FuncIdx) -> Vec<FuncIdx> {
        self.edges
            .iter()
            .filter(|e| e.callee == func_idx)
            .map(|e| e.caller)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect()
    }

    /// Return the number of distinct functions with at least one outgoing call.
    #[must_use]
    pub fn active_callers(&self) -> usize {
        self.adjacency.len()
    }

    /// BFS: return all functions reachable from `start`.
    #[must_use]
    pub fn reachable_from(&self, start: FuncIdx) -> Vec<FuncIdx> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start);
        while let Some(f) = queue.pop_front() {
            if visited.insert(f) && let Some(callees) = self.adjacency.get(&f) {
                for &c in callees {
                    if !visited.contains(&c) {
                        queue.push_back(c);
                    }
                }
            }
        }
        visited.remove(&start);
        visited.into_iter().collect()
    }

    /// Return `true` if there is any (direct or indirect) call from `from` to `to`.
    #[must_use]
    pub fn is_reachable(&self, from: FuncIdx, to: FuncIdx) -> bool {
        self.reachable_from(from).contains(&to)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ClosureTree
// ─────────────────────────────────────────────────────────────────────────────

/// A node in the closure / function nesting tree.
#[derive(Debug, Clone)]
pub struct ClosureNode {
    /// Function index.
    pub func_index: FuncIdx,
    /// Display name.
    pub name: String,
    /// Parent function index (`None` for the top-level chunk).
    pub parent: Option<FuncIdx>,
    /// Children (directly nested closures).
    pub children: Vec<FuncIdx>,
    /// Nesting depth (0 = top-level).
    pub depth: usize,
}

/// The complete closure nesting tree of a Lua chunk.
#[derive(Debug, Default)]
pub struct ClosureTree {
    pub nodes: HashMap<FuncIdx, ClosureNode>,
}

impl ClosureTree {
    /// Create a new empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the tree from a slice of `LuaFunctionInfo`.
    pub fn build(&mut self, functions: &[LuaFunctionInfo]) {
        // First pass: create all nodes.
        for func in functions {
            let name = func
                .name
                .clone()
                .unwrap_or_else(|| format!("func#{}", func.index));
            let parent = func.parent;
            self.nodes.insert(
                func.index,
                ClosureNode {
                    func_index: func.index,
                    name,
                    parent,
                    children: func.nested.clone(),
                    depth: 0,
                },
            );
        }
        // Second pass: compute depths.
        let indices: Vec<FuncIdx> = self.nodes.keys().copied().collect();
        for idx in indices {
            let depth = self.compute_depth(idx);
            if let Some(node) = self.nodes.get_mut(&idx) {
                node.depth = depth;
            }
        }
    }

    fn compute_depth(&self, mut idx: FuncIdx) -> usize {
        let mut depth = 0;
        for _ in 0..1000 {
            if let Some(node) = self.nodes.get(&idx) {
                if let Some(parent) = node.parent {
                    depth += 1;
                    idx = parent;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        depth
    }

    /// Return the maximum nesting depth in the tree.
    #[must_use]
    pub fn max_depth(&self) -> usize {
        self.nodes.values().map(|n| n.depth).max().unwrap_or(0)
    }

    /// Return all functions at depth `d`.
    #[must_use]
    pub fn at_depth(&self, d: usize) -> Vec<&ClosureNode> {
        self.nodes.values().filter(|n| n.depth == d).collect()
    }

    /// Return the children of `func_idx`.
    #[must_use]
    pub fn children_of(&self, func_idx: FuncIdx) -> Vec<&ClosureNode> {
        self.nodes.get(&func_idx).map_or_else(Vec::new, |node| {
            node.children
                .iter()
                .filter_map(|c| self.nodes.get(c))
                .collect()
        })
    }

    /// Return `true` if `func_idx` is a leaf (has no nested closures).
    #[must_use]
    pub fn is_leaf(&self, func_idx: FuncIdx) -> bool {
        self.nodes
            .get(&func_idx)
            .is_none_or(|n| n.children.is_empty())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaAnalysis — top-level façade
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level analysis state for a compiled Lua chunk.
#[derive(Debug, Default)]
pub struct LuaAnalysis {
    pub upvalues: LuaUpvalueAnalysis,
    pub globals: GlobalAccess,
    pub call_graph: LuaCallGraph,
    pub closure_tree: ClosureTree,
    /// Inferred table schemas keyed by the table variable name.
    pub table_schemas: HashMap<String, TableSchema>,
    /// All functions in the chunk.
    pub functions: Vec<LuaFunctionInfo>,
}

impl LuaAnalysis {
    /// Create a new analysis state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a function prototype to the analysis.
    pub fn add_function(&mut self, func: LuaFunctionInfo) {
        self.functions.push(func);
    }

    /// Run all analysis passes over the loaded functions.
    pub fn run(&mut self) {
        let funcs = self.functions.clone();
        self.upvalues.analyse(&funcs);
        for func in &funcs {
            self.globals.scan(func);
        }
        self.call_graph.build(&funcs);
        self.closure_tree.build(&funcs);
    }

    /// Return the total number of functions (including nested).
    #[must_use]
    pub const fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Return `true` if the chunk uses global variables.
    #[must_use]
    pub const fn uses_globals(&self) -> bool {
        !self.globals.entries.is_empty()
    }

    /// Return all globally-accessed names across all functions.
    #[must_use]
    pub fn all_global_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self
            .globals
            .entries
            .iter()
            .map(|e| e.name.as_str())
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    }

    /// Infer a table schema from explicit field access entries.
    pub fn infer_schema(
        &mut self,
        table_name: &str,
        fields: &[(&str, FieldValueType, AccessKind)],
    ) {
        let schema = self
            .table_schemas
            .entry(table_name.to_string())
            .or_insert_with(|| TableSchema::new(table_name));
        for (field, ty, kind) in fields {
            match kind {
                AccessKind::Read => schema.record_get(field),
                AccessKind::Write => schema.record_set(field, ty.clone()),
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_func(idx: FuncIdx, parent: Option<FuncIdx>) -> LuaFunctionInfo {
        LuaFunctionInfo {
            index: idx,
            name: Some(format!("func{idx}")),
            num_params: 0,
            is_vararg: true,
            num_upvalues: 0,
            upvalues: vec![],
            locals: vec![],
            instructions: vec![],
            constants: vec![],
            nested: vec![],
            parent,
        }
    }

    // ── LuaConst ──────────────────────────────────────────────────────────────

    #[test]
    fn test_lua_const_display_nil() {
        assert_eq!(LuaConst::Nil.to_string(), "nil");
    }

    #[test]
    fn test_lua_const_display_string() {
        assert_eq!(LuaConst::String("hello".into()).to_string(), "\"hello\"");
    }

    #[test]
    fn test_lua_const_display_integer() {
        assert_eq!(LuaConst::Integer(42).to_string(), "42");
    }

    // ── LuaUpvalueAnalysis ────────────────────────────────────────────────────

    #[test]
    fn test_upvalue_analyse_empty() {
        let mut uv = LuaUpvalueAnalysis::new();
        uv.analyse(&[]);
        assert_eq!(uv.total_upvalue_refs(), 0);
    }

    #[test]
    fn test_upvalue_analyse_with_env() {
        let mut func = make_func(0, None);
        func.upvalues.push(UpvalueDesc {
            in_stack: true,
            idx: 0,
            name: Some("_ENV".into()),
        });
        let mut uv = LuaUpvalueAnalysis::new();
        uv.analyse(&[func]);
        assert!(uv.captures_env(0));
    }

    #[test]
    fn test_upvalue_analyse_no_env() {
        let func = make_func(1, None);
        let mut uv = LuaUpvalueAnalysis::new();
        uv.analyse(&[func]);
        assert!(!uv.captures_env(1));
    }

    #[test]
    fn test_upvalue_names_for() {
        let mut func = make_func(2, Some(0));
        func.upvalues.push(UpvalueDesc {
            in_stack: false,
            idx: 0,
            name: Some("x".into()),
        });
        let mut uv = LuaUpvalueAnalysis::new();
        uv.analyse(&[func]);
        assert_eq!(uv.upvalues_for(2), vec!["x"]);
    }

    #[test]
    fn test_upvalue_total_refs() {
        let mut f0 = make_func(0, None);
        f0.upvalues.push(UpvalueDesc {
            in_stack: true,
            idx: 0,
            name: Some("a".into()),
        });
        f0.upvalues.push(UpvalueDesc {
            in_stack: true,
            idx: 1,
            name: Some("b".into()),
        });
        let mut uv = LuaUpvalueAnalysis::new();
        uv.analyse(&[f0]);
        assert_eq!(uv.total_upvalue_refs(), 2);
    }

    // ── GlobalAccess ──────────────────────────────────────────────────────────

    #[test]
    fn test_global_access_getglobal() {
        let mut func = make_func(0, None);
        func.constants.push(LuaConst::String("print".into()));
        func.instructions.push(LuaInstr {
            opcode: 5,
            a: 0,
            b: 0,
            c: 0,
        }); // GETGLOBAL Kst(0)
        let mut ga = GlobalAccess::new();
        ga.scan(&func);
        assert!(ga.read_names().contains(&"print"));
    }

    #[test]
    fn test_global_access_setglobal() {
        let mut func = make_func(0, None);
        func.constants.push(LuaConst::String("myGlobal".into()));
        func.instructions.push(LuaInstr {
            opcode: 7,
            a: 0,
            b: 0,
            c: 0,
        }); // SETGLOBAL Kst(0)
        let mut ga = GlobalAccess::new();
        ga.scan(&func);
        assert!(ga.is_written("myGlobal"));
    }

    #[test]
    fn test_global_access_no_access() {
        let func = make_func(0, None);
        let mut ga = GlobalAccess::new();
        ga.scan(&func);
        assert!(ga.entries.is_empty());
    }

    #[test]
    fn test_global_access_accesses_to() {
        let mut func = make_func(0, None);
        func.constants.push(LuaConst::String("x".into()));
        func.instructions.push(LuaInstr {
            opcode: 5,
            a: 0,
            b: 0,
            c: 0,
        });
        func.instructions.push(LuaInstr {
            opcode: 5,
            a: 1,
            b: 0,
            c: 0,
        });
        let mut ga = GlobalAccess::new();
        ga.scan(&func);
        assert_eq!(ga.accesses_to("x").len(), 2);
    }

    #[test]
    fn test_global_access_written_names() {
        let mut func = make_func(0, None);
        func.constants.push(LuaConst::String("w".into()));
        func.instructions.push(LuaInstr {
            opcode: 7,
            a: 0,
            b: 0,
            c: 0,
        });
        let mut ga = GlobalAccess::new();
        ga.scan(&func);
        assert!(ga.written_names().contains(&"w"));
    }

    // ── TableSchema ───────────────────────────────────────────────────────────

    #[test]
    fn test_table_schema_set_get() {
        let mut ts = TableSchema::new("t");
        ts.record_set("x", FieldValueType::Number);
        ts.record_get("x");
        assert_eq!(ts.field_type("x"), FieldValueType::Number);
        assert!(ts.has_field("x"));
    }

    #[test]
    fn test_table_schema_mixed_type() {
        let mut ts = TableSchema::new("t");
        ts.record_set("y", FieldValueType::Number);
        ts.record_set("y", FieldValueType::String);
        assert_eq!(ts.field_type("y"), FieldValueType::Mixed);
    }

    #[test]
    fn test_table_schema_unknown_field() {
        let ts = TableSchema::new("t");
        assert_eq!(ts.field_type("z"), FieldValueType::Unknown);
        assert!(!ts.has_field("z"));
    }

    #[test]
    fn test_table_schema_field_count() {
        let mut ts = TableSchema::new("t");
        ts.record_set("a", FieldValueType::Number);
        ts.record_set("b", FieldValueType::String);
        assert_eq!(ts.field_count(), 2);
    }

    #[test]
    fn test_table_schema_display() {
        let mut ts = TableSchema::new("obj");
        ts.record_set("n", FieldValueType::Number);
        let s = ts.to_string();
        assert!(s.contains("obj"));
        assert!(s.contains("n: number"));
    }

    // ── LuaCallGraph ──────────────────────────────────────────────────────────

    #[test]
    fn test_call_graph_add_edge() {
        let mut cg = LuaCallGraph::new();
        cg.add_edge(0, 1, 0);
        assert!(cg.callees(0).contains(&1));
    }

    #[test]
    fn test_call_graph_callers() {
        let mut cg = LuaCallGraph::new();
        cg.add_edge(0, 1, 0);
        cg.add_edge(2, 1, 5);
        let callers = cg.callers(1);
        assert!(callers.contains(&0));
        assert!(callers.contains(&2));
    }

    #[test]
    fn test_call_graph_reachable() {
        let mut cg = LuaCallGraph::new();
        cg.add_edge(0, 1, 0);
        cg.add_edge(1, 2, 0);
        assert!(cg.is_reachable(0, 2));
        assert!(!cg.is_reachable(2, 0));
    }

    #[test]
    fn test_call_graph_active_callers() {
        let mut cg = LuaCallGraph::new();
        cg.add_edge(0, 1, 0);
        cg.add_edge(0, 2, 1);
        assert_eq!(cg.active_callers(), 1);
    }

    #[test]
    fn test_call_graph_build_dynamic() {
        let mut func = make_func(0, None);
        func.instructions.push(LuaInstr {
            opcode: 28,
            a: 0,
            b: 1,
            c: 0,
        }); // CALL
        let mut cg = LuaCallGraph::new();
        cg.build(&[func]);
        assert!(cg.callees(0).contains(&u32::MAX));
    }

    // ── ClosureTree ───────────────────────────────────────────────────────────

    #[test]
    fn test_closure_tree_build_depth() {
        let mut f0 = make_func(0, None);
        f0.nested = vec![1];
        let mut f1 = make_func(1, Some(0));
        f1.nested = vec![2];
        let f2 = make_func(2, Some(1));

        let mut tree = ClosureTree::new();
        tree.build(&[f0, f1, f2]);
        assert_eq!(tree.nodes[&0].depth, 0);
        assert_eq!(tree.nodes[&1].depth, 1);
        assert_eq!(tree.nodes[&2].depth, 2);
    }

    #[test]
    fn test_closure_tree_max_depth() {
        let f0 = make_func(0, None);
        let f1 = make_func(1, Some(0));
        let mut tree = ClosureTree::new();
        tree.build(&[f0, f1]);
        assert_eq!(tree.max_depth(), 1);
    }

    #[test]
    fn test_closure_tree_is_leaf() {
        let f0 = make_func(0, None);
        let mut tree = ClosureTree::new();
        tree.build(&[f0]);
        assert!(tree.is_leaf(0));
    }

    #[test]
    fn test_closure_tree_children_of() {
        let mut f0 = make_func(0, None);
        f0.nested = vec![1, 2];
        let f1 = make_func(1, Some(0));
        let f2 = make_func(2, Some(0));
        let mut tree = ClosureTree::new();
        tree.build(&[f0, f1, f2]);
        assert_eq!(tree.children_of(0).len(), 2);
    }

    // ── LuaAnalysis (facade) ──────────────────────────────────────────────────

    #[test]
    fn test_lua_analysis_empty() {
        let la = LuaAnalysis::new();
        assert_eq!(la.function_count(), 0);
        assert!(!la.uses_globals());
    }

    #[test]
    fn test_lua_analysis_run() {
        let mut la = LuaAnalysis::new();
        let f = make_func(0, None);
        la.add_function(f);
        la.run();
        assert_eq!(la.function_count(), 1);
    }

    #[test]
    fn test_lua_analysis_all_global_names() {
        let mut la = LuaAnalysis::new();
        let mut func = make_func(0, None);
        func.constants.push(LuaConst::String("io".into()));
        func.instructions.push(LuaInstr {
            opcode: 5,
            a: 0,
            b: 0,
            c: 0,
        });
        la.add_function(func);
        la.run();
        let names = la.all_global_names();
        assert!(names.contains(&"io"));
    }

    #[test]
    fn test_lua_analysis_infer_schema() {
        let mut la = LuaAnalysis::new();
        la.infer_schema(
            "config",
            &[
                ("host", FieldValueType::String, AccessKind::Write),
                ("port", FieldValueType::Number, AccessKind::Write),
            ],
        );
        let schema = la.table_schemas.get("config").unwrap();
        assert_eq!(schema.field_type("host"), FieldValueType::String);
        assert_eq!(schema.field_count(), 2);
    }

    // ── Additional LuaUpvalueAnalysis tests ───────────────────────────────────

    #[test]
    fn test_upvalue_multiple_functions() {
        let mut f0 = make_func(0, None);
        f0.upvalues.push(UpvalueDesc {
            in_stack: true,
            idx: 0,
            name: Some("x".into()),
        });
        let mut f1 = make_func(1, Some(0));
        f1.upvalues.push(UpvalueDesc {
            in_stack: false,
            idx: 0,
            name: Some("y".into()),
        });
        let mut uv = LuaUpvalueAnalysis::new();
        uv.analyse(&[f0, f1]);
        assert_eq!(uv.total_upvalue_refs(), 2);
    }

    #[test]
    fn test_upvalue_unnamed() {
        let mut func = make_func(3, None);
        func.upvalues.push(UpvalueDesc {
            in_stack: true,
            idx: 2,
            name: None,
        });
        let mut uv = LuaUpvalueAnalysis::new();
        uv.analyse(&[func]);
        let names = uv.upvalues_for(3);
        assert!(!names.is_empty());
        assert!(names[0].contains("upval@"));
    }

    // ── Additional GlobalAccess tests ─────────────────────────────────────────

    #[test]
    fn test_global_read_only_set() {
        let mut func = make_func(0, None);
        func.constants.push(LuaConst::String("require".into()));
        func.instructions.push(LuaInstr {
            opcode: 5,
            a: 0,
            b: 0,
            c: 0,
        });
        let mut ga = GlobalAccess::new();
        ga.scan(&func);
        assert!(!ga.is_written("require"));
        assert!(ga.read_names().contains(&"require"));
    }

    #[test]
    fn test_global_multiple_read_same_name() {
        let mut func = make_func(0, None);
        func.constants.push(LuaConst::String("os".into()));
        func.instructions.push(LuaInstr {
            opcode: 5,
            a: 0,
            b: 0,
            c: 0,
        });
        func.instructions.push(LuaInstr {
            opcode: 5,
            a: 1,
            b: 0,
            c: 0,
        });
        let mut ga = GlobalAccess::new();
        ga.scan(&func);
        
        assert_eq!(ga
            .entries
            .iter()
            .filter(|e| e.kind == AccessKind::Read && e.name == "os").count(), 2);
    }

    // ── Additional ClosureTree tests ──────────────────────────────────────────

    #[test]
    fn test_closure_tree_at_depth() {
        let mut f0 = make_func(0, None);
        f0.nested = vec![1];
        let f1 = make_func(1, Some(0));
        let mut tree = ClosureTree::new();
        tree.build(&[f0, f1]);
        assert_eq!(tree.at_depth(0).len(), 1);
        assert_eq!(tree.at_depth(1).len(), 1);
    }

    #[test]
    fn test_closure_tree_empty() {
        let tree = ClosureTree::new();
        assert_eq!(tree.max_depth(), 0);
        assert!(tree.at_depth(0).is_empty());
    }

    // ── Additional CallGraph tests ─────────────────────────────────────────────

    #[test]
    fn test_call_graph_no_edges() {
        let cg = LuaCallGraph::new();
        assert!(cg.callees(0).is_empty());
        assert!(cg.callers(0).is_empty());
    }

    #[test]
    fn test_call_graph_multiple_edges() {
        let mut cg = LuaCallGraph::new();
        cg.add_edge(0, 1, 0);
        cg.add_edge(0, 2, 1);
        cg.add_edge(0, 3, 2);
        assert_eq!(cg.callees(0).len(), 3);
    }

    // ── LuaAnalysis additional tests ───────────────────────────────────────────

    #[test]
    fn test_lua_analysis_closure_tree_after_run() {
        let mut la = LuaAnalysis::new();
        let mut f0 = make_func(0, None);
        f0.nested = vec![1];
        let f1 = make_func(1, Some(0));
        la.add_function(f0);
        la.add_function(f1);
        la.run();
        assert!(la.closure_tree.nodes.contains_key(&0));
        assert!(la.closure_tree.nodes.contains_key(&1));
    }

    #[test]
    fn test_lua_analysis_table_schema_read_access() {
        let mut la = LuaAnalysis::new();
        la.infer_schema("http", &[("url", FieldValueType::String, AccessKind::Read)]);
        let schema = la.table_schemas.get("http").unwrap();
        assert!(schema.has_field("url"));
    }
}
