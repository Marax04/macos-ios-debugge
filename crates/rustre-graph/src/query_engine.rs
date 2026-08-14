// query_engine.rs — Advanced knowledge graph query engine
// Part of rustre-graph crate.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

// ── Domain types (self-contained; wired to actual graph types in integration) ─

/// Address of a function or symbol in the binary.
pub type Addr = u64;

/// Calling convention tag.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallingConvention {
    Cdecl,
    Stdcall,
    Fastcall,
    Thiscall,
    Vectorcall,
    Win64,
    SysV64,
    Unknown,
    Custom(String),
}

/// Cross-reference kind.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum XrefKind {
    Call,
    Jump,
    DataRead,
    DataWrite,
    DataRef,
    TypeUse,
    Unknown,
}

/// Source of a symbol (how it was discovered).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolSource {
    Import,
    Export,
    DebugInfo,
    Heuristic,
    UserDefined,
    Dwarf,
    Pdb,
    Unknown,
}

/// Symbol kind.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolKind {
    Function,
    Data,
    Label,
    Import,
    Export,
    Thunk,
    Unknown,
}

/// String encoding.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StringEncoding {
    Ascii,
    Utf8,
    Utf16Le,
    Utf16Be,
    Latin1,
    Unknown,
}

// ── Graph node types ─────────────────────────────────────────────────────────

/// A function node in the knowledge graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionNode {
    pub address: Addr,
    pub name: String,
    pub size: u64,
    pub calling_conv: CallingConvention,
    pub has_loop: bool,
    pub complexity: u32,  // cyclomatic complexity
    pub calls: Vec<Addr>, // addresses this function calls
    pub called_by: Vec<Addr>,
    pub module: String,
    pub is_noreturn: bool,
    pub is_thunk: bool,
    pub tags: Vec<String>,
    pub comment: Option<String>,
    pub type_id: Option<u32>,
}

impl FunctionNode {
    #[must_use]
    pub const fn calls_count(&self) -> usize {
        self.calls.len()
    }

    #[must_use]
    pub const fn callers_count(&self) -> usize {
        self.called_by.len()
    }
}

/// A cross-reference edge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrefEdge {
    pub from_addr: Addr,
    pub to_addr: Addr,
    pub kind: XrefKind,
    pub from_module: String,
    pub to_module: String,
    pub from_func: Option<Addr>,
    pub to_func: Option<Addr>,
    pub offset_in_func: Option<u64>,
}

/// A symbol node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolNode {
    pub address: Addr,
    pub name: String,
    pub demangled_name: Option<String>,
    pub kind: SymbolKind,
    pub source: SymbolSource,
    pub module: String,
    pub size: u64,
    pub type_id: Option<u32>,
}

/// A type node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeNode {
    pub type_id: u32,
    pub name: String,
    pub size: u64,
    pub fields: Vec<TypeField>,
    pub is_pointer: bool,
    pub pointee_type_id: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeField {
    pub name: String,
    pub type_id: u32,
    pub offset: u64,
}

/// A string literal found in the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringNode {
    pub address: Addr,
    pub value: String,
    pub encoding: StringEncoding,
    pub referenced_by: Vec<Addr>,
    pub length: usize,
}

// ── The graph store ──────────────────────────────────────────────────────────

/// The in-memory knowledge graph that the query engine operates against.
pub struct KnowledgeGraph {
    pub functions: RwLock<HashMap<Addr, FunctionNode>>,
    pub xrefs: RwLock<Vec<XrefEdge>>,
    pub symbols: RwLock<HashMap<Addr, SymbolNode>>,
    pub types: RwLock<HashMap<u32, TypeNode>>,
    pub strings: RwLock<HashMap<Addr, StringNode>>,
}

impl KnowledgeGraph {
    #[must_use]
    pub fn new() -> Self {
        Self {
            functions: RwLock::new(HashMap::default()),
            xrefs: RwLock::new(Vec::new()),
            symbols: RwLock::new(HashMap::default()),
            types: RwLock::new(HashMap::default()),
            strings: RwLock::new(HashMap::default()),
        }
    }
 /// # Panics
 ///
 /// Panics if the internal lock is poisoned.
    pub fn add_function(&self, f: FunctionNode) {
        self.functions.write().unwrap().insert(f.address, f);
    }
 /// # Panics
 ///
 /// Panics if the internal lock is poisoned.
    pub fn add_xref(&self, x: XrefEdge) {
        self.xrefs.write().unwrap().push(x);
    }
 /// # Panics
 ///
 /// Panics if the internal lock is poisoned.
    pub fn add_symbol(&self, s: SymbolNode) {
        self.symbols.write().unwrap().insert(s.address, s);
    }
 /// # Panics
 ///
 /// Panics if the internal lock is poisoned.
    pub fn add_type(&self, t: TypeNode) {
        self.types.write().unwrap().insert(t.type_id, t);
    }
 /// # Panics
 ///
 /// Panics if the internal lock is poisoned.
    pub fn add_string(&self, s: StringNode) {
        self.strings.write().unwrap().insert(s.address, s);
    }
 /// # Panics
 ///
 /// Panics if the internal lock is poisoned.
    pub fn function_at(&self, addr: Addr) -> Option<FunctionNode> {
        self.functions.read().unwrap().get(&addr).cloned()
    }
}

impl Default for KnowledgeGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ── Query filter types ───────────────────────────────────────────────────────

/// Predicate for filtering function nodes.
#[derive(Debug, Clone, Default)]
pub struct FunctionFilter {
    pub name_contains: Option<String>,
    pub name_exact: Option<String>,
    pub addr_min: Option<Addr>,
    pub addr_max: Option<Addr>,
    pub size_min: Option<u64>,
    pub size_max: Option<u64>,
    pub calling_conv: Option<CallingConvention>,
    pub has_loop: Option<bool>,
    pub complexity_min: Option<u32>,
    pub complexity_max: Option<u32>,
    pub calls_count_min: Option<usize>,
    pub calls_count_max: Option<usize>,
    pub callers_count_min: Option<usize>,
    pub callers_count_max: Option<usize>,
    pub module: Option<String>,
    pub is_noreturn: Option<bool>,
    pub is_thunk: Option<bool>,
    pub has_tag: Option<String>,
    pub calls_function_named: Option<String>,
}

impl FunctionFilter {
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn matches(&self, f: &FunctionNode, graph: &KnowledgeGraph) -> bool {
        if let Some(ref s) = self.name_contains
            && !f.name.to_lowercase().contains(&s.to_lowercase()) {
                return false;
            }
        if let Some(ref s) = self.name_exact
            && f.name != *s {
                return false;
            }
        if let Some(lo) = self.addr_min
            && f.address < lo {
                return false;
            }
        if let Some(hi) = self.addr_max
            && f.address > hi {
                return false;
            }
        if let Some(lo) = self.size_min
            && f.size < lo {
                return false;
            }
        if let Some(hi) = self.size_max
            && f.size > hi {
                return false;
            }
        if let Some(ref cc) = self.calling_conv
            && f.calling_conv != *cc {
                return false;
            }
        if let Some(hl) = self.has_loop
            && f.has_loop != hl {
                return false;
            }
        if let Some(lo) = self.complexity_min
            && f.complexity < lo {
                return false;
            }
        if let Some(hi) = self.complexity_max
            && f.complexity > hi {
                return false;
            }
        if let Some(lo) = self.calls_count_min
            && f.calls_count() < lo {
                return false;
            }
        if let Some(hi) = self.calls_count_max
            && f.calls_count() > hi {
                return false;
            }
        if let Some(lo) = self.callers_count_min
            && f.callers_count() < lo {
                return false;
            }
        if let Some(hi) = self.callers_count_max
            && f.callers_count() > hi {
                return false;
            }
        if let Some(ref m) = self.module
            && &f.module != m {
                return false;
            }
        if let Some(nr) = self.is_noreturn
            && f.is_noreturn != nr {
                return false;
            }
        if let Some(th) = self.is_thunk
            && f.is_thunk != th {
                return false;
            }
        if let Some(ref tag) = self.has_tag
            && !f.tags.contains(tag) {
                return false;
            }
        if let Some(ref target_name) = self.calls_function_named {
            let fns = graph.functions.read().unwrap();
            let calls_target = f.calls.iter().any(|&a| {
                fns.get(&a).is_some_and(|callee| {
                    callee.name.to_lowercase().contains(&target_name.to_lowercase())
                })
            });
            if !calls_target {
                return false;
            }
        }
        true
    }
}

/// Predicate for filtering xref edges.
#[derive(Debug, Clone, Default)]
pub struct XrefFilter {
    pub kind: Option<XrefKind>,
    pub from_func: Option<Addr>,
    pub to_func: Option<Addr>,
    pub from_module: Option<String>,
    pub to_module: Option<String>,
}

impl XrefFilter {
    #[must_use]
    pub fn matches(&self, x: &XrefEdge) -> bool {
        if let Some(ref k) = self.kind
            && x.kind != *k {
                return false;
            }
        if let Some(f) = self.from_func
            && x.from_func != Some(f) {
                return false;
            }
        if let Some(t) = self.to_func
            && x.to_func != Some(t) {
                return false;
            }
        if let Some(ref m) = self.from_module
            && &x.from_module != m {
                return false;
            }
        if let Some(ref m) = self.to_module
            && &x.to_module != m {
                return false;
            }
        true
    }
}

/// Predicate for filtering symbol nodes.
#[derive(Debug, Clone, Default)]
pub struct SymbolFilter {
    pub name_pattern: Option<String>,
    pub kind: Option<SymbolKind>,
    pub source: Option<SymbolSource>,
    pub demangled_contains: Option<String>,
    pub module: Option<String>,
}

impl SymbolFilter {
    #[must_use]
    pub fn matches(&self, s: &SymbolNode) -> bool {
        if let Some(ref p) = self.name_pattern
            && !glob_match(p, &s.name) {
                return false;
            }
        if let Some(ref k) = self.kind
            && s.kind != *k {
                return false;
            }
        if let Some(ref src) = self.source
            && s.source != *src {
                return false;
            }
        if let Some(ref d) = self.demangled_contains {
            let dem = s.demangled_name.as_deref().unwrap_or("");
            if !dem.to_lowercase().contains(&d.to_lowercase()) {
                return false;
            }
        }
        if let Some(ref m) = self.module
            && &s.module != m {
                return false;
            }
        true
    }
}

/// Predicate for filtering type nodes.
#[derive(Debug, Clone, Default)]
pub struct TypeFilter {
    pub name_contains: Option<String>,
    pub size_min: Option<u64>,
    pub size_max: Option<u64>,
    pub field_at_offset: Option<u64>,
    pub is_pointer: Option<bool>,
}

impl TypeFilter {
    #[must_use]
    pub fn matches(&self, t: &TypeNode) -> bool {
        if let Some(ref n) = self.name_contains
            && !t.name.to_lowercase().contains(&n.to_lowercase()) {
                return false;
            }
        if let Some(lo) = self.size_min
            && t.size < lo {
                return false;
            }
        if let Some(hi) = self.size_max
            && t.size > hi {
                return false;
            }
        if let Some(off) = self.field_at_offset
            && !t.fields.iter().any(|f| f.offset == off) {
                return false;
            }
        if let Some(p) = self.is_pointer
            && t.is_pointer != p {
                return false;
            }
        true
    }
}

/// Predicate for filtering string nodes.
#[derive(Debug, Clone, Default)]
pub struct StringFilter {
    pub value_contains: Option<String>,
    pub encoding: Option<StringEncoding>,
    pub referenced_by_function: Option<Addr>,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
}

impl StringFilter {
    #[must_use]
    pub fn matches(&self, s: &StringNode) -> bool {
        if let Some(ref v) = self.value_contains
            && !s.value.to_lowercase().contains(&v.to_lowercase()) {
                return false;
            }
        if let Some(ref enc) = self.encoding
            && s.encoding != *enc {
                return false;
            }
        if let Some(f) = self.referenced_by_function
            && !s.referenced_by.contains(&f) {
                return false;
            }
        if let Some(lo) = self.min_length
            && s.length < lo {
                return false;
            }
        if let Some(hi) = self.max_length
            && s.length > hi {
                return false;
            }
        true
    }
}

// ── Simple glob matcher ──────────────────────────────────────────────────────

/// Very small glob: supports `*` (any sequence) and `?` (any single char).
#[must_use]
pub fn glob_match(pattern: &str, text: &str) -> bool {
    // Iterative two-pointer match with backtracking on the last `*`.
    //
    // The previous implementation recursed and capped the depth at 4096 to
    // avoid a stack overflow. That cap silently turned "too deep" into "no
    // match": `glob_match("*", &"a".repeat(5000))` returned false. Demangled
    // C++/Rust names routinely exceed 4096 characters, and matching them is
    // exactly what `SymbolQuery::name_pattern` is for, so long symbols were
    // being dropped from query results with no way to tell that apart from a
    // genuine mismatch. Iterating removes the stack-overflow risk entirely,
    // which means the answer no longer has to be traded away for safety.
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();

    let (mut pi, mut ti) = (0usize, 0usize);
    // Where to resume if the current `*` turns out to have swallowed too little.
    let mut star: Option<usize> = None;
    let mut star_ti = 0usize;

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(s) = star {
            // Backtrack: let the last `*` consume one more character.
            pi = s + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    // Any pattern left over must be `*`s, which match the empty string.
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

// ── Query AST ────────────────────────────────────────────────────────────────

/// Top-level query discriminant.
#[derive(Debug, Clone)]
pub enum GraphQuery {
    Functions(Box<FunctionQuery>),
    Xrefs(XrefQuery),
    Symbols(SymbolQuery),
    Types(TypeQuery),
    Strings(StringQuery),
    Paths(PathQuery),
    Subgraph(SubgraphQuery),
    Traverse(TraverseQuery),
    Sql(SqlQuery),
    DataFlow(DataFlowQuery),
}

#[derive(Debug, Clone)]
pub struct FunctionQuery {
    pub filter: FunctionFilter,
    pub limit: Option<usize>,
    pub sort_by: FunctionSortKey,
    pub ascending: bool,
}

#[derive(Debug, Clone, Default)]
pub enum FunctionSortKey {
    #[default]
    Address,
    Name,
    Size,
    Complexity,
    CallsCount,
    CallersCount,
}

impl FunctionQuery {
    #[must_use]
    pub fn new() -> Self {
        Self {
            filter: FunctionFilter::default(),
            limit: None,
            sort_by: FunctionSortKey::default(),
            ascending: true,
        }
    }
}

impl Default for FunctionQuery {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct XrefQuery {
    pub filter: XrefFilter,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct SymbolQuery {
    pub filter: SymbolFilter,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct TypeQuery {
    pub filter: TypeFilter,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct StringQuery {
    pub filter: StringFilter,
    pub limit: Option<usize>,
}

/// Find all paths (call chains) from function A to function B.
#[derive(Debug, Clone)]
pub struct PathQuery {
    pub from: Addr,
    pub to: Addr,
    pub max_depth: usize,
    pub max_results: usize,
}

/// Extract a subgraph induced by a set of functions.
#[derive(Debug, Clone)]
pub struct SubgraphQuery {
    pub seed_addrs: Vec<Addr>,
}

/// BFS/DFS traversal from a seed node.
#[derive(Debug, Clone)]
pub struct TraverseQuery {
    pub seed: Addr,
    pub direction: TraverseDirection,
    pub max_depth: usize,
    pub mode: TraverseMode,
    pub edge_kind: Option<XrefKind>,
}

#[derive(Debug, Clone)]
pub enum TraverseDirection {
    /// Follow outgoing call edges (callee direction).
    Forward,
    /// Follow incoming call edges (caller direction).
    Backward,
    /// Both directions.
    Both,
}

#[derive(Debug, Clone)]
pub enum TraverseMode {
    Bfs,
    Dfs,
}

/// SQL-like query parsed into a filter.
#[derive(Debug, Clone)]
pub struct SqlQuery {
    pub raw: String,
    pub parsed: Option<ParsedSql>,
}

#[derive(Debug, Clone)]
pub struct ParsedSql {
    pub table: SqlTable,
    pub conditions: Vec<SqlCondition>,
    pub limit: Option<usize>,
    pub order_by: Option<String>,
    pub ascending: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqlTable {
    Functions,
    Symbols,
    Types,
    Strings,
    Xrefs,
}

#[derive(Debug, Clone)]
pub struct SqlCondition {
    pub field: String,
    pub op: SqlOp,
    pub value: SqlValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqlOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Like,
    NotLike,
}

#[derive(Debug, Clone)]
pub enum SqlValue {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
}

/// Data-flow query: "find functions calling A where the return value flows into B"
#[derive(Debug, Clone)]
pub struct DataFlowQuery {
    pub source_function: String,   // e.g. "malloc"
    pub sink_function: String,     // e.g. "memcpy"
    pub check_return_to_arg: bool,
}

// ── Query results ─────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum QueryResult {
    Functions(Vec<FunctionNode>),
    Xrefs(Vec<XrefEdge>),
    Symbols(Vec<SymbolNode>),
    Types(Vec<TypeNode>),
    Strings(Vec<StringNode>),
    Paths(Vec<CallPath>),
    Subgraph(SubgraphResult),
    DataFlow(Vec<DataFlowPath>),
    Empty,
}

/// A chain of function calls from one address to another.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallPath {
    pub nodes: Vec<Addr>,
    pub length: usize,
}

impl CallPath {
    #[must_use]
    pub const fn new(nodes: Vec<Addr>) -> Self {
        let len = nodes.len();
        Self { nodes, length: len }
    }
}

/// The induced subgraph for a set of functions.
#[derive(Debug, Clone)]
pub struct SubgraphResult {
    pub nodes: Vec<FunctionNode>,
    pub edges: Vec<XrefEdge>,
}

/// A data-flow path through call chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowPath {
    /// Address of the function where source is called.
    pub caller: Addr,
    /// Addresses of intermediate functions (if any) before the sink.
    pub intermediates: Vec<Addr>,
    /// Address of the function where sink is called.
    pub sink_caller: Addr,
}

// ── QueryBuilder: fluent API ─────────────────────────────────────────────────

/// Fluent builder for `GraphQuery`.
pub struct QueryBuilder {
    inner: QueryKindBuilder,
}

enum QueryKindBuilder {
    Function(Box<FunctionQuery>),
    Xref(XrefQuery),
    Symbol(SymbolQuery),
    Type(TypeQuery),
    Str(StringQuery),
    Path(PathQuery),
    Traverse(TraverseQuery),
    Sql(SqlQuery),
    DataFlow(DataFlowQuery),
}

impl QueryBuilder {
    /// Wrap a fully-formed [`FunctionQuery`] in a builder.
    #[must_use]
    pub fn from_function(q: FunctionQuery) -> Self {
        Self { inner: QueryKindBuilder::Function(Box::new(q)) }
    }
    /// Wrap a fully-formed [`XrefQuery`] in a builder.
    #[must_use]
    pub const fn from_xref(q: XrefQuery) -> Self {
        Self { inner: QueryKindBuilder::Xref(q) }
    }
    /// Wrap a fully-formed [`SymbolQuery`] in a builder.
    #[must_use]
    pub const fn from_symbol(q: SymbolQuery) -> Self {
        Self { inner: QueryKindBuilder::Symbol(q) }
    }
    /// Wrap a fully-formed [`TypeQuery`] in a builder.
    #[must_use]
    pub const fn from_type(q: TypeQuery) -> Self {
        Self { inner: QueryKindBuilder::Type(q) }
    }
    /// Wrap a fully-formed [`StringQuery`] in a builder.
    #[must_use]
    pub const fn from_string(q: StringQuery) -> Self {
        Self { inner: QueryKindBuilder::Str(q) }
    }
    /// Wrap a fully-formed [`PathQuery`] in a builder.
    #[must_use]
    pub const fn from_path(q: PathQuery) -> Self {
        Self { inner: QueryKindBuilder::Path(q) }
    }
    /// Wrap a fully-formed [`TraverseQuery`] in a builder.
    #[must_use]
    pub const fn from_traverse(q: TraverseQuery) -> Self {
        Self { inner: QueryKindBuilder::Traverse(q) }
    }
    /// Wrap a fully-formed [`SqlQuery`] in a builder.
    #[must_use]
    pub const fn from_sql(q: SqlQuery) -> Self {
        Self { inner: QueryKindBuilder::Sql(q) }
    }
    /// Wrap a fully-formed [`DataFlowQuery`] in a builder.
    #[must_use]
    pub const fn from_dataflow(q: DataFlowQuery) -> Self {
        Self { inner: QueryKindBuilder::DataFlow(q) }
    }

    /// Finalize this builder into a [`GraphQuery`] enum value, ready for execution.
    #[must_use]
    pub fn build(self) -> GraphQuery {
        match self.inner {
            QueryKindBuilder::Function(q) => GraphQuery::Functions(q), // q is already Box<FunctionQuery>
            QueryKindBuilder::Xref(q) => GraphQuery::Xrefs(q),
            QueryKindBuilder::Symbol(q) => GraphQuery::Symbols(q),
            QueryKindBuilder::Type(q) => GraphQuery::Types(q),
            QueryKindBuilder::Str(q) => GraphQuery::Strings(q),
            QueryKindBuilder::Path(q) => GraphQuery::Paths(q),
            QueryKindBuilder::Traverse(q) => GraphQuery::Traverse(q),
            QueryKindBuilder::Sql(q) => GraphQuery::Sql(q),
            QueryKindBuilder::DataFlow(q) => GraphQuery::DataFlow(q),
        }
    }

    /// Start building a function query.
    pub fn functions() -> FunctionQueryBuilder {
        FunctionQueryBuilder {
            q: FunctionQuery::new(),
        }
    }

    /// Start building a xref query.
    pub fn xrefs() -> XrefQueryBuilder {
        XrefQueryBuilder {
            q: XrefQuery {
                filter: XrefFilter::default(),
                limit: None,
            },
        }
    }

    /// Start building a symbol query.
    #[must_use]
    pub fn symbols() -> SymbolQueryBuilder {
        SymbolQueryBuilder {
            q: SymbolQuery {
                filter: SymbolFilter::default(),
                limit: None,
            },
        }
    }

    /// Start building a type query.
    #[must_use]
    pub fn types() -> TypeQueryBuilder {
        TypeQueryBuilder {
            q: TypeQuery {
                filter: TypeFilter::default(),
                limit: None,
            },
        }
    }

    /// Start building a string query.
    #[must_use]
    pub fn strings() -> StringQueryBuilder {
        StringQueryBuilder {
            q: StringQuery {
                filter: StringFilter::default(),
                limit: None,
            },
        }
    }

    /// Find paths between two addresses.
    #[must_use]
    pub const fn paths(from: Addr, to: Addr) -> PathQueryBuilder {
        PathQueryBuilder {
            q: PathQuery {
                from,
                to,
                max_depth: 10,
                max_results: 20,
            },
        }
    }

    /// Traverse from a seed.
    #[must_use]
    pub const fn traverse(seed: Addr) -> TraverseQueryBuilder {
        TraverseQueryBuilder {
            q: TraverseQuery {
                seed,
                direction: TraverseDirection::Forward,
                max_depth: 5,
                mode: TraverseMode::Bfs,
                edge_kind: None,
            },
        }
    }

    /// Parse a SQL-like query string.
    pub fn sql(raw: impl Into<String>) -> SqlQueryBuilder {
        SqlQueryBuilder { raw: raw.into() }
    }

    /// Data-flow query.
    pub fn data_flow(source: impl Into<String>, sink: impl Into<String>) -> DataFlowQueryBuilder {
        DataFlowQueryBuilder {
            source: source.into(),
            sink: sink.into(),
            check_return_to_arg: true,
        }
    }
}

// Sub-builders.
 #[must_use]
pub struct FunctionQueryBuilder {
    q: FunctionQuery,
}

impl FunctionQueryBuilder {
    pub fn name_contains(mut self, s: impl Into<String>) -> Self {
        self.q.filter.name_contains = Some(s.into());
        self
    }
    pub fn name_exact(mut self, s: impl Into<String>) -> Self {
        self.q.filter.name_exact = Some(s.into());
        self
    }
    pub const fn addr_range(mut self, lo: Addr, hi: Addr) -> Self {
        self.q.filter.addr_min = Some(lo);
        self.q.filter.addr_max = Some(hi);
        self
    }
    pub const fn size_min(mut self, v: u64) -> Self {
        self.q.filter.size_min = Some(v);
        self
    }
    pub const fn size_max(mut self, v: u64) -> Self {
        self.q.filter.size_max = Some(v);
        self
    }
    pub fn calling_conv(mut self, cc: CallingConvention) -> Self {
        self.q.filter.calling_conv = Some(cc);
        self
    }
    pub const fn has_loop(mut self, v: bool) -> Self {
        self.q.filter.has_loop = Some(v);
        self
    }
    pub const fn complexity_min(mut self, v: u32) -> Self {
        self.q.filter.complexity_min = Some(v);
        self
    }
    pub const fn complexity_max(mut self, v: u32) -> Self {
        self.q.filter.complexity_max = Some(v);
        self
    }
    pub const fn calls_count_min(mut self, v: usize) -> Self {
        self.q.filter.calls_count_min = Some(v);
        self
    }
    pub const fn calls_count_max(mut self, v: usize) -> Self {
        self.q.filter.calls_count_max = Some(v);
        self
    }
    pub const fn callers_count_min(mut self, v: usize) -> Self {
        self.q.filter.callers_count_min = Some(v);
        self
    }
    pub fn module(mut self, m: impl Into<String>) -> Self {
        self.q.filter.module = Some(m.into());
        self
    }
    pub const fn is_noreturn(mut self, v: bool) -> Self {
        self.q.filter.is_noreturn = Some(v);
        self
    }
    pub fn has_tag(mut self, t: impl Into<String>) -> Self {
        self.q.filter.has_tag = Some(t.into());
        self
    }
    pub fn calling(mut self, name: impl Into<String>) -> Self {
        self.q.filter.calls_function_named = Some(name.into());
        self
    }
    pub const fn limit(mut self, n: usize) -> Self {
        self.q.limit = Some(n);
        self
    }
    pub const fn sort_by(mut self, key: FunctionSortKey, ascending: bool) -> Self {
        self.q.sort_by = key;
        self.q.ascending = ascending;
        self
    }
    #[must_use]
    pub fn build(self) -> GraphQuery {
        GraphQuery::Functions(Box::new(self.q))
    }
    pub fn collect(self, engine: &QueryEngine) -> Vec<FunctionNode> {
        match engine.execute(self.build()) {
            QueryResult::Functions(v) => v,
            _ => vec![],
        }
    }
}
 #[must_use]
pub struct XrefQueryBuilder {
    q: XrefQuery,
}

impl XrefQueryBuilder {
    pub const fn kind(mut self, k: XrefKind) -> Self {
        self.q.filter.kind = Some(k);
        self
    }
    pub const fn from_func(mut self, addr: Addr) -> Self {
        self.q.filter.from_func = Some(addr);
        self
    }
    pub const fn to_func(mut self, addr: Addr) -> Self {
        self.q.filter.to_func = Some(addr);
        self
    }
    pub fn from_module(mut self, m: impl Into<String>) -> Self {
        self.q.filter.from_module = Some(m.into());
        self
    }
    pub const fn limit(mut self, n: usize) -> Self {
        self.q.limit = Some(n);
        self
    }
    #[must_use]
    pub fn build(self) -> GraphQuery {
        GraphQuery::Xrefs(self.q)
    }
    pub fn collect(self, engine: &QueryEngine) -> Vec<XrefEdge> {
        match engine.execute(self.build()) {
            QueryResult::Xrefs(v) => v,
            _ => vec![],
        }
    }
}

pub struct SymbolQueryBuilder {
    q: SymbolQuery,
}

impl SymbolQueryBuilder {
    #[must_use]
    pub fn name_pattern(mut self, p: impl Into<String>) -> Self {
        self.q.filter.name_pattern = Some(p.into());
        self
    }
    #[must_use]
    pub const fn kind(mut self, k: SymbolKind) -> Self {
        self.q.filter.kind = Some(k);
        self
    }
    #[must_use]
    pub const fn source(mut self, s: SymbolSource) -> Self {
        self.q.filter.source = Some(s);
        self
    }
    #[must_use]
    pub fn demangled_contains(mut self, s: impl Into<String>) -> Self {
        self.q.filter.demangled_contains = Some(s.into());
        self
    }
    #[must_use]
    pub fn module(mut self, m: impl Into<String>) -> Self {
        self.q.filter.module = Some(m.into());
        self
    }
    #[must_use]
    pub const fn limit(mut self, n: usize) -> Self {
        self.q.limit = Some(n);
        self
    }
    #[must_use]
    pub fn build(self) -> GraphQuery {
        GraphQuery::Symbols(self.q)
    }
    pub fn collect(self, engine: &QueryEngine) -> Vec<SymbolNode> {
        match engine.execute(self.build()) {
            QueryResult::Symbols(v) => v,
            _ => vec![],
        }
    }
}

pub struct TypeQueryBuilder {
    q: TypeQuery,
}

impl TypeQueryBuilder {
    #[must_use]
    pub fn name_contains(mut self, s: impl Into<String>) -> Self {
        self.q.filter.name_contains = Some(s.into());
        self
    }
    #[must_use]
    pub const fn size_range(mut self, lo: u64, hi: u64) -> Self {
        self.q.filter.size_min = Some(lo);
        self.q.filter.size_max = Some(hi);
        self
    }
    #[must_use]
    pub const fn field_at_offset(mut self, off: u64) -> Self {
        self.q.filter.field_at_offset = Some(off);
        self
    }
    #[must_use]
    pub const fn is_pointer(mut self, v: bool) -> Self {
        self.q.filter.is_pointer = Some(v);
        self
    }
    #[must_use]
    pub const fn limit(mut self, n: usize) -> Self {
        self.q.limit = Some(n);
        self
    }
    #[must_use]
    pub fn build(self) -> GraphQuery {
        GraphQuery::Types(self.q)
    }
    pub fn collect(self, engine: &QueryEngine) -> Vec<TypeNode> {
        match engine.execute(self.build()) {
            QueryResult::Types(v) => v,
            _ => vec![],
        }
    }
}

pub struct StringQueryBuilder {
    q: StringQuery,
}

impl StringQueryBuilder {
    #[must_use]
    pub fn value_contains(mut self, s: impl Into<String>) -> Self {
        self.q.filter.value_contains = Some(s.into());
        self
    }
    #[must_use]
    pub const fn encoding(mut self, e: StringEncoding) -> Self {
        self.q.filter.encoding = Some(e);
        self
    }
    #[must_use]
    pub const fn referenced_by(mut self, addr: Addr) -> Self {
        self.q.filter.referenced_by_function = Some(addr);
        self
    }
    #[must_use]
    pub const fn min_length(mut self, n: usize) -> Self {
        self.q.filter.min_length = Some(n);
        self
    }
    #[must_use]
    pub const fn max_length(mut self, n: usize) -> Self {
        self.q.filter.max_length = Some(n);
        self
    }
    #[must_use]
    pub const fn limit(mut self, n: usize) -> Self {
        self.q.limit = Some(n);
        self
    }
    #[must_use]
    pub fn build(self) -> GraphQuery {
        GraphQuery::Strings(self.q)
    }
    pub fn collect(self, engine: &QueryEngine) -> Vec<StringNode> {
        match engine.execute(self.build()) {
            QueryResult::Strings(v) => v,
            _ => vec![],
        }
    }
}

pub struct PathQueryBuilder {
    q: PathQuery,
}

impl PathQueryBuilder {
    #[must_use]
    pub const fn max_depth(mut self, d: usize) -> Self {
        self.q.max_depth = d;
        self
    }
    #[must_use]
    pub const fn max_results(mut self, n: usize) -> Self {
        self.q.max_results = n;
        self
    }
    #[must_use]
    pub const fn build(self) -> GraphQuery {
        GraphQuery::Paths(self.q)
    }
    pub fn collect(self, engine: &QueryEngine) -> Vec<CallPath> {
        match engine.execute(self.build()) {
            QueryResult::Paths(v) => v,
            _ => vec![],
        }
    }
}

pub struct TraverseQueryBuilder {
    q: TraverseQuery,
}

impl TraverseQueryBuilder {
    #[must_use]
    pub const fn forward(mut self) -> Self {
        self.q.direction = TraverseDirection::Forward;
        self
    }
    #[must_use]
    pub const fn backward(mut self) -> Self {
        self.q.direction = TraverseDirection::Backward;
        self
    }
    #[must_use]
    pub const fn both_directions(mut self) -> Self {
        self.q.direction = TraverseDirection::Both;
        self
    }
    #[must_use]
    pub const fn max_depth(mut self, d: usize) -> Self {
        self.q.max_depth = d;
        self
    }
    #[must_use]
    pub const fn bfs(mut self) -> Self {
        self.q.mode = TraverseMode::Bfs;
        self
    }
    #[must_use]
    pub const fn dfs(mut self) -> Self {
        self.q.mode = TraverseMode::Dfs;
        self
    }
    #[must_use]
    pub const fn edge_kind(mut self, k: XrefKind) -> Self {
        self.q.edge_kind = Some(k);
        self
    }
    #[must_use]
    pub const fn build(self) -> GraphQuery {
        GraphQuery::Traverse(self.q)
    }
    pub fn collect(self, engine: &QueryEngine) -> Vec<FunctionNode> {
        match engine.execute(self.build()) {
            QueryResult::Functions(v) => v,
            _ => vec![],
        }
    }
}

pub struct SqlQueryBuilder {
    raw: String,
}

impl SqlQueryBuilder {
    #[must_use]
    pub fn build(self) -> GraphQuery {
        let parsed = parse_sql(&self.raw);
        GraphQuery::Sql(SqlQuery {
            raw: self.raw,
            parsed,
        })
    }
    pub fn execute(self, engine: &QueryEngine) -> QueryResult {
        engine.execute(self.build())
    }
}

pub struct DataFlowQueryBuilder {
    source: String,
    sink: String,
    check_return_to_arg: bool,
}

impl DataFlowQueryBuilder {
    #[must_use]
    pub const fn check_return_to_arg(mut self, v: bool) -> Self {
        self.check_return_to_arg = v;
        self
    }
    #[must_use]
    pub fn build(self) -> GraphQuery {
        GraphQuery::DataFlow(DataFlowQuery {
            source_function: self.source,
            sink_function: self.sink,
            check_return_to_arg: self.check_return_to_arg,
        })
    }
    pub fn collect(self, engine: &QueryEngine) -> Vec<DataFlowPath> {
        match engine.execute(self.build()) {
            QueryResult::DataFlow(v) => v,
            _ => vec![],
        }
    }
}

// ── SQL parser ───────────────────────────────────────────────────────────────

/// Minimal SQL-like parser.
/// Supports: SELECT <table> WHERE <cond> [AND <cond> ...] [LIMIT n] [ORDER BY field [ASC|DESC]]
/// Example: "SELECT functions WHERE name LIKE '%crypt%' AND `calls_count` > 5"
#[must_use]
pub fn parse_sql(sql: &str) -> Option<ParsedSql> {
    let upper = sql.to_uppercase();
    // Fast reject: bail out early if the query clearly isn't a SELECT or contains
    // a forbidden destructive keyword. This avoids tokenizing obviously bad input.
    if !upper.contains("SELECT") {
        return None;
    }
    for forbidden in ["DROP ", "DELETE ", "UPDATE ", "INSERT ", "ALTER "] {
        if upper.contains(forbidden) {
            return None;
        }
    }
    let tokens: Vec<&str> = sql.split_whitespace().collect();

    // Find SELECT
    let sel_pos = tokens.iter().position(|t| t.to_uppercase() == "SELECT")?;
    let table_token = tokens.get(sel_pos + 1)?;
    let table = match table_token.to_uppercase().as_str() {
        "FUNCTIONS" | "FUNCTION" => SqlTable::Functions,
        "SYMBOLS" | "SYMBOL" => SqlTable::Symbols,
        "TYPES" | "TYPE" => SqlTable::Types,
        "STRINGS" | "STRING" => SqlTable::Strings,
        "XREFS" | "XREF" => SqlTable::Xrefs,
        _ => return None,
    };

    let mut conditions = Vec::new();
    let mut limit = None;
    let mut order_by = None;
    let mut ascending = true;

    // Scan for WHERE clause.
    if let Some(where_pos) = tokens.iter().position(|t| t.to_uppercase() == "WHERE") {
        let mut i = where_pos + 1;
        while i < tokens.len() {
            let token = tokens[i].to_uppercase();
            if token == "LIMIT" {
                if let Some(n) = tokens.get(i + 1).and_then(|t| t.parse::<usize>().ok()) {
                    limit = Some(n);
                }
                i += 2;
                continue;
            }
            if token == "ORDER" {
                if tokens.get(i + 1).map(|t| t.to_uppercase()) == Some("BY".into())
                    && let Some(col) = tokens.get(i + 2) {
                        order_by = Some(col.to_string());
                        if tokens
                            .get(i + 3)
                            .is_some_and(|t| t.to_uppercase() == "DESC")
                        {
                            ascending = false;
                        }
                    }
                break;
            }
            if token == "AND" {
                i += 1;
                continue;
            }

            // Try to parse: field NOT LIKE value  (four tokens)
            if let (Some(field), Some(op_str), Some(like_str), Some(val_str)) = (
                tokens.get(i),
                tokens.get(i + 1),
                tokens.get(i + 2),
                tokens.get(i + 3),
            )
                && op_str.eq_ignore_ascii_case("NOT") && like_str.eq_ignore_ascii_case("LIKE") {
                    let value_str = val_str.trim_matches('\'').trim_matches('"');
                    let value = if let Ok(n) = value_str.parse::<i64>() {
                        SqlValue::Int(n)
                    } else if let Ok(f) = value_str.parse::<f64>() {
                        SqlValue::Float(f)
                    } else if value_str.eq_ignore_ascii_case("TRUE") {
                        SqlValue::Bool(true)
                    } else if value_str.eq_ignore_ascii_case("FALSE") {
                        SqlValue::Bool(false)
                    } else {
                        SqlValue::Str(value_str.to_string())
                    };
                    conditions.push(SqlCondition {
                        field: field.to_lowercase(),
                        op: SqlOp::NotLike,
                        value,
                    });
                    i += 4;
                    continue;
                }

            // Try to parse: field OP value  (three tokens)
            if let (Some(field), Some(op_str), Some(val_str)) =
                (tokens.get(i), tokens.get(i + 1), tokens.get(i + 2))
            {
                let op = match op_str.to_uppercase().as_str() {
                    "=" | "==" => Some(SqlOp::Eq),
                    "!=" | "<>" => Some(SqlOp::Ne),
                    "<" => Some(SqlOp::Lt),
                    "<=" => Some(SqlOp::Le),
                    ">" => Some(SqlOp::Gt),
                    ">=" => Some(SqlOp::Ge),
                    "LIKE" => Some(SqlOp::Like),
                    _ => None,
                };

                if let Some(op) = op {
                    let value_str = val_str.trim_matches('\'').trim_matches('"');
                    let value = if let Ok(n) = value_str.parse::<i64>() {
                        SqlValue::Int(n)
                    } else if let Ok(f) = value_str.parse::<f64>() {
                        SqlValue::Float(f)
                    } else if value_str.to_uppercase() == "TRUE" {
                        SqlValue::Bool(true)
                    } else if value_str.to_uppercase() == "FALSE" {
                        SqlValue::Bool(false)
                    } else {
                        SqlValue::Str(value_str.to_string())
                    };

                    conditions.push(SqlCondition {
                        field: field.to_lowercase(),
                        op,
                        value,
                    });
                    i += 3;
                    continue;
                }
            }
            i += 1;
        }
    }

    // Check for trailing LIMIT outside WHERE.
    if limit.is_none()
        && let Some(lp) = tokens.iter().position(|t| t.to_uppercase() == "LIMIT") {
            limit = tokens.get(lp + 1).and_then(|t| t.parse::<usize>().ok());
        }

    Some(ParsedSql {
        table,
        conditions,
        limit,
        order_by,
        ascending,
    })
}

// ── Query result cache ───────────────────────────────────────────────────────

struct CacheEntry {
    result: Vec<u8>, // serialized QueryResult summary (or just a key)
    timestamp: u64,
    hit_count: u32,
}

/// Cache for query results.
///
/// Uses [`BTreeMap`] instead of [`HashMap`] because the cache key is derived
/// from user-controlled query strings (function names, addresses, SQL text).
/// A `HashMap` with a predictable hasher can be degraded to O(n) lookup by an
/// attacker who crafts colliding keys.  `BTreeMap` provides O(log n) regardless
/// of key distribution without needing an external dependency.
pub struct QueryCache {
    entries: RwLock<BTreeMap<String, CacheEntry>>,
    max_entries: usize,
}

impl QueryCache {
    #[must_use]
    pub const fn new(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(BTreeMap::new()),
            max_entries,
        }
    }

    /// Check if a query key is cached.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn has(&self, key: &str) -> bool {
        self.entries.read().unwrap().contains_key(key)
    }

    /// Insert raw bytes under key.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn insert(&self, key: String, data: Vec<u8>) {
        use std::time::{SystemTime, UNIX_EPOCH};
        let mut entries = self.entries.write().unwrap();
        if entries.len() >= self.max_entries {
            // Evict the entry with the oldest timestamp.
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, v)| v.timestamp)
                .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest);
            }
        }
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis().try_into().unwrap_or(u64::MAX);
        entries.insert(key, CacheEntry { result: data, timestamp: ts, hit_count: 0 });
    }
 /// # Panics
 ///
 /// Panics if the internal lock is poisoned.
    /// Retrieve and bump hit count.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let mut entries = self.entries.write().unwrap();
        entries.get_mut(key).map(|e| {
            e.hit_count = e.hit_count.saturating_add(1);
            e.result.clone()
        })
    }

    /// Invalidate all entries containing the given address in their key.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn invalidate_by_addr(&self, addr: Addr) {
        let prefix = format!("{addr:#x}");
        let mut entries = self.entries.write().unwrap();
        entries.retain(|k, _| !k.contains(&prefix));
    }

    /// Invalidate all entries for a given table name.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn invalidate_table(&self, table: &str) {
        let mut entries = self.entries.write().unwrap();
        entries.retain(|k, _| !k.starts_with(table));
    }

    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn clear(&self) {
        self.entries.write().unwrap().clear();
    }

    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn entry_count(&self) -> usize {
        self.entries.read().unwrap().len()
    }
}

// ── QueryEngine ──────────────────────────────────────────────────────────────

/// The main query execution engine.
pub struct QueryEngine {
    pub graph: Arc<KnowledgeGraph>,
    pub cache: QueryCache,
}

impl QueryEngine {
    pub const fn new(graph: Arc<KnowledgeGraph>) -> Self {
        Self {
            graph,
            cache: QueryCache::new(1024),
        }
    }

    /// Execute a `GraphQuery` and return results.
    pub fn execute(&self, query: GraphQuery) -> QueryResult {
        match query {
            GraphQuery::Functions(q) => self.exec_functions(&q),
            GraphQuery::Xrefs(q) => self.exec_xrefs(&q),
            GraphQuery::Symbols(q) => self.exec_symbols(&q),
            GraphQuery::Types(q) => self.exec_types(&q),
            GraphQuery::Strings(q) => self.exec_strings(&q),
            GraphQuery::Paths(q) => self.exec_paths(&q),
            GraphQuery::Subgraph(q) => self.exec_subgraph(&q),
            GraphQuery::Traverse(q) => self.exec_traverse(&q),
            GraphQuery::Sql(q) => self.exec_sql(q),
            GraphQuery::DataFlow(q) => self.exec_data_flow(&q),
        }
    }

    // ── Function execution ───────────────────────────────────────────────────

    fn exec_functions(&self, q: &FunctionQuery) -> QueryResult {
        let mut results: Vec<FunctionNode> = {
            let fns = self.graph.functions.read().unwrap();
            fns.values()
                .filter(|f| q.filter.matches(f, &self.graph))
                .cloned()
                .collect()
        };

        // Sort.
        match q.sort_by {
            FunctionSortKey::Address => results.sort_by_key(|f| f.address),
            FunctionSortKey::Name => results.sort_by(|a, b| a.name.cmp(&b.name)),
            FunctionSortKey::Size => results.sort_by_key(|f| f.size),
            FunctionSortKey::Complexity => results.sort_by_key(|f| f.complexity),
            FunctionSortKey::CallsCount => results.sort_by_key(FunctionNode::calls_count),
            FunctionSortKey::CallersCount => results.sort_by_key(FunctionNode::callers_count),
        }
        if !q.ascending {
            results.reverse();
        }

        if let Some(n) = q.limit {
            results.truncate(n);
        }

        QueryResult::Functions(results)
    }

    // ── Xref execution ───────────────────────────────────────────────────────

    fn exec_xrefs(&self, q: &XrefQuery) -> QueryResult {
        let mut results: Vec<XrefEdge> = {
            let xrefs = self.graph.xrefs.read().unwrap();
            xrefs.iter()
                .filter(|x| q.filter.matches(x))
                .cloned()
                .collect()
        };
        if let Some(n) = q.limit {
            results.truncate(n);
        }
        QueryResult::Xrefs(results)
    }

    // ── Symbol execution ─────────────────────────────────────────────────────

    fn exec_symbols(&self, q: &SymbolQuery) -> QueryResult {
        let mut results: Vec<SymbolNode> = {
            let syms = self.graph.symbols.read().unwrap();
            syms.values()
                .filter(|s| q.filter.matches(s))
                .cloned()
                .collect()
        };
        results.sort_by_key(|s| s.address);
        if let Some(n) = q.limit {
            results.truncate(n);
        }
        QueryResult::Symbols(results)
    }

    // ── Type execution ───────────────────────────────────────────────────────

    fn exec_types(&self, q: &TypeQuery) -> QueryResult {
        let mut results: Vec<TypeNode> = {
            let types = self.graph.types.read().unwrap();
            types.values()
                .filter(|t| q.filter.matches(t))
                .cloned()
                .collect()
        };
        results.sort_by_key(|t| t.type_id);
        if let Some(n) = q.limit {
            results.truncate(n);
        }
        QueryResult::Types(results)
    }

    // ── String execution ─────────────────────────────────────────────────────

    fn exec_strings(&self, q: &StringQuery) -> QueryResult {
        let mut results: Vec<StringNode> = {
            let strs = self.graph.strings.read().unwrap();
            strs.values()
                .filter(|s| q.filter.matches(s))
                .cloned()
                .collect()
        };
        results.sort_by_key(|s| s.address);
        if let Some(n) = q.limit {
            results.truncate(n);
        }
        QueryResult::Strings(results)
    }

    // ── Path execution (BFS all paths) ───────────────────────────────────────

    fn exec_paths(&self, q: &PathQuery) -> QueryResult {
        let paths = self.find_all_paths(q.from, q.to, q.max_depth, q.max_results);
        QueryResult::Paths(paths)
    }

    /// BFS to find all paths from `from` to `to` up to `max_depth` hops.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn find_all_paths(
        &self,
        from: Addr,
        to: Addr,
        max_depth: usize,
        max_results: usize,
    ) -> Vec<CallPath> {
        let fns = self.graph.functions.read().unwrap();
        let mut results = Vec::new();

        // BFS queue: (current_addr, path_so_far)
        let mut queue: VecDeque<(Addr, Vec<Addr>)> = VecDeque::new();
        queue.push_back((from, vec![from]));

        while let Some((current, path)) = queue.pop_front() {
            if results.len() >= max_results {
                break;
            }
            if path.len() > max_depth + 1 {
                continue;
            }
            if current == to && path.len() > 1 {
                results.push(CallPath::new(path));
                continue;
            }
            if let Some(f) = fns.get(&current) {
                for &callee in &f.calls {
                    // Avoid cycles (don't revisit nodes in current path).
                    if !path.contains(&callee) {
                        let mut new_path = path.clone();
                        new_path.push(callee);
                        queue.push_back((callee, new_path));
                    }
                }
            }
        }
        results
    }

    // ── Subgraph extraction ──────────────────────────────────────────────────

    fn exec_subgraph(&self, q: &SubgraphQuery) -> QueryResult {
        let seed_set: HashSet<Addr> = q.seed_addrs.iter().copied().collect();
        let (nodes, edges) = {
            let fns = self.graph.functions.read().unwrap();
            let xrefs = self.graph.xrefs.read().unwrap();
            let nodes: Vec<FunctionNode> = seed_set
                .iter()
                .filter_map(|a| fns.get(a).cloned())
                .collect();
            let edges: Vec<XrefEdge> = xrefs
                .iter()
                .filter(|x| {
                    x.from_func.is_some_and(|f| seed_set.contains(&f))
                        && x.to_func.is_some_and(|t| seed_set.contains(&t))
                })
                .cloned()
                .collect();
            (nodes, edges)
        };
        QueryResult::Subgraph(SubgraphResult { nodes, edges })
    }

    // ── Traverse ─────────────────────────────────────────────────────────────

    fn exec_traverse(&self, q: &TraverseQuery) -> QueryResult {
        let visited = match q.mode {
            TraverseMode::Bfs => self.bfs_traverse(q),
            TraverseMode::Dfs => self.dfs_traverse(q),
        };
        let nodes: Vec<FunctionNode> = {
            let fns = self.graph.functions.read().unwrap();
            visited
                .into_iter()
                .filter_map(|a| fns.get(&a).cloned())
                .collect()
        };
        QueryResult::Functions(nodes)
    }

    fn bfs_traverse(&self, q: &TraverseQuery) -> Vec<Addr> {
        let fns = self.graph.functions.read().unwrap();
        let xrefs = self.graph.xrefs.read().unwrap();
        let mut visited: HashSet<Addr> = HashSet::new();
        let mut queue: VecDeque<(Addr, usize)> = VecDeque::new();
        queue.push_back((q.seed, 0));
        visited.insert(q.seed);
        while let Some((current, depth)) = queue.pop_front() {
            if depth >= q.max_depth {
                continue;
            }
            for n in self.neighbors(&fns, &xrefs, current, &q.direction, &q.edge_kind) {
                if visited.insert(n) {
                    queue.push_back((n, depth + 1));
                }
            }
        }
        drop(fns);
        drop(xrefs);
        visited.into_iter().collect()
    }

    fn dfs_traverse(&self, q: &TraverseQuery) -> Vec<Addr> {
        let fns = self.graph.functions.read().unwrap();
        let xrefs = self.graph.xrefs.read().unwrap();
        // Track the SHALLOWEST depth at which each node has been reached, and
        // re-expand when a shorter route shows up.
        //
        // Marking a node visited at push time is only sound for BFS, where
        // first discovery IS the minimum distance — which is why
        // `bfs_traverse` above can do exactly that. A LIFO can reach a node
        // along a long path first; freezing it at that depth then truncates
        // its whole subtree, dropping nodes that are comfortably inside
        // `max_depth` via a shorter route.
        //
        // This terminates: a node is only re-pushed with a strictly smaller
        // depth, and depth is bounded below by zero.
        let mut best: HashMap<Addr, usize> = HashMap::new();
        let mut stack: Vec<(Addr, usize)> = vec![(q.seed, 0)];
        best.insert(q.seed, 0);
        while let Some((current, depth)) = stack.pop() {
            if depth >= q.max_depth {
                continue;
            }
            for n in self.neighbors(&fns, &xrefs, current, &q.direction, &q.edge_kind) {
                let next_depth = depth + 1;
                if best.get(&n).is_none_or(|&d| next_depth < d) {
                    best.insert(n, next_depth);
                    stack.push((n, next_depth));
                }
            }
        }
        drop(fns);
        drop(xrefs);
        best.into_keys().collect()
    }

    fn neighbors(
        &self,
        fns: &HashMap<Addr, FunctionNode>,
        xrefs: &[XrefEdge],
        addr: Addr,
        direction: &TraverseDirection,
        edge_kind: &Option<XrefKind>,
    ) -> Vec<Addr> {
        let mut result = Vec::new();
        match direction {
            TraverseDirection::Forward => {
                if let Some(f) = fns.get(&addr) {
                    result.extend_from_slice(&f.calls);
                }
            }
            TraverseDirection::Backward => {
                if let Some(f) = fns.get(&addr) {
                    result.extend_from_slice(&f.called_by);
                }
            }
            TraverseDirection::Both => {
                if let Some(f) = fns.get(&addr) {
                    result.extend_from_slice(&f.calls);
                    result.extend_from_slice(&f.called_by);
                }
            }
        }
        // If edge_kind is specified, filter through xrefs.
        if let Some(kind) = &edge_kind {
            let xref_targets: HashSet<Addr> = xrefs
                .iter()
                .filter(|x| &x.kind == kind)
                .filter_map(|x| match direction {
                    TraverseDirection::Forward => {
                        if x.from_func == Some(addr) { x.to_func } else { None }
                    }
                    TraverseDirection::Backward => {
                        if x.to_func == Some(addr) { x.from_func } else { None }
                    }
                    TraverseDirection::Both => {
                        if x.from_func == Some(addr) {
                            x.to_func
                        } else if x.to_func == Some(addr) {
                            x.from_func
                        } else {
                            None
                        }
                    }
                })
                .collect();
            result.retain(|a| xref_targets.contains(a));
        }
        result
    }

    // ── SQL execution ────────────────────────────────────────────────────────

    fn exec_sql(&self, q: SqlQuery) -> QueryResult {
        let parsed = match q.parsed {
            Some(p) => p,
            None => return QueryResult::Empty,
        };

        match parsed.table {
            SqlTable::Functions => {
                let mut filter = FunctionFilter::default();
                for cond in &parsed.conditions {
                    self.apply_sql_cond_to_func_filter(&mut filter, cond);
                }
                self.exec_functions(&FunctionQuery {
                    filter,
                    limit: parsed.limit,
                    sort_by: parsed
                        .order_by
                        .as_deref()
                        .map(|s| match s {
                            "name" => FunctionSortKey::Name,
                            "size" => FunctionSortKey::Size,
                            "complexity" => FunctionSortKey::Complexity,
                            "calls_count" => FunctionSortKey::CallsCount,
                            _ => FunctionSortKey::Address,
                        })
                        .unwrap_or_default(),
                    ascending: parsed.ascending,
                })
            }
            SqlTable::Symbols => {
                let mut filter = SymbolFilter::default();
                for cond in &parsed.conditions {
                    if cond.field == "name"
                        && let SqlValue::Str(ref s) = cond.value {
                            filter.name_pattern = Some(sql_like_to_glob(s));
                        }
                }
                self.exec_symbols(&SymbolQuery {
                    filter,
                    limit: parsed.limit,
                })
            }
            SqlTable::Types => {
                let mut filter = TypeFilter::default();
                for cond in &parsed.conditions {
                    if cond.field == "name" {
                        if let SqlValue::Str(ref s) = cond.value {
                            filter.name_contains = Some(s.clone());
                        }
                    } else if cond.field == "size" && let SqlValue::Int(n) = &cond.value {
                        {
                            match cond.op {
                                SqlOp::Ge | SqlOp::Gt => filter.size_min = u64::try_from(*n).ok(),
                                SqlOp::Le | SqlOp::Lt => filter.size_max = u64::try_from(*n).ok(),
                                SqlOp::Eq => {
                                    if let Ok(v) = u64::try_from(*n) {
                                        filter.size_min = Some(v);
                                        filter.size_max = Some(v);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                self.exec_types(&TypeQuery {
                    filter,
                    limit: parsed.limit,
                })
            }
            SqlTable::Strings => {
                let mut filter = StringFilter::default();
                for cond in &parsed.conditions {
                    if cond.field == "value"
                        && let SqlValue::Str(ref s) = cond.value {
                            filter.value_contains = Some(s.trim_matches('%').into());
                        }
                }
                self.exec_strings(&StringQuery {
                    filter,
                    limit: parsed.limit,
                })
            }
            SqlTable::Xrefs => {
                self.exec_xrefs(&XrefQuery {
                    filter: XrefFilter::default(),
                    limit: parsed.limit,
                })
            }
        }
    }

    fn apply_sql_cond_to_func_filter(&self, f: &mut FunctionFilter, cond: &SqlCondition) {
        match cond.field.as_str() {
            "name" => match (&cond.op, &cond.value) {
                (SqlOp::Like, SqlValue::Str(s)) => {
                    f.name_contains = Some(s.trim_matches('%').into());
                }
                (SqlOp::Eq, SqlValue::Str(s)) => {
                    f.name_exact = Some(s.clone());
                }
                _ => {}
            },
            "calls_count" => {
                if let SqlValue::Int(n) = cond.value {
                    match cond.op {
                        SqlOp::Ge | SqlOp::Gt => f.calls_count_min = usize::try_from(n).ok(),
                        SqlOp::Le | SqlOp::Lt => f.calls_count_max = usize::try_from(n).ok(),
                        SqlOp::Eq => {
                            if let Ok(v) = usize::try_from(n) {
                                f.calls_count_min = Some(v);
                                f.calls_count_max = Some(v);
                            }
                        }
                        _ => {}
                    }
                }
            }
            "complexity" => {
                if let SqlValue::Int(n) = cond.value {
                    match cond.op {
                        SqlOp::Ge | SqlOp::Gt => f.complexity_min = u32::try_from(n).ok(),
                        SqlOp::Le | SqlOp::Lt => f.complexity_max = u32::try_from(n).ok(),
                        _ => {}
                    }
                }
            }
            "has_loop" => {
                if let SqlValue::Bool(b) = cond.value {
                    f.has_loop = Some(b);
                }
            }
            "module" => {
                if let SqlValue::Str(ref s) = cond.value {
                    f.module = Some(s.clone());
                }
            }
            _ => {}
        }
    }

    // ── Data-flow execution ──────────────────────────────────────────────────

    fn exec_data_flow(&self, q: &DataFlowQuery) -> QueryResult {
        let fns = self.graph.functions.read().unwrap();

        // Find all functions that call the source.
        let source_callers: Vec<Addr> = fns
            .values()
            .filter(|f| {
                f.calls.iter().any(|&c| {
                    fns.get(&c)
                        .is_some_and(|callee| callee.name.contains(&q.source_function))
                })
            })
            .map(|f| f.address)
            .collect();

        // Find all functions that call the sink.
        let sink_callers: HashSet<Addr> = fns
            .values()
            .filter(|f| {
                f.calls.iter().any(|&c| {
                    fns.get(&c)
                        .is_some_and(|callee| callee.name.contains(&q.sink_function))
                })
            })
            .map(|f| f.address)
            .collect();

        let mut paths = Vec::new();
        drop(fns); // release lock before calling find_all_paths

        for &source_caller in &source_callers {
            // Direct: same function calls both source and sink.
            if sink_callers.contains(&source_caller) {
                paths.push(DataFlowPath {
                    caller: source_caller,
                    intermediates: vec![],
                    sink_caller: source_caller,
                });
                continue;
            }

            // Indirect: source_caller calls some chain that reaches a sink_caller.
            for &sink_caller in &sink_callers {
                let call_paths =
                    self.find_all_paths(source_caller, sink_caller, 5, 3);
                for cp in call_paths {
                    let intermediates =
                        cp.nodes[1..cp.nodes.len().saturating_sub(1)].to_vec();
                    paths.push(DataFlowPath {
                        caller: source_caller,
                        intermediates,
                        sink_caller,
                    });
                }
            }
        }

        QueryResult::DataFlow(paths)
    }

    // ── Full-text search ─────────────────────────────────────────────────────

    /// Search symbol names, comment text, type definitions for a query string.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn full_text_search(&self, query: &str) -> FullTextResults {
        let q_lower = query.to_lowercase();

        let (matching_functions, matching_symbols, matching_types, matching_strings) = {
            let fns = self.graph.functions.read().unwrap();
            let syms = self.graph.symbols.read().unwrap();
            let types = self.graph.types.read().unwrap();
            let strings = self.graph.strings.read().unwrap();

            let matching_functions: Vec<Addr> = fns
                .values()
                .filter(|f| {
                    f.name.to_lowercase().contains(&q_lower)
                        || f.comment
                            .as_deref()
                            .is_some_and(|c| c.to_lowercase().contains(&q_lower))
                        || f.tags.iter().any(|t| t.to_lowercase().contains(&q_lower))
                })
                .map(|f| f.address)
                .collect();

            let matching_symbols: Vec<Addr> = syms
                .values()
                .filter(|s| {
                    s.name.to_lowercase().contains(&q_lower)
                        || s.demangled_name
                            .as_deref()
                            .is_some_and(|d| d.to_lowercase().contains(&q_lower))
                })
                .map(|s| s.address)
                .collect();

            let matching_types: Vec<u32> = types
                .values()
                .filter(|t| {
                    t.name.to_lowercase().contains(&q_lower)
                        || t.fields.iter().any(|f| f.name.to_lowercase().contains(&q_lower))
                })
                .map(|t| t.type_id)
                .collect();

            let matching_strings: Vec<Addr> = strings
                .values()
                .filter(|s| s.value.to_lowercase().contains(&q_lower))
                .map(|s| s.address)
                .collect();

            (matching_functions, matching_symbols, matching_types, matching_strings)
        };

        FullTextResults {
            query: query.to_string(),
            function_addresses: matching_functions,
            symbol_addresses: matching_symbols,
            type_ids: matching_types,
            string_addresses: matching_strings,
        }
    }
}

/// Results from a full-text search.
#[derive(Debug, Clone)]
pub struct FullTextResults {
    pub query: String,
    pub function_addresses: Vec<Addr>,
    pub symbol_addresses: Vec<Addr>,
    pub type_ids: Vec<u32>,
    pub string_addresses: Vec<Addr>,
}

impl FullTextResults {
    #[must_use]
    pub const fn total_hits(&self) -> usize {
        self.function_addresses.len()
            + self.symbol_addresses.len()
            + self.type_ids.len()
            + self.string_addresses.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total_hits() == 0
    }
}

/// Convert SQL LIKE pattern (% wildcard) to glob (* wildcard).
fn sql_like_to_glob(s: &str) -> String {
    s.replace('%', "*").replace('_', "?")
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_graph() -> Arc<KnowledgeGraph> {
        let g = Arc::new(KnowledgeGraph::new());

        g.add_function(FunctionNode {
            address: 0x1000,
            name: "malloc".into(),
            size: 128,
            calling_conv: CallingConvention::Cdecl,
            has_loop: false,
            complexity: 5,
            calls: vec![],
            called_by: vec![0x2000, 0x3000],
            module: "libc".into(),
            is_noreturn: false,
            is_thunk: false,
            tags: vec![],
            comment: None,
            type_id: None,
        });

        g.add_function(FunctionNode {
            address: 0x2000,
            name: "parse_header".into(),
            size: 512,
            calling_conv: CallingConvention::Cdecl,
            has_loop: true,
            complexity: 18,
            calls: vec![0x1000, 0x4000],
            called_by: vec![0x5000],
            module: "main".into(),
            is_noreturn: false,
            is_thunk: false,
            tags: vec!["crypto".into()],
            comment: Some("Parses the file header and allocates buffer".into()),
            type_id: None,
        });

        g.add_function(FunctionNode {
            address: 0x3000,
            name: "memcpy".into(),
            size: 64,
            calling_conv: CallingConvention::Cdecl,
            has_loop: true,
            complexity: 3,
            calls: vec![],
            called_by: vec![0x2000],
            module: "libc".into(),
            is_noreturn: false,
            is_thunk: false,
            tags: vec![],
            comment: None,
            type_id: None,
        });

        g.add_function(FunctionNode {
            address: 0x4000,
            name: "memcpy_wrapper".into(),
            size: 48,
            calling_conv: CallingConvention::Cdecl,
            has_loop: false,
            complexity: 2,
            calls: vec![0x3000],
            called_by: vec![0x2000],
            module: "main".into(),
            is_noreturn: false,
            is_thunk: true,
            tags: vec![],
            comment: None,
            type_id: None,
        });

        g.add_function(FunctionNode {
            address: 0x5000,
            name: "main".into(),
            size: 1024,
            calling_conv: CallingConvention::Cdecl,
            has_loop: false,
            complexity: 12,
            calls: vec![0x2000],
            called_by: vec![],
            module: "main".into(),
            is_noreturn: false,
            is_thunk: false,
            tags: vec![],
            comment: None,
            type_id: None,
        });

        g.add_symbol(SymbolNode {
            address: 0x1000,
            name: "malloc".into(),
            demangled_name: None,
            kind: SymbolKind::Import,
            source: SymbolSource::Import,
            module: "libc".into(),
            size: 0,
            type_id: None,
        });

        g.add_string(StringNode {
            address: 0x8000,
            value: "Error: invalid header magic".into(),
            encoding: StringEncoding::Ascii,
            referenced_by: vec![0x2000],
            length: 28,
        });

        g.add_type(TypeNode {
            type_id: 1,
            name: "FileHeader".into(),
            size: 64,
            fields: vec![
                TypeField { name: "magic".into(), type_id: 2, offset: 0 },
                TypeField { name: "version".into(), type_id: 3, offset: 4 },
                TypeField { name: "size".into(), type_id: 3, offset: 8 },
            ],
            is_pointer: false,
            pointee_type_id: None,
        });

        g
    }

    #[test]
    fn test_function_query_by_name() {
        let g = make_graph();
        let engine = QueryEngine::new(g);
        let results = QueryBuilder::functions()
            .name_contains("malloc")
            .collect(&engine);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "malloc");
    }

    #[test]
    fn test_function_query_has_loop() {
        let g = make_graph();
        let engine = QueryEngine::new(g);
        let results = QueryBuilder::functions()
            .has_loop(true)
            .collect(&engine);
        assert_eq!(results.len(), 2); // parse_header + memcpy
    }

    #[test]
    fn test_function_query_complexity() {
        let g = make_graph();
        let engine = QueryEngine::new(g);
        let results = QueryBuilder::functions()
            .complexity_min(10)
            .collect(&engine);
        assert!(results.iter().all(|f| f.complexity >= 10));
    }

    #[test]
    fn test_function_query_calling() {
        let g = make_graph();
        let engine = QueryEngine::new(g);
        let results = QueryBuilder::functions()
            .calling("malloc")
            .collect(&engine);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "parse_header");
    }

    #[test]
    fn test_path_query() {
        let g = make_graph();
        let engine = QueryEngine::new(g);
        let paths = QueryBuilder::paths(0x5000, 0x3000)
            .max_depth(5)
            .collect(&engine);
        assert!(!paths.is_empty());
        let first = &paths[0];
        assert_eq!(*first.nodes.first().unwrap(), 0x5000);
        assert_eq!(*first.nodes.last().unwrap(), 0x3000);
    }

    #[test]
    fn test_traverse_bfs() {
        let g = make_graph();
        let engine = QueryEngine::new(g);
        let reachable = QueryBuilder::traverse(0x5000)
            .forward()
            .max_depth(3)
            .bfs()
            .collect(&engine);
        let addrs: HashSet<Addr> = reachable.iter().map(|f| f.address).collect();
        assert!(addrs.contains(&0x2000));
        assert!(addrs.contains(&0x1000));
    }

    #[test]
    fn test_full_text_search() {
        let g = make_graph();
        let engine = QueryEngine::new(g);
        let res = engine.full_text_search("header");
        assert!(!res.is_empty());
        assert!(res.function_addresses.contains(&0x2000));
        assert!(res.string_addresses.contains(&0x8000));
        assert!(res.type_ids.contains(&1));
    }

    #[test]
    fn test_sql_parse() {
        let sql = "SELECT functions WHERE name LIKE '%crypt%' AND calls_count > 5";
        let parsed = parse_sql(sql).unwrap();
        assert_eq!(parsed.table, SqlTable::Functions);
        assert!(!parsed.conditions.is_empty());
    }

    #[test]
    fn test_sql_execute() {
        let g = make_graph();
        let engine = QueryEngine::new(g);
        let result = QueryBuilder::sql(
            "SELECT functions WHERE name LIKE '%parse%'",
        )
        .execute(&engine);
        match result {
            QueryResult::Functions(fns) => {
                assert!(fns.iter().any(|f| f.name.contains("parse")));
            }
            _ => panic!("expected Functions"),
        }
    }

    #[test]
    fn test_data_flow_query() {
        let g = make_graph();
        let engine = QueryEngine::new(g);
        let paths = QueryBuilder::data_flow("malloc", "memcpy")
            .collect(&engine);
        // parse_header calls malloc and indirectly leads to memcpy via memcpy_wrapper.
        assert!(!paths.is_empty());
    }

    #[test]
    fn test_glob_match() {
        assert!(glob_match("*crypt*", "decrypt_xor"));
        assert!(glob_match("malloc", "malloc"));
        assert!(!glob_match("malloc", "calloc"));
        assert!(glob_match("sub_???", "sub_100"));
        assert!(glob_match("sub_*", "sub_12345"));
    }
}
