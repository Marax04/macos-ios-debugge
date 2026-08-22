// interprocedural.rs â€” Interprocedural type propagation for RustRE
// Performs bottom-up analysis over the call graph to infer and propagate
// type information across function boundaries, global variables, and
// struct fields. Converges via fixed-point iteration.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use petgraph::algo::tarjan_scc;
use petgraph::graph::DiGraph;

// ---------------------------------------------------------------------------
// Core type representation used throughout IPA
// ---------------------------------------------------------------------------

/// A type fact produced by IPA â€” may be concrete, inferred, or partially known.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum IpaType {
    #[default]
    /// Unknown / not yet inferred.
    Unknown,
    /// Void / no value.
    Void,
    /// Boolean (i1).
    Bool,
    /// Unsigned integer of given bit width.
    UInt(u32),
    /// Signed integer of given bit width.
    SInt(u32),
    /// Floating-point of given bit width (32 or 64).
    Float(u32),
    /// Raw pointer to a type.
    Pointer(Box<Self>),
    /// Array of N elements of given type.
    Array(Box<Self>, u64),
    /// Struct by name (resolved in type table).
    Struct(String),
    /// Function pointer: (param types, return type).
    FunctionPointer(Vec<Self>, Box<Self>),
    /// Union type â€” multiple possible types at the same location.
    Union(Vec<Self>),
    /// A named typedef alias.
    Typedef(String, Box<Self>),
}

impl IpaType {
    /// Returns true when this type carries no useful information.
    #[must_use] 
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }

    /// Returns true when this is a pointer type.
    #[must_use] 
    pub const fn is_pointer(&self) -> bool {
        matches!(self, Self::Pointer(_))
    }

    /// Unwrap one level of pointer indirection, returning the pointee type.
    #[must_use] 
    pub fn deref(&self) -> Option<&Self> {
        if let Self::Pointer(inner) = self {
            Some(inner)
        } else {
            None
        }
    }

    /// Compute the least-upper-bound (join) of two types.
    /// Returns `Unknown` when the types are incompatible.
    #[must_use] 
    pub fn join(&self, other: &Self) -> Self {
        if self == other {
            return self.clone();
        }
        match (self, other) {
            (Self::Unknown, t) | (t, Self::Unknown) => t.clone(),
            (Self::Pointer(a), Self::Pointer(b)) => {
                Self::Pointer(Box::new(a.join(b)))
            }
            (Self::Array(a, n), Self::Array(b, m)) if n == m => {
                Self::Array(Box::new(a.join(b)), *n)
            }
            // Fall back to a *canonical* union: flatten nested unions, drop
            // Unknown, sort and dedup the variants. This makes `join`
            // idempotent and absorbing (join(j, x) == j for j = join(x, y)),
            // which is required for the IPA fixpoint loops to converge:
            // the old `Union(vec![a, b])` wrapped the previous result in a
            // fresh Union every iteration, so summaries "changed" forever
            // (until max_iterations) and the variant order depended on join
            // order.
            (a, b) => {
                let mut variants: Vec<Self> = Vec::new();
                for t in [a, b] {
                    match t {
                        Self::Union(vs) => variants.extend(vs.iter().cloned()),
                        Self::Unknown => {}
                        other => variants.push(other.clone()),
                    }
                }
                variants.sort_unstable();
                variants.dedup();
                match variants.len() {
                    0 => Self::Unknown,
                    1 => variants.pop().unwrap(),
                    _ => Self::Union(variants),
                }
            }
        }
    }

    /// Bit-width in bits, if known and applicable.
    #[must_use] 
    pub const fn bit_width(&self) -> Option<u32> {
        match self {
            Self::Bool => Some(1),
            Self::UInt(w) | Self::SInt(w) | Self::Float(w) => Some(*w),
            Self::Pointer(_) => Some(64), // assume 64-bit
            _ => None,
        }
    }

    /// Byte size, if statically known.
    #[must_use]
    pub fn byte_size(&self) -> Option<u64> {
        self.bit_width().map(|w| u64::from(w).div_ceil(8))
    }

    /// Convert this IPA type into the crate-level [`crate::TypeFact`] lattice
    /// used by the live propagation path (`TypeEnvironment` / `TypePropagator`).
    ///
    /// Lossy where the lattices differ: `Void` has no `TypeFact` counterpart
    /// (maps to `Unknown`), named structs lose their name (field layout is not
    /// tracked here), and function pointers degrade to an opaque pointer.
    #[must_use]
    pub fn to_type_fact(&self) -> crate::TypeFact {
        use crate::TypeFact as TF;
        match self {
            Self::Unknown | Self::Void => TF::Unknown,
            Self::Bool => TF::Bool,
            Self::UInt(w) => TF::UnsignedInt((*w as usize).div_ceil(8)),
            Self::SInt(w) => TF::SignedInt((*w as usize).div_ceil(8)),
            Self::Float(w) => TF::Float((*w as usize).div_ceil(8)),
            Self::Pointer(inner) => TF::Pointer(Box::new(inner.to_type_fact())),
            Self::Array(elem, n) => TF::Array {
                element: Box::new(elem.to_type_fact()),
                length: usize::try_from(*n).ok(),
            },
            Self::Struct(_) => TF::Struct { fields: Vec::new() },
            Self::FunctionPointer(_, _) => TF::Pointer(Box::new(TF::Unknown)),
            Self::Union(variants) => {
                // Join of the converted variants; conflicting facts widen to
                // Unknown, matching TypeFact lattice semantics.
                let mut it = variants.iter().map(Self::to_type_fact);
                let first = it.next().unwrap_or(TF::Unknown);
                it.fold(first, |acc, t| acc.join(&t))
            }
            Self::Typedef(_, inner) => inner.to_type_fact(),
        }
    }
}

impl fmt::Display for IpaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "?"),
            Self::Void => write!(f, "void"),
            Self::Bool => write!(f, "bool"),
            Self::UInt(w) => write!(f, "u{w}"),
            Self::SInt(w) => write!(f, "i{w}"),
            Self::Float(32) => write!(f, "f32"),
            Self::Float(64) => write!(f, "f64"),
            Self::Float(w) => write!(f, "f{w}"),
            Self::Pointer(inner) => write!(f, "*{inner}"),
            Self::Array(elem, n) => write!(f, "[{elem}; {n}]"),
            Self::Struct(name) => write!(f, "struct {name}"),
            Self::FunctionPointer(params, ret) => {
                write!(f, "fn(")?;
                for (i, p) in params.iter().enumerate() {
                    if i > 0 { write!(f, ", ")?; }
                    write!(f, "{p}")?;
                }
                write!(f, ") -> {ret}")
            }
            Self::Union(variants) => {
                write!(f, "(")?;
                for (i, v) in variants.iter().enumerate() {
                    if i > 0 { write!(f, " | ")?; }
                    write!(f, "{v}")?;
                }
                write!(f, ")")
            }
            Self::Typedef(name, _) => write!(f, "{name}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Address / identifier types
// ---------------------------------------------------------------------------

/// Virtual address.
pub type Addr = u64;
/// A function identifier (address of function entry).
pub type FuncId = u64;
/// Index of a parameter within a function (0-based).
pub type ParamIdx = usize;
/// A struct field by (`struct_name`, `field_offset_bytes`).
pub type FieldKey = (String, u64);

// ---------------------------------------------------------------------------
// Type facts
// ---------------------------------------------------------------------------

/// A single typed assertion produced or consumed by IPA.
#[derive(Clone, Debug)]
pub struct TypeFact {
    pub source: TypeFactSource,
    pub ty: IpaType,
    pub confidence: f32, // 0.0 â€“ 1.0
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeFactSource {
    LibraryAnnotation,
    UsagePattern,
    ReturnPropagation,
    ParameterPropagation,
    FieldAccess,
    GlobalAccess,
    CallSite,
    UserAnnotation,
}

// ---------------------------------------------------------------------------
// Function type summary
// ---------------------------------------------------------------------------

/// Summarises the inferred type signature of a single function.
#[derive(Clone, Debug, Default)]
pub struct FuncTypeSummary {
    pub func_id: FuncId,
    pub name: String,
    /// Inferred return type.
    pub return_type: IpaType,
    /// Parameter types (index â†’ type).
    pub param_types: Vec<IpaType>,
    /// For each parameter that is a pointer to a struct, which fields are
    /// accessed and with what type (offset â†’ type).
    pub param_field_accesses: HashMap<ParamIdx, HashMap<u64, IpaType>>,
    /// Indicates whether the summary has been finalised in this iteration.
    pub is_stable: bool,
}

impl FuncTypeSummary {
    pub fn new(func_id: FuncId, name: impl Into<String>, num_params: usize) -> Self {
        Self {
            func_id,
            name: name.into(),
            return_type: IpaType::Unknown,
            param_types: vec![IpaType::Unknown; num_params],
            param_field_accesses: HashMap::new(),
            is_stable: false,
        }
    }

    /// Merge information from `other` into `self`. Returns true if anything changed.
    pub fn merge(&mut self, other: &Self) -> bool {
        let mut changed = false;

        let new_ret = self.return_type.join(&other.return_type);
        if new_ret != self.return_type {
            self.return_type = new_ret;
            changed = true;
        }

        // Grow param list if needed.
        if other.param_types.len() > self.param_types.len() {
            self.param_types.resize(other.param_types.len(), IpaType::Unknown);
            changed = true;
        }
        for (i, ot) in other.param_types.iter().enumerate() {
            let joined = self.param_types[i].join(ot);
            if joined != self.param_types[i] {
                self.param_types[i] = joined;
                changed = true;
            }
        }

        // Merge field accesses.
        for (param_idx, fields) in &other.param_field_accesses {
            let entry = self.param_field_accesses.entry(*param_idx).or_default();
            for (offset, ty) in fields {
                let current = entry.entry(*offset).or_insert(IpaType::Unknown);
                let joined = current.join(ty);
                if joined != *current {
                    *current = joined;
                    changed = true;
                }
            }
        }

        changed
    }
}

// ---------------------------------------------------------------------------
// Call graph
// ---------------------------------------------------------------------------

/// A directed call graph edge.
#[derive(Clone, Debug)]
pub struct CallEdge {
    pub caller: FuncId,
    pub callee: FuncId,
    /// Address of the call instruction.
    pub call_site: Addr,
    /// Argument types as seen at the call site.
    pub arg_types: Vec<IpaType>,
    /// What the return value is assigned to / how it is used.
    pub return_use: ReturnUse,
}

#[derive(Clone, Debug)]
pub enum ReturnUse {
    /// Return value is discarded.
    Discarded,
    /// Return value assigned to a variable (identified by SSA name or address).
    AssignedTo(String),
    /// Return value passed directly as argument N to another call.
    PassedAsArg(FuncId, ParamIdx),
    /// Return value compared.
    Compared,
    /// Return value returned from the caller itself.
    Returned,
}

/// Call graph: per-function outgoing edges and incoming edges.
#[derive(Default)]
pub struct CallGraph {
    pub functions: HashMap<FuncId, FuncInfo>,
    pub outgoing: HashMap<FuncId, Vec<CallEdge>>,
    pub incoming: HashMap<FuncId, Vec<CallEdge>>,
}

#[derive(Clone, Debug)]
pub struct FuncInfo {
    pub id: FuncId,
    pub name: String,
    pub num_params: usize,
    /// True for external/library functions with known signatures.
    pub is_library: bool,
}

impl CallGraph {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_function(&mut self, info: FuncInfo) {
        self.outgoing.entry(info.id).or_default();
        self.incoming.entry(info.id).or_default();
        self.functions.insert(info.id, info);
    }

    pub fn add_edge(&mut self, edge: CallEdge) {
        self.incoming.entry(edge.callee).or_default().push(edge.clone());
        self.outgoing.entry(edge.caller).or_default().push(edge);
    }

    /// Build a `petgraph::DiGraph` representation of this call graph.
    ///
    /// Node weights are `FuncId`; edge weights are the callee `FuncId` (unused
    /// by the algorithms but kept for debugging).  Returns the graph together
    /// with a mapping from `FuncId` to petgraph `NodeIndex`.
    fn to_petgraph(&self) -> (DiGraph<FuncId, ()>, HashMap<FuncId, petgraph::graph::NodeIndex>) {
        let mut g: DiGraph<FuncId, ()> = DiGraph::new();
        let mut node_map: HashMap<FuncId, petgraph::graph::NodeIndex> = HashMap::new();
        // Determinism: `self.functions`/`self.outgoing` are HashMaps whose
        // iteration order is randomized per run. The order in which nodes and
        // edges are inserted into the petgraph is observable through
        // `tarjan_scc` (node-index discovery order + neighbor order), so both
        // `sccs()` and `bottom_up_order()` would otherwise be nondeterministic.
        // Insert nodes and edges in ascending `FuncId` order.
        let mut ids: Vec<FuncId> = self.functions.keys().copied().collect();
        ids.sort_unstable();
        for id in ids {
            let nx = g.add_node(id);
            node_map.insert(id, nx);
        }
        let mut callers: Vec<FuncId> = self.outgoing.keys().copied().collect();
        callers.sort_unstable();
        for caller in callers {
            let edges = &self.outgoing[&caller];
            if let Some(&caller_nx) = node_map.get(&caller) {
                let mut callees: Vec<FuncId> = edges.iter().map(|e| e.callee).collect();
                callees.sort_unstable();
                for callee in callees {
                    if let Some(&callee_nx) = node_map.get(&callee) {
                        g.add_edge(caller_nx, callee_nx, ());
                    }
                }
            }
        }
        (g, node_map)
    }

    /// Topological sort (bottom-up: callees before callers).
    ///
    /// Uses `petgraph::algo::tarjan_scc` which returns SCCs in reverse
    /// topological order (leaves first).  We flatten the SCCs and collect
    /// `FuncId`s in that order, giving us a bottom-up traversal even in the
    /// presence of cycles.
    ///
    /// # Panics
    ///
    /// Panics if a node index has no associated weight (internal graph invariant).
    #[must_use]
    pub fn bottom_up_order(&self) -> Vec<FuncId> {
        let (g, _) = self.to_petgraph();
        // tarjan_scc returns SCCs in reverse topological order (leaves first).
        tarjan_scc(&g)
            .into_iter()
            .flat_map(|scc| scc.into_iter().map(|nx| *g.node_weight(nx).unwrap()))
            .collect()
    }

    /// Compute strongly connected components using `petgraph::algo::tarjan_scc`.
    ///
    /// Returns one `Vec<FuncId>` per SCC.  The order within each SCC is
    /// unspecified.  SCCs are returned in reverse topological order (leaf SCCs
    /// first).
    ///
    /// # Panics
    ///
    /// Panics if a node index has no associated weight (internal graph invariant).
    #[must_use]
    pub fn sccs(&self) -> Vec<Vec<FuncId>> {
        let (g, _) = self.to_petgraph();
        tarjan_scc(&g)
            .into_iter()
            .map(|scc| {
                scc.into_iter()
                    .map(|nx| *g.node_weight(nx).unwrap())
                    .collect()
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Library signature database
// ---------------------------------------------------------------------------

/// Known signatures for standard library / OS functions.
pub struct LibrarySignatureDb {
    signatures: HashMap<String, LibrarySig>,
}

#[derive(Clone, Debug)]
pub struct LibrarySig {
    pub name: String,
    pub return_type: IpaType,
    pub param_types: Vec<IpaType>,
    pub is_variadic: bool,
}

impl Default for LibrarySignatureDb {
    fn default() -> Self {
        Self::new()
    }
}

impl LibrarySignatureDb {
    #[must_use] 
    pub fn new() -> Self {
        let mut db = Self {
            signatures: HashMap::new(),
        };
        db.populate_libc();
        db.populate_posix();
        db.populate_windows();
        // Level 7: the mingw-w64 / libgcc runtime the corpus is actually full
        // of. Added last so a hand-curated entry above is never overwritten by
        // a mechanically extracted one.
        db.populate_mingw_runtime();
        db
    }

    pub(crate) fn add(&mut self, name: &str, ret: IpaType, params: Vec<IpaType>, variadic: bool) {
        self.signatures.insert(name.to_string(), LibrarySig {
            name: name.to_string(),
            return_type: ret,
            param_types: params,
            is_variadic: variadic,
        });
    }

    fn populate_libc(&mut self) {
        let void_ptr = IpaType::Pointer(Box::new(IpaType::Void));
        let char_ptr = IpaType::Pointer(Box::new(IpaType::SInt(8)));
        let size_t = IpaType::UInt(64);
        let i32 = IpaType::SInt(32);
        let i64 = IpaType::SInt(64);

        // Memory
        self.add("memcpy",  void_ptr.clone(),
            vec![void_ptr.clone(), void_ptr.clone(), size_t.clone()], false);
        self.add("memmove", void_ptr.clone(),
            vec![void_ptr.clone(), void_ptr.clone(), size_t.clone()], false);
        self.add("memset",  void_ptr.clone(),
            vec![void_ptr.clone(), i32.clone(), size_t.clone()], false);
        self.add("memcmp",  i32.clone(),
            vec![void_ptr.clone(), void_ptr.clone(), size_t.clone()], false);
        self.add("malloc",  void_ptr.clone(), vec![size_t.clone()], false);
        self.add("calloc",  void_ptr.clone(), vec![size_t.clone(), size_t.clone()], false);
        self.add("realloc", void_ptr.clone(), vec![void_ptr.clone(), size_t.clone()], false);
        self.add("free",    IpaType::Void,   vec![void_ptr.clone()], false);

        // String
        self.add("strcmp",   i32.clone(), vec![char_ptr.clone(), char_ptr.clone()], false);
        self.add("strncmp",  i32.clone(), vec![char_ptr.clone(), char_ptr.clone(), size_t.clone()], false);
        self.add("strcpy",   char_ptr.clone(), vec![char_ptr.clone(), char_ptr.clone()], false);
        self.add("strncpy",  char_ptr.clone(), vec![char_ptr.clone(), char_ptr.clone(), size_t.clone()], false);
        self.add("strlen",   size_t.clone(), vec![char_ptr.clone()], false);
        self.add("strcat",   char_ptr.clone(), vec![char_ptr.clone(), char_ptr.clone()], false);
        self.add("strchr",   char_ptr.clone(), vec![char_ptr.clone(), i32.clone()], false);
        self.add("strstr",   char_ptr.clone(), vec![char_ptr.clone(), char_ptr.clone()], false);

        // I/O
        self.add("printf",  i32.clone(), vec![char_ptr.clone()], true);
        self.add("fprintf", i32.clone(), vec![void_ptr.clone(), char_ptr.clone()], true);
        self.add("sprintf", i32.clone(), vec![char_ptr.clone(), char_ptr.clone()], true);
        self.add("snprintf",i32.clone(), vec![char_ptr.clone(), size_t.clone(), char_ptr.clone()], true);
        self.add("scanf",   i32.clone(), vec![char_ptr.clone()], true);
        self.add("sscanf",  i32.clone(), vec![char_ptr.clone(), char_ptr.clone()], true);
        self.add("fopen",   void_ptr.clone(), vec![char_ptr.clone(), char_ptr.clone()], false);
        self.add("fclose",  i32.clone(),  vec![void_ptr.clone()], false);
        self.add("fread",   size_t.clone(), vec![void_ptr.clone(), size_t.clone(), size_t.clone(), void_ptr.clone()], false);
        self.add("fwrite",  size_t.clone(), vec![void_ptr.clone(), size_t.clone(), size_t, void_ptr.clone()], false);
        self.add("fgets",   char_ptr.clone(), vec![char_ptr.clone(), i32.clone(), void_ptr.clone()], false);
        self.add("fputs",   i32.clone(),  vec![char_ptr.clone(), void_ptr], false);

        // Math
        self.add("abs",   i32.clone(), vec![i32.clone()], false);
        self.add("labs",  i64.clone(), vec![i64.clone()], false);
        self.add("atoi",  i32.clone(), vec![char_ptr.clone()], false);
        self.add("atol",  i64.clone(), vec![char_ptr.clone()], false);
        self.add("atof",  IpaType::Float(64), vec![char_ptr.clone()], false);
        self.add("strtol",i64,
            vec![char_ptr.clone(), IpaType::Pointer(Box::new(char_ptr)), i32.clone()], false);
        self.add("exit",  IpaType::Void, vec![i32], false);
        self.add("abort", IpaType::Void, vec![], false);
    }

    fn populate_posix(&mut self) {
        let void_ptr = IpaType::Pointer(Box::new(IpaType::Void));
        let char_ptr = IpaType::Pointer(Box::new(IpaType::SInt(8)));
        let i32 = IpaType::SInt(32);
        let i64 = IpaType::SInt(64);
        let size_t = IpaType::UInt(64);

        self.add("open",    i32.clone(), vec![char_ptr.clone(), i32.clone()], true);
        self.add("close",   i32.clone(), vec![i32.clone()], false);
        self.add("read",    i64.clone(), vec![i32.clone(), void_ptr.clone(), size_t.clone()], false);
        self.add("write",   i64.clone(), vec![i32.clone(), void_ptr.clone(), size_t.clone()], false);
        self.add("lseek",   i64.clone(), vec![i32.clone(), i64.clone(), i32.clone()], false);
        self.add("mmap",    void_ptr.clone(),
            vec![void_ptr.clone(), size_t.clone(), i32.clone(), i32.clone(), i32.clone(), i64], false);
        self.add("munmap",  i32.clone(), vec![void_ptr.clone(), size_t], false);
        self.add("getenv",  char_ptr.clone(), vec![char_ptr.clone()], false);
        self.add("putenv",  i32.clone(), vec![char_ptr.clone()], false);
        self.add("fork",    i32.clone(), vec![], false);
        self.add("waitpid", i32.clone(), vec![i32.clone(), IpaType::Pointer(Box::new(i32.clone())), i32.clone()], false);
        self.add("execve",  i32.clone(),
            vec![char_ptr.clone(),
                 IpaType::Pointer(Box::new(char_ptr.clone())),
                 IpaType::Pointer(Box::new(char_ptr))], false);
        self.add("pthread_create", i32.clone(),
            vec![void_ptr.clone(), void_ptr.clone(),
                 IpaType::FunctionPointer(vec![void_ptr.clone()], Box::new(void_ptr.clone())),
                 void_ptr.clone()], false);
        self.add("pthread_join",   i32.clone(),
            vec![IpaType::UInt(64), IpaType::Pointer(Box::new(void_ptr.clone()))], false);
        self.add("pthread_mutex_lock",   i32.clone(), vec![void_ptr.clone()], false);
        self.add("pthread_mutex_unlock", i32, vec![void_ptr], false);
    }

    fn populate_windows(&mut self) {
        let void_ptr = IpaType::Pointer(Box::new(IpaType::Void));
        let char_ptr = IpaType::Pointer(Box::new(IpaType::SInt(8)));
        let wchar_ptr = IpaType::Pointer(Box::new(IpaType::UInt(16)));
        let i32 = IpaType::SInt(32);
        let u32 = IpaType::UInt(32);
        let u64 = IpaType::UInt(64);
        let bool_t = IpaType::Bool;

        self.add("VirtualAlloc",
            void_ptr.clone(),
            vec![void_ptr.clone(), u64.clone(), u32.clone(), u32.clone()], false);
        self.add("VirtualFree",
            bool_t.clone(),
            vec![void_ptr.clone(), u64.clone(), u32.clone()], false);
        self.add("VirtualProtect",
            bool_t.clone(),
            vec![void_ptr.clone(), u64.clone(), u32.clone(),
                 IpaType::Pointer(Box::new(u32.clone()))], false);
        self.add("HeapAlloc",   void_ptr.clone(),
            vec![void_ptr.clone(), u32.clone(), u64.clone()], false);
        self.add("HeapFree",    bool_t.clone(),
            vec![void_ptr.clone(), u32.clone(), void_ptr.clone()], false);
        self.add("CreateFileW", void_ptr.clone(),
            vec![wchar_ptr.clone(), u32.clone(), u32.clone(), void_ptr.clone(),
                 u32.clone(), u32.clone(), void_ptr.clone()], false);
        self.add("ReadFile",    bool_t.clone(),
            vec![void_ptr.clone(), void_ptr.clone(), u32.clone(),
                 IpaType::Pointer(Box::new(u32.clone())), void_ptr.clone()], false);
        self.add("WriteFile",   bool_t.clone(),
            vec![void_ptr.clone(), void_ptr.clone(), u32.clone(),
                 IpaType::Pointer(Box::new(u32.clone())), void_ptr.clone()], false);
        self.add("CloseHandle", bool_t, vec![void_ptr.clone()], false);
        self.add("LoadLibraryA", void_ptr.clone(), vec![char_ptr.clone()], false);
        self.add("LoadLibraryW", void_ptr.clone(), vec![wchar_ptr], false);
        self.add("GetProcAddress", void_ptr.clone(),
            vec![void_ptr.clone(), char_ptr.clone()], false);
        self.add("GetLastError", u32.clone(), vec![], false);
        self.add("SetLastError", IpaType::Void, vec![u32.clone()], false);
        self.add("CreateThread", void_ptr.clone(),
            vec![void_ptr.clone(), u64,
                 IpaType::FunctionPointer(vec![void_ptr.clone()], Box::new(u32.clone())),
                 void_ptr.clone(), u32.clone(),
                 IpaType::Pointer(Box::new(u32.clone()))], false);
        self.add("WaitForSingleObject",
            u32.clone(), vec![void_ptr.clone(), u32.clone()], false);
        self.add("RegOpenKeyExA", i32.clone(),
            vec![void_ptr.clone(), char_ptr.clone(), u32.clone(), u32.clone(),
                 IpaType::Pointer(Box::new(void_ptr.clone()))], false);
        self.add("RegQueryValueExA", i32,
            vec![void_ptr.clone(), char_ptr, void_ptr,
                 IpaType::Pointer(Box::new(u32.clone())),
                 IpaType::Pointer(Box::new(IpaType::UInt(8))),
                 IpaType::Pointer(Box::new(u32))], false);
    }

    #[must_use] 
    pub fn lookup(&self, name: &str) -> Option<&LibrarySig> {
        self.signatures.get(name)
    }

    #[must_use] 
    pub fn contains(&self, name: &str) -> bool {
        self.signatures.contains_key(name)
    }

    pub fn all_names(&self) -> impl Iterator<Item = &str> {
        self.signatures.keys().map(String::as_str)
    }
}

// ---------------------------------------------------------------------------
// Global variable type tracker
// ---------------------------------------------------------------------------

/// Tracks type information for global variables across all access points.
#[derive(Default)]
pub struct GlobalVarTypeTracker {
    /// Collected type facts per global address.
    facts: HashMap<Addr, Vec<TypeFact>>,
    /// Resolved type per global address (after inference).
    resolved: HashMap<Addr, IpaType>,
    /// Optional name for each global.
    names: HashMap<Addr, String>,
}

impl GlobalVarTypeTracker {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_access(&mut self, addr: Addr, ty: IpaType, source: TypeFactSource, confidence: f32) {
        self.facts.entry(addr).or_default().push(TypeFact { source, ty, confidence });
    }

    pub fn set_name(&mut self, addr: Addr, name: impl Into<String>) {
        self.names.insert(addr, name.into());
    }

    /// Infer the best type for each global from collected facts.
    /// Returns true if any type changed.
    pub fn resolve_types(&mut self) -> bool {
        let mut changed = false;
        for (addr, facts) in &self.facts {
            if facts.is_empty() {
                continue;
            }
            // Sort by confidence descending, then join. Sorting first makes
            // the result independent of the order facts were recorded in:
            // previously, a high-confidence fact recorded *after* others
            // replaced (discarded) the joined result, while the same fact
            // recorded first was joined with the rest.
            let mut ordered: Vec<&TypeFact> = facts.iter().collect();
            ordered.sort_by(|a, b| {
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.ty.cmp(&b.ty))
            });
            let mut best: IpaType = IpaType::Unknown;
            let mut best_conf = 0.0f32;
            for fact in ordered {
                if fact.confidence > best_conf || best.is_unknown() {
                    best = fact.ty.clone();
                    best_conf = fact.confidence;
                } else {
                    best = best.join(&fact.ty);
                }
            }
            let old = self.resolved.get(addr).cloned().unwrap_or(IpaType::Unknown);
            if old != best {
                self.resolved.insert(*addr, best);
                changed = true;
            }
        }
        changed
    }

    #[must_use] 
    pub fn get_type(&self, addr: Addr) -> &IpaType {
        self.resolved.get(&addr).unwrap_or(&IpaType::Unknown)
    }

    pub fn all_globals(&self) -> impl Iterator<Item = (&Addr, &IpaType)> {
        self.resolved.iter()
    }
}

// ---------------------------------------------------------------------------
// Struct field type database
// ---------------------------------------------------------------------------

/// Tracks inferred types for struct fields, keyed by (`struct_name`, `field_offset`).
#[derive(Default)]
pub struct StructFieldTypeDb {
    fields: HashMap<FieldKey, Vec<IpaType>>,
    resolved: HashMap<FieldKey, IpaType>,
    field_names: HashMap<FieldKey, String>,
}

impl StructFieldTypeDb {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_field_fact(&mut self, struct_name: impl Into<String>, offset: u64, ty: IpaType) {
        self.fields
            .entry((struct_name.into(), offset))
            .or_default()
            .push(ty);
    }

    pub fn set_field_name(&mut self, key: FieldKey, name: impl Into<String>) {
        self.field_names.insert(key, name.into());
    }

    /// Infer field types from accumulated facts. Returns true if any changed.
    pub fn resolve(&mut self) -> bool {
        let mut changed = false;
        for (key, facts) in &self.fields {
            if facts.is_empty() {
                continue;
            }
            let joined = facts.iter().skip(1).fold(facts[0].clone(), |acc, t| acc.join(t));
            let old = self.resolved.get(key).cloned().unwrap_or(IpaType::Unknown);
            if old != joined {
                self.resolved.insert(key.clone(), joined);
                changed = true;
            }
        }
        changed
    }

    #[must_use] 
    pub fn get_field_type(&self, struct_name: &str, offset: u64) -> &IpaType {
        self.resolved
            .get(&(struct_name.to_string(), offset))
            .unwrap_or(&IpaType::Unknown)
    }

    #[must_use] 
    pub fn get_fields_of_struct(&self, struct_name: &str) -> Vec<(u64, &IpaType)> {
        // `resolved` is a HashMap: without the sort the returned field order
        // is randomized per run, which leaks into every consumer that emits
        // or compares field lists (e.g. detect_recursive_types offsets).
        let mut out: Vec<(u64, &IpaType)> = self.resolved
            .iter()
            .filter(|((s, _), _)| s == struct_name)
            .map(|((_, off), ty)| (*off, ty))
            .collect();
        out.sort_by_key(|(off, _)| *off);
        out
    }

    /// All struct names with at least one resolved field.
    #[must_use] 
    pub fn all_struct_names(&self) -> HashSet<&str> {
        self.resolved.keys().map(|(s, _)| s.as_str()).collect()
    }
}

// ---------------------------------------------------------------------------
// Call site record
// ---------------------------------------------------------------------------

/// Information at a specific call site, used to propagate types.
#[derive(Clone, Debug)]
pub struct CallSiteInfo {
    pub site_addr: Addr,
    pub caller: FuncId,
    pub callee: FuncId,
    pub arg_types: Vec<IpaType>,
    pub return_binding: Option<String>, // SSA name of LHS variable, if any
}

// ---------------------------------------------------------------------------
// IPA context â€” aggregates all data for one analysis run
// ---------------------------------------------------------------------------

pub struct IpaContext {
    pub call_graph: CallGraph,
    pub lib_db: LibrarySignatureDb,
    pub summaries: HashMap<FuncId, FuncTypeSummary>,
    pub globals: GlobalVarTypeTracker,
    pub struct_fields: StructFieldTypeDb,
    /// All call sites in the binary.
    pub call_sites: Vec<CallSiteInfo>,
    /// Variable-to-type map per function (`func_id` â†’ (`var_name` â†’ type)).
    pub var_types: HashMap<FuncId, HashMap<String, IpaType>>,
    /// Maximum number of iterations before forced convergence.
    pub max_iterations: usize,
}

impl IpaContext {
    #[must_use] 
    pub fn new(call_graph: CallGraph) -> Self {
        Self {
            call_graph,
            lib_db: LibrarySignatureDb::new(),
            summaries: HashMap::new(),
            globals: GlobalVarTypeTracker::new(),
            struct_fields: StructFieldTypeDb::new(),
            call_sites: Vec::new(),
            var_types: HashMap::new(),
            max_iterations: 64,
        }
    }

    /// Initialise summaries from library annotations and known parameter counts.
    pub fn init_summaries(&mut self) {
        for (&id, info) in &self.call_graph.functions {
            if info.is_library {
                if let Some(sig) = self.lib_db.lookup(&info.name) {
                    let mut summary = FuncTypeSummary::new(id, &info.name, sig.param_types.len());
                    summary.return_type = sig.return_type.clone();
                    sig.param_types.clone_into(&mut summary.param_types);
                    summary.is_stable = true;
                    self.summaries.insert(id, summary);
                } else {
                    let s = FuncTypeSummary::new(id, &info.name, info.num_params);
                    self.summaries.insert(id, s);
                }
            } else {
                let s = FuncTypeSummary::new(id, &info.name, info.num_params);
                self.summaries.insert(id, s);
            }
        }
    }

    /// Look up or create a summary for a function.
    pub fn get_or_create_summary(&mut self, func_id: FuncId) -> &mut FuncTypeSummary {
        let info = self.call_graph.functions.get(&func_id).cloned();
        let num_params = info.as_ref().map_or(0, |i| i.num_params);
        let name = info.map(|i| i.name).unwrap_or_default();
        self.summaries
            .entry(func_id)
            .or_insert_with(|| FuncTypeSummary::new(func_id, name, num_params))
    }
}

// ---------------------------------------------------------------------------
// Main IPA analysis
// ---------------------------------------------------------------------------

/// Interprocedural type analysis.
///
/// Runs in multiple phases:
/// 1. Apply library annotations.
/// 2. Bottom-up: infer return types and parameter types from usage within each function.
/// 3. Top-down: propagate call-site argument types and return type usage to callers.
/// 4. Global variable typing.
/// 5. Struct field propagation through function boundaries.
/// 6. Converge via fixed-point iteration.
pub struct IpaTypeAnalysis {
    pub ctx: IpaContext,
    pub iteration: usize,
}

impl IpaTypeAnalysis {
    #[must_use] 
    pub const fn new(ctx: IpaContext) -> Self {
        Self { ctx, iteration: 0 }
    }

    /// Top-level entry: run until convergence or `max_iterations`.
    pub fn run(&mut self) -> IpaResult {
        self.ctx.init_summaries();

        let mut changed = true;
        while changed && self.iteration < self.ctx.max_iterations {
            self.iteration += 1;
            changed = false;

            changed |= self.phase_bottom_up();
            changed |= self.phase_top_down();
            changed |= self.phase_global_typing();
            changed |= self.phase_struct_field_propagation();
            changed |= self.phase_call_site_propagation();
        }

        self.build_result()
    }

    // ------------------------------------------------------------------
    // Phase 1: bottom-up â€” infer from usage within functions
    // ------------------------------------------------------------------

    fn phase_bottom_up(&mut self) -> bool {
        let order = self.ctx.call_graph.bottom_up_order();
        let mut changed = false;
        for func_id in order {
            changed |= self.infer_function_summary(func_id);
        }
        changed
    }

    /// Infer the type summary for a single function from its internal usage.
    ///
    /// In a real implementation this would walk the LLIL/HLIL instruction
    /// stream. Here we encode the inference rules symbolically, leaving
    /// hooks (marked with `// HOOK: ...`) where the real IR analysis
    /// would plug in.
    fn infer_function_summary(&mut self, func_id: FuncId) -> bool {
        let info = match self.ctx.call_graph.functions.get(&func_id) {
            Some(i) => i.clone(),
            None => return false,
        };

        // Library functions are already annotated; skip.
        if info.is_library {
            return false;
        }

        // HOOK: gather_return_type_facts(func_id) â†’ Vec<IpaType>
        // This would walk all RETURN instructions in the function and collect
        // the types of the returned values.
        let return_facts: Vec<IpaType> = Self::collect_return_type_facts(func_id);
        let inferred_return = return_facts
            .iter()
            .skip(1)
            .fold(return_facts.first().cloned().unwrap_or(IpaType::Unknown),
                  |acc, t| acc.join(t));

        // HOOK: gather_param_usage_facts(func_id) â†’ Vec<Vec<IpaType>>
        // For each parameter, collect the types with which it is used.
        let param_facts: Vec<Vec<IpaType>> = Self::collect_param_usage_facts(func_id);

        let summary = self.ctx.get_or_create_summary(func_id);
        let mut changed = false;

        let new_ret = summary.return_type.join(&inferred_return);
        if new_ret != summary.return_type {
            summary.return_type = new_ret;
            changed = true;
        }

        if summary.param_types.len() < param_facts.len() {
            summary.param_types.resize(param_facts.len(), IpaType::Unknown);
            changed = true;
        }
        for (i, facts) in param_facts.iter().enumerate() {
            let joined = facts.iter().skip(1)
                .fold(facts.first().cloned().unwrap_or(IpaType::Unknown),
                      |acc, t| acc.join(t));
            let new_ty = summary.param_types[i].join(&joined);
            if new_ty != summary.param_types[i] {
                summary.param_types[i] = new_ty;
                changed = true;
            }
        }

        changed
    }

    // Stub â€” real impl would walk HLIL/LLIL return instructions.
    const fn collect_return_type_facts(_func_id: FuncId) -> Vec<IpaType> {
        // HOOK: walk IR of func_id, collect types from RETURN exprs.
        Vec::new()
    }

    // Stub â€” real impl would walk HLIL/LLIL usage of each parameter.
    const fn collect_param_usage_facts(_func_id: FuncId) -> Vec<Vec<IpaType>> {
        // HOOK: for each parameter, inspect how it is used (loads, stores,
        // arithmetic operands, passed to callee) and derive type constraints.
        Vec::new()
    }

    // ------------------------------------------------------------------
    // Phase 2: top-down â€” propagate return types to callers
    // ------------------------------------------------------------------

    fn phase_top_down(&mut self) -> bool {
        let mut changed = false;

        // Clone call sites to avoid borrow conflicts.
        let call_sites: Vec<CallSiteInfo> = self.ctx.call_sites.clone();

        for site in &call_sites {
            changed |= self.propagate_return_type_to_caller(site);
            changed |= self.propagate_arg_types_to_callee(site);
        }
        changed
    }

    /// If callee has an inferred return type T and the caller assigns the
    /// return value to variable V, then V: T in the caller's scope.
    fn propagate_return_type_to_caller(&mut self, site: &CallSiteInfo) -> bool {
        let callee_ret = self.ctx.summaries
            .get(&site.callee)
            .map_or(IpaType::Unknown, |s| s.return_type.clone());

        if callee_ret.is_unknown() {
            return false;
        }

        let binding = match &site.return_binding {
            Some(b) => b.clone(),
            None => return false,
        };

        let var_map = self.ctx.var_types.entry(site.caller).or_default();
        let current = var_map.entry(binding).or_insert(IpaType::Unknown);
        let joined = current.join(&callee_ret);
        if joined != *current {
            *current = joined;
            return true;
        }
        false
    }

    /// If caller passes a typed argument to callee parameter N, propagate
    /// that type into the callee's parameter summary.
    fn propagate_arg_types_to_callee(&mut self, site: &CallSiteInfo) -> bool {
        let mut changed = false;
        let arg_types: Vec<IpaType> = site.arg_types.clone();
        let callee = site.callee;

        let summary = self.ctx.get_or_create_summary(callee);
        if summary.param_types.len() < arg_types.len() {
            summary.param_types.resize(arg_types.len(), IpaType::Unknown);
            changed = true;
        }
        for (i, arg_ty) in arg_types.iter().enumerate() {
            if arg_ty.is_unknown() {
                continue;
            }
            let joined = summary.param_types[i].join(arg_ty);
            if joined != summary.param_types[i] {
                summary.param_types[i] = joined;
                changed = true;
            }
        }
        changed
    }

    // ------------------------------------------------------------------
    // Phase 3: global variable typing
    // ------------------------------------------------------------------

    fn phase_global_typing(&mut self) -> bool {
        // HOOK: gather_global_access_facts() would inspect all LOAD/STORE
        // instructions referencing global addresses and record type facts.
        self.ctx.globals.resolve_types()
    }

    // ------------------------------------------------------------------
    // Phase 4: struct field propagation through function boundaries
    // ------------------------------------------------------------------

    fn phase_struct_field_propagation(&mut self) -> bool {
        // For each function, if a parameter is typed as *StructX and the
        // function accesses parameter->field at offset N with type T, then
        // we record that StructX::field_at(N) has type T.
        let mut new_facts: Vec<(String, u64, IpaType)> = Vec::new();

        for (&func_id, summary) in &self.ctx.summaries {
            for (param_idx, field_accesses) in &summary.param_field_accesses {
                let param_ty = summary.param_types.get(*param_idx)
                    .cloned()
                    .unwrap_or(IpaType::Unknown);
                let struct_name = match &param_ty {
                    IpaType::Pointer(inner) => match inner.as_ref() {
                        IpaType::Struct(name) => name.clone(),
                        _ => continue,
                    },
                    _ => continue,
                };
                for (&offset, ty) in field_accesses {
                    new_facts.push((struct_name.clone(), offset, ty.clone()));
                }
                let _ = func_id; // suppress warning
            }
        }

        let mut changed = false;
        for (struct_name, offset, ty) in new_facts {
            let old_ty = self.ctx.struct_fields
                .get_field_type(&struct_name, offset).clone();
            self.ctx.struct_fields.add_field_fact(&struct_name, offset, ty.clone());
            let new_ty = old_ty.join(&ty);
            if new_ty != old_ty {
                changed = true;
            }
        }
        changed |= self.ctx.struct_fields.resolve();
        changed
    }

    // ------------------------------------------------------------------
    // Phase 5: call site propagation (explicit)
    // ------------------------------------------------------------------

    fn phase_call_site_propagation(&mut self) -> bool {
        // Propagate types from known callee summaries into the call-graph edges.
        let mut changed = false;

        let edges: Vec<CallEdge> = self.ctx.call_graph.outgoing
            .values()
            .flat_map(|v| v.iter().cloned())
            .collect();

        for edge in edges {
            // If callee return type is known, update the caller's variable.
            let callee_ret = self.ctx.summaries
                .get(&edge.callee)
                .map_or(IpaType::Unknown, |s| s.return_type.clone());

            if !callee_ret.is_unknown()
                && let ReturnUse::AssignedTo(ref var) = edge.return_use {
                    let var_map = self.ctx.var_types.entry(edge.caller).or_default();
                    let current = var_map.entry(var.clone()).or_insert(IpaType::Unknown);
                    let joined = current.join(&callee_ret);
                    if joined != *current {
                        *current = joined;
                        changed = true;
                    }
                }

            // Propagate argument types to callee parameters.
            let callee_summary = self.ctx.summaries.entry(edge.callee).or_insert_with(|| {
                let num = self.ctx.call_graph.functions.get(&edge.callee)
                    .map_or(0, |i| i.num_params);
                FuncTypeSummary::new(edge.callee, "", num)
            });
            for (i, arg_ty) in edge.arg_types.iter().enumerate() {
                if arg_ty.is_unknown() {
                    continue;
                }
                if callee_summary.param_types.len() <= i {
                    callee_summary.param_types.resize(i + 1, IpaType::Unknown);
                }
                let joined = callee_summary.param_types[i].join(arg_ty);
                if joined != callee_summary.param_types[i] {
                    callee_summary.param_types[i] = joined;
                    changed = true;
                }
            }
        }
        changed
    }

    // ------------------------------------------------------------------
    // Build the final result
    // ------------------------------------------------------------------

    fn build_result(&self) -> IpaResult {
        IpaResult {
            summaries: self.ctx.summaries.clone(),
            global_types: self.ctx.globals.resolved.clone(),
            struct_field_types: self.ctx.struct_fields.resolved.clone(),
            var_types: self.ctx.var_types.clone(),
            iterations: self.iteration,
            converged: self.iteration < self.ctx.max_iterations,
        }
    }
}

// ---------------------------------------------------------------------------
// IPA result
// ---------------------------------------------------------------------------

/// The enriched type information produced by IPA.
#[derive(Debug)]
pub struct IpaResult {
    /// Per-function type summaries.
    pub summaries: HashMap<FuncId, FuncTypeSummary>,
    /// Global variable types.
    pub global_types: HashMap<Addr, IpaType>,
    /// Struct field types: (`struct_name`, offset) â†’ type.
    pub struct_field_types: HashMap<FieldKey, IpaType>,
    /// Variable types per function.
    pub var_types: HashMap<FuncId, HashMap<String, IpaType>>,
    /// Number of iterations taken.
    pub iterations: usize,
    /// Whether the analysis converged before `max_iterations`.
    pub converged: bool,
}

impl IpaResult {
    /// Look up the inferred return type of a function.
    #[must_use] 
    pub fn return_type(&self, func_id: FuncId) -> &IpaType {
        self.summaries.get(&func_id)
            .map_or(&IpaType::Unknown, |s| &s.return_type)
    }

    /// Look up the inferred type of parameter N of a function.
    #[must_use] 
    pub fn param_type(&self, func_id: FuncId, idx: ParamIdx) -> &IpaType {
        self.summaries.get(&func_id)
            .and_then(|s| s.param_types.get(idx))
            .unwrap_or(&IpaType::Unknown)
    }

    /// Look up the inferred type of a variable within a function.
    #[must_use] 
    pub fn var_type(&self, func_id: FuncId, var: &str) -> &IpaType {
        self.var_types.get(&func_id)
            .and_then(|m| m.get(var))
            .unwrap_or(&IpaType::Unknown)
    }

    /// Look up the inferred type of a global variable at `addr`.
    #[must_use] 
    pub fn global_type(&self, addr: Addr) -> &IpaType {
        self.global_types.get(&addr).unwrap_or(&IpaType::Unknown)
    }

    /// Look up the inferred type of a struct field.
    #[must_use] 
    pub fn field_type(&self, struct_name: &str, offset: u64) -> &IpaType {
        self.struct_field_types
            .get(&(struct_name.to_string(), offset))
            .unwrap_or(&IpaType::Unknown)
    }

    /// Print a compact summary of the analysis results.
    pub fn print_summary(&self) {
        println!("=== IPA Type Analysis Result ===");
        println!("Iterations: {} (converged: {})", self.iterations, self.converged);
        println!("\n--- Function Summaries ({}) ---", self.summaries.len());
        let mut funcs: Vec<&FuncTypeSummary> = self.summaries.values().collect();
        funcs.sort_by_key(|s| s.func_id);
        for s in funcs {
            print!("  {:016x} {} (", s.func_id, s.name);
            for (i, p) in s.param_types.iter().enumerate() {
                if i > 0 { print!(", "); }
                print!("{p}");
            }
            println!(") -> {}", s.return_type);
        }
        println!("\n--- Global Variable Types ({}) ---", self.global_types.len());
        let mut globals: Vec<(Addr, &IpaType)> =
            self.global_types.iter().map(|(a, t)| (*a, t)).collect();
        globals.sort_by_key(|(a, _)| *a);
        for (addr, ty) in globals {
            println!("  {addr:016x}: {ty}");
        }
        println!("\n--- Struct Field Types ---");
        let mut fields: Vec<(&FieldKey, &IpaType)> = self.struct_field_types.iter().collect();
        fields.sort_by_key(|((s, o), _)| (s.as_str(), *o));
        for ((struct_name, offset), ty) in fields {
            println!("  {struct_name}+0x{offset:x}: {ty}");
        }
    }
}

// ---------------------------------------------------------------------------
// Convergence checker
// ---------------------------------------------------------------------------

/// Tracks whether the analysis state has stabilised.
pub struct ConvergenceChecker {
    prev_snapshot: Option<ConvergenceSnapshot>,
}

#[derive(Clone, Debug, PartialEq)]
struct ConvergenceSnapshot {
    summaries_hash: u64,
    globals_count: usize,
    fields_count: usize,
}

impl Default for ConvergenceChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl ConvergenceChecker {
    #[must_use] 
    pub const fn new() -> Self {
        Self { prev_snapshot: None }
    }

    /// Returns true if the analysis has converged (no change since last call).
    pub fn check(&mut self, result: &IpaResult) -> bool {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        let mut hasher = DefaultHasher::new();
        let mut funcs: Vec<_> = result.summaries.iter().collect();
        funcs.sort_by_key(|(id, _)| *id);
        for (id, summary) in &funcs {
            id.hash(&mut hasher);
            format!("{:?}", summary.return_type).hash(&mut hasher);
        }
        let h = hasher.finish();

        let snap = ConvergenceSnapshot {
            summaries_hash: h,
            globals_count: result.global_types.len(),
            fields_count: result.struct_field_types.len(),
        };

        let converged = self.prev_snapshot.as_ref() == Some(&snap);
        self.prev_snapshot = Some(snap);
        converged
    }
}

// ---------------------------------------------------------------------------
// Worklist-based IPA
// ---------------------------------------------------------------------------

/// An alternative IPA driver that uses a worklist instead of iterating
/// over all functions every round. More efficient for sparse call graphs.
pub struct WorklistIpa {
    ctx: IpaContext,
    worklist: VecDeque<FuncId>,
    in_worklist: HashSet<FuncId>,
    iteration_counts: HashMap<FuncId, usize>,
    max_per_func: usize,
}

impl WorklistIpa {
    #[must_use] 
    pub fn new(ctx: IpaContext) -> Self {
        // Determinism: `functions` is a HashMap, so `keys()` order is
        // randomized per run. The initial worklist order is observable
        // through `max_per_func` (which function hits the cap first) and
        // through `iterations`, so seed the worklist in sorted order.
        let mut all: Vec<FuncId> = ctx.call_graph.functions.keys().copied().collect();
        all.sort_unstable();
        let mut wl: VecDeque<FuncId> = VecDeque::new();
        let mut in_wl: HashSet<FuncId> = HashSet::new();
        for id in &all {
            wl.push_back(*id);
            in_wl.insert(*id);
        }
        Self {
            ctx,
            worklist: wl,
            in_worklist: in_wl,
            iteration_counts: HashMap::new(),
            max_per_func: 32,
        }
    }

    pub fn run(&mut self) -> IpaResult {
        self.ctx.init_summaries();

        while let Some(func_id) = self.worklist.pop_front() {
            self.in_worklist.remove(&func_id);

            let count = self.iteration_counts.entry(func_id).or_insert(0);
            if *count >= self.max_per_func {
                continue;
            }
            *count += 1;

            let changed = self.process_function(func_id);

            if changed {
                // Re-enqueue all callers.
                if let Some(edges) = self.ctx.call_graph.incoming.get(&func_id).cloned() {
                    for edge in edges {
                        if self.in_worklist.insert(edge.caller) {
                            self.worklist.push_back(edge.caller);
                        }
                    }
                }
                // Re-enqueue all callees (for top-down propagation).
                if let Some(edges) = self.ctx.call_graph.outgoing.get(&func_id).cloned() {
                    for edge in edges {
                        if self.in_worklist.insert(edge.callee) {
                            self.worklist.push_back(edge.callee);
                        }
                    }
                }
            }
        }

        self.build_result()
    }

    fn process_function(&mut self, func_id: FuncId) -> bool {
        let info = match self.ctx.call_graph.functions.get(&func_id) {
            Some(i) => i.clone(),
            None => return false,
        };
        if info.is_library {
            return false;
        }

        // Propagate callee return types into variable bindings within this function.
        let outgoing = self.ctx.call_graph.outgoing.get(&func_id)
            .cloned()
            .unwrap_or_default();
        let mut changed = false;

        for edge in &outgoing {
            let callee_ret = self.ctx.summaries.get(&edge.callee)
                .map_or(IpaType::Unknown, |s| s.return_type.clone());

            if let ReturnUse::AssignedTo(ref var) = edge.return_use
                && !callee_ret.is_unknown() {
                    let vm = self.ctx.var_types.entry(func_id).or_default();
                    let cur = vm.entry(var.clone()).or_insert(IpaType::Unknown);
                    let joined = cur.join(&callee_ret);
                    if joined != *cur {
                        *cur = joined;
                        changed = true;
                    }
                }
        }

        changed
    }

    fn build_result(&self) -> IpaResult {
        IpaResult {
            summaries: self.ctx.summaries.clone(),
            global_types: self.ctx.globals.resolved.clone(),
            struct_field_types: self.ctx.struct_fields.resolved.clone(),
            var_types: self.ctx.var_types.clone(),
            iterations: self.iteration_counts.values().copied().sum(),
            converged: self.worklist.is_empty(),
        }
    }
}

// ---------------------------------------------------------------------------
// Type inference statistics
// ---------------------------------------------------------------------------

/// Statistics about the quality of inferred types.
#[derive(Debug, Default)]
pub struct IpaStats {
    pub total_functions: usize,
    pub functions_with_known_return: usize,
    pub functions_with_all_params_known: usize,
    pub total_globals: usize,
    pub globals_with_known_type: usize,
    pub total_fields: usize,
    pub fields_with_known_type: usize,
    pub total_vars: usize,
    pub vars_with_known_type: usize,
}

impl IpaStats {
    #[must_use] 
    pub fn compute(result: &IpaResult) -> Self {
        let mut stats = Self::default();
        for s in result.summaries.values() {
            stats.total_functions += 1;
            if !s.return_type.is_unknown() {
                stats.functions_with_known_return += 1;
            }
            if s.param_types.iter().all(|t| !t.is_unknown()) {
                stats.functions_with_all_params_known += 1;
            }
        }
        for ty in result.global_types.values() {
            stats.total_globals += 1;
            if !ty.is_unknown() {
                stats.globals_with_known_type += 1;
            }
        }
        for ty in result.struct_field_types.values() {
            stats.total_fields += 1;
            if !ty.is_unknown() {
                stats.fields_with_known_type += 1;
            }
        }
        for vars in result.var_types.values() {
            for ty in vars.values() {
                stats.total_vars += 1;
                if !ty.is_unknown() {
                    stats.vars_with_known_type += 1;
                }
            }
        }
        stats
    }

    pub fn print(&self) {
        println!("=== IPA Statistics ===");
        println!("Functions: {}/{} known return, {}/{} all params known",
            self.functions_with_known_return, self.total_functions,
            self.functions_with_all_params_known, self.total_functions);
        println!("Globals: {}/{} typed", self.globals_with_known_type, self.total_globals);
        println!("Struct fields: {}/{} typed", self.fields_with_known_type, self.total_fields);
        println!("Variables: {}/{} typed", self.vars_with_known_type, self.total_vars);
    }
}

// ---------------------------------------------------------------------------
// Type annotation applicator
// ---------------------------------------------------------------------------

/// Applies IPA results back to an IR/annotation system.
pub struct TypeAnnotationApplicator<'a> {
    result: &'a IpaResult,
}

impl<'a> TypeAnnotationApplicator<'a> {
    #[must_use] 
    pub const fn new(result: &'a IpaResult) -> Self {
        TypeAnnotationApplicator { result }
    }

    /// Generate a map of all annotations that should be applied.
    #[must_use] 
    pub fn collect_annotations(&self) -> Vec<TypeAnnotation> {
        let mut annotations = Vec::new();

        // Determinism: `summaries`/`global_types`/`struct_field_types` are
        // HashMaps whose iteration order is randomized per run; the annotation
        // list order is observable by every consumer, so iterate in sorted
        // key order.
        let mut func_ids: Vec<&FuncId> = self.result.summaries.keys().collect();
        func_ids.sort_unstable();

        // Function signatures.
        for func_id in func_ids {
            let summary = &self.result.summaries[func_id];
            annotations.push(TypeAnnotation::FunctionReturn {
                func_id: *func_id,
                ty: summary.return_type.clone(),
            });
            for (i, ty) in summary.param_types.iter().enumerate() {
                annotations.push(TypeAnnotation::Parameter {
                    func_id: *func_id,
                    param_idx: i,
                    ty: ty.clone(),
                });
            }
        }

        // Global types (sorted by address).
        let mut global_addrs: Vec<&Addr> = self.result.global_types.keys().collect();
        global_addrs.sort_unstable();
        for addr in global_addrs {
            annotations.push(TypeAnnotation::Global {
                addr: *addr,
                ty: self.result.global_types[addr].clone(),
            });
        }

        // Struct fields (sorted by (name, offset)).
        let mut field_keys: Vec<&FieldKey> = self.result.struct_field_types.keys().collect();
        field_keys.sort_unstable();
        for key in field_keys {
            let (struct_name, offset) = key;
            let ty = &self.result.struct_field_types[key];
            annotations.push(TypeAnnotation::StructField {
                struct_name: struct_name.clone(),
                offset: *offset,
                ty: ty.clone(),
            });
        }

        annotations
    }
}

/// A single type annotation to be applied to the binary.
#[derive(Debug, Clone)]
pub enum TypeAnnotation {
    FunctionReturn { func_id: FuncId, ty: IpaType },
    Parameter { func_id: FuncId, param_idx: ParamIdx, ty: IpaType },
    Global { addr: Addr, ty: IpaType },
    StructField { struct_name: String, offset: u64, ty: IpaType },
    Variable { func_id: FuncId, var_name: String, ty: IpaType },
}

// ---------------------------------------------------------------------------
// Recursive type detection
// ---------------------------------------------------------------------------

/// Detects recursive (self-referential) struct types such as linked-list nodes.
pub fn detect_recursive_types(
    struct_fields: &StructFieldTypeDb,
) -> HashMap<String, Vec<u64>> {
    let struct_names: Vec<String> = struct_fields
        .all_struct_names()
        .into_iter()
        .map(str::to_owned)
        .collect();

    let mut recursive: HashMap<String, Vec<u64>> = HashMap::new();

    for name in &struct_names {
        let fields = struct_fields.get_fields_of_struct(name);
        for (offset, ty) in fields {
            let self_ref = match ty {
                IpaType::Pointer(inner) => match inner.as_ref() {
                    IpaType::Struct(s) => s == name,
                    _ => false,
                },
                _ => false,
            };
            if self_ref {
                recursive.entry(name.clone()).or_default().push(offset);
            }
        }
    }
    recursive
}

// ---------------------------------------------------------------------------
// Type compatibility checker
// ---------------------------------------------------------------------------

/// Checks whether two types are compatible (one can be used where the other
/// is expected), following C-style implicit conversion rules.
#[must_use] 
pub fn types_compatible(a: &IpaType, b: &IpaType) -> bool {
    if a == b {
        return true;
    }
    match (a, b) {
        (IpaType::Unknown, _) | (_, IpaType::Unknown) => true,
        (IpaType::UInt(w1) | IpaType::SInt(w1), IpaType::UInt(w2) | IpaType::SInt(w2)) => w1 == w2,
        (IpaType::Pointer(_), IpaType::Pointer(b_inner)) if matches!(b_inner.as_ref(), IpaType::Void) => true,
        (IpaType::Pointer(a_inner), IpaType::Pointer(_)) if matches!(a_inner.as_ref(), IpaType::Void) => true,
        (IpaType::Array(a_elem, _), IpaType::Pointer(b_inner)) => types_compatible(a_elem, b_inner),
        (IpaType::Pointer(a_inner), IpaType::Array(b_elem, _)) => types_compatible(a_inner, b_elem),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipatype_join_same() {
        let t = IpaType::UInt(32);
        assert_eq!(t.join(&t), IpaType::UInt(32));
    }

    #[test]
    fn test_ipatype_join_unknown() {
        let unknown = IpaType::Unknown;
        let u32 = IpaType::UInt(32);
        assert_eq!(unknown.join(&u32), IpaType::UInt(32));
        assert_eq!(u32.join(&unknown), IpaType::UInt(32));
    }

    #[test]
    fn test_ipatype_join_pointer() {
        let p1 = IpaType::Pointer(Box::new(IpaType::UInt(32)));
        let p2 = IpaType::Pointer(Box::new(IpaType::Unknown));
        let joined = p1.join(&p2);
        assert_eq!(joined, IpaType::Pointer(Box::new(IpaType::UInt(32))));
    }

    #[test]
    fn test_ipatype_to_type_fact_scalars_and_pointers() {
        use crate::TypeFact as TF;
        assert_eq!(IpaType::UInt(32).to_type_fact(), TF::UnsignedInt(4));
        assert_eq!(IpaType::SInt(64).to_type_fact(), TF::SignedInt(8));
        assert_eq!(IpaType::Float(64).to_type_fact(), TF::Float(8));
        assert_eq!(IpaType::Bool.to_type_fact(), TF::Bool);
        assert_eq!(IpaType::Void.to_type_fact(), TF::Unknown);
        assert_eq!(
            IpaType::Pointer(Box::new(IpaType::SInt(8))).to_type_fact(),
            TF::Pointer(Box::new(TF::SignedInt(1)))
        );
        assert_eq!(
            IpaType::Array(Box::new(IpaType::UInt(16)), 5).to_type_fact(),
            TF::Array { element: Box::new(TF::UnsignedInt(2)), length: Some(5) }
        );
        // Typedef unwraps; function pointer degrades to opaque pointer.
        assert_eq!(
            IpaType::Typedef("size_t".into(), Box::new(IpaType::UInt(64))).to_type_fact(),
            TF::UnsignedInt(8)
        );
        assert!(matches!(
            IpaType::FunctionPointer(vec![], Box::new(IpaType::Void)).to_type_fact(),
            TF::Pointer(_)
        ));
    }

    #[test]
    fn test_ipatype_to_type_fact_union_joins() {
        use crate::TypeFact as TF;
        // Identical variants collapse; conflicting ones widen to Unknown.
        let u = IpaType::Union(vec![IpaType::UInt(32), IpaType::Struct("S".into())]);
        assert_eq!(u.to_type_fact(), TF::Unknown);
    }

    #[test]
    fn test_ipatype_display() {
        assert_eq!(format!("{}", IpaType::UInt(32)), "u32");
        assert_eq!(format!("{}", IpaType::Pointer(Box::new(IpaType::Void))), "*void");
        assert_eq!(format!("{}", IpaType::Struct("Foo".into())), "struct Foo");
    }

    #[test]
    fn test_func_type_summary_merge() {
        let mut s1 = FuncTypeSummary::new(1, "foo", 2);
        s1.return_type = IpaType::UInt(32);
        s1.param_types = vec![IpaType::Pointer(Box::new(IpaType::Void)), IpaType::Unknown];

        let mut s2 = FuncTypeSummary::new(1, "foo", 2);
        s2.return_type = IpaType::Unknown;
        s2.param_types = vec![IpaType::Unknown, IpaType::SInt(64)];

        let changed = s1.merge(&s2);
        assert!(changed);
        assert_eq!(s1.return_type, IpaType::UInt(32));
        assert_eq!(s1.param_types[1], IpaType::SInt(64));
    }

    #[test]
    fn test_library_db_lookup() {
        let db = LibrarySignatureDb::new();
        let sig = db.lookup("memcpy").unwrap();
        assert_eq!(sig.param_types.len(), 3);
        assert!(!sig.is_variadic);

        let printf = db.lookup("printf").unwrap();
        assert!(printf.is_variadic);
    }

    #[test]
    fn test_library_db_contains() {
        let db = LibrarySignatureDb::new();
        assert!(db.contains("malloc"));
        assert!(db.contains("VirtualAlloc"));
        assert!(db.contains("open"));
        assert!(!db.contains("nonexistent_function_xyz"));
    }

    #[test]
    fn test_global_var_tracker() {
        let mut tracker = GlobalVarTypeTracker::new();
        tracker.record_access(0x1000, IpaType::UInt(32), TypeFactSource::UsagePattern, 0.9);
        tracker.record_access(0x1000, IpaType::UInt(32), TypeFactSource::UsagePattern, 0.8);
        tracker.record_access(0x2000, IpaType::Pointer(Box::new(IpaType::SInt(8))),
                              TypeFactSource::UsagePattern, 1.0);
        let changed = tracker.resolve_types();
        assert!(changed);
        assert_eq!(*tracker.get_type(0x1000), IpaType::UInt(32));
    }

    #[test]
    fn test_struct_field_db() {
        let mut db = StructFieldTypeDb::new();
        db.add_field_fact("Node", 0, IpaType::SInt(32));
        db.add_field_fact("Node", 8, IpaType::Pointer(Box::new(IpaType::Struct("Node".into()))));
        let changed = db.resolve();
        assert!(changed);
        assert_eq!(*db.get_field_type("Node", 0), IpaType::SInt(32));
    }

    #[test]
    fn test_recursive_type_detection() {
        let mut db = StructFieldTypeDb::new();
        db.add_field_fact("Node", 0, IpaType::SInt(32));
        db.add_field_fact("Node", 8, IpaType::Pointer(Box::new(IpaType::Struct("Node".into()))));
        db.resolve();
        let rec = detect_recursive_types(&db);
        assert!(rec.contains_key("Node"));
        assert_eq!(rec["Node"], vec![8]);
    }

    #[test]
    fn test_types_compatible() {
        assert!(types_compatible(&IpaType::UInt(32), &IpaType::UInt(32)));
        assert!(types_compatible(&IpaType::Unknown, &IpaType::SInt(64)));
        assert!(types_compatible(
            &IpaType::Pointer(Box::new(IpaType::UInt(8))),
            &IpaType::Pointer(Box::new(IpaType::Void)),
        ));
        assert!(!types_compatible(&IpaType::UInt(32), &IpaType::Float(32)));
    }

    #[test]
    fn test_call_graph_bottom_up_order() {
        let mut cg = CallGraph::new();
        cg.add_function(FuncInfo { id: 1, name: "a".into(), num_params: 0, is_library: false });
        cg.add_function(FuncInfo { id: 2, name: "b".into(), num_params: 0, is_library: false });
        cg.add_function(FuncInfo { id: 3, name: "c".into(), num_params: 0, is_library: false });
        cg.add_edge(CallEdge {
            caller: 1, callee: 2, call_site: 0x100,
            arg_types: vec![], return_use: ReturnUse::Discarded,
        });
        cg.add_edge(CallEdge {
            caller: 2, callee: 3, call_site: 0x200,
            arg_types: vec![], return_use: ReturnUse::Discarded,
        });

        let order = cg.bottom_up_order();
        let pos: HashMap<FuncId, usize> = order.iter().enumerate().map(|(i, &id)| (id, i)).collect();
        assert!(pos[&3] < pos[&2]);
        assert!(pos[&2] < pos[&1]);
    }

    #[test]
    fn test_convergence_checker() {
        let result = IpaResult {
            summaries: HashMap::new(),
            global_types: HashMap::new(),
            struct_field_types: HashMap::new(),
            var_types: HashMap::new(),
            iterations: 1,
            converged: false,
        };
        let mut checker = ConvergenceChecker::new();
        assert!(!checker.check(&result));
        assert!(checker.check(&result)); // second call with same state â†’ converged
    }

    #[test]
    fn test_ipa_stats_empty() {
        let result = IpaResult {
            summaries: HashMap::new(),
            global_types: HashMap::new(),
            struct_field_types: HashMap::new(),
            var_types: HashMap::new(),
            iterations: 0,
            converged: true,
        };
        let stats = IpaStats::compute(&result);
        assert_eq!(stats.total_functions, 0);
        assert_eq!(stats.total_globals, 0);
    }

    /// Validate SCC output on a graph with back-edges (a cycle) and a
    /// cross-edge to an external node.
    ///
    /// Graph:
    ///   1 â†’ 2 â†’ 3 â†’ 1  (cycle: SCC {1,2,3})
    ///   2 â†’ 4            (cross-edge: SCC {4})
    ///
    /// Expected SCCs (bottom-up): [{4}, {1,2,3}] in some order, but {4}
    /// must appear before {1,2,3} since 4 has no outgoing edges.
    #[test]
    fn test_scc_with_back_and_cross_edges() {
        let mut cg = CallGraph::new();
        for id in 1u64..=4 {
            cg.add_function(FuncInfo { id, name: id.to_string(), num_params: 0, is_library: false });
        }
        // Cycle 1â†’2â†’3â†’1
        cg.add_edge(CallEdge { caller: 1, callee: 2, call_site: 0x10, arg_types: vec![], return_use: ReturnUse::Discarded });
        cg.add_edge(CallEdge { caller: 2, callee: 3, call_site: 0x20, arg_types: vec![], return_use: ReturnUse::Discarded });
        cg.add_edge(CallEdge { caller: 3, callee: 1, call_site: 0x30, arg_types: vec![], return_use: ReturnUse::Discarded });
        // Cross-edge 2â†’4
        cg.add_edge(CallEdge { caller: 2, callee: 4, call_site: 0x40, arg_types: vec![], return_use: ReturnUse::Discarded });

        let sccs = cg.sccs();
        assert_eq!(sccs.len(), 2, "expected exactly 2 SCCs");

        // Each SCC is an unordered set of ids; find the big cycle and the singleton.
        let cycle_scc = sccs.iter().find(|s| s.len() == 3).expect("3-node SCC {1,2,3}");
        let singleton_scc = sccs.iter().find(|s| s.len() == 1).expect("singleton SCC {4}");

        let mut cycle_ids: Vec<u64> = cycle_scc.clone();
        cycle_ids.sort();
        assert_eq!(cycle_ids, vec![1, 2, 3]);
        assert_eq!(singleton_scc[0], 4);
    }

    /// Determinism regression: `bottom_up_order` / `sccs` must not depend on
    /// `HashMap` iteration order. Build the *same* graph many times (each build
    /// gets a freshly-seeded `HashMap`) and require byte-identical output.
    ///
    /// Before the fix, `to_petgraph` iterated `self.functions`/`self.outgoing`
    /// in `HashMap` order, so the node-index and neighbor discovery order handed
    /// to `tarjan_scc` â€” and therefore the flattened SCC order â€” varied per run.
    #[test]
    fn call_graph_order_is_deterministic() {
        fn build() -> (Vec<FuncId>, Vec<Vec<FuncId>>) {
            let mut cg = CallGraph::new();
            // Enough functions that HashMap seeding reliably permutes iteration.
            for id in 0u64..40 {
                cg.add_function(FuncInfo { id, name: id.to_string(), num_params: 0, is_library: false });
            }
            // A DAG plus one cycle to exercise SCC flattening.
            for id in 0u64..39 {
                cg.add_edge(CallEdge {
                    caller: id, callee: id + 1, call_site: id,
                    arg_types: vec![], return_use: ReturnUse::Discarded,
                });
            }
            cg.add_edge(CallEdge {
                caller: 20, callee: 10, call_site: 0xdead,
                arg_types: vec![], return_use: ReturnUse::Discarded,
            });
            (cg.bottom_up_order(), cg.sccs())
        }
        let (order0, sccs0) = build();
        for _ in 0..64 {
            let (order, sccs) = build();
            assert_eq!(order, order0, "bottom_up_order is nondeterministic");
            assert_eq!(sccs, sccs0, "sccs is nondeterministic");
        }
    }

    // ------------------------------------------------------------------
    // Property tests: join canonicality and fixpoint convergence
    // ------------------------------------------------------------------

    use crate::test_prng::xorshift;

    /// Generate a random `IpaType` (bounded depth).
    fn random_type(state: &mut u64, depth: usize) -> IpaType {
        let choice = xorshift(state) % if depth == 0 { 7 } else { 10 };
        match choice {
            0 => IpaType::Unknown,
            1 => IpaType::Void,
            2 => IpaType::Bool,
            3 => IpaType::UInt(8 << (xorshift(state) % 4)),
            4 => IpaType::SInt(8 << (xorshift(state) % 4)),
            5 => IpaType::Float(if xorshift(state).is_multiple_of(2) { 32 } else { 64 }),
            6 => IpaType::Struct(format!("S{}", xorshift(state) % 4)),
            7 => IpaType::Pointer(Box::new(random_type(state, depth - 1))),
            8 => IpaType::Array(Box::new(random_type(state, depth - 1)), xorshift(state) % 4),
            _ => {
                let a = random_type(state, depth - 1);
                let b = random_type(state, depth - 1);
                a.join(&b)
            }
        }
    }

    /// Regression: join must be idempotent and absorbing so that fixpoint
    /// loops converge. Before the fix, `Union(vec![a, b]).join(&a)` produced
    /// a *new* nested union every time, so summaries changed forever.
    #[test]
    fn regress_join_absorbing_and_commutative() {
        let mut state = 0x243F_6A88_85A3_08D3u64;
        for _ in 0..2000 {
            let x = random_type(&mut state, 3);
            let y = random_type(&mut state, 3);
            // Idempotence.
            assert_eq!(x.join(&x), x, "join not idempotent for {x}");
            // Commutativity (canonical union representation).
            assert_eq!(x.join(&y), y.join(&x), "join not commutative for {x}, {y}");
            // Absorption: joining either operand back in is a no-op.
            let j = x.join(&y);
            assert_eq!(j.join(&x), j, "join not absorbing (x) for {x}, {y}");
            assert_eq!(j.join(&y), j, "join not absorbing (y) for {x}, {y}");
            // Stability: re-joining the join with itself is a no-op.
            assert_eq!(j.join(&j), j);
        }
    }

    /// Regression: the explicit shape that used to grow without bound.
    #[test]
    fn regress_join_union_no_nested_growth() {
        let a = IpaType::UInt(32);
        let b = IpaType::Struct("Foo".into());
        let u = a.join(&b);
        assert_eq!(u.join(&a), u);
        assert_eq!(u.join(&b), u);
        assert_eq!(u.join(&u), u);
        // Unknown must not appear as a union variant.
        let v = u.join(&IpaType::Unknown);
        assert_eq!(v, u);
    }

    /// Regression: IPA fixpoint must actually converge (and quickly) when
    /// call sites repeatedly feed the same conflicting argument types.
    /// Before the join fix, every iteration re-wrapped param types in a new
    /// Union, so the loop only stopped at `max_iterations` and reported
    /// converged = false.
    #[test]
    fn regress_ipa_fixpoint_converges_with_conflicting_args() {
        let mut cg = CallGraph::new();
        for id in 1u64..=3 {
            cg.add_function(FuncInfo { id, name: format!("f{id}"), num_params: 1, is_library: false });
        }
        // Two callers pass conflicting types to callee 3; cycle 1<->2 too.
        cg.add_edge(CallEdge {
            caller: 1, callee: 3, call_site: 0x10,
            arg_types: vec![IpaType::UInt(32)],
            return_use: ReturnUse::AssignedTo("v1".into()),
        });
        cg.add_edge(CallEdge {
            caller: 2, callee: 3, call_site: 0x20,
            arg_types: vec![IpaType::Struct("S".into())],
            return_use: ReturnUse::Discarded,
        });
        cg.add_edge(CallEdge {
            caller: 1, callee: 2, call_site: 0x30,
            arg_types: vec![IpaType::Float(64)],
            return_use: ReturnUse::Discarded,
        });
        cg.add_edge(CallEdge {
            caller: 2, callee: 1, call_site: 0x40,
            arg_types: vec![IpaType::Bool],
            return_use: ReturnUse::Discarded,
        });

        let mut ipa = IpaTypeAnalysis::new(IpaContext::new(cg));
        let result = ipa.run();
        assert!(result.converged, "IPA did not converge");
        assert!(result.iterations <= 4, "IPA took {} iterations", result.iterations);
        // Callee 3 saw both types: canonical union expected, order-independent.
        let p = result.param_type(3, 0);
        assert_eq!(*p, IpaType::UInt(32).join(&IpaType::Struct("S".into())));
    }

    /// Order-independence: running IPA over the same constraints with call
    /// sites / edges inserted in different orders must give identical
    /// summaries.
    #[test]
    fn ipa_result_is_call_site_order_independent() {
        fn run_with_order(perm: &[usize]) -> Vec<(FuncId, IpaType, Vec<IpaType>)> {
            let types = [
                IpaType::UInt(32),
                IpaType::Struct("A".into()),
                IpaType::Pointer(Box::new(IpaType::SInt(8))),
                IpaType::Float(64),
                IpaType::Bool,
            ];
            let mut cg = CallGraph::new();
            for id in 0u64..5 {
                cg.add_function(FuncInfo { id, name: format!("f{id}"), num_params: 2, is_library: false });
            }
            let edges: Vec<CallEdge> = (0..5usize)
                .map(|k| CallEdge {
                    caller: (k as u64) % 5,
                    callee: ((k as u64) + 1) % 5,
                    call_site: 0x100 + k as u64,
                    arg_types: vec![types[k].clone(), types[(k + 2) % 5].clone()],
                    return_use: ReturnUse::AssignedTo(format!("v{k}")),
                })
                .collect();
            for &k in perm {
                cg.add_edge(edges[k].clone());
            }
            let mut ipa = IpaTypeAnalysis::new(IpaContext::new(cg));
            let result = ipa.run();
            assert!(result.converged);
            let mut out: Vec<(FuncId, IpaType, Vec<IpaType>)> = result.summaries
                .values()
                .map(|s| (s.func_id, s.return_type.clone(), s.param_types.clone()))
                .collect();
            out.sort_by_key(|(id, _, _)| *id);
            out
        }
        let base = run_with_order(&[0, 1, 2, 3, 4]);
        for perm in [
            [4, 3, 2, 1, 0],
            [2, 0, 4, 1, 3],
            [1, 4, 0, 3, 2],
            [3, 1, 4, 2, 0],
        ] {
            assert_eq!(run_with_order(&perm), base, "IPA result depends on edge insertion order");
        }
    }

    /// Regression: `GlobalVarTypeTracker::resolve_types` must not depend on
    /// the order facts were recorded. Before the fix, a high-confidence fact
    /// recorded last *replaced* the accumulated join, while the same fact
    /// recorded first was joined with the rest.
    #[test]
    fn regress_global_resolve_order_independent() {
        let facts = [
            (IpaType::UInt(32), 0.5f32),
            (IpaType::Struct("S".into()), 0.9),
            (IpaType::Float(64), 0.5),
        ];
        let orders: [[usize; 3]; 6] =
            [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
        let mut results = Vec::new();
        for order in orders {
            let mut tracker = GlobalVarTypeTracker::new();
            for &k in &order {
                let (ty, conf) = &facts[k];
                tracker.record_access(0x1000, ty.clone(), TypeFactSource::UsagePattern, *conf);
            }
            tracker.resolve_types();
            results.push(tracker.get_type(0x1000).clone());
        }
        for r in &results[1..] {
            assert_eq!(r, &results[0], "resolve_types depends on fact order: {results:?}");
        }
    }

    // --- Fixpoint solve order-independence (property tests) ---

    use crate::test_prng::XorShift64;

    /// Fisherâ€“Yates shuffle driven by the deterministic PRNG.
    fn shuffle<T>(v: &mut [T], rng: &mut XorShift64) {
        for i in (1..v.len()).rev() {
            let j = (rng.next() % (i as u64 + 1)) as usize;
            v.swap(i, j);
        }
    }

    /// Deterministically generate a random call graph + call sites, with
    /// functions/edges/sites inserted in the given permutation order.
    fn build_ctx(perm_seed: u64, rng_seed: u64) -> IpaContext {
        let mut g = XorShift64(rng_seed);
        let n_funcs = 8u64;
        let mut funcs: Vec<FuncInfo> = (1..=n_funcs)
            .map(|id| FuncInfo {
                id,
                name: if id == 1 { "memcpy".to_string() } else { format!("f{id}") },
                num_params: (g.next() % 4) as usize,
                is_library: id == 1,
            })
            .collect();
        let sample_types = [
            IpaType::Unknown,
            IpaType::UInt(32),
            IpaType::SInt(64),
            IpaType::Pointer(Box::new(IpaType::Void)),
            IpaType::Float(64),
        ];
        let mut edges: Vec<CallEdge> = Vec::new();
        let mut sites: Vec<CallSiteInfo> = Vec::new();
        for k in 0..20u64 {
            let caller = g.next() % n_funcs + 1;
            let callee = g.next() % n_funcs + 1;
            let n_args = (g.next() % 3) as usize;
            let arg_types: Vec<IpaType> = (0..n_args)
                .map(|_| sample_types[(g.next() % 5) as usize].clone())
                .collect();
            let assigned = g.next().is_multiple_of(2);
            edges.push(CallEdge {
                caller,
                callee,
                call_site: 0x1000 + k * 0x10,
                arg_types: arg_types.clone(),
                return_use: if assigned {
                    ReturnUse::AssignedTo(format!("v{}", g.next() % 4))
                } else {
                    ReturnUse::Discarded
                },
            });
            sites.push(CallSiteInfo {
                site_addr: 0x1000 + k * 0x10,
                caller,
                callee,
                arg_types,
                return_binding: if assigned { Some(format!("v{}", g.next() % 4)) } else { None },
            });
        }
        // Permute insertion order (HashMap layout + worklist seeding).
        let mut perm = XorShift64(perm_seed);
        shuffle(&mut funcs, &mut perm);
        shuffle(&mut edges, &mut perm);
        shuffle(&mut sites, &mut perm);
        let mut cg = CallGraph::new();
        for f in funcs {
            cg.add_function(f);
        }
        for e in edges {
            cg.add_edge(e);
        }
        let mut ctx = IpaContext::new(cg);
        ctx.call_sites = sites;
        ctx
    }

    fn result_fingerprint(r: &IpaResult) -> String {
        let mut s = String::new();
        let mut ids: Vec<_> = r.summaries.keys().copied().collect();
        ids.sort_unstable();
        for id in ids {
            let sm = &r.summaries[&id];
            s.push_str(&format!("{}:{:?}->{:?};", id, sm.param_types, sm.return_type));
        }
        let mut fids: Vec<_> = r.var_types.keys().copied().collect();
        fids.sort_unstable();
        for id in fids {
            let mut vars: Vec<_> = r.var_types[&id].iter().collect();
            vars.sort();
            s.push_str(&format!("{id}|{vars:?};"));
        }
        s
    }

    /// The main phase-iterating solver must produce identical results no
    /// matter what order functions, edges, and call sites were inserted in.
    #[test]
    fn ipa_solve_is_insertion_order_independent() {
        for graph_seed in [0x1111_u64, 0x2222, 0x3333, 0x4444] {
            let base = {
                let mut a = IpaTypeAnalysis::new(build_ctx(1, graph_seed));
                result_fingerprint(&a.run())
            };
            for perm_seed in 2..12u64 {
                let mut a = IpaTypeAnalysis::new(build_ctx(perm_seed, graph_seed));
                let fp = result_fingerprint(&a.run());
                assert_eq!(
                    fp, base,
                    "IpaTypeAnalysis result depends on insertion order (graph {graph_seed:#x}, perm {perm_seed})"
                );
            }
        }
    }

    /// The worklist solver must also be insertion-order independent. Before
    /// the fix the initial worklist was seeded from `HashMap::keys()`, so the
    /// processing order (observable through the `max_per_func` cap and via
    /// join tie-breaking) was randomized per run.
    #[test]
    fn worklist_ipa_is_insertion_order_independent() {
        for graph_seed in [0xaaaa_u64, 0xbbbb, 0xcccc, 0xdddd] {
            let base = {
                let mut w = WorklistIpa::new(build_ctx(1, graph_seed));
                result_fingerprint(&w.run())
            };
            for perm_seed in 2..12u64 {
                let mut w = WorklistIpa::new(build_ctx(perm_seed, graph_seed));
                let fp = result_fingerprint(&w.run());
                assert_eq!(
                    fp, base,
                    "WorklistIpa result depends on insertion order (graph {graph_seed:#x}, perm {perm_seed})"
                );
            }
        }
    }

    /// Both solvers agree on `var_types` for the same input (they implement
    /// the same top-down return-type propagation).
    #[test]
    fn worklist_and_phase_solver_agree_on_var_types() {
        for graph_seed in [0x5150_u64, 0x6161] {
            let mut a = IpaTypeAnalysis::new(build_ctx(1, graph_seed));
            let ra = a.run();
            let mut w = WorklistIpa::new(build_ctx(1, graph_seed));
            let rw = w.run();
            // WorklistIpa only propagates via call-graph edges (not
            // ctx.call_sites), so compare only functions it produced.
            for (fid, vars) in &rw.var_types {
                for (var, ty) in vars {
                    if !ty.is_unknown() {
                        let a_ty = ra.var_type(*fid, var);
                        assert!(
                            !a_ty.is_unknown(),
                            "phase solver missing var {var} of fn {fid} (worklist says {ty:?})"
                        );
                    }
                }
            }
        }
    }

    /// Regression: `collect_annotations` must emit annotations in a stable
    /// order (`func_id`, then global addr, then (struct, offset)), not `HashMap`
    /// iteration order.
    #[test]
    fn regress_collect_annotations_deterministic_order() {
        fn build() -> Vec<String> {
            let mut summaries = HashMap::new();
            for id in 0u64..24 {
                let mut s = FuncTypeSummary::new(id, format!("f{id}"), 1);
                s.return_type = IpaType::UInt(32);
                summaries.insert(id, s);
            }
            let mut global_types = HashMap::new();
            let mut struct_field_types = HashMap::new();
            for k in 0u64..24 {
                global_types.insert(0x1000 + k, IpaType::SInt(64));
                struct_field_types.insert((format!("S{k}"), k * 8), IpaType::Bool);
            }
            let result = IpaResult {
                summaries,
                global_types,
                struct_field_types,
                var_types: HashMap::new(),
                iterations: 1,
                converged: true,
            };
            TypeAnnotationApplicator::new(&result)
                .collect_annotations()
                .iter()
                .map(|a| format!("{a:?}"))
                .collect()
        }
        let base = build();
        for _ in 0..32 {
            assert_eq!(build(), base, "collect_annotations order is nondeterministic");
        }
        // Sanity: function annotations come sorted by func_id.
        assert!(base[0].contains("func_id: 0"));
    }

    /// Regression: `get_fields_of_struct` must return fields sorted by
    /// offset, not in `HashMap` iteration order.
    #[test]
    fn regress_get_fields_of_struct_sorted() {
        let mut db = StructFieldTypeDb::new();
        for off in [40u64, 8, 0, 32, 16, 24] {
            db.add_field_fact("S", off, IpaType::UInt(32));
        }
        db.resolve();
        let fields = db.get_fields_of_struct("S");
        let offs: Vec<u64> = fields.iter().map(|(o, _)| *o).collect();
        assert_eq!(offs, vec![0, 8, 16, 24, 32, 40]);
    }
}
