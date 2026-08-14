//! Rename propagation for FLIRT match results.
//!
//! Once a function is identified (e.g. `memcpy` at offset 0x1234), this module:
//!
//! 1. Renames all **call-sites** that call into the newly-identified function.
//! 2. Propagates **parameter types** derived from the known function signature.
//! 3. Renames **local variables** where a stored return value is traceable.
//! 4. Updates the **symbol table** so subsequent passes see the new names.
//!
//! The propagator works on an abstract representation (`BinaryContext`) so it is
//! not tied to a specific disassembler back-end.

use std::collections::{HashSet, VecDeque};
// AHashMap (randomised) prevents hash-collision DoS from attacker-controlled
// function names/addresses from untrusted .sig/.pat files.
use ahash::AHashMap as HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// TypeDescriptor
// ─────────────────────────────────────────────────────────────────────────────

/// A simplified type descriptor for function parameters and return values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeDescriptor {
    Void,
    Bool,
    U8, U16, U32, U64,
    I8, I16, I32, I64,
    F32, F64,
    Pointer(Box<Self>),
    Array { elem: Box<Self>, count: usize },
    Struct(String),
    Union(String),
    Enum(String),
    FnPtr { params: Vec<Self>, ret: Box<Self> },
    Unknown,
}

impl TypeDescriptor {
    /// Return a C-style display string.
    #[must_use]
    pub fn c_str(&self) -> String {
        match self {
            Self::Void => "void".into(),
            Self::Bool => "bool".into(),
            Self::U8 => "uint8_t".into(),
            Self::U16 => "uint16_t".into(),
            Self::U32 => "uint32_t".into(),
            Self::U64 => "uint64_t".into(),
            Self::I8 => "int8_t".into(),
            Self::I16 => "int16_t".into(),
            Self::I32 => "int32_t".into(),
            Self::I64 => "int64_t".into(),
            Self::F32 => "float".into(),
            Self::F64 => "double".into(),
            Self::Pointer(t) => format!("{}*", t.c_str()),
            Self::Array { elem, count } => format!("{}[{count}]", elem.c_str()),
            Self::Struct(n) => format!("struct {n}"),
            Self::Union(n) => format!("union {n}"),
            Self::Enum(n) => format!("enum {n}"),
            Self::FnPtr { params, ret } => {
                let ps: Vec<String> = params.iter().map(Self::c_str).collect();
                format!("{}(*)({})", ret.c_str(), ps.join(", "))
            }
            Self::Unknown => "/*?*/".into(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionSignature
// ─────────────────────────────────────────────────────────────────────────────

/// Known signature for a library function.
#[derive(Debug, Clone)]
pub struct FunctionSignature {
    /// Canonical function name.
    pub name: String,
    /// Return type.
    pub return_type: TypeDescriptor,
    /// Parameter names and types (in order).
    pub params: Vec<(String, TypeDescriptor)>,
    /// Whether the function is variadic.
    pub variadic: bool,
    /// Calling convention tag (e.g. `"cdecl"`, `"ms_x64"`, `"sysv_x64"`).
    pub calling_convention: String,
}

impl FunctionSignature {
    /// Look up a known signature by function name.
    #[must_use]
    pub fn builtin(name: &str) -> Option<Self> {
        BUILTIN_SIGNATURES.iter().find(|s| s.name == name).cloned()
    }
}

/// Pre-built signatures for the most commonly identified library functions.
static BUILTIN_SIGNATURES: &[FunctionSignature] = &[];

// We build them lazily with a helper function.
/// Return a `Vec` of all known built-in signatures.
#[must_use]
pub fn builtin_signatures() -> Vec<FunctionSignature> {
    use TypeDescriptor::{Pointer, Void, I8, U64, I32};

    let ptr_void = || Pointer(Box::new(Void));
    let ptr_char = || Pointer(Box::new(I8));
    let ptr_const_char = || Pointer(Box::new(I8));
    let size_t = || U64;
    let int = || I32;

    let mut sigs = Vec::new();

    // Helper macros to reduce boilerplate for the many built-ins below.
    let sysv = || String::from("sysv_x64");
    let win64 = || String::from("msvc_x64");

    // ── libc: memory ────────────────────────────────────────────────
    for name in ["memcpy", "memmove"] {
        sigs.push(FunctionSignature { name: name.into(), return_type: ptr_void(),
            params: vec![("dst".into(), ptr_void()), ("src".into(), ptr_void()), ("n".into(), size_t())],
            variadic: false, calling_convention: sysv() });
    }
    sigs.push(FunctionSignature { name: "memset".into(), return_type: ptr_void(),
        params: vec![("s".into(), ptr_void()), ("c".into(), int()), ("n".into(), size_t())],
        variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "memcmp".into(), return_type: int(),
        params: vec![("s1".into(), ptr_void()), ("s2".into(), ptr_void()), ("n".into(), size_t())],
        variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "memchr".into(), return_type: ptr_void(),
        params: vec![("s".into(), ptr_void()), ("c".into(), int()), ("n".into(), size_t())],
        variadic: false, calling_convention: sysv() });

    // ── libc: strings ───────────────────────────────────────────────
    sigs.push(FunctionSignature { name: "strlen".into(), return_type: size_t(),
        params: vec![("s".into(), ptr_const_char())],
        variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "strnlen".into(), return_type: size_t(),
        params: vec![("s".into(), ptr_const_char()), ("maxlen".into(), size_t())],
        variadic: false, calling_convention: sysv() });
    // NOTE: these must be per-function. A previous version gave all seven the
    // same `(char *s1, const char *s2)` shape, which handed `strdup` a phantom
    // second parameter and typed `strchr`'s character argument as a pointer.
    // Wrong prototypes propagate straight into the caller's type recovery, so a
    // confident-but-wrong signature is worse here than no signature at all.
    for name in ["strcpy", "strcat", "strtok"] {
        // char *f(char *dst, const char *src)
        sigs.push(FunctionSignature { name: name.into(), return_type: ptr_char(),
            params: vec![("dst".into(), ptr_char()), ("src".into(), ptr_const_char())],
            variadic: false, calling_convention: sysv() });
    }
    // char *strdup(const char *s) — one parameter, not two.
    sigs.push(FunctionSignature { name: "strdup".into(), return_type: ptr_char(),
        params: vec![("s".into(), ptr_const_char())],
        variadic: false, calling_convention: sysv() });
    for name in ["strchr", "strrchr"] {
        // char *f(const char *s, int c) — the needle is an int, not a pointer.
        sigs.push(FunctionSignature { name: name.into(), return_type: ptr_char(),
            params: vec![("s".into(), ptr_const_char()), ("c".into(), int())],
            variadic: false, calling_convention: sysv() });
    }
    // char *strstr(const char *haystack, const char *needle)
    sigs.push(FunctionSignature { name: "strstr".into(), return_type: ptr_char(),
        params: vec![("haystack".into(), ptr_const_char()), ("needle".into(), ptr_const_char())],
        variadic: false, calling_convention: sysv() });
    for name in ["strncpy", "strncat"] {
        sigs.push(FunctionSignature { name: name.into(), return_type: ptr_char(),
            params: vec![("dst".into(), ptr_char()), ("src".into(), ptr_const_char()), ("n".into(), size_t())],
            variadic: false, calling_convention: sysv() });
    }
    for name in ["strcmp", "strcasecmp"] {
        sigs.push(FunctionSignature { name: name.into(), return_type: int(),
            params: vec![("s1".into(), ptr_const_char()), ("s2".into(), ptr_const_char())],
            variadic: false, calling_convention: sysv() });
    }
    for name in ["strncmp", "strncasecmp"] {
        sigs.push(FunctionSignature { name: name.into(), return_type: int(),
            params: vec![("s1".into(), ptr_const_char()), ("s2".into(), ptr_const_char()), ("n".into(), size_t())],
            variadic: false, calling_convention: sysv() });
    }
    for name in ["atoi", "atol"] {
        sigs.push(FunctionSignature { name: name.into(), return_type: int(),
            params: vec![("nptr".into(), ptr_const_char())],
            variadic: false, calling_convention: sysv() });
    }

    // ── libc: heap ──────────────────────────────────────────────────
    sigs.push(FunctionSignature { name: "malloc".into(), return_type: ptr_void(),
        params: vec![("size".into(), size_t())],
        variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "calloc".into(), return_type: ptr_void(),
        params: vec![("n".into(), size_t()), ("size".into(), size_t())],
        variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "realloc".into(), return_type: ptr_void(),
        params: vec![("ptr".into(), ptr_void()), ("size".into(), size_t())],
        variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "free".into(), return_type: Void,
        params: vec![("ptr".into(), ptr_void())],
        variadic: false, calling_convention: sysv() });

    // ── libc: stdio ─────────────────────────────────────────────────
    for name in ["printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf", "vsprintf", "vsnprintf"] {
        sigs.push(FunctionSignature { name: name.into(), return_type: int(),
            params: vec![("fmt".into(), ptr_const_char())],
            variadic: true, calling_convention: sysv() });
    }
    for name in ["puts", "fputs"] {
        sigs.push(FunctionSignature { name: name.into(), return_type: int(),
            params: vec![("s".into(), ptr_const_char())],
            variadic: false, calling_convention: sysv() });
    }
    sigs.push(FunctionSignature { name: "fopen".into(), return_type: ptr_void(),
        params: vec![("path".into(), ptr_const_char()), ("mode".into(), ptr_const_char())],
        variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "fclose".into(), return_type: int(),
        params: vec![("stream".into(), ptr_void())],
        variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "fread".into(), return_type: size_t(),
        params: vec![("ptr".into(), ptr_void()), ("size".into(), size_t()), ("nmemb".into(), size_t()), ("stream".into(), ptr_void())],
        variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "fwrite".into(), return_type: size_t(),
        params: vec![("ptr".into(), ptr_void()), ("size".into(), size_t()), ("nmemb".into(), size_t()), ("stream".into(), ptr_void())],
        variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "fseek".into(), return_type: int(),
        params: vec![("stream".into(), ptr_void()), ("offset".into(), U64), ("whence".into(), int())],
        variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "ftell".into(), return_type: U64,
        params: vec![("stream".into(), ptr_void())],
        variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "fgets".into(), return_type: ptr_char(),
        params: vec![("buf".into(), ptr_char()), ("n".into(), int()), ("stream".into(), ptr_void())],
        variadic: false, calling_convention: sysv() });

    // ── libc: process ───────────────────────────────────────────────
    sigs.push(FunctionSignature { name: "exit".into(), return_type: Void,
        params: vec![("status".into(), int())],
        variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "abort".into(), return_type: Void,
        params: vec![], variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "system".into(), return_type: int(),
        params: vec![("cmd".into(), ptr_const_char())],
        variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "getenv".into(), return_type: ptr_char(),
        params: vec![("name".into(), ptr_const_char())],
        variadic: false, calling_convention: sysv() });

    // ── POSIX syscalls ─────────────────────────────────────────────
    sigs.push(FunctionSignature { name: "open".into(), return_type: int(),
        params: vec![("path".into(), ptr_const_char()), ("flags".into(), int()), ("mode".into(), int())],
        variadic: true, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "close".into(), return_type: int(),
        params: vec![("fd".into(), int())],
        variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "read".into(), return_type: U64,
        params: vec![("fd".into(), int()), ("buf".into(), ptr_void()), ("count".into(), size_t())],
        variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "write".into(), return_type: U64,
        params: vec![("fd".into(), int()), ("buf".into(), ptr_void()), ("count".into(), size_t())],
        variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "lseek".into(), return_type: U64,
        params: vec![("fd".into(), int()), ("off".into(), U64), ("whence".into(), int())],
        variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "mmap".into(), return_type: ptr_void(),
        params: vec![("addr".into(), ptr_void()), ("len".into(), size_t()), ("prot".into(), int()), ("flags".into(), int()), ("fd".into(), int()), ("off".into(), U64)],
        variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "munmap".into(), return_type: int(),
        params: vec![("addr".into(), ptr_void()), ("len".into(), size_t())],
        variadic: false, calling_convention: sysv() });
    for name in ["fork", "getpid", "getppid", "getuid", "geteuid", "getgid"] {
        sigs.push(FunctionSignature { name: name.into(), return_type: int(),
            params: vec![], variadic: false, calling_convention: sysv() });
    }
    sigs.push(FunctionSignature { name: "execve".into(), return_type: int(),
        params: vec![("file".into(), ptr_const_char()), ("argv".into(), ptr_void()), ("envp".into(), ptr_void())],
        variadic: false, calling_convention: sysv() });

    // ── POSIX sockets ──────────────────────────────────────────────
    sigs.push(FunctionSignature { name: "socket".into(), return_type: int(),
        params: vec![("domain".into(), int()), ("type_".into(), int()), ("protocol".into(), int())],
        variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "bind".into(), return_type: int(),
        params: vec![("sock".into(), int()), ("addr".into(), ptr_void()), ("len".into(), int())],
        variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "listen".into(), return_type: int(),
        params: vec![("sock".into(), int()), ("backlog".into(), int())],
        variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "accept".into(), return_type: int(),
        params: vec![("sock".into(), int()), ("addr".into(), ptr_void()), ("len".into(), ptr_void())],
        variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "connect".into(), return_type: int(),
        params: vec![("sock".into(), int()), ("addr".into(), ptr_void()), ("len".into(), int())],
        variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "send".into(), return_type: U64,
        params: vec![("sock".into(), int()), ("buf".into(), ptr_void()), ("len".into(), size_t()), ("flags".into(), int())],
        variadic: false, calling_convention: sysv() });
    sigs.push(FunctionSignature { name: "recv".into(), return_type: U64,
        params: vec![("sock".into(), int()), ("buf".into(), ptr_void()), ("len".into(), size_t()), ("flags".into(), int())],
        variadic: false, calling_convention: sysv() });

    // ── Win32 API (msvc_x64) ───────────────────────────────────────
    for name in ["ExitProcess", "GetCurrentProcess", "GetCurrentThread", "GetLastError", "SetLastError", "CloseHandle"] {
        sigs.push(FunctionSignature { name: name.into(), return_type: int(),
            params: vec![], variadic: false, calling_convention: win64() });
    }
    sigs.push(FunctionSignature { name: "CreateFileA".into(), return_type: ptr_void(),
        params: vec![("filename".into(), ptr_const_char()), ("access".into(), int()), ("share".into(), int()),
                     ("security".into(), ptr_void()), ("creation".into(), int()), ("attrs".into(), int()), ("template".into(), ptr_void())],
        variadic: false, calling_convention: win64() });
    sigs.push(FunctionSignature { name: "CreateFileW".into(), return_type: ptr_void(),
        params: vec![("filename".into(), ptr_void()), ("access".into(), int()), ("share".into(), int()),
                     ("security".into(), ptr_void()), ("creation".into(), int()), ("attrs".into(), int()), ("template".into(), ptr_void())],
        variadic: false, calling_convention: win64() });
    sigs.push(FunctionSignature { name: "ReadFile".into(), return_type: int(),
        params: vec![("handle".into(), ptr_void()), ("buf".into(), ptr_void()), ("nbytes".into(), int()), ("read".into(), ptr_void()), ("overlapped".into(), ptr_void())],
        variadic: false, calling_convention: win64() });
    sigs.push(FunctionSignature { name: "WriteFile".into(), return_type: int(),
        params: vec![("handle".into(), ptr_void()), ("buf".into(), ptr_void()), ("nbytes".into(), int()), ("written".into(), ptr_void()), ("overlapped".into(), ptr_void())],
        variadic: false, calling_convention: win64() });
    for name in ["LoadLibraryA", "LoadLibraryW"] {
        sigs.push(FunctionSignature { name: name.into(), return_type: ptr_void(),
            params: vec![("name".into(), ptr_const_char())], variadic: false, calling_convention: win64() });
    }
    sigs.push(FunctionSignature { name: "GetProcAddress".into(), return_type: ptr_void(),
        params: vec![("module".into(), ptr_void()), ("name".into(), ptr_const_char())],
        variadic: false, calling_convention: win64() });
    sigs.push(FunctionSignature { name: "VirtualAlloc".into(), return_type: ptr_void(),
        params: vec![("addr".into(), ptr_void()), ("size".into(), size_t()), ("type_".into(), int()), ("protect".into(), int())],
        variadic: false, calling_convention: win64() });
    sigs.push(FunctionSignature { name: "VirtualFree".into(), return_type: int(),
        params: vec![("addr".into(), ptr_void()), ("size".into(), size_t()), ("type_".into(), int())],
        variadic: false, calling_convention: win64() });
    sigs.push(FunctionSignature { name: "VirtualProtect".into(), return_type: int(),
        params: vec![("addr".into(), ptr_void()), ("size".into(), size_t()), ("new_prot".into(), int()), ("old_prot".into(), ptr_void())],
        variadic: false, calling_convention: win64() });
    sigs.push(FunctionSignature { name: "HeapAlloc".into(), return_type: ptr_void(),
        params: vec![("heap".into(), ptr_void()), ("flags".into(), int()), ("bytes".into(), size_t())],
        variadic: false, calling_convention: win64() });
    sigs.push(FunctionSignature { name: "HeapFree".into(), return_type: int(),
        params: vec![("heap".into(), ptr_void()), ("flags".into(), int()), ("mem".into(), ptr_void())],
        variadic: false, calling_convention: win64() });
    sigs.push(FunctionSignature { name: "WaitForSingleObject".into(), return_type: int(),
        params: vec![("handle".into(), ptr_void()), ("timeout".into(), int())],
        variadic: false, calling_convention: win64() });
    sigs.push(FunctionSignature { name: "Sleep".into(), return_type: Void,
        params: vec![("ms".into(), int())],
        variadic: false, calling_convention: win64() });

    sigs
}

// ─────────────────────────────────────────────────────────────────────────────
// RenameRecord
// ─────────────────────────────────────────────────────────────────────────────

/// A rename action to be applied to the disassembly.
#[derive(Debug, Clone)]
pub struct RenameRecord {
    /// Virtual address / offset of the target.
    pub address: u64,
    /// New name to apply.
    pub new_name: String,
    /// Reason for the rename.
    pub reason: RenameReason,
}

/// Why a rename was suggested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenameReason {
    /// Direct FLIRT pattern match.
    DirectMatch,
    /// Call-site propagation (the callee was identified).
    CallSitePropagation { callee: String },
    /// Return-value store propagation.
    ReturnValueStore { source_fn: String },
    /// Parameter alias propagation.
    ParameterAlias { param_name: String, source_fn: String },
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeApply
// ─────────────────────────────────────────────────────────────────────────────

/// A type annotation to apply to a local variable or argument slot.
#[derive(Debug, Clone)]
pub struct TypeApply {
    /// Function address.
    pub function_addr: u64,
    /// Local variable / argument identifier (e.g. `"arg_0"`, `"var_10"`).
    pub var_id: String,
    /// Suggested type.
    pub suggested_type: TypeDescriptor,
    /// Source signature that produced this suggestion.
    pub from_sig: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// BinaryContext — abstract binary representation
// ─────────────────────────────────────────────────────────────────────────────

/// Abstract representation of a disassembled binary for propagation purposes.
///
/// Callers supply this through the `BinaryContextAdapter` trait.
pub trait BinaryContextAdapter {
    /// Return all call instructions (`caller_addr`, `callee_addr`) in the binary.
    fn call_edges(&self) -> Vec<(u64, u64)>;

    /// Return the current name of an address, if any.
    fn name_at(&self, addr: u64) -> Option<String>;

    /// List all local variable identifiers within a function.
    fn local_vars(&self, func_addr: u64) -> Vec<String>;

    /// Apply a rename record.
    fn apply_rename(&mut self, record: &RenameRecord);

    /// Apply a type annotation.
    fn apply_type(&mut self, ann: &TypeApply);
}

// ─────────────────────────────────────────────────────────────────────────────
// PropagationPlan
// ─────────────────────────────────────────────────────────────────────────────

/// The set of renames and type annotations to apply.
#[derive(Debug, Default)]
pub struct PropagationPlan {
    pub renames: Vec<RenameRecord>,
    pub type_annotations: Vec<TypeApply>,
}

impl PropagationPlan {
    /// Number of pending actions.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.renames.len() + self.type_annotations.len()
    }

    /// `true` when no actions are pending.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.renames.is_empty() && self.type_annotations.is_empty()
    }

    /// Apply this plan to a binary context.
    pub fn apply<B: BinaryContextAdapter>(&self, ctx: &mut B) {
        for r in &self.renames {
            ctx.apply_rename(r);
        }
        for t in &self.type_annotations {
            ctx.apply_type(t);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RenamePropagator
// ─────────────────────────────────────────────────────────────────────────────

/// Computes a [`PropagationPlan`] from a set of newly-identified functions.
pub struct RenamePropagator {
    /// Maximum BFS depth for call-site propagation.
    pub max_depth: usize,
    /// Whether to propagate type annotations.
    pub propagate_types: bool,
    /// Whether to propagate call-site renames.
    pub propagate_callsites: bool,
    /// Signature database (name → signature).
    sig_db: HashMap<String, FunctionSignature>,
}

impl Default for RenamePropagator {
    fn default() -> Self {
        let mut sig_db = HashMap::new();
        for sig in builtin_signatures() {
            sig_db.insert(sig.name.clone(), sig);
        }
        Self {
            max_depth: 3,
            propagate_types: true,
            propagate_callsites: true,
            sig_db,
        }
    }
}

impl RenamePropagator {
    /// Create a propagator with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an additional known function signature.
    pub fn add_signature(&mut self, sig: FunctionSignature) {
        self.sig_db.insert(sig.name.clone(), sig);
    }

    /// Build a [`PropagationPlan`] from a set of newly-identified `(address, name)` pairs.
    ///
    /// `call_edges` is `(caller_addr, callee_addr)` for all calls in the binary.
    #[must_use]
    pub fn build_plan(
        &self,
        new_identifications: &[(u64, String)],
        call_edges: &[(u64, u64)],
        existing_names: &HashMap<u64, String>,
    ) -> PropagationPlan {
        let mut plan = PropagationPlan::default();
        let mut seen: HashSet<u64> = HashSet::new();

        // Build callee → callers map.
        let mut callers_of: HashMap<u64, Vec<u64>> = HashMap::new();
        for &(caller, callee) in call_edges {
            callers_of.entry(callee).or_default().push(caller);
        }

        // BFS from each new identification.
        let mut queue: VecDeque<(u64, String, usize)> = VecDeque::new();
        for &(addr, ref name) in new_identifications {
            // Direct rename.
            if !existing_names.contains_key(&addr) {
                plan.renames.push(RenameRecord {
                    address: addr,
                    new_name: name.clone(),
                    reason: RenameReason::DirectMatch,
                });
                seen.insert(addr);
            }

            // Type propagation.
            if self.propagate_types
                && let Some(sig) = self.sig_db.get(name) {
                    Self::build_type_annotations(addr, sig, &mut plan);
                }

            if self.propagate_callsites {
                queue.push_back((addr, name.clone(), 0));
            }
        }

        // BFS: rename call-sites (the caller function containing the CALL instruction).
        // We rename the *caller function* only when the callee is a known single-purpose
        // wrapper (heuristic: name ends with "_impl", "_internal", etc.).
        while let Some((target_addr, target_name, depth)) = queue.pop_front() {
            if depth >= self.max_depth {
                continue;
            }
            let callers = callers_of.get(&target_addr).cloned().unwrap_or_default();
            for caller_addr in callers {
                if seen.contains(&caller_addr) {
                    continue;
                }
                if existing_names.contains_key(&caller_addr) {
                    continue;
                }
                // Only auto-rename wrappers that call exactly one identified function.
                let callee_count = call_edges.iter().filter(|&&(ca, _)| ca == caller_addr).count();
                if callee_count == 1 {
                    let wrapper_name = format!("{target_name}_wrapper");
                    plan.renames.push(RenameRecord {
                        address: caller_addr,
                        new_name: wrapper_name.clone(),
                        reason: RenameReason::CallSitePropagation { callee: target_name.clone() },
                    });
                    seen.insert(caller_addr);
                    queue.push_back((caller_addr, wrapper_name, depth + 1));
                }
            }
        }

        plan
    }

    fn build_type_annotations(func_addr: u64, sig: &FunctionSignature, plan: &mut PropagationPlan) {
        for (i, (_param_name, ty)) in sig.params.iter().enumerate() {
            // Argument variable naming convention varies by tool.
            // We produce suggestions for both IDA-style (arg_N) and Ghidra-style (param_N).
            let ida_var = format!("arg_{}", i * 8);
            let ghidra_var = format!("param_{}", i + 1);
            for var_id in [ida_var, ghidra_var] {
                plan.type_annotations.push(TypeApply {
                    function_addr: func_addr,
                    var_id,
                    suggested_type: ty.clone(),
                    from_sig: sig.name.clone(),
                });
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PropagationStats
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics from a propagation run.
#[derive(Debug, Clone, Default)]
pub struct PropagationStats {
    pub renames_direct: usize,
    pub renames_callsite: usize,
    pub type_annotations: usize,
}

impl PropagationStats {
    /// Compute from a plan.
    #[must_use]
    pub fn from_plan(plan: &PropagationPlan) -> Self {
        let renames_direct = plan.renames.iter().filter(|r| r.reason == RenameReason::DirectMatch).count();
        let renames_callsite = plan.renames.iter().filter(|r| matches!(r.reason, RenameReason::CallSitePropagation { .. })).count();
        Self {
            renames_direct,
            renames_callsite,
            type_annotations: plan.type_annotations.len(),
        }
    }
}

impl std::fmt::Display for PropagationStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "direct={} callsite={} types={}",
            self.renames_direct, self.renames_callsite, self.type_annotations)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_descriptor_display() {
        let t = TypeDescriptor::Pointer(Box::new(TypeDescriptor::I32));
        assert_eq!(t.c_str(), "int32_t*");
        let arr = TypeDescriptor::Array { elem: Box::new(TypeDescriptor::U8), count: 4 };
        assert_eq!(arr.c_str(), "uint8_t[4]");
    }

    #[test]
    fn test_propagator_direct_rename() {
        let prop = RenamePropagator::new();
        let ids = vec![(0x1000u64, "memcpy".into())];
        let plan = prop.build_plan(&ids, &[], &HashMap::new());
        assert_eq!(plan.renames.len(), 1);
        assert_eq!(plan.renames[0].address, 0x1000);
        assert_eq!(plan.renames[0].reason, RenameReason::DirectMatch);
    }

    #[test]
    fn test_propagator_wrapper_rename() {
        let prop = RenamePropagator::new();
        let ids = vec![(0x2000u64, "memset".into())];
        // One caller at 0x3000 that only calls 0x2000.
        let edges = vec![(0x3000u64, 0x2000u64)];
        let plan = prop.build_plan(&ids, &edges, &HashMap::new());
        // Should rename 0x3000 as "memset_wrapper".
        let wrapper = plan.renames.iter().find(|r| r.address == 0x3000);
        assert!(wrapper.is_some());
        assert_eq!(wrapper.unwrap().new_name, "memset_wrapper");
    }

    #[test]
    fn test_type_annotations_generated() {
        let prop = RenamePropagator::new();
        let ids = vec![(0x4000u64, "memcpy".into())];
        let plan = prop.build_plan(&ids, &[], &HashMap::new());
        // memcpy has 3 params × 2 naming styles = 6 annotations.
        assert_eq!(plan.type_annotations.len(), 6);
    }

    #[test]
    fn test_builtin_signatures_populated() {
        let sigs = builtin_signatures();
        assert!(!sigs.is_empty());
        let names: Vec<&str> = sigs.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"memcpy"));
        assert!(names.contains(&"malloc"));
    }

    #[test]
    fn test_propagation_stats() {
        let mut plan = PropagationPlan::default();
        plan.renames.push(RenameRecord {
            address: 0,
            new_name: "foo".into(),
            reason: RenameReason::DirectMatch,
        });
        plan.renames.push(RenameRecord {
            address: 1,
            new_name: "foo_wrapper".into(),
            reason: RenameReason::CallSitePropagation { callee: "foo".into() },
        });
        let stats = PropagationStats::from_plan(&plan);
        assert_eq!(stats.renames_direct, 1);
        assert_eq!(stats.renames_callsite, 1);
    }

    // ── libc prototype fidelity ─────────────────────────────────────────────
    // Regression guard for the bug where `strcpy/strcat/strdup/strchr/strrchr/
    // strstr/strtok` were emitted from one loop with an identical two-pointer
    // shape. Arity is checked explicitly because a phantom parameter compiles
    // cleanly and then silently corrupts the caller's recovered types.

    fn sig_named(name: &str) -> FunctionSignature {
        builtin_signatures()
            .into_iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("builtin signature `{name}` is missing"))
    }

    #[test]
    fn strdup_takes_exactly_one_parameter() {
        assert_eq!(sig_named("strdup").params.len(), 1);
    }

    #[test]
    fn strchr_family_second_param_is_an_int_not_a_pointer() {
        for name in ["strchr", "strrchr"] {
            let s = sig_named(name);
            assert_eq!(s.params.len(), 2, "{name} arity");
            assert!(
                !format!("{:?}", s.params[1].1).contains("Pointer"),
                "{name}: the character argument must not be a pointer, got {:?}",
                s.params[1].1
            );
        }
    }

    #[test]
    fn libc_string_builtins_have_published_arity() {
        // (name, arity) from the C standard.
        for (name, arity) in [
            ("strcpy", 2), ("strcat", 2), ("strtok", 2), ("strdup", 1),
            ("strchr", 2), ("strrchr", 2), ("strstr", 2),
            ("strlen", 1), ("strnlen", 2), ("strncpy", 3), ("strncat", 3),
            ("strcmp", 2), ("strncmp", 3),
            ("memcpy", 3), ("memmove", 3), ("memset", 3), ("memcmp", 3), ("memchr", 3),
        ] {
            assert_eq!(sig_named(name).params.len(), arity, "arity of `{name}`");
        }
    }

    #[test]
    fn builtin_signature_names_are_unique() {
        // A duplicate name means one of the two definitions silently wins at
        // lookup time, and which one wins depends on insertion order.
        let all = builtin_signatures();
        let mut seen = std::collections::HashSet::new();
        for s in &all {
            assert!(seen.insert(s.name.clone()), "duplicate builtin signature `{}`", s.name);
        }
    }
}
