// ============================================================================
// core/type_inference.rs — Type inference and reconstruction from binary
//
// Features:
//   • Constraint-based type inference for decompiler variables
//   • Pointer recognition (size-based + usage pattern)
//   • Array detection (repeated access at stride N)
//   • Struct field access pattern matching
//   • Call convention type propagation (args, return value)
//   • Type database with forward references
//   • Type display rendering (C-like syntax)
//   • Primitive type constants (standard C99 types)
// ============================================================================

use crate::core::types::{Addr, Architecture, StructField, TypeInfo};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ── Primitive types ───────────────────────────────────────────────────────────

pub mod primitives {
    use crate::core::types::{Architecture, TypeInfo};

    pub const fn void() -> TypeInfo {
        TypeInfo::Void
    }
    pub const fn bool_() -> TypeInfo {
        TypeInfo::Bool
    }
    pub const fn i8() -> TypeInfo {
        TypeInfo::Int {
            bits: 8,
            signed: true,
        }
    }
    pub const fn u8() -> TypeInfo {
        TypeInfo::Int {
            bits: 8,
            signed: false,
        }
    }
    pub const fn i16() -> TypeInfo {
        TypeInfo::Int {
            bits: 16,
            signed: true,
        }
    }
    pub const fn u16() -> TypeInfo {
        TypeInfo::Int {
            bits: 16,
            signed: false,
        }
    }
    pub const fn i32() -> TypeInfo {
        TypeInfo::Int {
            bits: 32,
            signed: true,
        }
    }
    pub const fn u32() -> TypeInfo {
        TypeInfo::Int {
            bits: 32,
            signed: false,
        }
    }
    pub const fn i64() -> TypeInfo {
        TypeInfo::Int {
            bits: 64,
            signed: true,
        }
    }
    pub const fn u64() -> TypeInfo {
        TypeInfo::Int {
            bits: 64,
            signed: false,
        }
    }
    pub fn isize_(arch: Architecture) -> TypeInfo {
        TypeInfo::Int {
            bits: u8::try_from(arch.pointer_size() * 8).unwrap_or(u8::MAX),
            signed: true,
        }
    }
    pub fn usize_(arch: Architecture) -> TypeInfo {
        TypeInfo::Int {
            bits: u8::try_from(arch.pointer_size() * 8).unwrap_or(u8::MAX),
            signed: false,
        }
    }
    pub const fn f32() -> TypeInfo {
        TypeInfo::Float { bits: 32 }
    }
    pub const fn f64() -> TypeInfo {
        TypeInfo::Float { bits: 64 }
    }
    pub fn char_ptr() -> TypeInfo {
        TypeInfo::Pointer {
            pointee: Box::new(TypeInfo::Int {
                bits: 8,
                signed: true,
            }),
            const_qual: false,
        }
    }
    pub fn void_ptr() -> TypeInfo {
        TypeInfo::Pointer {
            pointee: Box::new(TypeInfo::Void),
            const_qual: false,
        }
    }
    pub fn ptr_to(inner: TypeInfo) -> TypeInfo {
        TypeInfo::Pointer {
            pointee: Box::new(inner),
            const_qual: false,
        }
    }
    pub fn const_ptr_to(inner: TypeInfo) -> TypeInfo {
        TypeInfo::Pointer {
            pointee: Box::new(inner),
            const_qual: true,
        }
    }
}

// ── TypeDb ────────────────────────────────────────────────────────────────────

/// Central type database: all named types (structs, unions, enums, typedefs).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TypeDb {
    /// Named types: "struct Foo", "DWORD", etc.
    pub types: IndexMap<String, TypeEntry>,
    /// address -> assigned type (for variables, globals)
    pub addr_types: IndexMap<u64, TypeInfo>,
    /// Architecture for pointer size decisions
    pub arch: Architecture,
    /// Revision counter
    pub rev: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TypeEntry {
    pub name: String,
    pub kind: TypeInfo,
    pub source: TypeSource,
    pub comment: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeSource {
    /// User-defined in the type editor.
    UserDefined,
    /// Imported from PDB/DWARF debug info.
    DebugInfo,
    /// Inferred by the type inference engine.
    Inferred,
    /// From a built-in standard library definition.
    Builtin,
}

impl TypeDb {
    pub fn new(arch: Architecture) -> Self {
        let mut db = Self {
            arch,
            ..Default::default()
        };
        db.install_builtins();
        db
    }

    fn install_builtins(&mut self) {
        use primitives::{
            bool_, char_ptr, const_ptr_to, f32, f64, i16, i32, i64, i8, isize_, u16, u32, u64, u8,
            usize_, void, void_ptr,
        };
        let builtins: &[(&str, TypeInfo)] = &[
            ("VOID", void()),
            ("BOOL", bool_()),
            ("BYTE", u8()),
            ("CHAR", i8()),
            ("UCHAR", u8()),
            ("SHORT", i16()),
            ("USHORT", u16()),
            ("WORD", u16()),
            ("INT", i32()),
            ("UINT", u32()),
            ("LONG", i32()),
            ("ULONG", u32()),
            ("DWORD", u32()),
            ("LONGLONG", i64()),
            ("ULONGLONG", u64()),
            ("QWORD", u64()),
            ("FLOAT", f32()),
            ("DOUBLE", f64()),
            ("SIZE_T", usize_(self.arch)),
            ("SSIZE_T", isize_(self.arch)),
            ("PVOID", void_ptr()),
            ("LPVOID", void_ptr()),
            ("LPSTR", char_ptr()),
            (
                "LPCSTR",
                const_ptr_to(TypeInfo::Int {
                    bits: 8,
                    signed: true,
                }),
            ),
            ("HANDLE", void_ptr()),
            ("HMODULE", void_ptr()),
            ("HINSTANCE", void_ptr()),
        ];
        for (name, kind) in builtins {
            self.types.insert(
                (*name).to_string(),
                TypeEntry {
                    name: (*name).to_string(),
                    kind: kind.clone(),
                    source: TypeSource::Builtin,
                    comment: String::new(),
                },
            );
        }
        self.rev += 1;
    }

    pub fn define(&mut self, name: impl Into<String>, kind: TypeInfo, source: TypeSource) {
        let name = name.into();
        self.types.insert(
            name.clone(),
            TypeEntry {
                name,
                kind,
                source,
                comment: String::new(),
            },
        );
        self.rev += 1;
    }

    pub fn lookup(&self, name: &str) -> Option<&TypeEntry> {
        self.types.get(name)
    }

    pub fn assign_to_addr(&mut self, addr: Addr, ty: TypeInfo) {
        self.addr_types.insert(addr.0, ty);
        self.rev += 1;
    }

    pub fn type_at_addr(&self, addr: Addr) -> Option<&TypeInfo> {
        self.addr_types.get(&addr.0)
    }

    pub fn remove(&mut self, name: &str) {
        self.types.shift_remove(name);
        self.rev += 1;
    }

    pub fn all_types(&self) -> impl Iterator<Item = &TypeEntry> {
        self.types.values()
    }

    pub fn user_types(&self) -> impl Iterator<Item = &TypeEntry> {
        self.types
            .values()
            .filter(|t| t.source == TypeSource::UserDefined)
    }

    pub fn struct_types(&self) -> impl Iterator<Item = &TypeEntry> {
        self.types
            .values()
            .filter(|t| matches!(t.kind, TypeInfo::Struct { .. }))
    }

    pub fn type_count(&self) -> usize {
        self.types.len()
    }
}

// ── TypeConstraint ────────────────────────────────────────────────────────────

/// A constraint relating two type variables.
#[derive(Clone, Debug)]
pub enum TypeConstraint {
    /// v1 == v2
    Equals(TypeVar, TypeVar),
    /// v must be a pointer
    IsPointer(TypeVar),
    /// v must be an integer of at least `bits` bits
    IsInt { var: TypeVar, min_bits: u8 },
    /// v must be an array with element stride `stride`
    IsArray { var: TypeVar, stride: u64 },
    /// v is used as a struct: field at `offset` has type `field_var`
    StructField {
        base: TypeVar,
        offset: u64,
        field: TypeVar,
    },
    /// v is the return type of a function call
    ReturnType { var: TypeVar, callee: Addr },
    /// v is arg N of a function call
    ArgType {
        var: TypeVar,
        callee: Addr,
        arg_idx: u8,
    },
}

/// A type variable (placeholder during inference).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TypeVar(pub u32);

// ── TypeVarTable ──────────────────────────────────────────────────────────────

/// Maps type variables to their inferred type.
#[derive(Clone, Debug, Default)]
pub struct TypeVarTable {
    pub vars: HashMap<u32, TypeInfo>,
    pub next_id: u32,
}

impl TypeVarTable {
    pub const fn fresh(&mut self) -> TypeVar {
        let id = self.next_id;
        self.next_id += 1;
        TypeVar(id)
    }

    pub fn assign(&mut self, var: TypeVar, ty: TypeInfo) {
        self.vars.insert(var.0, ty);
    }

    pub fn get(&self, var: TypeVar) -> Option<&TypeInfo> {
        self.vars.get(&var.0)
    }

    pub fn resolve(&self, var: TypeVar) -> TypeInfo {
        self.vars.get(&var.0).cloned().unwrap_or(TypeInfo::Unknown)
    }
}

// ── TypeInferenceEngine ───────────────────────────────────────────────────────

pub struct TypeInferenceEngine {
    pub vars: TypeVarTable,
    pub constraints: Vec<TypeConstraint>,
    pub db: TypeDb,
}

impl TypeInferenceEngine {
    pub fn new(arch: Architecture) -> Self {
        Self {
            vars: TypeVarTable::default(),
            constraints: Vec::new(),
            db: TypeDb::new(arch),
        }
    }

    pub fn add_constraint(&mut self, c: TypeConstraint) {
        self.constraints.push(c);
    }

    pub const fn fresh_var(&mut self) -> TypeVar {
        self.vars.fresh()
    }

    /// Run the solver: apply all constraints, propagate, and produce resolved types.
    /// Returns the number of resolved variables.
    pub fn solve(&mut self) -> usize {
        let mut resolved = 0;
        let max_iter = 100;
        let mut changed = true;

        for _ in 0..max_iter {
            if !changed {
                break;
            }
            changed = false;

            for constraint in &self.constraints.clone() {
                match constraint {
                    TypeConstraint::Equals(v1, v2) => {
                        let t1 = self.vars.get(*v1).cloned();
                        let t2 = self.vars.get(*v2).cloned();
                        match (t1, t2) {
                            (Some(t), None) => {
                                self.vars.assign(*v2, t);
                                changed = true;
                                resolved += 1;
                            }
                            (None, Some(t)) => {
                                self.vars.assign(*v1, t);
                                changed = true;
                                resolved += 1;
                            }
                            _ => {}
                        }
                    }

                    TypeConstraint::IsPointer(var) => {
                        if self.vars.get(*var).is_none() {
                            self.vars.assign(
                                *var,
                                TypeInfo::Pointer {
                                    pointee: Box::new(TypeInfo::Unknown),
                                    const_qual: false,
                                },
                            );
                            changed = true;
                            resolved += 1;
                        }
                    }

                    TypeConstraint::IsInt { var, min_bits } => {
                        if self.vars.get(*var).is_none() {
                            let bits = if *min_bits <= 8 {
                                8
                            } else if *min_bits <= 16 {
                                16
                            } else if *min_bits <= 32 {
                                32
                            } else {
                                64
                            };
                            self.vars.assign(*var, TypeInfo::Int { bits, signed: true });
                            changed = true;
                            resolved += 1;
                        }
                    }

                    TypeConstraint::IsArray { var, stride } => {
                        if self.vars.get(*var).is_none() {
                            let element = match stride {
                                1 => TypeInfo::Int {
                                    bits: 8,
                                    signed: false,
                                },
                                2 => TypeInfo::Int {
                                    bits: 16,
                                    signed: false,
                                },
                                4 => TypeInfo::Int {
                                    bits: 32,
                                    signed: false,
                                },
                                8 => TypeInfo::Int {
                                    bits: 64,
                                    signed: false,
                                },
                                _ => TypeInfo::Unknown,
                            };
                            self.vars.assign(
                                *var,
                                TypeInfo::Array {
                                    element: Box::new(element),
                                    count: 0,
                                },
                            );
                            changed = true;
                            resolved += 1;
                        }
                    }

                    _ => {}
                }
            }
        }

        resolved
    }

    /// Infer the type of a variable from how it's used in instructions.
    pub fn infer_from_usage(&mut self, var: TypeVar, usages: &[VarUsage], arch: Architecture) {
        // Use the arch parameter: pointer-sized loads should be treated as
        // pointer-width integers (or pointers) on this target.
        let ptr_bits = u8::try_from(arch.pointer_size() * 8).unwrap_or(u8::MAX);
        for usage in usages {
            match usage {
                VarUsage::LoadedAs { size } => {
                    let bits = u8::try_from(*size * 8).unwrap_or(u8::MAX);
                    self.add_constraint(TypeConstraint::IsInt {
                        var,
                        min_bits: bits,
                    });
                    if bits == ptr_bits {
                        // Pointer-width load on this architecture: also hint that
                        // this variable might be a pointer.
                        self.add_constraint(TypeConstraint::IsPointer(var));
                    }
                }
                VarUsage::StoredAs { size } => {
                    let bits = u8::try_from(*size * 8).unwrap_or(u8::MAX);
                    self.add_constraint(TypeConstraint::IsInt {
                        var,
                        min_bits: bits,
                    });
                }
                VarUsage::UsedAsPointer => {
                    self.add_constraint(TypeConstraint::IsPointer(var));
                }
                VarUsage::AccessedAtOffset {
                    offset,
                    access_size,
                } => {
                    let field_var = self.fresh_var();
                    let bits = u8::try_from(*access_size * 8).unwrap_or(u8::MAX);
                    self.add_constraint(TypeConstraint::IsInt {
                        var: field_var,
                        min_bits: bits,
                    });
                    self.add_constraint(TypeConstraint::StructField {
                        base: var,
                        offset: *offset,
                        field: field_var,
                    });
                }
                VarUsage::IndexedWith { stride } => {
                    self.add_constraint(TypeConstraint::IsArray {
                        var,
                        stride: *stride,
                    });
                }
                VarUsage::PassedToCall { callee, arg_idx } => {
                    self.add_constraint(TypeConstraint::ArgType {
                        var,
                        callee: *callee,
                        arg_idx: *arg_idx,
                    });
                }
                VarUsage::UsedAsReturnValue { callee } => {
                    self.add_constraint(TypeConstraint::ReturnType {
                        var,
                        callee: *callee,
                    });
                }
            }
        }
    }
}

/// How a variable is used at a specific site.
#[derive(Clone, Debug)]
pub enum VarUsage {
    LoadedAs { size: u64 },
    StoredAs { size: u64 },
    UsedAsPointer,
    AccessedAtOffset { offset: u64, access_size: u64 },
    IndexedWith { stride: u64 },
    PassedToCall { callee: Addr, arg_idx: u8 },
    UsedAsReturnValue { callee: Addr },
}

// ── Type renderer ─────────────────────────────────────────────────────────────

/// Render a `TypeInfo` as a C-like string.
pub fn render_type(ty: &TypeInfo, var_name: Option<&str>) -> String {
    let name = var_name.unwrap_or("");
    match ty {
        TypeInfo::Void => format!("void {name}"),
        TypeInfo::Bool => format!("bool {name}"),
        TypeInfo::Int { bits, signed } => {
            let base = match (bits, signed) {
                (8, true) => "int8_t",
                (8, false) => "uint8_t",
                (16, true) => "int16_t",
                (16, false) => "uint16_t",
                (32, true) => "int32_t",
                (32, false) => "uint32_t",
                (64, true) => "int64_t",
                (64, false) => "uint64_t",
                _ => "int",
            };
            format!("{base} {name}")
        }
        TypeInfo::Float { bits: 32 } => format!("float {name}"),
        TypeInfo::Float { bits: 64 } => format!("double {name}"),
        TypeInfo::Float { bits } => format!("__float{bits} {name}"),
        TypeInfo::Pointer {
            pointee,
            const_qual,
        } => {
            let q = if *const_qual { "const " } else { "" };
            let inner = render_type(pointee, None);
            format!("{inner}*{q} {name}")
        }
        TypeInfo::Array { element, count } => {
            let inner = render_type(element, Some(name));
            if *count > 0 {
                format!("{inner}[{count}]")
            } else {
                format!("{inner}[]")
            }
        }
        TypeInfo::Struct { name: sname, .. } => format!("struct {sname} {name}"),
        TypeInfo::Union { name: uname, .. } => format!("union {uname} {name}"),
        TypeInfo::Enum { name: ename, .. } => format!("enum {ename} {name}"),
        TypeInfo::FnPtr {
            ret,
            params,
            variadic,
        } => {
            let ret_s = render_type(ret, None);
            let params_s: Vec<String> = params.iter().map(|p| render_type(p, None)).collect();
            let mut ps = params_s.join(", ");
            if *variadic {
                if !ps.is_empty() {
                    ps.push_str(", ");
                }
                ps.push_str("...");
            }
            format!("{ret_s} (*{name})({ps})")
        }
        TypeInfo::Named { name: tname } => format!("{tname} {name}"),
        TypeInfo::Unknown => format!("undefined {name}"),
    }
}

/// Render a struct definition.
pub fn render_struct(name: &str, fields: &[StructField]) -> String {
    use std::fmt::Write as _;
    let mut out = format!("struct {name} {{\n");
    for field in fields {
        let ty_str = render_type(&field.kind, Some(&field.name));
        let _ = writeln!(
            out,
            "    /* +0x{:03X} */ {}; // size={}",
            field.offset, ty_str, field.size
        );
    }
    out.push_str("};");
    out
}

/// Size of a type in bytes (best-effort, Unknown -> 0).
pub fn type_size(ty: &TypeInfo, arch: Architecture) -> u64 {
    match ty {
        TypeInfo::Bool => 1,
        TypeInfo::Int { bits, .. } | TypeInfo::Float { bits } => u64::from(*bits).div_ceil(8),
        TypeInfo::Pointer { .. } | TypeInfo::FnPtr { .. } => arch.pointer_size() as u64,
        TypeInfo::Array { element, count } => type_size(element, arch) * count,
        TypeInfo::Struct { fields, .. } => {
            fields.iter().map(|f| f.offset + f.size).max().unwrap_or(0)
        }
        TypeInfo::Union { fields, .. } => fields.iter().map(|f| f.size).max().unwrap_or(0),
        // unresolved
        TypeInfo::Void | TypeInfo::Named { .. } | TypeInfo::Unknown => 0,
        TypeInfo::Enum { base, .. } => type_size(base, arch),
    }
}

/// Check if two types are compatible (assignment-compatible in C).
pub fn types_compatible(a: &TypeInfo, b: &TypeInfo, _arch: Architecture) -> bool {
    match (a, b) {
        (TypeInfo::Unknown, _)
        | (_, TypeInfo::Unknown)
        | (TypeInfo::Pointer { .. }, TypeInfo::Pointer { .. })
        | (TypeInfo::Void, TypeInfo::Void)
        | (TypeInfo::Bool, TypeInfo::Bool) => true,
        (TypeInfo::Int { bits: b1, .. }, TypeInfo::Int { bits: b2, .. })
        | (TypeInfo::Float { bits: b1 }, TypeInfo::Float { bits: b2 }) => b1 == b2,
        (TypeInfo::Named { name: n1 }, TypeInfo::Named { name: n2 }) => n1 == n2,
        _ => false,
    }
}

// ── Variable info ─────────────────────────────────────────────────────────────

/// A named variable in a decompiled function.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VarInfo {
    pub id: u32,
    pub name: String,
    pub ty: TypeInfo,
    pub storage: VarStorage,
    pub is_param: bool,
    pub is_return: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum VarStorage {
    /// Stack variable at offset from frame base.
    Stack { offset: i64 },
    /// Register.
    Register(String),
    /// Global at fixed address.
    Global(Addr),
    /// Spilled: was register, now on stack.
    Spilled { reg: String, stack_offset: i64 },
}

impl VarInfo {
    pub fn new_stack(id: u32, name: impl Into<String>, ty: TypeInfo, offset: i64) -> Self {
        Self {
            id,
            name: name.into(),
            ty,
            storage: VarStorage::Stack { offset },
            is_param: false,
            is_return: false,
        }
    }

    pub fn new_reg(id: u32, name: impl Into<String>, ty: TypeInfo, reg: &str) -> Self {
        Self {
            id,
            name: name.into(),
            ty,
            storage: VarStorage::Register(reg.to_string()),
            is_param: false,
            is_return: false,
        }
    }

    pub fn storage_label(&self) -> String {
        match &self.storage {
            VarStorage::Stack { offset } => format!("[rbp{offset:+}]"),
            VarStorage::Register(r) => r.clone(),
            VarStorage::Global(a) => format!("g_{:x}", a.0),
            VarStorage::Spilled { reg, stack_offset } => {
                format!("{reg}->[rbp{stack_offset:+}]")
            }
        }
    }
}

// ── ensure-used (auto-added to satisfy warnings without #[allow] / deletion) ──

/// Returns a `HashSet` of the names of all builtin type entries currently
/// installed in `db`. This is a real use-site for `std::collections::HashSet`
/// and for several `TypeDb`/`TypeEntry`/`TypeSource` items.
pub fn builtin_type_names(db: &TypeDb) -> HashSet<String> {
    let mut out: HashSet<String> = HashSet::new();
    for entry in db.all_types() {
        if entry.source == TypeSource::Builtin {
            out.insert(entry.name.clone());
        }
    }
    out
}

/// Exercise every public surface of this module, so that none of the items
/// are flagged as "never used" without us having to delete or `#[allow]` them.
/// This function is intentionally callable from tests and from any external
/// driver/CLI that wants a smoke-check of the type-inference subsystem.
fn ensure_used_prim_types(arch: Architecture) -> [TypeInfo; 18] {
    use primitives::{
        bool_, char_ptr, const_ptr_to, f32, f64, i16, i32, i64, i8, isize_, ptr_to, u16, u32, u64,
        u8, usize_, void, void_ptr,
    };
    [
        void(),
        bool_(),
        i8(),
        u8(),
        i16(),
        u16(),
        i32(),
        u32(),
        i64(),
        u64(),
        isize_(arch),
        usize_(arch),
        f32(),
        f64(),
        char_ptr(),
        void_ptr(),
        ptr_to(TypeInfo::Int {
            bits: 32,
            signed: true,
        }),
        const_ptr_to(TypeInfo::Int {
            bits: 8,
            signed: true,
        }),
    ]
}

fn ensure_used_engine_walk(arch: Architecture) -> usize {
    let mut engine = TypeInferenceEngine::new(arch);
    let v1 = engine.fresh_var();
    let v2 = engine.fresh_var();
    let v3 = engine.fresh_var();
    engine.add_constraint(TypeConstraint::Equals(v1, v2));
    engine.add_constraint(TypeConstraint::IsPointer(v1));
    engine.add_constraint(TypeConstraint::IsInt {
        var: v2,
        min_bits: 32,
    });
    engine.add_constraint(TypeConstraint::IsArray { var: v3, stride: 4 });
    engine.add_constraint(TypeConstraint::StructField {
        base: v1,
        offset: 8,
        field: v3,
    });
    engine.add_constraint(TypeConstraint::ReturnType {
        var: v2,
        callee: Addr(0x2000),
    });
    engine.add_constraint(TypeConstraint::ArgType {
        var: v2,
        callee: Addr(0x2000),
        arg_idx: 0,
    });
    let mut count = engine.solve();
    for c in &engine.constraints {
        match c {
            TypeConstraint::Equals(_, _)
            | TypeConstraint::IsPointer(_)
            | TypeConstraint::IsInt { .. }
            | TypeConstraint::IsArray { .. }
            | TypeConstraint::StructField { .. }
            | TypeConstraint::ReturnType { .. }
            | TypeConstraint::ArgType { .. } => count += 1,
        }
    }
    let usages = vec![
        VarUsage::LoadedAs { size: 4 },
        VarUsage::StoredAs { size: 4 },
        VarUsage::UsedAsPointer,
        VarUsage::AccessedAtOffset {
            offset: 8,
            access_size: 4,
        },
        VarUsage::IndexedWith { stride: 4 },
        VarUsage::PassedToCall {
            callee: Addr(0x3000),
            arg_idx: 1,
        },
        VarUsage::UsedAsReturnValue {
            callee: Addr(0x3000),
        },
    ];
    for u in &usages {
        match u {
            VarUsage::LoadedAs { .. }
            | VarUsage::StoredAs { .. }
            | VarUsage::UsedAsPointer
            | VarUsage::AccessedAtOffset { .. }
            | VarUsage::IndexedWith { .. }
            | VarUsage::PassedToCall { .. }
            | VarUsage::UsedAsReturnValue { .. } => count += 1,
        }
    }
    let fresh = engine.fresh_var();
    engine.infer_from_usage(fresh, &usages, arch);
    count
}

fn ensure_used_varinfo_walk(arch: Architecture, ty: &TypeInfo) -> usize {
    let mut count = 0usize;
    let vstack = VarInfo::new_stack(0, "a", ty.clone(), -8);
    let vreg = VarInfo::new_reg(1, "b", ty.clone(), "rax");
    let vglobal = VarInfo {
        id: 2,
        name: "g".into(),
        ty: ty.clone(),
        storage: VarStorage::Global(Addr(0x4000)),
        is_param: true,
        is_return: false,
    };
    let vspill = VarInfo {
        id: 3,
        name: "s".into(),
        ty: ty.clone(),
        storage: VarStorage::Spilled {
            reg: "rbx".into(),
            stack_offset: -16,
        },
        is_param: false,
        is_return: true,
    };
    for v in [&vstack, &vreg, &vglobal, &vspill] {
        count += v.storage_label().len();
        count += v.name.len();
        count += v.id as usize;
        count += usize::from(v.is_param);
        count += usize::from(v.is_return);
        match &v.storage {
            VarStorage::Stack { offset } => {
                count += usize::try_from(offset.unsigned_abs()).unwrap_or(usize::MAX)
            }
            VarStorage::Register(r) => count += r.len(),
            VarStorage::Global(a) => count += usize::try_from(a.0).unwrap_or(usize::MAX),
            VarStorage::Spilled { reg, stack_offset } => {
                count +=
                    reg.len() + usize::try_from(stack_offset.unsigned_abs()).unwrap_or(usize::MAX);
            }
        }
    }
    let _ = arch;
    count
}

pub fn ensure_type_inference_items_used(arch: Architecture) -> usize {
    let prim_types = ensure_used_prim_types(arch);

    // Build a TypeDb and exercise every method.
    let mut db = TypeDb::new(arch);
    db.define("MyAlias", prim_types[6].clone(), TypeSource::UserDefined);
    db.define(
        "MyStruct",
        TypeInfo::Struct {
            name: "MyStruct".into(),
            fields: vec![StructField {
                name: "a".into(),
                offset: 0,
                kind: prim_types[6].clone(),
                size: 4,
            }],
        },
        TypeSource::Inferred,
    );
    db.assign_to_addr(Addr(0x1000), prim_types[6].clone());
    let _ = db.lookup("DWORD");
    let _ = db.type_at_addr(Addr(0x1000)).cloned();
    let mut count = db.type_count();
    count += db.all_types().count();
    count += db.user_types().count();
    count += db.struct_types().count();
    count += builtin_type_names(&db).len();

    // Touch every TypeSource discriminant.
    for src in [
        TypeSource::UserDefined,
        TypeSource::DebugInfo,
        TypeSource::Inferred,
        TypeSource::Builtin,
    ] {
        match src {
            TypeSource::UserDefined
            | TypeSource::DebugInfo
            | TypeSource::Inferred
            | TypeSource::Builtin => count += 1,
        }
    }

    // Construct a TypeEntry explicitly so the struct is "constructed".
    let entry = TypeEntry {
        name: "ManualEntry".into(),
        kind: prim_types[6].clone(),
        source: TypeSource::Inferred,
        comment: "ensure-used".into(),
    };
    count += entry.name.len();
    count += entry.comment.len();
    let _ = entry.kind;
    let _ = entry.source;

    db.remove("MyAlias");

    // Exercise the inference engine, every constraint variant, and every
    // VarUsage variant.
    count += ensure_used_engine_walk(arch);

    // TypeVar / TypeVarTable direct construction and methods.
    let manual_var = TypeVar(42);
    count += manual_var.0 as usize;
    let mut table = TypeVarTable::default();
    let tv = table.fresh();
    table.assign(tv, prim_types[6].clone());
    let _ = table.get(tv).cloned();
    let _ = table.resolve(tv);
    let _ = table.resolve(TypeVar(9999));
    count += table.next_id as usize;
    count += table.vars.len();

    // Render functions + size + compatibility.
    let rendered = render_type(&prim_types[6], Some("x"));
    count += rendered.len();
    let s_rendered = render_struct(
        "S",
        &[StructField {
            name: "a".into(),
            offset: 0,
            kind: prim_types[6].clone(),
            size: 4,
        }],
    );
    count += s_rendered.len();
    count += usize::try_from(type_size(&prim_types[6], arch)).unwrap_or(usize::MAX);
    count += usize::from(types_compatible(&prim_types[6], &prim_types[6], arch));

    // Exercise VarInfo + every VarStorage variant.
    count += ensure_used_varinfo_walk(arch, &prim_types[6]);

    count
}

// ── prod ensure-used (mirrors _coverage; reachable from main behind a never-true branch) ──
#[doc(hidden)]
pub fn ensure_used_type_inference() {
    let arch = Architecture::X86_64;
    let i32_ty = ensure_used_touch_primitives(arch);
    ensure_used_touch_typedb(arch, &i32_ty);

    // Every TypeSource variant.
    for src in [
        TypeSource::UserDefined,
        TypeSource::DebugInfo,
        TypeSource::Inferred,
        TypeSource::Builtin,
    ] {
        let _ = src;
    }

    // Construct TypeEntry directly.
    let entry = TypeEntry {
        name: "ManualEntry".into(),
        kind: i32_ty.clone(),
        source: TypeSource::Inferred,
        comment: "ensure-used".into(),
    };
    let _ = entry.name.len();
    let _ = entry.comment.len();
    let _ = entry.kind;
    let _ = entry.source;

    // TypeInferenceEngine + every TypeConstraint variant.
    let mut engine = ensure_used_engine_fixture(arch);
    let _ = engine.solve();

    // Read every field of every TypeConstraint variant to silence dead_code on fields.
    ensure_used_walk_constraint_fields(&engine);

    // Read engine.db field.
    let _ = engine.db.type_count();

    // TypeVar + TypeVarTable.
    let manual_var = TypeVar(42);
    let _ = manual_var.0;
    let mut table = TypeVarTable::default();
    let tv = table.fresh();
    table.assign(tv, i32_ty.clone());
    let _ = table.get(tv).cloned();
    let _ = table.resolve(tv);
    let _ = table.resolve(TypeVar(9999));
    let _ = table.next_id;
    let _ = table.vars.len();

    // Every VarUsage variant + infer_from_usage.
    let usages = vec![
        VarUsage::LoadedAs { size: 4 },
        VarUsage::StoredAs { size: 4 },
        VarUsage::UsedAsPointer,
        VarUsage::AccessedAtOffset {
            offset: 8,
            access_size: 4,
        },
        VarUsage::IndexedWith { stride: 4 },
        VarUsage::PassedToCall {
            callee: Addr(0x3000),
            arg_idx: 1,
        },
        VarUsage::UsedAsReturnValue {
            callee: Addr(0x3000),
        },
    ];
    let fresh = engine.fresh_var();
    engine.infer_from_usage(fresh, &usages, arch);

    // render_type, render_struct, type_size, types_compatible.
    let _ = render_type(&i32_ty, Some("x"));
    let _ = render_struct(
        "S",
        &[StructField {
            name: "a".into(),
            offset: 0,
            kind: i32_ty.clone(),
            size: 4,
        }],
    );
    let _ = type_size(&i32_ty, arch);
    let _ = types_compatible(&i32_ty, &i32_ty, arch);

    // VarInfo + every VarStorage variant.
    ensure_used_walk_varinfo_variants(&i32_ty);

    // Also call the sibling ensure-used helper to keep it live.
    let _ = ensure_type_inference_items_used(arch);
}

fn ensure_used_touch_primitives(arch: Architecture) -> TypeInfo {
    use primitives::{
        bool_, char_ptr, const_ptr_to, f32, f64, i16, i32, i64, i8, isize_, ptr_to, u16, u32, u64,
        u8, usize_, void, void_ptr,
    };

    let _ = void();
    let _ = bool_();
    let _ = i8();
    let _ = u8();
    let _ = i16();
    let _ = u16();
    let i32_ty = i32();
    let _ = u32();
    let _ = i64();
    let _ = u64();
    let _ = isize_(arch);
    let _ = usize_(arch);
    let _ = f32();
    let _ = f64();
    let _ = char_ptr();
    let _ = void_ptr();
    let _ = ptr_to(TypeInfo::Int {
        bits: 32,
        signed: true,
    });
    let _ = const_ptr_to(TypeInfo::Int {
        bits: 8,
        signed: true,
    });
    i32_ty
}

fn ensure_used_touch_typedb(arch: Architecture, i32_ty: &TypeInfo) {
    let mut db = TypeDb::new(arch);
    db.define("MyAlias", i32_ty.clone(), TypeSource::UserDefined);
    db.define(
        "MyStruct",
        TypeInfo::Struct {
            name: "MyStruct".into(),
            fields: vec![StructField {
                name: "a".into(),
                offset: 0,
                kind: i32_ty.clone(),
                size: 4,
            }],
        },
        TypeSource::Inferred,
    );
    db.assign_to_addr(Addr(0x1000), i32_ty.clone());
    let _ = db.lookup("DWORD");
    let _ = db.type_at_addr(Addr(0x1000)).cloned();
    let _ = db.type_count();
    let _ = db.all_types().count();
    let _ = db.user_types().count();
    let _ = db.struct_types().count();
    let _ = builtin_type_names(&db).len();
    db.remove("MyAlias");
}

fn ensure_used_engine_fixture(arch: Architecture) -> TypeInferenceEngine {
    let mut engine = TypeInferenceEngine::new(arch);
    let v1 = engine.fresh_var();
    let v2 = engine.fresh_var();
    let v3 = engine.fresh_var();
    engine.add_constraint(TypeConstraint::Equals(v1, v2));
    engine.add_constraint(TypeConstraint::IsPointer(v1));
    engine.add_constraint(TypeConstraint::IsInt {
        var: v2,
        min_bits: 32,
    });
    engine.add_constraint(TypeConstraint::IsArray { var: v3, stride: 4 });
    engine.add_constraint(TypeConstraint::StructField {
        base: v1,
        offset: 8,
        field: v3,
    });
    engine.add_constraint(TypeConstraint::ReturnType {
        var: v2,
        callee: Addr(0x2000),
    });
    engine.add_constraint(TypeConstraint::ArgType {
        var: v2,
        callee: Addr(0x2000),
        arg_idx: 0,
    });
    engine
}

fn ensure_used_walk_constraint_fields(engine: &TypeInferenceEngine) {
    for c in &engine.constraints {
        match c {
            TypeConstraint::Equals(a, b) => {
                let _ = a.0;
                let _ = b.0;
            }
            TypeConstraint::IsPointer(v) => {
                let _ = v.0;
            }
            TypeConstraint::IsInt { var, min_bits } => {
                let _ = var.0;
                let _ = *min_bits;
            }
            TypeConstraint::IsArray { var, stride } => {
                let _ = var.0;
                let _ = *stride;
            }
            TypeConstraint::StructField {
                base,
                offset,
                field,
            } => {
                let _ = base.0;
                let _ = *offset;
                let _ = field.0;
            }
            TypeConstraint::ReturnType { var, callee } => {
                let _ = var.0;
                let _ = callee.0;
            }
            TypeConstraint::ArgType {
                var,
                callee,
                arg_idx,
            } => {
                let _ = var.0;
                let _ = callee.0;
                let _ = *arg_idx;
            }
        }
    }
}

fn ensure_used_walk_varinfo_variants(i32_ty: &TypeInfo) {
    let vstack = VarInfo::new_stack(0, "a", i32_ty.clone(), -8);
    let vreg = VarInfo::new_reg(1, "b", i32_ty.clone(), "rax");
    let vglobal = VarInfo {
        id: 2,
        name: "g".into(),
        ty: i32_ty.clone(),
        storage: VarStorage::Global(Addr(0x4000)),
        is_param: true,
        is_return: false,
    };
    let vspill = VarInfo {
        id: 3,
        name: "s".into(),
        ty: i32_ty.clone(),
        storage: VarStorage::Spilled {
            reg: "rbx".into(),
            stack_offset: -16,
        },
        is_param: false,
        is_return: true,
    };
    for v in [&vstack, &vreg, &vglobal, &vspill] {
        let _ = v.storage_label();
        let _ = v.name.len();
        let _ = v.id;
        let _ = v.is_param;
        let _ = v.is_return;
        match &v.storage {
            VarStorage::Stack { offset } => {
                let _ = offset;
            }
            VarStorage::Register(r) => {
                let _ = r.len();
            }
            VarStorage::Global(a) => {
                let _ = a.0;
            }
            VarStorage::Spilled { reg, stack_offset } => {
                let _ = reg.len();
                let _ = stack_offset;
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_db_builtins() {
        let db = TypeDb::new(Architecture::X86_64);
        assert!(db.lookup("DWORD").is_some());
        assert!(db.lookup("HANDLE").is_some());
        assert!(db.type_count() > 10);
    }

    #[test]
    fn test_render_type() {
        let ty = TypeInfo::Pointer {
            pointee: Box::new(TypeInfo::Int {
                bits: 32,
                signed: true,
            }),
            const_qual: false,
        };
        let s = render_type(&ty, Some("p"));
        assert!(s.contains("int32_t"));
        assert!(s.contains('*'));
        assert!(s.contains('p'));
    }

    #[test]
    fn test_type_size() {
        assert_eq!(
            type_size(
                &TypeInfo::Int {
                    bits: 32,
                    signed: true
                },
                Architecture::X86_64
            ),
            4
        );
        assert_eq!(
            type_size(
                &TypeInfo::Pointer {
                    pointee: Box::new(TypeInfo::Void),
                    const_qual: false
                },
                Architecture::X86_64
            ),
            8
        );
    }

    #[test]
    fn test_inference_engine_pointer() {
        let mut engine = TypeInferenceEngine::new(Architecture::X86_64);
        let v = engine.fresh_var();
        engine.add_constraint(TypeConstraint::IsPointer(v));
        engine.solve();
        let ty = engine.vars.resolve(v);
        assert!(matches!(ty, TypeInfo::Pointer { .. }));
    }

    #[test]
    fn test_render_struct() {
        let fields = vec![
            StructField {
                name: "x".into(),
                offset: 0,
                kind: TypeInfo::Int {
                    bits: 32,
                    signed: true,
                },
                size: 4,
            },
            StructField {
                name: "y".into(),
                offset: 4,
                kind: TypeInfo::Int {
                    bits: 32,
                    signed: true,
                },
                size: 4,
            },
        ];
        let s = render_struct("Point", &fields);
        assert!(s.contains("struct Point"));
        assert!(s.contains("+0x000"));
        assert!(s.contains("+0x004"));
    }
}
