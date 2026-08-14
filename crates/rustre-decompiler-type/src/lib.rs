//! `rustre-decompiler-type`
//!
//! Type-aware decompilation: struct field access recovery, array access,
//! pointer arithmetic, and variable renaming based on inferred types.
//!
//! # Key components
//!
//! * [`DecompType`] — a complete type system for decompiler use.
//! * [`TypeEnvironment`] — stores inferred types for each variable.
//! * [`TypedExprEmitter`] — rewrites raw pointer-arithmetic expressions into
//!   typed accesses (`ptr->field`, `arr[i]`, etc.).
//! * [`TypeAwareRenamer`] — generates human-readable variable names from
//!   their inferred type (e.g. `p_node` for `Node *`).

pub mod array_detector;
pub mod c_type_layout;
pub mod pointer_analysis;
pub mod struct_recovery;
pub mod type_printer_advanced;
pub mod type_propagation;
pub mod type_propagator;
pub mod type_reconstruction;
pub mod type_recovery_engine;
pub mod type_recovery_heuristics;
pub mod type_unification;
pub mod type_flow_lattice;
pub mod aggregate_recovery;
pub mod andersen_pta;
pub mod union_detection;
pub mod class_hierarchy_types;

use std::collections::HashMap;
use std::fmt::Write as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use rustre_decompiler_expr::{BinOp, Expr, IntWidth};

/// Enum variant for discriminated union types.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnumVariant {
    pub name: String,
    pub value: i64,
}

/// A single field in a struct.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StructField {
    pub offset: u64,
    pub name: String,
    pub ty: DecompType,
}

impl StructField {
    #[must_use]
    pub fn new(offset: u64, name: impl Into<String>, ty: DecompType) -> Self {
        Self {
            offset,
            name: name.into(),
            ty,
        }
    }
}

/// A struct type definition.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StructType {
    pub name: String,
    pub fields: Vec<StructField>,
    pub total_size: u64,
}

impl StructType {
    #[must_use]
    pub fn new(name: impl Into<String>, fields: Vec<StructField>, total_size: u64) -> Self {
        Self {
            name: name.into(),
            fields,
            total_size,
        }
    }

    /// Find the field covering the given byte offset (exact or containing).
    #[must_use]
    pub fn field_at(&self, offset: u64) -> Option<&StructField> {
        self.fields.iter().find(|f| {
            // Skip fields whose type has no known size (e.g. Unknown-typed fields),
            // because field_end would equal f.offset making the predicate always true.
            let size = match f.ty.byte_size() {
                Some(s) if s > 0 => s,
                _ => return false,
            };
            let field_end = f.offset + size;
            offset >= f.offset && offset < field_end
        })
    }

    /// Find a field by exact offset.
    #[must_use]
    pub fn field_exact(&self, offset: u64) -> Option<&StructField> {
        self.fields.iter().find(|f| f.offset == offset)
    }
}

/// The decompiler type representation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DecompType {
    Void,
    Bool,
    Int(IntWidth),
    Float32,
    Float64,
    Ptr(Box<Self>),
    Array(Box<Self>, u64),
    Struct(Box<StructType>),
    FnPtr {
        ret: Box<Self>,
        params: Vec<Self>,
    },
    CStr,
    Enum {
        name: String,
        variants: Vec<EnumVariant>,
        backing: IntWidth,
    },
    Unknown,
}

impl DecompType {
    /// Return the byte size of this type assuming a 64-bit (8-byte) pointer.
    ///
    /// For pointer-width-aware sizing, use [`byte_size_with_ptr_width`].
    #[must_use] 
    pub fn byte_size(&self) -> Option<u64> {
        self.byte_size_with_ptr_width(8)
    }

    /// Return the byte size of this type using the given pointer width in bytes
    /// (`ptr_width` should be 4 for 32-bit targets or 8 for 64-bit targets).
    #[must_use] 
    pub fn byte_size_with_ptr_width(&self, ptr_width: u8) -> Option<u64> {
        let ptr_bytes = u64::from(ptr_width);
        Some(match self {
            Self::Void => 0,
            Self::Bool | Self::Int(IntWidth::I8 | IntWidth::U8) => 1,
            Self::Int(IntWidth::I16 | IntWidth::U16) => 2,
            Self::Int(IntWidth::I32 | IntWidth::U32) | Self::Float32 => 4,
            Self::Int(IntWidth::I64 | IntWidth::U64) | Self::Float64 => 8,
            Self::Ptr(_) | Self::FnPtr { .. } | Self::CStr => ptr_bytes,
            Self::Array(inner, n) => inner.byte_size_with_ptr_width(ptr_width)?.checked_mul(*n)?,
            Self::Struct(s) => s.total_size,
            Self::Enum { backing, .. } => u64::from(backing.bits()) / 8,
            Self::Unknown => return None,
        })
    }

    /// Is this a pointer or pointer-like type?
    #[must_use]
    pub const fn is_pointer(&self) -> bool {
        matches!(self, Self::Ptr(_) | Self::CStr | Self::FnPtr { .. })
    }

    /// Dereference: return the pointee type.
    #[must_use]
    pub fn pointee(&self) -> Option<&Self> {
        match self {
            Self::Ptr(inner) => Some(inner),
            _ => None,
        }
    }

    /// Return a short C-like name for this type.
    #[must_use]
    pub fn c_name(&self) -> String {
        match self {
            Self::Void => "void".to_string(),
            Self::Bool => "bool".to_string(),
            Self::Int(w) => int_width_cname(*w).to_string(),
            Self::Float32 => "float".to_string(),
            Self::Float64 => "double".to_string(),
            Self::Ptr(inner) => format!("{} *", inner.c_name()),
            Self::Array(inner, n) => format!("{}[{n}]", inner.c_name()),
            Self::Struct(s) => format!("struct {}", s.name),
            Self::FnPtr { ret, params } => {
                let params_str: Vec<String> = params.iter().map(Self::c_name).collect();
                format!("{}(*)({})", ret.c_name(), params_str.join(", "))
            }
            Self::CStr => "char *".to_string(),
            Self::Enum { name, .. } => format!("enum {name}"),
            Self::Unknown => "void *".to_string(),
        }
    }

    /// Prefix for variable naming.
    #[must_use]
    pub const fn name_prefix(&self) -> &'static str {
        match self {
            Self::Bool => "b_",
            Self::Int(w) if w.is_signed() => "i",
            Self::Int(_) => "u",
            Self::Ptr(_) => "p_",
            Self::CStr => "sz_",
            Self::Float32 | Self::Float64 => "f_",
            Self::Array(_, _) => "arr_",
            Self::Struct(_) => "s_",
            Self::FnPtr { .. } => "pfn_",
            Self::Enum { .. } => "e_",
            _ => "v_",
        }
    }
}

/// Hex-Rays/IDA spellings, deliberately NOT stdint.
///
/// Every type printed by `DecompType::c_name` has been through `parse_c_type`,
/// which maps `"__int64"` and `"int64_t"` to the same `Int(I64)` — so whichever
/// spelling this function picks is the one the whole pipeline emits. It used to
/// pick stdint, which silently rewrote the `__int64` that the rest of the
/// pipeline deliberately emits (see `scaled_elem_type`'s "matching the rest of
/// the pipeline's spellings (not `stdint`)") into `int64_t`: corpus-wide that
/// left 3055 signatures spelling a parameter `int64_t` and 2572 spelling the
/// same thing `__int64`, purely by whether the value happened to be
/// round-tripped. IDA-style output is the project's goal, so IDA wins.
///
/// All of these are accepted by the `ida_defs.h` prelude — verified with
/// `gcc -std=gnu89 -fsyntax-only`; mingw supplies `__int8/16/64` as builtins,
/// which is also why the prelude must NOT typedef `__int64` itself.
const fn int_width_cname(w: IntWidth) -> &'static str {
    match w {
        IntWidth::I8 => "char",
        IntWidth::I16 => "__int16",
        IntWidth::I32 => "int",
        IntWidth::I64 => "__int64",
        IntWidth::U8 => "unsigned __int8",
        IntWidth::U16 => "unsigned __int16",
        IntWidth::U32 => "unsigned int",
        IntWidth::U64 => "unsigned __int64",
    }
}

/// Parse a C-style type spelling (as produced by `x86_register_width::c_type_for`
/// and similar helpers) into a [`DecompType`].
///
/// Supported spellings:
/// * `void`, `bool`, `char` → primitives
/// * `int8_t` / `uint8_t` … `int64_t` / `uint64_t` → `Int(IntWidth::…)`
/// * `float`, `double` → `Float32`, `Float64`
/// * anything ending in `*` → `Ptr(inner)` (recurses on the base)
/// * `const T`, `unsigned T` prefixes stripped
///
/// Unknown spellings fall back to [`DecompType::Unknown`] rather than panicking.
#[must_use]
pub fn parse_c_type(spelling: &str) -> DecompType {
    let s = spelling.trim();
    if s.is_empty() {
        return DecompType::Unknown;
    }
    // Peel trailing '*' as pointer.
    if let Some(base) = s.strip_suffix('*') {
        return DecompType::Ptr(Box::new(parse_c_type(base.trim())));
    }
    // Strip common qualifiers.
    for prefix in ["const ", "volatile ", "signed ", "restrict "] {
        if let Some(rest) = s.strip_prefix(prefix) {
            return parse_c_type(rest.trim());
        }
    }
    match s {
        "void" => DecompType::Void,
        "bool" | "_Bool" => DecompType::Bool,
        "char" | "int8_t" => DecompType::Int(IntWidth::I8),
        "unsigned char" | "uint8_t" | "byte" => DecompType::Int(IntWidth::U8),
        "short" | "int16_t" => DecompType::Int(IntWidth::I16),
        "unsigned short" | "uint16_t" | "WORD" => DecompType::Int(IntWidth::U16),
        "int" | "int32_t" | "long" => DecompType::Int(IntWidth::I32),
        "unsigned" | "unsigned int" | "uint32_t" | "DWORD" | "unsigned long" => {
            DecompType::Int(IntWidth::U32)
        }
        "int64_t" | "long long" | "__int64" => DecompType::Int(IntWidth::I64),
        "uint64_t" | "size_t" | "unsigned long long" | "QWORD" | "__uint64" => {
            DecompType::Int(IntWidth::U64)
        }
        "float" => DecompType::Float32,
        "double" => DecompType::Float64,
        _ => DecompType::Unknown,
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Type environment
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Maps variable names to their inferred types.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TypeEnvironment {
    vars: HashMap<String, DecompType>,
    structs: HashMap<String, StructType>,
}

impl TypeEnvironment {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Assign a type to a variable.
    pub fn set(&mut self, var: impl Into<String>, ty: DecompType) {
        self.vars.insert(var.into(), ty);
    }

    /// Look up the type of a variable.
    #[must_use]
    pub fn get(&self, var: &str) -> Option<&DecompType> {
        self.vars.get(var)
    }

    /// Register a named struct type.
    pub fn add_struct(&mut self, st: StructType) {
        self.structs.insert(st.name.clone(), st);
    }

    /// Look up a struct by name.
    #[must_use]
    pub fn struct_named(&self, name: &str) -> Option<&StructType> {
        self.structs.get(name)
    }

    /// Resolve `DecompType::Struct(—¦)` inline definitions as well as named
    /// structs registered in the environment.
    #[must_use]
    pub fn resolve_struct<'a>(&'a self, ty: &'a DecompType) -> Option<&'a StructType> {
        match ty {
            DecompType::Struct(s) => Some(s),
            _ => None,
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Error type
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Error)]
pub enum TypeError {
    #[error("unknown variable '{0}'")]
    UnknownVar(String),
    #[error("type mismatch: expected {expected}, got {got}")]
    Mismatch { expected: String, got: String },
    #[error("cannot dereference non-pointer type '{0}'")]
    DerefNonPointer(String),
    #[error("struct '{0}' has no field at offset 0x{1:x}")]
    NoFieldAtOffset(String, u64),
    #[error("array element size is zero")]
    ZeroElemSize,
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// TypedExprEmitter
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Rewrites raw pointer-arithmetic expressions into typed accesses.
///
/// Example transformations:
/// - `*(ptr + 0x10)`  â†'  `ptr->field_at_0x10` if `ptr` is a struct pointer
/// - `*(ptr + i * 4)` â†'  `ptr[i]` if `ptr` is an array pointer
/// - `*(ptr + 0)`     â†'  `*ptr` or `ptr->first_field`
pub struct TypedExprEmitter<'a> {
    env: &'a TypeEnvironment,
}

impl<'a> TypedExprEmitter<'a> {
    /// Create a new emitter.
    ///
    /// `ptr_size` is the target pointer width in bytes (4 or 8); stored for
    /// future platform-specific pointer-cast emission.
    #[must_use]
    pub const fn new(env: &'a TypeEnvironment, _ptr_size: u32) -> Self {
        Self { env }
    }

    /// Emit a typed C expression string for `expr`.
    ///
    /// # Errors
    /// Returns a `TypeError` if a type constraint is violated (e.g.
    /// dereferencing a non-pointer).
    pub fn emit(&self, expr: &Expr) -> Result<String, TypeError> {
        self.emit_inner(expr, false)
    }

    fn emit_inner(&self, expr: &Expr, needs_parens: bool) -> Result<String, TypeError> {
        let s = match expr {
            Expr::Const(v, w) => Self::emit_const(*v, *w),
            Expr::Var(n) => n.clone(),
            Expr::BinOp(op, a, b) => self.emit_binop(*op, a, b)?,
            Expr::UnOp(op, e) => {
                use rustre_decompiler_expr::UnOp;
                match op {
                    UnOp::Deref => self.emit_deref(e)?,
                    UnOp::AddrOf => format!("&{}", self.emit_inner(e, true)?),
                    UnOp::Neg => format!("-{}", self.emit_inner(e, true)?),
                    UnOp::Not => format!("~{}", self.emit_inner(e, true)?),
                    UnOp::LNot => format!("!{}", self.emit_inner(e, true)?),
                    UnOp::Cast(w) => {
                        format!("({}){}", int_width_cname(*w), self.emit_inner(e, true)?)
                    }
                }
            }
            Expr::Load { ptr, size } => self.emit_load(ptr, *size)?,
            Expr::FieldAccess { base, offset } => self.emit_field_access(base, *offset)?,
            Expr::Index {
                base,
                index,
                elem_size,
            } => self.emit_index(base, index, *elem_size)?,
            Expr::Call { callee, args } => self.emit_call(callee, args)?,
            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => format!(
                "({} ? {} : {})",
                self.emit(cond)?,
                self.emit(then_expr)?,
                self.emit(else_expr)?
            ),
            Expr::Phi(exprs) => {
                let parts: Result<Vec<_>, _> = exprs.iter().map(|e| self.emit(e)).collect();
                format!("phi({})", parts?.join(", "))
            }
        };
        if needs_parens && expr_needs_parens(expr) {
            Ok(format!("({s})"))
        } else {
            Ok(s)
        }
    }

    fn emit_const(v: i64, w: IntWidth) -> String {
        // For common small positive values use decimal; otherwise hex.
        if (0..1000).contains(&v) {
            format!("{v}")
        } else {
            match w {
                IntWidth::U8 | IntWidth::U16 | IntWidth::U32 => {
                    format!("0x{:X}U", v.cast_unsigned())
                }
                IntWidth::U64 => format!("0x{:X}ULL", v.cast_unsigned()),
                _ => format!("0x{v:X}"),
            }
        }
    }

    fn emit_binop(&self, op: BinOp, a: &Expr, b: &Expr) -> Result<String, TypeError> {
        // Special case: pointer + offset â†' field or array access.
        if matches!(op, BinOp::Add)
            && let Some(field_expr) = self.try_emit_ptr_add(a, b)? {
                return Ok(field_expr);
            }
        let a_s = self.emit_inner(a, true)?;
        let b_s = self.emit_inner(b, true)?;
        Ok(format!("{a_s} {} {b_s}", op.as_str()))
    }

    /// Attempt to recognise a pointer-arithmetic pattern and rewrite it.
    fn try_emit_ptr_add(
        &self,
        ptr_expr: &Expr,
        offset_expr: &Expr,
    ) -> Result<Option<String>, TypeError> {
        // Identify the base pointer type.
        let base_type = self.infer_type(ptr_expr);

        let Some(base_ty) = base_type else {
            return Ok(None);
        };

        match &base_ty {
            DecompType::Ptr(inner) => {
                let inner = inner.as_ref();

                // Constant offset: struct field access or `ptr + 0` dereference.
                if let Some(offset_val) = offset_expr.as_const() {
                    let offset = offset_val.cast_unsigned();
                    if let DecompType::Struct(st) = inner {
                        if let Some(field) = st.field_exact(offset) {
                            let base_s = self.emit_inner(ptr_expr, false)?;
                            return Ok(Some(format!("{base_s}->{}", field.name)));
                        }
                        if offset == 0
                            && let Some(first) = st.fields.first() {
                                let base_s = self.emit_inner(ptr_expr, false)?;
                                return Ok(Some(format!("{base_s}->{}", first.name)));
                            }
                    }
                    // `ptr + 0` â†' `*ptr`.
                    if offset == 0 {
                        let base_s = self.emit_inner(ptr_expr, false)?;
                        return Ok(Some(format!("*{base_s}")));
                    }
                }

                // Variable offset: array index pattern `base + index * elem_size`.
                if let Some((index_expr, elem_size)) = try_extract_scaled(offset_expr) {
                    let expected_size = inner.byte_size().unwrap_or(0);
                    if elem_size == expected_size || expected_size == 0 {
                        let base_s = self.emit_inner(ptr_expr, false)?;
                        let idx_s = self.emit_inner(index_expr, false)?;
                        return Ok(Some(format!("{base_s}[{idx_s}]")));
                    }
                }

                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn emit_deref(&self, ptr: &Expr) -> Result<String, TypeError> {
        // Check we are dereferencing a pointer type.
        if let Some(ty) = self.infer_type(ptr)
            && !ty.is_pointer() {
                return Err(TypeError::DerefNonPointer(ty.c_name()));
            }
        let inner = self.emit_inner(ptr, true)?;
        Ok(format!("*{inner}"))
    }

    fn emit_load(&self, ptr: &Expr, _size: u8) -> Result<String, TypeError> {
        // A load is essentially a dereference.
        self.emit_deref(ptr)
    }

    fn emit_field_access(&self, base: &Expr, offset: u64) -> Result<String, TypeError> {
        let base_s = self.emit_inner(base, false)?;
        // Try to find the struct type.
        if let Some(ty) = self.infer_type(base) {
            let struct_ty = match &ty {
                DecompType::Ptr(inner) => self.env.resolve_struct(inner),
                DecompType::Struct(_) => self.env.resolve_struct(&ty),
                _ => None,
            };
            if let Some(st) = struct_ty {
                if let Some(field) = st.field_exact(offset) {
                    let arrow = matches!(&ty, DecompType::Ptr(_));
                    let op = if arrow { "->" } else { "." };
                    return Ok(format!("{base_s}{op}{}", field.name));
                }
                return Err(TypeError::NoFieldAtOffset(st.name.clone(), offset));
            }
        }
        // Fallback: emit as byte offset.
        Ok(format!("FIELD({base_s}, 0x{offset:x})"))
    }

    fn emit_index(&self, base: &Expr, index: &Expr, _elem_size: u32) -> Result<String, TypeError> {
        let base_s = self.emit_inner(base, false)?;
        let idx_s = self.emit_inner(index, false)?;
        Ok(format!("{base_s}[{idx_s}]"))
    }

    fn emit_call(&self, callee: &Expr, args: &[Expr]) -> Result<String, TypeError> {
        let callee_s = self.emit_inner(callee, false)?;
        let args_s: Result<Vec<_>, _> = args.iter().map(|a| self.emit(a)).collect();
        Ok(format!("{}({})", callee_s, args_s?.join(", ")))
    }

    /// Best-effort type inference for an expression.
    fn infer_type(&self, expr: &Expr) -> Option<DecompType> {
        match expr {
            Expr::Var(n) => self.env.get(n).cloned(),
            Expr::Const(_, w) | Expr::UnOp(rustre_decompiler_expr::UnOp::Cast(w), _) => Some(DecompType::Int(*w)),
            Expr::BinOp(_, a, _) => self.infer_type(a),
            Expr::UnOp(rustre_decompiler_expr::UnOp::Deref, e) => {
                if let Some(DecompType::Ptr(inner)) = self.infer_type(e) {
                    Some(*inner)
                } else {
                    None
                }
            }
            Expr::UnOp(rustre_decompiler_expr::UnOp::AddrOf, e) => {
                Some(DecompType::Ptr(Box::new(self.infer_type(e)?)))
            }
            Expr::Load { ptr, .. } => {
                if let Some(DecompType::Ptr(inner)) = self.infer_type(ptr) {
                    Some(*inner)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// Returns `true` if an expression requires parentheses when used as an
/// operand.
const fn expr_needs_parens(expr: &Expr) -> bool {
    matches!(expr, Expr::BinOp(_, _, _) | Expr::Ternary { .. })
}

/// Try to recognise `index * scale` or just `index` (scale=1).
/// Returns `(index_expr, scale)`.
fn try_extract_scaled(expr: &Expr) -> Option<(&Expr, u64)> {
    match expr {
        Expr::BinOp(BinOp::Mul, a, b) => {
            if let Some(scale) = b.as_const() {
                if scale < 0 { return None; }
                return Some((a, scale.cast_unsigned()));
            }
            if let Some(scale) = a.as_const() {
                if scale < 0 { return None; }
                return Some((b, scale.cast_unsigned()));
            }
            None
        }
        Expr::BinOp(BinOp::Shl, a, b) => {
            if let Some(shift) = b.as_const() {
                if !(0..64).contains(&shift) { return None; }
                return Some((a, 1u64 << shift));
            }
            None
        }
        other => Some((other, 1)),
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// TypeAwareRenamer
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Generates readable variable names based on type and a numeric suffix.
///
/// Example mappings:
/// - `int32_t` â†' `i0`, `i1`, —¦
/// - `uint8_t *` â†' `p_0`, `p_1`, —¦
/// - `char *` â†' `sz_0`, —¦
/// - `struct Foo *` â†' `p_foo_0`, —¦
#[derive(Debug, Default)]
pub struct TypeAwareRenamer {
    counters: HashMap<String, u32>,
}

/// Returns `true` if `word` appears as a whole identifier within `text`.
/// An identifier boundary is any position not adjacent to a word character
/// (alphanumeric or `_`).
fn lhs_contains_word(text: &str, word: &str) -> bool {
    let bytes = text.as_bytes();
    let wlen = word.len();
    if wlen == 0 || wlen > bytes.len() {
        return false;
    }
    let is_word_char = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut start = 0usize;
    while start + wlen <= bytes.len() {
        if let Some(pos) = text[start..].find(word) {
            let abs = start + pos;
            let left_ok = abs == 0 || !is_word_char(bytes[abs - 1]);
            let right_ok = abs + wlen == bytes.len() || !is_word_char(bytes[abs + wlen]);
            if left_ok && right_ok {
                return true;
            }
            start = abs + 1;
        } else {
            break;
        }
    }
    false
}

impl TypeAwareRenamer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate a fresh name for a variable of the given type.
    pub fn rename(&mut self, ty: &DecompType) -> String {
        let prefix = Self::prefix_for(ty);
        let count = self.counters.entry(prefix.clone()).or_insert(0);
        let name = format!("{prefix}{count}");
        *count += 1;
        name
    }

    /// Generate a name for the given raw name + type, optionally using the
    /// raw name as a hint.
    pub fn rename_with_hint(&mut self, hint: &str, ty: &DecompType) -> String {
        if hint.starts_with("arg") || hint.starts_with("param") {
            return hint.to_string();
        }
        self.rename(ty)
    }

    fn prefix_for(ty: &DecompType) -> String {
        match ty {
            DecompType::Ptr(inner) => match inner.as_ref() {
                DecompType::Struct(s) => {
                    let lower = s.name.to_lowercase();
                    format!("p_{lower}_")
                }
                DecompType::Int(IntWidth::I8 | IntWidth::U8) => "sz_".to_string(),
                _ => "p_".to_string(),
            },
            DecompType::CStr => "sz_".to_string(),
            DecompType::Bool => "b_".to_string(),
            DecompType::Int(w) => {
                if w.is_signed() {
                    match w.bits() {
                        8 => "c".to_string(),
                        16 => "s".to_string(),
                        32 => "i".to_string(),
                        _ => "ll".to_string(),
                    }
                } else {
                    match w.bits() {
                        8 => "uc".to_string(),
                        16 => "us".to_string(),
                        32 => "ui".to_string(),
                        _ => "ull".to_string(),
                    }
                }
            }
            DecompType::Float32 => "f".to_string(),
            DecompType::Float64 => "d".to_string(),
            DecompType::Array(_, _) => "arr_".to_string(),
            DecompType::Struct(s) => {
                let lower = s.name.to_lowercase();
                format!("s_{lower}_")
            }
            DecompType::FnPtr { .. } => "pfn_".to_string(),
            DecompType::Enum { name, .. } => {
                let lower = name.to_lowercase();
                format!("e_{lower}_")
            }
            DecompType::Void | DecompType::Unknown => "v".to_string(),
        }
    }

    /// Bulk-rename a list of `(raw_name, type)` pairs, returning the mapping.
    pub fn rename_all(&mut self, vars: &[(String, DecompType)]) -> HashMap<String, String> {
        vars.iter()
            .map(|(n, ty)| (n.clone(), self.rename(ty)))
            .collect()
    }

    /// Reset all counters.
    pub fn reset(&mut self) {
        self.counters.clear();
    }

    /// Apply variable renaming heuristics to a block of C source code.
    ///
    /// When `env` contains type information for a variable, the type-driven
    /// prefix from [`TypeAwareRenamer::rename`] is used.  Otherwise the
    /// following fallback heuristics are applied:
    ///
    /// * `var_N` â†' `v_N` (shorter generic name)
    /// * Variables assigned from `malloc` / `new` â†' `ptr_N`
    /// * Variables used as loop counters (incremented / decremented with
    ///   `++` or `--`) â†' `i_N`, `j_N`, `k_N` in order of discovery
    ///
    /// The rename map is applied as a whole-word substitution so that
    /// `var_10` is not accidentally matched inside `var_100`.
    #[must_use]
    pub fn rename_variables(&mut self, code: &str, env: &TypeEnvironment) -> String {
        let (candidates, candidate_set) = Self::collect_var_candidates(code);
        if candidates.is_empty() {
            return code.to_string();
        }
        let (malloc_vars, counter_vars) =
            Self::classify_candidates(code, &candidates, &candidate_set);
        let rename_map = self.build_rename_map(&candidates, env, &malloc_vars, &counter_vars);
        Self::apply_renames(code, &rename_map)
    }

    fn collect_var_candidates(code: &str) -> (Vec<String>, std::collections::HashSet<String>) {
        let mut candidates: Vec<String> = Vec::new();
        let mut candidate_set: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let bytes = code.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            if bytes[i..].starts_with(b"var_") {
                let before_ok = i == 0 || {
                    let b = bytes[i - 1];
                    !b.is_ascii_alphanumeric() && b != b'_'
                };
                if before_ok {
                    let start = i;
                    let mut end = i + 4;
                    while end < bytes.len()
                        && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_')
                    {
                        end += 1;
                    }
                    let ident = &code[start..end];
                    if !candidate_set.contains(ident) {
                        candidate_set.insert(ident.to_string());
                        candidates.push(ident.to_string());
                    }
                    i = end;
                    continue;
                }
            }
            i += 1;
        }
        (candidates, candidate_set)
    }

    fn classify_candidates(
        code: &str,
        candidates: &[String],
        candidate_set: &std::collections::HashSet<String>,
    ) -> (std::collections::HashSet<String>, std::collections::HashSet<String>) {
        let mut malloc_vars: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut counter_vars: std::collections::HashSet<String> = std::collections::HashSet::new();
        for line in code.lines() {
            let trimmed = line.trim();
            if let Some(eq_pos) = trimmed.find('=') {
                let lhs = trimmed[..eq_pos].trim();
                let rhs = trimmed[eq_pos + 1..].trim();
                if rhs.starts_with("malloc(") || rhs.starts_with("new ") {
                    for candidate in candidates {
                        if candidate_set.contains(candidate.as_str())
                            && lhs_contains_word(lhs, candidate)
                        {
                            malloc_vars.insert(candidate.clone());
                        }
                    }
                }
            }
            for candidate in candidates {
                if counter_vars.contains(candidate) { continue; }
                let inc = format!("{candidate}++");
                let dec = format!("{candidate}--");
                let pre_inc = format!("++{candidate}");
                let pre_dec = format!("--{candidate}");
                if trimmed.contains(&inc) || trimmed.contains(&dec)
                    || trimmed.contains(&pre_inc) || trimmed.contains(&pre_dec)
                {
                    counter_vars.insert(candidate.clone());
                }
            }
        }
        (malloc_vars, counter_vars)
    }

    fn build_rename_map(
        &mut self,
        candidates: &[String],
        env: &TypeEnvironment,
        malloc_vars: &std::collections::HashSet<String>,
        counter_vars: &std::collections::HashSet<String>,
    ) -> std::collections::HashMap<String, String> {
        let counter_names = ["i", "j", "k", "l", "m", "n"];
        let mut counter_idx = 0usize;
        let mut rename_map: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for candidate in candidates {
            let new_name = if let Some(ty) = env.get(candidate) {
                self.rename(ty)
            } else if malloc_vars.contains(candidate) {
                let count = self.counters.entry("ptr_".to_string()).or_insert(0);
                let name = format!("ptr_{count}");
                *count += 1;
                name
            } else if counter_vars.contains(candidate) {
                if counter_idx < counter_names.len() {
                    let b = counter_names[counter_idx];
                    counter_idx += 1;
                    b.to_string()
                } else {
                    format!("i{counter_idx}")
                }
            } else {
                let suffix = candidate.strip_prefix("var_").unwrap_or(candidate);
                format!("v_{suffix}")
            };
            rename_map.insert(candidate.clone(), new_name);
        }
        rename_map
    }

    fn apply_renames(
        code: &str,
        rename_map: &std::collections::HashMap<String, String>,
    ) -> String {
        let mut sorted_pairs: Vec<(&String, &String)> = rename_map.iter().collect();
        sorted_pairs.sort_by(|(a, _), (b, _)| b.len().cmp(&a.len()));
        let mut result = code.to_string();
        for (old, new) in sorted_pairs {
            let mut out = String::with_capacity(result.len());
            let mut rest = result.as_str();
            while let Some(pos) = rest.find(old.as_str()) {
                let before_ok = pos == 0 || {
                    let b = rest.as_bytes()[pos - 1];
                    !b.is_ascii_alphanumeric() && b != b'_'
                };
                let after_pos = pos + old.len();
                let after_ok = after_pos >= rest.len() || {
                    let b = rest.as_bytes()[after_pos];
                    !b.is_ascii_alphanumeric() && b != b'_'
                };
                if before_ok && after_ok {
                    out.push_str(&rest[..pos]);
                    out.push_str(new);
                } else {
                    out.push_str(&rest[..after_pos]);
                }
                rest = &rest[after_pos..];
            }
            out.push_str(rest);
            result = out;
        }
        result
    }

}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Tests
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_decompiler_expr::{Expr, IntWidth, UnOp};

    fn make_node_struct() -> StructType {
        StructType::new(
            "Node",
            vec![
                StructField::new(0, "value", DecompType::Int(IntWidth::I32)),
                StructField::new(8, "next", DecompType::Ptr(Box::new(DecompType::Unknown))),
            ],
            16,
        )
    }

    fn env_with_node() -> TypeEnvironment {
        let mut env = TypeEnvironment::new();
        let st = make_node_struct();
        env.set(
            "node",
            DecompType::Ptr(Box::new(DecompType::Struct(Box::new(st.clone())))),
        );
        env.add_struct(st);
        env
    }

    fn emitter(env: &TypeEnvironment) -> TypedExprEmitter<'_> {
        TypedExprEmitter::new(env, 8)
    }

    // â"€â"€ DecompType helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_byte_size_int() {
        assert_eq!(DecompType::Int(IntWidth::I32).byte_size(), Some(4));
        assert_eq!(DecompType::Int(IntWidth::U64).byte_size(), Some(8));
    }

    #[test]
    fn test_byte_size_ptr() {
        assert_eq!(
            DecompType::Ptr(Box::new(DecompType::Void)).byte_size(),
            Some(8)
        );
    }

    #[test]
    fn test_byte_size_array() {
        let ty = DecompType::Array(Box::new(DecompType::Int(IntWidth::I32)), 10);
        assert_eq!(ty.byte_size(), Some(40));
    }

    #[test]
    fn test_byte_size_struct() {
        let st = DecompType::Struct(Box::new(make_node_struct()));
        assert_eq!(st.byte_size(), Some(16));
    }

    #[test]
    fn test_c_name_ptr() {
        let ty = DecompType::Ptr(Box::new(DecompType::Int(IntWidth::I32)));
        // IDA spells a 32-bit int `int`, not `int32_t` — see `int_width_cname`.
        assert_eq!(ty.c_name(), "int *");
    }

    #[test]
    fn test_c_name_struct() {
        let ty = DecompType::Struct(Box::new(make_node_struct()));
        assert_eq!(ty.c_name(), "struct Node");
    }

    #[test]
    fn test_is_pointer() {
        assert!(DecompType::Ptr(Box::new(DecompType::Void)).is_pointer());
        assert!(DecompType::CStr.is_pointer());
        assert!(!DecompType::Int(IntWidth::I32).is_pointer());
    }

    // â"€â"€ StructType field lookup â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_struct_field_exact() {
        let st = make_node_struct();
        assert_eq!(
            st.field_exact(0).map(|f| &f.name),
            Some(&"value".to_string())
        );
        assert_eq!(
            st.field_exact(8).map(|f| &f.name),
            Some(&"next".to_string())
        );
        assert!(st.field_exact(4).is_none());
    }

    // â"€â"€ TypedExprEmitter â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_emit_const_small() {
        let env = TypeEnvironment::new();
        let e = emitter(&env);
        assert_eq!(e.emit(&Expr::Const(42, IntWidth::I32)).unwrap(), "42");
    }

    #[test]
    fn test_emit_const_hex() {
        let env = TypeEnvironment::new();
        let e = emitter(&env);
        assert_eq!(
            e.emit(&Expr::Const(0x1000, IntWidth::I64)).unwrap(),
            "0x1000"
        );
    }

    #[test]
    fn test_emit_var() {
        let env = TypeEnvironment::new();
        let e = emitter(&env);
        assert_eq!(e.emit(&Expr::Var("x".to_string())).unwrap(), "x");
    }

    #[test]
    fn test_emit_struct_field_access() {
        let env = env_with_node();
        let e = emitter(&env);
        // `node + 8` should become `node->next`
        let expr = Expr::BinOp(
            BinOp::Add,
            Box::new(Expr::Var("node".to_string())),
            Box::new(Expr::Const(8, IntWidth::U64)),
        );
        let result = e.emit(&expr).unwrap();
        assert_eq!(result, "node->next");
    }

    #[test]
    fn test_emit_struct_field_zero_offset() {
        let env = env_with_node();
        let e = emitter(&env);
        // `node + 0` â†' `*node` (or `node->value`)
        let expr = Expr::BinOp(
            BinOp::Add,
            Box::new(Expr::Var("node".to_string())),
            Box::new(Expr::Const(0, IntWidth::U64)),
        );
        let result = e.emit(&expr).unwrap();
        // Result should reference `value` field or dereference.
        assert!(result.contains("node"));
    }

    #[test]
    fn test_emit_array_index() {
        let mut env = TypeEnvironment::new();
        env.set(
            "arr",
            DecompType::Ptr(Box::new(DecompType::Int(IntWidth::I32))),
        );
        let e = emitter(&env);
        // `arr + i * 4` â†' `arr[i]`
        let expr = Expr::BinOp(
            BinOp::Add,
            Box::new(Expr::Var("arr".to_string())),
            Box::new(Expr::BinOp(
                BinOp::Mul,
                Box::new(Expr::Var("i".to_string())),
                Box::new(Expr::Const(4, IntWidth::U64)),
            )),
        );
        let result = e.emit(&expr).unwrap();
        assert_eq!(result, "arr[i]");
    }

    #[test]
    fn test_emit_deref() {
        let mut env = TypeEnvironment::new();
        env.set(
            "p",
            DecompType::Ptr(Box::new(DecompType::Int(IntWidth::I32))),
        );
        let e = emitter(&env);
        let expr = Expr::UnOp(UnOp::Deref, Box::new(Expr::Var("p".to_string())));
        assert_eq!(e.emit(&expr).unwrap(), "*p");
    }

    #[test]
    fn test_emit_call() {
        let env = TypeEnvironment::new();
        let e = emitter(&env);
        let expr = Expr::Call {
            callee: Box::new(Expr::Var("foo".to_string())),
            args: vec![Expr::Const(1, IntWidth::I32), Expr::Var("x".to_string())],
        };
        assert_eq!(e.emit(&expr).unwrap(), "foo(1, x)");
    }

    #[test]
    fn test_emit_ternary() {
        let env = TypeEnvironment::new();
        let e = emitter(&env);
        let expr = Expr::Ternary {
            cond: Box::new(Expr::Var("c".to_string())),
            then_expr: Box::new(Expr::Const(1, IntWidth::I32)),
            else_expr: Box::new(Expr::Const(0, IntWidth::I32)),
        };
        let result = e.emit(&expr).unwrap();
        assert!(result.contains('?'));
    }

    // â"€â"€ TypeAwareRenamer â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_rename_int() {
        let mut r = TypeAwareRenamer::new();
        let name = r.rename(&DecompType::Int(IntWidth::I32));
        assert!(name.starts_with('i'));
    }

    #[test]
    fn test_rename_ptr() {
        let mut r = TypeAwareRenamer::new();
        let name = r.rename(&DecompType::Ptr(Box::new(DecompType::Void)));
        assert!(name.starts_with("p_"));
    }

    #[test]
    fn test_rename_struct_ptr() {
        let mut r = TypeAwareRenamer::new();
        let st = make_node_struct();
        let name = r.rename(&DecompType::Ptr(Box::new(DecompType::Struct(Box::new(st)))));
        assert!(name.starts_with("p_node_"));
    }

    #[test]
    fn test_rename_cstr() {
        let mut r = TypeAwareRenamer::new();
        let name = r.rename(&DecompType::CStr);
        assert!(name.starts_with("sz_"));
    }

    #[test]
    fn test_rename_bool() {
        let mut r = TypeAwareRenamer::new();
        let name = r.rename(&DecompType::Bool);
        assert!(name.starts_with("b_"));
    }

    #[test]
    fn test_rename_counter_increments() {
        let mut r = TypeAwareRenamer::new();
        let n0 = r.rename(&DecompType::Int(IntWidth::I32));
        let n1 = r.rename(&DecompType::Int(IntWidth::I32));
        assert_ne!(n0, n1);
    }

    #[test]
    fn test_rename_reset() {
        let mut r = TypeAwareRenamer::new();
        let n0 = r.rename(&DecompType::Int(IntWidth::I32));
        r.reset();
        let n1 = r.rename(&DecompType::Int(IntWidth::I32));
        assert_eq!(n0, n1);
    }

    #[test]
    fn test_rename_all() {
        let mut r = TypeAwareRenamer::new();
        let vars = vec![
            ("t0".to_string(), DecompType::Int(IntWidth::I32)),
            (
                "t1".to_string(),
                DecompType::Ptr(Box::new(DecompType::Void)),
            ),
        ];
        let map = r.rename_all(&vars);
        assert!(map.contains_key("t0"));
        assert!(map.contains_key("t1"));
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// TypeQualifier —" bitflags-style qualifier set
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Qualifiers that can be applied to a C type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct TypeQualifier(pub u8);

impl TypeQualifier {
    pub const NONE: Self = Self(0);
    pub const CONST: Self = Self(1 << 0);
    pub const VOLATILE: Self = Self(1 << 1);
    pub const RESTRICT: Self = Self(1 << 2);

    #[must_use]
    pub const fn is_const(self) -> bool {
        self.0 & Self::CONST.0 != 0
    }

    #[must_use]
    pub const fn is_volatile(self) -> bool {
        self.0 & Self::VOLATILE.0 != 0
    }

    #[must_use]
    pub const fn is_restrict(self) -> bool {
        self.0 & Self::RESTRICT.0 != 0
    }

    #[must_use]
    pub const fn with_const(self) -> Self {
        Self(self.0 | Self::CONST.0)
    }

    #[must_use]
    pub const fn with_volatile(self) -> Self {
        Self(self.0 | Self::VOLATILE.0)
    }

    #[must_use]
    pub const fn with_restrict(self) -> Self {
        Self(self.0 | Self::RESTRICT.0)
    }

    #[must_use]
    pub fn qualifier_string(self) -> String {
        let mut parts = Vec::new();
        if self.is_const() {
            parts.push("const");
        }
        if self.is_volatile() {
            parts.push("volatile");
        }
        if self.is_restrict() {
            parts.push("restrict");
        }
        parts.join(" ")
    }
}

impl std::fmt::Display for TypeQualifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.qualifier_string())
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// QualifiedType —" a type with optional qualifiers
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A [`DecompType`] with attached qualifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualifiedType {
    pub ty: DecompType,
    pub qualifiers: TypeQualifier,
}

impl QualifiedType {
    #[must_use]
    pub const fn new(ty: DecompType) -> Self {
        Self {
            ty,
            qualifiers: TypeQualifier::NONE,
        }
    }

    #[must_use]
    pub const fn with_qualifiers(mut self, q: TypeQualifier) -> Self {
        self.qualifiers = q;
        self
    }

    #[must_use]
    pub fn c_name(&self) -> String {
        let q = self.qualifiers.qualifier_string();
        if q.is_empty() {
            self.ty.c_name()
        } else {
            format!("{} {}", q, self.ty.c_name())
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// UnionType
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A union type definition (all members share the same storage).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnionType {
    pub name: String,
    pub members: Vec<StructField>,
    pub total_size: u64,
}

impl UnionType {
    #[must_use]
    pub fn new(name: impl Into<String>, members: Vec<StructField>) -> Self {
        let total_size = members
            .iter()
            .filter_map(|m| m.ty.byte_size())
            .max()
            .unwrap_or(0);
        Self {
            name: name.into(),
            members,
            total_size,
        }
    }

    #[must_use]
    pub fn member_named(&self, name: &str) -> Option<&StructField> {
        self.members.iter().find(|m| m.name == name)
    }

    #[must_use]
    pub fn c_name(&self) -> String {
        format!("union {}", self.name)
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// FunctionType
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A function type (used for prototypes and function pointers).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionType {
    pub name: String,
    pub return_type: DecompType,
    pub parameters: Vec<(String, DecompType)>,
    pub is_variadic: bool,
    pub calling_convention: CallingConvention,
}

/// Calling conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CallingConvention {
    #[default]
    CDecl,
    StdCall,
    FastCall,
    ThisCall,
    SysV64,
    MsX64,
    Custom,
}

impl CallingConvention {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CDecl => "__cdecl",
            Self::StdCall => "__stdcall",
            Self::FastCall => "__fastcall",
            Self::ThisCall => "__thiscall",
            Self::SysV64 => "/*sysv64*/",
            Self::MsX64 => "/*ms_x64*/",
            Self::Custom => "/*custom*/",
        }
    }
}

impl FunctionType {
    #[must_use]
    pub fn new(name: impl Into<String>, return_type: DecompType) -> Self {
        Self {
            name: name.into(),
            return_type,
            parameters: Vec::new(),
            is_variadic: false,
            calling_convention: CallingConvention::default(),
        }
    }

    pub fn add_param(&mut self, name: impl Into<String>, ty: DecompType) {
        self.parameters.push((name.into(), ty));
    }

    #[must_use]
    pub fn c_prototype(&self) -> String {
        let params: Vec<String> = self
            .parameters
            .iter()
            .map(|(n, t)| format!("{} {}", t.c_name(), n))
            .collect();
        let variadic = if self.is_variadic { ", ..." } else { "" };
        format!(
            "{} {} {}({}{})",
            self.return_type.c_name(),
            self.calling_convention.as_str(),
            self.name,
            params.join(", "),
            variadic
        )
    }

    #[must_use]
    pub const fn arity(&self) -> usize {
        self.parameters.len()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// TypeLayout —" computed layout of a type
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Computed memory layout information for a type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeLayout {
    pub size: u64,
    pub alignment: u64,
    pub field_offsets: Vec<(String, u64)>,
}

impl TypeLayout {
    /// Compute layout for a struct type (simple non-packed).
    #[must_use]
    pub fn for_struct(st: &StructType) -> Self {
        let mut offsets = Vec::with_capacity(st.fields.len());
        let mut max_align = 1u64;
        for field in &st.fields {
            let sz = field.ty.byte_size().unwrap_or(1);
            let align = sz.min(8);
            max_align = max_align.max(align);
            offsets.push((field.name.clone(), field.offset));
        }
        Self {
            size: st.total_size,
            alignment: max_align,
            field_offsets: offsets,
        }
    }

    #[must_use]
    pub const fn padded_size(&self) -> u64 {
        if self.alignment == 0 {
            return self.size;
        }
        let rem = self.size % self.alignment;
        if rem == 0 {
            self.size
        } else {
            self.size + self.alignment - rem
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// TypeConstraint / TypeUnifier
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A constraint that two variables must have compatible types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeConstraint {
    pub lhs: String,
    pub rhs: String,
    pub reason: String,
}

impl TypeConstraint {
    #[must_use]
    pub fn new(lhs: impl Into<String>, rhs: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            lhs: lhs.into(),
            rhs: rhs.into(),
            reason: reason.into(),
        }
    }
}

/// Unifies type constraints using a union-find approach.
#[derive(Debug, Default)]
pub struct TypeUnifier {
    constraints: Vec<TypeConstraint>,
    /// Union-find parent table.
    parent: HashMap<String, String>,
}

impl TypeUnifier {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_constraint(&mut self, c: &TypeConstraint) {
        self.constraints.push(c.clone());
        self.union(&c.lhs, &c.rhs);
    }

    fn find(&mut self, x: &str) -> String {
        if !self.parent.contains_key(x) {
            self.parent.insert(x.to_string(), x.to_string());
            return x.to_string();
        }
        let p = self.parent[x].clone();
        if p == x {
            return x.to_string();
        }
        let root = self.find(&p);
        self.parent.insert(x.to_string(), root.clone());
        root
    }

    fn union(&mut self, a: &str, b: &str) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra != rb {
            self.parent.insert(ra, rb);
        }
    }

    /// Return the canonical representative for a variable.
    pub fn canonical(&mut self, var: &str) -> String {
        self.find(var)
    }

    /// Return all equivalence classes.
    pub fn equivalence_classes(&mut self) -> HashMap<String, Vec<String>> {
        let keys: Vec<String> = self.parent.keys().cloned().collect();
        let mut classes: HashMap<String, Vec<String>> = HashMap::new();
        for key in keys {
            let root = self.find(&key.clone());
            classes.entry(root).or_default().push(key);
        }
        classes
    }

    #[must_use]
    pub const fn constraint_count(&self) -> usize {
        self.constraints.len()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// TypeInference engine
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Forward-propagating type inference engine.
#[derive(Debug, Default)]
pub struct TypeInference {
    env: TypeEnvironment,
    unifier: TypeUnifier,
    constraints: Vec<TypeConstraint>,
}

impl TypeInference {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_type(&mut self, var: impl Into<String>, ty: DecompType) {
        self.env.set(var, ty);
    }

    pub fn add_constraint(&mut self, c: TypeConstraint) {
        self.unifier.add_constraint(&c);
        self.constraints.push(c);
    }

    pub fn infer_assignment(&mut self, dst: &str, src_ty: DecompType) {
        self.env.set(dst, src_ty);
    }

    pub fn infer_pointer_deref(&mut self, ptr_var: &str, result_var: &str) {
        if let Some(ty) = self.env.get(ptr_var).cloned()
            && let DecompType::Ptr(inner) = ty {
                self.env.set(result_var, *inner);
            }
    }

    #[must_use]
    pub fn get_type(&self, var: &str) -> Option<&DecompType> {
        self.env.get(var)
    }

    #[must_use]
    pub fn type_count(&self) -> usize {
        self.env.vars.len()
    }

    /// Propagate types through a list of variable assignments.
    pub fn propagate(&mut self, assignments: &[(String, String)]) {
        for (dst, src) in assignments {
            if let Some(ty) = self.env.get(src).cloned() {
                self.env.set(dst.clone(), ty);
            }
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// TypePropagator
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Propagates types across expression boundaries.
#[derive(Debug, Default)]
pub struct TypePropagator {
    known: HashMap<String, DecompType>,
    propagation_log: Vec<String>,
}

impl TypePropagator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seed(&mut self, var: impl Into<String>, ty: DecompType) {
        self.known.insert(var.into(), ty);
    }

    pub fn propagate_through_binop(&mut self, result: &str, lhs: &str, _rhs: &str) {
        if let Some(ty) = self.known.get(lhs).cloned()
            && !self.known.contains_key(result) {
                self.propagation_log.push(format!("{result} <- {lhs}"));
                self.known.insert(result.to_string(), ty);
            }
    }

    pub fn propagate_through_assign(&mut self, dst: &str, src: &str) {
        if let Some(ty) = self.known.get(src).cloned() {
            self.propagation_log.push(format!("{dst} = {src}"));
            self.known.insert(dst.to_string(), ty);
        }
    }

    #[must_use]
    pub fn get(&self, var: &str) -> Option<&DecompType> {
        self.known.get(var)
    }

    #[must_use]
    pub const fn propagation_count(&self) -> usize {
        self.propagation_log.len()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// TypeRecovery
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Recovers type information from binary patterns.
#[derive(Debug, Default)]
pub struct TypeRecovery {
    recovered: HashMap<u64, DecompType>,
}

impl TypeRecovery {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, addr: u64, ty: DecompType) {
        self.recovered.insert(addr, ty);
    }

    #[must_use]
    pub fn get(&self, addr: u64) -> Option<&DecompType> {
        self.recovered.get(&addr)
    }

    /// Heuristic: if a value is written to and read from as a 4-byte word, infer `int32_t`.
    pub fn infer_from_access_size(&mut self, addr: u64, access_size: u8) {
        let ty = match access_size {
            1 => DecompType::Int(IntWidth::U8),
            2 => DecompType::Int(IntWidth::U16),
            4 => DecompType::Int(IntWidth::U32),
            8 => DecompType::Int(IntWidth::U64),
            _ => DecompType::Unknown,
        };
        self.recovered.entry(addr).or_insert(ty);
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.recovered.len()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// CTypeEmitter —" emits C type declarations
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Emits formatted C type declarations.
#[derive(Debug, Default)]
pub struct CTypeEmitter {
    indent: usize,
}

impl CTypeEmitter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_indent(indent: usize) -> Self {
        Self { indent }
    }

    fn pad(&self) -> String {
        "    ".repeat(self.indent)
    }

    /// Emit a struct declaration.
    #[must_use]
    pub fn emit_struct(&self, st: &StructType) -> String {
        let pad = self.pad();
        let mut out = format!("{pad}struct {} {{\n", st.name);
        for field in &st.fields {
            writeln!(out, "{pad}    {} {}; // offset {:#x}", field.ty.c_name(), field.name, field.offset).unwrap();
        }
        writeln!(out, "{pad}}}; // size = {:#x}", st.total_size).unwrap();
        out
    }

    /// Emit a union declaration.
    #[must_use]
    pub fn emit_union(&self, u: &UnionType) -> String {
        let pad = self.pad();
        let mut out = format!("{pad}union {} {{\n", u.name);
        for member in &u.members {
            writeln!(out, "{pad}    {} {};", member.ty.c_name(), member.name).unwrap();
        }
        writeln!(out, "{pad}}}; // size = {:#x}", u.total_size).unwrap();
        out
    }

    /// Emit a function prototype.
    #[must_use]
    pub fn emit_function(&self, f: &FunctionType) -> String {
        format!("{}{};", self.pad(), f.c_prototype())
    }

    /// Emit a typedef.
    #[must_use]
    pub fn emit_typedef(&self, alias: &str, ty: &DecompType) -> String {
        format!("{}typedef {} {};", self.pad(), ty.c_name(), alias)
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// TypeDatabase
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// In-memory database of all types for a binary.
#[derive(Debug, Default)]
pub struct TypeDatabase {
    structs: HashMap<String, StructType>,
    unions: HashMap<String, UnionType>,
    functions: HashMap<String, FunctionType>,
    typedefs: HashMap<String, DecompType>,
}

impl TypeDatabase {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_struct(&mut self, st: StructType) {
        self.structs.insert(st.name.clone(), st);
    }

    pub fn add_union(&mut self, u: UnionType) {
        self.unions.insert(u.name.clone(), u);
    }

    pub fn add_function(&mut self, f: FunctionType) {
        self.functions.insert(f.name.clone(), f);
    }

    pub fn add_typedef(&mut self, alias: impl Into<String>, ty: DecompType) {
        self.typedefs.insert(alias.into(), ty);
    }

    #[must_use]
    pub fn get_struct(&self, name: &str) -> Option<&StructType> {
        self.structs.get(name)
    }

    #[must_use]
    pub fn get_union(&self, name: &str) -> Option<&UnionType> {
        self.unions.get(name)
    }

    #[must_use]
    pub fn get_function(&self, name: &str) -> Option<&FunctionType> {
        self.functions.get(name)
    }

    #[must_use]
    pub fn resolve_typedef(&self, alias: &str) -> Option<&DecompType> {
        self.typedefs.get(alias)
    }

    #[must_use]
    pub fn struct_count(&self) -> usize {
        self.structs.len()
    }

    #[must_use]
    pub fn union_count(&self) -> usize {
        self.unions.len()
    }

    #[must_use]
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    #[must_use]
    pub fn typedef_count(&self) -> usize {
        self.typedefs.len()
    }

    /// Populate common Windows types.
    pub fn load_windows_types(&mut self) {
        // DWORD
        self.add_typedef("DWORD", DecompType::Int(IntWidth::U32));
        self.add_typedef("WORD", DecompType::Int(IntWidth::U16));
        self.add_typedef("BYTE", DecompType::Int(IntWidth::U8));
        self.add_typedef("BOOL", DecompType::Int(IntWidth::I32));
        self.add_typedef("HANDLE", DecompType::Ptr(Box::new(DecompType::Void)));
        self.add_typedef("LPVOID", DecompType::Ptr(Box::new(DecompType::Void)));
        self.add_typedef("LPCSTR", DecompType::CStr);
        self.add_typedef("LPSTR", DecompType::CStr);
        self.add_typedef("HMODULE", DecompType::Ptr(Box::new(DecompType::Void)));
        self.add_typedef("HINSTANCE", DecompType::Ptr(Box::new(DecompType::Void)));
        self.add_typedef("HWND", DecompType::Ptr(Box::new(DecompType::Void)));
        self.add_typedef("UINT", DecompType::Int(IntWidth::U32));
        self.add_typedef("INT", DecompType::Int(IntWidth::I32));
        self.add_typedef("LONG", DecompType::Int(IntWidth::I32));
        self.add_typedef("ULONG", DecompType::Int(IntWidth::U32));
        self.add_typedef("LONGLONG", DecompType::Int(IntWidth::I64));
        self.add_typedef("ULONGLONG", DecompType::Int(IntWidth::U64));
        self.add_typedef("ULONG_PTR", DecompType::Int(IntWidth::U64));
        self.add_typedef("SIZE_T", DecompType::Int(IntWidth::U64));
        self.add_typedef("PVOID", DecompType::Ptr(Box::new(DecompType::Void)));
        // POINT struct
        self.add_struct(StructType::new(
            "POINT",
            vec![
                StructField::new(0, "x", DecompType::Int(IntWidth::I32)),
                StructField::new(4, "y", DecompType::Int(IntWidth::I32)),
            ],
            8,
        ));
        // RECT struct
        self.add_struct(StructType::new(
            "RECT",
            vec![
                StructField::new(0, "left", DecompType::Int(IntWidth::I32)),
                StructField::new(4, "top", DecompType::Int(IntWidth::I32)),
                StructField::new(8, "right", DecompType::Int(IntWidth::I32)),
                StructField::new(12, "bottom", DecompType::Int(IntWidth::I32)),
            ],
            16,
        ));
    }

    /// Populate common Linux/POSIX types.
    pub fn load_linux_types(&mut self) {
        self.add_typedef("pid_t", DecompType::Int(IntWidth::I32));
        self.add_typedef("uid_t", DecompType::Int(IntWidth::U32));
        self.add_typedef("gid_t", DecompType::Int(IntWidth::U32));
        self.add_typedef("size_t", DecompType::Int(IntWidth::U64));
        self.add_typedef("ssize_t", DecompType::Int(IntWidth::I64));
        self.add_typedef("off_t", DecompType::Int(IntWidth::I64));
        self.add_typedef("time_t", DecompType::Int(IntWidth::I64));
        self.add_typedef("mode_t", DecompType::Int(IntWidth::U32));
        self.add_typedef("ino_t", DecompType::Int(IntWidth::U64));
        self.add_typedef("dev_t", DecompType::Int(IntWidth::U64));
        self.add_typedef("nlink_t", DecompType::Int(IntWidth::U64));
        self.add_typedef("blksize_t", DecompType::Int(IntWidth::I64));
        self.add_typedef("blkcnt_t", DecompType::Int(IntWidth::I64));
    }

    /// Emit all struct declarations.
    #[must_use]
    pub fn emit_all_structs(&self) -> String {
        let emitter = CTypeEmitter::new();
        self.structs
            .values()
            .map(|st| emitter.emit_struct(st))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// TypeCompatibility
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Check whether two types are assignment-compatible.
#[must_use]
pub fn are_compatible(a: &DecompType, b: &DecompType) -> bool {
    if a == b {
        return true;
    }
    matches!((a, b), (DecompType::Int(_), DecompType::Int(_)) |
(DecompType::Ptr(_) | DecompType::Unknown, DecompType::Ptr(_)) |
(DecompType::Ptr(_) | _, DecompType::Unknown) | (DecompType::Unknown, _))
}

/// Check if `a` is implicitly convertible to `b`.
#[must_use]
pub fn is_implicitly_convertible(a: &DecompType, b: &DecompType) -> bool {
    if are_compatible(a, b) {
        return true;
    }
    // Smaller integers can convert to larger ones.
    if let (DecompType::Int(wa), DecompType::Int(wb)) = (a, b) {
        return wa.bits() <= wb.bits();
    }
    // Float can convert to double.
    matches!((a, b), (DecompType::Float32, DecompType::Float64))
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// StandardLibTypes
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Generates standard C library function types.
pub struct StandardLibTypes;

impl StandardLibTypes {
    /// Build a `TypeDatabase` pre-populated with common C stdlib functions.
    #[must_use]
    pub fn stdlib_db() -> TypeDatabase {
        let mut db = TypeDatabase::new();

        // malloc
        let mut malloc = FunctionType::new("malloc", DecompType::Ptr(Box::new(DecompType::Void)));
        malloc.add_param("size", DecompType::Int(IntWidth::U64));
        db.add_function(malloc);

        // free
        let mut free = FunctionType::new("free", DecompType::Void);
        free.add_param("ptr", DecompType::Ptr(Box::new(DecompType::Void)));
        db.add_function(free);

        // memcpy
        let mut memcpy = FunctionType::new("memcpy", DecompType::Ptr(Box::new(DecompType::Void)));
        memcpy.add_param("dst", DecompType::Ptr(Box::new(DecompType::Void)));
        memcpy.add_param("src", DecompType::Ptr(Box::new(DecompType::Void)));
        memcpy.add_param("n", DecompType::Int(IntWidth::U64));
        db.add_function(memcpy);

        // memset
        let mut memset = FunctionType::new("memset", DecompType::Ptr(Box::new(DecompType::Void)));
        memset.add_param("s", DecompType::Ptr(Box::new(DecompType::Void)));
        memset.add_param("c", DecompType::Int(IntWidth::I32));
        memset.add_param("n", DecompType::Int(IntWidth::U64));
        db.add_function(memset);

        // strlen
        let mut strlen = FunctionType::new("strlen", DecompType::Int(IntWidth::U64));
        strlen.add_param("s", DecompType::CStr);
        db.add_function(strlen);

        // printf
        let mut printf = FunctionType::new("printf", DecompType::Int(IntWidth::I32));
        printf.add_param("fmt", DecompType::CStr);
        printf.is_variadic = true;
        db.add_function(printf);

        db
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PointerAnalysis
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Tracks pointer aliasing and points-to information.
#[derive(Debug, Default)]
pub struct PointerAnalysis {
    points_to: HashMap<String, Vec<String>>,
    may_alias: Vec<(String, String)>,
}

impl PointerAnalysis {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_points_to(&mut self, ptr: impl Into<String>, target: impl Into<String>) {
        self.points_to
            .entry(ptr.into())
            .or_default()
            .push(target.into());
    }

    pub fn record_may_alias(&mut self, a: impl Into<String>, b: impl Into<String>) {
        self.may_alias.push((a.into(), b.into()));
    }

    #[must_use]
    pub fn points_to_targets(&self, ptr: &str) -> &[String] {
        self.points_to.get(ptr).map_or(&[], Vec::as_slice)
    }

    #[must_use]
    pub fn may_alias_with(&self, a: &str) -> Vec<&str> {
        self.may_alias
            .iter()
            .filter_map(|(x, y)| {
                if x == a {
                    Some(y.as_str())
                } else if y == a {
                    Some(x.as_str())
                } else {
                    None
                }
            })
            .collect()
    }

    #[must_use]
    pub fn is_definitely_not_null(&self, ptr: &str) -> bool {
        !self.points_to.get(ptr).unwrap_or(&Vec::new()).is_empty()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Additional tests
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod extended_tests {
    use super::*;

    // â"€â"€ TypeQualifier â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_type_qualifier_const() {
        let q = TypeQualifier::CONST;
        assert!(q.is_const());
        assert!(!q.is_volatile());
        assert_eq!(q.qualifier_string(), "const");
    }

    #[test]
    fn test_type_qualifier_combined() {
        let q = TypeQualifier::CONST.with_volatile();
        assert!(q.is_const());
        assert!(q.is_volatile());
    }

    #[test]
    fn test_qualified_type_c_name() {
        let qt = QualifiedType::new(DecompType::Int(IntWidth::I32))
            .with_qualifiers(TypeQualifier::CONST);
        assert_eq!(qt.c_name(), "const int");
    }

    // â"€â"€ UnionType â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_union_type_size() {
        let u = UnionType::new(
            "MyUnion",
            vec![
                StructField::new(0, "i", DecompType::Int(IntWidth::I32)),
                StructField::new(0, "f", DecompType::Float32),
                StructField::new(0, "ll", DecompType::Int(IntWidth::I64)),
            ],
        );
        assert_eq!(u.total_size, 8);
    }

    #[test]
    fn test_union_member_named() {
        let u = UnionType::new(
            "U",
            vec![StructField::new(0, "x", DecompType::Int(IntWidth::I32))],
        );
        assert!(u.member_named("x").is_some());
        assert!(u.member_named("z").is_none());
    }

    // â"€â"€ FunctionType â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_function_type_prototype() {
        let mut f = FunctionType::new("add", DecompType::Int(IntWidth::I32));
        f.add_param("a", DecompType::Int(IntWidth::I32));
        f.add_param("b", DecompType::Int(IntWidth::I32));
        let proto = f.c_prototype();
        assert!(proto.contains("add"));
        assert!(proto.contains("int"));
    }

    #[test]
    fn test_function_type_arity() {
        let mut f = FunctionType::new("fn", DecompType::Void);
        f.add_param("x", DecompType::Int(IntWidth::U64));
        assert_eq!(f.arity(), 1);
    }

    #[test]
    fn test_function_type_variadic() {
        let mut f = FunctionType::new("printf", DecompType::Int(IntWidth::I32));
        f.add_param("fmt", DecompType::CStr);
        f.is_variadic = true;
        assert!(f.c_prototype().contains("..."));
    }

    // â"€â"€ CallingConvention â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_calling_convention_str() {
        assert_eq!(CallingConvention::CDecl.as_str(), "__cdecl");
        assert_eq!(CallingConvention::StdCall.as_str(), "__stdcall");
    }

    // â"€â"€ TypeLayout â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_type_layout_for_struct() {
        let st = StructType::new(
            "Foo",
            vec![
                StructField::new(0, "a", DecompType::Int(IntWidth::I32)),
                StructField::new(4, "b", DecompType::Int(IntWidth::I32)),
            ],
            8,
        );
        let layout = TypeLayout::for_struct(&st);
        assert_eq!(layout.size, 8);
        assert_eq!(layout.field_offsets.len(), 2);
    }

    #[test]
    fn test_type_layout_padded_size() {
        let layout = TypeLayout {
            size: 7,
            alignment: 4,
            field_offsets: vec![],
        };
        assert_eq!(layout.padded_size(), 8);
    }

    // â"€â"€ TypeUnifier â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_type_unifier_same_class() {
        let mut u = TypeUnifier::new();
        u.add_constraint(&TypeConstraint::new("x", "y", "assign"));
        u.add_constraint(&TypeConstraint::new("y", "z", "assign"));
        let cx = u.canonical("x");
        let cz = u.canonical("z");
        assert_eq!(cx, cz);
    }

    #[test]
    fn test_type_unifier_constraint_count() {
        let mut u = TypeUnifier::new();
        u.add_constraint(&TypeConstraint::new("a", "b", "test"));
        assert_eq!(u.constraint_count(), 1);
    }

    // â"€â"€ TypeInference â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_type_inference_set_get() {
        let mut inf = TypeInference::new();
        inf.set_type("x", DecompType::Int(IntWidth::I32));
        assert!(inf.get_type("x").is_some());
    }

    #[test]
    fn test_type_inference_propagate() {
        let mut inf = TypeInference::new();
        inf.set_type("src", DecompType::Int(IntWidth::I64));
        inf.propagate(&[("dst".to_string(), "src".to_string())]);
        assert_eq!(inf.get_type("dst"), Some(&DecompType::Int(IntWidth::I64)));
    }

    // â"€â"€ TypePropagator â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_type_propagator_seed_and_get() {
        let mut tp = TypePropagator::new();
        tp.seed("p", DecompType::Ptr(Box::new(DecompType::Void)));
        assert!(tp.get("p").is_some());
    }

    #[test]
    fn test_type_propagator_through_assign() {
        let mut tp = TypePropagator::new();
        tp.seed("a", DecompType::Int(IntWidth::I32));
        tp.propagate_through_assign("b", "a");
        assert!(tp.get("b").is_some());
        assert_eq!(tp.propagation_count(), 1);
    }

    // â"€â"€ TypeRecovery â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_type_recovery_from_access_size() {
        let mut tr = TypeRecovery::new();
        tr.infer_from_access_size(0x1000, 4);
        assert_eq!(tr.get(0x1000), Some(&DecompType::Int(IntWidth::U32)));
    }

    #[test]
    fn test_type_recovery_count() {
        let mut tr = TypeRecovery::new();
        tr.record(0x1000, DecompType::Int(IntWidth::I32));
        tr.record(0x2000, DecompType::Int(IntWidth::I64));
        assert_eq!(tr.count(), 2);
    }

    // â"€â"€ CTypeEmitter â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_type_emitter_struct() {
        let emitter = CTypeEmitter::new();
        let st = StructType::new(
            "Point",
            vec![
                StructField::new(0, "x", DecompType::Int(IntWidth::I32)),
                StructField::new(4, "y", DecompType::Int(IntWidth::I32)),
            ],
            8,
        );
        let out = emitter.emit_struct(&st);
        assert!(out.contains("struct Point"));
        assert!(out.contains('x'));
        assert!(out.contains('y'));
    }

    #[test]
    fn test_type_emitter_typedef() {
        let emitter = CTypeEmitter::new();
        let out = emitter.emit_typedef("MyInt", &DecompType::Int(IntWidth::I32));
        assert!(out.contains("typedef"));
        assert!(out.contains("MyInt"));
    }

    #[test]
    fn test_type_emitter_union() {
        let emitter = CTypeEmitter::new();
        let u = UnionType::new(
            "IntOrFloat",
            vec![
                StructField::new(0, "i", DecompType::Int(IntWidth::I32)),
                StructField::new(0, "f", DecompType::Float32),
            ],
        );
        let out = emitter.emit_union(&u);
        assert!(out.contains("union IntOrFloat"));
    }

    // â"€â"€ TypeDatabase â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_type_db_windows_types() {
        let mut db = TypeDatabase::new();
        db.load_windows_types();
        assert!(db.resolve_typedef("DWORD").is_some());
        assert!(db.resolve_typedef("HANDLE").is_some());
        assert!(db.get_struct("RECT").is_some());
        assert!(db.get_struct("POINT").is_some());
    }

    #[test]
    fn test_type_db_linux_types() {
        let mut db = TypeDatabase::new();
        db.load_linux_types();
        assert!(db.resolve_typedef("pid_t").is_some());
        assert!(db.resolve_typedef("size_t").is_some());
    }

    #[test]
    fn test_type_db_add_function() {
        let mut db = TypeDatabase::new();
        let f = FunctionType::new("myfunc", DecompType::Void);
        db.add_function(f);
        assert_eq!(db.function_count(), 1);
        assert!(db.get_function("myfunc").is_some());
    }

    #[test]
    fn test_stdlib_db() {
        let db = StandardLibTypes::stdlib_db();
        assert!(db.get_function("malloc").is_some());
        assert!(db.get_function("free").is_some());
        assert!(db.get_function("printf").is_some());
    }

    // â"€â"€ TypeCompatibility â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_are_compatible_same() {
        assert!(are_compatible(
            &DecompType::Int(IntWidth::I32),
            &DecompType::Int(IntWidth::I32)
        ));
    }

    #[test]
    fn test_are_compatible_ints() {
        assert!(are_compatible(
            &DecompType::Int(IntWidth::I8),
            &DecompType::Int(IntWidth::I64)
        ));
    }

    #[test]
    fn test_are_compatible_ptr_unknown() {
        assert!(are_compatible(
            &DecompType::Ptr(Box::new(DecompType::Void)),
            &DecompType::Unknown,
        ));
    }

    #[test]
    fn test_is_implicitly_convertible_float() {
        assert!(is_implicitly_convertible(
            &DecompType::Float32,
            &DecompType::Float64
        ));
    }

    // â"€â"€ PointerAnalysis â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_pointer_analysis_points_to() {
        let mut pa = PointerAnalysis::new();
        pa.record_points_to("p", "heap_block");
        assert_eq!(pa.points_to_targets("p"), &["heap_block"]);
        assert!(pa.is_definitely_not_null("p"));
    }

    #[test]
    fn test_pointer_analysis_may_alias() {
        let mut pa = PointerAnalysis::new();
        pa.record_may_alias("p", "q");
        let aliases = pa.may_alias_with("p");
        assert!(aliases.contains(&"q"));
    }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Multi-level type recovery: access-width sizing, primitive inference from
// operations, pointer detection from dereferences, struct-field clustering from
// `*(ptr+offset)`, array inference from `*(ptr + i*stride)`, and a constraint
// solver built on union-find over a small type lattice.
//
// This module is purely additive; it builds on `DecompType`, `IntWidth`, etc.
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

use std::collections::{BTreeMap, HashSet};

use rustre_decompiler_expr::UnOp;

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Type lattice
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A point in the simple type lattice used by the constraint solver. The
/// lattice orders types from least to most specific:
///
/// ```text
///                Top (Unknown)
///              /      |       \
///        Integer    Pointer   Float
///         |  |        |
///       sizes—¦     pointee—¦
///              \     |     /
///                  Bottom (conflict)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LatticeType {
    /// Unknown —" no information yet (the lattice top).
    Top,
    /// An integer of a known width and signedness, or unknown width.
    Integer { width: Option<IntWidth> },
    /// A boolean.
    Bool,
    /// A 32-bit float.
    Float32,
    /// A 64-bit float.
    Float64,
    /// A pointer to an inner lattice type.
    Pointer(Box<Self>),
    /// A conflict —" two incompatible facts were merged (the lattice bottom).
    Bottom,
}

impl LatticeType {
    /// Join (least upper bound) —" merges two facts about the same value. If
    /// they conflict, the result is `Bottom`.
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        use LatticeType::{Bool, Bottom, Float32, Float64, Integer, Pointer, Top};
        match (self, other) {
            (Top, x) | (x, Top) => x.clone(),
            (Integer { width: a }, Integer { width: b }) => Integer {
                width: join_width(*a, *b),
            },
            (Pointer(a), Pointer(b)) => Pointer(Box::new(a.join(b))),
            (Bool, Bool) => Bool,
            (Float32, Float32) => Float32,
            // Float widening: f32 âŠ" f64 â†' f64 (the wider).
            (Float64 | Float32, Float64) | (Float64, Float32) => Float64,
            // A pointer is also pointer-sized integer-compatible, but mixing a
            // concrete pointer with an integer is a conflict for our purposes.
            _ => Bottom,
        }
    }

    /// Convert the lattice type to a concrete `DecompType`, using `default`
    /// when the lattice value is too vague.
    #[must_use]
    pub fn to_decomp(&self) -> DecompType {
        match self {
            Self::Top | Self::Bottom => DecompType::Unknown,
            Self::Bool => DecompType::Bool,
            Self::Float32 => DecompType::Float32,
            Self::Float64 => DecompType::Float64,
            Self::Integer { width } => DecompType::Int(width.unwrap_or(IntWidth::I32)),
            Self::Pointer(inner) => DecompType::Ptr(Box::new(inner.to_decomp())),
        }
    }

    /// Build a lattice type from a `DecompType`.
    #[must_use]
    pub fn from_decomp(ty: &DecompType) -> Self {
        match ty {
            DecompType::Bool => Self::Bool,
            DecompType::Float32 => Self::Float32,
            DecompType::Float64 => Self::Float64,
            DecompType::Int(w) => Self::Integer { width: Some(*w) },
            DecompType::Ptr(inner) => Self::Pointer(Box::new(Self::from_decomp(inner))),
            DecompType::CStr => Self::Pointer(Box::new(Self::Integer {
                width: Some(IntWidth::I8),
            })),
            _ => Self::Top,
        }
    }

    /// Is this the conflict (bottom) value?
    #[must_use]
    pub const fn is_conflict(&self) -> bool {
        matches!(self, Self::Bottom)
    }
}

/// Join two optional widths, preferring the wider one and a known signedness.
fn join_width(a: Option<IntWidth>, b: Option<IntWidth>) -> Option<IntWidth> {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some(x), Some(y)) => {
            // Take the wider width; prefer signed if either is signed.
            let bits = x.bits().max(y.bits());
            let signed = x.is_signed() || y.is_signed();
            Some(width_for(bits, signed))
        }
    }
}

/// The `IntWidth` for a bit-count and signedness.
#[must_use]
const fn width_for(bits: u32, signed: bool) -> IntWidth {
    match (bits, signed) {
        (0..=8, true) => IntWidth::I8,
        (0..=8, false) => IntWidth::U8,
        (9..=16, true) => IntWidth::I16,
        (9..=16, false) => IntWidth::U16,
        (17..=32, true) => IntWidth::I32,
        (17..=32, false) => IntWidth::U32,
        (_, true) => IntWidth::I64,
        (_, false) => IntWidth::U64,
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Access-width sizing
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Records the access widths observed for each variable and derives a sized
/// integer type from the widest access.
#[derive(Debug, Default)]
pub struct AccessWidthSizer {
    /// variable â†' set of byte widths seen.
    widths: HashMap<String, Vec<u8>>,
    /// variable â†' whether a signed operation was applied.
    signed: HashMap<String, bool>,
}

impl AccessWidthSizer {
    /// New sizer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an access of `bytes` width to `var`.
    pub fn observe(&mut self, var: impl Into<String>, bytes: u8) {
        self.widths.entry(var.into()).or_default().push(bytes);
    }

    /// Mark `var` as used in a signed operation.
    pub fn mark_signed(&mut self, var: impl Into<String>) {
        self.signed.insert(var.into(), true);
    }

    /// The inferred integer type for `var`, or `None` if never observed.
    #[must_use]
    pub fn infer(&self, var: &str) -> Option<DecompType> {
        let widths = self.widths.get(var)?;
        let max_bytes = widths.iter().copied().max()?;
        let signed = self.signed.get(var).copied().unwrap_or(false);
        let bits = u32::from(max_bytes) * 8;
        Some(DecompType::Int(width_for(bits, signed)))
    }

    /// Number of variables with observations.
    #[must_use]
    pub fn count(&self) -> usize {
        self.widths.len()
    }

    /// All variables that have at least one observation.
    #[must_use]
    pub fn vars(&self) -> Vec<String> {
        self.widths.keys().cloned().collect()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Primitive inference from operations
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Infers a primitive type for an expression based on the operations applied to
/// it (e.g. an `Sar` implies signed; a float op implies float).
#[derive(Debug, Default)]
pub struct PrimitiveInference;

impl PrimitiveInference {
    /// New engine.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Infer a lattice type from the shape of an expression.
    #[must_use]
    pub fn infer(&self, expr: &Expr) -> LatticeType {
        match expr {
            Expr::Const(v, w) => {
                // Pointer-ish large constants stay integer here; callers refine.
                let signed = *v < 0;
                LatticeType::Integer {
                    width: Some(if signed { w.to_signed() } else { *w }),
                }
            }
            Expr::UnOp(UnOp::Cast(w), _) => LatticeType::Integer { width: Some(*w) },
            Expr::UnOp(UnOp::Neg, e) => {
                // Negation implies a signed integer.
                match self.infer(e) {
                    LatticeType::Integer { width } => LatticeType::Integer {
                        width: width.map(IntWidth::to_signed),
                    },
                    other => other,
                }
            }
            Expr::UnOp(UnOp::Deref, e) | Expr::Load { ptr: e, .. } => {
                if let LatticeType::Pointer(inner) = self.infer(e) {
                    *inner
                } else {
                    LatticeType::Top
                }
            }
            Expr::UnOp(UnOp::AddrOf, e) => LatticeType::Pointer(Box::new(self.infer(e))),
            Expr::UnOp(_, e) => self.infer(e),
            Expr::BinOp(op, a, b) => self.infer_binop(*op, a, b),
            _ => LatticeType::Top,
        }
    }

    fn infer_binop(&self, op: BinOp, a: &Expr, b: &Expr) -> LatticeType {
        // Signed-shift-right implies signed integer.
        if op == BinOp::Sar {
            let inner = self.infer(a);
            return match inner {
                LatticeType::Integer { width } => LatticeType::Integer {
                    width: width.map(IntWidth::to_signed),
                },
                LatticeType::Top => LatticeType::Integer { width: None },
                other => other,
            };
        }
        if op.is_comparison() {
            return LatticeType::Bool;
        }
        if op.is_logical() {
            return LatticeType::Bool;
        }
        // Arithmetic / bitwise: join the operand inferences.
        let la = self.infer(a);
        let lb = self.infer(b);
        let joined = la.join(&lb);
        if joined.is_conflict() {
            // Fall back to a generic integer rather than a hard conflict for
            // mixed-but-compatible arithmetic.
            LatticeType::Integer { width: None }
        } else if matches!(joined, LatticeType::Top) {
            LatticeType::Integer { width: None }
        } else {
            joined
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Pointer detection
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Detects which variables are used as pointers (dereferenced or used as the
/// base of a memory access).
#[derive(Debug, Default)]
pub struct PointerDetector {
    pointer_vars: HashSet<String>,
}

impl PointerDetector {
    /// New detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan an expression, recording any variable that is dereferenced.
    pub fn scan(&mut self, expr: &Expr) {
        match expr {
            Expr::UnOp(UnOp::Deref, inner) | Expr::Load { ptr: inner, .. } => {
                self.mark_base(inner);
                self.scan(inner);
            }
            Expr::FieldAccess { base, .. } | Expr::Index { base, .. } => {
                self.mark_base(base);
                self.scan(base);
            }
            Expr::BinOp(_, a, b) => {
                self.scan(a);
                self.scan(b);
            }
            Expr::UnOp(_, e) => self.scan(e),
            Expr::Call { callee, args } => {
                self.scan(callee);
                for a in args {
                    self.scan(a);
                }
            }
            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                self.scan(cond);
                self.scan(then_expr);
                self.scan(else_expr);
            }
            _ => {}
        }
    }

    /// Mark the base variable of a memory access as a pointer (handles
    /// `ptr`, `ptr + k`, `ptr + i*scale`).
    fn mark_base(&mut self, expr: &Expr) {
        match expr {
            Expr::Var(v) => {
                self.pointer_vars.insert(v.clone());
            }
            Expr::BinOp(BinOp::Add | BinOp::Sub, a, _) => self.mark_base(a),
            _ => {}
        }
    }

    /// Is `var` known to be a pointer?
    #[must_use]
    pub fn is_pointer(&self, var: &str) -> bool {
        self.pointer_vars.contains(var)
    }

    /// All detected pointer variables (sorted).
    #[must_use]
    pub fn pointers(&self) -> Vec<String> {
        let mut v: Vec<String> = self.pointer_vars.iter().cloned().collect();
        v.sort();
        v
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Struct field clustering
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// One observed access into a candidate struct: (offset, byte width).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldAccess {
    /// Byte offset from the base pointer.
    pub offset: u64,
    /// Access width in bytes.
    pub width: u8,
}

/// Clusters `*(ptr + offset)` accesses by base pointer into candidate structs.
#[derive(Debug, Default)]
pub struct StructClusterer {
    /// base variable â†' set of (offset, width) accesses.
    accesses: BTreeMap<String, Vec<FieldAccess>>,
}

impl StructClusterer {
    /// New clusterer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an access to `base + offset` of the given width.
    pub fn observe(&mut self, base: impl Into<String>, offset: u64, width: u8) {
        self.accesses
            .entry(base.into())
            .or_default()
            .push(FieldAccess { offset, width });
    }

    /// Scan an expression for `*(base + const)` patterns and record them.
    /// `default_width` is used for a bare `*ptr` with no width annotation.
    pub fn scan(&mut self, expr: &Expr) {
        match expr {
            Expr::Load { ptr, size } => {
                self.record_access(ptr, *size);
                self.scan(ptr);
            }
            Expr::UnOp(UnOp::Deref, inner) => {
                self.record_access(inner, 8);
                self.scan(inner);
            }
            Expr::FieldAccess { base, offset } => {
                if let Expr::Var(v) = base.as_ref() {
                    self.observe(v.clone(), *offset, 8);
                }
                self.scan(base);
            }
            Expr::BinOp(_, a, b) => {
                self.scan(a);
                self.scan(b);
            }
            Expr::UnOp(_, e) => self.scan(e),
            Expr::Call { callee, args } => {
                self.scan(callee);
                for a in args {
                    self.scan(a);
                }
            }
            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                self.scan(cond);
                self.scan(then_expr);
                self.scan(else_expr);
            }
            _ => {}
        }
    }

    /// Given a pointer expression, record a field access if it is of the form
    /// `base + const`.
    fn record_access(&mut self, ptr: &Expr, width: u8) {
        match ptr {
            Expr::Var(v) => self.observe(v.clone(), 0, width),
            Expr::BinOp(BinOp::Add, a, b) => {
                if let (Expr::Var(v), Some(off)) = (a.as_ref(), b.as_const())
                    && off >= 0 {
                        self.observe(v.clone(), off.cast_unsigned(), width);
                    }
            }
            _ => {}
        }
    }

    /// Build a candidate struct from the clustered accesses of `base`. Fields
    /// are merged by offset (widest access wins), named `field_<offset>`.
    #[must_use]
    pub fn build_struct(&self, base: &str, name: &str) -> Option<StructType> {
        let accesses = self.accesses.get(base)?;
        if accesses.is_empty() {
            return None;
        }
        // Merge by offset; keep the widest width seen at each offset.
        let mut by_offset: BTreeMap<u64, u8> = BTreeMap::new();
        for a in accesses {
            let e = by_offset.entry(a.offset).or_insert(a.width);
            *e = (*e).max(a.width);
        }
        let mut fields = Vec::with_capacity(by_offset.len());
        let mut total = 0u64;
        for (offset, width) in by_offset {
            let ty = DecompType::Int(width_for(u32::from(width) * 8, false));
            fields.push(StructField::new(offset, format!("field_{offset:x}"), ty));
            total = total.max(offset + u64::from(width));
        }
        Some(StructType::new(name, fields, total))
    }

    /// Number of distinct base pointers observed.
    #[must_use]
    pub fn base_count(&self) -> usize {
        self.accesses.len()
    }

    /// Distinct offsets seen for `base`.
    #[must_use]
    pub fn offsets(&self, base: &str) -> Vec<u64> {
        let mut v: Vec<u64> = self
            .accesses
            .get(base)
            .map(|a| a.iter().map(|f| f.offset).collect())
            .unwrap_or_default();
        v.sort_unstable();
        v.dedup();
        v
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Array inference
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A recovered array access: base, index variable, and element stride.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArrayAccess {
    /// The base pointer variable.
    pub base: String,
    /// The index variable.
    pub index: String,
    /// The element stride in bytes.
    pub stride: u64,
}

/// Infers array element types from `*(base + index * stride)` patterns.
#[derive(Debug, Default)]
pub struct ArrayInference {
    accesses: Vec<ArrayAccess>,
}

impl ArrayInference {
    /// New engine.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan an expression, recording any array-index pattern found.
    pub fn scan(&mut self, expr: &Expr) {
        if let Some(a) = Self::match_array_access(expr) {
            self.accesses.push(a);
        }
        match expr {
            Expr::BinOp(_, a, b) => {
                self.scan(a);
                self.scan(b);
            }
            Expr::UnOp(_, e) | Expr::Load { ptr: e, .. } => self.scan(e),
            Expr::Index { base, index, .. } => {
                self.scan(base);
                self.scan(index);
            }
            Expr::Call { callee, args } => {
                self.scan(callee);
                for a in args {
                    self.scan(a);
                }
            }
            _ => {}
        }
    }

    /// Recognise `base + index * stride` or `base + (index << shift)`.
    #[must_use]
    pub fn match_array_access(expr: &Expr) -> Option<ArrayAccess> {
        let Expr::BinOp(BinOp::Add, base, offset) = expr else {
            return None;
        };
        let Expr::Var(base_var) = base.as_ref() else {
            return None;
        };
        match offset.as_ref() {
            Expr::BinOp(BinOp::Mul, idx, scale) => {
                let stride = scale.as_const()?.cast_unsigned();
                let index = idx.as_var()?.to_string();
                Some(ArrayAccess {
                    base: base_var.clone(),
                    index,
                    stride,
                })
            }
            Expr::BinOp(BinOp::Shl, idx, shift) => {
                let s = shift.as_const()?;
                let index = idx.as_var()?.to_string();
                Some(ArrayAccess {
                    base: base_var.clone(),
                    index,
                    stride: 1u64 << s,
                })
            }
            _ => None,
        }
    }

    /// Infer the element type for a base pointer from its stride (assumes a
    /// primitive element of `stride` bytes).
    #[must_use]
    pub fn element_type(&self, base: &str) -> Option<DecompType> {
        let stride = self.accesses.iter().find(|a| a.base == base)?.stride;
        let elem = match stride {
            2 => DecompType::Int(IntWidth::U16),
            4 => DecompType::Int(IntWidth::U32),
            8 => DecompType::Int(IntWidth::U64),
            _ => DecompType::Int(IntWidth::U8),
        };
        Some(elem)
    }

    /// All recovered accesses.
    #[must_use]
    pub fn accesses(&self) -> &[ArrayAccess] {
        &self.accesses
    }

    /// Number of accesses recorded.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.accesses.len()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Constraint solver: union-find + lattice
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A typing constraint over variables and concrete types.
#[derive(Debug, Clone)]
pub enum Constraint {
    /// Two variables share the same type.
    Equal(String, String),
    /// A variable has at least the given type (joined into its lattice point).
    HasType(String, LatticeType),
    /// A variable is a pointer to the type of another variable.
    PointsTo { ptr: String, pointee: String },
}

/// Solves typing constraints with a union-find over variables plus a lattice
/// value per equivalence class. Conflicts are recorded but never panic.
#[derive(Debug, Default)]
pub struct ConstraintSolver {
    parent: HashMap<String, String>,
    rank: HashMap<String, u32>,
    /// Lattice value for the representative of each class.
    types: HashMap<String, LatticeType>,
    constraints: Vec<Constraint>,
    conflicts: Vec<String>,
}

impl ConstraintSolver {
    /// New solver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a constraint (deferred until `solve`).
    pub fn add(&mut self, c: Constraint) {
        self.constraints.push(c);
    }

    fn ensure(&mut self, v: &str) {
        if !self.parent.contains_key(v) {
            self.parent.insert(v.to_string(), v.to_string());
            self.rank.insert(v.to_string(), 0);
            self.types.insert(v.to_string(), LatticeType::Top);
        }
    }

    fn find(&mut self, v: &str) -> String {
        self.ensure(v);
        let p = self.parent[v].clone();
        if p == v {
            return v.to_string();
        }
        let root = self.find(&p);
        self.parent.insert(v.to_string(), root.clone());
        root
    }

    fn union(&mut self, a: &str, b: &str) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra == rb {
            return;
        }
        // Merge lattice values.
        let ta = self.types.get(&ra).cloned().unwrap_or(LatticeType::Top);
        let tb = self.types.get(&rb).cloned().unwrap_or(LatticeType::Top);
        let merged = ta.join(&tb);
        if merged.is_conflict() {
            self.conflicts.push(format!("{ra} â‹ˆ {rb}"));
        }
        // Union by rank.
        let (root, child) = {
            let rank_a = self.rank[&ra];
            let rank_b = self.rank[&rb];
            if rank_a < rank_b {
                (rb.clone(), ra.clone())
            } else {
                (ra.clone(), rb.clone())
            }
        };
        self.parent.insert(child, root.clone());
        if self.rank[&ra] == self.rank[&rb] {
            *self.rank.get_mut(&root).unwrap() += 1;
        }
        self.types.insert(root, merged);
    }

    fn meet_type(&mut self, v: &str, ty: &LatticeType) {
        let root = self.find(v);
        let cur = self.types.get(&root).cloned().unwrap_or(LatticeType::Top);
        let merged = cur.join(ty);
        if merged.is_conflict() {
            self.conflicts.push(format!("{root}: type conflict"));
        }
        self.types.insert(root, merged);
    }

    /// Solve all constraints, returning a map from variable to resolved type.
    pub fn solve(&mut self) -> HashMap<String, DecompType> {
        let constraints = std::mem::take(&mut self.constraints);
        // First pass: unions and direct type facts.
        for c in &constraints {
            match c {
                Constraint::Equal(a, b) => self.union(a, b),
                Constraint::HasType(v, ty) => self.meet_type(v, ty),
                Constraint::PointsTo { .. } => {}
            }
        }
        // Second pass: pointer relationships (need representatives settled).
        for c in &constraints {
            if let Constraint::PointsTo { ptr, pointee } = c {
                let pointee_root = self.find(pointee);
                let inner = self
                    .types
                    .get(&pointee_root)
                    .cloned()
                    .unwrap_or(LatticeType::Top);
                self.meet_type(ptr, &LatticeType::Pointer(Box::new(inner)));
            }
        }
        self.constraints = constraints;

        // Materialise: every variable resolves to its class representative type.
        let vars: Vec<String> = self.parent.keys().cloned().collect();
        let mut result = HashMap::new();
        for v in vars {
            let root = self.find(&v);
            let lt = self.types.get(&root).cloned().unwrap_or(LatticeType::Top);
            result.insert(v, lt.to_decomp());
        }
        result
    }

    /// Any conflicts encountered.
    #[must_use]
    pub fn conflicts(&self) -> &[String] {
        &self.conflicts
    }

    /// Whether the variable shares a class with another.
    #[must_use]
    pub fn same_class(&mut self, a: &str, b: &str) -> bool {
        self.find(a) == self.find(b)
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Top-level multi-level recovery driver
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Bundles the recovery passes (access widths, pointers, structs, arrays,
/// constraint solving) into a single driver.
#[derive(Debug, Default)]
pub struct MultiLevelTypeRecovery {
    sizer: AccessWidthSizer,
    pointers: PointerDetector,
    structs: StructClusterer,
    arrays: ArrayInference,
    solver: ConstraintSolver,
    primitives: PrimitiveInference,
}

impl MultiLevelTypeRecovery {
    /// New driver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed an assignment `name = expr` into all relevant passes.
    pub fn observe_assignment(&mut self, name: &str, expr: &Expr) {
        self.pointers.scan(expr);
        self.structs.scan(expr);
        self.arrays.scan(expr);
        // Primitive inference becomes a `HasType` constraint.
        let lt = self.primitives.infer(expr);
        if !matches!(lt, LatticeType::Top) {
            self.solver.add(Constraint::HasType(name.to_string(), lt));
        }
        // Copy assignments unify the two sides.
        if let Expr::Var(src) = expr {
            self.solver
                .add(Constraint::Equal(name.to_string(), src.clone()));
        }
    }

    /// Record a memory access width for a variable.
    pub fn observe_access(&mut self, var: &str, bytes: u8) {
        self.sizer.observe(var, bytes);
    }

    /// Resolve all variable types. Pointer-detected variables that the solver
    /// left unknown are promoted to `void *`, and access-width facts fill in
    /// integer sizes.
    pub fn resolve(&mut self) -> HashMap<String, DecompType> {
        // Inject pointer facts as constraints.
        for p in self.pointers.pointers() {
            self.solver.add(Constraint::HasType(
                p,
                LatticeType::Pointer(Box::new(LatticeType::Top)),
            ));
        }
        let mut resolved = self.solver.solve();

        // Refine integers with observed access widths. This covers both
        // variables already known to the solver and variables seen only via
        // a memory-access width observation.
        for v in self.sizer.vars() {
            if let Some(sized) = self.sizer.infer(&v) {
                let entry = resolved.entry(v).or_insert(DecompType::Unknown);
                if matches!(entry, DecompType::Unknown | DecompType::Int(_)) {
                    *entry = sized;
                }
            }
        }
        resolved
    }

    /// Access to the struct clusterer for building candidate structs.
    #[must_use]
    pub const fn struct_clusterer(&self) -> &StructClusterer {
        &self.structs
    }

    /// Access to the array inference engine.
    #[must_use]
    pub const fn array_inference(&self) -> &ArrayInference {
        &self.arrays
    }

    /// Access to the pointer detector.
    #[must_use]
    pub const fn pointer_detector(&self) -> &PointerDetector {
        &self.pointers
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Tests for multi-level type recovery
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod recovery_tests {
    use super::*;
    use rustre_decompiler_expr::{BinOp, Expr, IntWidth, UnOp};

    fn c(v: i64) -> Expr {
        Expr::Const(v, IntWidth::I64)
    }
    fn var(n: &str) -> Expr {
        Expr::Var(n.to_string())
    }
    fn binop(op: BinOp, a: Expr, b: Expr) -> Expr {
        Expr::BinOp(op, Box::new(a), Box::new(b))
    }
    fn load(ptr: Expr, size: u8) -> Expr {
        Expr::Load {
            ptr: Box::new(ptr),
            size,
        }
    }

    // â"€â"€ Lattice â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lattice_join_top() {
        let i = LatticeType::Integer {
            width: Some(IntWidth::I32),
        };
        assert_eq!(LatticeType::Top.join(&i), i);
    }

    #[test]
    fn test_lattice_join_widths() {
        let a = LatticeType::Integer {
            width: Some(IntWidth::I8),
        };
        let b = LatticeType::Integer {
            width: Some(IntWidth::I32),
        };
        // wider, signed wins
        assert_eq!(
            a.join(&b),
            LatticeType::Integer {
                width: Some(IntWidth::I32)
            }
        );
    }

    #[test]
    fn test_lattice_conflict() {
        let i = LatticeType::Integer {
            width: Some(IntWidth::I32),
        };
        let f = LatticeType::Float32;
        assert!(i.join(&f).is_conflict());
    }

    #[test]
    fn test_lattice_pointer_join() {
        let a = LatticeType::Pointer(Box::new(LatticeType::Top));
        let b = LatticeType::Pointer(Box::new(LatticeType::Integer {
            width: Some(IntWidth::I32),
        }));
        let j = a.join(&b);
        assert_eq!(
            j,
            LatticeType::Pointer(Box::new(LatticeType::Integer {
                width: Some(IntWidth::I32)
            }))
        );
    }

    #[test]
    fn test_lattice_to_decomp() {
        assert_eq!(
            LatticeType::Integer {
                width: Some(IntWidth::U32)
            }
            .to_decomp(),
            DecompType::Int(IntWidth::U32)
        );
        assert_eq!(LatticeType::Bool.to_decomp(), DecompType::Bool);
    }

    #[test]
    fn test_lattice_roundtrip() {
        let ty = DecompType::Ptr(Box::new(DecompType::Int(IntWidth::I32)));
        let lt = LatticeType::from_decomp(&ty);
        assert_eq!(lt.to_decomp(), ty);
    }

    // â"€â"€ Access-width sizing â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_access_width_4_bytes_is_32bit() {
        let mut s = AccessWidthSizer::new();
        s.observe("x", 4);
        assert_eq!(s.infer("x"), Some(DecompType::Int(IntWidth::U32)));
    }

    #[test]
    fn test_access_width_picks_widest() {
        let mut s = AccessWidthSizer::new();
        s.observe("x", 1);
        s.observe("x", 8);
        s.observe("x", 2);
        assert_eq!(s.infer("x"), Some(DecompType::Int(IntWidth::U64)));
    }

    #[test]
    fn test_access_width_signed() {
        let mut s = AccessWidthSizer::new();
        s.observe("x", 4);
        s.mark_signed("x");
        assert_eq!(s.infer("x"), Some(DecompType::Int(IntWidth::I32)));
    }

    // â"€â"€ Primitive inference â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_primitive_comparison_is_bool() {
        let p = PrimitiveInference::new();
        let e = binop(BinOp::Lt, var("a"), var("b"));
        assert_eq!(p.infer(&e), LatticeType::Bool);
    }

    #[test]
    fn test_primitive_sar_is_signed() {
        let p = PrimitiveInference::new();
        let e = binop(BinOp::Sar, var("x"), c(2));
        // signed integer
        if let LatticeType::Integer { width } = p.infer(&e) {
            assert!(width.is_none_or(IntWidth::is_signed));
        } else {
            panic!("expected integer");
        }
    }

    #[test]
    fn test_primitive_cast_width() {
        let p = PrimitiveInference::new();
        let e = Expr::UnOp(UnOp::Cast(IntWidth::U16), Box::new(var("x")));
        assert_eq!(
            p.infer(&e),
            LatticeType::Integer {
                width: Some(IntWidth::U16)
            }
        );
    }

    // â"€â"€ Pointer detection â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_pointer_detect_deref() {
        let mut d = PointerDetector::new();
        d.scan(&Expr::UnOp(UnOp::Deref, Box::new(var("p"))));
        assert!(d.is_pointer("p"));
    }

    #[test]
    fn test_pointer_detect_load_with_offset() {
        let mut d = PointerDetector::new();
        d.scan(&load(binop(BinOp::Add, var("base"), c(16)), 4));
        assert!(d.is_pointer("base"));
    }

    #[test]
    fn test_pointer_detect_non_pointer() {
        let mut d = PointerDetector::new();
        d.scan(&binop(BinOp::Add, var("x"), c(1)));
        assert!(!d.is_pointer("x"));
    }

    // â"€â"€ Struct clustering â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_struct_clustering_offsets() {
        let mut sc = StructClusterer::new();
        // *(node + 0) [4 bytes], *(node + 8) [8 bytes]
        sc.scan(&load(var("node"), 4));
        sc.scan(&load(binop(BinOp::Add, var("node"), c(8)), 8));
        let offs = sc.offsets("node");
        assert_eq!(offs, vec![0, 8]);
    }

    #[test]
    fn test_struct_clustering_build() {
        let mut sc = StructClusterer::new();
        sc.observe("node", 0, 4);
        sc.observe("node", 8, 8);
        sc.observe("node", 0, 4); // duplicate offset
        let st = sc.build_struct("node", "Node").unwrap();
        assert_eq!(st.fields.len(), 2);
        assert_eq!(st.fields[0].offset, 0);
        assert_eq!(st.fields[1].offset, 8);
        // total size covers offset 8 + 8 bytes = 16
        assert_eq!(st.total_size, 16);
    }

    #[test]
    fn test_struct_clustering_widest_at_offset() {
        let mut sc = StructClusterer::new();
        sc.observe("p", 0, 1);
        sc.observe("p", 0, 4);
        let st = sc.build_struct("p", "P").unwrap();
        // widest (4 bytes) wins â†' u32
        assert_eq!(st.fields[0].ty, DecompType::Int(IntWidth::U32));
    }

    // â"€â"€ Array inference â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_array_match_mul() {
        let e = binop(BinOp::Add, var("arr"), binop(BinOp::Mul, var("i"), c(4)));
        let a = ArrayInference::match_array_access(&e).unwrap();
        assert_eq!(a.base, "arr");
        assert_eq!(a.index, "i");
        assert_eq!(a.stride, 4);
    }

    #[test]
    fn test_array_match_shift() {
        let e = binop(BinOp::Add, var("arr"), binop(BinOp::Shl, var("i"), c(3)));
        let a = ArrayInference::match_array_access(&e).unwrap();
        assert_eq!(a.stride, 8);
    }

    #[test]
    fn test_array_element_type() {
        let mut ai = ArrayInference::new();
        ai.scan(&binop(
            BinOp::Add,
            var("arr"),
            binop(BinOp::Mul, var("i"), c(4)),
        ));
        assert_eq!(ai.element_type("arr"), Some(DecompType::Int(IntWidth::U32)));
        assert_eq!(ai.count(), 1);
    }

    #[test]
    fn test_array_no_match_const_offset() {
        let e = binop(BinOp::Add, var("arr"), c(4));
        assert!(ArrayInference::match_array_access(&e).is_none());
    }

    // â"€â"€ Constraint solver â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_solver_equal_unifies() {
        let mut s = ConstraintSolver::new();
        s.add(Constraint::Equal("x".into(), "y".into()));
        s.add(Constraint::HasType(
            "x".into(),
            LatticeType::Integer {
                width: Some(IntWidth::I32),
            },
        ));
        let r = s.solve();
        assert_eq!(r.get("y"), Some(&DecompType::Int(IntWidth::I32)));
    }

    #[test]
    fn test_solver_transitive() {
        let mut s = ConstraintSolver::new();
        s.add(Constraint::Equal("a".into(), "b".into()));
        s.add(Constraint::Equal("b".into(), "c".into()));
        s.add(Constraint::HasType("a".into(), LatticeType::Float64));
        let r = s.solve();
        assert_eq!(r.get("c"), Some(&DecompType::Float64));
    }

    #[test]
    fn test_solver_points_to() {
        let mut s = ConstraintSolver::new();
        s.add(Constraint::HasType(
            "target".into(),
            LatticeType::Integer {
                width: Some(IntWidth::I32),
            },
        ));
        s.add(Constraint::PointsTo {
            ptr: "p".into(),
            pointee: "target".into(),
        });
        let r = s.solve();
        assert_eq!(
            r.get("p"),
            Some(&DecompType::Ptr(Box::new(DecompType::Int(IntWidth::I32))))
        );
    }

    #[test]
    fn test_solver_conflict_recorded() {
        let mut s = ConstraintSolver::new();
        s.add(Constraint::HasType(
            "x".into(),
            LatticeType::Integer {
                width: Some(IntWidth::I32),
            },
        ));
        s.add(Constraint::HasType("x".into(), LatticeType::Float32));
        s.solve();
        assert!(!s.conflicts().is_empty());
    }

    #[test]
    fn test_solver_same_class() {
        let mut s = ConstraintSolver::new();
        s.add(Constraint::Equal("a".into(), "b".into()));
        s.solve();
        assert!(s.same_class("a", "b"));
        assert!(!s.same_class("a", "z"));
    }

    // â"€â"€ Multi-level driver â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_multilevel_pointer_and_width() {
        let mut r = MultiLevelTypeRecovery::new();
        // p = *(base + 0) ; base is a pointer
        r.observe_assignment("p", &load(var("base"), 8));
        r.observe_access("counter", 4);
        let resolved = r.resolve();
        // base detected as pointer
        assert!(matches!(resolved.get("base"), Some(DecompType::Ptr(_))));
        // counter sized to 32-bit
        assert_eq!(
            resolved.get("counter"),
            Some(&DecompType::Int(IntWidth::U32))
        );
    }

    #[test]
    fn test_multilevel_struct_recovery() {
        let mut r = MultiLevelTypeRecovery::new();
        r.observe_assignment("a", &load(var("node"), 4));
        r.observe_assignment("b", &load(binop(BinOp::Add, var("node"), c(8)), 8));
        let st = r.struct_clusterer().build_struct("node", "Node");
        assert!(st.is_some());
        assert_eq!(st.unwrap().fields.len(), 2);
    }

    #[test]
    fn test_multilevel_array_recovery() {
        let mut r = MultiLevelTypeRecovery::new();
        r.observe_assignment(
            "v",
            &load(
                binop(BinOp::Add, var("arr"), binop(BinOp::Mul, var("i"), c(4))),
                4,
            ),
        );
        assert_eq!(
            r.array_inference().element_type("arr"),
            Some(DecompType::Int(IntWidth::U32))
        );
    }

    #[test]
    fn test_multilevel_copy_unifies() {
        let mut r = MultiLevelTypeRecovery::new();
        r.observe_assignment("dst", &var("src"));
        r.observe_assignment("src", &Expr::Const(0, IntWidth::I32));
        let resolved = r.resolve();
        // dst and src unified; src is i32 (from const), so dst should be i32 too.
        assert_eq!(resolved.get("dst"), resolved.get("src"));
    }
}

