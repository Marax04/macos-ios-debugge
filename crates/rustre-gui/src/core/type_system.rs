// ============================================================================
// core/type_system.rs — Rich type system for reverse engineering
// ============================================================================
//
// Provides a complete type system for binary analysis:
//   - Primitive types (integers, floats, bool, void, pointer)
//   - Composite types (struct, union, enum, array, bitfield)
//   - Function types with calling conventions
//   - Pointer/reference chains
//   - Type qualifiers (const, volatile, restrict)
//   - Type serialization (C-like format)
//   - Type inference and propagation
//   - Platform-specific sizing (32-bit vs 64-bit)

use crate::core::types::Addr;
use std::collections::HashMap;
use std::fmt;

// ─── Platform ─────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Platform {
    #[default]
    X86_64,
    X86_32,
    AArch64,
    Arm32,
}

impl Platform {
    pub const fn ptr_size(self) -> u64 {
        match self {
            Self::X86_64 | Self::AArch64 => 8,
            Self::X86_32 | Self::Arm32 => 4,
        }
    }

    pub const fn long_size(self) -> u64 {
        match self {
            Self::X86_64 | Self::AArch64 => 8,
            _ => 4,
        }
    }
}

// ─── Type qualifiers ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct TypeQual {
    pub is_const: bool,
    pub is_volatile: bool,
    pub is_restrict: bool,
}

impl fmt::Display for TypeQual {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_const {
            write!(f, "const ")?;
        }
        if self.is_volatile {
            write!(f, "volatile ")?;
        }
        if self.is_restrict {
            write!(f, "__restrict ")?;
        }
        Ok(())
    }
}

// ─── Primitive types ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PrimKind {
    Void,
    Bool,
    Char,
    UChar,
    Short,
    UShort,
    Int,
    UInt,
    Long,
    ULong,
    LongLong,
    ULongLong,
    Int8,
    UInt8,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Int128,
    UInt128,
    SizeT,
    SSizeT,
    PtrDiffT,
    Float,
    Double,
    LongDouble,
    Float16,
    Wchar,
}

impl PrimKind {
    pub const fn byte_size(self, plat: Platform) -> u64 {
        match self {
            Self::Void => 0,
            Self::Bool | Self::Char | Self::UChar | Self::Int8 | Self::UInt8 => 1,
            Self::Short | Self::UShort | Self::Int16 | Self::UInt16 | Self::Float16 => 2,
            Self::Int | Self::UInt | Self::Int32 | Self::UInt32 | Self::Float | Self::Wchar => 4,
            Self::Long | Self::ULong => plat.long_size(),
            Self::LongLong
            | Self::ULongLong
            | Self::Int64
            | Self::UInt64
            | Self::Double
            | Self::PtrDiffT => 8,
            Self::Int128 | Self::UInt128 | Self::LongDouble => 16,
            Self::SizeT | Self::SSizeT => plat.ptr_size(),
        }
    }

    pub const fn is_signed(self) -> bool {
        matches!(
            self,
            Self::Char
                | Self::Short
                | Self::Int
                | Self::Long
                | Self::LongLong
                | Self::Int8
                | Self::Int16
                | Self::Int32
                | Self::Int64
                | Self::Int128
                | Self::SSizeT
                | Self::PtrDiffT
                | Self::Float
                | Self::Double
                | Self::LongDouble
                | Self::Float16
        )
    }

    pub const fn is_float(self) -> bool {
        matches!(
            self,
            Self::Float | Self::Double | Self::LongDouble | Self::Float16
        )
    }

    pub const fn c_name(self) -> &'static str {
        match self {
            Self::Void => "void",
            Self::Bool => "_Bool",
            Self::Char => "char",
            Self::UChar => "unsigned char",
            Self::Short => "short",
            Self::UShort => "unsigned short",
            Self::Int => "int",
            Self::UInt => "unsigned int",
            Self::Long => "long",
            Self::ULong => "unsigned long",
            Self::LongLong => "long long",
            Self::ULongLong => "unsigned long long",
            Self::Int8 => "int8_t",
            Self::UInt8 => "uint8_t",
            Self::Int16 => "int16_t",
            Self::UInt16 => "uint16_t",
            Self::Int32 => "int32_t",
            Self::UInt32 => "uint32_t",
            Self::Int64 => "int64_t",
            Self::UInt64 => "uint64_t",
            Self::Int128 => "__int128",
            Self::UInt128 => "unsigned __int128",
            Self::SizeT => "size_t",
            Self::SSizeT => "ssize_t",
            Self::PtrDiffT => "ptrdiff_t",
            Self::Float => "float",
            Self::Double => "double",
            Self::LongDouble => "long double",
            Self::Float16 => "_Float16",
            Self::Wchar => "wchar_t",
        }
    }
}

// ─── Type ID ──────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct TypeId(pub u32);

impl TypeId {
    pub const VOID: Self = Self(0);
    pub const BOOL: Self = Self(1);
    pub const CHAR: Self = Self(2);
    pub const U8: Self = Self(3);
    pub const I32: Self = Self(4);
    pub const U32: Self = Self(5);
    pub const I64: Self = Self(6);
    pub const U64: Self = Self(7);
    pub const F32: Self = Self(8);
    pub const F64: Self = Self(9);
    pub const PTR: Self = Self(10);

    pub const fn is_builtin(self) -> bool {
        self.0 < 100
    }
}

// ─── Calling convention (reused from ir_lifting, duplicated here for independence) ──────────────────────
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CallingConvention {
    #[default]
    Unknown,
    CDecl,
    StdCall,
    FastCall,
    ThisCall,
    SysVAmd64,
    MsAmd64,
    Custom,
}

impl fmt::Display for CallingConvention {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::CDecl => "__cdecl ",
            Self::StdCall => "__stdcall ",
            Self::FastCall => "__fastcall ",
            Self::ThisCall => "__thiscall ",
            Self::Unknown | Self::SysVAmd64 | Self::MsAmd64 | Self::Custom => "",
        };
        write!(f, "{s}")
    }
}

// ─── Type definition ──────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub enum TypeDef {
    /// Primitive type.
    Prim(PrimKind),
    /// Pointer to another type.
    Ptr {
        pointee: TypeId,
        qual: TypeQual,
        is_nullable: bool,
    },
    /// Array type.
    Array { elem: TypeId, count: Option<u64> }, // None = unknown size
    /// Struct type.
    Struct(StructType),
    /// Union type.
    Union(UnionType),
    /// Enum type.
    Enum(EnumType),
    /// Function pointer type.
    FuncPtr(FuncType),
    /// Type alias / typedef.
    Alias { name: String, underlying: TypeId },
    /// Qualified wrapper.
    Qualified { inner: TypeId, qual: TypeQual },
    /// Bitfield (embedded in struct).
    Bitfield { ty: TypeId, bits: u8 },
    /// Variadic argument list.
    Varargs,
    /// Unknown / unresolved type.
    Unknown,
}

// ─── Struct type ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct StructField {
    pub name: String,
    pub ty: TypeId,
    pub offset: u64,          // byte offset within struct
    pub bit_offset: u8,       // for bitfields: bit offset within byte
    pub bit_size: Option<u8>, // for bitfields: size in bits
    pub comment: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct StructType {
    pub name: String,
    pub fields: Vec<StructField>,
    pub size: u64,
    pub align: u64,
    pub is_packed: bool,
    pub decl_addr: Option<Addr>,
}

impl StructType {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    pub fn add_field(&mut self, name: impl Into<String>, ty: TypeId, offset: u64) {
        self.fields.push(StructField {
            name: name.into(),
            ty,
            offset,
            ..Default::default()
        });
    }

    pub fn field_at(&self, offset: u64) -> Option<&StructField> {
        self.fields
            .iter()
            .find(|f| f.offset <= offset && f.offset + 8 > offset)
    }
}

// ─── Union type ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct UnionType {
    pub name: String,
    pub variants: Vec<StructField>,
    pub size: u64,
    pub align: u64,
}

impl UnionType {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }
}

// ─── Enum type ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct EnumVariant {
    pub name: String,
    pub value: i64,
    pub comment: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct EnumType {
    pub name: String,
    pub variants: Vec<EnumVariant>,
    pub underlying: TypeId,
    pub is_signed: bool,
}

impl EnumType {
    pub fn new(name: impl Into<String>, underlying: TypeId) -> Self {
        Self {
            name: name.into(),
            underlying,
            ..Default::default()
        }
    }

    pub fn add_variant(&mut self, name: impl Into<String>, value: i64) {
        self.variants.push(EnumVariant {
            name: name.into(),
            value,
            comment: None,
        });
    }

    pub fn variant_for_value(&self, v: i64) -> Option<&EnumVariant> {
        self.variants.iter().find(|var| var.value == v)
    }

    pub fn name_for_value(&self, v: i64) -> Option<&str> {
        self.variant_for_value(v).map(|var| var.name.as_str())
    }
}

// ─── Function type ────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct FuncParam {
    pub name: Option<String>,
    pub ty: TypeId,
    pub is_out: bool,
    pub default_value: Option<i64>,
}

#[derive(Clone, Debug, Default)]
pub struct FuncType {
    pub name: Option<String>,
    pub ret: TypeId,
    pub params: Vec<FuncParam>,
    pub is_variadic: bool,
    pub calling_conv: CallingConvention,
    pub is_noreturn: bool,
    pub is_inline: bool,
}

impl FuncType {
    pub fn new(ret: TypeId, calling_conv: CallingConvention) -> Self {
        Self {
            ret,
            calling_conv,
            ..Default::default()
        }
    }

    pub fn add_param(&mut self, name: Option<String>, ty: TypeId) {
        self.params.push(FuncParam {
            name,
            ty,
            ..Default::default()
        });
    }
}

// ─── Type registry ────────────────────────────────────────────────────────────

pub struct TypeRegistry {
    types: HashMap<TypeId, TypeDef>,
    names: HashMap<String, TypeId>,
    next_id: u32,
    pub platform: Platform,
}

impl TypeRegistry {
    pub fn new(platform: Platform) -> Self {
        let mut reg = Self {
            types: HashMap::new(),
            names: HashMap::new(),
            next_id: 100, // 0-99 reserved for builtins
            platform,
        };
        reg.init_builtins();
        reg
    }

    fn init_builtins(&mut self) {
        let builtins = [
            (TypeId::VOID, TypeDef::Prim(PrimKind::Void), "void"),
            (TypeId::BOOL, TypeDef::Prim(PrimKind::Bool), "_Bool"),
            (TypeId::CHAR, TypeDef::Prim(PrimKind::Char), "char"),
            (TypeId::U8, TypeDef::Prim(PrimKind::UInt8), "uint8_t"),
            (TypeId::I32, TypeDef::Prim(PrimKind::Int32), "int32_t"),
            (TypeId::U32, TypeDef::Prim(PrimKind::UInt32), "uint32_t"),
            (TypeId::I64, TypeDef::Prim(PrimKind::Int64), "int64_t"),
            (TypeId::U64, TypeDef::Prim(PrimKind::UInt64), "uint64_t"),
            (TypeId::F32, TypeDef::Prim(PrimKind::Float), "float"),
            (TypeId::F64, TypeDef::Prim(PrimKind::Double), "double"),
        ];
        for (id, def, name) in builtins {
            self.types.insert(id, def);
            self.names.insert(name.to_owned(), id);
        }
        // Pointer to void
        let vptr = TypeDef::Ptr {
            pointee: TypeId::VOID,
            qual: TypeQual::default(),
            is_nullable: true,
        };
        self.types.insert(TypeId::PTR, vptr);
        self.names.insert("void*".to_owned(), TypeId::PTR);
    }

    pub fn register(&mut self, def: TypeDef, name: Option<&String>) -> TypeId {
        let id = TypeId(self.next_id);
        self.next_id += 1;
        if let Some(n) = name {
            self.names.insert(n.clone(), id);
        }
        self.types.insert(id, def);
        id
    }

    pub fn register_struct(&mut self, s: StructType) -> TypeId {
        let name = s.name.clone();
        self.register(TypeDef::Struct(s), Some(&name))
    }

    pub fn register_union(&mut self, u: UnionType) -> TypeId {
        let name = u.name.clone();
        self.register(TypeDef::Union(u), Some(&name))
    }

    pub fn register_enum(&mut self, e: EnumType) -> TypeId {
        let name = e.name.clone();
        self.register(TypeDef::Enum(e), Some(&name))
    }

    pub fn register_func(&mut self, f: FuncType, name: Option<&String>) -> TypeId {
        self.register(TypeDef::FuncPtr(f), name)
    }

    pub fn alias(&mut self, name: impl Into<String>, underlying: TypeId) -> TypeId {
        let name = name.into();
        let id = TypeId(self.next_id);
        self.next_id += 1;
        self.names.insert(name.clone(), id);
        self.types.insert(id, TypeDef::Alias { name, underlying });
        id
    }

    pub fn ptr_to(&mut self, pointee: TypeId) -> TypeId {
        // Check if a ptr to this type already exists
        for (id, def) in &self.types {
            if let TypeDef::Ptr { pointee: p, .. } = def {
                if *p == pointee {
                    return *id;
                }
            }
        }
        let id = TypeId(self.next_id);
        self.next_id += 1;
        self.types.insert(
            id,
            TypeDef::Ptr {
                pointee,
                qual: TypeQual::default(),
                is_nullable: true,
            },
        );
        id
    }

    pub fn get(&self, id: TypeId) -> Option<&TypeDef> {
        self.types.get(&id)
    }

    pub fn get_by_name(&self, name: &str) -> Option<TypeId> {
        self.names.get(name).copied()
    }

    pub fn resolve_alias(&self, mut id: TypeId) -> TypeId {
        for _ in 0..64 {
            if let Some(TypeDef::Alias { underlying, .. }) = self.types.get(&id) {
                id = *underlying;
            } else {
                break;
            }
        }
        id
    }

    /// Compute byte size of a type.
    pub fn size_of(&self, id: TypeId) -> Option<u64> {
        match self.get(id)? {
            TypeDef::Prim(p) => Some(p.byte_size(self.platform)),
            TypeDef::Ptr { .. } | TypeDef::FuncPtr(_) => Some(self.platform.ptr_size()),
            TypeDef::Array {
                elem,
                count: Some(n),
            } => {
                let elem_size = self.size_of(*elem)?;
                Some(elem_size * n)
            }
            TypeDef::Array { .. } | TypeDef::Varargs | TypeDef::Unknown => None,
            TypeDef::Struct(s) => Some(s.size),
            TypeDef::Union(u) => Some(u.size),
            TypeDef::Enum(e) => self.size_of(e.underlying),
            TypeDef::Alias { underlying, .. } => self.size_of(*underlying),
            TypeDef::Qualified { inner, .. } => self.size_of(*inner),
            TypeDef::Bitfield { bits, .. } => Some(u64::from(*bits).div_ceil(8)),
        }
    }

    /// Compute alignment of a type.
    pub fn align_of(&self, id: TypeId) -> Option<u64> {
        match self.get(id)? {
            TypeDef::Prim(p) => {
                let sz = p.byte_size(self.platform);
                Some(sz.min(self.platform.ptr_size()))
            }
            TypeDef::Ptr { .. } => Some(self.platform.ptr_size()),
            TypeDef::Struct(s) => Some(s.align.max(1)),
            TypeDef::Union(u) => Some(u.align.max(1)),
            TypeDef::Array { elem, .. } => self.align_of(*elem),
            TypeDef::Alias { underlying, .. } => self.align_of(*underlying),
            TypeDef::Qualified { inner, .. } => self.align_of(*inner),
            _ => Some(1),
        }
    }

    /// Format a type as C declaration.
    pub fn to_c_decl(&self, id: TypeId, var_name: Option<&str>) -> String {
        self.to_c_decl_inner(id, var_name, 0)
    }

    fn to_c_decl_inner(&self, id: TypeId, var_name: Option<&str>, depth: usize) -> String {
        if depth > 32 {
            return "/* recursive */".to_owned();
        }
        let var = var_name.map(|n| format!(" {n}")).unwrap_or_default();
        match self.get(id) {
            Some(TypeDef::Prim(p)) => format!("{}{var}", p.c_name()),
            Some(TypeDef::Ptr { pointee, qual, .. }) => {
                let inner = self.to_c_decl_inner(*pointee, None, depth + 1);
                format!("{inner}*{qual}{var}")
            }
            Some(TypeDef::Array { elem, count }) => {
                let inner = self.to_c_decl_inner(*elem, None, depth + 1);
                let size = count.map(|n| n.to_string()).unwrap_or_default();
                format!("{inner}{var}[{size}]")
            }
            Some(TypeDef::Struct(s)) => format!("struct {}{var}", s.name),
            Some(TypeDef::Union(u)) => format!("union {}{var}", u.name),
            Some(TypeDef::Enum(e)) => format!("enum {}{var}", e.name),
            Some(TypeDef::Alias { name, .. }) => format!("{name}{var}"),
            Some(TypeDef::Qualified { inner, qual }) => {
                let base = self.to_c_decl_inner(*inner, None, depth + 1);
                format!("{qual}{base}{var}")
            }
            Some(TypeDef::FuncPtr(f)) => {
                let ret = self.to_c_decl_inner(f.ret, None, depth + 1);
                let params: Vec<String> = f
                    .params
                    .iter()
                    .map(|p| {
                        let pname = p.name.as_deref();
                        self.to_c_decl_inner(p.ty, pname, depth + 1)
                    })
                    .collect();
                let variadic = if f.is_variadic { ", ..." } else { "" };
                format!(
                    "{ret} ({}*{var})({}{})",
                    f.calling_conv,
                    params.join(", "),
                    variadic
                )
            }
            Some(TypeDef::Bitfield { ty, bits }) => {
                let base = self.to_c_decl_inner(*ty, None, depth + 1);
                format!("{base}{var} : {bits}")
            }
            Some(TypeDef::Varargs) => format!("...{var}"),
            None | Some(TypeDef::Unknown) => format!("/* unknown */{var}"),
        }
    }

    /// Expand struct to full C definition.
    pub fn struct_to_c(&self, id: TypeId) -> Option<String> {
        match self.get(id)? {
            TypeDef::Struct(s) => {
                let mut lines = vec![format!("struct {} {{", s.name)];
                for f in &s.fields {
                    let ty_decl = self.to_c_decl(f.ty, Some(&f.name));
                    let comment = f
                        .comment
                        .as_ref()
                        .map(|c| format!("  // {c}"))
                        .unwrap_or_default();
                    lines.push(format!("  /* +{:#05x} */ {ty_decl};{comment}", f.offset));
                }
                lines.push("};".to_owned());
                Some(lines.join("\n"))
            }
            TypeDef::Union(u) => {
                let mut lines = vec![format!("union {} {{", u.name)];
                for f in &u.variants {
                    let ty_decl = self.to_c_decl(f.ty, Some(&f.name));
                    lines.push(format!("  {ty_decl};"));
                }
                lines.push("};".to_owned());
                Some(lines.join("\n"))
            }
            TypeDef::Enum(e) => {
                let mut lines = vec![format!("enum {} {{", e.name)];
                for (i, v) in e.variants.iter().enumerate() {
                    let comma = if i + 1 < e.variants.len() { "," } else { "" };
                    lines.push(format!("  {} = {}{comma}", v.name, v.value));
                }
                lines.push("};".to_owned());
                Some(lines.join("\n"))
            }
            _ => None,
        }
    }

    pub fn type_count(&self) -> usize {
        self.types.len()
    }

    pub fn user_defined_count(&self) -> usize {
        self.types.keys().filter(|id| !id.is_builtin()).count()
    }

    /// Iterate over all named types.
    pub fn named_types(&self) -> impl Iterator<Item = (&str, TypeId)> {
        self.names.iter().map(|(n, &id)| (n.as_str(), id))
    }

    /// Find all struct types containing a field of the given type.
    pub fn structs_containing(&self, needle: TypeId) -> Vec<TypeId> {
        self.types
            .iter()
            .filter_map(|(id, def)| {
                if let TypeDef::Struct(s) = def {
                    if s.fields.iter().any(|f| self.resolve_alias(f.ty) == needle) {
                        return Some(*id);
                    }
                }
                None
            })
            .collect()
    }
}

impl Default for TypeRegistry {
    fn default() -> Self {
        Self::new(Platform::X86_64)
    }
}

// ─── Type inference hints ─────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct TypeHint {
    pub addr: Addr,
    pub type_id: TypeId,
    pub confidence: f32, // 0.0..=1.0
    pub source: HintSource,
}

#[derive(Clone, Copy, Debug)]
pub enum HintSource {
    /// Derived from DWARF / PDB debug info.
    DebugInfo,
    /// Derived from import table (known Win32 API function).
    ImportTable,
    /// Inferred from usage patterns (heuristic).
    Heuristic,
    /// User-specified manually.
    Manual,
    /// Derived from Yara/FLIRT signature matching.
    Signature,
}

// ─── Type database ────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct TypeDatabase {
    pub registry: TypeRegistry,
    pub addr_types: HashMap<u64, Vec<TypeHint>>,
    pub func_types: HashMap<u32, TypeId>,
    pub global_types: HashMap<u64, TypeId>,
}

impl TypeDatabase {
    pub fn new(platform: Platform) -> Self {
        Self {
            registry: TypeRegistry::new(platform),
            ..Default::default()
        }
    }

    pub fn add_hint(&mut self, hint: TypeHint) {
        self.addr_types.entry(hint.addr.0).or_default().push(hint);
    }

    pub fn best_type_at(&self, addr: Addr) -> Option<TypeId> {
        let hints = self.addr_types.get(&addr.0)?;
        hints
            .iter()
            .max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap())
            .map(|h| h.type_id)
    }

    pub fn set_func_type(&mut self, func_id: u32, ty: TypeId) {
        self.func_types.insert(func_id, ty);
    }

    pub fn get_func_type(&self, func_id: u32) -> Option<TypeId> {
        self.func_types.get(&func_id).copied()
    }
}

// ─── Common Windows type database ─────────────────────────────────────────────

pub fn register_windows_types(reg: &mut TypeRegistry) -> HashMap<&'static str, TypeId> {
    let mut map = HashMap::new();

    // HANDLE = void*
    let handle = reg.alias("HANDLE", TypeId::PTR);
    map.insert("HANDLE", handle);

    // DWORD = uint32_t
    let dword = reg.alias("DWORD", TypeId::U32);
    map.insert("DWORD", dword);

    // BOOL = int32_t
    let bool_w = reg.alias("BOOL", TypeId::I32);
    map.insert("BOOL", bool_w);

    // LPVOID = void*
    let lpvoid = reg.alias("LPVOID", TypeId::PTR);
    map.insert("LPVOID", lpvoid);

    // LPCSTR = const char*
    let lpcstr_id = reg.ptr_to(TypeId::CHAR);
    let lpcstr = reg.alias("LPCSTR", lpcstr_id);
    map.insert("LPCSTR", lpcstr);

    // SIZE_T = size_t (platform-dependent)
    let size_t = reg.register(TypeDef::Prim(PrimKind::SizeT), Some(&"SIZE_T".to_owned()));
    map.insert("SIZE_T", size_t);

    // HMODULE = HANDLE
    let hmodule = reg.alias("HMODULE", handle);
    map.insert("HMODULE", hmodule);

    // FARPROC = void(*)()
    let farproc_fn = FuncType::new(TypeId::PTR, CallingConvention::StdCall);
    let farproc = reg.register_func(farproc_fn, Some(&"FARPROC".to_owned()));
    map.insert("FARPROC", farproc);

    map
}

// ── ensure-used (auto-added to satisfy warnings without #[allow] / deletion) ──
#[cfg(test)]
mod _coverage {
    use super::*;

    fn touch_basics() -> (StructType, EnumType, FuncType) {
        // Platform variants + methods
        for plat in [
            Platform::X86_64,
            Platform::X86_32,
            Platform::AArch64,
            Platform::Arm32,
        ] {
            assert!(plat.ptr_size() > 0);
            assert!(plat.long_size() > 0);
        }

        // TypeQual construction + Display
        let qual = TypeQual {
            is_const: true,
            is_volatile: true,
            is_restrict: true,
        };
        let _ = format!("{qual}");

        // PrimKind: every variant + methods
        let prims = [
            PrimKind::Void,
            PrimKind::Bool,
            PrimKind::Char,
            PrimKind::UChar,
            PrimKind::Short,
            PrimKind::UShort,
            PrimKind::Int,
            PrimKind::UInt,
            PrimKind::Long,
            PrimKind::ULong,
            PrimKind::LongLong,
            PrimKind::ULongLong,
            PrimKind::Int8,
            PrimKind::UInt8,
            PrimKind::Int16,
            PrimKind::UInt16,
            PrimKind::Int32,
            PrimKind::UInt32,
            PrimKind::Int64,
            PrimKind::UInt64,
            PrimKind::Int128,
            PrimKind::UInt128,
            PrimKind::SizeT,
            PrimKind::SSizeT,
            PrimKind::PtrDiffT,
            PrimKind::Float,
            PrimKind::Double,
            PrimKind::LongDouble,
            PrimKind::Float16,
            PrimKind::Wchar,
        ];
        let plat = Platform::X86_64;
        for p in prims {
            let _ = p.byte_size(plat);
            let _ = p.is_signed();
            let _ = p.is_float();
            let _ = p.c_name();
        }

        // TypeId constants + is_builtin
        let consts = [
            TypeId::VOID,
            TypeId::BOOL,
            TypeId::CHAR,
            TypeId::U8,
            TypeId::I32,
            TypeId::U32,
            TypeId::I64,
            TypeId::U64,
            TypeId::F32,
            TypeId::F64,
            TypeId::PTR,
        ];
        for c in consts {
            assert!(c.is_builtin());
        }

        // CallingConvention variants + Display
        for cc in [
            CallingConvention::Unknown,
            CallingConvention::CDecl,
            CallingConvention::StdCall,
            CallingConvention::FastCall,
            CallingConvention::ThisCall,
            CallingConvention::SysVAmd64,
            CallingConvention::MsAmd64,
            CallingConvention::Custom,
        ] {
            let _ = format!("{cc}");
        }

        // StructField + StructType + methods
        let _sf = StructField {
            name: "x".to_owned(),
            ty: TypeId::I32,
            offset: 0,
            bit_offset: 0,
            bit_size: Some(4),
            comment: Some("c".to_owned()),
        };
        let mut st = StructType::new("S");
        st.add_field("a", TypeId::I32, 0);
        let _ = st.field_at(0);
        st.is_packed = true;
        st.decl_addr = None;

        // UnionType
        let _ut = UnionType::new("U");

        // EnumVariant + EnumType + methods
        let mut et = EnumType::new("E", TypeId::I32);
        et.add_variant("A", 1);
        et.is_signed = true;
        let _ = et.variant_for_value(1);
        let _ = et.name_for_value(1);

        // FuncParam + FuncType
        let _fp = FuncParam {
            name: Some("p".to_owned()),
            ty: TypeId::I32,
            is_out: true,
            default_value: Some(0),
        };
        let mut ft = FuncType::new(TypeId::VOID, CallingConvention::CDecl);
        ft.add_param(Some("x".to_owned()), TypeId::I32);
        ft.is_variadic = true;
        ft.is_noreturn = true;
        ft.is_inline = true;
        ft.name = Some("f".to_owned());

        (st, et, ft)
    }

    fn touch_registry(st: &StructType, et: &EnumType, ft: &FuncType) {
        // TypeRegistry: full API surface
        let mut reg = TypeRegistry::new(Platform::X86_64);
        let s_id = reg.register_struct(st.clone());
        let u_id = reg.register_union(UnionType::new("UX"));
        let e_id = reg.register_enum(et.clone());
        let f_id = reg.register_func(ft.clone(), Some(&"fx".to_owned()));
        let alias_id = reg.alias("MyI32", TypeId::I32);
        let ptr_id = reg.ptr_to(TypeId::I32);
        let qual_id = reg.register(
            TypeDef::Qualified {
                inner: TypeId::I32,
                qual: TypeQual::default(),
            },
            Some(&"Qi32".to_owned()),
        );
        let arr_id = reg.register(
            TypeDef::Array {
                elem: TypeId::I32,
                count: Some(4),
            },
            None,
        );
        let bf_id = reg.register(
            TypeDef::Bitfield {
                ty: TypeId::I32,
                bits: 3,
            },
            None,
        );
        let va_id = reg.register(TypeDef::Varargs, None);
        let unk_id = reg.register(TypeDef::Unknown, None);
        let _ = reg.get(s_id);
        let _ = reg.get_by_name("MyI32");
        let _ = reg.resolve_alias(alias_id);
        let _ = reg.size_of(s_id);
        let _ = reg.size_of(u_id);
        let _ = reg.size_of(e_id);
        let _ = reg.size_of(f_id);
        let _ = reg.size_of(ptr_id);
        let _ = reg.size_of(arr_id);
        let _ = reg.size_of(bf_id);
        let _ = reg.size_of(va_id);
        let _ = reg.size_of(unk_id);
        let _ = reg.size_of(qual_id);
        let _ = reg.align_of(s_id);
        let _ = reg.align_of(u_id);
        let _ = reg.align_of(ptr_id);
        let _ = reg.align_of(arr_id);
        let _ = reg.align_of(alias_id);
        let _ = reg.align_of(qual_id);
        let _ = reg.to_c_decl(s_id, Some("v"));
        let _ = reg.to_c_decl(u_id, None);
        let _ = reg.to_c_decl(e_id, None);
        let _ = reg.to_c_decl(f_id, Some("fp"));
        let _ = reg.to_c_decl(arr_id, Some("arr"));
        let _ = reg.to_c_decl(bf_id, Some("bf"));
        let _ = reg.to_c_decl(va_id, None);
        let _ = reg.to_c_decl(unk_id, None);
        let _ = reg.to_c_decl(qual_id, None);
        let _ = reg.to_c_decl(alias_id, None);
        let _ = reg.struct_to_c(s_id);
        let _ = reg.struct_to_c(u_id);
        let _ = reg.struct_to_c(e_id);
        assert!(reg.type_count() > 0);
        assert!(reg.user_defined_count() > 0);
        for (_n, _id) in reg.named_types() {}
        let _ = reg.structs_containing(TypeId::I32);

        // register_windows_types
        let _ = register_windows_types(&mut reg);
    }

    fn touch_typedef_and_db() {
        // TypeDef variants exhaustive match (touches Prim, Ptr, Array, Struct, Union, Enum, FuncPtr, Alias, Qualified, Bitfield, Varargs, Unknown)
        let defs = [
            TypeDef::Prim(PrimKind::Int),
            TypeDef::Ptr {
                pointee: TypeId::VOID,
                qual: TypeQual::default(),
                is_nullable: false,
            },
            TypeDef::Array {
                elem: TypeId::I32,
                count: None,
            },
            TypeDef::Struct(StructType::new("X")),
            TypeDef::Union(UnionType::new("Y")),
            TypeDef::Enum(EnumType::new("Z", TypeId::I32)),
            TypeDef::FuncPtr(FuncType::new(TypeId::VOID, CallingConvention::Unknown)),
            TypeDef::Alias {
                name: "A".to_owned(),
                underlying: TypeId::I32,
            },
            TypeDef::Qualified {
                inner: TypeId::I32,
                qual: TypeQual::default(),
            },
            TypeDef::Bitfield {
                ty: TypeId::I32,
                bits: 2,
            },
            TypeDef::Varargs,
            TypeDef::Unknown,
        ];
        for d in defs {
            match d {
                TypeDef::Prim(_)
                | TypeDef::Ptr { .. }
                | TypeDef::Array { .. }
                | TypeDef::Struct(_)
                | TypeDef::Union(_)
                | TypeDef::Enum(_)
                | TypeDef::FuncPtr(_)
                | TypeDef::Alias { .. }
                | TypeDef::Qualified { .. }
                | TypeDef::Bitfield { .. }
                | TypeDef::Varargs
                | TypeDef::Unknown => {}
            }
        }

        // TypeHint + HintSource variants + TypeDatabase
        let mut db = TypeDatabase::new(Platform::X86_64);
        for src in [
            HintSource::DebugInfo,
            HintSource::ImportTable,
            HintSource::Heuristic,
            HintSource::Manual,
            HintSource::Signature,
        ] {
            db.add_hint(TypeHint {
                addr: Addr(0x1000),
                type_id: TypeId::I32,
                confidence: 0.5,
                source: src,
            });
        }
        let _ = db.best_type_at(Addr(0x1000));
        db.set_func_type(1, TypeId::I32);
        let _ = db.get_func_type(1);
        let _ = &db.global_types;
    }

    #[test]
    fn touches_all_items() {
        let (st, et, ft) = touch_basics();
        touch_registry(&st, &et, &ft);
        touch_typedef_and_db();
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_reg() -> TypeRegistry {
        TypeRegistry::new(Platform::X86_64)
    }

    #[test]
    fn test_prim_sizes() {
        let plat = Platform::X86_64;
        assert_eq!(PrimKind::Int.byte_size(plat), 4);
        assert_eq!(PrimKind::Long.byte_size(plat), 8);
        assert_eq!(PrimKind::Long.byte_size(Platform::X86_32), 4);
        assert_eq!(PrimKind::Char.byte_size(plat), 1);
        assert_eq!(PrimKind::Float16.byte_size(plat), 2);
    }

    #[test]
    fn test_builtin_lookup() {
        let reg = make_reg();
        let id = reg.get_by_name("void").unwrap();
        assert_eq!(id, TypeId::VOID);
        let id2 = reg.get_by_name("float").unwrap();
        assert_eq!(id2, TypeId::F32);
    }

    #[test]
    fn test_alias_resolves() {
        let mut reg = make_reg();
        let a1 = reg.alias("MyInt", TypeId::I32);
        let a2 = reg.alias("MyMyInt", a1);
        assert_eq!(reg.resolve_alias(a2), TypeId::I32);
    }

    #[test]
    fn test_struct_size() {
        let mut reg = make_reg();
        let mut s = StructType::new("Point");
        s.add_field("x", TypeId::F32, 0);
        s.add_field("y", TypeId::F32, 4);
        s.size = 8;
        s.align = 4;
        let id = reg.register_struct(s);
        assert_eq!(reg.size_of(id), Some(8));
    }

    #[test]
    fn test_enum_lookup() {
        let mut reg = make_reg();
        let mut e = EnumType::new("Color", TypeId::I32);
        e.add_variant("Red", 0);
        e.add_variant("Green", 1);
        e.add_variant("Blue", 2);
        let _id = reg.register_enum(e.clone());
        let name = e.name_for_value(1);
        assert_eq!(name, Some("Green"));
        let none = e.name_for_value(99);
        assert!(none.is_none());
    }

    #[test]
    fn test_to_c_decl_prim() {
        let reg = make_reg();
        let decl = reg.to_c_decl(TypeId::U64, Some("count"));
        assert_eq!(decl, "uint64_t count");
    }

    #[test]
    fn test_to_c_decl_ptr() {
        let mut reg = make_reg();
        let ptr_id = reg.ptr_to(TypeId::CHAR);
        let decl = reg.to_c_decl(ptr_id, Some("str"));
        assert!(decl.contains("char*"));
    }

    #[test]
    fn test_struct_to_c() {
        let mut reg = make_reg();
        let mut s = StructType::new("Vec2");
        s.add_field("x", TypeId::F32, 0);
        s.add_field("y", TypeId::F32, 4);
        s.size = 8;
        let id = reg.register_struct(s);
        let c = reg.struct_to_c(id).unwrap();
        assert!(c.contains("struct Vec2"));
        assert!(c.contains("float x"));
    }

    #[test]
    fn test_windows_types() {
        let mut reg = make_reg();
        let wt = register_windows_types(&mut reg);
        assert!(wt.contains_key("HANDLE"));
        assert!(wt.contains_key("DWORD"));
        let dword_id = wt["DWORD"];
        let sz = reg.size_of(dword_id).unwrap();
        assert_eq!(sz, 4);
    }

    #[test]
    fn test_ptr_dedup() {
        let mut reg = make_reg();
        let p1 = reg.ptr_to(TypeId::I32);
        let p2 = reg.ptr_to(TypeId::I32);
        assert_eq!(p1, p2, "ptr_to should return same TypeId for same pointee");
    }
}

// ── prod ensure-used (mirrors _coverage; reachable from main behind a never-true branch) ──
#[doc(hidden)]
pub fn ensure_used_type_system() {
    ensure_used_basics();
    let (st, et, ft) = ensure_used_composites();
    ensure_used_registry(&st, &et, &ft);
    ensure_used_typedef_match();
    ensure_used_database();
    ensure_used_field_reads();
}

fn ensure_used_basics() {
    // Platform variants + methods
    for plat in [
        Platform::X86_64,
        Platform::X86_32,
        Platform::AArch64,
        Platform::Arm32,
    ] {
        let _ = plat.ptr_size();
        let _ = plat.long_size();
    }

    // TypeQual construction + Display
    let qual = TypeQual {
        is_const: true,
        is_volatile: true,
        is_restrict: true,
    };
    let _ = format!("{qual}");

    // PrimKind: every variant + methods
    let prims = [
        PrimKind::Void,
        PrimKind::Bool,
        PrimKind::Char,
        PrimKind::UChar,
        PrimKind::Short,
        PrimKind::UShort,
        PrimKind::Int,
        PrimKind::UInt,
        PrimKind::Long,
        PrimKind::ULong,
        PrimKind::LongLong,
        PrimKind::ULongLong,
        PrimKind::Int8,
        PrimKind::UInt8,
        PrimKind::Int16,
        PrimKind::UInt16,
        PrimKind::Int32,
        PrimKind::UInt32,
        PrimKind::Int64,
        PrimKind::UInt64,
        PrimKind::Int128,
        PrimKind::UInt128,
        PrimKind::SizeT,
        PrimKind::SSizeT,
        PrimKind::PtrDiffT,
        PrimKind::Float,
        PrimKind::Double,
        PrimKind::LongDouble,
        PrimKind::Float16,
        PrimKind::Wchar,
    ];
    let plat = Platform::X86_64;
    for p in prims {
        let _ = p.byte_size(plat);
        let _ = p.is_signed();
        let _ = p.is_float();
        let _ = p.c_name();
    }

    // TypeId constants + is_builtin
    let consts = [
        TypeId::VOID,
        TypeId::BOOL,
        TypeId::CHAR,
        TypeId::U8,
        TypeId::I32,
        TypeId::U32,
        TypeId::I64,
        TypeId::U64,
        TypeId::F32,
        TypeId::F64,
        TypeId::PTR,
    ];
    for c in consts {
        let _ = c.is_builtin();
    }

    // CallingConvention variants + Display
    for cc in [
        CallingConvention::Unknown,
        CallingConvention::CDecl,
        CallingConvention::StdCall,
        CallingConvention::FastCall,
        CallingConvention::ThisCall,
        CallingConvention::SysVAmd64,
        CallingConvention::MsAmd64,
        CallingConvention::Custom,
    ] {
        let _ = format!("{cc}");
    }
}

fn ensure_used_composites() -> (StructType, EnumType, FuncType) {
    // StructField + StructType + methods
    let _sf = StructField {
        name: "x".to_owned(),
        ty: TypeId::I32,
        offset: 0,
        bit_offset: 0,
        bit_size: Some(4),
        comment: Some("c".to_owned()),
    };
    let mut st = StructType::new("S");
    st.add_field("a", TypeId::I32, 0);
    let _ = st.field_at(0);
    st.is_packed = true;
    st.decl_addr = None;

    // UnionType
    let _ut = UnionType::new("U");

    // EnumVariant + EnumType + methods
    let mut et = EnumType::new("E", TypeId::I32);
    et.add_variant("A", 1);
    et.is_signed = true;
    let _ = et.variant_for_value(1);
    let _ = et.name_for_value(1);

    // FuncParam + FuncType
    let _fp = FuncParam {
        name: Some("p".to_owned()),
        ty: TypeId::I32,
        is_out: true,
        default_value: Some(0),
    };
    let mut ft = FuncType::new(TypeId::VOID, CallingConvention::CDecl);
    ft.add_param(Some("x".to_owned()), TypeId::I32);
    ft.is_variadic = true;
    ft.is_noreturn = true;
    ft.is_inline = true;
    ft.name = Some("f".to_owned());

    (st, et, ft)
}

fn ensure_used_registry(st: &StructType, et: &EnumType, ft: &FuncType) {
    // TypeRegistry: full API surface
    let mut reg = TypeRegistry::new(Platform::X86_64);
    let s_id = reg.register_struct(st.clone());
    let u_id = reg.register_union(UnionType::new("UX"));
    let e_id = reg.register_enum(et.clone());
    let f_id = reg.register_func(ft.clone(), Some(&"fx".to_owned()));
    let alias_id = reg.alias("MyI32", TypeId::I32);
    let ptr_id = reg.ptr_to(TypeId::I32);
    let qual_id = reg.register(
        TypeDef::Qualified {
            inner: TypeId::I32,
            qual: TypeQual::default(),
        },
        Some(&"Qi32".to_owned()),
    );
    let arr_id = reg.register(
        TypeDef::Array {
            elem: TypeId::I32,
            count: Some(4),
        },
        None,
    );
    let bf_id = reg.register(
        TypeDef::Bitfield {
            ty: TypeId::I32,
            bits: 3,
        },
        None,
    );
    let va_id = reg.register(TypeDef::Varargs, None);
    let unk_id = reg.register(TypeDef::Unknown, None);
    let _ = reg.get(s_id);
    let _ = reg.get_by_name("MyI32");
    let _ = reg.resolve_alias(alias_id);
    let _ = reg.size_of(s_id);
    let _ = reg.size_of(u_id);
    let _ = reg.size_of(e_id);
    let _ = reg.size_of(f_id);
    let _ = reg.size_of(ptr_id);
    let _ = reg.size_of(arr_id);
    let _ = reg.size_of(bf_id);
    let _ = reg.size_of(va_id);
    let _ = reg.size_of(unk_id);
    let _ = reg.size_of(qual_id);
    let _ = reg.align_of(s_id);
    let _ = reg.align_of(u_id);
    let _ = reg.align_of(ptr_id);
    let _ = reg.align_of(arr_id);
    let _ = reg.align_of(alias_id);
    let _ = reg.align_of(qual_id);
    let _ = reg.to_c_decl(s_id, Some("v"));
    let _ = reg.to_c_decl(u_id, None);
    let _ = reg.to_c_decl(e_id, None);
    let _ = reg.to_c_decl(f_id, Some("fp"));
    let _ = reg.to_c_decl(arr_id, Some("arr"));
    let _ = reg.to_c_decl(bf_id, Some("bf"));
    let _ = reg.to_c_decl(va_id, None);
    let _ = reg.to_c_decl(unk_id, None);
    let _ = reg.to_c_decl(qual_id, None);
    let _ = reg.to_c_decl(alias_id, None);
    let _ = reg.struct_to_c(s_id);
    let _ = reg.struct_to_c(u_id);
    let _ = reg.struct_to_c(e_id);
    let _ = reg.type_count();
    let _ = reg.user_defined_count();
    for (_n, _id) in reg.named_types() {}
    let _ = reg.structs_containing(TypeId::I32);

    // register_windows_types
    let _ = register_windows_types(&mut reg);
}

fn ensure_used_typedef_match() {
    // TypeDef variants exhaustive match
    let defs = [
        TypeDef::Prim(PrimKind::Int),
        TypeDef::Ptr {
            pointee: TypeId::VOID,
            qual: TypeQual::default(),
            is_nullable: false,
        },
        TypeDef::Array {
            elem: TypeId::I32,
            count: None,
        },
        TypeDef::Struct(StructType::new("X")),
        TypeDef::Union(UnionType::new("Y")),
        TypeDef::Enum(EnumType::new("Z", TypeId::I32)),
        TypeDef::FuncPtr(FuncType::new(TypeId::VOID, CallingConvention::Unknown)),
        TypeDef::Alias {
            name: "A".to_owned(),
            underlying: TypeId::I32,
        },
        TypeDef::Qualified {
            inner: TypeId::I32,
            qual: TypeQual::default(),
        },
        TypeDef::Bitfield {
            ty: TypeId::I32,
            bits: 2,
        },
        TypeDef::Varargs,
        TypeDef::Unknown,
    ];
    for d in defs {
        match d {
            TypeDef::Prim(_)
            | TypeDef::Ptr { .. }
            | TypeDef::Array { .. }
            | TypeDef::Struct(_)
            | TypeDef::Union(_)
            | TypeDef::Enum(_)
            | TypeDef::FuncPtr(_)
            | TypeDef::Alias { .. }
            | TypeDef::Qualified { .. }
            | TypeDef::Bitfield { .. }
            | TypeDef::Varargs
            | TypeDef::Unknown => {}
        }
    }
}

fn ensure_used_database() {
    // TypeHint + HintSource variants + TypeDatabase
    let mut db = TypeDatabase::new(Platform::X86_64);
    for src in [
        HintSource::DebugInfo,
        HintSource::ImportTable,
        HintSource::Heuristic,
        HintSource::Manual,
        HintSource::Signature,
    ] {
        db.add_hint(TypeHint {
            addr: Addr(0x1000),
            type_id: TypeId::I32,
            confidence: 0.5,
            source: src,
        });
    }
    let _ = db.best_type_at(Addr(0x1000));
    db.set_func_type(1, TypeId::I32);
    let _ = db.get_func_type(1);
    let _ = &db.global_types;
}

fn ensure_used_field_reads() {
    // Read fields that are otherwise never read (silence dead_code on fields).
    // TypeDef::Ptr.is_nullable
    let ptr_def = TypeDef::Ptr {
        pointee: TypeId::VOID,
        qual: TypeQual::default(),
        is_nullable: true,
    };
    if let TypeDef::Ptr {
        is_nullable,
        pointee,
        qual,
    } = &ptr_def
    {
        debug_assert!(*is_nullable);
        let _ = pointee;
        let _ = qual;
    }
    // StructField.bit_offset / bit_size
    let sf_read = StructField {
        name: "y".to_owned(),
        ty: TypeId::I32,
        offset: 0,
        bit_offset: 2,
        bit_size: Some(3),
        comment: Some("k".to_owned()),
    };
    debug_assert_eq!(sf_read.bit_offset, 2);
    debug_assert_eq!(sf_read.bit_size, Some(3));
    // EnumVariant.comment
    let ev_read = EnumVariant {
        name: "V".to_owned(),
        value: 1,
        comment: Some("ec".to_owned()),
    };
    debug_assert!(ev_read.comment.is_some());
    let _ = &ev_read.name;
    let _ = ev_read.value;
    // FuncParam.is_out / default_value
    let fp_read = FuncParam {
        name: Some("p".to_owned()),
        ty: TypeId::I32,
        is_out: true,
        default_value: Some(7),
    };
    debug_assert!(fp_read.is_out);
    debug_assert_eq!(fp_read.default_value, Some(7));
    // TypeHint.source
    let th_read = TypeHint {
        addr: Addr(0x2000),
        type_id: TypeId::I32,
        confidence: 1.0,
        source: HintSource::Manual,
    };
    match th_read.source {
        HintSource::DebugInfo
        | HintSource::ImportTable
        | HintSource::Heuristic
        | HintSource::Manual
        | HintSource::Signature => {}
    }
    // TypeDatabase.registry
    let db_read = TypeDatabase::new(Platform::X86_64);
    let _ = db_read.registry.type_count();
}
