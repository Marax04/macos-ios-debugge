//! STABS type reconstruction.
//!
//! Takes the raw `StabsTypeExpr` values from the full parser and resolves
//! cross-references, builds struct/union member trees, follows typedef chains,
//! and names anonymous types where possible.
//!
//! The output is a [`ReconstructedTypeDb`] mapping `(file, type_num)` →
//! [`ReconstructedType`], which can be consumed by symbol providers or
//! decompiler backends.

use std::collections::HashMap;

use crate::stabs_full_parser::{
    StabsField, StabsTypeExpr, ParsedStab,
    parse_type_descriptor, split_name_type,
};

// ─────────────────────────────────────────────────────────────────────────────
// TypeRef key
// ─────────────────────────────────────────────────────────────────────────────

/// Cross-file type reference key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypeKey {
    /// File index (0 = current file).
    pub file: u16,
    /// Type number within the file.
    pub num: u32,
}

impl TypeKey {
    /// Build a same-file key (`file = 0`).
    #[must_use]
    pub const fn local(num: u32) -> Self { Self { file: 0, num } }
    /// Build a cross-file `(file,num)` key.
    #[must_use]
    pub const fn cross(file: u16, num: u32) -> Self { Self { file, num } }
}

/// Parse a raw STABS `name:descriptor` payload into its split name and
/// fully decoded [`StabsTypeExpr`] in one call.
///
/// Convenience wrapper used by reconstructor consumers that already have
/// the raw payload string (e.g. from a custom record source) and want
/// to skip the boilerplate of calling [`split_name_type`] and
/// [`parse_type_descriptor`] separately.
#[must_use]
pub fn split_and_parse_payload(payload: &str) -> (String, StabsTypeExpr) {
    let (name, type_str) = split_name_type(payload);
    (name, parse_type_descriptor(type_str))
}

/// A flat field descriptor used when projecting a reconstructed aggregate
/// onto the original [`StabsField`] shape (name, type expr, bit offset,
/// bit size). Useful for re-emitting STABS-style debug info.
#[derive(Debug, Clone)]
pub struct FlattenedField {
    /// Field name.
    pub name: String,
    /// Field type expression.
    pub ty: StabsTypeExpr,
    /// Bit offset within the aggregate.
    pub bit_offset: u32,
    /// Bit size (0 = natural size of the type).
    pub bit_size: u32,
}

impl From<&StabsField> for FlattenedField {
    fn from(f: &StabsField) -> Self {
        Self {
            name: f.name.clone(),
            ty: f.type_expr.clone(),
            bit_offset: f.bit_offset,
            bit_size: f.bit_size,
        }
    }
}

impl std::fmt::Display for TypeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.file == 0 { write!(f, "{}", self.num) } else { write!(f, "({},{})", self.file, self.num) }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReconstructedType
// ─────────────────────────────────────────────────────────────────────────────

/// A fully resolved and named type, ready for use by consumers.
#[derive(Debug, Clone)]
pub enum ReconstructedType {
    /// Primitive / built-in type.
    Primitive(PrimitiveKind),
    /// Pointer to another type.
    Pointer {
        /// Pointed-to type key.
        target: TypeKey,
    },
    /// C++ reference (`&`).
    Reference {
        /// Referenced type key.
        target: TypeKey,
    },
    /// `volatile`-qualified type.
    Volatile {
        /// Qualified (inner) type key.
        inner: TypeKey,
    },
    /// `const`-qualified type.
    Const {
        /// Qualified (inner) type key.
        inner: TypeKey,
    },
    /// Array with resolved element type.
    Array {
        /// Element type key.
        elem: TypeKey,
        /// Lower index bound.
        lo: i64,
        /// Upper index bound.
        hi: i64,
    },
    /// Function type.
    Function {
        /// Return type key.
        return_type: TypeKey,
    },
    /// Struct with named members.
    Struct {
        /// Struct tag name, if any.
        name: Option<String>,
        /// Size in bytes.
        size: u32,
        /// Resolved members.
        members: Vec<StructMember>,
    },
    /// Union with named members.
    Union {
        /// Union tag name, if any.
        name: Option<String>,
        /// Size in bytes.
        size: u32,
        /// Resolved members.
        members: Vec<StructMember>,
    },
    /// Enum with named values.
    Enum {
        /// Enum tag name, if any.
        name: Option<String>,
        /// `(name, value)` enumerator pairs.
        values: Vec<(String, i64)>,
    },
    /// Typedef alias.
    Typedef {
        /// Typedef name.
        name: String,
        /// Aliased type key.
        target: TypeKey,
    },
    /// Sub-range of another type (e.g. `char = signed byte 0..127`).
    Range {
        /// Base type key.
        base: TypeKey,
        /// Lower bound.
        lo: i64,
        /// Upper bound.
        hi: i64,
    },
    /// Void type.
    Void,
    /// Unknown / failed to resolve.
    Unknown {
        /// Why resolution failed.
        reason: String,
    },
}

impl ReconstructedType {
    /// Return the type's C declaration string.
    #[must_use]
    pub fn c_decl(&self) -> String {
        match self {
            Self::Primitive(k) => k.c_name().to_string(),
            Self::Pointer { .. } => "void *".to_string(),
            Self::Reference { .. } => "void &".to_string(),
            Self::Volatile { .. } => "volatile <T>".to_string(),
            Self::Const { .. } => "const <T>".to_string(),
            Self::Array { lo, hi, .. } => format!("<T>[{}]", hi - lo + 1),
            Self::Function { .. } => "(*fn)(...)".to_string(),
            Self::Struct { name, size, .. } => {
                name.as_deref().map_or_else(|| format!("struct /*anon:{size}*/"), |n| format!("struct {n}"))
            }
            Self::Union { name, size, .. } => {
                name.as_deref().map_or_else(|| format!("union /*anon:{size}*/"), |n| format!("union {n}"))
            }
            Self::Enum { name, .. } => {
                name.as_deref().map_or_else(|| "enum /*anon*/".to_string(), |n| format!("enum {n}"))
            }
            Self::Typedef { name, .. } => name.clone(),
            Self::Range { lo, hi, .. } => format!("/*range {lo}..{hi}*/"),
            Self::Void => "void".to_string(),
            Self::Unknown { reason } => format!("/*?:{reason}*/"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PrimitiveKind
// ─────────────────────────────────────────────────────────────────────────────

/// Primitive types derived from STABS range descriptors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrimitiveKind {
    /// `char`.
    Char,
    /// `signed char`.
    SChar,
    /// `unsigned char`.
    UChar,
    /// `short`.
    Short,
    /// `unsigned short`.
    UShort,
    /// `int`.
    Int,
    /// `unsigned int`.
    UInt,
    /// `long`.
    Long,
    /// `unsigned long`.
    ULong,
    /// `long long`.
    LongLong,
    /// `unsigned long long`.
    ULongLong,
    /// `float`.
    Float,
    /// `double`.
    Double,
    /// `long double`.
    LongDouble,
    /// `bool`.
    Bool,
    /// `void`.
    Void,
    /// Unrecognised range.
    Unknown,
}

impl PrimitiveKind {
    /// Return the C type name.
    #[must_use]
    pub const fn c_name(&self) -> &'static str {
        match self {
            Self::Char => "char",
            Self::SChar => "signed char",
            Self::UChar => "unsigned char",
            Self::Short => "short",
            Self::UShort => "unsigned short",
            Self::Int => "int",
            Self::UInt => "unsigned int",
            Self::Long => "long",
            Self::ULong => "unsigned long",
            Self::LongLong => "long long",
            Self::ULongLong => "unsigned long long",
            Self::Float => "float",
            Self::Double => "double",
            Self::LongDouble => "long double",
            Self::Bool => "bool",
            Self::Void => "void",
            Self::Unknown => "/*?*/",
        }
    }

    /// Infer from a STABS `Range` descriptor (`r<base>;<lo>;<hi>`).
    #[must_use]
    pub const fn from_range(lo: i64, hi: i64) -> Self {
        match (lo, hi) {
            (0 | -128, 127) => Self::SChar,
            (0, 255) => Self::UChar,
            (-32_768, 32_767) => Self::Short,
            (0, 65_535) => Self::UShort,
            (-2_147_483_648, 2_147_483_647) => Self::Int,
            (0, 4_294_967_295) => Self::UInt,
            (i64::MIN, i64::MAX) => Self::LongLong,
            (0, -1) => Self::ULongLong, // wraps
            _ => Self::Unknown,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StructMember
// ─────────────────────────────────────────────────────────────────────────────

/// A member of a struct or union with resolved type.
#[derive(Debug, Clone)]
pub struct StructMember {
    /// Member name.
    pub name: String,
    /// Resolved member type key.
    pub type_key: TypeKey,
    /// Bit offset within the aggregate.
    pub bit_offset: u32,
    /// Bit size (0 = natural size of the type).
    pub bit_size: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// TypedefChain
// ─────────────────────────────────────────────────────────────────────────────

/// A chain of typedef aliases leading to a base type.
#[derive(Debug, Clone)]
pub struct TypedefChain {
    /// Alias names from outermost to innermost.
    pub steps: Vec<String>,
    /// Key of the underlying base type.
    pub base_key: TypeKey,
}

impl TypedefChain {
    /// Number of steps in the chain.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.steps.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReconstructedTypeDb
// ─────────────────────────────────────────────────────────────────────────────

/// Resolved type database.
pub struct ReconstructedTypeDb {
    types: HashMap<TypeKey, ReconstructedType>,
    /// Typedef chains: name → chain.
    typedefs: HashMap<String, TypedefChain>,
    /// Name → `TypeKey` for named struct/union/enum.
    named_types: HashMap<String, TypeKey>,
}

impl ReconstructedTypeDb {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self {
            types: HashMap::new(),
            typedefs: HashMap::new(),
            named_types: HashMap::new(),
        }
    }

    /// Insert a resolved type.
    pub fn insert(&mut self, key: TypeKey, ty: ReconstructedType) {
        // Register named types.
        match &ty {
            ReconstructedType::Struct { name: Some(n), .. }
            | ReconstructedType::Union { name: Some(n), .. }
            | ReconstructedType::Enum { name: Some(n), .. } => {
                self.named_types.insert(n.clone(), key);
            }
            ReconstructedType::Typedef { name, .. } => {
                // Build or extend typedef chain.
                let chain = self.typedefs.entry(name.clone()).or_insert_with(|| TypedefChain {
                    steps: vec![name.clone()],
                    base_key: key,
                });
                // Update base_key to the innermost if we can resolve further.
                chain.base_key = key;
            }
            _ => {}
        }
        self.types.insert(key, ty);
    }

    /// Look up a type by key.
    #[must_use]
    pub fn get(&self, key: &TypeKey) -> Option<&ReconstructedType> {
        self.types.get(key)
    }

    /// Look up a type by name (struct/union/enum/typedef).
    #[must_use]
    pub fn get_by_name(&self, name: &str) -> Option<(&TypeKey, &ReconstructedType)> {
        self.named_types.get(name).and_then(|k| self.types.get(k).map(|t| (k, t)))
    }

    /// Follow a typedef chain to the base type.
    #[must_use]
    pub fn resolve_typedef(&self, name: &str) -> Option<&ReconstructedType> {
        let chain = self.typedefs.get(name)?;
        self.types.get(&chain.base_key)
    }

    /// Number of registered types.
    #[must_use]
    pub fn len(&self) -> usize {
        self.types.len()
    }

    /// `true` when empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// Iterate all keys and types.
    pub fn iter(&self) -> impl Iterator<Item = (&TypeKey, &ReconstructedType)> {
        self.types.iter()
    }
}

impl Default for ReconstructedTypeDb {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StabsTypeReconstructor
// ─────────────────────────────────────────────────────────────────────────────

/// Walks parsed STABS records and builds a [`ReconstructedTypeDb`].
pub struct StabsTypeReconstructor {
    /// Current file index (incremented at `N_BINCL`).
    current_file: u16,
    /// Include file stack for `N_BINCL` / `N_EINCL`.
    include_stack: Vec<u16>,
    /// Pending raw type assignments: key → expr (to be resolved).
    raw_types: HashMap<TypeKey, StabsTypeExpr>,
}

impl StabsTypeReconstructor {
    /// Create a new reconstructor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            current_file: 0,
            include_stack: Vec::new(),
            raw_types: HashMap::new(),
        }
    }

    /// Process a stream of parsed STABS records and build a type database.
    #[must_use]
    pub fn reconstruct(&mut self, records: &[ParsedStab]) -> ReconstructedTypeDb {
        // First pass: collect all type assignments.
        self.current_file = 0;
        for rec in records {
            self.collect_types(rec);
        }

        // Second pass: resolve all collected types.
        // Borrow `raw_types` immutably for the whole pass. The previous code
        // deep-cloned the entire map once per type (O(n^2) allocations over a
        // recursive boxed tree); `resolve_expr` is an associated fn that only
        // reads the map, so no clone is needed at all.
        let mut db = ReconstructedTypeDb::new();
        for (key, expr) in &self.raw_types {
            db.insert(*key, Self::resolve_expr(expr, &self.raw_types));
        }
        db
    }

    fn collect_types(&mut self, rec: &ParsedStab) {
        match rec {
            ParsedStab::BeginInclude { .. } => {
                self.include_stack.push(self.current_file);
                self.current_file += 1;
            }
            ParsedStab::EndInclude => {
                if let Some(prev) = self.include_stack.pop() {
                    self.current_file = prev;
                }
            }
            ParsedStab::LocalSym { type_expr, .. }
            | ParsedStab::Param { type_expr, .. }
            | ParsedStab::Register { type_expr, .. }
            | ParsedStab::GlobalSym { type_expr, .. }
            | ParsedStab::StaticDataSym { type_expr, .. }
            | ParsedStab::StaticBssSym { type_expr, .. } => {
                self.register_type_expr(type_expr);
            }
            _ => {}
        }
    }

    fn register_type_expr(&mut self, expr: &StabsTypeExpr) {
        // We walk the expression recursively and register any TypeRef that
        // has a definition (i.e. an assignment `num=...`).
        // Since the parser already handles the `num=body` syntax, we just
        // store top-level expressions.  For a full implementation, the parser
        // would need to emit (key, body) pairs; here we do a best-effort walk.
        match expr {
            StabsTypeExpr::TypeRef { file, num } => {
                let key = TypeKey::cross(*file, *num);
                self.raw_types.entry(key).or_insert_with(|| expr.clone());
            }
            StabsTypeExpr::Struct { fields, .. } | StabsTypeExpr::Union { fields, .. } => {
                for f in fields {
                    self.register_type_expr(&f.type_expr);
                }
            }
            StabsTypeExpr::Pointer(inner)
            | StabsTypeExpr::Reference(inner)
            | StabsTypeExpr::Volatile(inner)
            | StabsTypeExpr::Const(inner) => {
                self.register_type_expr(inner);
            }
            StabsTypeExpr::Array { index_type, elem_type, .. } => {
                self.register_type_expr(index_type);
                self.register_type_expr(elem_type);
            }
            StabsTypeExpr::Range { base, .. } => {
                self.register_type_expr(base);
            }
            _ => {}
        }
    }

    fn resolve_expr(expr: &StabsTypeExpr, raw: &HashMap<TypeKey, StabsTypeExpr>) -> ReconstructedType {
        match expr {
            StabsTypeExpr::Void => ReconstructedType::Void,
            StabsTypeExpr::TypeRef { file, num } => {
                // If the referenced type is defined, resolve it recursively.
                let key = TypeKey::cross(*file, *num);
                if let Some(inner) = raw.get(&key) && !matches!(inner, StabsTypeExpr::TypeRef { .. }) {
                    return Self::resolve_expr(inner, raw);
                }
                ReconstructedType::Unknown { reason: format!("unresolved ref ({file},{num})") }
            }
            StabsTypeExpr::Pointer(inner) => {
                let inner_key = Self::expr_to_key(inner);
                ReconstructedType::Pointer { target: inner_key }
            }
            StabsTypeExpr::Reference(inner) => {
                let inner_key = Self::expr_to_key(inner);
                ReconstructedType::Reference { target: inner_key }
            }
            StabsTypeExpr::Volatile(inner) => {
                ReconstructedType::Volatile { inner: Self::expr_to_key(inner) }
            }
            StabsTypeExpr::Const(inner) => {
                ReconstructedType::Const { inner: Self::expr_to_key(inner) }
            }
            StabsTypeExpr::Array { index_type: _, elem_type, lo, hi } => {
                ReconstructedType::Array { elem: Self::expr_to_key(elem_type), lo: *lo, hi: *hi }
            }
            StabsTypeExpr::Function { return_type } => {
                ReconstructedType::Function { return_type: Self::expr_to_key(return_type) }
            }
            StabsTypeExpr::Range { base, lo, hi } => {
                // Try to identify primitive type.
                let prim = PrimitiveKind::from_range(*lo, *hi);
                if matches!(prim, PrimitiveKind::Unknown) {
                    ReconstructedType::Range { base: Self::expr_to_key(base), lo: *lo, hi: *hi }
                } else {
                    ReconstructedType::Primitive(prim)
                }
            }
            StabsTypeExpr::Struct { name, size, fields } => {
                let members: Vec<StructMember> = fields.iter().map(|f| StructMember {
                    name: f.name.clone(),
                    type_key: Self::expr_to_key(&f.type_expr),
                    bit_offset: f.bit_offset,
                    bit_size: f.bit_size,
                }).collect();
                ReconstructedType::Struct { name: name.clone(), size: *size, members }
            }
            StabsTypeExpr::Union { name, size, fields } => {
                let members: Vec<StructMember> = fields.iter().map(|f| StructMember {
                    name: f.name.clone(),
                    type_key: Self::expr_to_key(&f.type_expr),
                    bit_offset: f.bit_offset,
                    bit_size: f.bit_size,
                }).collect();
                ReconstructedType::Union { name: name.clone(), size: *size, members }
            }
            StabsTypeExpr::Enum { name, values } => {
                ReconstructedType::Enum { name: name.clone(), values: values.clone() }
            }
            StabsTypeExpr::Typedef { name, inner } => {
                ReconstructedType::Typedef { name: name.clone(), target: Self::expr_to_key(inner) }
            }
            StabsTypeExpr::Unknown(s) => {
                ReconstructedType::Unknown { reason: s.clone() }
            }
            StabsTypeExpr::MemberPtr { .. } => ReconstructedType::Unknown { reason: "unhandled expr".into() }
        }
    }

    const fn expr_to_key(expr: &StabsTypeExpr) -> TypeKey {
        match expr {
            StabsTypeExpr::TypeRef { file, num } => TypeKey::cross(*file, *num),
            _ => TypeKey::local(u32::MAX), // synthetic key for inline types
        }
    }
}

impl Default for StabsTypeReconstructor {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EnumValueIndex
// ─────────────────────────────────────────────────────────────────────────────

/// Index of all enum types with their named values for fast reverse lookup.
pub struct EnumValueIndex {
    /// `value_name` → (`enum_key`, `numeric_value`)
    by_value_name: HashMap<String, (TypeKey, i64)>,
    /// `enum_key` → `Vec<(name, value)>`
    by_key: HashMap<TypeKey, Vec<(String, i64)>>,
}

impl EnumValueIndex {
    /// Build from a type database.
    #[must_use]
    pub fn build(db: &ReconstructedTypeDb) -> Self {
        let mut by_value_name = HashMap::new();
        let mut by_key = HashMap::new();
        for (key, ty) in db.iter() {
            if let ReconstructedType::Enum { values, .. } = ty {
                by_key.insert(*key, values.clone());
                for (name, val) in values {
                    by_value_name.insert(name.clone(), (*key, *val));
                }
            }
        }
        Self { by_value_name, by_key }
    }

    /// Look up the enum key and value for a named enum constant.
    #[must_use]
    pub fn lookup_value(&self, name: &str) -> Option<(TypeKey, i64)> {
        self.by_value_name.get(name).copied()
    }

    /// Get all values for an enum by key.
    #[must_use]
    pub fn values_for(&self, key: &TypeKey) -> Option<&Vec<(String, i64)>> {
        self.by_key.get(key)
    }

    /// Total number of enum value entries.
    #[must_use]
    pub fn total_values(&self) -> usize {
        self.by_value_name.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primitive_from_range_int() {
        assert_eq!(PrimitiveKind::from_range(-2_147_483_648, 2_147_483_647), PrimitiveKind::Int);
    }

    #[test]
    fn test_primitive_from_range_char() {
        assert_eq!(PrimitiveKind::from_range(-128, 127), PrimitiveKind::SChar);
    }

    #[test]
    fn test_reconstructed_struct() {
        let ty = ReconstructedType::Struct {
            name: Some("Point".into()),
            size: 8,
            members: vec![
                StructMember { name: "x".into(), type_key: TypeKey::local(1), bit_offset: 0, bit_size: 32 },
                StructMember { name: "y".into(), type_key: TypeKey::local(1), bit_offset: 32, bit_size: 32 },
            ],
        };
        assert!(ty.c_decl().contains("Point"));
    }

    #[test]
    fn test_type_db_insert_and_get() {
        let mut db = ReconstructedTypeDb::new();
        let key = TypeKey::local(42);
        db.insert(key, ReconstructedType::Void);
        assert!(db.get(&key).is_some());
        assert!(matches!(db.get(&key).unwrap(), ReconstructedType::Void));
    }

    #[test]
    fn test_type_db_named_struct() {
        let mut db = ReconstructedTypeDb::new();
        let key = TypeKey::local(10);
        db.insert(key, ReconstructedType::Struct {
            name: Some("MyStruct".into()),
            size: 4,
            members: Vec::new(),
        });
        let found = db.get_by_name("MyStruct");
        assert!(found.is_some());
        assert_eq!(*found.unwrap().0, key);
    }

    #[test]
    fn test_enum_value_index() {
        let mut db = ReconstructedTypeDb::new();
        let key = TypeKey::local(20);
        db.insert(key, ReconstructedType::Enum {
            name: Some("Color".into()),
            values: vec![("RED".into(), 0), ("GREEN".into(), 1), ("BLUE".into(), 2)],
        });
        let idx = EnumValueIndex::build(&db);
        let (found_key, val) = idx.lookup_value("GREEN").unwrap();
        assert_eq!(found_key, key);
        assert_eq!(val, 1);
        assert_eq!(idx.total_values(), 3);
    }

    #[test]
    fn test_reconstructor_with_range_type() {
        // Simulate a single STABS N_LSYM with a range type descriptor.
        let parsed = vec![
            ParsedStab::LocalSym {
                name: "x".into(),
                type_expr: StabsTypeExpr::Range {
                    base: Box::new(StabsTypeExpr::TypeRef { file: 0, num: 1 }),
                    lo: -2_147_483_648,
                    hi: 2_147_483_647,
                },
                offset: -4,
            }
        ];
        let mut reconstructor = StabsTypeReconstructor::new();
        let db = reconstructor.reconstruct(&parsed);
        // Should have registered at least one type.
        assert!(!db.is_empty());
    }

    #[test]
    fn test_type_key_display() {
        let k1 = TypeKey::local(5);
        let k2 = TypeKey::cross(2, 10);
        assert_eq!(k1.to_string(), "5");
        assert_eq!(k2.to_string(), "(2,10)");
    }
}
