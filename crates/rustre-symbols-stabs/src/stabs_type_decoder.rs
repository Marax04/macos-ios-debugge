//! STABS type string decoder.
//!
//! Parses the complex type encoding used by GCC in STABS debug info:
//!   - Primitive type references: "(module,type)" or bare integer
//!   - Pointer types: "*type"
//!   - Array types: "ar(range-type);low;high;elem-type"
//!   - Struct/union: "s(size)field1:type,offset,size;..."
//!   - Enum: "e1:value,..."
//!   - Function/method: "f(ret-type)" or "(args)ret"
//!   - Cross-reference: "xs(name):", "xu(name):", "xe(name):"
//!   - Range type: "r(type);low;high"
//!   - Typedef: "tname:t(ref)"
//!   - Const/volatile qualifiers: "k(type)" / "B(type)"
//!   - Bitfield: packed integer within struct

use std::collections::HashMap;
use std::fmt;

// ── Decoded type ───────────────────────────────────────────────────────────────

/// A decoded STABS type.
#[derive(Debug, Clone, PartialEq)]
pub enum StabType {
    /// Unresolved forward reference or unknown
    Unknown(String),
    /// `void`.
    Void,
    /// `bool`.
    Bool,
    /// `char`.
    Char,
    /// `signed char`.
    SignedChar,
    /// `unsigned char`.
    UnsignedChar,
    /// `short`.
    Short,
    /// `unsigned short`.
    UnsignedShort,
    /// `int`.
    Int,
    /// `unsigned int`.
    UnsignedInt,
    /// `long`.
    Long,
    /// `unsigned long`.
    UnsignedLong,
    /// `long long`.
    LongLong,
    /// `unsigned long long`.
    UnsignedLongLong,
    /// `float`.
    Float,
    /// `double`.
    Double,
    /// `long double`.
    LongDouble,
    /// A pointer to another type
    Pointer(Box<Self>),
    /// A reference (C++) to another type
    Reference(Box<Self>),
    /// Array[low..high] of elem_type
    Array {
        /// Lower index bound.
        low: i64,
        /// Upper index bound.
        high: i64,
        /// Element type.
        elem_type: Box<Self>,
    },
    /// Struct or union
    Struct {
        /// Tag name (empty for anonymous).
        name: String,
        /// True for `union`, false for `struct`.
        is_union: bool,
        /// Total size in bytes.
        byte_size: u32,
        /// Member fields.
        fields: Vec<StructField>,
    },
    /// Enum
    Enum {
        /// Tag name (empty for anonymous).
        name: String,
        /// Enumerators.
        variants: Vec<EnumVariant>,
    },
    /// Function returning ret_type with given arg types
    Function {
        /// Return type.
        ret_type: Box<Self>,
        /// Argument types.
        arg_types: Vec<Self>,
    },
    /// Cross-reference (forward declaration): struct, union, enum
    XRef {
        /// Aggregate kind referenced.
        kind: XRefKind,
        /// Tag name referenced.
        name: String,
    },
    /// Typedef alias
    Typedef {
        /// Typedef name.
        name: String,
        /// Aliased type.
        inner: Box<Self>,
    },
    /// Const-qualified type
    Const(Box<Self>),
    /// Volatile-qualified type
    Volatile(Box<Self>),
    /// Range type
    Range {
        /// Base type the range restricts.
        base_type: Box<Self>,
        /// Lower bound.
        low: i64,
        /// Upper bound.
        high: i64,
    },
    /// Type by reference (e.g. "(1,2)")
    TypeRef {
        /// Module (file) index.
        module: i32,
        /// Type index within the module.
        index: i32,
    },
}

impl StabType {
    /// Canonical C name of the type, or the tag/typedef name for aggregates.
    #[must_use]
    pub const fn name(&self) -> &str {
        match self {
            Self::Void => "void",
            Self::Bool => "bool",
            Self::Char => "char",
            Self::SignedChar => "signed char",
            Self::UnsignedChar => "unsigned char",
            Self::Short => "short",
            Self::UnsignedShort => "unsigned short",
            Self::Int => "int",
            Self::UnsignedInt => "unsigned int",
            Self::Long => "long",
            Self::UnsignedLong => "unsigned long",
            Self::LongLong => "long long",
            Self::UnsignedLongLong => "unsigned long long",
            Self::Float => "float",
            Self::Double => "double",
            Self::LongDouble => "long double",
            Self::Struct { name, .. } | Self::Enum { name, .. } | Self::Typedef { name, .. }
            | Self::XRef { name, .. } => name.as_str(),
            Self::Unknown(s) => s.as_str(),
            _ => "<unnamed>",
        }
    }

    /// Size in bytes, when statically known.
    #[must_use]
    pub const fn byte_size(&self) -> Option<u32> {
        match self {
            Self::Void => Some(0),
            Self::Bool | Self::Char | Self::SignedChar | Self::UnsignedChar => Some(1),
            Self::Short | Self::UnsignedShort => Some(2),
            Self::Int | Self::UnsignedInt | Self::Float => Some(4),
            Self::LongLong | Self::UnsignedLongLong | Self::Double => Some(8),
            Self::LongDouble => Some(16),
            Self::Struct { byte_size, .. } => Some(*byte_size),
            _ => None,
        }
    }

    /// Returns `true` if this is a pointer type.
    #[must_use]
    pub fn is_pointer(&self) -> bool { matches!(self, Self::Pointer(_)) }
    /// Returns `true` if this is a struct/union type.
    #[must_use]
    pub fn is_struct(&self) -> bool { matches!(self, Self::Struct { .. }) }
    /// Returns `true` if this is an enum type.
    #[must_use]
    pub fn is_enum(&self) -> bool { matches!(self, Self::Enum { .. }) }
    /// Returns `true` if this is `void`.
    #[must_use]
    pub fn is_void(&self) -> bool { matches!(self, Self::Void) }
}

impl fmt::Display for StabType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pointer(inner) => write!(f, "{inner}*"),
            Self::Reference(inner) => write!(f, "{inner}&"),
            Self::Array { low, high, elem_type } => write!(f, "{elem_type}[{low}..{high}]"),
            Self::Struct { name, is_union, .. } => {
                write!(f, "{} {name}", if *is_union { "union" } else { "struct" })
            }
            Self::Enum { name, .. } => write!(f, "enum {name}"),
            Self::Function { ret_type, .. } => write!(f, "fn() -> {ret_type}"),
            Self::Const(inner) => write!(f, "const {inner}"),
            Self::Volatile(inner) => write!(f, "volatile {inner}"),
            Self::Typedef { name, .. } => write!(f, "{name}"),
            Self::XRef { kind, name } => write!(f, "{kind} {name}"),
            Self::TypeRef { module, index } => write!(f, "({module},{index})"),
            other => write!(f, "{}", other.name()),
        }
    }
}

/// Aggregate kind named by a STABS cross-reference (`xs`/`xu`/`xe`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XRefKind {
    /// `xs` — struct cross-reference.
    Struct,
    /// `xu` — union cross-reference.
    Union,
    /// `xe` — enum cross-reference.
    Enum,
}

impl fmt::Display for XRefKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Struct => write!(f, "struct"),
            Self::Union => write!(f, "union"),
            Self::Enum => write!(f, "enum"),
        }
    }
}

/// A field of a decoded struct or union.
#[derive(Debug, Clone, PartialEq)]
pub struct StructField {
    /// Field name.
    pub name: String,
    /// Field type.
    pub field_type: StabType,
    /// Bit offset from start of struct
    pub bit_offset: u32,
    /// Bit size (0 = use type's natural size)
    pub bit_size: u32,
}

impl StructField {
    /// Byte offset of the field (bit offset / 8).
    #[must_use]
    pub const fn byte_offset(&self) -> u32 { self.bit_offset / 8 }
    /// Returns `true` if the field is a bitfield (size not byte-aligned).
    #[must_use]
    pub fn is_bitfield(&self) -> bool { !self.bit_size.is_multiple_of(8) }
}

/// A decoded enum variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumVariant {
    /// Enumerator name.
    pub name: String,
    /// Enumerator value.
    pub value: i64,
}

// ── Type database ──────────────────────────────────────────────────────────────

/// A type ID in the form (module, index)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypeId {
    /// Module (file) index.
    pub module: i32,
    /// Type index within the module.
    pub index: i32,
}

impl TypeId {
    /// Build a `(module, index)` type ID.
    #[must_use]
    pub const fn new(module: i32, index: i32) -> Self { Self { module, index } }
    /// Build a type ID in module 0.
    #[must_use]
    pub const fn simple(index: i32) -> Self { Self { module: 0, index } }
}

/// Database of all decoded STABS types, keyed by (module, type_index)
#[derive(Debug, Default)]
pub struct TypeDatabase {
    types: HashMap<TypeId, StabType>,
    name_map: HashMap<String, TypeId>,
}

impl TypeDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Insert a type, also indexing it by name when it has one.
    pub fn insert(&mut self, id: TypeId, ty: StabType) {
        let name = ty.name().to_string();
        if !name.is_empty() && name != "<unnamed>" {
            self.name_map.insert(name, id);
        }
        self.types.insert(id, ty);
    }

    /// Look up a type by ID.
    #[must_use]
    pub fn get(&self, id: TypeId) -> Option<&StabType> { self.types.get(&id) }

    /// Number of types currently stored in the database.
    #[must_use]
    pub fn len(&self) -> usize { self.types.len() }

    /// Returns `true` if the database contains no types.
    #[must_use]
    pub fn is_empty(&self) -> bool { self.types.is_empty() }

    /// Look up a named type (typedef or tag).
    #[must_use]
    pub fn lookup_by_name(&self, name: &str) -> Option<&StabType> {
        let id = self.name_map.get(name)?;
        self.types.get(id)
    }

    /// Follow typedef/qualifier/`TypeRef` chains to the concrete type (depth-bounded).
    #[must_use]
    pub fn resolve<'a>(&'a self, ty: &'a StabType) -> &'a StabType {
        self.resolve_depth(ty, 0)
    }

    fn resolve_depth<'a>(&'a self, ty: &'a StabType, depth: u32) -> &'a StabType {
        if depth > 128 {
            // Guard against cyclic or pathologically deep typedef chains in
            // adversarial input.
            return ty;
        }
        match ty {
            StabType::TypeRef { module, index } => {
                let id = TypeId::new(*module, *index);
                self.types.get(&id).map_or(ty, |resolved| self.resolve_depth(resolved, depth + 1))
            }
            StabType::Typedef { inner, .. } | StabType::Const(inner) | StabType::Volatile(inner) => self.resolve_depth(inner, depth + 1),
            other => other,
        }
    }

    /// Number of types stored (alias of [`Self::len`]).
    #[must_use]
    pub fn type_count(&self) -> usize { self.types.len() }
}

// ── Parser ─────────────────────────────────────────────────────────────────────

/// Cursor over a type string for recursive-descent parsing
struct TypeCursor<'a> {
    s: &'a str,
    pos: usize,
    /// Current recursive-descent nesting depth; bounded by [`MAX_PARSE_DEPTH`]
    /// so that a hostile descriptor such as 200_000 consecutive `*` cannot
    /// overflow the stack.
    depth: u32,
}

/// Maximum nesting depth accepted by the recursive type parser.
/// Real compilers never emit more than a handful of levels.
const MAX_PARSE_DEPTH: u32 = 100;

impl<'a> TypeCursor<'a> {
    fn new(s: &'a str) -> Self { Self { s, pos: 0, depth: 0 } }
    #[must_use]
    fn remaining(&self) -> &'a str { &self.s[self.pos..] }
    #[must_use]
    fn peek(&self) -> Option<char> { self.remaining().chars().next() }
    #[must_use]
    const fn at_end(&self) -> bool { self.pos >= self.s.len() }

    fn advance(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.s.len());
    }

    fn consume_char(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.advance(c.len_utf8());
        Some(c)
    }

    fn expect(&mut self, ch: char) -> bool {
        if self.peek() == Some(ch) { self.advance(1); true } else { false }
    }

    /// Read an integer (possibly negative)
    fn read_int(&mut self) -> Option<i64> {
        let start = self.pos;
        if self.peek() == Some('-') { self.advance(1); }
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.advance(1);
        }
        if self.pos == start { return None; }
        self.s[start..self.pos].parse().ok()
    }

    /// Read until a delimiter char, returning the slice
    fn read_until(&mut self, delimiter: char) -> &'a str {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c == delimiter { break; }
            self.advance(c.len_utf8());
        }
        &self.s[start..self.pos]
    }

    /// Read until any of the given delimiters
    fn read_until_any(&mut self, delimiters: &[char]) -> &'a str {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if delimiters.contains(&c) { break; }
            self.advance(c.len_utf8());
        }
        &self.s[start..self.pos]
    }
}

/// Promote a freshly-decoded aggregate type to carry the given tag name
/// when the original definition left it anonymous (`"<unnamed>"`).
///
/// Used by `process_lsym_entry` when handling `T<tag>:...` definitions:
/// the tag identifier from outside the type body must be glued onto the
/// inner struct/union/enum so that `TypeDatabase::lookup_by_name` works.
fn promote_anonymous_to_tag(ty: StabType, tag: &str) -> StabType {
    fn is_blank(name: &str) -> bool {
        name.is_empty() || name == "<unnamed>"
    }
    match ty {
        StabType::Struct { name, is_union, byte_size, fields } if is_blank(&name) => {
            StabType::Struct { name: tag.to_string(), is_union, byte_size, fields }
        }
        StabType::Enum { name, variants } if is_blank(&name) => {
            StabType::Enum { name: tag.to_string(), variants }
        }
        other => other,
    }
}

/// Decode a STABS type string into a `StabType`
#[must_use]
pub fn decode_type(type_str: &str) -> StabType {
    let mut cursor = TypeCursor::new(type_str);
    if cursor.at_end() {
        return StabType::Void;
    }
    parse_type(&mut cursor)
}

fn parse_type(cur: &mut TypeCursor<'_>) -> StabType {
    if cur.depth >= MAX_PARSE_DEPTH {
        // Degrade gracefully instead of recursing further. We deliberately
        // consume no more input: the caller unwinds and the remaining text is
        // discarded by the enclosing parse.
        return StabType::Unknown("depth limit".into());
    }
    cur.depth += 1;
    let out = parse_type_inner(cur);
    cur.depth -= 1;
    out
}

fn parse_type_inner(cur: &mut TypeCursor<'_>) -> StabType {
    match cur.peek() {
        None => StabType::Void,
        Some('(') => parse_type_ref(cur),
        Some('*') => { cur.advance(1); StabType::Pointer(Box::new(parse_type(cur))) }
        Some('&') => { cur.advance(1); StabType::Reference(Box::new(parse_type(cur))) }
        Some('a' | 'A') => parse_array(cur),
        Some('s') if cur.remaining().starts_with("su") => parse_struct(cur, false),
        Some('s') => parse_struct(cur, false),
        Some('u') => parse_struct(cur, true),
        Some('e') => parse_enum(cur),
        Some('x') => parse_xref(cur),
        Some('f') => { cur.advance(1); StabType::Function { ret_type: Box::new(parse_type(cur)), arg_types: vec![] } }
        Some('k') => { cur.advance(1); StabType::Const(Box::new(parse_type(cur))) }
        Some('B') => { cur.advance(1); StabType::Volatile(Box::new(parse_type(cur))) }
        Some('r') => parse_range(cur),
        Some('t') => {
            // Typedef: "tname:type"
            cur.advance(1);
            let name = cur.read_until(':').to_string();
            cur.expect(':');
            let inner = parse_type(cur);
            StabType::Typedef { name, inner: Box::new(inner) }
        }
        Some(c) if c.is_ascii_digit() => parse_bare_type_ref(cur),
        Some(_) => {
            let s = cur.read_until_any(&[';', ',', ')']).to_string();
            StabType::Unknown(s)
        }
    }
}

fn parse_type_ref(cur: &mut TypeCursor<'_>) -> StabType {
    // "(module,index)"
    if !cur.expect('(') { return StabType::Unknown("bad typeref".into()); }
    let module = i32::try_from(cur.read_int().unwrap_or(0)).unwrap_or(i32::MAX);
    cur.expect(',');
    let index = i32::try_from(cur.read_int().unwrap_or(0)).unwrap_or(i32::MAX);
    cur.expect(')');
    // Resolve primitives
    if module == 0 && let Some(prim) = resolve_primitive(index) {
        return prim;
    }
    StabType::TypeRef { module, index }
}

fn parse_bare_type_ref(cur: &mut TypeCursor<'_>) -> StabType {
    let index = i32::try_from(cur.read_int().unwrap_or(0)).unwrap_or(i32::MAX);
    if let Some(prim) = resolve_primitive(index) {
        return prim;
    }
    StabType::TypeRef { module: 0, index }
}

/// Map Sun/GCC primitive type indices to [`StabType`]
#[must_use]
const fn resolve_primitive(index: i32) -> Option<StabType> {
    Some(match index {
        1 => StabType::Int,
        2 => StabType::Char,
        3 => StabType::Short,
        4 => StabType::Long,
        5 => StabType::UnsignedChar,
        6 => StabType::SignedChar,
        7 => StabType::UnsignedShort,
        8 => StabType::UnsignedInt,
        9 => StabType::UnsignedLong,
        10 => StabType::Void,
        11 => StabType::Float,
        12 => StabType::Double,
        13 => StabType::LongDouble,
        14 => StabType::LongLong,
        15 => StabType::UnsignedLongLong,
        16 => StabType::Bool,
        _ => return None,
    })
}

fn parse_array(cur: &mut TypeCursor<'_>) -> StabType {
    // "ar(range-type);low;high;elem-type" or "A(elem-type)"
    cur.advance(1); // 'a' or 'A'
    if cur.peek() == Some('r') {
        cur.advance(1); // 'r'
        let _range_type = parse_type(cur);
        cur.expect(';');
        let low = cur.read_int().unwrap_or(0);
        cur.expect(';');
        let high = cur.read_int().unwrap_or(-1);
        cur.expect(';');
        let elem_type = parse_type(cur);
        StabType::Array { low, high, elem_type: Box::new(elem_type) }
    } else {
        // Dynamic array
        let elem_type = parse_type(cur);
        StabType::Array { low: 0, high: -1, elem_type: Box::new(elem_type) }
    }
}

fn parse_struct(cur: &mut TypeCursor<'_>, is_union: bool) -> StabType {
    cur.advance(1); // 's' or 'u'
    let byte_size = u32::try_from(cur.read_int().unwrap_or(0)).unwrap_or(u32::MAX);
    let mut fields = Vec::new();

    // Fields: "name:type,bit_offset,bit_size;"
    while cur.peek().is_some_and(|c| c != ';' && c != ')') {
        let name = cur.read_until(':').to_string();
        if name.is_empty() { break; }
        cur.expect(':');
        let field_type = parse_type(cur);
        cur.expect(',');
        let bit_offset = u32::try_from(cur.read_int().unwrap_or(0)).unwrap_or(u32::MAX);
        cur.expect(',');
        let bit_size = u32::try_from(cur.read_int().unwrap_or(0)).unwrap_or(u32::MAX);
        cur.expect(';');
        fields.push(StructField { name, field_type, bit_offset, bit_size });
    }
    cur.expect(';');

    StabType::Struct { name: String::new(), is_union, byte_size, fields }
}

fn parse_enum(cur: &mut TypeCursor<'_>) -> StabType {
    cur.advance(1); // 'e'
    let mut variants = Vec::new();

    // "name:value,"  terminated by ";"
    while cur.peek().is_some_and(|c| c != ';') {
        let name = cur.read_until(':').to_string();
        if name.is_empty() { break; }
        cur.expect(':');
        let value = cur.read_int().unwrap_or(0);
        cur.expect(',');
        variants.push(EnumVariant { name, value });
    }
    cur.expect(';');

    StabType::Enum { name: String::new(), variants }
}

fn parse_xref(cur: &mut TypeCursor<'_>) -> StabType {
    cur.advance(1); // 'x'
    let kind = match cur.consume_char() {
        Some('s') => XRefKind::Struct,
        Some('u') => XRefKind::Union,
        Some('e') => XRefKind::Enum,
        _ => return StabType::Unknown("bad xref".into()),
    };
    let name = cur.read_until(':').to_string();
    cur.expect(':');
    StabType::XRef { kind, name }
}

fn parse_range(cur: &mut TypeCursor<'_>) -> StabType {
    cur.advance(1); // 'r'
    let base_type = parse_type(cur);
    cur.expect(';');
    let low = cur.read_int().unwrap_or(0);
    cur.expect(';');
    let high = cur.read_int().unwrap_or(0);
    StabType::Range { base_type: Box::new(base_type), low, high }
}

// ── Full type-descriptor processor ────────────────────────────────────────────

/// Processes a complete stab name entry like "foo:t(1,5)=struct{...}" and
/// inserts the resulting type into the database.
pub fn process_type_definition(entry: &str, db: &mut TypeDatabase) {
    // Split at the first ':'
    let Some(colon) = entry.find(':') else { return };
    let name = &entry[..colon];
    let rest = &entry[colon+1..];

    // rest may start with type kind indicator 't' (typedef), 'T' (tag)
    let (is_tag, type_str) = if rest.starts_with('t') || rest.starts_with('T') {
        (rest.starts_with('T'), &rest[1..])
    } else {
        (false, rest)
    };

    // Check for "(module,index)=..." defining a new type
    if type_str.starts_with('(') || type_str.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        let mut cur = TypeCursor::new(type_str);
        let id_type = parse_type_ref_id(&mut cur);
        if cur.expect('=') {
            let mut defined = complete_type(cur.remaining(), name);
            // Tag-form ('T') definitions name a struct/union/enum tag rather
            // than a typedef; promote anonymous aggregates to carry the tag
            // name so callers can find them via `lookup_by_name`.
            if is_tag {
                defined = promote_anonymous_to_tag(defined, name);
            }
            let (module, index) = id_type;
            db.insert(TypeId::new(module, index), defined);
        }
    } else {
        let mut defined = complete_type(type_str, name);
        if is_tag {
            defined = promote_anonymous_to_tag(defined, name);
        }
        // Use a dummy ID based on name hash for unnamed types
        let hash = simple_hash(name).cast_signed();
        db.insert(TypeId::new(-1, hash), defined);
    }
}

/// Parse "(m,i)" and return (m,i) without consuming further
fn parse_type_ref_id(cur: &mut TypeCursor<'_>) -> (i32, i32) {
    if cur.peek() != Some('(') {
        let index = i32::try_from(cur.read_int().unwrap_or(0)).unwrap_or(i32::MAX);
        return (0, index);
    }
    cur.expect('(');
    let m = i32::try_from(cur.read_int().unwrap_or(0)).unwrap_or(i32::MAX);
    cur.expect(',');
    let i = i32::try_from(cur.read_int().unwrap_or(0)).unwrap_or(i32::MAX);
    cur.expect(')');
    (m, i)
}

/// Parse a full type body, attaching the given name
fn complete_type(type_str: &str, name: &str) -> StabType {
    let mut ty = decode_type(type_str);
    // Attach name to anonymous struct/union/enum
    match &mut ty {
        StabType::Struct { name: n, .. } | StabType::Enum { name: n, .. } if n.is_empty() => *n = name.to_string(),
        _ => {}
    }
    ty
}

fn simple_hash(s: &str) -> u32 {
    let mut h: u32 = 5381;
    for b in s.bytes() { h = h.wrapping_mul(33).wrapping_add(u32::from(b)); }
    h
}

// ── Typedef resolution ─────────────────────────────────────────────────────────

/// Walk a typedef chain to find the underlying concrete type
#[must_use]
pub fn underlying_type<'a>(ty: &'a StabType, db: &'a TypeDatabase) -> &'a StabType {
    underlying_type_depth(ty, db, 0)
}

/// Maximum typedef/`TypeRef` chain length followed by [`underlying_type`].
/// Mutually recursive definitions (`a:t(0,100)=(0,101)`, `b:t(0,101)=(0,100)`)
/// are legal STABS and would otherwise recurse until the stack overflows.
const MAX_UNDERLYING_DEPTH: u32 = 128;

fn underlying_type_depth<'a>(ty: &'a StabType, db: &'a TypeDatabase, depth: u32) -> &'a StabType {
    if depth > MAX_UNDERLYING_DEPTH {
        return ty;
    }
    match ty {
        StabType::Typedef { inner, .. } | StabType::Const(inner) | StabType::Volatile(inner) => {
            underlying_type_depth(inner, db, depth + 1)
        }
        StabType::TypeRef { module, index } => {
            let id = TypeId::new(*module, *index);
            db.get(id)
                .map_or(ty, |resolved| underlying_type_depth(resolved, db, depth + 1))
        }
        other => other,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_pointer_to_int() {
        let ty = decode_type("*(0,1)");
        assert!(ty.is_pointer());
        if let StabType::Pointer(inner) = &ty {
            assert_eq!(**inner, StabType::Int);
        }
    }

    #[test]
    fn test_decode_int_primitive() {
        assert_eq!(decode_type("(0,1)"), StabType::Int);
        assert_eq!(decode_type("(0,2)"), StabType::Char);
        assert_eq!(decode_type("(0,10)"), StabType::Void);
    }

    #[test]
    fn test_decode_array() {
        let ty = decode_type("ar(0,1);0;9;(0,1)");
        if let StabType::Array { low, high, elem_type } = ty {
            assert_eq!(low, 0);
            assert_eq!(high, 9);
            assert_eq!(*elem_type, StabType::Int);
        } else {
            panic!("Expected array, got {:?}", ty);
        }
    }

    #[test]
    fn test_decode_struct() {
        // struct with two int fields
        let ty = decode_type("s8x:(0,1),0,32;y:(0,1),32,32;");
        if let StabType::Struct { byte_size, fields, .. } = ty {
            assert_eq!(byte_size, 8);
            assert_eq!(fields.len(), 2);
            assert_eq!(fields[0].name, "x");
            assert_eq!(fields[0].bit_offset, 0);
            assert_eq!(fields[1].name, "y");
            assert_eq!(fields[1].bit_offset, 32);
        } else {
            panic!("Expected struct, got {:?}", ty);
        }
    }

    #[test]
    fn test_decode_enum() {
        let ty = decode_type("eRed:0,Green:1,Blue:2,;");
        if let StabType::Enum { variants, .. } = ty {
            assert_eq!(variants.len(), 3);
            assert_eq!(variants[0].name, "Red");
            assert_eq!(variants[0].value, 0);
            assert_eq!(variants[2].name, "Blue");
            assert_eq!(variants[2].value, 2);
        } else {
            panic!("Expected enum, got {:?}", ty);
        }
    }

    #[test]
    fn test_decode_xref() {
        let ty = decode_type("xsMyStruct:");
        if let StabType::XRef { kind, name } = ty {
            assert_eq!(kind, XRefKind::Struct);
            assert_eq!(name, "MyStruct");
        } else {
            panic!("Expected xref, got {:?}", ty);
        }
    }

    #[test]
    fn test_decode_const() {
        let ty = decode_type("k(0,1)");
        if let StabType::Const(inner) = ty {
            assert_eq!(*inner, StabType::Int);
        } else {
            panic!("Expected const, got {:?}", ty);
        }
    }

    #[test]
    fn test_type_database_insert_lookup() {
        let mut db = TypeDatabase::new();
        let id = TypeId::new(0, 42);
        db.insert(id, StabType::Int);
        assert_eq!(db.get(id), Some(&StabType::Int));
    }

    #[test]
    fn test_underlying_type_through_typedef() {
        let mut db = TypeDatabase::new();
        let int_id = TypeId::new(0, 1);
        db.insert(int_id, StabType::Int);
        let typedef = StabType::Typedef {
            name: "MyInt".to_string(),
            inner: Box::new(StabType::TypeRef { module: 0, index: 1 }),
        };
        let resolved = underlying_type(&typedef, &db);
        assert_eq!(resolved, &StabType::Int);
    }

    #[test]
    fn test_struct_field_byte_offset() {
        let f = StructField {
            name: "x".to_string(),
            field_type: StabType::Int,
            bit_offset: 64,
            bit_size: 32,
        };
        assert_eq!(f.byte_offset(), 8);
        assert!(!f.is_bitfield());
    }

    #[test]
    fn test_stab_type_display() {
        let ptr = StabType::Pointer(Box::new(StabType::Int));
        let s = format!("{}", ptr);
        assert!(s.contains("int"));
    }
}
