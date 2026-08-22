// stabs_type_resolver.rs — STABS type descriptor resolver
//
// Parses and resolves the type descriptors embedded in STABS string tables.
// Handles cross-file type references, forward declarations, and recursive
// definitions. Produces a fully resolved TypeDb for downstream consumers.

use std::collections::HashMap;
use std::fmt;
use std::str::Chars;

// ---------------------------------------------------------------------------
// TypeRef — (file_index, type_id) pair used as a dictionary key
// ---------------------------------------------------------------------------

/// Identifies a STABS type by the file index it belongs to and its numeric id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypeRef {
    /// Source-file index the type number is scoped to (0 = current file).
    pub file: u16,
    /// Numeric type id within that file.
    pub id: u32,
}

impl TypeRef {
    /// Create a reference from an explicit `(file, id)` pair.
    #[must_use]
    pub const fn new(file: u16, id: u32) -> Self {
        Self { file, id }
    }
    /// The "current file" sentinel uses file = 0.
    #[must_use]
    pub const fn local(id: u32) -> Self {
        Self { file: 0, id }
    }
}

impl fmt::Display for TypeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({},{})", self.file, self.id)
    }
}

// ---------------------------------------------------------------------------
// StabsMember — a struct/union field
// ---------------------------------------------------------------------------

/// A struct or union member parsed from a STABS aggregate descriptor.
#[derive(Debug, Clone, PartialEq)]
pub struct StabsMember {
    /// Member name.
    pub name: String,
    /// Reference to the member's type.
    pub type_ref: TypeRef,
    /// Bit offset of the member within the aggregate.
    pub bit_offset: u32,
    /// Bit width of the member.
    pub bit_size: u32,
}

impl StabsMember {
    /// Create a member from its name, type reference, and bit layout.
    #[must_use]
    pub fn new(name: &str, type_ref: TypeRef, bit_offset: u32, bit_size: u32) -> Self {
        Self {
            name: name.to_string(),
            type_ref,
            bit_offset,
            bit_size,
        }
    }
}

// ---------------------------------------------------------------------------
// StabsType — the fully structured type
// ---------------------------------------------------------------------------

/// A structured STABS type decoded from a type descriptor string.
#[derive(Debug, Clone, PartialEq)]
pub enum StabsType {
    /// The void type (`v` descriptor).
    Void,
    /// Integer type derived from a range (`r`) descriptor.
    Int {
        /// True when the range lower bound is negative.
        signed: bool,
        /// Width in bytes (1..=8).
        bytes: u8,
    },
    /// Floating-point type (size-encoded `r` descriptor).
    Float {
        /// Width in bytes.
        bytes: u8,
    },
    /// Boolean type (`b` descriptor).
    Bool,
    /// Character type (`c` descriptor).
    Char,
    /// Pointer to another type (`*` descriptor).
    Pointer(Box<Self>),
    /// Array type (`a` descriptor).
    Array {
        /// Index type (usually a range descriptor).
        index: Box<Self>,
        /// Element type.
        element: Box<Self>,
    },
    /// Struct type (`s` descriptor).
    Struct {
        /// Struct tag name (empty for anonymous structs).
        name: String,
        /// Total size in bytes.
        size: u32,
        /// Member list with bit offsets and sizes.
        members: Vec<StabsMember>,
    },
    /// Union type (`u` descriptor).
    Union {
        /// Union tag name (empty for anonymous unions).
        name: String,
        /// Total size in bytes.
        size: u32,
        /// Member list (all at bit offset 0).
        variants: Vec<StabsMember>,
    },
    /// Enum type (`e` descriptor).
    Enum {
        /// Enum tag name (empty for anonymous enums).
        name: String,
        /// `(name, value)` pairs for each enumerator.
        variants: Vec<(String, i64)>,
    },
    /// Function type (`f` descriptor).
    Function {
        /// Return type.
        return_type: Box<Self>,
        /// Parameter types (STABS rarely encodes these; often empty).
        params: Vec<Self>,
    },
    /// Named alias for another type.
    Typedef {
        /// Typedef name.
        name: String,
        /// Aliased type.
        target: Box<Self>,
    },
    /// Lazy reference — not yet resolved.
    Reference(TypeRef),
    /// Could not be resolved at all.
    Unresolved(TypeRef),
}

impl StabsType {
    /// Byte size of the type, when statically known.
    #[must_use]
    pub fn byte_size(&self) -> Option<u32> {
        match self {
            Self::Void => Some(0),
            Self::Int { bytes, .. } => Some(u32::from(*bytes)),
            Self::Float { bytes } => Some(u32::from(*bytes)),
            Self::Bool => Some(1),
            Self::Char => Some(1),
            Self::Pointer(_) => Some(8), // assume 64-bit
            Self::Struct { size, .. } | Self::Union { size, .. } => Some(*size),
            Self::Enum { .. } => Some(4),
            Self::Array { .. } => {
                // Array byte size requires element count from the index range,
                // which is not stored in StabsType::Array. Return None always.
                None
            }
            _ => None,
        }
    }

    /// Short human-readable name for the type (e.g. `i32`, `*char`, `struct Foo`).
    #[must_use]
    pub fn type_name(&self) -> String {
        match self {
            Self::Void => "void".into(),
            Self::Int { signed, bytes } => {
                format!("{}{}", if *signed { "i" } else { "u" }, bytes * 8)
            }
            Self::Float { bytes } => format!("f{}", bytes * 8),
            Self::Bool => "bool".into(),
            Self::Char => "char".into(),
            Self::Pointer(inner) => format!("*{}", inner.type_name()),
            Self::Struct { name, .. } => format!("struct {name}"),
            Self::Union { name, .. } => format!("union {name}"),
            Self::Enum { name, .. } => format!("enum {name}"),
            Self::Function { return_type, .. } => format!("fn() -> {}", return_type.type_name()),
            Self::Typedef { name, .. } => name.clone(),
            Self::Array { element, .. } => format!("[{}]", element.type_name()),
            Self::Reference(r) => format!("ref{r}"),
            Self::Unresolved(r) => format!("?{r}"),
        }
    }
}

// ---------------------------------------------------------------------------
// TypeDb — registry of all parsed and resolved types
// ---------------------------------------------------------------------------

/// Registry of all parsed and resolved STABS types, keyed by [`TypeRef`].
#[derive(Debug, Default)]
pub struct TypeDb {
    /// All known types keyed by their `(file, id)` reference.
    pub types: HashMap<TypeRef, StabsType>,
}

impl TypeDb {
    /// Create an empty type database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or replace) a type under the given reference.
    pub fn insert(&mut self, r: TypeRef, t: StabsType) {
        self.types.insert(r, t);
    }

    /// Look up a type by reference.
    #[must_use]
    pub fn get(&self, r: &TypeRef) -> Option<&StabsType> {
        self.types.get(r)
    }

    /// Number of registered types.
    #[must_use]
    pub fn len(&self) -> usize {
        self.types.len()
    }

    /// True if no types are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Parser state
// ---------------------------------------------------------------------------

struct Parser<'a> {
    src: &'a str,
    pos: usize,
    current_file: u16,
    /// Recursive-descent nesting depth, bounded by [`MAX_PARSE_DEPTH`].
    depth: u32,
}

/// Maximum nesting depth accepted by the recursive descriptor parser.
const MAX_PARSE_DEPTH: u32 = 100;

impl<'a> Parser<'a> {
    const fn new(s: &'a str, file: u16) -> Self {
        Self { src: s, pos: 0, current_file: file, depth: 0 }
    }

    /// Iterator over the remaining characters from the current cursor.
    ///
    /// Used by call-sites that want to look ahead more than a single
    /// `char` without committing to consumption (`peek` only sees one).
    fn remaining_chars(&self) -> Chars<'a> {
        self.src[self.pos..].chars()
    }

    fn peek(&self) -> Option<char> {
        self.remaining_chars().next()
    }

    fn advance(&mut self) -> Option<char> {
        let ch = self.src[self.pos..].chars().next()?;
        self.pos += ch.len_utf8();
        Some(ch)
    }

    fn expect(&mut self, c: char) -> Result<(), String> {
        match self.advance() {
            Some(got) if got == c => Ok(()),
            Some(got) => Err(format!("expected '{}' got '{}' at pos {}", c, got, self.pos)),
            None => Err(format!("expected '{}' but got EOF at pos {}", c, self.pos)),
        }
    }

    fn eat_char(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.pos += c.len_utf8();
            true
        } else {
            false
        }
    }

    fn parse_digits(&mut self) -> String {
        let start = self.pos;
        while self.peek().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            self.pos += 1;
        }
        self.src[start..self.pos].to_string()
    }

    fn parse_u32(&mut self) -> Result<u32, String> {
        let s = self.parse_digits();
        s.parse::<u32>().map_err(|_| format!("bad u32 '{}' at pos {}", s, self.pos))
    }

    /// Parse a signed integer as `i128`.
    ///
    /// Required for range bounds: `-9223372036854775808` has a digit magnitude
    /// of `i64::MAX + 1`, so parsing the digits as `i64` before negating fails
    /// and the whole `long long` range silently falls through to a 4-byte int.
    fn parse_i128(&mut self) -> Result<i128, String> {
        let neg = self.eat_char('-');
        let s = self.parse_digits();
        let v: i128 = s.parse::<i128>().map_err(|_| String::from("bad i128"))?;
        Ok(if neg { -v } else { v })
    }

    fn parse_i64(&mut self) -> Result<i64, String> {
        let neg = self.eat_char('-');
        let s = self.parse_digits();
        let v: i64 = s.parse::<i64>().map_err(|_| format!("bad i64"))?;
        Ok(if neg { -v } else { v })
    }

    fn parse_name_until(&mut self, terminators: &[char]) -> String {
        let mut out = String::new();
        while let Some(c) = self.peek() {
            if terminators.contains(&c) {
                break;
            }
            out.push(c);
            self.pos += c.len_utf8();
        }
        out
    }

    /// Parse a type reference of the form  (file,id)  or just  id
    fn parse_type_ref(&mut self) -> Result<TypeRef, String> {
        if self.eat_char('(') {
            let file = self.parse_u32()? as u16;
            self.expect(',')?;
            let id = self.parse_u32()?;
            self.expect(')')?;
            Ok(TypeRef::new(file, id))
        } else {
            let id = self.parse_u32()?;
            Ok(TypeRef::new(self.current_file, id))
        }
    }

    /// Parse one `StabsType` starting at current position.
    fn parse_type(&mut self) -> Result<StabsType, String> {
        if self.depth >= MAX_PARSE_DEPTH {
            return Err(String::from("type nesting depth limit exceeded"));
        }
        self.depth += 1;
        let out = self.parse_type_checked();
        self.depth -= 1;
        out
    }

    fn parse_type_checked(&mut self) -> Result<StabsType, String> {
        // Check if we start with a type ref definition:  (f,id)=desc  or  id=desc
        let saved_pos = self.pos;
        let result = self.try_parse_type_def();
        if result.is_ok() {
            return result;
        }
        self.pos = saved_pos;
        self.parse_type_descriptor()
    }

    fn try_parse_type_def(&mut self) -> Result<StabsType, String> {
        let _tref = self.parse_type_ref()?;
        self.expect('=')?;
        self.parse_type_descriptor()
    }

    fn parse_type_descriptor(&mut self) -> Result<StabsType, String> {
        match self.peek() {
            Some('*') => {
                self.advance();
                let inner = self.parse_type()?;
                Ok(StabsType::Pointer(Box::new(inner)))
            }
            Some('r') => {
                self.advance();
                // Range descriptor: r<type>;<lo>;<hi>;
                //
                // Decoded structurally, not by a literal-pair table. The old
                // table classified `r(0,1);0;9;` (an array index range) and the
                // unsigned form `r1;0;-1;` as 8-byte FLOATS, and reported a
                // 64-bit integer range as a 4-byte int.
                let _base = self.parse_type_ref().ok();
                self.eat_char(';');
                let lo = self.parse_i128().unwrap_or(0);
                self.eat_char(';');
                let hi = self.parse_i128().unwrap_or(0);

                // Structural forms with hi < lo are tested FIRST: they are size
                // encodings, not value ranges.
                if hi == 0 && lo > 0 {
                    // `r1;8;0;` — a float whose size is `lo` bytes.
                    return Ok(StabsType::Float {
                        bytes: u8::try_from(lo).unwrap_or(8),
                    });
                }
                if lo == 0 && hi == -1 {
                    // `r1;0;-1;` — the unsigned-word form.
                    return Ok(StabsType::Int { signed: false, bytes: 8 });
                }
                // Explicit pairs that disambiguate vendor quirks (notably
                // signed char, whose range is indistinguishable from a 7-bit
                // unsigned by width alone).
                let literal = match (lo, hi) {
                    (-128, 127) => Some(StabsType::Int { signed: true, bytes: 1 }),
                    (0, 255) => Some(StabsType::Int { signed: false, bytes: 1 }),
                    (0, 127) => Some(StabsType::Int { signed: true, bytes: 1 }),
                    (-32768, 32767) => Some(StabsType::Int { signed: true, bytes: 2 }),
                    (0, 65535) => Some(StabsType::Int { signed: false, bytes: 2 }),
                    (-2_147_483_648, 2_147_483_647) => {
                        Some(StabsType::Int { signed: true, bytes: 4 })
                    }
                    _ => None,
                };
                if let Some(t) = literal {
                    return Ok(t);
                }
                // General case: derive the width from the span, in i128 so the
                // full 64-bit signed range cannot overflow the subtraction.
                let span = hi.saturating_sub(lo).saturating_add(1).max(1);
                let bits = u32::try_from(span).map_or(64, |v: u32| {
                    v.checked_next_power_of_two().map_or(32, u32::trailing_zeros)
                });
                let bytes = u8::try_from(bits.div_ceil(8)).unwrap_or(8).clamp(1, 8);
                Ok(StabsType::Int { signed: lo < 0, bytes })
            }
            Some('b') => {
                self.advance();
                // boolean
                Ok(StabsType::Bool)
            }
            Some('c') => {
                self.advance();
                Ok(StabsType::Char)
            }
            Some('s') => {
                // struct
                self.advance();
                self.parse_struct_or_union(false)
            }
            Some('u') => {
                // union
                self.advance();
                self.parse_struct_or_union(true)
            }
            Some('e') => {
                self.advance();
                self.parse_enum()
            }
            Some('a') => {
                self.advance();
                self.parse_array()
            }
            Some('f') => {
                self.advance();
                // function returning a type
                let ret = self.parse_type()?;
                Ok(StabsType::Function { return_type: Box::new(ret), params: vec![] })
            }
            Some('x') => {
                self.advance();
                // cross reference: xs name:   or xe name:   or xu name:
                //
                // The kind char must be honoured: discarding it turned every
                // union and enum forward declaration into an empty *struct*.
                // The referenced type is defined in another CU, so it stays
                // opaque (size 0, no members) until resolved — which is legal —
                // but at least it keeps its correct kind.
                let kind = self.advance(); // 's','e','u'
                let name = self.parse_name_until(&[':']);
                self.eat_char(':');
                Ok(match kind {
                    Some('u') => StabsType::Union { name, size: 0, variants: vec![] },
                    Some('e') => StabsType::Enum { name, variants: vec![] },
                    _ => StabsType::Struct { name, size: 0, members: vec![] },
                })
            }
            Some('v') => {
                self.advance();
                Ok(StabsType::Void)
            }
            Some('(') | Some('0'..='9') => {
                let tref = self.parse_type_ref()?;
                Ok(StabsType::Reference(tref))
            }
            Some(c) => Err(format!("unknown type descriptor char '{}' at pos {}", c, self.pos)),
            None => Err("unexpected EOF in type descriptor".into()),
        }
    }

    fn parse_struct_or_union(&mut self, is_union: bool) -> Result<StabsType, String> {
        let size = self.parse_u32()?;
        let mut members = Vec::new();
        // members: name:type,bit_offset,bit_size;  ...  ;
        while self.peek() != Some(';') && self.peek().is_some() {
            let name = self.parse_name_until(&[':']);
            if name.is_empty() { break; }
            self.expect(':')?;
            let type_ref = self.parse_type_ref()?;
            self.expect(',')?;
            let bit_offset = self.parse_u32()?;
            self.expect(',')?;
            let bit_size = self.parse_u32()?;
            self.eat_char(';');
            members.push(StabsMember::new(&name, type_ref, bit_offset, bit_size));
        }
        self.eat_char(';');
        if is_union {
            Ok(StabsType::Union { name: String::new(), size, variants: members })
        } else {
            Ok(StabsType::Struct { name: String::new(), size, members })
        }
    }

    fn parse_enum(&mut self) -> Result<StabsType, String> {
        // name:value,name:value,...;
        let mut variants = Vec::new();
        while self.peek() != Some(';') && self.peek().is_some() {
            let name = self.parse_name_until(&[':']);
            if name.is_empty() { break; }
            self.expect(':')?;
            let value = self.parse_i64()?;
            self.eat_char(',');
            variants.push((name, value));
        }
        self.eat_char(';');
        Ok(StabsType::Enum { name: String::new(), variants })
    }

    fn parse_array(&mut self) -> Result<StabsType, String> {
        // a<index-type>;<element-type>
        // The index type is usually a range like `r(0,1);0;9` whose own
        // trailing components consume two semicolons, leaving the cursor at
        // the `;` separator before the element type.
        let index = self.parse_type()?;
        self.eat_char(';');
        let element = self.parse_type()?;
        Ok(StabsType::Array {
            index: Box::new(index),
            element: Box::new(element),
        })
    }
}

// ---------------------------------------------------------------------------
// Public parsing entry point
// ---------------------------------------------------------------------------

/// Parse a STABS type string into a `StabsType`.
///
/// `s` is the portion of the STABS string after the `name:type_char` prefix.
/// `file` is the current source-file index (for scoping cross-file references).
pub fn parse_type_string(s: &str, file: u16) -> Result<StabsType, String> {
    let mut p = Parser::new(s, file);
    p.parse_type()
}

// ---------------------------------------------------------------------------
// StabsTypeResolver — manages a TypeDb and resolves references
// ---------------------------------------------------------------------------

/// Manages a [`TypeDb`] and resolves `Reference` entries to concrete types.
pub struct StabsTypeResolver {
    /// The underlying type database.
    pub db: TypeDb,
    current_file: u16,
}

impl StabsTypeResolver {
    /// Create a resolver with an empty database, scoped to file 0.
    #[must_use]
    pub fn new() -> Self {
        Self { db: TypeDb::new(), current_file: 0 }
    }

    /// Set the file index used to scope unparenthesized type numbers.
    pub const fn set_current_file(&mut self, file: u16) {
        self.current_file = file;
    }

    /// Register a raw type string under the given `TypeRef`.
    pub fn register(&mut self, tref: TypeRef, type_str: &str) -> Result<(), String> {
        let parsed = parse_type_string(type_str, tref.file)?;
        self.db.insert(tref, parsed);
        Ok(())
    }

    /// Register using a compact definition string like `(0,1)=s4x:1,0,8;y:1,8,8;`
    pub fn register_definition(&mut self, def: &str) -> Result<TypeRef, String> {
        let mut p = Parser::new(def, self.current_file);
        let tref = p.parse_type_ref()?;
        p.expect('=')?;
        let ty = p.parse_type_descriptor()?;
        self.db.insert(tref, ty);
        Ok(tref)
    }

    /// Resolve all `Reference` variants in the db by looking up their targets.
    /// Iterates until stable (handles chains: A→B→C where C is concrete).
    pub fn resolve_all(&mut self) {
        for _ in 0..16 {
            let keys: Vec<TypeRef> = self.db.types.keys().copied().collect();
            let mut changed = false;
            for k in keys {
                let resolved = self.resolve_type(self.db.types[&k].clone());
                let entry = self.db.types.get_mut(&k).unwrap();
                if *entry != resolved {
                    *entry = resolved;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }

    /// Maximum reference-inlining depth. Self-referential types (e.g. a
    /// linked list `(0,1)=*(0,1)`) and mutual cycles are perfectly legal
    /// STABS, so recursion MUST be bounded: on hitting the limit a
    /// `Reference` is left as `Unresolved` instead of overflowing the stack.
    const MAX_RESOLVE_DEPTH: u32 = 16;

    fn resolve_type(&self, t: StabsType) -> StabsType {
        self.resolve_type_depth(t, Self::MAX_RESOLVE_DEPTH)
    }

    fn resolve_type_depth(&self, t: StabsType, depth: u32) -> StabsType {
        let Some(next) = depth.checked_sub(1) else {
            // Depth budget exhausted: leave references unresolved (cycle).
            return match t {
                StabsType::Reference(r) => StabsType::Unresolved(r),
                other => other,
            };
        };
        match t {
            StabsType::Reference(r) => {
                if let Some(resolved) = self.db.get(&r) {
                    self.resolve_type_depth(resolved.clone(), next)
                } else {
                    StabsType::Unresolved(r)
                }
            }
            StabsType::Pointer(inner) => {
                StabsType::Pointer(Box::new(self.resolve_type_depth(*inner, next)))
            }
            StabsType::Array { index, element } => StabsType::Array {
                index: Box::new(self.resolve_type_depth(*index, next)),
                element: Box::new(self.resolve_type_depth(*element, next)),
            },
            StabsType::Struct { name, size, members } => {
                let members = members.into_iter().map(|m| StabsMember {
                    name: m.name,
                    type_ref: m.type_ref,
                    bit_offset: m.bit_offset,
                    bit_size: m.bit_size,
                }).collect();
                StabsType::Struct { name, size, members }
            }
            StabsType::Union { name, size, variants } => {
                let variants = variants.into_iter().map(|m| StabsMember {
                    name: m.name,
                    type_ref: m.type_ref,
                    bit_offset: m.bit_offset,
                    bit_size: m.bit_size,
                }).collect();
                StabsType::Union { name, size, variants }
            }
            StabsType::Function { return_type, params } => StabsType::Function {
                return_type: Box::new(self.resolve_type_depth(*return_type, next)),
                params: params
                    .into_iter()
                    .map(|p| self.resolve_type_depth(p, next))
                    .collect(),
            },
            StabsType::Typedef { name, target } => StabsType::Typedef {
                name,
                target: Box::new(self.resolve_type_depth(*target, next)),
            },
            other => other,
        }
    }

    /// Look up a type in the resolved database.
    #[must_use]
    pub fn lookup(&self, tref: TypeRef) -> Option<&StabsType> {
        self.db.get(&tref)
    }

    /// Return a human-readable summary of what is in the db.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut out = String::new();
        let mut keys: Vec<TypeRef> = self.db.types.keys().copied().collect();
        keys.sort_by_key(|k| (k.file, k.id));
        for k in keys {
            let ty = &self.db.types[&k];
            out.push_str(&format!("  {} => {}\n", k, ty.type_name()));
        }
        out
    }

    /// Count types by variant.
    #[must_use]
    pub fn count_by_kind(&self) -> HashMap<&'static str, usize> {
        let mut m: HashMap<&'static str, usize> = HashMap::new();
        for t in self.db.types.values() {
            let kind = match t {
                StabsType::Void => "Void",
                StabsType::Int { .. } => "Int",
                StabsType::Float { .. } => "Float",
                StabsType::Bool => "Bool",
                StabsType::Char => "Char",
                StabsType::Pointer(_) => "Pointer",
                StabsType::Array { .. } => "Array",
                StabsType::Struct { .. } => "Struct",
                StabsType::Union { .. } => "Union",
                StabsType::Enum { .. } => "Enum",
                StabsType::Function { .. } => "Function",
                StabsType::Typedef { .. } => "Typedef",
                StabsType::Reference(_) => "Reference",
                StabsType::Unresolved(_) => "Unresolved",
            };
            *m.entry(kind).or_insert(0) += 1;
        }
        m
    }
}

impl Default for StabsTypeResolver {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn tref(id: u32) -> TypeRef { TypeRef::local(id) }

    #[test]
    fn test_type_ref_display() {
        let r = TypeRef::new(2, 17);
        assert_eq!(r.to_string(), "(2,17)");
    }

    #[test]
    fn test_parse_int_range_signed_8bit() {
        let t = parse_type_string("r(0,1);-128;127;", 0).unwrap();
        // simplified parser maps signed 1-byte range
        match t {
            StabsType::Int { signed, bytes } => {
                assert_eq!(bytes, 1);
                assert!(signed);
            }
            other => panic!("expected Int, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_signed_int_4byte() {
        let t = parse_type_string("r(0,1);-2147483648;2147483647;", 0).unwrap();
        match t {
            StabsType::Int { signed, bytes } => {
                assert!(signed);
                assert_eq!(bytes, 4);
            }
            _ => panic!("expected Int"),
        }
    }

    #[test]
    fn test_parse_unsigned_int_2byte() {
        let t = parse_type_string("r(0,1);0;65535;", 0).unwrap();
        match t {
            StabsType::Int { signed, bytes } => {
                assert!(!signed);
                assert_eq!(bytes, 2);
            }
            _ => panic!("expected Int"),
        }
    }

    #[test]
    fn test_parse_pointer() {
        let t = parse_type_string("*(0,1)", 0).unwrap();
        match t {
            StabsType::Pointer(inner) => {
                assert!(matches!(*inner, StabsType::Reference(TypeRef { id: 1, .. })));
            }
            _ => panic!("expected Pointer"),
        }
    }

    #[test]
    fn test_parse_void() {
        let t = parse_type_string("v", 0).unwrap();
        assert_eq!(t, StabsType::Void);
    }

    #[test]
    fn test_parse_bool() {
        let t = parse_type_string("b", 0).unwrap();
        assert_eq!(t, StabsType::Bool);
    }

    #[test]
    fn test_parse_char() {
        let t = parse_type_string("c", 0).unwrap();
        assert_eq!(t, StabsType::Char);
    }

    #[test]
    fn test_parse_function_returning_void() {
        let t = parse_type_string("fv", 0).unwrap();
        match t {
            StabsType::Function { return_type, params } => {
                assert_eq!(*return_type, StabsType::Void);
                assert!(params.is_empty());
            }
            _ => panic!("expected Function"),
        }
    }

    #[test]
    fn test_parse_struct_two_members() {
        // s8x:1,0,32;y:1,32,32;
        let t = parse_type_string("s8x:(0,1),0,32;y:(0,1),32,32;", 0).unwrap();
        match t {
            StabsType::Struct { size, members, .. } => {
                assert_eq!(size, 8);
                assert_eq!(members.len(), 2);
                assert_eq!(members[0].name, "x");
                assert_eq!(members[0].bit_offset, 0);
                assert_eq!(members[1].name, "y");
                assert_eq!(members[1].bit_offset, 32);
            }
            _ => panic!("expected Struct"),
        }
    }

    #[test]
    fn test_parse_enum_two_variants() {
        let t = parse_type_string("eA:0,B:1,C:2,;", 0).unwrap();
        match t {
            StabsType::Enum { variants, .. } => {
                assert_eq!(variants.len(), 3);
                assert_eq!(variants[0], ("A".into(), 0));
                assert_eq!(variants[2], ("C".into(), 2));
            }
            _ => panic!("expected Enum"),
        }
    }

    #[test]
    fn test_register_and_resolve_pointer_to_int() {
        let mut resolver = StabsTypeResolver::new();
        // type 1 = i32
        resolver.db.insert(tref(1), StabsType::Int { signed: true, bytes: 4 });
        // type 2 = *type1
        resolver.db.insert(tref(2), StabsType::Pointer(Box::new(StabsType::Reference(tref(1)))));
        resolver.resolve_all();
        match resolver.lookup(tref(2)).unwrap() {
            StabsType::Pointer(inner) => {
                assert!(matches!(**inner, StabsType::Int { signed: true, bytes: 4 }));
            }
            _ => panic!("expected Pointer(Int)"),
        }
    }

    #[test]
    fn test_unresolved_when_missing() {
        let mut resolver = StabsTypeResolver::new();
        resolver.db.insert(tref(5), StabsType::Reference(tref(99)));
        resolver.resolve_all();
        assert!(matches!(resolver.lookup(tref(5)), Some(StabsType::Unresolved(_))));
    }

    #[test]
    fn test_count_by_kind() {
        let mut resolver = StabsTypeResolver::new();
        resolver.db.insert(tref(1), StabsType::Int { signed: true, bytes: 4 });
        resolver.db.insert(tref(2), StabsType::Int { signed: false, bytes: 8 });
        resolver.db.insert(tref(3), StabsType::Void);
        let counts = resolver.count_by_kind();
        assert_eq!(counts["Int"], 2);
        assert_eq!(counts["Void"], 1);
    }

    #[test]
    fn test_type_name_int() {
        assert_eq!(StabsType::Int { signed: true, bytes: 4 }.type_name(), "i32");
        assert_eq!(StabsType::Int { signed: false, bytes: 8 }.type_name(), "u64");
    }

    #[test]
    fn test_type_name_float() {
        assert_eq!(StabsType::Float { bytes: 4 }.type_name(), "f32");
        assert_eq!(StabsType::Float { bytes: 8 }.type_name(), "f64");
    }

    #[test]
    fn test_parse_array_descriptor() {
        let t = parse_type_string("ar(0,1);0;9;(0,2)", 0).unwrap();
        assert!(matches!(t, StabsType::Array { .. }));
    }

    #[test]
    fn test_type_db_len() {
        let mut db = TypeDb::new();
        assert!(db.is_empty());
        db.insert(tref(1), StabsType::Void);
        assert_eq!(db.len(), 1);
    }

    #[test]
    fn test_stabs_member_creation() {
        let m = StabsMember::new("field", TypeRef::local(3), 64, 32);
        assert_eq!(m.name, "field");
        assert_eq!(m.bit_offset, 64);
        assert_eq!(m.bit_size, 32);
    }
}
