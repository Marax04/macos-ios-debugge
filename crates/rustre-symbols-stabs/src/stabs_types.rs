//! Complete STABS type system.
//!
//! Parses all STABS type descriptors and builds a [`StabsTypeDb`] for
//! cross-referencing types by `(file_index, type_number)`.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// TypeRef: cross-file type reference
// ─────────────────────────────────────────────────────────────────────────────

/// A cross-file type reference used in STABS `(file, type_num)` syntax.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TypeRef {
    /// File index (0 = current file, N = cross-file reference).
    pub file: u16,
    /// Type number within the file.
    pub num: u32,
}

impl TypeRef {
    /// Build a same-file reference (`file = 0`).
    #[must_use] 
    pub const fn local(num: u32) -> Self {
        Self { file: 0, num }
    }
    /// Build a cross-file `(file,num)` reference.
    #[must_use] 
    pub const fn cross(file: u16, num: u32) -> Self {
        Self { file, num }
    }
}

impl fmt::Display for TypeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.file == 0 {
            write!(f, "{}", self.num)
        } else {
            write!(f, "({},{})", self.file, self.num)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StabsBaseType
// ─────────────────────────────────────────────────────────────────────────────

/// A primitive / built-in STABS type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StabsBaseType {
    /// Integer type.
    Int {
        /// Width in bits.
        bits: u8,
        /// Whether the type is signed.
        signed: bool,
    },
    /// IEEE floating-point type.
    Float {
        /// Width in bits.
        bits: u8,
    },
    /// `char`.
    Char,
    /// `wchar_t`.
    WChar,
    /// `_Bool` / boolean.
    Bool,
    /// `void`.
    Void,
    /// `void*`.
    VoidPtr,
    /// `long double`.
    LongDouble {
        /// Width in bits (typically 80 or 96).
        bits: u8,
    },
    /// GNU complex type (e.g. `_Complex float`).
    Complex {
        /// Width in bits of each component.
        bits: u8,
    },
}

impl StabsBaseType {
    /// Canonical C name.
    #[must_use] 
    pub fn c_name(&self) -> String {
        match self {
            Self::Int {
                bits: 32,
                signed: true,
            } => "int".into(),
            Self::Int {
                bits: 32,
                signed: false,
            } => "unsigned int".into(),
            Self::Int {
                bits: 64,
                signed: true,
            } => "long long".into(),
            Self::Int {
                bits: 64,
                signed: false,
            } => "unsigned long long".into(),
            Self::Int { bits, signed } => {
                format!("{}int{}_t", if *signed { "" } else { "u" }, bits)
            }
            Self::Float { bits: 32 } => "float".into(),
            Self::Float { bits: 64 } => "double".into(),
            Self::Float { bits } => format!("float{bits}"),
            Self::Char => "char".into(),
            Self::WChar => "wchar_t".into(),
            Self::Bool => "_Bool".into(),
            Self::Void => "void".into(),
            Self::VoidPtr => "void*".into(),
            Self::LongDouble { .. } => "long double".into(),
            Self::Complex { bits } => format!("_Complex float{bits}"),
        }
    }

    /// Byte size (0 = architecture-dependent).
    #[must_use] 
    pub const fn byte_size(&self) -> usize {
        match self {
            Self::Int { bits, .. }
            | Self::Float { bits }
            | Self::LongDouble { bits }
            | Self::Complex { bits } => (*bits as usize).div_ceil(8),
            Self::Char | Self::Bool => 1,
            Self::WChar => 4,
            Self::Void => 0,
            Self::VoidPtr => 8,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StabsArrayType
// ─────────────────────────────────────────────────────────────────────────────

/// STABS array type descriptor (e.g. `ar1;0;9;16` = int[10]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabsArrayType {
    /// Index type (usually int).
    pub index_type: TypeRef,
    /// Lower bound.
    pub lower: i64,
    /// Upper bound.
    pub upper: i64,
    /// Element type.
    pub element_type: TypeRef,
}

impl StabsArrayType {
    /// Number of elements (`upper - lower + 1`, 0 if bounds are inverted).
    #[must_use]
    pub fn count(&self) -> usize {
        if self.upper < self.lower {
            0
        } else {
            self.upper
                .saturating_sub(self.lower)
                .saturating_add(1)
                .try_into()
                .unwrap_or(usize::MAX)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StabsStructField / StabsCompositeType
// ─────────────────────────────────────────────────────────────────────────────

/// A field in a struct or union.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabsStructField {
    /// Field name.
    pub name: String,
    /// Field type reference.
    pub type_ref: TypeRef,
    /// Bit offset from the start of the struct.
    pub bit_offset: u32,
    /// Bit size (0 = full type size).
    pub bit_size: u32,
}

/// An enum variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabsEnumVariant {
    /// Enumerator name.
    pub name: String,
    /// Enumerator value.
    pub value: i64,
}

/// A struct, union, or enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StabsCompositeType {
    /// A `struct` type.
    Struct {
        /// Struct tag name (may be empty for anonymous structs).
        name: String,
        /// Total size in bytes.
        byte_size: u32,
        /// Member fields in declaration order.
        fields: Vec<StabsStructField>,
    },
    /// A `union` type.
    Union {
        /// Union tag name (may be empty for anonymous unions).
        name: String,
        /// Total size in bytes.
        byte_size: u32,
        /// Member fields (all at offset 0).
        fields: Vec<StabsStructField>,
    },
    /// An `enum` type.
    Enum {
        /// Enum tag name (may be empty for anonymous enums).
        name: String,
        /// Enumerators.
        variants: Vec<StabsEnumVariant>,
    },
}

impl StabsCompositeType {
    /// Tag name of the struct/union/enum.
    #[must_use] 
    pub fn name(&self) -> &str {
        match self {
            Self::Struct { name, .. } | Self::Union { name, .. } | Self::Enum { name, .. } => name,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StabsFunctionType
// ─────────────────────────────────────────────────────────────────────────────

/// A STABS function type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabsFunctionType {
    /// Return type reference.
    pub return_type: TypeRef,
    /// Parameter type references.
    pub param_types: Vec<TypeRef>,
    /// Whether the function takes `...` variadic arguments.
    pub is_variadic: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// StabsPointerType / StabsQualifiedType
// ─────────────────────────────────────────────────────────────────────────────

/// Pointer type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabsPointerType {
    /// Pointed-to type.
    pub pointee: TypeRef,
}

/// Reference type (C++ `&`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabsReferenceType {
    /// Referenced type.
    pub pointee: TypeRef,
}

/// Type qualifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeQualifier {
    /// `const`.
    Const,
    /// `volatile`.
    Volatile,
    /// `restrict`.
    Restrict,
}

/// Qualified type (const/volatile).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabsQualifiedType {
    /// The qualifier applied.
    pub qualifier: TypeQualifier,
    /// The qualified (inner) type.
    pub inner: TypeRef,
}

// ─────────────────────────────────────────────────────────────────────────────
// StabsType (unified type variant)
// ─────────────────────────────────────────────────────────────────────────────

/// Any STABS type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StabsType {
    /// Primitive / built-in type.
    Base(StabsBaseType),
    /// Pointer type.
    Pointer(StabsPointerType),
    /// C++ reference type.
    Reference(StabsReferenceType),
    /// Array type.
    Array(StabsArrayType),
    /// Function type.
    Function(StabsFunctionType),
    /// Struct, union, or enum.
    Composite(StabsCompositeType),
    /// Typedef alias.
    Typedef {
        /// Typedef name.
        name: String,
        /// Aliased type.
        inner: TypeRef,
    },
    /// Const/volatile-qualified type.
    Qualified(StabsQualifiedType),
    /// Self-reference (type N is the same as another type M).
    Alias(TypeRef),
    /// Incomplete / forward-declared type.
    Forward {
        /// Tag name of the forward-declared type.
        name: String,
    },
}

impl StabsType {
    /// Human-readable kind string.
    #[must_use] 
    pub const fn kind_str(&self) -> &'static str {
        match self {
            Self::Base(_) => "base",
            Self::Pointer(_) => "pointer",
            Self::Reference(_) => "reference",
            Self::Array(_) => "array",
            Self::Function(_) => "function",
            Self::Composite(c) => match c {
                StabsCompositeType::Struct { .. } => "struct",
                StabsCompositeType::Union { .. } => "union",
                StabsCompositeType::Enum { .. } => "enum",
            },
            Self::Typedef { .. } => "typedef",
            Self::Qualified(_) => "qualified",
            Self::Alias(_) => "alias",
            Self::Forward { .. } => "forward",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StabsTypeParser
// ─────────────────────────────────────────────────────────────────────────────

/// Parses STABS type descriptor strings into [`StabsType`] values.
pub struct StabsTypeParser;

impl StabsTypeParser {
    /// Parse a STABS type string at the given `offset` inside `s`.
    /// Returns `(type, chars_consumed)`.
    ///
    /// # Errors
    /// Returns a `String` error if the type descriptor is unrecognized or malformed.
    pub fn parse(s: &str) -> Result<(StabsType, usize), String> {
        if s.is_empty() {
            return Err("empty type string".into());
        }
        let bytes = s.as_bytes();
        match bytes[0] {
            b'(' => Self::parse_cross_ref(s),
            b'*' => {
                let (inner, n) = Self::parse_type_ref(&s[1..])?;
                Ok((
                    StabsType::Pointer(StabsPointerType { pointee: inner }),
                    1 + n,
                ))
            }
            b'&' => {
                let (inner, n) = Self::parse_type_ref(&s[1..])?;
                Ok((
                    StabsType::Reference(StabsReferenceType { pointee: inner }),
                    1 + n,
                ))
            }
            b'a' if bytes.get(1) == Some(&b'r') => Self::parse_array(&s[1..]),
            b'f' => {
                let (ret, n) = Self::parse_type_ref(&s[1..])?;
                Ok((
                    StabsType::Function(StabsFunctionType {
                        return_type: ret,
                        param_types: Vec::new(),
                        is_variadic: false,
                    }),
                    1 + n,
                ))
            }
            b's' => Self::parse_struct(&s[1..], false),
            b'u' => Self::parse_struct(&s[1..], true),
            b'e' => Self::parse_enum(&s[1..]),
            b't' => {
                let (inner, n) = Self::parse_type_ref(&s[1..])?;
                Ok((
                    StabsType::Typedef {
                        name: String::new(),
                        inner,
                    },
                    1 + n,
                ))
            }
            b'k' => {
                let (inner, n) = Self::parse_type_ref(&s[1..])?;
                Ok((
                    StabsType::Qualified(StabsQualifiedType {
                        qualifier: TypeQualifier::Const,
                        inner,
                    }),
                    1 + n,
                ))
            }
            b'B' => {
                let (inner, n) = Self::parse_type_ref(&s[1..])?;
                Ok((
                    StabsType::Qualified(StabsQualifiedType {
                        qualifier: TypeQualifier::Volatile,
                        inner,
                    }),
                    1 + n,
                ))
            }
            d if d.is_ascii_digit() || d == b'-' => {
                // Built-in type number (negative = GNU built-in, positive = alias)
                let (num, n) = Self::parse_int(s)?;
                if num < 0 {
                    let base = Self::gnu_builtin(num)?;
                    Ok((StabsType::Base(base), n))
                } else {
                    Ok((StabsType::Alias(TypeRef::local(u32::try_from(num).unwrap_or(0))), n))
                }
            }
            other => Err(format!("unknown type descriptor: {:?}", other as char)),
        }
    }

    /// Parse a `(file,num)` cross reference, returning the inner `TypeRef`.
    fn parse_cross_ref(s: &str) -> Result<(StabsType, usize), String> {
        // Format: (file,num)rest
        let close = s.find(')').ok_or("unclosed cross-ref")?;
        let inner = &s[1..close];
        let comma = inner.find(',').ok_or("no comma in cross-ref")?;
        let file: u16 = inner[..comma]
            .parse()
            .map_err(|e| format!("cross-ref file: {e}"))?;
        let num: u32 = inner[comma + 1..]
            .parse()
            .map_err(|e| format!("cross-ref num: {e}"))?;
        Ok((StabsType::Alias(TypeRef::cross(file, num)), close + 1))
    }

    /// Parse a type reference (either `(f,n)` or a bare decimal).
    fn parse_type_ref(s: &str) -> Result<(TypeRef, usize), String> {
        if s.starts_with('(') {
            let close = s.find(')').ok_or("unclosed cross-ref in type-ref")?;
            let inner = &s[1..close];
            let comma = inner.find(',').ok_or("no comma in cross-ref")?;
            let file: u16 = inner[..comma].parse().map_err(|e| format!("{e}"))?;
            let num: u32 = inner[comma + 1..].parse().map_err(|e| format!("{e}"))?;
            Ok((TypeRef::cross(file, num), close + 1))
        } else {
            let (n, consumed) = Self::parse_int(s)?;
            Ok((TypeRef::local(u32::try_from(n.unsigned_abs()).unwrap_or(0)), consumed))
        }
    }

    fn parse_int(s: &str) -> Result<(i64, usize), String> {
        let neg = s.starts_with('-');
        let digits: String = s
            .chars()
            .skip(usize::from(neg))
            .take_while(char::is_ascii_digit)
            .collect();
        if digits.is_empty() {
            return Err(format!("expected integer at {s:?}"));
        }
        let n: i64 = digits.parse().map_err(|e| format!("{e}"))?;
        let consumed = digits.len() + usize::from(neg);
        Ok((if neg { -n } else { n }, consumed))
    }

    fn parse_array(s: &str) -> Result<(StabsType, usize), String> {
        // Format: r<index_type>;<lower>;<upper>;<element_type>
        if !s.starts_with('r') {
            return Err("array descriptor must start with 'r'".into());
        }
        let (idx_ref, n1) = Self::parse_type_ref(&s[1..])?;
        let rest = &s[1 + n1..];
        if !rest.starts_with(';') {
            return Err("expected ; after index type".into());
        }
        let (lower, n2) = Self::parse_int(&rest[1..])?;
        let rest2 = &rest[1 + n2..];
        if !rest2.starts_with(';') {
            return Err("expected ; after lower bound".into());
        }
        let (upper, n3) = Self::parse_int(&rest2[1..])?;
        let rest3 = &rest2[1 + n3..];
        if !rest3.starts_with(';') {
            return Err("expected ; after upper bound".into());
        }
        let (elem, n4) = Self::parse_type_ref(&rest3[1..])?;
        Ok((
            StabsType::Array(StabsArrayType {
                index_type: idx_ref,
                lower,
                upper,
                element_type: elem,
            }),
            2 + n1 + 1 + n2 + 1 + n3 + 1 + n4,
        ))
    }

    fn parse_struct(s: &str, is_union: bool) -> Result<(StabsType, usize), String> {
        // Format: <byte_size>[<name>:<type_ref>,<bit_off>,<bit_size>;]*;
        let (byte_size, n) = Self::parse_int(s)?;
        let rest = &s[n..];
        let mut fields = Vec::new();
        let mut pos = 0;
        // Find terminal ';'
        while pos < rest.len() {
            if rest[pos..].starts_with(';') {
                pos += 1;
                break;
            }
            // Parse: name:type_ref,bit_off,bit_size;
            let colon = rest[pos..].find(':').map(|i| pos + i);
            if colon.is_none() {
                break;
            }
            let colon_idx = colon.unwrap();
            let name = rest[pos..colon_idx].to_string();
            let after_colon = &rest[colon_idx + 1..];
            let (tref, t_n) = Self::parse_type_ref(after_colon)?;
            let after_type = &after_colon[t_n..];
            // ,bit_off,bit_size;
            let commas: Vec<usize> = after_type
                .char_indices()
                .filter(|(_, c)| *c == ',')
                .map(|(i, _)| i)
                .take(2)
                .collect();
            let (bit_off, bit_size) = if commas.len() >= 2 {
                let o: u32 = after_type[commas[0] + 1..commas[1]].parse().unwrap_or(0);
                let semi = after_type[commas[1] + 1..].find(';').unwrap_or(0);
                let sz: u32 = after_type[commas[1] + 1..commas[1] + 1 + semi]
                    .parse()
                    .unwrap_or(0);
                (o, sz)
            } else {
                (0, 0)
            };
            fields.push(StabsStructField {
                name,
                type_ref: tref,
                bit_offset: bit_off,
                bit_size,
            });
            // Advance past the field including the trailing ';'
            let field_end =
                colon_idx - pos + 1 + t_n + after_type.find(';').map_or(0, |i| i + 1);
            pos += field_end;
        }
        let total = n + pos;
        if is_union {
            Ok((
                StabsType::Composite(StabsCompositeType::Union {
                    name: String::new(),
                    byte_size: u32::try_from(byte_size).unwrap_or(0),
                    fields,
                }),
                total,
            ))
        } else {
            Ok((
                StabsType::Composite(StabsCompositeType::Struct {
                    name: String::new(),
                    byte_size: u32::try_from(byte_size).unwrap_or(0),
                    fields,
                }),
                total,
            ))
        }
    }

    fn parse_enum(s: &str) -> Result<(StabsType, usize), String> {
        // Format: <name>:<value>,<name>:<value>,...;
        let mut variants = Vec::new();
        let mut pos = 0;
        while pos < s.len() {
            if s[pos..].starts_with(';') {
                pos += 1;
                break;
            }
            let colon = s[pos..].find(':').map(|i| pos + i);
            if colon.is_none() {
                break;
            }
            let ci = colon.unwrap();
            let name = s[pos..ci].to_string();
            let (val, vn) = Self::parse_int(&s[ci + 1..])?;
            variants.push(StabsEnumVariant { name, value: val });
            pos = ci + 1 + vn;
            if s[pos..].starts_with(',') {
                pos += 1;
            }
        }
        Ok((
            StabsType::Composite(StabsCompositeType::Enum {
                name: String::new(),
                variants,
            }),
            pos,
        ))
    }

    /// Map a GNU/GDB negative built-in type number to a base type.
    ///
    /// The assignment is fixed by the STABS document ("Negative Type Numbers",
    /// sourceware.org/gdb/onlinedocs/stabs.html) and is NOT a simple ordering —
    /// e.g. -11 is `void` and -16 is `boolean`. `long`/`unsigned long` are
    /// target-word-sized; this crate targets 64-bit hosts, so they are 64 bits.
    /// Numbers with no representable `StabsBaseType` (stringptr, complex)
    /// return `Err` rather than being silently mistyped.
    fn gnu_builtin(n: i64) -> Result<StabsBaseType, String> {
        const fn int(bits: u8, signed: bool) -> StabsBaseType {
            StabsBaseType::Int { bits, signed }
        }
        Ok(match n {
            -1 => int(32, true),                        // int
            -2 => StabsBaseType::Char,                  // char
            -3 => int(16, true),                        // short
            -4 => int(64, true),                        // long (target word)
            -5 => int(8, false),                        // unsigned char
            -6 => int(8, true),                         // signed char
            -7 => int(16, false),                       // unsigned short
            -8 => int(32, false),                       // unsigned int
            -9 => int(32, false),                       // unsigned
            -10 => int(64, false),                      // unsigned long
            -11 => StabsBaseType::Void,                 // void
            -12 => StabsBaseType::Float { bits: 32 },   // float
            -13 => StabsBaseType::Float { bits: 64 },   // double
            -14 => StabsBaseType::LongDouble { bits: 96 }, // long double
            -15 => int(32, true),                       // integer
            -16 => StabsBaseType::Bool,                 // boolean
            -17 => StabsBaseType::Float { bits: 32 },   // short real
            -18 => StabsBaseType::Float { bits: 64 },   // real
            -20 => int(8, false),                       // character
            -21 => int(8, false),                       // logical*1
            -22 => int(16, false),                      // logical*2
            -23 => int(32, false),                      // logical*4
            -24 => int(32, false),                      // logical
            -27 => int(8, true),                        // integer*1
            -28 => int(16, true),                       // integer*2
            -29 => int(32, true),                       // integer*4
            -25 => StabsBaseType::Complex { bits: 32 },  // complex (float pair)
            -26 => StabsBaseType::Complex { bits: 64 },  // complex (double pair)
            -30 => StabsBaseType::WChar,                // wchar
            -31 => int(64, true),                       // long long
            -32 => int(64, false),                      // unsigned long long
            -33 => int(64, false),                      // logical*8
            -34 => int(64, true),                       // integer*8
            _ => return Err(format!("unknown GNU built-in type: {n}")),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StabsTypeDb
// ─────────────────────────────────────────────────────────────────────────────

/// Database mapping `TypeRef → StabsType`.
#[derive(Debug, Default)]
pub struct StabsTypeDb {
    types: HashMap<TypeRef, StabsType>,
    /// Named types (typedefs / structs / enums) by name.
    named: HashMap<String, TypeRef>,
}

impl StabsTypeDb {
    /// Create an empty database.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a type, also indexing it by name if it is a named typedef or composite.
    pub fn insert(&mut self, r: TypeRef, t: StabsType) {
        if let StabsType::Typedef { ref name, .. } = t
            && !name.is_empty() {
                self.named.insert(name.clone(), r);
            }
        if let StabsType::Composite(ref c) = t {
            let n = c.name().to_string();
            if !n.is_empty() {
                self.named.insert(n, r);
            }
        }
        self.types.insert(r, t);
    }

    /// Look up a type by reference.
    #[must_use] 
    pub fn get(&self, r: &TypeRef) -> Option<&StabsType> {
        self.types.get(r)
    }

    /// Look up a named typedef/struct/enum by name.
    #[must_use] 
    pub fn get_by_name(&self, name: &str) -> Option<&StabsType> {
        self.named.get(name).and_then(|r| self.types.get(r))
    }

    #[must_use] 
    /// Follow an alias chain to the first non-alias type.
    ///
    /// Iterative and bounded: `1=2` / `2=1` is a legal (if degenerate) pair of
    /// STABS descriptors and would make a recursive implementation overflow the
    /// stack. On hitting the budget the last node reached is returned, so
    /// callers still get a type rather than `None`.
    pub fn resolve(&self, r: &TypeRef) -> Option<&StabsType> {
        const MAX_ALIAS_HOPS: u32 = 64;
        let mut cur = self.types.get(r)?;
        for _ in 0..MAX_ALIAS_HOPS {
            match cur {
                StabsType::Alias(inner) => match self.types.get(inner) {
                    Some(next) => cur = next,
                    None => return Some(cur),
                },
                other => return Some(other),
            }
        }
        Some(cur)
    }

    /// Number of types in the database.
    #[must_use] 
    pub fn len(&self) -> usize {
        self.types.len()
    }
    /// Whether the database holds no types.
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// All type references in the database.
    pub fn refs(&self) -> impl Iterator<Item = &TypeRef> {
        self.types.keys()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // --- TypeRef ---

    #[test]
    fn type_ref_local_display() {
        assert_eq!(format!("{}", TypeRef::local(5)), "5");
    }

    #[test]
    fn type_ref_cross_display() {
        assert_eq!(format!("{}", TypeRef::cross(2, 7)), "(2,7)");
    }

    // --- StabsBaseType ---

    #[test]
    fn base_type_int32_c_name() {
        assert_eq!(
            StabsBaseType::Int {
                bits: 32,
                signed: true
            }
            .c_name(),
            "int"
        );
    }

    #[test]
    fn base_type_float32_c_name() {
        assert_eq!(StabsBaseType::Float { bits: 32 }.c_name(), "float");
    }

    #[test]
    fn base_type_byte_size() {
        assert_eq!(
            StabsBaseType::Int {
                bits: 64,
                signed: true
            }
            .byte_size(),
            8
        );
        assert_eq!(StabsBaseType::Float { bits: 32 }.byte_size(), 4);
        assert_eq!(StabsBaseType::Char.byte_size(), 1);
    }

    #[test]
    fn base_type_void_size_zero() {
        assert_eq!(StabsBaseType::Void.byte_size(), 0);
    }

    // --- StabsArrayType ---

    #[test]
    fn array_count() {
        let a = StabsArrayType {
            index_type: TypeRef::local(1),
            lower: 0,
            upper: 9,
            element_type: TypeRef::local(16),
        };
        assert_eq!(a.count(), 10);
    }

    #[test]
    fn array_count_zero_when_inverted() {
        let a = StabsArrayType {
            index_type: TypeRef::local(1),
            lower: 5,
            upper: 3,
            element_type: TypeRef::local(16),
        };
        assert_eq!(a.count(), 0);
    }

    // --- StabsTypeParser ---

    #[test]
    fn parse_gnu_builtin_int() {
        let (t, _) = StabsTypeParser::parse("-1").unwrap();
        assert!(matches!(
            t,
            StabsType::Base(StabsBaseType::Int {
                bits: 32,
                signed: true
            })
        ));
    }

    #[test]
    fn parse_gnu_builtin_float() {
        let (t, _) = StabsTypeParser::parse("-12").unwrap();
        assert!(matches!(
            t,
            StabsType::Base(StabsBaseType::Float { bits: 32 })
        ));
    }

    #[test]
    fn parse_gnu_builtin_bool() {
        let (t, _) = StabsTypeParser::parse("-16").unwrap();
        assert!(matches!(t, StabsType::Base(StabsBaseType::Bool)));
    }

    #[test]
    fn parse_pointer_to_builtin() {
        let (t, _) = StabsTypeParser::parse("*-1").unwrap();
        matches!(t, StabsType::Pointer(_));
    }

    #[test]
    fn parse_alias() {
        let (t, n) = StabsTypeParser::parse("5").unwrap();
        assert_eq!(n, 1);
        assert!(matches!(t, StabsType::Alias(TypeRef { file: 0, num: 5 })));
    }

    #[test]
    fn parse_cross_ref() {
        let (t, n) = StabsTypeParser::parse("(1,3)").unwrap();
        assert_eq!(n, 5);
        assert!(matches!(t, StabsType::Alias(TypeRef { file: 1, num: 3 })));
    }

    #[test]
    fn parse_function_type() {
        let (t, _) = StabsTypeParser::parse("f-1").unwrap();
        assert!(matches!(t, StabsType::Function(_)));
    }

    #[test]
    fn parse_const_qualified() {
        let (t, _) = StabsTypeParser::parse("k-1").unwrap();
        if let StabsType::Qualified(q) = t {
            assert_eq!(q.qualifier, TypeQualifier::Const);
        } else {
            panic!("expected qualified");
        }
    }

    #[test]
    fn parse_empty_fails() {
        assert!(StabsTypeParser::parse("").is_err());
    }

    #[test]
    fn parse_unknown_descriptor_fails() {
        assert!(StabsTypeParser::parse("Z").is_err());
    }

    // --- StabsTypeDb ---

    #[test]
    fn type_db_insert_get() {
        let mut db = StabsTypeDb::new();
        let r = TypeRef::local(1);
        db.insert(
            r,
            StabsType::Base(StabsBaseType::Int {
                bits: 32,
                signed: true,
            }),
        );
        assert!(db.get(&r).is_some());
    }

    #[test]
    fn type_db_len() {
        let mut db = StabsTypeDb::new();
        db.insert(TypeRef::local(1), StabsType::Base(StabsBaseType::Char));
        db.insert(TypeRef::local(2), StabsType::Base(StabsBaseType::Void));
        assert_eq!(db.len(), 2);
    }

    #[test]
    fn type_db_is_empty() {
        let db = StabsTypeDb::new();
        assert!(db.is_empty());
    }

    #[test]
    fn type_db_resolve_alias() {
        let mut db = StabsTypeDb::new();
        db.insert(
            TypeRef::local(1),
            StabsType::Base(StabsBaseType::Int {
                bits: 32,
                signed: true,
            }),
        );
        db.insert(TypeRef::local(2), StabsType::Alias(TypeRef::local(1)));
        let resolved = db.resolve(&TypeRef::local(2)).unwrap();
        assert!(matches!(
            resolved,
            StabsType::Base(StabsBaseType::Int { .. })
        ));
    }

    #[test]
    fn type_db_missing_returns_none() {
        let db = StabsTypeDb::new();
        assert!(db.get(&TypeRef::local(99)).is_none());
    }

    #[test]
    fn composite_name() {
        let c = StabsCompositeType::Struct {
            name: "Point".into(),
            byte_size: 8,
            fields: vec![],
        };
        assert_eq!(c.name(), "Point");
    }

    #[test]
    fn type_kind_str() {
        assert_eq!(StabsType::Base(StabsBaseType::Char).kind_str(), "base");
        assert_eq!(
            StabsType::Forward { name: "foo".into() }.kind_str(),
            "forward"
        );
    }

    #[test]
    fn gnu_builtin_unknown_errors() {
        assert!(StabsTypeParser::gnu_builtin(-99).is_err());
    }

    #[test]
    fn gnu_builtin_void() {
        let t = StabsTypeParser::gnu_builtin(-11).unwrap();
        assert!(matches!(t, StabsBaseType::Void));
    }
}
