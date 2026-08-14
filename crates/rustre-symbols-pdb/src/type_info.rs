//! `type_info` — `TPI` (Type Information) stream parser.
//!
//! Parses the `CodeView` type stream (~50 leaf types) into a `TypeDatabase`.
//! Supports: pointers, arrays, structs/classes, unions, enums, procedures,
//! member functions, field lists, and all primitive type codes.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::stream_reader::StreamReader;
use crate::{PdbError, Result};

// ── Leaf type codes ───────────────────────────────────────────────────────────

/// Leaf code for a pointer type record.
pub const LF_POINTER: u16 = 0x1002;
/// Leaf code for a procedure (function) type record.
pub const LF_PROCEDURE: u16 = 0x1008;
/// Leaf code for a member function type record.
pub const LF_MFUNCTION: u16 = 0x1009;
/// Leaf code for an argument list record.
pub const LF_ARGLIST: u16 = 0x1201;
/// Leaf code for a field list record.
pub const LF_FIELDLIST: u16 = 0x1203;
/// Leaf code for an array type record.
pub const LF_ARRAY: u16 = 0x1503;
/// Leaf code for a class type record.
pub const LF_CLASS: u16 = 0x1504;
/// Leaf code for a struct type record.
pub const LF_STRUCTURE: u16 = 0x1505;
/// Leaf code for a union type record.
pub const LF_UNION: u16 = 0x1506;
/// Leaf code for an enum type record.
pub const LF_ENUM: u16 = 0x1507;
/// Leaf code for a virtual table shape record.
pub const LF_VTSHAPE: u16 = 0x000A;
// Field list sub-record types.
/// Field list sub-record: data member.
pub const LF_MEMBER: u16 = 0x150D;
/// Field list sub-record: static data member.
pub const LF_STMEMBER: u16 = 0x150E;
/// Field list sub-record: method.
pub const LF_METHOD: u16 = 0x150F;
/// Field list sub-record: nested type.
pub const LF_NESTTYPE: u16 = 0x1510;
/// Field list sub-record: direct base class.
pub const LF_BCLASS: u16 = 0x1400;
/// Field list sub-record: virtual base class.
pub const LF_VBCLASS: u16 = 0x1401;
/// Field list sub-record: enumerator value.
pub const LF_ENUMERATE: u16 = 0x1502;

// ── Access control ────────────────────────────────────────────────────────────

/// C++ access specifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Access {
    /// `private` access
    Private = 1,
    /// `protected` access
    Protected = 2,
    /// `public` access
    Public = 3,
}

impl Access {
    const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Private,
            2 => Self::Protected,
            _ => Self::Public,
        }
    }
}

/// Virtual function kind for method records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MethodKind {
    /// Ordinary non-virtual method
    Vanilla,
    /// Virtual method overriding a base declaration
    Virtual,
    /// Static method
    Static,
    /// Friend function
    Friend,
    /// Virtual method introduced by this class
    IntroducingVirtual,
    /// Pure virtual method
    PureVirtual,
    /// Pure virtual method introduced by this class
    PureIntroducingVirtual,
}

impl MethodKind {
    /// Decode the method kind from the `CV_methodprop` bits of an attribute byte.
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v & 0x1C {
            0x04 => Self::Virtual,
            0x08 => Self::Static,
            0x0C => Self::Friend,
            0x10 => Self::IntroducingVirtual,
            0x14 => Self::PureVirtual,
            0x18 => Self::PureIntroducingVirtual,
            _ => Self::Vanilla,
        }
    }
}

// ── Field list fields ─────────────────────────────────────────────────────────

/// One field inside a field list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CvField {
    /// A data member (`LF_MEMBER`).
    Member {
        /// Access specifier
        access: Access,
        /// Type index of the member's type
        type_idx: u32,
        /// Byte offset of the member within the containing type
        offset: i64,
        /// Member name
        name: String,
    },
    /// A static data member (`LF_STMEMBER`).
    StaticMember {
        /// Access specifier
        access: Access,
        /// Type index of the member's type
        type_idx: u32,
        /// Member name
        name: String,
    },
    /// A virtual base class (`LF_VBCLASS`).
    VirtualBaseClass {
        /// Access specifier
        access: Access,
        /// Type index of the virtual base class
        base_type: u32,
        /// Type index of the virtual base pointer
        vbptr_type: u32,
        /// Offset of the virtual base pointer
        vbptr_offset: i64,
        /// Index into the virtual base displacement table
        vtable_idx: i64,
    },
    /// A method (`LF_METHOD` / `LF_ONEMETHOD`).
    Method {
        /// Access specifier
        access: Access,
        /// Virtual/static/vanilla method kind
        kind: MethodKind,
        /// Type index of the method's `MemberFunction` type
        type_idx: u32,
        /// Vtable offset for introducing-virtual methods
        vtable_offset: Option<i32>,
        /// Method name
        name: String,
    },
    /// A nested type declaration (`LF_NESTTYPE`).
    NestedType {
        /// Type index of the nested type
        type_idx: u32,
        /// Nested type name
        name: String,
    },
    /// An enumerator value (`LF_ENUMERATE`).
    Enumerate {
        /// Access specifier
        access: Access,
        /// Enumerator value
        value: i64,
        /// Enumerator name
        name: String,
    },
    /// A direct base class (`LF_BCLASS`).
    BaseClass {
        /// Access specifier
        access: Access,
        /// Type index of the base class
        type_idx: u32,
        /// Byte offset of the base within the derived class
        offset: i64,
    },
}

// ── CvType ────────────────────────────────────────────────────────────────────

/// A decoded `CodeView` type record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CvType {
    /// A built-in primitive type (int, float, char, ...).
    Primitive {
        /// Primitive type code
        code: u32,
        /// C name of the primitive
        name: &'static str,
        /// Size in bytes
        size: u8,
    },
    /// A pointer type (`LF_POINTER`).
    Pointer {
        /// Type index of the pointed-to type
        pointee: u32,
        /// Pointer kind bits from the attribute dword
        pointer_kind: u8,
        /// Pointer size in bytes (4 or 8)
        size: u8,
    },
    /// An array type (`LF_ARRAY`).
    Array {
        /// Type index of the element type
        element_type: u32,
        /// Type index of the indexing type
        index_type: u32,
        /// Total array size in bytes
        size: i64,
        /// Array type name (often empty)
        name: String,
    },
    /// A struct or class type (`LF_STRUCTURE` / `LF_CLASS`).
    Struct {
        /// Number of members
        count: u16,
        /// Type index of the field list
        field_list: u32,
        /// Size in bytes
        size: i64,
        /// Type name
        name: String,
        /// True if declared with `class` rather than `struct`
        is_class: bool,
    },
    /// A union type (`LF_UNION`).
    Union {
        /// Number of members
        count: u16,
        /// Type index of the field list
        field_list: u32,
        /// Size in bytes
        size: i64,
        /// Type name
        name: String,
    },
    /// An enum type (`LF_ENUM`).
    Enum {
        /// Number of enumerators
        count: u16,
        /// Type index of the underlying integer type
        underlying_type: u32,
        /// Type index of the field list holding the enumerators
        field_list: u32,
        /// Type name
        name: String,
    },
    /// A function type (`LF_PROCEDURE`).
    Procedure {
        /// Type index of the return type
        return_type: u32,
        /// Calling convention code
        call_conv: u8,
        /// Number of parameters
        arg_count: u16,
        /// Type index of the argument list
        arg_list: u32,
    },
    /// A member function type (`LF_MFUNCTION`).
    MemberFunction {
        /// Type index of the return type
        return_type: u32,
        /// Type index of the containing class
        class_type: u32,
        /// Type index of the `this` pointer type
        this_type: u32,
        /// Calling convention code
        call_conv: u8,
        /// Number of parameters
        arg_count: u16,
        /// Type index of the argument list
        arg_list: u32,
    },
    /// A field list record (`LF_FIELDLIST`).
    FieldList {
        /// The decoded fields
        fields: Vec<CvField>,
    },
    /// An argument list record (`LF_ARGLIST`).
    ArgList {
        /// Type indices of the arguments
        arg_types: Vec<u32>,
    },
    /// A virtual table shape record (`LF_VTSHAPE`).
    VtShape {
        /// Number of vtable entries
        count: u16,
    },
    /// An unrecognized leaf type, stored by its leaf code.
    Unknown(u16),
}

impl CvType {
    /// Return a C-like type string for simple cases.
    #[must_use]
    pub fn to_c_string(&self, db: &TypeDatabase) -> String {
        match self {
            Self::Primitive { name, .. } => (*name).to_string(),
            Self::Pointer { pointee, .. } => {
                let inner = db
                    .get(*pointee)
                    .map_or_else(|| format!("type_{pointee:#x}"), |t| t.to_c_string(db));
                format!("{inner} *")
            }
            Self::Array {
                element_type, size, ..
            } => {
                let elem = db
                    .get(*element_type)
                    .map_or_else(|| format!("type_{element_type:#x}"), |t| t.to_c_string(db));
                format!("{elem}[{size}]")
            }
            Self::Struct { name, .. } => format!("struct {name}"),
            Self::Union { name, .. } => format!("union {name}"),
            Self::Enum { name, .. } => format!("enum {name}"),
            Self::Procedure {
                return_type,
                arg_count,
                ..
            } => {
                let ret = db
                    .get(*return_type)
                    .map_or_else(|| "void".to_string(), |t| t.to_c_string(db));
                format!("{ret} (*)(/* {arg_count} args */)")
            }
            _ => "<complex_type>".to_string(),
        }
    }
}

// ── TypeDatabase ──────────────────────────────────────────────────────────────

/// A database mapping type indices to `CvType` records.
#[derive(Debug, Clone, Default)]
pub struct TypeDatabase {
    /// `type_index → CvType`
    types: HashMap<u32, CvType>,
    /// The first user-defined type index (types below this are primitives).
    pub first_user_type: u32,
}

impl TypeDatabase {
    /// Create a new database pre-populated with the primitive types.
    #[must_use]
    pub fn new() -> Self {
        let mut db = Self {
            types: HashMap::new(),
            first_user_type: 0x1000,
        };
        register_primitives(&mut db);
        db
    }

    /// Insert a type record.
    pub fn insert(&mut self, index: u32, ty: CvType) {
        self.types.insert(index, ty);
    }

    /// Look up a type by index.
    #[must_use]
    pub fn get(&self, index: u32) -> Option<&CvType> {
        self.types.get(&index)
    }

    /// Number of type records (including primitives).
    #[must_use]
    pub fn len(&self) -> usize {
        self.types.len()
    }

    /// True when the database is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// Render the type at `index` as a C-like string.
    #[must_use]
    pub fn type_to_string(&self, index: u32) -> String {
        self.get(index).map_or_else(
            || format!("<unknown_type_{index:#x}>"),
            |t| t.to_c_string(self),
        )
    }
}

fn register_primitives(db: &mut TypeDatabase) {
    static PRIMITIVES: &[(u32, &str, u8)] = &[
        (0x0001, "void", 0),
        (0x0003, "bool", 1),
        (0x0010, "int8_t", 1),
        (0x0011, "int16_t", 2),
        (0x0012, "int32_t", 4),
        (0x0013, "int64_t", 8),
        (0x0020, "uint8_t", 1),
        (0x0021, "uint16_t", 2),
        (0x0022, "uint32_t", 4),
        (0x0023, "uint64_t", 8),
        (0x0040, "float", 4),
        (0x0041, "double", 8),
        (0x0070, "char", 1),
        (0x0071, "wchar_t", 2),
    ];
    for &(code, name, size) in PRIMITIVES {
        db.insert(code, CvType::Primitive { code, name, size });
    }
}

// ── parse_type_stream ─────────────────────────────────────────────────────────

/// Parse the `TPI` stream and return a `TypeDatabase`.
///
/// `TPI` stream format:
/// - 56-byte header
///
/// # Errors
/// Returns an error if parsing/reading fails.
/// - Sequential type records, each preceded by a 4-byte `(length, leaf_type)` header.
pub fn parse_type_stream(data: &[u8]) -> Result<TypeDatabase> {
    if data.len() < 56 {
        return Err(PdbError::StreamTooShort);
    }

    let mut db = TypeDatabase::new();

    // Read the header.
    let mut hdr = StreamReader::new(&data[..56]);
    let _version = hdr.read_u32()?;
    let _header_size = hdr.read_u32()?;
    let first_index = hdr.read_u32()?;
    let _one_past_last_index = hdr.read_u32()?;
    // Remaining header fields are not needed here.

    db.first_user_type = first_index;

    let mut rdr = StreamReader::new(&data[56..]);
    let mut current_index = first_index;

    while rdr.remaining() >= 4 {
        let start = rdr.pos();
        let length = rdr.read_u16()? as usize;
        if length < 2 {
            break;
        }
        let leaf_type = rdr.read_u16()?;
        let payload_end = start + 2 + length;

        let cv_type = parse_one_type(leaf_type, &mut rdr, start + 4, payload_end)?;
        db.insert(current_index, cv_type);
        current_index += 1;

        // Advance to next record.
        rdr.seek(payload_end);
    }

    Ok(db)
}

fn parse_fieldlist_fields(rdr: &mut StreamReader<'_>) -> Result<Vec<CvField>> {
    let mut fields = Vec::new();
    while rdr.remaining() >= 2 {
        let kind = rdr.read_u16()?;
        if !parse_one_field(rdr, kind, &mut fields)? {
            break;
        }
    }
    Ok(fields)
}

/// Returns `false` when parsing should stop (unknown kind or truncated).
fn parse_one_field(
    rdr: &mut StreamReader<'_>,
    kind: u16,
    fields: &mut Vec<CvField>,
) -> Result<bool> {
    match kind {
        LF_MEMBER => {
            if rdr.remaining() < 6 {
                return Ok(false);
            }
            let attr = rdr.read_u16()?;
            let access = Access::from_u8((attr & 0x3) as u8);
            let type_idx = rdr.read_u32()?;
            let offset = rdr.read_numeric_leaf()?;
            let name = rdr.read_cstring().unwrap_or_default();
            rdr.align(4);
            fields.push(CvField::Member { access, type_idx, offset, name });
        }
        LF_STMEMBER => {
            if rdr.remaining() < 6 {
                return Ok(false);
            }
            let attr = rdr.read_u16()?;
            let access = Access::from_u8((attr & 0x3) as u8);
            let type_idx = rdr.read_u32()?;
            let name = rdr.read_cstring().unwrap_or_default();
            rdr.align(4);
            fields.push(CvField::StaticMember { access, type_idx, name });
        }
        LF_ENUMERATE => {
            if rdr.remaining() < 2 {
                return Ok(false);
            }
            let attr = rdr.read_u16()?;
            let access = Access::from_u8((attr & 0x3) as u8);
            let value = rdr.read_numeric_leaf()?;
            let name = rdr.read_cstring().unwrap_or_default();
            rdr.align(4);
            fields.push(CvField::Enumerate { access, value, name });
        }
        LF_BCLASS => {
            if rdr.remaining() < 6 {
                return Ok(false);
            }
            let attr = rdr.read_u16()?;
            let access = Access::from_u8((attr & 0x3) as u8);
            let type_idx = rdr.read_u32()?;
            let offset = rdr.read_numeric_leaf()?;
            rdr.align(4);
            fields.push(CvField::BaseClass { access, type_idx, offset });
        }
        LF_NESTTYPE => {
            if rdr.remaining() < 6 {
                return Ok(false);
            }
            let _ = rdr.read_u16()?; // pad
            let type_idx = rdr.read_u32()?;
            let name = rdr.read_cstring().unwrap_or_default();
            rdr.align(4);
            fields.push(CvField::NestedType { type_idx, name });
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn parse_composite_type(leaf_type: u16, rdr: &mut StreamReader<'_>) -> Result<CvType> {
    match leaf_type {
        LF_POINTER => {
            if rdr.remaining() < 6 {
                return Ok(CvType::Unknown(leaf_type));
            }
            let pointee = rdr.read_u32()?;
            let attr = rdr.read_u32()?;
            let pointer_kind = (attr & 0x1F) as u8;
            let size = if (attr >> 5) & 0x1 != 0 { 4u8 } else { 8u8 };
            Ok(CvType::Pointer { pointee, pointer_kind, size })
        }
        LF_ARRAY => {
            if rdr.remaining() < 8 {
                return Ok(CvType::Unknown(leaf_type));
            }
            let element_type = rdr.read_u32()?;
            let index_type = rdr.read_u32()?;
            let size = rdr.read_numeric_leaf()?;
            let name = rdr.read_cstring().unwrap_or_default();
            Ok(CvType::Array { element_type, index_type, size, name })
        }
        LF_CLASS | LF_STRUCTURE => {
            if rdr.remaining() < 16 {
                return Ok(CvType::Unknown(leaf_type));
            }
            let count = rdr.read_u16()?;
            let _ = rdr.read_u16()?; // property
            let field_list = rdr.read_u32()?;
            let _ = rdr.read_u32()?; // derived
            let _ = rdr.read_u32()?; // vshape
            let size = rdr.read_numeric_leaf()?;
            let name = rdr.read_cstring().unwrap_or_default();
            Ok(CvType::Struct { count, field_list, size, name, is_class: leaf_type == LF_CLASS })
        }
        LF_UNION => {
            if rdr.remaining() < 10 {
                return Ok(CvType::Unknown(leaf_type));
            }
            let count = rdr.read_u16()?;
            let _ = rdr.read_u16()?; // property
            let field_list = rdr.read_u32()?;
            let size = rdr.read_numeric_leaf()?;
            let name = rdr.read_cstring().unwrap_or_default();
            Ok(CvType::Union { count, field_list, size, name })
        }
        LF_ENUM => {
            if rdr.remaining() < 12 {
                return Ok(CvType::Unknown(leaf_type));
            }
            let count = rdr.read_u16()?;
            let _ = rdr.read_u16()?; // property
            let underlying_type = rdr.read_u32()?;
            let field_list = rdr.read_u32()?;
            let name = rdr.read_cstring().unwrap_or_default();
            Ok(CvType::Enum { count, underlying_type, field_list, name })
        }
        _ => Ok(CvType::Unknown(leaf_type)),
    }
}

fn parse_callable_type(leaf_type: u16, rdr: &mut StreamReader<'_>) -> Result<CvType> {
    match leaf_type {
        LF_PROCEDURE => {
            if rdr.remaining() < 12 {
                return Ok(CvType::Unknown(leaf_type));
            }
            let return_type = rdr.read_u32()?;
            let call_conv = rdr.read_u8()?;
            let _ = rdr.read_u8()?; // attrs
            let arg_count = rdr.read_u16()?;
            let arg_list = rdr.read_u32()?;
            Ok(CvType::Procedure { return_type, call_conv, arg_count, arg_list })
        }
        LF_MFUNCTION => {
            if rdr.remaining() < 20 {
                return Ok(CvType::Unknown(leaf_type));
            }
            let return_type = rdr.read_u32()?;
            let class_type = rdr.read_u32()?;
            let this_type = rdr.read_u32()?;
            let call_conv = rdr.read_u8()?;
            let _ = rdr.read_u8()?; // attrs
            let arg_count = rdr.read_u16()?;
            let arg_list = rdr.read_u32()?;
            Ok(CvType::MemberFunction {
                return_type,
                class_type,
                this_type,
                call_conv,
                arg_count,
                arg_list,
            })
        }
        LF_FIELDLIST => Ok(CvType::FieldList { fields: parse_fieldlist_fields(rdr)? }),
        LF_ARGLIST => {
            if rdr.remaining() < 4 {
                return Ok(CvType::Unknown(leaf_type));
            }
            let count = rdr.read_u32()? as usize;
            let mut arg_types = Vec::with_capacity(count.min(256));
            for _ in 0..count.min(256) {
                if rdr.remaining() < 4 {
                    break;
                }
                arg_types.push(rdr.read_u32()?);
            }
            Ok(CvType::ArgList { arg_types })
        }
        LF_VTSHAPE => {
            let count = rdr.read_u16().unwrap_or(0);
            Ok(CvType::VtShape { count })
        }
        _ => Ok(CvType::Unknown(leaf_type)),
    }
}

fn parse_one_type(
    leaf_type: u16,
    rdr: &mut StreamReader<'_>,
    _payload_start: usize,
    _payload_end: usize,
) -> Result<CvType> {
    match leaf_type {
        LF_POINTER | LF_ARRAY | LF_CLASS | LF_STRUCTURE | LF_UNION | LF_ENUM => {
            parse_composite_type(leaf_type, rdr)
        }
        LF_PROCEDURE
        | LF_MFUNCTION
        | LF_FIELDLIST
        | LF_ARGLIST
        | LF_VTSHAPE => parse_callable_type(leaf_type, rdr),
        _ => Ok(CvType::Unknown(leaf_type)),
    }
}

/// Render a `CvType` as a C-like type string.
#[must_use]
pub fn type_to_string(t: &CvType, db: &TypeDatabase) -> String {
    t.to_c_string(db)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tpi_header(first_index: u32) -> Vec<u8> {
        let mut v = vec![0u8; 56];
        // version = 20_040_203 (CV_SIGNATURE_C13)
        v[0..4].copy_from_slice(&20_040_203u32.to_le_bytes());
        // header_size
        v[4..8].copy_from_slice(&56u32.to_le_bytes());
        // first type index
        v[8..12].copy_from_slice(&first_index.to_le_bytes());
        // one past last (placeholder)
        v[12..16].copy_from_slice(&(first_index + 10).to_le_bytes());
        v
    }

    fn frame_type(leaf: u16, payload: &[u8]) -> Vec<u8> {
        let length = u16::try_from(2 + payload.len()).unwrap();
        let mut v = Vec::new();
        v.extend_from_slice(&length.to_le_bytes());
        v.extend_from_slice(&leaf.to_le_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn test_parse_primitives_in_db() {
        let db = TypeDatabase::new();
        assert!(db.get(0x0012).is_some()); // int32_t
        assert!(db.get(0x0022).is_some()); // uint32_t
    }

    #[test]
    fn test_parse_struct() {
        let mut data = make_tpi_header(0x1000);
        let mut payload = Vec::new();
        payload.extend_from_slice(&2u16.to_le_bytes()); // count
        payload.extend_from_slice(&0u16.to_le_bytes()); // property
        payload.extend_from_slice(&0u32.to_le_bytes()); // field
        payload.extend_from_slice(&0u32.to_le_bytes()); // derived
        payload.extend_from_slice(&0u32.to_le_bytes()); // vshape
        payload.extend_from_slice(&16u16.to_le_bytes()); // size (numeric leaf < 0x8000)
        payload.extend_from_slice(b"MyStruct\x00");
        data.extend(frame_type(LF_STRUCTURE, &payload));
        let db = parse_type_stream(&data).unwrap();
        let t = db.get(0x1000).expect("type 0x1000 must exist");
        assert!(matches!(t, CvType::Struct { .. }));
        assert_eq!(db.type_to_string(0x1000), "struct MyStruct");
    }

    #[test]
    fn test_parse_pointer() {
        let mut data = make_tpi_header(0x1000);
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x0012u32.to_le_bytes()); // pointee = int32_t
        payload.extend_from_slice(&0u32.to_le_bytes()); // attributes
        data.extend(frame_type(LF_POINTER, &payload));
        let db = parse_type_stream(&data).unwrap();
        let t = db.get(0x1000).unwrap();
        assert!(matches!(t, CvType::Pointer { .. }));
        assert!(db.type_to_string(0x1000).contains("int32_t"));
    }

    #[test]
    fn test_parse_enum() {
        let mut data = make_tpi_header(0x1000);
        let mut payload = Vec::new();
        payload.extend_from_slice(&3u16.to_le_bytes()); // count
        payload.extend_from_slice(&0u16.to_le_bytes()); // property
        payload.extend_from_slice(&0x0022u32.to_le_bytes()); // underlying = uint32_t
        payload.extend_from_slice(&0u32.to_le_bytes()); // field_list
        payload.extend_from_slice(b"Color\x00");
        data.extend(frame_type(LF_ENUM, &payload));
        let db = parse_type_stream(&data).unwrap();
        let t = db.get(0x1000).unwrap();
        assert!(matches!(t, CvType::Enum { name, .. } if name == "Color"));
    }

    #[test]
    fn test_type_db_len() {
        let db = TypeDatabase::new();
        assert!(!db.is_empty());
    }

    #[test]
    fn test_type_db_unknown() {
        let db = TypeDatabase::new();
        assert!(db.type_to_string(0xFFFF).contains("unknown"));
    }

    #[test]
    fn test_tpi_too_short() {
        let data = vec![0u8; 10];
        assert!(parse_type_stream(&data).is_err());
    }

    #[test]
    fn test_access_from_u8() {
        assert_eq!(Access::from_u8(1), Access::Private);
        assert_eq!(Access::from_u8(2), Access::Protected);
        assert_eq!(Access::from_u8(3), Access::Public);
    }
}
