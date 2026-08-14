//! DWARF type-information reader.
//!
//! Parses `DW_TAG_structure_type`, `DW_TAG_pointer_type`, `DW_TAG_base_type`,
//! `DW_TAG_typedef`, `DW_TAG_array_type`, `DW_TAG_union_type`, and
//! `DW_TAG_enumeration_type` DIEs into a typed in-memory representation.
//!
//! The primary entry point is [`DwarfTypeReader`], which is constructed from
//! raw `.debug_info` and `.debug_abbrev` byte slices and exposes
//! [`DwarfTypeReader::read_type_tree`] to extract the full type hierarchy.
//!
//! # Parallel implementations
//!
//! This crate ships more than one type-tree implementation: see also `dwarf_type_decoder` and `dwarf_type_parser`.
//! None of them is wired into [`crate::DwarfReader`], which uses its own
//! inline copy, so each carries an independent bug set and a fix applied
//! here does not propagate. Pick one deliberately and stay on it.

use std::collections::HashMap;

// ── DWARF tag constants ───────────────────────────────────────────────────────

const DW_TAG_BASE_TYPE: u16 = 0x24;
const DW_TAG_POINTER_TYPE: u16 = 0x0f;
const DW_TAG_TYPEDEF: u16 = 0x16;
const DW_TAG_STRUCTURE_TYPE: u16 = 0x13;
const DW_TAG_UNION_TYPE: u16 = 0x17;
const DW_TAG_ARRAY_TYPE: u16 = 0x01;
const DW_TAG_ENUMERATION_TYPE: u16 = 0x04;
const DW_TAG_MEMBER: u16 = 0x0d;
const DW_TAG_ENUMERATOR: u16 = 0x28;

/// Returns `true` if `tag` is one of the child-DIE tags this reader knows
/// how to interpret as a member or enumerator within a parent type.
///
/// Exposed so higher layers (e.g. the IL builder) can pre-filter DIE
/// children before invoking the heavier type-reader pipeline.
#[must_use]
pub const fn is_type_member_tag(tag: u16) -> bool {
    matches!(tag, DW_TAG_MEMBER | DW_TAG_ENUMERATOR)
}
const DW_TAG_CONST_TYPE: u16 = 0x26;
const DW_TAG_VOLATILE_TYPE: u16 = 0x35;
const DW_TAG_RESTRICT_TYPE: u16 = 0x37;
const DW_TAG_SUBROUTINE_TYPE: u16 = 0x15;
const DW_TAG_REFERENCE_TYPE: u16 = 0x10;

// ── DWARF attribute constants ─────────────────────────────────────────────────

const DW_AT_NAME: u16 = 0x03;
const DW_AT_BYTE_SIZE: u16 = 0x0b;
const DW_AT_TYPE: u16 = 0x49;
const DW_AT_BIT_SIZE: u16 = 0x0c;
const DW_AT_BIT_OFFSET: u16 = 0x0d;
const DW_AT_DATA_MEMBER_LOCATION: u16 = 0x38;
const DW_AT_CONST_VALUE: u16 = 0x1c;
const DW_AT_ENCODING: u16 = 0x3e;
const DW_AT_UPPER_BOUND: u16 = 0x2f;
const DW_AT_COUNT: u16 = 0x37;

// ── TypeAttribute ─────────────────────────────────────────────────────────────

/// A single attribute extracted from a type DIE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeAttribute {
    /// A string value (e.g. `DW_AT_name`).
    String(String),
    /// An unsigned integer value.
    Uint(u64),
    /// A signed integer value.
    Int(i64),
    /// A reference to another DIE (offset within `.debug_info`).
    Ref(u64),
}

impl TypeAttribute {
    /// Return the inner string if this is a `String` variant.
    #[must_use]
    pub const fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Return the inner `u64` if this is a `Uint` or `Ref` variant.
    #[must_use]
    pub const fn as_uint(&self) -> Option<u64> {
        match self {
            Self::Uint(v) | Self::Ref(v) => Some(*v),
            Self::Int(v) => Some((*v).unsigned_abs()),
            _ => None,
        }
    }

    /// Return the inner `i64` if this is an `Int` or `Uint` variant.
    #[must_use]
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(v) => Some(*v),
            Self::Uint(v) => i64::try_from(*v).ok(),
            _ => None,
        }
    }
}

// ── DwarfType ─────────────────────────────────────────────────────────────────

/// Broad category of a DWARF type tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwarfTypeKind {
    /// `DW_TAG_base_type` (int, char, float, ...).
    Base,
    /// `DW_TAG_pointer_type`.
    Pointer,
    /// `DW_TAG_reference_type`.
    Reference,
    /// `DW_TAG_typedef`.
    Typedef,
    /// `DW_TAG_structure_type`.
    Struct,
    /// `DW_TAG_union_type`.
    Union,
    /// `DW_TAG_array_type`.
    Array,
    /// `DW_TAG_enumeration_type`.
    Enum,
    /// `DW_TAG_const_type` qualifier wrapper.
    Const,
    /// `DW_TAG_volatile_type` qualifier wrapper.
    Volatile,
    /// `DW_TAG_restrict_type` qualifier wrapper.
    Restrict,
    /// `DW_TAG_subroutine_type` (function type).
    Subroutine,
    /// Any other type tag.
    Other,
}

impl DwarfTypeKind {
    /// Human-readable category name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::Pointer => "pointer",
            Self::Reference => "reference",
            Self::Typedef => "typedef",
            Self::Struct => "struct",
            Self::Union => "union",
            Self::Array => "array",
            Self::Enum => "enum",
            Self::Const => "const",
            Self::Volatile => "volatile",
            Self::Restrict => "restrict",
            Self::Subroutine => "subroutine",
            Self::Other => "other",
        }
    }
}

/// A member (field) of a struct or union type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeMember {
    /// Field name (may be empty for anonymous fields).
    pub name: String,
    /// Offset from the start of the containing type, in bytes.
    pub byte_offset: u64,
    /// Type offset within `.debug_info` (a `DW_AT_type` reference).
    pub type_ref: Option<u64>,
    /// Bit size for bitfields.
    pub bit_size: Option<u64>,
    /// Bit offset for bitfields.
    pub bit_offset: Option<u64>,
}

/// An enumerator constant within an enumeration type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumVariant {
    /// Enumerator name.
    pub name: String,
    /// Constant value.
    pub value: i64,
}

/// An in-memory representation of a single DWARF type.
#[derive(Debug, Clone)]
pub struct DwarfType {
    /// Offset of this DIE within `.debug_info`.
    pub die_offset: u64,
    /// Tag kind.
    pub kind: DwarfTypeKind,
    /// Type name, if present.
    pub name: Option<String>,
    /// Size in bytes (0 if unknown).
    pub byte_size: u64,
    /// Reference to the inner type (for pointer / typedef / const / volatile).
    pub inner_type_ref: Option<u64>,
    /// Struct / union member list.
    pub members: Vec<TypeMember>,
    /// Enum variant list.
    pub variants: Vec<EnumVariant>,
    /// Array element count (if known).
    pub array_count: Option<u64>,
    /// DWARF base-type encoding (`DW_AT_encoding`).
    pub encoding: Option<u64>,
    /// Raw attribute map for anything not captured by the fields above.
    pub raw_attrs: HashMap<u16, TypeAttribute>,
}

impl DwarfType {
    /// Return the display name: the explicit name or a synthesised one.
    #[must_use]
    pub fn display_name(&self) -> String {
        match &self.name {
            Some(n) if !n.is_empty() => n.clone(),
            _ => format!("<anonymous {}@{:#x}>", self.kind.as_str(), self.die_offset),
        }
    }

    /// Whether this type is a plain C pointer.
    #[must_use]
    pub const fn is_pointer(&self) -> bool {
        matches!(self.kind, DwarfTypeKind::Pointer | DwarfTypeKind::Reference)
    }

    /// Whether this type is a composite (struct / union).
    #[must_use]
    pub const fn is_composite(&self) -> bool {
        matches!(self.kind, DwarfTypeKind::Struct | DwarfTypeKind::Union)
    }

    /// Whether this type is a qualifier wrapper (const / volatile / restrict).
    #[must_use]
    pub const fn is_qualifier(&self) -> bool {
        matches!(
            self.kind,
            DwarfTypeKind::Const | DwarfTypeKind::Volatile | DwarfTypeKind::Restrict
        )
    }

    /// Follow the typedef / qualifier chain depth-first to find the ultimate
    /// base type offset.  Returns `self.die_offset` if there is no `inner_type_ref`.
    #[must_use]
    pub fn resolve_to_base<'a>(&'a self, registry: &'a TypeRegistry) -> &'a Self {
        let mut current = self;
        for _ in 0..64 {
            match current.inner_type_ref {
                Some(r) if (current.is_qualifier()
                    || current.kind == DwarfTypeKind::Typedef) =>
                {
                    match registry.get(r) {
                        Some(t) => current = t,
                        None => break,
                    }
                }
                _ => break,
            }
        }
        current
    }
}

// ── TypeRegistry ──────────────────────────────────────────────────────────────

/// A map of DIE offset → parsed [`DwarfType`].
#[derive(Debug, Default)]
pub struct TypeRegistry {
    types: HashMap<u64, DwarfType>,
}

impl TypeRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a type.
    pub fn insert(&mut self, t: DwarfType) {
        self.types.insert(t.die_offset, t);
    }

    /// Retrieve a type by its DIE offset.
    #[must_use]
    pub fn get(&self, offset: u64) -> Option<&DwarfType> {
        self.types.get(&offset)
    }

    /// Total number of types in the registry.
    #[must_use]
    pub fn len(&self) -> usize {
        self.types.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// Return all struct/union types.
    #[must_use]
    pub fn composites(&self) -> Vec<&DwarfType> {
        self.types
            .values()
            .filter(|t| t.is_composite())
            .collect()
    }

    /// Return all pointer types.
    #[must_use]
    pub fn pointers(&self) -> Vec<&DwarfType> {
        self.types
            .values()
            .filter(|t| t.is_pointer())
            .collect()
    }

    /// Return all named types sorted by name.
    #[must_use]
    pub fn named_types(&self) -> Vec<&DwarfType> {
        let mut named: Vec<&DwarfType> = self
            .types
            .values()
            .filter(|t| t.name.as_deref().is_some_and(|n| !n.is_empty()))
            .collect();
        named.sort_by(|a, b| a.name.cmp(&b.name));
        named
    }
}

// ── Low-level byte helpers ────────────────────────────────────────────────────

fn read_u8(data: &[u8], off: &mut usize) -> Option<u8> {
    let v = data.get(*off).copied()?;
    *off += 1;
    Some(v)
}

fn read_u16_le(data: &[u8], off: &mut usize) -> Option<u16> {
    if *off + 2 > data.len() {
        return None;
    }
    let v = u16::from_le_bytes([data[*off], data[*off + 1]]);
    *off += 2;
    Some(v)
}

fn read_u32_le(data: &[u8], off: &mut usize) -> Option<u32> {
    if *off + 4 > data.len() {
        return None;
    }
    let v = u32::from_le_bytes(data[*off..*off + 4].try_into().ok()?);
    *off += 4;
    Some(v)
}

fn read_u64_le(data: &[u8], off: &mut usize) -> Option<u64> {
    if *off + 8 > data.len() {
        return None;
    }
    let v = u64::from_le_bytes(data[*off..*off + 8].try_into().ok()?);
    *off += 8;
    Some(v)
}

fn read_uleb128(data: &[u8], off: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let b = read_u8(data, off)?;
        if shift >= 64 {
            return None;
        }
        result |= u64::from(b & 0x7f) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Some(result);
        }
    }
}

fn read_sleb128(data: &[u8], off: &mut usize) -> Option<i64> {
    let mut result = 0i64;
    let mut shift = 0u32;
    let b = loop {
        let byte = read_u8(data, off)?;
        result |= i64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break byte;
        }
        if shift >= 64 {
            return None;
        }
    };
    if shift < 64 && (b & 0x40) != 0 {
        result |= !0i64 << shift;
    }
    Some(result)
}

fn read_cstring(data: &[u8], off: &mut usize) -> Option<String> {
    let start = *off;
    while *off < data.len() && data[*off] != 0 {
        *off += 1;
    }
    if *off >= data.len() {
        return None;
    }
    let s = String::from_utf8_lossy(&data[start..*off]).into_owned();
    *off += 1;
    Some(s)
}

// ── Abbreviation table ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct AbbrevAttr {
    name: u16,
    form: u16,
}

#[derive(Debug, Clone)]
struct AbbrevEntry {
    tag: u16,
    has_children: bool,
    attrs: Vec<AbbrevAttr>,
}

fn parse_abbrev_table(data: &[u8]) -> HashMap<u64, AbbrevEntry> {
    let mut map = HashMap::new();
    let mut off = 0usize;
    loop {
        let Some(code) = read_uleb128(data, &mut off) else {
            break;
        };
        if code == 0 {
            break;
        }
        let Some(tag_u64) = read_uleb128(data, &mut off) else {
            break;
        };
        let tag = tag_u64 as u16;
        let has_children = read_u8(data, &mut off).unwrap_or(0) != 0;
        let mut attrs = Vec::new();
        loop {
            let Some(attr_u64) = read_uleb128(data, &mut off) else {
                break;
            };
            let Some(form_u64) = read_uleb128(data, &mut off) else {
                break;
            };
            if attr_u64 == 0 && form_u64 == 0 {
                break;
            }
            if form_u64 == 0x21 {
                // DW_FORM_implicit_const: extra SLEB128
                read_sleb128(data, &mut off);
            }
            attrs.push(AbbrevAttr {
                name: attr_u64 as u16,
                form: form_u64 as u16,
            });
        }
        map.insert(code, AbbrevEntry { tag, has_children, attrs });
    }
    map
}

// ── Attribute value reader ────────────────────────────────────────────────────

fn skip_attr_form(data: &[u8], off: &mut usize, form: u16, addr_size: u8, offset_size: usize) {
    match form {
        0x01 => { *off += addr_size as usize; } // DW_FORM_addr
        0x02 => { read_uleb128(data, off); }    // DW_FORM_block2 size
        0x03 => { let l = read_u16_le(data, off).unwrap_or(0); *off += l as usize; }
        0x04 => { let l = read_u32_le(data, off).unwrap_or(0); *off += l as usize; }
        0x05 => { *off += 2; }  // data2
        0x06 => { *off += 4; }  // data4
        0x07 => { *off += 8; }  // data8
        0x08 => { read_cstring(data, off); } // string
        0x09 => { let l = read_uleb128(data, off).unwrap_or(0); *off = off.saturating_add(l as usize); }
        0x0a => { let l = read_u8(data, off).unwrap_or(0); *off += l as usize; }
        0x0b | 0x0c => { *off += 1; } // data1 / flag
        0x0d => { read_sleb128(data, off); } // sdata
        0x0e => { *off += offset_size; } // strp
        0x0f => { read_uleb128(data, off); } // udata
        0x10 | 0x17 => { *off += offset_size; } // ref_addr / sec_offset
        0x11 => { *off += 1; } // ref1
        0x12 => { *off += 2; } // ref2
        0x13 => { *off += 4; } // ref4
        0x14 => { *off += 8; } // ref8
        0x15 => { read_uleb128(data, off); } // ref_udata
        0x16 => { // indirect: read actual form first
            if let Some(actual) = read_uleb128(data, off) {
                skip_attr_form(data, off, actual as u16, addr_size, offset_size);
            }
        }
        0x18 => { let l = read_uleb128(data, off).unwrap_or(0); *off = off.saturating_add(l as usize); }
        0x19 => {} // flag_present: zero bytes
        0x1a | 0x1b => { read_uleb128(data, off); } // strx / addrx
        0x1f => { *off += offset_size; } // line_strp
        _ => {}
    }
}

/// Read an attribute value that we care about; return `None` if the form is
/// not one we can decode into a `TypeAttribute`.
fn read_useful_attr(
    data: &[u8],
    off: &mut usize,
    form: u16,
    addr_size: u8,
    offset_size: usize,
    debug_str: &[u8],
) -> Option<TypeAttribute> {
    match form {
        // Addresses
        0x01 => {
            let v = if addr_size == 8 {
                read_u64_le(data, off)?
            } else {
                u64::from(read_u32_le(data, off)?)
            };
            Some(TypeAttribute::Uint(v))
        }
        // data1 / flag / ref1
        0x0b | 0x0c | 0x11 => Some(TypeAttribute::Uint(u64::from(read_u8(data, off)?))),
        // data2 / ref2
        0x05 | 0x12 => Some(TypeAttribute::Uint(u64::from(read_u16_le(data, off)?))),
        // data4 / ref4
        0x06 | 0x13 => Some(TypeAttribute::Uint(u64::from(read_u32_le(data, off)?))),
        // data8 / ref8
        0x07 | 0x14 => Some(TypeAttribute::Uint(read_u64_le(data, off)?)),
        // udata / ref_udata
        0x0f | 0x15 => Some(TypeAttribute::Uint(read_uleb128(data, off)?)),
        // sdata
        0x0d => Some(TypeAttribute::Int(read_sleb128(data, off)?)),
        // inline string
        0x08 => Some(TypeAttribute::String(read_cstring(data, off)?)),
        // strp → indirect string
        0x0e | 0x1f => {
            let str_off = if offset_size == 8 {
                usize::try_from(read_u64_le(data, off)?).ok()?
            } else {
                read_u32_le(data, off)? as usize
            };
            let mut tmp = str_off;
            Some(TypeAttribute::String(read_cstring(debug_str, &mut tmp)?))
        }
        // ref_addr / sec_offset (treat as uint)
        0x10 | 0x17 => {
            let v = if offset_size == 8 {
                read_u64_le(data, off)?
            } else {
                u64::from(read_u32_le(data, off)?)
            };
            Some(TypeAttribute::Uint(v))
        }
        // flag_present
        0x19 => Some(TypeAttribute::Uint(1)),
        _ => {
            skip_attr_form(data, off, form, addr_size, offset_size);
            None
        }
    }
}

// ── DIE raw record ────────────────────────────────────────────────────────────

struct RawDie {
    offset: u64,
    tag: u16,
    has_children: bool,
    attrs: HashMap<u16, TypeAttribute>,
}

// ── DwarfTypeReader ───────────────────────────────────────────────────────────

/// Reads DWARF type information from raw `.debug_info` / `.debug_abbrev` slices.
pub struct DwarfTypeReader<'a> {
    debug_info: &'a [u8],
    debug_abbrev: &'a [u8],
    debug_str: &'a [u8],
}

impl<'a> DwarfTypeReader<'a> {
    /// Create a reader from the three DWARF sections.
    #[must_use]
    pub const fn new(
        debug_info: &'a [u8],
        debug_abbrev: &'a [u8],
        debug_str: &'a [u8],
    ) -> Self {
        Self {
            debug_info,
            debug_abbrev,
            debug_str,
        }
    }

    /// Parse all type DIEs and return a [`TypeRegistry`].
    #[must_use]
    pub fn read_type_tree(&self) -> TypeRegistry {
        let mut registry = TypeRegistry::new();
        let mut off = 0usize;
        while off < self.debug_info.len() {
            if let Some(next) = self.parse_cu(&mut off, &mut registry) {
                off = next;
            } else {
                break;
            }
        }
        registry
    }

    fn parse_cu(&self, off: &mut usize, registry: &mut TypeRegistry) -> Option<usize> {
        if *off + 4 > self.debug_info.len() {
            return None;
        }
        let initial_len = read_u32_le(self.debug_info, off)?;
        let (is_64bit, unit_len) = if initial_len == 0xFFFF_FFFF {
            let len = read_u64_le(self.debug_info, off)?;
            (true, usize::try_from(len).ok()?)
        } else {
            (false, initial_len as usize)
        };
        let unit_end = off.checked_add(unit_len)?;
        if unit_end > self.debug_info.len() {
            return None;
        }
        let offset_size: usize = if is_64bit { 8 } else { 4 };
        let _version = read_u16_le(self.debug_info, off)?;
        let abbrev_offset = if is_64bit {
            usize::try_from(read_u64_le(self.debug_info, off)?).ok()?
        } else {
            read_u32_le(self.debug_info, off)? as usize
        };
        let addr_size = read_u8(self.debug_info, off)?;

        let abbrev_data = self.debug_abbrev.get(abbrev_offset..).unwrap_or(&[]);
        let abbrevs = parse_abbrev_table(abbrev_data);

        self.parse_dies(self.debug_info, off, unit_end, &abbrevs, addr_size, offset_size, registry);
        Some(unit_end)
    }

    fn parse_dies(
        &self,
        data: &[u8],
        off: &mut usize,
        end: usize,
        abbrevs: &HashMap<u64, AbbrevEntry>,
        addr_size: u8,
        offset_size: usize,
        registry: &mut TypeRegistry,
    ) {
        while *off < end {
            let die_offset = *off as u64;
            let Some(code) = read_uleb128(data, off) else {
                break;
            };
            if code == 0 {
                continue;
            }
            let Some(entry) = abbrevs.get(&code) else {
                break;
            };
            let mut attrs: HashMap<u16, TypeAttribute> = HashMap::new();
            for a in &entry.attrs {
                if let Some(val) =
                    read_useful_attr(data, off, a.form, addr_size, offset_size, self.debug_str)
                {
                    attrs.insert(a.name, val);
                }
            }
            let raw = RawDie {
                offset: die_offset,
                tag: entry.tag,
                has_children: entry.has_children,
                attrs,
            };
            if let Some(t) = self.convert_die(&raw) {
                registry.insert(t);
            }
            if !raw.has_children {
                // No children — nothing to recurse into.
            }
        }
    }

    fn convert_die(&self, die: &RawDie) -> Option<DwarfType> {
        let kind = match die.tag {
            t if t == DW_TAG_BASE_TYPE => DwarfTypeKind::Base,
            t if t == DW_TAG_POINTER_TYPE => DwarfTypeKind::Pointer,
            t if t == DW_TAG_REFERENCE_TYPE => DwarfTypeKind::Reference,
            t if t == DW_TAG_TYPEDEF => DwarfTypeKind::Typedef,
            t if t == DW_TAG_STRUCTURE_TYPE => DwarfTypeKind::Struct,
            t if t == DW_TAG_UNION_TYPE => DwarfTypeKind::Union,
            t if t == DW_TAG_ARRAY_TYPE => DwarfTypeKind::Array,
            t if t == DW_TAG_ENUMERATION_TYPE => DwarfTypeKind::Enum,
            t if t == DW_TAG_CONST_TYPE => DwarfTypeKind::Const,
            t if t == DW_TAG_VOLATILE_TYPE => DwarfTypeKind::Volatile,
            t if t == DW_TAG_RESTRICT_TYPE => DwarfTypeKind::Restrict,
            t if t == DW_TAG_SUBROUTINE_TYPE => DwarfTypeKind::Subroutine,
            _ => return None, // ignore non-type DIEs
        };

        let name = die
            .attrs
            .get(&DW_AT_NAME)
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let byte_size = die
            .attrs
            .get(&DW_AT_BYTE_SIZE)
            .and_then(TypeAttribute::as_uint)
            .unwrap_or(0);
        let inner_type_ref = die
            .attrs
            .get(&DW_AT_TYPE)
            .and_then(TypeAttribute::as_uint);
        let encoding = die
            .attrs
            .get(&DW_AT_ENCODING)
            .and_then(TypeAttribute::as_uint);
        let array_count = die
            .attrs
            .get(&DW_AT_UPPER_BOUND)
            .and_then(TypeAttribute::as_uint)
            .map(|ub| ub + 1)
            .or_else(|| {
                die.attrs
                    .get(&DW_AT_COUNT)
                    .and_then(TypeAttribute::as_uint)
            });

        Some(DwarfType {
            die_offset: die.offset,
            kind,
            name,
            byte_size,
            inner_type_ref,
            members: Vec::new(),
            variants: Vec::new(),
            array_count,
            encoding,
            raw_attrs: die.attrs.clone(),
        })
    }
}

// ── Convenience helpers ───────────────────────────────────────────────────────

/// Build a member record from a `DW_TAG_member` DIE attribute map.
#[must_use]
pub fn member_from_attrs(attrs: &HashMap<u16, TypeAttribute>) -> TypeMember {
    let name = attrs
        .get(&DW_AT_NAME)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    let byte_offset = attrs
        .get(&DW_AT_DATA_MEMBER_LOCATION)
        .and_then(TypeAttribute::as_uint)
        .unwrap_or(0);
    let type_ref = attrs.get(&DW_AT_TYPE).and_then(TypeAttribute::as_uint);
    let bit_size = attrs
        .get(&DW_AT_BIT_SIZE)
        .and_then(TypeAttribute::as_uint);
    let bit_offset = attrs
        .get(&DW_AT_BIT_OFFSET)
        .and_then(TypeAttribute::as_uint);
    TypeMember {
        name,
        byte_offset,
        type_ref,
        bit_size,
        bit_offset,
    }
}

/// Build an enum variant record from a `DW_TAG_enumerator` DIE attribute map.
#[must_use]
pub fn enum_variant_from_attrs(attrs: &HashMap<u16, TypeAttribute>) -> EnumVariant {
    let name = attrs
        .get(&DW_AT_NAME)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    let value = attrs
        .get(&DW_AT_CONST_VALUE)
        .and_then(TypeAttribute::as_int)
        .unwrap_or(0);
    EnumVariant { name, value }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_reader<'a>(info: &'a [u8], abbrev: &'a [u8]) -> DwarfTypeReader<'a> {
        DwarfTypeReader::new(info, abbrev, b"")
    }

    #[test]
    fn empty_sections_give_empty_registry() {
        let r = make_reader(b"", b"");
        assert!(r.read_type_tree().is_empty());
    }

    #[test]
    fn type_kind_as_str() {
        assert_eq!(DwarfTypeKind::Struct.as_str(), "struct");
        assert_eq!(DwarfTypeKind::Pointer.as_str(), "pointer");
        assert_eq!(DwarfTypeKind::Base.as_str(), "base");
    }

    #[test]
    fn dwarf_type_display_name_anonymous() {
        let t = DwarfType {
            die_offset: 0x10,
            kind: DwarfTypeKind::Struct,
            name: None,
            byte_size: 8,
            inner_type_ref: None,
            members: Vec::new(),
            variants: Vec::new(),
            array_count: None,
            encoding: None,
            raw_attrs: HashMap::new(),
        };
        assert!(t.display_name().contains("struct"));
        assert!(t.display_name().contains("0x10"));
    }

    #[test]
    fn dwarf_type_display_name_named() {
        let t = DwarfType {
            die_offset: 0,
            kind: DwarfTypeKind::Base,
            name: Some("int".into()),
            byte_size: 4,
            inner_type_ref: None,
            members: Vec::new(),
            variants: Vec::new(),
            array_count: None,
            encoding: Some(5),
            raw_attrs: HashMap::new(),
        };
        assert_eq!(t.display_name(), "int");
    }

    #[test]
    fn type_attribute_as_str() {
        let a = TypeAttribute::String("hello".into());
        assert_eq!(a.as_str(), Some("hello"));
        assert_eq!(TypeAttribute::Uint(42).as_str(), None);
    }

    #[test]
    fn type_attribute_as_uint() {
        assert_eq!(TypeAttribute::Uint(7).as_uint(), Some(7));
        assert_eq!(TypeAttribute::Ref(0x100).as_uint(), Some(0x100));
        assert_eq!(TypeAttribute::Int(-3).as_uint(), Some(3));
    }

    #[test]
    fn type_attribute_as_int() {
        assert_eq!(TypeAttribute::Int(-5).as_int(), Some(-5));
        assert_eq!(TypeAttribute::Uint(10).as_int(), Some(10));
    }

    #[test]
    fn is_pointer_and_composite() {
        let ptr = DwarfType {
            die_offset: 0,
            kind: DwarfTypeKind::Pointer,
            name: None,
            byte_size: 8,
            inner_type_ref: Some(0x20),
            members: Vec::new(),
            variants: Vec::new(),
            array_count: None,
            encoding: None,
            raw_attrs: HashMap::new(),
        };
        assert!(ptr.is_pointer());
        assert!(!ptr.is_composite());
        assert!(!ptr.is_qualifier());
    }

    #[test]
    fn registry_insert_and_get() {
        let mut reg = TypeRegistry::new();
        let t = DwarfType {
            die_offset: 42,
            kind: DwarfTypeKind::Base,
            name: Some("char".into()),
            byte_size: 1,
            inner_type_ref: None,
            members: Vec::new(),
            variants: Vec::new(),
            array_count: None,
            encoding: Some(8),
            raw_attrs: HashMap::new(),
        };
        reg.insert(t);
        assert_eq!(reg.len(), 1);
        assert!(reg.get(42).is_some());
        assert!(reg.get(99).is_none());
    }

    #[test]
    fn member_from_attrs_defaults() {
        let attrs = HashMap::new();
        let m = member_from_attrs(&attrs);
        assert_eq!(m.name, "");
        assert_eq!(m.byte_offset, 0);
        assert!(m.type_ref.is_none());
    }

    #[test]
    fn enum_variant_from_attrs_defaults() {
        let attrs = HashMap::new();
        let ev = enum_variant_from_attrs(&attrs);
        assert_eq!(ev.name, "");
        assert_eq!(ev.value, 0);
    }

    #[test]
    fn registry_composites_and_pointers() {
        let mut reg = TypeRegistry::new();
        for (i, kind) in [
            DwarfTypeKind::Struct,
            DwarfTypeKind::Pointer,
            DwarfTypeKind::Base,
            DwarfTypeKind::Union,
        ]
        .iter()
        .enumerate()
        {
            reg.insert(DwarfType {
                die_offset: i as u64,
                kind: *kind,
                name: None,
                byte_size: 4,
                inner_type_ref: None,
                members: Vec::new(),
                variants: Vec::new(),
                array_count: None,
                encoding: None,
                raw_attrs: HashMap::new(),
            });
        }
        assert_eq!(reg.composites().len(), 2);
        assert_eq!(reg.pointers().len(), 1);
    }

    #[test]
    fn resolve_to_base_no_chain() {
        let mut reg = TypeRegistry::new();
        let t = DwarfType {
            die_offset: 1,
            kind: DwarfTypeKind::Base,
            name: Some("int".into()),
            byte_size: 4,
            inner_type_ref: None,
            members: Vec::new(),
            variants: Vec::new(),
            array_count: None,
            encoding: None,
            raw_attrs: HashMap::new(),
        };
        reg.insert(t);
        let base = reg.get(1).unwrap().resolve_to_base(&reg);
        assert_eq!(base.die_offset, 1);
    }

    #[test]
    fn resolve_to_base_through_typedef() {
        let mut reg = TypeRegistry::new();
        // int base type at offset 1
        reg.insert(DwarfType {
            die_offset: 1,
            kind: DwarfTypeKind::Base,
            name: Some("int".into()),
            byte_size: 4,
            inner_type_ref: None,
            members: Vec::new(),
            variants: Vec::new(),
            array_count: None,
            encoding: None,
            raw_attrs: HashMap::new(),
        });
        // typedef MyInt = int at offset 2
        reg.insert(DwarfType {
            die_offset: 2,
            kind: DwarfTypeKind::Typedef,
            name: Some("MyInt".into()),
            byte_size: 4,
            inner_type_ref: Some(1),
            members: Vec::new(),
            variants: Vec::new(),
            array_count: None,
            encoding: None,
            raw_attrs: HashMap::new(),
        });
        let base = reg.get(2).unwrap().resolve_to_base(&reg);
        assert_eq!(base.die_offset, 1);
    }

    #[test]
    fn named_types_sorted() {
        let mut reg = TypeRegistry::new();
        for (offset, name) in [(10u64, "zzz"), (20, "aaa"), (30, "mmm")] {
            reg.insert(DwarfType {
                die_offset: offset,
                kind: DwarfTypeKind::Base,
                name: Some(name.into()),
                byte_size: 4,
                inner_type_ref: None,
                members: Vec::new(),
                variants: Vec::new(),
                array_count: None,
                encoding: None,
                raw_attrs: HashMap::new(),
            });
        }
        let named = reg.named_types();
        assert_eq!(named[0].name.as_deref(), Some("aaa"));
        assert_eq!(named[2].name.as_deref(), Some("zzz"));
    }
}
