//! DWARF debug information reader for ELF binaries — structured type layer.
//!
//! **Layer:** higher-level companion to [`crate::debug_sections`].
//! While `debug_sections` provides low-level section parsers (CU headers,
//! abbrev tables, line-number table prologues, CIE/FDE records), this
//! module provides:
//!
//! * A complete `DwarfTag` enum covering all DWARF 4 tags.
//! * A complete `DwarfAttr` / `DwarfForm` enum covering all attribute codes.
//! * [`DwarfEntry`] — a structured DIE (Debug Information Entry) with
//!   decoded attribute values.
//! * [`ElfDwarfReader`] — a high-level walker that uses the low-level
//!   parsers internally and yields `DwarfUnit` / `DwarfEntry` values.
//!
//! These two modules are intentionally kept separate: `debug_sections` is
//! thin and allocation-light (suitable for quick scans), while this module
//! builds richer in-memory structures for full DIE-tree traversal.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// DWARF constants
// ---------------------------------------------------------------------------

/// DWARF tag identifiers (partial list covering the most common tags).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DwarfTag {
    ArrayType          = 0x01,
    ClassType          = 0x02,
    EntryPoint         = 0x03,
    EnumerationType    = 0x04,
    FormalParameter    = 0x05,
    ImportedDeclaration = 0x08,
    Label              = 0x0A,
    LexicalBlock       = 0x0B,
    Member             = 0x0D,
    PointerType        = 0x0F,
    ReferenceType      = 0x10,
    CompileUnit        = 0x11,
    StringType         = 0x12,
    StructureType      = 0x13,
    SubroutineType     = 0x15,
    Typedef            = 0x16,
    UnionType          = 0x17,
    UnspecifiedParameters = 0x18,
    Variant            = 0x19,
    CommonBlock        = 0x1A,
    CommonInclusion    = 0x1B,
    Inheritance        = 0x1C,
    InlinedSubroutine  = 0x1D,
    Module             = 0x1E,
    PtrToMemberType    = 0x1F,
    SetType            = 0x20,
    SubrangeType       = 0x21,
    WithStmt           = 0x22,
    AccessDeclaration  = 0x23,
    BaseType           = 0x24,
    CatchBlock         = 0x25,
    ConstType          = 0x26,
    Constant           = 0x27,
    Enumerator         = 0x28,
    FileType           = 0x29,
    Friend             = 0x2A,
    Namelist           = 0x2B,
    NamelistItem       = 0x2C,
    PackedType         = 0x2D,
    Subprogram         = 0x2E,
    TemplateTypeParam  = 0x2F,
    TemplateValueParam = 0x30,
    ThrownType         = 0x31,
    TryBlock           = 0x32,
    VariantPart        = 0x33,
    Variable           = 0x34,
    VolatileType       = 0x35,
    DwarfProcedure     = 0x36,
    RestrictType       = 0x37,
    InterfaceType      = 0x38,
    Namespace          = 0x39,
    ImportedModule     = 0x3A,
    UnspecifiedType    = 0x3B,
    PartialUnit        = 0x3C,
    ImportedUnit       = 0x3D,
    MutableType        = 0x3E,
    Condition          = 0x3F,
    SharedType         = 0x40,
    TypeUnit           = 0x41,
    RvalueReferenceType = 0x42,
    TemplateAlias      = 0x43,
    Unknown(u16),
}

impl DwarfTag {
    #[must_use] 
    pub const fn from_u16(v: u16) -> Self {
        match v {
            0x01 => Self::ArrayType,
            0x02 => Self::ClassType,
            0x11 => Self::CompileUnit,
            0x2E => Self::Subprogram,
            0x34 => Self::Variable,
            0x13 => Self::StructureType,
            0x16 => Self::Typedef,
            0x24 => Self::BaseType,
            0x17 => Self::UnionType,
            0x04 => Self::EnumerationType,
            0x28 => Self::Enumerator,
            0x0D => Self::Member,
            0x05 => Self::FormalParameter,
            0x0F => Self::PointerType,
            0x39 => Self::Namespace,
            0x1D => Self::InlinedSubroutine,
            other => Self::Unknown(other),
        }
    }

    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::CompileUnit        => "DW_TAG_compile_unit",
            Self::Subprogram         => "DW_TAG_subprogram",
            Self::Variable           => "DW_TAG_variable",
            Self::BaseType           => "DW_TAG_base_type",
            Self::PointerType        => "DW_TAG_pointer_type",
            Self::StructureType      => "DW_TAG_structure_type",
            Self::UnionType          => "DW_TAG_union_type",
            Self::ClassType          => "DW_TAG_class_type",
            Self::Typedef            => "DW_TAG_typedef",
            Self::EnumerationType    => "DW_TAG_enumeration_type",
            Self::Enumerator         => "DW_TAG_enumerator",
            Self::Member             => "DW_TAG_member",
            Self::FormalParameter    => "DW_TAG_formal_parameter",
            Self::ArrayType          => "DW_TAG_array_type",
            Self::Namespace          => "DW_TAG_namespace",
            Self::InlinedSubroutine  => "DW_TAG_inlined_subroutine",
            _                        => "DW_TAG_unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// DWARF attribute forms
// ---------------------------------------------------------------------------

/// A subset of DWARF attribute form codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DwarfForm {
    Addr        = 0x01,
    Block2      = 0x03,
    Block4      = 0x04,
    Data2       = 0x05,
    Data4       = 0x06,
    Data8       = 0x07,
    String      = 0x08,
    Block       = 0x09,
    Block1      = 0x0A,
    Data1       = 0x0B,
    Flag        = 0x0C,
    Sdata       = 0x0D,
    Strp        = 0x0E,
    Udata       = 0x0F,
    RefAddr     = 0x10,
    Ref1        = 0x11,
    Ref2        = 0x12,
    Ref4        = 0x13,
    Ref8        = 0x14,
    RefUdata    = 0x15,
    Indirect    = 0x16,
    SecOffset   = 0x17,
    Exprloc     = 0x18,
    FlagPresent = 0x19,
    RefSig8     = 0x20,
    Unknown(u8),
}

impl DwarfForm {
    #[must_use] 
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0x01 => Self::Addr,
            0x05 => Self::Data2,
            0x06 => Self::Data4,
            0x07 => Self::Data8,
            0x08 => Self::String,
            0x0B => Self::Data1,
            0x0C => Self::Flag,
            0x0D => Self::Sdata,
            0x0E => Self::Strp,
            0x0F => Self::Udata,
            0x11 => Self::Ref1,
            0x12 => Self::Ref2,
            0x13 => Self::Ref4,
            0x14 => Self::Ref8,
            0x17 => Self::SecOffset,
            0x18 => Self::Exprloc,
            0x19 => Self::FlagPresent,
            other => Self::Unknown(other),
        }
    }

    /// Map a 16-bit DWARF form code to a [`DwarfForm`].
    ///
    /// Values that fit in a `u8` use the same mapping as [`Self::from_u8`].
    /// Higher values are returned as [`DwarfForm::Unknown`] with the low byte.
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        let lo = v.to_le_bytes()[0]; // always the low byte
        if v <= 0xFF {
            Self::from_u8(lo)
        } else {
            Self::Unknown(lo)
        }
    }
}

// ---------------------------------------------------------------------------
// DWARF attribute values
// ---------------------------------------------------------------------------

/// The decoded value of a single DWARF attribute.
#[derive(Debug, Clone)]
pub enum DwarfValue {
    Uint(u64),
    Sint(i64),
    Bytes(Vec<u8>),
    Str(String),
    Ref(u64),
    Flag(bool),
    Address(u64),
}

impl DwarfValue {
    /// Returns the inner unsigned integer if this is [`DwarfValue::Uint`] or [`DwarfValue::Address`].
    #[must_use] 
    pub const fn as_uint(&self) -> Option<u64> {
        match self {
            Self::Uint(v) | Self::Address(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns the inner string if this is [`DwarfValue::Str`].
    #[must_use] 
    pub const fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// DWARF abbreviation table entry
// ---------------------------------------------------------------------------

/// A single abbreviation declaration from `.debug_abbrev`.
#[derive(Debug, Clone)]
pub struct AbbrevEntry {
    /// Abbreviation code (1-based, non-zero).
    pub code: u64,
    /// DWARF tag for this entry.
    pub tag: DwarfTag,
    /// Whether this entry has children.
    pub has_children: bool,
    /// Ordered list of (attribute name, form) pairs.
    pub attributes: Vec<(u16, DwarfForm)>,
}

// ---------------------------------------------------------------------------
// DWARF information entry (DIE)
// ---------------------------------------------------------------------------

/// A single Debugging Information Entry (DIE) from `.debug_info`.
#[derive(Debug, Clone)]
pub struct DwarfEntry {
    /// Byte offset within the `.debug_info` section.
    pub offset: usize,
    /// Abbreviation code used (0 = null DIE).
    pub abbrev_code: u64,
    /// DWARF tag.
    pub tag: DwarfTag,
    /// Decoded attribute map (attribute ID → value).
    pub attributes: HashMap<u16, DwarfValue>,
    /// Child entries (if `has_children` was set in the abbreviation).
    pub children: Vec<Self>,
    /// Nesting depth within its compile unit.
    pub depth: usize,
}

impl DwarfEntry {
    /// Returns the value of `DW_AT_name` (0x03) if present.
    #[must_use] 
    pub fn name(&self) -> Option<&str> {
        self.attributes.get(&0x03)?.as_str()
    }

    /// Returns the value of `DW_AT_low_pc` (0x11) as an address.
    #[must_use] 
    pub fn low_pc(&self) -> Option<u64> {
        self.attributes.get(&0x11)?.as_uint()
    }

    /// Returns the value of `DW_AT_high_pc` (0x12).
    #[must_use] 
    pub fn high_pc(&self) -> Option<u64> {
        self.attributes.get(&0x12)?.as_uint()
    }

    /// Returns `true` if this DIE represents a function-like construct.
    #[must_use] 
    pub const fn is_function(&self) -> bool {
        matches!(self.tag, DwarfTag::Subprogram | DwarfTag::InlinedSubroutine)
    }
}

// ---------------------------------------------------------------------------
// DWARF compile unit
// ---------------------------------------------------------------------------

/// One DWARF compile unit from `.debug_info`.
#[derive(Debug, Clone)]
pub struct DwarfUnit {
    /// Byte offset of this unit's header within `.debug_info`.
    pub offset: usize,
    /// Total length of the unit (including the length field).
    pub unit_length: u64,
    /// DWARF version (2, 3, 4, or 5).
    pub version: u16,
    /// Offset into `.debug_abbrev` for this unit's abbreviation table.
    pub debug_abbrev_offset: u64,
    /// Address size in bytes (4 for 32-bit, 8 for 64-bit).
    pub address_size: u8,
    /// Whether this unit uses the 64-bit DWARF format.
    pub is_64bit_format: bool,
    /// Top-level DIE for this unit (always a compile-unit or type-unit DIE).
    pub root: Option<DwarfEntry>,
    /// Flat list of all DIEs in this unit (pre-order, includes root).
    pub all_entries: Vec<DwarfEntry>,
}

impl DwarfUnit {
    /// Returns the compile unit's producer string (`DW_AT_producer`), if present.
    #[must_use] 
    pub fn producer(&self) -> Option<&str> {
        self.root.as_ref()?.attributes.get(&0x25)?.as_str()
    }

    /// Returns the compile unit's source file name (`DW_AT_name`), if present.
    #[must_use] 
    pub fn source_file(&self) -> Option<&str> {
        self.root.as_ref()?.name()
    }

    /// Returns the compile directory (`DW_AT_comp_dir`, attribute 0x1B), if present.
    #[must_use] 
    pub fn comp_dir(&self) -> Option<&str> {
        self.root.as_ref()?.attributes.get(&0x1B)?.as_str()
    }

    /// Returns all function DIEs (subprograms) found in this unit.
    #[must_use] 
    pub fn functions(&self) -> Vec<&DwarfEntry> {
        self.all_entries.iter().filter(|e| e.is_function()).collect()
    }

    /// Returns all variable DIEs found in this unit.
    #[must_use] 
    pub fn variables(&self) -> Vec<&DwarfEntry> {
        self.all_entries
            .iter()
            .filter(|e| e.tag == DwarfTag::Variable)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Reader state
// ---------------------------------------------------------------------------

/// Error type for DWARF parsing failures.
#[derive(Debug, Clone)]
pub struct DwarfError(pub String);

impl std::fmt::Display for DwarfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DWARF parse error: {}", self.0)
    }
}

impl std::error::Error for DwarfError {}

/// Cursor-based byte reader for a section slice.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    const fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn read_u8(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn read_u16_le(&mut self) -> Option<u16> {
        let bytes: [u8; 2] = self.data.get(self.pos..self.pos + 2)?.try_into().ok()?;
        self.pos += 2;
        Some(u16::from_le_bytes(bytes))
    }

    fn read_u32_le(&mut self) -> Option<u32> {
        let bytes: [u8; 4] = self.data.get(self.pos..self.pos + 4)?.try_into().ok()?;
        self.pos += 4;
        Some(u32::from_le_bytes(bytes))
    }

    fn read_u64_le(&mut self) -> Option<u64> {
        let bytes: [u8; 8] = self.data.get(self.pos..self.pos + 8)?.try_into().ok()?;
        self.pos += 8;
        Some(u64::from_le_bytes(bytes))
    }

    /// Read an unsigned LEB128 value.
    fn read_uleb128(&mut self) -> Option<u64> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.read_u8()?;
            result |= u64::from(byte & 0x7F) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                return Some(result);
            }
            if shift >= 64 {
                return None;
            }
        }
    }

    /// Read a signed LEB128 value.
    fn read_sleb128(&mut self) -> Option<i64> {
        let mut result: i64 = 0;
        let mut shift = 0i32;
        let mut byte;
        loop {
            byte = self.read_u8()?;
            result |= i64::from(byte & 0x7F) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
            if shift >= 64 {
                return None;
            }
        }
        if shift < 64 && (byte & 0x40) != 0 {
            result |= -(1i64 << shift);
        }
        Some(result)
    }

    /// Read a NUL-terminated string.
    fn read_cstr(&mut self) -> Option<String> {
        let start = self.pos;
        while self.pos < self.data.len() && self.data[self.pos] != 0 {
            self.pos += 1;
        }
        if self.pos >= self.data.len() {
            return None;
        }
        let s = String::from_utf8_lossy(&self.data[start..self.pos]).into_owned();
        self.pos += 1; // consume NUL
        Some(s)
    }

    pub fn skip(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.data.len());
    }

    fn read_bytes(&mut self, n: usize) -> Option<Vec<u8>> {
        let end = self.pos.checked_add(n)?;
        if end > self.data.len() {
            return None;
        }
        let v = self.data[self.pos..end].to_vec();
        self.pos = end;
        Some(v)
    }
}

// ---------------------------------------------------------------------------
// Abbreviation table parser
// ---------------------------------------------------------------------------

fn parse_abbrev_table(abbrev_data: &[u8], abbrev_offset: u64) -> HashMap<u64, AbbrevEntry> {
    let mut map = HashMap::new();
    let start = usize::try_from(abbrev_offset).unwrap_or(usize::MAX);
    if start >= abbrev_data.len() {
        return map;
    }
    let mut cur = Cursor::new(&abbrev_data[start..]);
    if cur.remaining() == 0 {
        return map;
    }
    while let Some(code) = cur.read_uleb128() {
        if code == 0 {
            break;
        }
        let Some(tag_raw) = cur.read_uleb128() else { break };
        let Some(has_children_byte) = cur.read_u8() else { break };
        let tag = DwarfTag::from_u16(u16::try_from(tag_raw).unwrap_or(u16::MAX));
        let has_children = has_children_byte == 1;
        let mut attributes = Vec::new();
        while let Some(attr_name) = cur.read_uleb128() {
            let Some(attr_form) = cur.read_uleb128() else { break };
            if attr_name == 0 && attr_form == 0 {
                break;
            }
            let attr_name16 = u16::try_from(attr_name).unwrap_or(u16::MAX);
            let attr_form16 = u16::try_from(attr_form).unwrap_or(u16::MAX);
            attributes.push((attr_name16, DwarfForm::from_u16(attr_form16)));
        }
        map.insert(
            code,
            AbbrevEntry {
                code,
                tag,
                has_children,
                attributes,
            },
        );
    }
    map
}

// ---------------------------------------------------------------------------
// Attribute value decoder
// ---------------------------------------------------------------------------

fn read_attr_value(
    cur: &mut Cursor<'_>,
    form: DwarfForm,
    addr_size: u8,
    debug_str: Option<&[u8]>,
    is_64bit_format: bool,
) -> Option<DwarfValue> {
    match form {
        DwarfForm::Addr => {
            let v = if addr_size == 8 {
                cur.read_u64_le()?
            } else {
                u64::from(cur.read_u32_le()?)
            };
            Some(DwarfValue::Address(v))
        }
        DwarfForm::Data1 => Some(DwarfValue::Uint(u64::from(cur.read_u8()?))),
        DwarfForm::Data2 => Some(DwarfValue::Uint(u64::from(cur.read_u16_le()?))),
        DwarfForm::Data4 => Some(DwarfValue::Uint(u64::from(cur.read_u32_le()?))),
        DwarfForm::Data8 => Some(DwarfValue::Uint(cur.read_u64_le()?)),
        DwarfForm::Udata => Some(DwarfValue::Uint(cur.read_uleb128()?)),
        DwarfForm::Sdata => Some(DwarfValue::Sint(cur.read_sleb128()?)),
        DwarfForm::String => Some(DwarfValue::Str(cur.read_cstr()?)),
        DwarfForm::Strp => {
            let off = if is_64bit_format {
                cur.read_u64_le()?
            } else {
                u64::from(cur.read_u32_le()?)
            };
            let s = debug_str.and_then(|ds| {
                let start = usize::try_from(off).ok()?;
                if start >= ds.len() {
                    return None;
                }
                let end = ds[start..].iter().position(|&b| b == 0).map(|p| start + p)?;
                Some(String::from_utf8_lossy(&ds[start..end]).into_owned())
            }).unwrap_or_default();
            Some(DwarfValue::Str(s))
        }
        DwarfForm::Flag => Some(DwarfValue::Flag(cur.read_u8()? != 0)),
        DwarfForm::FlagPresent => Some(DwarfValue::Flag(true)),
        DwarfForm::Ref1 => Some(DwarfValue::Ref(u64::from(cur.read_u8()?))),
        DwarfForm::Ref2 => Some(DwarfValue::Ref(u64::from(cur.read_u16_le()?))),
        DwarfForm::Ref4 => Some(DwarfValue::Ref(u64::from(cur.read_u32_le()?))),
        DwarfForm::Ref8 | DwarfForm::RefSig8 => Some(DwarfValue::Ref(cur.read_u64_le()?)),
        DwarfForm::RefUdata => Some(DwarfValue::Ref(cur.read_uleb128()?)),
        DwarfForm::SecOffset => {
            let v = if is_64bit_format {
                cur.read_u64_le()?
            } else {
                u64::from(cur.read_u32_le()?)
            };
            Some(DwarfValue::Uint(v))
        }
        DwarfForm::Exprloc => {
            let len = usize::try_from(cur.read_uleb128()?).unwrap_or(0);
            let bytes = cur.read_bytes(len)?;
            Some(DwarfValue::Bytes(bytes))
        }
        DwarfForm::Block1 => {
            let len = usize::from(cur.read_u8()?);
            Some(DwarfValue::Bytes(cur.read_bytes(len)?))
        }
        DwarfForm::Block2 => {
            let len = usize::from(cur.read_u16_le()?);
            Some(DwarfValue::Bytes(cur.read_bytes(len)?))
        }
        DwarfForm::Block4 => {
            let len = usize::try_from(cur.read_u32_le()?).unwrap_or(0);
            Some(DwarfValue::Bytes(cur.read_bytes(len)?))
        }
        DwarfForm::Block => {
            let len = usize::try_from(cur.read_uleb128()?).unwrap_or(0);
            Some(DwarfValue::Bytes(cur.read_bytes(len)?))
        }
        DwarfForm::RefAddr => {
            let v = if is_64bit_format {
                cur.read_u64_le()?
            } else {
                u64::from(cur.read_u32_le()?)
            };
            Some(DwarfValue::Ref(v))
        }
        DwarfForm::Unknown(n) => {
            // Skip over unknown forms to allow continued parsing; size is not
            // known statically so we consume 1 byte as a best-effort advance.
            let _ = n;
            cur.skip(1);
            None
        }
        DwarfForm::Indirect => None,
    }
}

// ---------------------------------------------------------------------------
// DIE tree parser
// ---------------------------------------------------------------------------

struct DieParseCtx<'a> {
    abbrevs: &'a HashMap<u64, AbbrevEntry>,
    addr_size: u8,
    str_data: Option<&'a [u8]>,
    is_64bit_format: bool,
    unit_start_offset: usize,
}

fn parse_dies(
    cur: &mut Cursor<'_>,
    ctx: &DieParseCtx<'_>,
    depth: usize,
    max_depth: usize,
) -> Vec<DwarfEntry> {
    let DieParseCtx { abbrevs, addr_size, str_data, is_64bit_format, unit_start_offset } = ctx;
    let mut entries = Vec::new();
    if depth > max_depth {
        return entries;
    }
    loop {
        let offset = unit_start_offset + cur.pos;
        let Some(code) = cur.read_uleb128() else { break };
        if code == 0 {
            // Null DIE signals end of sibling list
            break;
        }
        let Some(abbrev) = abbrevs.get(&code) else {
            // Unknown abbrev code: cannot continue parsing this chain
            break;
        };
        let tag = abbrev.tag;
        let has_children = abbrev.has_children;
        let mut attr_map: HashMap<u16, DwarfValue> = HashMap::new();
        for &(attr_name, form) in &abbrev.attributes {
            if let Some(val) = read_attr_value(cur, form, *addr_size, *str_data, *is_64bit_format) {
                attr_map.insert(attr_name, val);
            }
        }
        let children = if has_children && depth < max_depth {
            parse_dies(cur, ctx, depth + 1, max_depth)
        } else if has_children {
            // Drain children without collecting them
            drain_children(cur, abbrevs, *addr_size, *str_data, *is_64bit_format);
            Vec::new()
        } else {
            Vec::new()
        };
        entries.push(DwarfEntry {
            offset,
            abbrev_code: code,
            tag,
            attributes: attr_map,
            children,
            depth,
        });
    }
    entries
}

fn drain_children(
    cur: &mut Cursor<'_>,
    abbrevs: &HashMap<u64, AbbrevEntry>,
    addr_size: u8,
    debug_str: Option<&[u8]>,
    is_64bit_format: bool,
) {
    while let Some(code) = cur.read_uleb128() {
        if code == 0 {
            break;
        }
        let Some(abbrev) = abbrevs.get(&code) else {
            break;
        };
        for &(_attr_name, form) in &abbrev.attributes {
            let _ = read_attr_value(cur, form, addr_size, debug_str, is_64bit_format);
        }
        if abbrev.has_children {
            drain_children(cur, abbrevs, addr_size, debug_str, is_64bit_format);
        }
    }
}

fn flatten_entries(root: &[DwarfEntry]) -> Vec<DwarfEntry> {
    let mut flat = Vec::new();
    for e in root {
        flat.push(e.clone());
        flat.extend(flatten_entries(&e.children));
    }
    flat
}

// ---------------------------------------------------------------------------
// ElfDwarfReader — public API
// ---------------------------------------------------------------------------

/// Reads and parses DWARF debug information from raw ELF section data.
///
/// # Usage
///
/// ```
/// use rustre_loader_elf::elf_dwarf_reader::ElfDwarfReader;
///
/// // In practice these are the raw `.debug_info` / `.debug_abbrev` /
/// // `.debug_str` section bytes; empty input simply yields no compile units.
/// let reader = ElfDwarfReader::new(&[], &[], None);
/// if let Ok(result) = reader.read_debug_info() {
///     for unit in &result.units {
///         println!("CU: {:?}", unit.source_file());
///     }
/// }
/// ```
///
/// The example was marked `rust,ignore` until 2026-07-29, so it had never been
/// compiled — and it did not: the third parameter is `Option<&[u8]>`, and it
/// was passing a bare `debug_str`. A public example is a claim about the API,
/// and an ignored one is an unverified claim; this one was in fact wrong.
pub struct ElfDwarfReader<'a> {
    info_data:   &'a [u8],
    abbrev_data: &'a [u8],
    strings:     Option<&'a [u8]>,
}

impl<'a> ElfDwarfReader<'a> {
    /// Create a new reader from raw section bytes.
    ///
    /// * `info_data`   — raw bytes of `.debug_info`
    /// * `abbrev_data` — raw bytes of `.debug_abbrev`
    /// * `strings`     — raw bytes of `.debug_str` (optional)
    #[must_use]
    pub const fn new(
        info_data:   &'a [u8],
        abbrev_data: &'a [u8],
        strings:     Option<&'a [u8]>,
    ) -> Self {
        Self { info_data, abbrev_data, strings }
    }

    /// Parse all compile units from `.debug_info`.
    ///
    /// # Errors
    /// Returns an error if the debug info is malformed.
    pub fn read_debug_info(&self) -> Result<DwarfReadResult, DwarfError> {
        let mut units = Vec::new();
        let mut cur = Cursor::new(self.info_data);

        while !cur.is_empty() {
            let unit_start = cur.pos;
            let Some(unit) = self.parse_unit(&mut cur, unit_start) else {
                break;
            };
            units.push(unit);
        }

        Ok(DwarfReadResult { units })
    }

    fn parse_unit(&self, cur: &mut Cursor<'_>, unit_start: usize) -> Option<DwarfUnit> {
        const MAX_DEPTH: usize = 64;
        // Determine 32-bit or 64-bit DWARF format
        let first_word = cur.read_u32_le()?;
        let (is_64bit_format, unit_length) = if first_word == 0xFFFF_FFFF {
            let len = cur.read_u64_le()?;
            (true, len)
        } else {
            (false, u64::from(first_word))
        };

        let header_end = cur.pos + usize::try_from(unit_length).unwrap_or(0);
        if header_end > self.info_data.len() {
            // Truncated unit — skip
            cur.pos = self.info_data.len();
            return None;
        }

        let version = cur.read_u16_le()?;
        let debug_abbrev_offset = if is_64bit_format {
            cur.read_u64_le()?
        } else {
            u64::from(cur.read_u32_le()?)
        };
        let address_size = cur.read_u8()?;

        let abbrevs = parse_abbrev_table(self.abbrev_data, debug_abbrev_offset);
        let dies_start = cur.pos;
        let unit_data = &self.info_data[dies_start..header_end.min(self.info_data.len())];
        let mut die_cur = Cursor::new(unit_data);

        let ctx = DieParseCtx {
            abbrevs: &abbrevs,
            addr_size: address_size,
            str_data: self.strings,
            is_64bit_format,
            unit_start_offset: dies_start,
        };
        let top_dies = parse_dies(&mut die_cur, &ctx, 0, MAX_DEPTH);

        cur.pos = header_end.min(self.info_data.len());

        let root = top_dies.first().cloned();
        let all_entries = flatten_entries(&top_dies);

        Some(DwarfUnit {
            offset: unit_start,
            unit_length,
            version,
            debug_abbrev_offset,
            address_size,
            is_64bit_format,
            root,
            all_entries,
        })
    }
}

// ---------------------------------------------------------------------------
// DwarfReadResult
// ---------------------------------------------------------------------------

/// Result of parsing all DWARF compile units from an ELF binary.
#[derive(Debug, Clone)]
pub struct DwarfReadResult {
    /// All compile units found in `.debug_info`.
    pub units: Vec<DwarfUnit>,
}

impl DwarfReadResult {
    /// Returns an iterator over all function DIEs across all compile units.
    pub fn all_functions(&self) -> impl Iterator<Item = &DwarfEntry> {
        self.units.iter().flat_map(|u| u.functions())
    }

    /// Returns all compile unit source file names.
    #[must_use] 
    pub fn source_files(&self) -> Vec<&str> {
        self.units.iter().filter_map(|u| u.source_file()).collect()
    }

    /// Returns the total number of DIEs across all units.
    #[must_use] 
    pub fn total_die_count(&self) -> usize {
        self.units.iter().map(|u| u.all_entries.len()).sum()
    }

    /// Find a DIE by its absolute offset in `.debug_info`.
    #[must_use] 
    pub fn find_by_offset(&self, offset: usize) -> Option<&DwarfEntry> {
        for unit in &self.units {
            if let Some(e) = unit.all_entries.iter().find(|e| e.offset == offset) {
                return Some(e);
            }
        }
        None
    }
}

/// Top-level convenience function: parse DWARF from named raw sections.
///
/// Returns `Ok(DwarfReadResult)` on success or a [`DwarfError`] if the
/// `.debug_info` section is absent or corrupt.
///
/// # Errors
/// Returns an error if `debug_info` or `debug_abbrev` is empty or if parsing fails.
pub fn read_debug_info<'a>(
    debug_info:   &'a [u8],
    debug_abbrev: &'a [u8],
    debug_str:    Option<&'a [u8]>,
) -> Result<DwarfReadResult, DwarfError> {
    if debug_info.is_empty() {
        return Err(DwarfError(".debug_info section is empty".into()));
    }
    if debug_abbrev.is_empty() {
        return Err(DwarfError(".debug_abbrev section is empty".into()));
    }
    ElfDwarfReader::new(debug_info, debug_abbrev, debug_str).read_debug_info()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_uleb128(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (v & 0x7F) as u8;
            v >>= 7;
            if v != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if v == 0 {
                break;
            }
        }
        out
    }

    #[test]
    fn test_empty_debug_info_returns_error() {
        let result = read_debug_info(&[], &[], None);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_abbrev_returns_error() {
        let result = read_debug_info(&[0u8; 16], &[], None);
        assert!(result.is_err());
    }

    #[test]
    fn test_dwarf_tag_compile_unit() {
        assert_eq!(DwarfTag::from_u16(0x11), DwarfTag::CompileUnit);
        assert_eq!(DwarfTag::CompileUnit.name(), "DW_TAG_compile_unit");
    }

    #[test]
    fn test_dwarf_tag_subprogram() {
        assert_eq!(DwarfTag::from_u16(0x2E), DwarfTag::Subprogram);
    }

    #[test]
    fn test_dwarf_tag_unknown() {
        assert_eq!(DwarfTag::from_u16(0xFFFF), DwarfTag::Unknown(0xFFFF));
    }

    #[test]
    fn test_dwarf_form_from_u8() {
        assert_eq!(DwarfForm::from_u8(0x08), DwarfForm::String);
        assert_eq!(DwarfForm::from_u8(0x0E), DwarfForm::Strp);
    }

    #[test]
    fn test_dwarf_value_as_uint() {
        let v = DwarfValue::Uint(42);
        assert_eq!(v.as_uint(), Some(42));
        let v2 = DwarfValue::Str("hello".into());
        assert_eq!(v2.as_uint(), None);
    }

    #[test]
    fn test_dwarf_value_as_str() {
        let v = DwarfValue::Str("main".into());
        assert_eq!(v.as_str(), Some("main"));
    }

    #[test]
    fn test_cursor_uleb128() {
        let bytes = make_uleb128(300);
        let mut cur = Cursor::new(&bytes);
        assert_eq!(cur.read_uleb128(), Some(300u64));
    }

    #[test]
    fn test_cursor_sleb128_positive() {
        // sleb128 of 127 requires explicit zero continuation byte (single-byte 0x7F is -1)
        let bytes = [0xFFu8, 0x00];
        let mut cur = Cursor::new(&bytes);
        assert_eq!(cur.read_sleb128(), Some(127i64));
    }

    #[test]
    fn test_cursor_cstr() {
        let data = b"hello\x00world\x00";
        let mut cur = Cursor::new(data);
        assert_eq!(cur.read_cstr(), Some("hello".to_string()));
        assert_eq!(cur.read_cstr(), Some("world".to_string()));
    }

    #[test]
    fn test_parse_abbrev_table_empty() {
        // Just a single zero byte = empty table
        let abbrev = [0u8];
        let map = parse_abbrev_table(&abbrev, 0);
        assert!(map.is_empty());
    }

    #[test]
    fn test_read_debug_info_minimal_cu() {
        // Build a minimal DWARF32 compile unit:
        //   - unit_length: u32  (total bytes after length field)
        //   - version: u16      (4)
        //   - abbrev_offset: u32 (0)
        //   - address_size: u8  (8)
        //   - DIEs: one null DIE (uleb128 = 0x00)
        // A single zero byte = valid empty abbrev table (a fully empty slice is rejected)
        let abbrev: Vec<u8> = vec![0u8];

        // Build a single compile unit with no real DIEs (just the null terminator)
        let mut info: Vec<u8> = Vec::new();
        // unit_length (not counting the 4-byte length field itself)
        // version(2) + abbrev_offset(4) + addr_size(1) + null_die(1) = 8
        let unit_length: u32 = 8;
        info.extend_from_slice(&unit_length.to_le_bytes()); // unit_length
        info.extend_from_slice(&4u16.to_le_bytes());         // version
        info.extend_from_slice(&0u32.to_le_bytes());         // abbrev_offset
        info.push(8u8);                                       // address_size
        info.push(0u8);                                       // null DIE

        let result = read_debug_info(&info, &abbrev, None).expect("should parse");
        assert_eq!(result.units.len(), 1);
        let unit = &result.units[0];
        assert_eq!(unit.version, 4);
        assert_eq!(unit.address_size, 8);
        assert!(!unit.is_64bit_format);
        assert_eq!(unit.all_entries.len(), 0); // null DIE produces no entries
    }

    #[test]
    fn test_result_source_files_empty() {
        let result = DwarfReadResult { units: vec![] };
        assert!(result.source_files().is_empty());
        assert_eq!(result.total_die_count(), 0);
    }

    #[test]
    fn test_die_is_function() {
        let e = DwarfEntry {
            offset: 0,
            abbrev_code: 1,
            tag: DwarfTag::Subprogram,
            attributes: HashMap::new(),
            children: vec![],
            depth: 0,
        };
        assert!(e.is_function());
    }

    #[test]
    fn test_die_name_returns_none_when_missing() {
        let e = DwarfEntry {
            offset: 0,
            abbrev_code: 1,
            tag: DwarfTag::Variable,
            attributes: HashMap::new(),
            children: vec![],
            depth: 0,
        };
        assert!(e.name().is_none());
        assert!(e.low_pc().is_none());
    }
}
