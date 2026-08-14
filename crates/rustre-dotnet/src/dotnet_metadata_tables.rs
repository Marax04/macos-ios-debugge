// dotnet_metadata_tables.rs — Full .NET metadata table parser
// Covers all 45 ECMA-335 metadata tables, coded indexes, heap readers,
// and row-level parsers.

use std::collections::HashMap;
use std::fmt;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum MetadataError {
    OutOfBounds { offset: usize, size: usize, table: &'static str },
    InvalidSignature(u32),
    UnknownTable(u8),
    HeapOffsetOob { heap: &'static str, offset: usize },
    InvalidUtf8 { offset: usize },
    InvalidCodedIndex { tag: u8, kind: &'static str },
}

impl fmt::Display for MetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfBounds { offset, size, table } =>
                write!(f, "out-of-bounds read at 0x{offset:08x} (size {size}) in table {table}"),
            Self::InvalidSignature(sig) =>
                write!(f, "invalid metadata signature 0x{sig:08x}"),
            Self::UnknownTable(id) =>
                write!(f, "unknown table id 0x{id:02x}"),
            Self::HeapOffsetOob { heap, offset } =>
                write!(f, "heap '{heap}' offset 0x{offset:x} out of bounds"),
            Self::InvalidUtf8 { offset } =>
                write!(f, "invalid UTF-8 at heap offset 0x{offset:x}"),
            Self::InvalidCodedIndex { tag, kind } =>
                write!(f, "invalid coded index tag {tag} for {kind}"),
        }
    }
}

pub type MetaResult<T> = Result<T, MetadataError>;

// ─── MetadataTable enum ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum MetadataTable {
    Module                = 0x00,
    TypeRef               = 0x01,
    TypeDef               = 0x02,
    Field                 = 0x04,
    MethodDef             = 0x06,
    Param                 = 0x08,
    InterfaceImpl         = 0x09,
    MemberRef             = 0x0A,
    Constant              = 0x0B,
    CustomAttribute       = 0x0C,
    FieldMarshal          = 0x0D,
    DeclSecurity          = 0x0E,
    ClassLayout           = 0x0F,
    FieldLayout           = 0x10,
    StandAloneSig         = 0x11,
    EventMap              = 0x12,
    Event                 = 0x14,
    PropertyMap           = 0x15,
    Property              = 0x17,
    MethodSemantics       = 0x18,
    MethodImpl            = 0x19,
    ModuleRef             = 0x1A,
    TypeSpec              = 0x1B,
    ImplMap               = 0x1C,
    FieldRva              = 0x1D,
    Assembly              = 0x20,
    AssemblyProcessor     = 0x21,
    AssemblyOS            = 0x22,
    AssemblyRef           = 0x23,
    AssemblyRefProcessor  = 0x24,
    AssemblyRefOS         = 0x25,
    File                  = 0x26,
    ExportedType          = 0x27,
    ManifestResource      = 0x28,
    NestedClass           = 0x29,
    GenericParam          = 0x2A,
    MethodSpec            = 0x2B,
    GenericParamConstraint= 0x2C,
}

impl MetadataTable {
    #[must_use] 
    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            0x00 => Some(Self::Module),
            0x01 => Some(Self::TypeRef),
            0x02 => Some(Self::TypeDef),
            0x04 => Some(Self::Field),
            0x06 => Some(Self::MethodDef),
            0x08 => Some(Self::Param),
            0x09 => Some(Self::InterfaceImpl),
            0x0A => Some(Self::MemberRef),
            0x0B => Some(Self::Constant),
            0x0C => Some(Self::CustomAttribute),
            0x0D => Some(Self::FieldMarshal),
            0x0E => Some(Self::DeclSecurity),
            0x0F => Some(Self::ClassLayout),
            0x10 => Some(Self::FieldLayout),
            0x11 => Some(Self::StandAloneSig),
            0x12 => Some(Self::EventMap),
            0x14 => Some(Self::Event),
            0x15 => Some(Self::PropertyMap),
            0x17 => Some(Self::Property),
            0x18 => Some(Self::MethodSemantics),
            0x19 => Some(Self::MethodImpl),
            0x1A => Some(Self::ModuleRef),
            0x1B => Some(Self::TypeSpec),
            0x1C => Some(Self::ImplMap),
            0x1D => Some(Self::FieldRva),
            0x20 => Some(Self::Assembly),
            0x21 => Some(Self::AssemblyProcessor),
            0x22 => Some(Self::AssemblyOS),
            0x23 => Some(Self::AssemblyRef),
            0x24 => Some(Self::AssemblyRefProcessor),
            0x25 => Some(Self::AssemblyRefOS),
            0x26 => Some(Self::File),
            0x27 => Some(Self::ExportedType),
            0x28 => Some(Self::ManifestResource),
            0x29 => Some(Self::NestedClass),
            0x2A => Some(Self::GenericParam),
            0x2B => Some(Self::MethodSpec),
            0x2C => Some(Self::GenericParamConstraint),
            _ => None,
        }
    }

    #[must_use] 
    pub const fn id(self) -> u8 { self as u8 }

    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::Module => "Module",
            Self::TypeRef => "TypeRef",
            Self::TypeDef => "TypeDef",
            Self::Field => "Field",
            Self::MethodDef => "MethodDef",
            Self::Param => "Param",
            Self::InterfaceImpl => "InterfaceImpl",
            Self::MemberRef => "MemberRef",
            Self::Constant => "Constant",
            Self::CustomAttribute => "CustomAttribute",
            Self::FieldMarshal => "FieldMarshal",
            Self::DeclSecurity => "DeclSecurity",
            Self::ClassLayout => "ClassLayout",
            Self::FieldLayout => "FieldLayout",
            Self::StandAloneSig => "StandAloneSig",
            Self::EventMap => "EventMap",
            Self::Event => "Event",
            Self::PropertyMap => "PropertyMap",
            Self::Property => "Property",
            Self::MethodSemantics => "MethodSemantics",
            Self::MethodImpl => "MethodImpl",
            Self::ModuleRef => "ModuleRef",
            Self::TypeSpec => "TypeSpec",
            Self::ImplMap => "ImplMap",
            Self::FieldRva => "FieldRva",
            Self::Assembly => "Assembly",
            Self::AssemblyProcessor => "AssemblyProcessor",
            Self::AssemblyOS => "AssemblyOS",
            Self::AssemblyRef => "AssemblyRef",
            Self::AssemblyRefProcessor => "AssemblyRefProcessor",
            Self::AssemblyRefOS => "AssemblyRefOS",
            Self::File => "File",
            Self::ExportedType => "ExportedType",
            Self::ManifestResource => "ManifestResource",
            Self::NestedClass => "NestedClass",
            Self::GenericParam => "GenericParam",
            Self::MethodSpec => "MethodSpec",
            Self::GenericParamConstraint => "GenericParamConstraint",
        }
    }

    #[must_use] 
    pub const fn all() -> &'static [Self] {
        &[
            Self::Module, Self::TypeRef, Self::TypeDef, Self::Field,
            Self::MethodDef, Self::Param, Self::InterfaceImpl, Self::MemberRef,
            Self::Constant, Self::CustomAttribute, Self::FieldMarshal,
            Self::DeclSecurity, Self::ClassLayout, Self::FieldLayout,
            Self::StandAloneSig, Self::EventMap, Self::Event, Self::PropertyMap,
            Self::Property, Self::MethodSemantics, Self::MethodImpl,
            Self::ModuleRef, Self::TypeSpec, Self::ImplMap, Self::FieldRva,
            Self::Assembly, Self::AssemblyProcessor, Self::AssemblyOS,
            Self::AssemblyRef, Self::AssemblyRefProcessor, Self::AssemblyRefOS,
            Self::File, Self::ExportedType, Self::ManifestResource,
            Self::NestedClass, Self::GenericParam, Self::MethodSpec,
            Self::GenericParamConstraint,
        ]
    }
}

// ─── Coded Index Types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodedIndexKind {
    TypeDefOrRef,
    HasConstant,
    HasCustomAttribute,
    HasFieldMarshal,
    HasDeclSecurity,
    MemberRefParent,
    HasSemantics,
    MethodDefOrRef,
    MemberForwarded,
    Implementation,
    CustomAttributeType,
    ResolutionScope,
    TypeOrMethodDef,
}

impl CodedIndexKind {
    /// Number of tag bits for this coded-index kind.
    #[must_use] 
    pub const fn tag_bits(self) -> u32 {
        match self {
            Self::HasCustomAttribute  => 5,
            Self::HasFieldMarshal | Self::HasSemantics | Self::MethodDefOrRef | Self::MemberForwarded | Self::TypeOrMethodDef     => 1,
            Self::MemberRefParent | Self::CustomAttributeType     => 3,
            Self::TypeDefOrRef | Self::HasConstant | Self::HasDeclSecurity | Self::Implementation | Self::ResolutionScope     => 2,
            }
    }

    /// Tables referenced by this coded-index kind (in tag order).
    #[must_use] 
    pub const fn tables(self) -> &'static [Option<MetadataTable>] {
        match self {
            Self::TypeDefOrRef => &[
                Some(MetadataTable::TypeDef),
                Some(MetadataTable::TypeRef),
                Some(MetadataTable::TypeSpec),
                None,
            ],
            Self::HasConstant => &[
                Some(MetadataTable::Field),
                Some(MetadataTable::Param),
                Some(MetadataTable::Property),
                None,
            ],
            Self::HasCustomAttribute => &[
                Some(MetadataTable::MethodDef),
                Some(MetadataTable::Field),
                Some(MetadataTable::TypeRef),
                Some(MetadataTable::TypeDef),
                Some(MetadataTable::Param),
                Some(MetadataTable::InterfaceImpl),
                Some(MetadataTable::MemberRef),
                Some(MetadataTable::Module),
                None, // Permission
                Some(MetadataTable::Property),
                Some(MetadataTable::Event),
                Some(MetadataTable::StandAloneSig),
                Some(MetadataTable::ModuleRef),
                Some(MetadataTable::TypeSpec),
                Some(MetadataTable::Assembly),
                Some(MetadataTable::AssemblyRef),
                Some(MetadataTable::File),
                Some(MetadataTable::ExportedType),
                Some(MetadataTable::ManifestResource),
                Some(MetadataTable::GenericParam),
                Some(MetadataTable::GenericParamConstraint),
                Some(MetadataTable::MethodSpec),
                None, None, None, None, None, None, None, None, None, None,
            ],
            Self::HasFieldMarshal => &[
                Some(MetadataTable::Field),
                Some(MetadataTable::Param),
            ],
            Self::HasDeclSecurity => &[
                Some(MetadataTable::TypeDef),
                Some(MetadataTable::MethodDef),
                Some(MetadataTable::Assembly),
                None,
            ],
            Self::MemberRefParent => &[
                Some(MetadataTable::TypeDef),
                Some(MetadataTable::TypeRef),
                Some(MetadataTable::ModuleRef),
                Some(MetadataTable::MethodDef),
                Some(MetadataTable::TypeSpec),
                None, None, None,
            ],
            Self::HasSemantics => &[
                Some(MetadataTable::Event),
                Some(MetadataTable::Property),
            ],
            Self::MethodDefOrRef => &[
                Some(MetadataTable::MethodDef),
                Some(MetadataTable::MemberRef),
            ],
            Self::MemberForwarded => &[
                Some(MetadataTable::Field),
                Some(MetadataTable::MethodDef),
            ],
            Self::Implementation => &[
                Some(MetadataTable::File),
                Some(MetadataTable::AssemblyRef),
                Some(MetadataTable::ExportedType),
                None,
            ],
            Self::CustomAttributeType => &[
                None,
                None,
                Some(MetadataTable::MethodDef),
                Some(MetadataTable::MemberRef),
                None, None, None, None,
            ],
            Self::ResolutionScope => &[
                Some(MetadataTable::Module),
                Some(MetadataTable::ModuleRef),
                Some(MetadataTable::AssemblyRef),
                Some(MetadataTable::TypeRef),
            ],
            Self::TypeOrMethodDef => &[
                Some(MetadataTable::TypeDef),
                Some(MetadataTable::MethodDef),
            ],
        }
    }

    /// Decode a raw coded index into (table, 1-based row).
    /// # Errors
    /// Returns an error when the operation fails.
    pub fn decode(self, raw: u32) -> MetaResult<(MetadataTable, u32)> {
        let tag_bits = self.tag_bits();
        let mask = (1u32 << tag_bits) - 1;
        let tag = u8::try_from(raw & mask).unwrap_or(u8::MAX);
        let row = raw >> tag_bits;
        let tables = self.tables();
        let tbl_opt = tables.get(tag as usize).copied().flatten();
        tbl_opt.map_or(Err(MetadataError::InvalidCodedIndex { tag, kind: "unknown" }), |t| Ok((t, row)))
    }
}

// ─── Heap Sizes ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Default)]
pub struct HeapSizes {
    pub string_wide: bool,
    pub guid_wide:   bool,
    pub blob_wide:   bool,
}

impl HeapSizes {
    #[must_use] 
    pub const fn from_byte(b: u8) -> Self {
        Self {
            string_wide: (b & 0x01) != 0,
            guid_wide:   (b & 0x02) != 0,
            blob_wide:   (b & 0x04) != 0,
        }
    }

    #[must_use] 
    pub const fn string_index_size(self) -> usize { if self.string_wide { 4 } else { 2 } }
    #[must_use] 
    pub const fn guid_index_size(self)   -> usize { if self.guid_wide   { 4 } else { 2 } }
    #[must_use] 
    pub const fn blob_index_size(self)   -> usize { if self.blob_wide   { 4 } else { 2 } }
}

// ─── TableInfo ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TableInfo {
    pub table:    MetadataTable,
    pub row_count: u32,
    pub row_size:  usize,
    pub data_offset: usize,
}

// ─── Row Structs ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ModuleRow {
    pub generation: u16,
    pub name:       String,
    pub mv_id:      u32,
    pub enc_id:     u32,
    pub enc_base_id:u32,
}

#[derive(Debug, Clone)]
pub struct TypeRefRow {
    pub resolution_scope: u32,
    pub name:             String,
    pub namespace:        String,
}

#[derive(Debug, Clone)]
pub struct TypeDefRow {
    pub flags:           u32,
    pub name:            String,
    pub namespace:       String,
    pub extends:         u32,  // coded: TypeDefOrRef
    pub field_list:      u32,
    pub method_list:     u32,
}

impl TypeDefRow {
    #[must_use] 
    pub const fn is_interface(&self) -> bool   { (self.flags & 0x0000_0020) != 0 }
    #[must_use] 
    pub const fn is_abstract(&self) -> bool    { (self.flags & 0x0000_0080) != 0 }
    #[must_use] 
    pub const fn is_sealed(&self) -> bool      { (self.flags & 0x0000_0100) != 0 }
    #[must_use] 
    pub const fn is_value_type(&self) -> bool  { (self.flags & 0x0000_0008) != 0 }
    #[must_use] 
    pub const fn visibility(&self) -> u32      { self.flags & 0x0000_0007 }
}

#[derive(Debug, Clone)]
pub struct FieldRow {
    pub flags:  u16,
    pub name:   String,
    pub signature: Vec<u8>,
}

impl FieldRow {
    #[must_use] 
    pub const fn is_static(&self) -> bool    { (self.flags & 0x0010) != 0 }
    #[must_use] 
    pub const fn is_literal(&self) -> bool   { (self.flags & 0x0040) != 0 }
    #[must_use] 
    pub const fn is_init_only(&self) -> bool { (self.flags & 0x0020) != 0 }
}

#[derive(Debug, Clone)]
pub struct MethodDefRow {
    pub rva:         u32,
    pub impl_flags:  u16,
    pub flags:       u16,
    pub name:        String,
    pub signature:   Vec<u8>,
    pub param_list:  u32,
}

impl MethodDefRow {
    #[must_use] 
    pub const fn is_static(&self) -> bool     { (self.flags & 0x0008) != 0 }
    #[must_use] 
    pub const fn is_virtual(&self) -> bool    { (self.flags & 0x0040) != 0 }
    #[must_use] 
    pub const fn is_abstract(&self) -> bool   { (self.flags & 0x0010) != 0 }
    #[must_use] 
    pub const fn is_special_name(&self) -> bool { (self.flags & 0x0800) != 0 }
    #[must_use] 
    pub const fn visibility(&self) -> u16     { self.flags & 0x0007 }
}

#[derive(Debug, Clone)]
pub struct ParamRow {
    pub flags:    u16,
    pub sequence: u16,
    pub name:     String,
}

#[derive(Debug, Clone)]
pub struct InterfaceImplRow {
    pub class:     u32,
    pub interface: u32, // coded TypeDefOrRef
}

#[derive(Debug, Clone)]
pub struct MemberRefRow {
    pub class:     u32, // coded MemberRefParent
    pub name:      String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ConstantRow {
    pub kind:   u8,
    pub parent: u32, // coded HasConstant
    pub value:  Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CustomAttributeRow {
    pub parent: u32, // coded HasCustomAttribute
    pub kind:   u32, // coded CustomAttributeType
    pub value:  Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AssemblyRow {
    pub hash_alg:    u32,
    pub major:       u16,
    pub minor:       u16,
    pub build:       u16,
    pub revision:    u16,
    pub flags:       u32,
    pub public_key:  Vec<u8>,
    pub name:        String,
    pub culture:     String,
}

#[derive(Debug, Clone)]
pub struct AssemblyRefRow {
    pub major:          u16,
    pub minor:          u16,
    pub build:          u16,
    pub revision:       u16,
    pub flags:          u32,
    pub public_key_tok: Vec<u8>,
    pub name:           String,
    pub culture:        String,
    pub hash_value:     Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct GenericParamRow {
    pub number:   u16,
    pub flags:    u16,
    pub owner:    u32, // coded TypeOrMethodDef
    pub name:     String,
}

#[derive(Debug, Clone)]
pub struct NestedClassRow {
    pub nested_class:    u32,
    pub enclosing_class: u32,
}

#[derive(Debug, Clone)]
pub struct ClassLayoutRow {
    pub packing_size: u16,
    pub class_size:   u32,
    pub parent:       u32,
}

#[derive(Debug, Clone)]
pub struct MethodSemanticsRow {
    pub semantics: u16,
    pub method:    u32,
    pub association: u32, // coded HasSemantics
}

// ─── HeapReader ───────────────────────────────────────────────────────────────

pub struct HeapReader<'a> {
    strings: &'a [u8],
    blob:    &'a [u8],
    guid:    &'a [u8],
    us:      &'a [u8],
}

impl<'a> HeapReader<'a> {
    #[must_use] 
    pub const fn new(strings: &'a [u8], blob: &'a [u8], guid: &'a [u8], us: &'a [u8]) -> Self {
        Self { strings, blob, guid, us }
    }

    /// # Errors
    /// Returns an error when the operation fails.
    pub fn read_string(&self, offset: usize) -> MetaResult<String> {
        if offset >= self.strings.len() {
            return Err(MetadataError::HeapOffsetOob { heap: "#Strings", offset });
        }
        let tail = &self.strings[offset..];
        let nul = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        std::str::from_utf8(&tail[..nul])
            .map(std::borrow::ToOwned::to_owned)
            .map_err(|_| MetadataError::InvalidUtf8 { offset })
    }

    /// # Errors
    /// Returns an error when the operation fails.
    pub fn read_blob(&self, offset: usize) -> MetaResult<&'a [u8]> {
        if offset >= self.blob.len() {
            return Err(MetadataError::HeapOffsetOob { heap: "#Blob", offset });
        }
        let (len, consumed) = decode_compressed_uint(&self.blob[offset..])?;
        let start = offset + consumed;
        let end = start + len as usize;
        if end > self.blob.len() {
            return Err(MetadataError::HeapOffsetOob { heap: "#Blob", offset: end });
        }
        Ok(&self.blob[start..end])
    }

    /// # Errors
    /// Returns an error when the operation fails.
    pub fn read_guid(&self, idx: usize) -> MetaResult<[u8; 16]> {
        if idx == 0 { return Ok([0u8; 16]); }
        let offset = (idx - 1) * 16;
        if offset + 16 > self.guid.len() {
            return Err(MetadataError::HeapOffsetOob { heap: "#GUID", offset });
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&self.guid[offset..offset + 16]);
        Ok(arr)
    }

    /// # Errors
    /// Returns an error when the operation fails.
    pub fn read_us_string(&self, offset: usize) -> MetaResult<String> {
        if offset >= self.us.len() {
            return Err(MetadataError::HeapOffsetOob { heap: "#US", offset });
        }
        let (len, consumed) = decode_compressed_uint(&self.us[offset..])?;
        let start = offset + consumed;
        let byte_len = len as usize;
        if byte_len == 0 { return Ok(String::new()); }
        // Last byte is a "has non-ascii" marker; strip it
        let char_bytes = byte_len.saturating_sub(1);
        let slice = self.us.get(start..start + char_bytes)
            .ok_or(MetadataError::HeapOffsetOob { heap: "#US", offset: start + char_bytes })?;
        let chars: Vec<u16> = slice.chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16(&chars).map_err(|_| MetadataError::InvalidUtf8 { offset })
    }
}

// ─── Compressed integer decoder ───────────────────────────────────────────────

/// # Errors
/// Returns an error when the operation fails.
pub fn decode_compressed_uint(data: &[u8]) -> MetaResult<(u32, usize)> {
    if data.is_empty() {
        return Err(MetadataError::OutOfBounds { offset: 0, size: 1, table: "compressed-uint" });
    }
    let b0 = data[0];
    if b0 & 0x80 == 0 {
        return Ok((u32::from(b0), 1));
    }
    if data.len() < 2 {
        return Err(MetadataError::OutOfBounds { offset: 0, size: 2, table: "compressed-uint" });
    }
    if b0 & 0xC0 == 0x80 {
        let val = (u32::from(b0 & 0x3F) << 8) | u32::from(data[1]);
        return Ok((val, 2));
    }
    if data.len() < 4 {
        return Err(MetadataError::OutOfBounds { offset: 0, size: 4, table: "compressed-uint" });
    }
    let val = (u32::from(b0 & 0x1F) << 24)
        | (u32::from(data[1]) << 16)
        | (u32::from(data[2]) << 8)
        | u32::from(data[3]);
    Ok((val, 4))
}

// ─── Cursor ───────────────────────────────────────────────────────────────────

struct Cursor<'a> {
    data: &'a [u8],
    pos:  usize,
}

impl<'a> Cursor<'a> {
    const fn new(data: &'a [u8]) -> Self { Self { data, pos: 0 } }

    fn read_u8(&mut self) -> MetaResult<u8> {
        if self.pos >= self.data.len() {
            return Err(MetadataError::OutOfBounds { offset: self.pos, size: 1, table: "cursor" });
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u16(&mut self) -> MetaResult<u16> {
        if self.pos + 2 > self.data.len() {
            return Err(MetadataError::OutOfBounds { offset: self.pos, size: 2, table: "cursor" });
        }
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos+1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_u32(&mut self) -> MetaResult<u32> {
        if self.pos + 4 > self.data.len() {
            return Err(MetadataError::OutOfBounds { offset: self.pos, size: 4, table: "cursor" });
        }
        let v = u32::from_le_bytes(self.data[self.pos..self.pos+4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    fn read_index(&mut self, wide: bool) -> MetaResult<u32> {
        if wide { self.read_u32() } else { self.read_u16().map(u32::from) }
    }

    const fn position(&self) -> usize { self.pos }
}

// ─── TableReader ─────────────────────────────────────────────────────────────

pub struct TableReader<'a> {
    pub heap: HeapReader<'a>,
    pub heap_sizes: HeapSizes,
    pub row_counts: HashMap<u8, u32>,
    pub tables: HashMap<u8, TableInfo>,
    pub raw:  &'a [u8],
}

impl<'a> TableReader<'a> {
    /// # Errors
    /// Returns an error when the operation fails.
    pub fn new(
        metadata_stream: &'a [u8],
        strings: &'a [u8],
        blob: &'a [u8],
        guid: &'a [u8],
        us: &'a [u8],
    ) -> MetaResult<Self> {
        let mut cur = Cursor::new(metadata_stream);
        let _reserved  = cur.read_u32()?;  // 0
        let _major     = cur.read_u8()?;
        let _minor     = cur.read_u8()?;
        let heap_flags = cur.read_u8()?;
        let _rid       = cur.read_u8()?;
        let valid_lo   = cur.read_u32()?;
        let valid_hi   = cur.read_u32()?;
        let _sorted_lo = cur.read_u32()?;
        let _sorted_hi = cur.read_u32()?;
        let valid: u64 = (u64::from(valid_hi) << 32) | u64::from(valid_lo);
        let heap_sizes = HeapSizes::from_byte(heap_flags);

        let mut row_counts: HashMap<u8, u32> = HashMap::new();
        let mut present_tables: Vec<u8> = Vec::new();
        for bit in 0u8..64 {
            if (valid >> bit) & 1 == 1 {
                let count = cur.read_u32()?;
                row_counts.insert(bit, count);
                present_tables.push(bit);
            }
        }

        let heap = HeapReader::new(strings, blob, guid, us);
        let mut reader = Self {
            heap,
            heap_sizes,
            row_counts,
            tables: HashMap::new(),
            raw: metadata_stream,
        };

        let mut offset = cur.position();
        for tid in &present_tables {
            let rc = reader.row_counts[tid];
            let row_size = reader.compute_row_size(*tid);
            let tbl = MetadataTable::from_id(*tid)
                .ok_or(MetadataError::UnknownTable(*tid))?;
            reader.tables.insert(*tid, TableInfo {
                table: tbl,
                row_count: rc,
                row_size,
                data_offset: offset,
            });
            offset += rc as usize * row_size;
        }

        Ok(reader)
    }

    #[must_use] 
    pub fn row_count(&self, t: MetadataTable) -> u32 {
        self.row_counts.get(&t.id()).copied().unwrap_or(0)
    }

    /// Returns whether a simple table index needs 4 bytes (>= 65536 rows).
    #[must_use] 
    pub fn index_size(&self, t: MetadataTable) -> usize {
        if self.row_count(t) >= 0x10000 { 4 } else { 2 }
    }

    /// Returns whether a coded index needs 4 bytes.
    #[must_use] 
    pub fn coded_index_size(&self, kind: CodedIndexKind) -> usize {
        let tag_bits = kind.tag_bits();
        let tables = kind.tables();
        let max_rows = tables.iter()
            .filter_map(|opt| *opt)
            .map(|t| self.row_count(t))
            .max()
            .unwrap_or(0);
        let threshold = 1u32 << (16 - tag_bits);
        if max_rows >= threshold { 4 } else { 2 }
    }

    fn compute_row_size(&self, tid: u8) -> usize {
        let hs = self.heap_sizes;
        let ss = hs.string_index_size();
        let gs = hs.guid_index_size();
        let bs = hs.blob_index_size();
        let ci = |k: CodedIndexKind| self.coded_index_size(k);
        let ti = |t: MetadataTable| self.index_size(t);
        match tid {
            0x00 => 2 + ss + gs + gs + gs, // Module
            0x01 => ci(CodedIndexKind::ResolutionScope) + ss + ss, // TypeRef
            0x02 => 4 + ss + ss + ci(CodedIndexKind::TypeDefOrRef) + ti(MetadataTable::Field) + ti(MetadataTable::MethodDef), // TypeDef
            0x04 | 0x17 => 2 + ss + bs, // Field
            0x06 => 4 + 2 + 2 + ss + bs + ti(MetadataTable::Param), // MethodDef
            0x08 => 2 + 2 + ss, // Param
            0x09 => ti(MetadataTable::TypeDef) + ci(CodedIndexKind::TypeDefOrRef), // InterfaceImpl
            0x0A => ci(CodedIndexKind::MemberRefParent) + ss + bs, // MemberRef
            0x0B => 2 + ci(CodedIndexKind::HasConstant) + bs, // Constant
            0x0C => ci(CodedIndexKind::HasCustomAttribute) + ci(CodedIndexKind::CustomAttributeType) + bs, // CustomAttribute
            0x0D => ci(CodedIndexKind::HasFieldMarshal) + bs, // FieldMarshal
            0x0E => 2 + ci(CodedIndexKind::HasDeclSecurity) + bs, // DeclSecurity
            0x0F => 2 + 4 + ti(MetadataTable::TypeDef), // ClassLayout
            0x10 | 0x1D => 4 + ti(MetadataTable::Field), // FieldLayout
            0x11 | 0x1B => bs, // StandAloneSig
            0x12 => ti(MetadataTable::TypeDef) + ti(MetadataTable::Event), // EventMap
            0x14 => 2 + ss + ci(CodedIndexKind::TypeDefOrRef), // Event
            0x15 => ti(MetadataTable::TypeDef) + ti(MetadataTable::Property), // PropertyMap
            // Property
            0x18 => 2 + ti(MetadataTable::MethodDef) + ci(CodedIndexKind::HasSemantics), // MethodSemantics
            0x19 => ti(MetadataTable::TypeDef) + ci(CodedIndexKind::MethodDefOrRef) + ci(CodedIndexKind::MethodDefOrRef), // MethodImpl
            0x1A => ss, // ModuleRef
            // TypeSpec
            0x1C => 2 + ci(CodedIndexKind::MemberForwarded) + ss + ti(MetadataTable::ModuleRef), // ImplMap
            // FieldRva
            0x20 => 4 + 2 + 2 + 2 + 2 + 4 + bs + ss + ss, // Assembly
            0x21 => 4, // AssemblyProcessor
            0x22 => 4 + 4 + 4, // AssemblyOS
            0x23 => 2 + 2 + 2 + 2 + 4 + bs + ss + ss + bs, // AssemblyRef
            0x24 => 4 + ti(MetadataTable::AssemblyRef), // AssemblyRefProcessor
            0x25 => 4 + 4 + 4 + ti(MetadataTable::AssemblyRef), // AssemblyRefOS
            0x26 => 4 + ss + bs, // File
            0x27 => 4 + ss + ss + ci(CodedIndexKind::Implementation) + ti(MetadataTable::TypeDef), // ExportedType
            0x28 => 4 + 4 + ss + ci(CodedIndexKind::Implementation), // ManifestResource
            0x29 => ti(MetadataTable::TypeDef) + ti(MetadataTable::TypeDef), // NestedClass
            0x2A => 2 + 2 + ci(CodedIndexKind::TypeOrMethodDef) + ss, // GenericParam
            0x2B => ci(CodedIndexKind::MethodDefOrRef) + bs, // MethodSpec
            0x2C => ti(MetadataTable::GenericParam) + ci(CodedIndexKind::TypeDefOrRef), // GenericParamConstraint
            _ => 0,
        }
    }

    fn row_data(&self, t: MetadataTable, row: u32) -> MetaResult<&[u8]> {
        let info = self.tables.get(&t.id())
            .ok_or_else(|| MetadataError::UnknownTable(t.id()))?;
        if row == 0 || row > info.row_count {
            return Err(MetadataError::OutOfBounds {
                offset: row as usize,
                size: info.row_size,
                table: t.name(),
            });
        }
        let start = info.data_offset + (row as usize - 1) * info.row_size;
        let end   = start + info.row_size;
        if end > self.raw.len() {
            return Err(MetadataError::OutOfBounds { offset: start, size: info.row_size, table: t.name() });
        }
        Ok(&self.raw[start..end])
    }

    // ── Row parsers ────────────────────────────────────────────────────────────

    /// # Errors
    /// Returns an error when the operation fails.
    pub fn read_module(&self, row: u32) -> MetaResult<ModuleRow> {
        let data = self.row_data(MetadataTable::Module, row)?;
        let mut c = Cursor::new(data);
        let hs = self.heap_sizes;
        let generation = c.read_u16()?;
        let name_off    = c.read_index(hs.string_wide)? as usize;
        let mv_id       = c.read_index(hs.guid_wide)? ;
        let enc_id      = c.read_index(hs.guid_wide)?;
        let enc_base_id = c.read_index(hs.guid_wide)?;
        Ok(ModuleRow {
            generation,
            name: self.heap.read_string(name_off)?,
            mv_id,
            enc_id,
            enc_base_id,
        })
    }

    /// # Errors
    /// Returns an error when the operation fails.
    pub fn read_type_ref(&self, row: u32) -> MetaResult<TypeRefRow> {
        let data = self.row_data(MetadataTable::TypeRef, row)?;
        let mut c = Cursor::new(data);
        let hs = self.heap_sizes;
        let ci_size = self.coded_index_size(CodedIndexKind::ResolutionScope);
        let resolution_scope = c.read_index(ci_size == 4)?;
        let name_off  = c.read_index(hs.string_wide)? as usize;
        let ns_off    = c.read_index(hs.string_wide)? as usize;
        Ok(TypeRefRow {
            resolution_scope,
            name:      self.heap.read_string(name_off)?,
            namespace: self.heap.read_string(ns_off)?,
        })
    }

    /// # Errors
    /// Returns an error when the operation fails.
    pub fn read_type_def(&self, row: u32) -> MetaResult<TypeDefRow> {
        let data = self.row_data(MetadataTable::TypeDef, row)?;
        let mut c = Cursor::new(data);
        let hs = self.heap_sizes;
        let flags     = c.read_u32()?;
        let name_off  = c.read_index(hs.string_wide)? as usize;
        let ns_off    = c.read_index(hs.string_wide)? as usize;
        let ext_size  = self.coded_index_size(CodedIndexKind::TypeDefOrRef);
        let extends   = c.read_index(ext_size == 4)?;
        let fl_size   = self.index_size(MetadataTable::Field);
        let ml_size   = self.index_size(MetadataTable::MethodDef);
        let field_list  = c.read_index(fl_size == 4)?;
        let method_list = c.read_index(ml_size == 4)?;
        Ok(TypeDefRow {
            flags,
            name:      self.heap.read_string(name_off)?,
            namespace: self.heap.read_string(ns_off)?,
            extends,
            field_list,
            method_list,
        })
    }

    /// # Errors
    /// Returns an error when the operation fails.
    pub fn read_field(&self, row: u32) -> MetaResult<FieldRow> {
        let data = self.row_data(MetadataTable::Field, row)?;
        let mut c = Cursor::new(data);
        let hs = self.heap_sizes;
        let flags     = c.read_u16()?;
        let name_off  = c.read_index(hs.string_wide)? as usize;
        let sig_off   = c.read_index(hs.blob_wide)? as usize;
        Ok(FieldRow {
            flags,
            name:      self.heap.read_string(name_off)?,
            signature: self.heap.read_blob(sig_off)?.to_vec(),
        })
    }

    /// # Errors
    /// Returns an error when the operation fails.
    pub fn read_method_def(&self, row: u32) -> MetaResult<MethodDefRow> {
        let data = self.row_data(MetadataTable::MethodDef, row)?;
        let mut c = Cursor::new(data);
        let hs = self.heap_sizes;
        let rva        = c.read_u32()?;
        let impl_flags = c.read_u16()?;
        let flags      = c.read_u16()?;
        let name_off   = c.read_index(hs.string_wide)? as usize;
        let sig_off    = c.read_index(hs.blob_wide)? as usize;
        let pl_size    = self.index_size(MetadataTable::Param);
        let param_list = c.read_index(pl_size == 4)?;
        Ok(MethodDefRow {
            rva,
            impl_flags,
            flags,
            name:      self.heap.read_string(name_off)?,
            signature: self.heap.read_blob(sig_off)?.to_vec(),
            param_list,
        })
    }

    /// # Errors
    /// Returns an error when the operation fails.
    pub fn read_param(&self, row: u32) -> MetaResult<ParamRow> {
        let data = self.row_data(MetadataTable::Param, row)?;
        let mut c = Cursor::new(data);
        let hs = self.heap_sizes;
        let flags    = c.read_u16()?;
        let sequence = c.read_u16()?;
        let name_off = c.read_index(hs.string_wide)? as usize;
        Ok(ParamRow {
            flags,
            sequence,
            name: self.heap.read_string(name_off)?,
        })
    }

    /// # Errors
    /// Returns an error when the operation fails.
    pub fn read_member_ref(&self, row: u32) -> MetaResult<MemberRefRow> {
        let data = self.row_data(MetadataTable::MemberRef, row)?;
        let mut c = Cursor::new(data);
        let hs = self.heap_sizes;
        let ci_size = self.coded_index_size(CodedIndexKind::MemberRefParent);
        let class    = c.read_index(ci_size == 4)?;
        let name_off = c.read_index(hs.string_wide)? as usize;
        let sig_off  = c.read_index(hs.blob_wide)? as usize;
        Ok(MemberRefRow {
            class,
            name:      self.heap.read_string(name_off)?,
            signature: self.heap.read_blob(sig_off)?.to_vec(),
        })
    }

    /// # Errors
    /// Returns an error when the operation fails.
    pub fn read_custom_attribute(&self, row: u32) -> MetaResult<CustomAttributeRow> {
        let data = self.row_data(MetadataTable::CustomAttribute, row)?;
        let mut c = Cursor::new(data);
        let hs = self.heap_sizes;
        let p_size = self.coded_index_size(CodedIndexKind::HasCustomAttribute);
        let k_size = self.coded_index_size(CodedIndexKind::CustomAttributeType);
        let parent = c.read_index(p_size == 4)?;
        let kind   = c.read_index(k_size == 4)?;
        let val_off= c.read_index(hs.blob_wide)? as usize;
        Ok(CustomAttributeRow {
            parent,
            kind,
            value: self.heap.read_blob(val_off)?.to_vec(),
        })
    }

    /// # Errors
    /// Returns an error when the operation fails.
    pub fn read_assembly_ref(&self, row: u32) -> MetaResult<AssemblyRefRow> {
        let data = self.row_data(MetadataTable::AssemblyRef, row)?;
        let mut c = Cursor::new(data);
        let hs = self.heap_sizes;
        let major    = c.read_u16()?;
        let minor    = c.read_u16()?;
        let build    = c.read_u16()?;
        let revision = c.read_u16()?;
        let flags    = c.read_u32()?;
        let pkt_off  = c.read_index(hs.blob_wide)? as usize;
        let name_off = c.read_index(hs.string_wide)? as usize;
        let cult_off = c.read_index(hs.string_wide)? as usize;
        let hash_off = c.read_index(hs.blob_wide)? as usize;
        Ok(AssemblyRefRow {
            major, minor, build, revision, flags,
            public_key_tok: self.heap.read_blob(pkt_off)?.to_vec(),
            name:           self.heap.read_string(name_off)?,
            culture:        self.heap.read_string(cult_off)?,
            hash_value:     self.heap.read_blob(hash_off)?.to_vec(),
        })
    }

    /// Iterate all rows of a table.
    pub fn iter_type_defs(&self) -> impl Iterator<Item = MetaResult<TypeDefRow>> + '_ {
        let count = self.row_count(MetadataTable::TypeDef);
        (1..=count).map(move |row| self.read_type_def(row))
    }

    pub fn iter_method_defs(&self) -> impl Iterator<Item = MetaResult<MethodDefRow>> + '_ {
        let count = self.row_count(MetadataTable::MethodDef);
        (1..=count).map(move |row| self.read_method_def(row))
    }

    pub fn iter_assembly_refs(&self) -> impl Iterator<Item = MetaResult<AssemblyRefRow>> + '_ {
        let count = self.row_count(MetadataTable::AssemblyRef);
        (1..=count).map(move |row| self.read_assembly_ref(row))
    }

    /// Find all `TypeDef` rows matching a fully-qualified name.
    #[must_use] 
    pub fn find_type(&self, namespace: &str, name: &str) -> Vec<(u32, TypeDefRow)> {
        let count = self.row_count(MetadataTable::TypeDef);
        let mut out = Vec::new();
        for row in 1..=count {
            if let Ok(r) = self.read_type_def(row)
                && r.namespace == namespace && r.name == name {
                    out.push((row, r));
                }
        }
        out
    }

    /// Collect all methods belonging to a `TypeDef` row (using `field_list` / `method_list` ranges).
    /// # Errors
    /// Returns an error when the operation fails.
    pub fn methods_of_type(&self, type_row: u32) -> MetaResult<Vec<(u32, MethodDefRow)>> {
        let tdef = self.read_type_def(type_row)?;
        let next_type_row = type_row + 1;
        let method_end = if next_type_row <= self.row_count(MetadataTable::TypeDef) {
            self.read_type_def(next_type_row)?.method_list
        } else {
            self.row_count(MetadataTable::MethodDef) + 1
        };
        let mut methods = Vec::new();
        for row in tdef.method_list..method_end {
            methods.push((row, self.read_method_def(row)?));
        }
        Ok(methods)
    }
}

// ─── Unit Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_table_ids_unique() {
        let all = MetadataTable::all();
        let ids: Vec<u8> = all.iter().map(|t| t.id()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ids.len(), sorted.len());
    }

    #[test]
    fn test_table_name_round_trip() {
        for t in MetadataTable::all() {
            let id = t.id();
            let recovered = MetadataTable::from_id(id).unwrap();
            assert_eq!(*t, recovered);
        }
    }

    #[test]
    fn test_table_count_is_38() {
        assert_eq!(MetadataTable::all().len(), 38);
    }

    #[test]
    fn test_heap_sizes_from_byte() {
        let hs = HeapSizes::from_byte(0b0000_0111);
        assert!(hs.string_wide);
        assert!(hs.guid_wide);
        assert!(hs.blob_wide);

        let hs2 = HeapSizes::from_byte(0);
        assert!(!hs2.string_wide);
        assert!(!hs2.guid_wide);
        assert!(!hs2.blob_wide);
    }

    #[test]
    fn test_heap_index_sizes() {
        let hs_wide = HeapSizes { string_wide: true, guid_wide: true, blob_wide: true };
        assert_eq!(hs_wide.string_index_size(), 4);
        assert_eq!(hs_wide.guid_index_size(), 4);
        assert_eq!(hs_wide.blob_index_size(), 4);

        let hs_narrow = HeapSizes::default();
        assert_eq!(hs_narrow.string_index_size(), 2);
    }

    #[test]
    fn test_decode_compressed_uint_single_byte() {
        let (v, consumed) = decode_compressed_uint(&[0x03]).unwrap();
        assert_eq!(v, 3);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_decode_compressed_uint_two_bytes() {
        let (v, consumed) = decode_compressed_uint(&[0x81, 0x48]).unwrap();
        assert_eq!(v, 0x0148);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_decode_compressed_uint_four_bytes() {
        let (v, consumed) = decode_compressed_uint(&[0xC0, 0x00, 0x30, 0x00]).unwrap();
        assert_eq!(v, 0x0000_3000);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn test_heap_reader_string() {
        let strings = b"\x00Hello\x00World\x00";
        let heap = HeapReader::new(strings, &[], &[], &[]);
        assert_eq!(heap.read_string(1).unwrap(), "Hello");
        assert_eq!(heap.read_string(7).unwrap(), "World");
    }

    #[test]
    fn test_heap_reader_empty_string() {
        let strings = b"\x00";
        let heap = HeapReader::new(strings, &[], &[], &[]);
        assert_eq!(heap.read_string(0).unwrap(), "");
    }

    #[test]
    fn test_heap_reader_blob() {
        let blob = b"\x00\x03\xDE\xAD\xBE";
        let heap = HeapReader::new(&[], blob, &[], &[]);
        let data = heap.read_blob(1).unwrap();
        assert_eq!(data, &[0xDE, 0xAD, 0xBE]);
    }

    #[test]
    fn test_heap_reader_guid() {
        let guid_data = [0u8; 32];
        let heap = HeapReader::new(&[], &[], &guid_data, &[]);
        let g = heap.read_guid(1).unwrap();
        assert_eq!(g, [0u8; 16]);
    }

    #[test]
    fn test_heap_reader_guid_zero() {
        let heap = HeapReader::new(&[], &[], &[], &[]);
        let g = heap.read_guid(0).unwrap();
        assert_eq!(g, [0u8; 16]);
    }

    #[test]
    fn test_coded_index_type_def_or_ref_decode() {
        // tag=0 → TypeDef, row=1 → raw = (1<<2)|0 = 4
        let (tbl, row) = CodedIndexKind::TypeDefOrRef.decode(4).unwrap();
        assert_eq!(tbl, MetadataTable::TypeDef);
        assert_eq!(row, 1);
    }

    #[test]
    fn test_coded_index_type_ref() {
        // tag=1 → TypeRef, row=2 → raw = (2<<2)|1 = 9
        let (tbl, row) = CodedIndexKind::TypeDefOrRef.decode(9).unwrap();
        assert_eq!(tbl, MetadataTable::TypeRef);
        assert_eq!(row, 2);
    }

    #[test]
    fn test_coded_index_has_semantics() {
        // HasSemantics tag=0 → Event, row=3 → raw = (3<<1)|0 = 6
        let (tbl, row) = CodedIndexKind::HasSemantics.decode(6).unwrap();
        assert_eq!(tbl, MetadataTable::Event);
        assert_eq!(row, 3);
    }

    #[test]
    fn test_type_def_flags() {
        let r = TypeDefRow {
            flags: 0x0000_01A0, // interface | abstract | sealed
            name: String::new(),
            namespace: String::new(),
            extends: 0,
            field_list: 1,
            method_list: 1,
        };
        assert!(r.is_abstract());
        assert!(r.is_sealed());
    }

    #[test]
    fn test_method_def_flags() {
        let r = MethodDefRow {
            rva: 0,
            impl_flags: 0,
            flags: 0x0050, // virtual | abstract
            name: String::new(),
            signature: vec![],
            param_list: 1,
        };
        assert!(r.is_virtual());
        assert!(r.is_abstract());
        assert!(!r.is_static());
    }

    #[test]
    fn test_field_flags() {
        let r = FieldRow {
            flags: 0x0010, // static
            name: String::new(),
            signature: vec![],
        };
        assert!(r.is_static());
        assert!(!r.is_literal());
    }
}
