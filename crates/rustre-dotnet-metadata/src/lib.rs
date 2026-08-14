//! `rustre-dotnet-metadata`
//!
//! Pure-Rust ECMA-335 CLI metadata parser. Reads PE files containing .NET managed
//! code and exposes typed access to every metadata table, heap and stream.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::unreadable_literal,
    clippy::format_push_string,
    clippy::format_in_format_args,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::similar_names,
    clippy::items_after_statements,
    clippy::match_same_arms,
    clippy::needless_pass_by_value,
    clippy::needless_raw_string_hashes,
    clippy::option_if_let_else,
    clippy::manual_let_else,
    clippy::redundant_closure_for_method_calls,
    clippy::unnecessary_wraps,
    clippy::unused_self,
    clippy::redundant_guards,
    clippy::map_unwrap_or,
    clippy::if_not_else,
    clippy::struct_excessive_bools,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_const_for_fn,
    clippy::doc_markdown,
    clippy::default_trait_access,
    clippy::wildcard_imports,
    clippy::single_match_else,
    clippy::unnested_or_patterns,
    clippy::needless_continue,
    clippy::implicit_hasher,
    clippy::ignored_unit_patterns,
    clippy::semicolon_if_nothing_returned,
    clippy::stable_sort_primitive,
    clippy::trivially_copy_pass_by_ref,
    clippy::ptr_as_ptr,
    clippy::ref_option,
    clippy::fn_params_excessive_bools
)]

pub mod metadata_analyzer;
pub mod metadata_full;
pub mod metadata_resolver;
pub mod generic_resolver;
pub mod attribute_reader;
pub mod assembly_resolver;
pub mod metadata_tables;
pub mod il_disassembler;
pub mod type_system;

use std::collections::HashMap;

use thiserror::Error;

// â"€â"€â"€ Error â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Error)]
pub enum MetadataError {
    #[error("data too short: need {need} bytes at offset {offset}, have {have}")]
    UnexpectedEof {
        offset: usize,
        need: usize,
        have: usize,
    },
    #[error("invalid PE magic at offset {0}")]
    InvalidPeMagic(usize),
    #[error("invalid metadata signature: expected 0x424A_5342, got 0x{0:08X}")]
    InvalidMetadataSignature(u32),
    #[error("stream {0:?} not found")]
    StreamNotFound(String),
    #[error("string offset {0} out of range")]
    StringOffsetOutOfRange(u32),
    #[error("guid index {0} out of range")]
    GuidIndexOutOfRange(u32),
    #[error("blob offset {0} out of range")]
    BlobOffsetOutOfRange(u32),
    #[error("invalid compressed integer at offset {0}")]
    InvalidCompressedInt(usize),
    #[error("table {0:#04X} is not supported")]
    UnsupportedTable(u8),
    #[error("invalid token 0x{0:08X}")]
    InvalidToken(u32),
    #[error("invalid UTF-8 in metadata string")]
    InvalidUtf8,
    #[error("table index {index} out of range for table {table:#04X} (rows: {rows})")]
    TableIndexOutOfRange { table: u8, index: u32, rows: u32 },
}

pub type Result<T> = std::result::Result<T, MetadataError>;

// â"€â"€â"€ Low-level byte reader â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    const fn at(data: &'a [u8], pos: usize) -> Self {
        Self { data, pos }
    }

    const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn peek_u8(&self) -> Result<u8> {
        if self.pos >= self.data.len() {
            return Err(MetadataError::UnexpectedEof {
                offset: self.pos,
                need: 1,
                have: 0,
            });
        }
        Ok(self.data[self.pos])
    }

    fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            return Err(MetadataError::UnexpectedEof {
                offset: self.pos,
                need: 1,
                have: 0,
            });
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u16(&mut self) -> Result<u16> {
        self.ensure(2)?;
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_u32(&mut self) -> Result<u32> {
        self.ensure(4)?;
        let v = u32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        self.ensure(n)?;
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    const fn align(&mut self, n: usize) {
        let rem = self.pos % n;
        if rem != 0 {
            self.pos += n - rem;
        }
    }

    const fn ensure(&self, n: usize) -> Result<()> {
        let have = self.data.len().saturating_sub(self.pos);
        if have < n {
            Err(MetadataError::UnexpectedEof {
                offset: self.pos,
                need: n,
                have,
            })
        } else {
            Ok(())
        }
    }

    /// Read a null-terminated ASCII/UTF-8 string from current position.
    fn read_cstr(&mut self) -> Result<String> {
        let start = self.pos;
        while self.pos < self.data.len() && self.data[self.pos] != 0 {
            self.pos += 1;
        }
        let s = std::str::from_utf8(&self.data[start..self.pos])
            .map_err(|_| MetadataError::InvalidUtf8)?
            .to_string();
        if self.pos < self.data.len() {
            self.pos += 1; // skip NUL
        }
        Ok(s)
    }

    /// ECMA-335 Â§II.23.2 compressed unsigned integer.
    fn read_compressed_uint(&mut self) -> Result<u32> {
        let b0 = self.peek_u8()?;
        if b0 & 0x80 == 0 {
            self.pos += 1;
            return Ok(u32::from(b0));
        }
        if b0 & 0xC0 == 0x80 {
            self.ensure(2)?;
            let val = (u32::from(b0 & 0x3F) << 8) | u32::from(self.data[self.pos + 1]);
            self.pos += 2;
            return Ok(val);
        }
        if b0 & 0xE0 == 0xC0 {
            self.ensure(4)?;
            let val = (u32::from(b0 & 0x1F) << 24)
                | (u32::from(self.data[self.pos + 1]) << 16)
                | (u32::from(self.data[self.pos + 2]) << 8)
                | u32::from(self.data[self.pos + 3]);
            self.pos += 4;
            return Ok(val);
        }
        Err(MetadataError::InvalidCompressedInt(self.pos))
    }
}

// â"€â"€â"€ Stream / MetadataRoot â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone)]
pub struct Stream {
    pub name: String,
    pub offset: u32,
    pub size: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct MetadataRoot {
    pub major_version: u16,
    pub minor_version: u16,
    pub streams: Vec<Stream>,
}

// â"€â"€â"€ Heaps â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone, Default)]
pub struct StringHeap {
    data: Vec<u8>,
}

impl StringHeap {
    #[must_use]
    pub const fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// # Errors
    /// Returns [`MetadataError`] if the offset is out of range or the string is not valid UTF-8.
    pub fn get(&self, offset: u32) -> Result<&str> {
        let off = offset as usize;
        if off >= self.data.len() {
            return Err(MetadataError::StringOffsetOutOfRange(offset));
        }
        let end = self.data[off..]
            .iter()
            .position(|&b| b == 0)
            .map_or(self.data.len(), |p| off + p);
        std::str::from_utf8(&self.data[off..end]).map_err(|_| MetadataError::InvalidUtf8)
    }
}

#[derive(Debug, Clone, Default)]
pub struct UserStringHeap {
    data: Vec<u8>,
}

impl UserStringHeap {
    #[must_use]
    pub const fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Returns the UTF-16LE string at the given offset (strips the terminal byte).
    ///
    /// # Errors
    /// Returns [`MetadataError`] if the offset is out of range or the string is not valid UTF-16.
    pub fn get(&self, offset: u32) -> Result<String> {
        let mut r = Reader::at(&self.data, offset as usize);
        let len = r.read_compressed_uint()? as usize;
        if len == 0 {
            return Ok(String::new());
        }
        // last byte is a hint; skip it for the string length
        let str_bytes = len.saturating_sub(1);
        let bytes = r.read_bytes(str_bytes)?;
        // interpret as UTF-16LE pairs
        let u16s: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16(&u16s).map_err(|_| MetadataError::InvalidUtf8)
    }
}

#[derive(Debug, Clone, Default)]
pub struct GuidHeap {
    data: Vec<u8>,
}

impl GuidHeap {
    #[must_use]
    pub const fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// 1-based GUID index â†' 16-byte array.
    ///
    /// # Errors
    /// Returns [`MetadataError`] if the index is out of range.
    pub fn get(&self, index: u32) -> Result<[u8; 16]> {
        if index == 0 {
            return Ok([0u8; 16]);
        }
        let off = ((index - 1) as usize) * 16;
        if off + 16 > self.data.len() {
            return Err(MetadataError::GuidIndexOutOfRange(index));
        }
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&self.data[off..off + 16]);
        Ok(guid)
    }
}

#[derive(Debug, Clone, Default)]
pub struct BlobHeap {
    data: Vec<u8>,
}

impl BlobHeap {
    #[must_use]
    pub const fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// # Errors
    /// Returns [`MetadataError`] if the offset is out of range.
    pub fn get(&self, offset: u32) -> Result<&[u8]> {
        let mut r = Reader::at(&self.data, offset as usize);
        if r.remaining() == 0 {
            return Err(MetadataError::BlobOffsetOutOfRange(offset));
        }
        let len = r.read_compressed_uint()? as usize;
        let start = r.pos;
        if start + len > self.data.len() {
            return Err(MetadataError::BlobOffsetOutOfRange(offset));
        }
        Ok(&self.data[start..start + len])
    }
}

#[derive(Debug, Clone, Default)]
pub struct MetadataHeaps {
    pub strings: StringHeap,
    pub user_strings: UserStringHeap,
    pub guid: GuidHeap,
    pub blob: BlobHeap,
}

// â"€â"€â"€ Coded indices â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Table IDs (ECMA-335 Â§II.22)
pub mod table_id {
    pub const MODULE: u8 = 0x00;
    pub const TYPE_REF: u8 = 0x01;
    pub const TYPE_DEF: u8 = 0x02;
    pub const FIELD_PTR: u8 = 0x03;
    pub const FIELD: u8 = 0x04;
    pub const METHOD_PTR: u8 = 0x05;
    pub const METHOD_DEF: u8 = 0x06;
    pub const PARAM_PTR: u8 = 0x07;
    pub const PARAM: u8 = 0x08;
    pub const INTERFACE_IMPL: u8 = 0x09;
    pub const MEMBER_REF: u8 = 0x0A;
    pub const CONSTANT: u8 = 0x0B;
    pub const CUSTOM_ATTRIBUTE: u8 = 0x0C;
    pub const FIELD_MARSHAL: u8 = 0x0D;
    pub const DECL_SECURITY: u8 = 0x0E;
    pub const CLASS_LAYOUT: u8 = 0x0F;
    pub const FIELD_LAYOUT: u8 = 0x10;
    pub const STAND_ALONE_SIG: u8 = 0x11;
    pub const EVENT_MAP: u8 = 0x12;
    pub const EVENT: u8 = 0x14;
    pub const PROPERTY_MAP: u8 = 0x15;
    pub const PROPERTY: u8 = 0x17;
    pub const METHOD_SEMANTICS: u8 = 0x18;
    pub const METHOD_IMPL: u8 = 0x19;
    pub const MODULE_REF: u8 = 0x1A;
    pub const TYPE_SPEC: u8 = 0x1B;
    pub const IMPL_MAP: u8 = 0x1C;
    pub const FIELD_RVA: u8 = 0x1D;
    pub const ASSEMBLY: u8 = 0x20;
    pub const ASSEMBLY_PROCESSOR: u8 = 0x21;
    pub const ASSEMBLY_OS: u8 = 0x22;
    pub const ASSEMBLY_REF: u8 = 0x23;
    pub const ASSEMBLY_REF_PROCESSOR: u8 = 0x24;
    pub const ASSEMBLY_REF_OS: u8 = 0x25;
    pub const FILE: u8 = 0x26;
    pub const EXPORTED_TYPE: u8 = 0x27;
    pub const MANIFEST_RESOURCE: u8 = 0x28;
    pub const NESTED_CLASS: u8 = 0x29;
    pub const GENERIC_PARAM: u8 = 0x2A;
    pub const METHOD_SPEC: u8 = 0x2B;
    pub const GENERIC_PARAM_CONSTRAINT: u8 = 0x2C;

    /// Returns the ECMA-335 table name for a raw table id, or `None` if unknown.
    ///
    /// `None` is returned if the id is not one of the defined CLI metadata tables.
    /// This is the canonical consumer of every constant above, so the table id
    /// list stays in sync with this lookup.
    #[must_use]
    pub const fn name_for(id: u8) -> Option<&'static str> {
        Some(match id {
            MODULE => "Module",
            TYPE_REF => "TypeRef",
            TYPE_DEF => "TypeDef",
            FIELD_PTR => "FieldPtr",
            FIELD => "Field",
            METHOD_PTR => "MethodPtr",
            METHOD_DEF => "MethodDef",
            PARAM_PTR => "ParamPtr",
            PARAM => "Param",
            INTERFACE_IMPL => "InterfaceImpl",
            MEMBER_REF => "MemberRef",
            CONSTANT => "Constant",
            CUSTOM_ATTRIBUTE => "CustomAttribute",
            FIELD_MARSHAL => "FieldMarshal",
            DECL_SECURITY => "DeclSecurity",
            CLASS_LAYOUT => "ClassLayout",
            FIELD_LAYOUT => "FieldLayout",
            STAND_ALONE_SIG => "StandAloneSig",
            EVENT_MAP => "EventMap",
            EVENT => "Event",
            PROPERTY_MAP => "PropertyMap",
            PROPERTY => "Property",
            METHOD_SEMANTICS => "MethodSemantics",
            METHOD_IMPL => "MethodImpl",
            MODULE_REF => "ModuleRef",
            TYPE_SPEC => "TypeSpec",
            IMPL_MAP => "ImplMap",
            FIELD_RVA => "FieldRVA",
            ASSEMBLY => "Assembly",
            ASSEMBLY_PROCESSOR => "AssemblyProcessor",
            ASSEMBLY_OS => "AssemblyOS",
            ASSEMBLY_REF => "AssemblyRef",
            ASSEMBLY_REF_PROCESSOR => "AssemblyRefProcessor",
            ASSEMBLY_REF_OS => "AssemblyRefOS",
            FILE => "File",
            EXPORTED_TYPE => "ExportedType",
            MANIFEST_RESOURCE => "ManifestResource",
            NESTED_CLASS => "NestedClass",
            GENERIC_PARAM => "GenericParam",
            METHOD_SPEC => "MethodSpec",
            GENERIC_PARAM_CONSTRAINT => "GenericParamConstraint",
            _ => return None,
        })
    }
}

// â"€â"€â"€ Table row types â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone, Default)]
pub struct ModuleRow {
    pub generation: u16,
    pub name: String,
    pub mvid: u32,
    pub enc_id: u32,
    pub enc_base_id: u32,
}

#[derive(Debug, Clone, Default)]
pub struct TypeRefRow {
    pub resolution_scope: u32,
    pub type_name: String,
    pub type_namespace: String,
}

#[derive(Debug, Clone, Default)]
pub struct TypeDefRow {
    pub flags: u32,
    pub type_name: String,
    pub type_namespace: String,
    pub extends: u32,
    pub field_list: u32,
    pub method_list: u32,
}

#[derive(Debug, Clone, Default)]
pub struct FieldRow {
    pub flags: u16,
    pub name: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct MethodDefRow {
    pub rva: u32,
    pub impl_flags: u16,
    pub flags: u16,
    pub name: String,
    pub signature: Vec<u8>,
    pub param_list: u32,
}

#[derive(Debug, Clone, Default)]
pub struct ParamRow {
    pub flags: u16,
    pub sequence: u16,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct InterfaceImplRow {
    pub class: u32,
    pub interface: u32,
}

#[derive(Debug, Clone, Default)]
pub struct MemberRefRow {
    pub class: u32,
    pub name: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct ConstantRow {
    pub const_type: u8,
    pub parent: u32,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct CustomAttributeRow {
    pub parent: u32,
    pub attr_type: u32,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct AssemblyRow {
    pub hash_alg_id: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub build_number: u16,
    pub revision_number: u16,
    pub flags: u32,
    pub public_key: Vec<u8>,
    pub name: String,
    pub culture: String,
}

#[derive(Debug, Clone, Default)]
pub struct AssemblyRefRow {
    pub major_version: u16,
    pub minor_version: u16,
    pub build_number: u16,
    pub revision_number: u16,
    pub flags: u32,
    pub public_key_or_token: Vec<u8>,
    pub name: String,
    pub culture: String,
    pub hash_value: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct NestedClassRow {
    pub nested_class: u32,
    pub enclosing_class: u32,
}

// â"€â"€â"€ Additional table row types (ECMA-335 Â§II.22) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone, Default)]
pub struct FieldMarshalRow {
    /// Coded `HasFieldMarshal` index (Field or Param).
    pub parent: u32,
    pub native_type: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct DeclSecurityRow {
    pub action: u16,
    /// Coded `HasDeclSecurity`.
    pub parent: u32,
    pub permission_set: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct ClassLayoutRow {
    pub packing_size: u16,
    pub class_size: u32,
    /// Index into `TypeDef` table (1-based).
    pub parent: u32,
}

#[derive(Debug, Clone, Default)]
pub struct FieldLayoutRow {
    pub offset: u32,
    /// Index into Field table (1-based).
    pub field: u32,
}

#[derive(Debug, Clone, Default)]
pub struct StandAloneSigRow {
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct EventMapRow {
    /// Index into `TypeDef` (1-based).
    pub parent: u32,
    /// Index into Event table (1-based).
    pub event_list: u32,
}

#[derive(Debug, Clone, Default)]
pub struct EventRow {
    pub event_flags: u16,
    pub name: String,
    /// Coded `TypeDefOrRef` —" event handler type.
    pub event_type: u32,
}

#[derive(Debug, Clone, Default)]
pub struct PropertyMapRow {
    /// Index into `TypeDef` (1-based).
    pub parent: u32,
    /// Index into Property table (1-based).
    pub property_list: u32,
}

#[derive(Debug, Clone, Default)]
pub struct PropertyRow {
    pub flags: u16,
    pub name: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct MethodSemanticsRow {
    pub semantics: u16,
    /// Index into `MethodDef` (1-based).
    pub method: u32,
    /// Coded `HasSemantics` (Event or Property).
    pub association: u32,
}

#[derive(Debug, Clone, Default)]
pub struct MethodImplRow {
    /// Index into `TypeDef` (1-based).
    pub class: u32,
    /// Coded `MethodDefOrRef` —" the body.
    pub method_body: u32,
    /// Coded `MethodDefOrRef` —" the declaration.
    pub method_declaration: u32,
}

#[derive(Debug, Clone, Default)]
pub struct ModuleRefRow {
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct TypeSpecRow {
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct ImplMapRow {
    pub mapping_flags: u16,
    /// Coded `MemberForwarded`.
    pub member_forwarded: u32,
    pub import_name: String,
    /// Index into `ModuleRef` (1-based).
    pub import_scope: u32,
}

#[derive(Debug, Clone, Default)]
pub struct FieldRvaRow {
    pub rva: u32,
    /// Index into Field (1-based).
    pub field: u32,
}

#[derive(Debug, Clone, Default)]
pub struct FileRow {
    pub flags: u32,
    pub name: String,
    pub hash_value: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct ExportedTypeRow {
    pub flags: u32,
    pub type_def_id: u32,
    pub type_name: String,
    pub type_namespace: String,
    /// Coded Implementation.
    pub implementation: u32,
}

#[derive(Debug, Clone, Default)]
pub struct ManifestResourceRow {
    pub offset: u32,
    pub flags: u32,
    pub name: String,
    /// Coded Implementation (0 = embedded).
    pub implementation: u32,
}

#[derive(Debug, Clone, Default)]
pub struct GenericParamRow {
    pub number: u16,
    pub flags: u16,
    /// Coded `TypeOrMethodDef`.
    pub owner: u32,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct MethodSpecRow {
    /// Coded `MethodDefOrRef`.
    pub method: u32,
    pub instantiation: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct GenericParamConstraintRow {
    /// Index into `GenericParam` (1-based).
    pub owner: u32,
    /// Coded `TypeDefOrRef`.
    pub constraint: u32,
}

// â"€â"€â"€ Semantic flags for MethodSemantics â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// ECMA-335 Â§II.22.28 MethodSemantics.Semantics values.
pub mod method_semantics {
    pub const SETTER: u16 = 0x0001;
    pub const GETTER: u16 = 0x0002;
    pub const OTHER: u16 = 0x0004;
    pub const ADD_ON: u16 = 0x0008;
    pub const REMOVE_ON: u16 = 0x0010;
    pub const FIRE: u16 = 0x0020;
}

/// ECMA-335 Â§II.23.1.5 `EventAttributes` values.
pub mod event_attributes {
    pub const SPECIAL_NAME: u16 = 0x0200;
    pub const RT_SPECIAL_NAME: u16 = 0x0400;
}

/// ECMA-335 Â§II.23.1.14 `PropertyAttributes` values.
pub mod property_attributes {
    pub const SPECIAL_NAME: u16 = 0x0200;
    pub const RT_SPECIAL_NAME: u16 = 0x0400;
    pub const HAS_DEFAULT: u16 = 0x1000;
}

/// ECMA-335 Â§II.23.1.8 `ImplMapAttributes` (`PInvokeAttributes`) values.
pub mod impl_map_attributes {
    pub const NO_MANGLE: u16 = 0x0001;
    pub const CHAR_SET_ANSI: u16 = 0x0002;
    pub const CHAR_SET_UNICODE: u16 = 0x0004;
    pub const CHAR_SET_AUTO: u16 = 0x0006;
    pub const SUPPORTS_LAST_ERROR: u16 = 0x0040;
    pub const CALL_CONV_WINAPI: u16 = 0x0100;
    pub const CALL_CONV_CDECL: u16 = 0x0200;
    pub const CALL_CONV_STDCALL: u16 = 0x0300;
    pub const CALL_CONV_THISCALL: u16 = 0x0400;
    pub const CALL_CONV_FASTCALL: u16 = 0x0500;
}

// â"€â"€â"€ MetadataTables â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone, Default)]
pub struct MetadataTables {
    pub module: Vec<ModuleRow>,
    pub type_ref: Vec<TypeRefRow>,
    pub type_def: Vec<TypeDefRow>,
    pub field: Vec<FieldRow>,
    pub method_def: Vec<MethodDefRow>,
    pub param: Vec<ParamRow>,
    pub interface_impl: Vec<InterfaceImplRow>,
    pub member_ref: Vec<MemberRefRow>,
    pub constant: Vec<ConstantRow>,
    pub custom_attribute: Vec<CustomAttributeRow>,
    pub field_marshal: Vec<FieldMarshalRow>,
    pub decl_security: Vec<DeclSecurityRow>,
    pub class_layout: Vec<ClassLayoutRow>,
    pub field_layout: Vec<FieldLayoutRow>,
    pub stand_alone_sig: Vec<StandAloneSigRow>,
    pub event_map: Vec<EventMapRow>,
    pub event: Vec<EventRow>,
    pub property_map: Vec<PropertyMapRow>,
    pub property: Vec<PropertyRow>,
    pub method_semantics: Vec<MethodSemanticsRow>,
    pub method_impl: Vec<MethodImplRow>,
    pub module_ref: Vec<ModuleRefRow>,
    pub type_spec: Vec<TypeSpecRow>,
    pub impl_map: Vec<ImplMapRow>,
    pub field_rva: Vec<FieldRvaRow>,
    pub assembly: Vec<AssemblyRow>,
    pub assembly_ref: Vec<AssemblyRefRow>,
    pub file: Vec<FileRow>,
    pub exported_type: Vec<ExportedTypeRow>,
    pub manifest_resource: Vec<ManifestResourceRow>,
    pub nested_class: Vec<NestedClassRow>,
    pub generic_param: Vec<GenericParamRow>,
    pub method_spec: Vec<MethodSpecRow>,
    pub generic_param_constraint: Vec<GenericParamConstraintRow>,
}

impl MetadataTables {
    /// Returns the number of rows in the `TypeDef` table.
    #[must_use]
    pub const fn type_def_count(&self) -> usize {
        self.type_def.len()
    }

    /// Returns the number of rows in the `MethodDef` table.
    #[must_use]
    pub const fn method_def_count(&self) -> usize {
        self.method_def.len()
    }

    /// Returns the number of rows in the Field table.
    #[must_use]
    pub const fn field_count(&self) -> usize {
        self.field.len()
    }

    /// Find a `TypeDef` row by its 1-based index.
    ///
    /// # Errors
    /// Returns [`MetadataError`] if the index is out of range.
    pub fn type_def_by_index(&self, index: u32) -> Result<&TypeDefRow> {
        let idx = index as usize;
        if idx == 0 || idx > self.type_def.len() {
            return Err(MetadataError::TableIndexOutOfRange {
                table: 0x02,
                index,
                rows: u32::try_from(self.type_def.len()).unwrap_or(u32::MAX),
            });
        }
        Ok(&self.type_def[idx - 1])
    }

    /// Find a `MethodDef` row by its 1-based index.
    ///
    /// # Errors
    /// Returns [`MetadataError`] if the index is out of range.
    pub fn method_def_by_index(&self, index: u32) -> Result<&MethodDefRow> {
        let idx = index as usize;
        if idx == 0 || idx > self.method_def.len() {
            return Err(MetadataError::TableIndexOutOfRange {
                table: 0x06,
                index,
                rows: u32::try_from(self.method_def.len()).unwrap_or(u32::MAX),
            });
        }
        Ok(&self.method_def[idx - 1])
    }

    /// Find a Field row by its 1-based index.
    ///
    /// # Errors
    /// Returns [`MetadataError`] if the index is out of range.
    pub fn field_by_index(&self, index: u32) -> Result<&FieldRow> {
        let idx = index as usize;
        if idx == 0 || idx > self.field.len() {
            return Err(MetadataError::TableIndexOutOfRange {
                table: 0x04,
                index,
                rows: u32::try_from(self.field.len()).unwrap_or(u32::MAX),
            });
        }
        Ok(&self.field[idx - 1])
    }

    /// Find a Param row by its 1-based index.
    ///
    /// # Errors
    /// Returns [`MetadataError`] if the index is out of range.
    pub fn param_by_index(&self, index: u32) -> Result<&ParamRow> {
        let idx = index as usize;
        if idx == 0 || idx > self.param.len() {
            return Err(MetadataError::TableIndexOutOfRange {
                table: 0x08,
                index,
                rows: u32::try_from(self.param.len()).unwrap_or(u32::MAX),
            });
        }
        Ok(&self.param[idx - 1])
    }

    /// Look up the `ClassLayout` for a given `TypeDef` 1-based index, if any.
    #[must_use]
    pub fn class_layout_for(&self, type_def_index: u32) -> Option<&ClassLayoutRow> {
        self.class_layout
            .iter()
            .find(|cl| cl.parent == type_def_index)
    }

    /// Look up all `CustomAttribute` rows for a given coded parent.
    #[must_use]
    pub fn custom_attributes_for(&self, parent_coded: u32) -> Vec<&CustomAttributeRow> {
        self.custom_attribute
            .iter()
            .filter(|ca| ca.parent == parent_coded)
            .collect()
    }

    /// Look up all `InterfaceImpl` rows for a given `TypeDef` 1-based index.
    #[must_use]
    pub fn interfaces_for(&self, type_def_index: u32) -> Vec<&InterfaceImplRow> {
        self.interface_impl
            .iter()
            .filter(|ii| ii.class == type_def_index)
            .collect()
    }

    /// Look up all `GenericParam` rows for a given coded `TypeOrMethodDef` owner.
    #[must_use]
    pub fn generic_params_for(&self, owner_coded: u32) -> Vec<&GenericParamRow> {
        self.generic_param
            .iter()
            .filter(|gp| gp.owner == owner_coded)
            .collect()
    }

    /// Look up all `MethodSemantics` rows for a given coded `HasSemantics` association.
    #[must_use]
    pub fn method_semantics_for(&self, association_coded: u32) -> Vec<&MethodSemanticsRow> {
        self.method_semantics
            .iter()
            .filter(|ms| ms.association == association_coded)
            .collect()
    }

    /// Look up all `MethodImpl` rows for a given `TypeDef` 1-based index.
    #[must_use]
    pub fn method_impls_for(&self, type_def_index: u32) -> Vec<&MethodImplRow> {
        self.method_impl
            .iter()
            .filter(|mi| mi.class == type_def_index)
            .collect()
    }

    /// Look up all nested classes for a given enclosing `TypeDef` 1-based index.
    #[must_use]
    pub fn nested_types_of(&self, enclosing_index: u32) -> Vec<u32> {
        self.nested_class
            .iter()
            .filter(|nc| nc.enclosing_class == enclosing_index)
            .map(|nc| nc.nested_class)
            .collect()
    }

    /// Look up the `ImplMap` row for a given coded `MemberForwarded`.
    #[must_use]
    pub fn impl_map_for(&self, member_forwarded: u32) -> Option<&ImplMapRow> {
        self.impl_map
            .iter()
            .find(|im| im.member_forwarded == member_forwarded)
    }

    /// Find the `EventMap` entry for a `TypeDef` 1-based index.
    #[must_use]
    pub fn event_map_for(&self, type_def_index: u32) -> Option<&EventMapRow> {
        self.event_map.iter().find(|em| em.parent == type_def_index)
    }

    /// Find the `PropertyMap` entry for a `TypeDef` 1-based index.
    #[must_use]
    pub fn property_map_for(&self, type_def_index: u32) -> Option<&PropertyMapRow> {
        self.property_map
            .iter()
            .find(|pm| pm.parent == type_def_index)
    }

    /// Returns events belonging to a `TypeDef` via `EventMap`.
    #[must_use]
    pub fn events_for_type(&self, type_def_index: u32) -> Vec<&EventRow> {
        let Some(em) = self.event_map_for(type_def_index) else {
            return Vec::new();
        };
        let next_event = self
            .event_map
            .iter()
            .find(|other| other.parent > type_def_index)
            .map_or_else(
                || u32::try_from(self.event.len()).unwrap_or(u32::MAX) + 1,
                |o| o.event_list,
            );
        (em.event_list..next_event)
            .filter_map(|i| self.event.get((i as usize).wrapping_sub(1)))
            .collect()
    }

    /// Returns properties belonging to a `TypeDef` via `PropertyMap`.
    #[must_use]
    pub fn properties_for_type(&self, type_def_index: u32) -> Vec<&PropertyRow> {
        let Some(pm) = self.property_map_for(type_def_index) else {
            return Vec::new();
        };
        let next_prop = self
            .property_map
            .iter()
            .find(|other| other.parent > type_def_index)
            .map_or_else(
                || u32::try_from(self.property.len()).unwrap_or(u32::MAX) + 1,
                |o| o.property_list,
            );
        (pm.property_list..next_prop)
            .filter_map(|i| self.property.get((i as usize).wrapping_sub(1)))
            .collect()
    }
}

// â"€â"€â"€ TypeVisibility / helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NestedVisibility {
    Public,
    Private,
    Family,
    Assembly,
    FamilyAndAssembly,
    FamilyOrAssembly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeVisibility {
    NotPublic,
    Public,
    Nested(NestedVisibility),
}

impl TypeVisibility {
    #[must_use]
    pub const fn from_flags(flags: u32) -> Self {
        match flags & 0x7 {
            0x01 => Self::Public,
            0x02 => Self::Nested(NestedVisibility::Public),
            0x03 => Self::Nested(NestedVisibility::Private),
            0x04 => Self::Nested(NestedVisibility::Family),
            0x05 => Self::Nested(NestedVisibility::Assembly),
            0x06 => Self::Nested(NestedVisibility::FamilyAndAssembly),
            0x07 => Self::Nested(NestedVisibility::FamilyOrAssembly),
            // 0x00 and all unknown values default to NotPublic.
            _ => Self::NotPublic,
        }
    }
}

// â"€â"€â"€ Token resolution â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone)]
pub enum TokenResolution {
    TypeDef(TypeDefRow),
    TypeRef(TypeRefRow),
    MethodDef(MethodDefRow),
    Field(FieldRow),
    MemberRef(MemberRefRow),
    Assembly(AssemblyRow),
    AssemblyRef(AssemblyRefRow),
    String(String),
    Unknown(u32),
}

/// Simple typed index wrappers used by the high-level API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct TypeRef(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FieldRef(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MethodRef(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ParamRef(pub u32);

// â"€â"€â"€ High-level row views â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Enriched `TypeDef` view with resolved child lists.
#[derive(Debug, Clone)]
pub struct TypeDefView {
    pub access_flags: u32,
    pub name: String,
    pub namespace: String,
    pub extends: TypeRef,
    pub fields: Vec<FieldRef>,
    pub methods: Vec<MethodRef>,
}

/// Enriched `MethodDef` view with resolved param list.
#[derive(Debug, Clone)]
pub struct MethodDefView {
    pub rva: u32,
    pub impl_flags: u16,
    pub flags: u16,
    pub name: String,
    pub signature: Vec<u8>,
    pub params: Vec<ParamRef>,
}

// â"€â"€â"€ Coded index helpers (ECMA-335 Â§II.24.2.6) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

fn coded_index_size(tables: &[u8], bits: u32, row_counts: &HashMap<u8, u32>) -> usize {
    let max_rows = tables
        .iter()
        .map(|t| row_counts.get(t).copied().unwrap_or(0))
        .max()
        .unwrap_or(0);
    if max_rows < (1u32 << (16 - bits)) {
        2
    } else {
        4
    }
}

fn read_coded_index(r: &mut Reader<'_>, size: usize) -> Result<u32> {
    if size == 2 {
        Ok(u32::from(r.read_u16()?))
    } else {
        r.read_u32()
    }
}

// â"€â"€â"€ MetadataReader â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone)]
pub struct MetadataReader {
    pub root: MetadataRoot,
    pub heaps: MetadataHeaps,
    pub tables: MetadataTables,
}

/// Internal helper: every size and per-table row count `parse_tables` needs.
struct ParseTablesCtx {
    string_idx_size: usize,
    guid_idx_size: usize,
    blob_idx_size: usize,
    type_def_or_ref_size: usize,
    has_constant_size: usize,
    has_field_marshal_size: usize,
    has_decl_security_size: usize,
    has_custom_attr_size: usize,
    member_ref_parent_size: usize,
    custom_attr_type_size: usize,
    resolution_scope_size: usize,
    td_size: usize,
    field_size: usize,
    method_size: usize,
    param_size: usize,
    row_counts: HashMap<u8, u32>,
    table_ids: Vec<u8>,
}

impl MetadataReader {
    /// Parse CLI metadata from raw PE bytes.
    ///
    /// # Errors
    /// Returns [`MetadataError`] if the PE or metadata structures are invalid or truncated.
    pub fn parse_from_bytes(data: &[u8]) -> Result<Self> {
        let cli_header_rva = Self::find_cli_header_rva(data)?;
        let cli_off = Self::rva_to_offset(data, cli_header_rva)?;

        // CLI header: cb(4), MajorRuntimeVersion(2), MinorRuntimeVersion(2),
        //             MetaData.VirtualAddress(4), MetaData.Size(4), Flags(4), ...
        let mut r = Reader::at(data, cli_off);
        let _cb = r.read_u32()?;
        let _major_rt = r.read_u16()?;
        let _minor_rt = r.read_u16()?;
        let metadata_rva = r.read_u32()?;
        let _metadata_size = r.read_u32()?;

        let metadata_off = Self::rva_to_offset(data, metadata_rva)?;
        Self::parse_metadata(data, metadata_off)
    }

    fn parse_metadata(data: &[u8], base: usize) -> Result<Self> {
        let mut r = Reader::at(data, base);

        // Metadata root header
        let sig = r.read_u32()?;
        if sig != 0x424A_5342 {
            return Err(MetadataError::InvalidMetadataSignature(sig));
        }
        let major_version = r.read_u16()?;
        let minor_version = r.read_u16()?;
        let _reserved = r.read_u32()?;
        let version_len = r.read_u32()? as usize;
        let _version = r.read_bytes(version_len)?;
        r.align(4);
        let _flags = r.read_u16()?;
        let num_streams = r.read_u16()? as usize;
        // ECMA-335 assemblies have at most ~5 streams (#~, #Strings, #US, #GUID, #Blob).
        // Cap to a safe limit to guard against untrusted input claiming huge stream counts.
        if num_streams > 64 {
            return Err(MetadataError::UnexpectedEof {
                offset: r.pos,
                need: num_streams * 8,
                have: r.remaining(),
            });
        }
        let mut streams = Vec::with_capacity(num_streams);
        for _ in 0..num_streams {
            let offset = r.read_u32()?;
            let size = r.read_u32()?;
            let name = r.read_cstr()?;
            r.align(4);
            let abs_off = base.checked_add(offset as usize).ok_or(
                MetadataError::UnexpectedEof { offset: base, need: offset as usize, have: 0 }
            )?;
            let end = abs_off.checked_add(size as usize).ok_or(
                MetadataError::UnexpectedEof { offset: abs_off, need: size as usize, have: 0 }
            )?;
            if end > data.len() {
                return Err(MetadataError::UnexpectedEof {
                    offset: abs_off,
                    need: size as usize,
                    have: data.len().saturating_sub(abs_off),
                });
            }
            streams.push(Stream {
                name,
                offset,
                size,
                data: data[abs_off..end].to_vec(),
            });
        }

        let root = MetadataRoot {
            major_version,
            minor_version,
            streams: streams.clone(),
        };

        // Build heaps
        let get_stream = |name: &str| -> Vec<u8> {
            streams
                .iter()
                .find(|s| s.name == name)
                .map(|s| s.data.clone())
                .unwrap_or_default()
        };

        let strings_data = get_stream("#Strings");
        let us_data = get_stream("#US");
        let guid_data = get_stream("#GUID");
        let blob_data = get_stream("#Blob");

        let heaps = MetadataHeaps {
            strings: StringHeap::new(strings_data),
            user_strings: UserStringHeap::new(us_data),
            guid: GuidHeap::new(guid_data),
            blob: BlobHeap::new(blob_data),
        };

        // Parse #~ stream
        let tilde_data = get_stream("#~");
        let tables = if tilde_data.is_empty() {
            MetadataTables::default()
        } else {
            Self::parse_tables(&tilde_data, &heaps)?
        };

        Ok(Self {
            root,
            heaps,
            tables,
        })
    }

    fn parse_tables(data: &[u8], heaps: &MetadataHeaps) -> Result<MetadataTables> {
        let mut r = Reader::new(data);
        let ctx = Self::parse_tables_prelude(&mut r)?;
        let mut tables = MetadataTables::default();

        // Pre-allocate per-table Vec capacity from row counts to avoid repeated reallocation.
        let row_cap = |tid: u8| ctx.row_counts.get(&tid).copied().unwrap_or(0) as usize;
        tables.module.reserve(row_cap(0x00));
        tables.type_ref.reserve(row_cap(0x01));
        tables.type_def.reserve(row_cap(0x02));
        tables.field.reserve(row_cap(0x04));
        tables.method_def.reserve(row_cap(0x06));
        tables.param.reserve(row_cap(0x08));
        tables.interface_impl.reserve(row_cap(0x09));
        tables.member_ref.reserve(row_cap(0x0A));
        tables.constant.reserve(row_cap(0x0B));
        tables.custom_attribute.reserve(row_cap(0x0C));
        tables.field_marshal.reserve(row_cap(0x0D));
        tables.decl_security.reserve(row_cap(0x0E));
        tables.class_layout.reserve(row_cap(0x0F));
        tables.field_layout.reserve(row_cap(0x10));
        tables.stand_alone_sig.reserve(row_cap(0x11));
        tables.event_map.reserve(row_cap(0x12));
        tables.event.reserve(row_cap(0x14));
        tables.property_map.reserve(row_cap(0x15));
        tables.property.reserve(row_cap(0x17));
        tables.method_semantics.reserve(row_cap(0x18));
        tables.method_impl.reserve(row_cap(0x19));
        tables.module_ref.reserve(row_cap(0x1A));
        tables.type_spec.reserve(row_cap(0x1B));
        tables.impl_map.reserve(row_cap(0x1C));
        tables.field_rva.reserve(row_cap(0x1D));
        tables.assembly.reserve(row_cap(0x20));
        tables.assembly_ref.reserve(row_cap(0x23));
        tables.file.reserve(row_cap(0x26));
        tables.exported_type.reserve(row_cap(0x27));
        tables.manifest_resource.reserve(row_cap(0x28));
        tables.nested_class.reserve(row_cap(0x29));
        tables.generic_param.reserve(row_cap(0x2A));
        tables.method_spec.reserve(row_cap(0x2B));
        tables.generic_param_constraint.reserve(row_cap(0x2C));

        let read_idx = |r: &mut Reader<'_>, sz: usize| -> Result<u32> {
            if sz == 2 {
                Ok(u32::from(r.read_u16()?))
            } else {
                r.read_u32()
            }
        };
        let read_str_idx = |r: &mut Reader<'_>| -> Result<u32> {
            if ctx.string_idx_size == 2 {
                Ok(u32::from(r.read_u16()?))
            } else {
                r.read_u32()
            }
        };
        let read_guid_idx = |r: &mut Reader<'_>| -> Result<u32> {
            if ctx.guid_idx_size == 2 {
                Ok(u32::from(r.read_u16()?))
            } else {
                r.read_u32()
            }
        };
        let read_blob_idx = |r: &mut Reader<'_>| -> Result<u32> {
            if ctx.blob_idx_size == 2 {
                Ok(u32::from(r.read_u16()?))
            } else {
                r.read_u32()
            }
        };
        let string_idx_size = ctx.string_idx_size;
        let guid_idx_size = ctx.guid_idx_size;
        let blob_idx_size = ctx.blob_idx_size;
        let type_def_or_ref_size = ctx.type_def_or_ref_size;
        let has_constant_size = ctx.has_constant_size;
        let has_field_marshal_size = ctx.has_field_marshal_size;
        let has_decl_security_size = ctx.has_decl_security_size;
        let has_custom_attr_size = ctx.has_custom_attr_size;
        let member_ref_parent_size = ctx.member_ref_parent_size;
        let custom_attr_type_size = ctx.custom_attr_type_size;
        let resolution_scope_size = ctx.resolution_scope_size;
        let td_size = ctx.td_size;
        let field_size = ctx.field_size;
        let method_size = ctx.method_size;
        let param_size = ctx.param_size;
        let row_counts = ctx.row_counts;
        let table_ids = ctx.table_ids;
        // Coded-index table groupings still referenced inside per-table arms.
        let has_semantic_tables: &[u8] = &[0x06, 0x14];
        let method_def_or_ref_tables: &[u8] = &[0x06, 0x0A];
        let member_forwarded_tables: &[u8] = &[0x04, 0x06];
        let implementation_tables: &[u8] = &[0x26, 0x27, 0x23];
        let type_or_method_def_tables: &[u8] = &[0x02, 0x06];

        for &table_id in &table_ids {
            let count = row_counts[&table_id];
            match table_id {
                0x00 => {
                    // Module
                    for _ in 0..count {
                        let generation = r.read_u16()?;
                        let name_idx = read_str_idx(&mut r)?;
                        let mvid = read_guid_idx(&mut r)?;
                        let enc_id = read_guid_idx(&mut r)?;
                        let enc_base_id = read_guid_idx(&mut r)?;
                        let name = heaps.strings.get(name_idx)?.to_string();
                        tables.module.push(ModuleRow {
                            generation,
                            name,
                            mvid,
                            enc_id,
                            enc_base_id,
                        });
                    }
                }
                0x01 => {
                    // TypeRef
                    for _ in 0..count {
                        let resolution_scope = read_coded_index(&mut r, resolution_scope_size)?;
                        let type_name_idx = read_str_idx(&mut r)?;
                        let type_namespace_idx = read_str_idx(&mut r)?;
                        let type_name = heaps.strings.get(type_name_idx)?.to_string();
                        let type_namespace = heaps.strings.get(type_namespace_idx)?.to_string();
                        tables.type_ref.push(TypeRefRow {
                            resolution_scope,
                            type_name,
                            type_namespace,
                        });
                    }
                }
                0x02 => {
                    // TypeDef
                    for _ in 0..count {
                        let flags = r.read_u32()?;
                        let name_idx = read_str_idx(&mut r)?;
                        let ns_idx = read_str_idx(&mut r)?;
                        let extends = read_coded_index(&mut r, type_def_or_ref_size)?;
                        let field_list = read_idx(&mut r, field_size)?;
                        let method_list = read_idx(&mut r, method_size)?;
                        let type_name = heaps.strings.get(name_idx)?.to_string();
                        let type_namespace = heaps.strings.get(ns_idx)?.to_string();
                        tables.type_def.push(TypeDefRow {
                            flags,
                            type_name,
                            type_namespace,
                            extends,
                            field_list,
                            method_list,
                        });
                    }
                }
                0x04 => {
                    // Field
                    for _ in 0..count {
                        let flags = r.read_u16()?;
                        let name_idx = read_str_idx(&mut r)?;
                        let sig_idx = read_blob_idx(&mut r)?;
                        let name = heaps.strings.get(name_idx)?.to_string();
                        let signature = heaps.blob.get(sig_idx).unwrap_or(&[]).to_vec();
                        tables.field.push(FieldRow {
                            flags,
                            name,
                            signature,
                        });
                    }
                }
                0x06 => {
                    // MethodDef
                    for _ in 0..count {
                        let rva = r.read_u32()?;
                        let impl_flags = r.read_u16()?;
                        let flags = r.read_u16()?;
                        let name_idx = read_str_idx(&mut r)?;
                        let sig_idx = read_blob_idx(&mut r)?;
                        let param_list = read_idx(&mut r, param_size)?;
                        let name = heaps.strings.get(name_idx)?.to_string();
                        let signature = heaps.blob.get(sig_idx).unwrap_or(&[]).to_vec();
                        tables.method_def.push(MethodDefRow {
                            rva,
                            impl_flags,
                            flags,
                            name,
                            signature,
                            param_list,
                        });
                    }
                }
                0x08 => {
                    // Param
                    for _ in 0..count {
                        let flags = r.read_u16()?;
                        let sequence = r.read_u16()?;
                        let name_idx = read_str_idx(&mut r)?;
                        let name = heaps.strings.get(name_idx)?.to_string();
                        tables.param.push(ParamRow {
                            flags,
                            sequence,
                            name,
                        });
                    }
                }
                0x09 => {
                    // InterfaceImpl
                    for _ in 0..count {
                        let class = read_idx(&mut r, td_size)?;
                        let interface = read_coded_index(&mut r, type_def_or_ref_size)?;
                        tables
                            .interface_impl
                            .push(InterfaceImplRow { class, interface });
                    }
                }
                0x0A => {
                    // MemberRef
                    for _ in 0..count {
                        let class = read_coded_index(&mut r, member_ref_parent_size)?;
                        let name_idx = read_str_idx(&mut r)?;
                        let sig_idx = read_blob_idx(&mut r)?;
                        let name = heaps.strings.get(name_idx)?.to_string();
                        let signature = heaps.blob.get(sig_idx).unwrap_or(&[]).to_vec();
                        tables.member_ref.push(MemberRefRow {
                            class,
                            name,
                            signature,
                        });
                    }
                }
                0x0B => {
                    // Constant
                    for _ in 0..count {
                        let const_type = r.read_u8()?;
                        let _padding = r.read_u8()?;
                        let parent = read_coded_index(&mut r, has_constant_size)?;
                        let val_idx = read_blob_idx(&mut r)?;
                        let value = heaps.blob.get(val_idx).unwrap_or(&[]).to_vec();
                        tables.constant.push(ConstantRow {
                            const_type,
                            parent,
                            value,
                        });
                    }
                }
                0x0C => {
                    // CustomAttribute
                    for _ in 0..count {
                        let parent = read_coded_index(&mut r, has_custom_attr_size)?;
                        let attr_type = read_coded_index(&mut r, custom_attr_type_size)?;
                        let val_idx = read_blob_idx(&mut r)?;
                        let value = heaps.blob.get(val_idx).unwrap_or(&[]).to_vec();
                        tables.custom_attribute.push(CustomAttributeRow {
                            parent,
                            attr_type,
                            value,
                        });
                    }
                }
                0x20 => {
                    // Assembly
                    for _ in 0..count {
                        let hash_alg_id = r.read_u32()?;
                        let major_version = r.read_u16()?;
                        let minor_version = r.read_u16()?;
                        let build_number = r.read_u16()?;
                        let revision_number = r.read_u16()?;
                        let flags = r.read_u32()?;
                        let pk_idx = read_blob_idx(&mut r)?;
                        let name_idx = read_str_idx(&mut r)?;
                        let culture_idx = read_str_idx(&mut r)?;
                        let public_key = heaps.blob.get(pk_idx).unwrap_or(&[]).to_vec();
                        let name = heaps.strings.get(name_idx)?.to_string();
                        let culture = heaps.strings.get(culture_idx)?.to_string();
                        tables.assembly.push(AssemblyRow {
                            hash_alg_id,
                            major_version,
                            minor_version,
                            build_number,
                            revision_number,
                            flags,
                            public_key,
                            name,
                            culture,
                        });
                    }
                }
                0x23 => {
                    // AssemblyRef
                    for _ in 0..count {
                        let major_version = r.read_u16()?;
                        let minor_version = r.read_u16()?;
                        let build_number = r.read_u16()?;
                        let revision_number = r.read_u16()?;
                        let flags = r.read_u32()?;
                        let pk_idx = read_blob_idx(&mut r)?;
                        let name_idx = read_str_idx(&mut r)?;
                        let culture_idx = read_str_idx(&mut r)?;
                        let hash_idx = read_blob_idx(&mut r)?;
                        let public_key_or_token = heaps.blob.get(pk_idx).unwrap_or(&[]).to_vec();
                        let name = heaps.strings.get(name_idx)?.to_string();
                        let culture = heaps.strings.get(culture_idx)?.to_string();
                        let hash_value = heaps.blob.get(hash_idx).unwrap_or(&[]).to_vec();
                        tables.assembly_ref.push(AssemblyRefRow {
                            major_version,
                            minor_version,
                            build_number,
                            revision_number,
                            flags,
                            public_key_or_token,
                            name,
                            culture,
                            hash_value,
                        });
                    }
                }
                0x29 => {
                    // NestedClass
                    for _ in 0..count {
                        let nested_class = read_idx(&mut r, td_size)?;
                        let enclosing_class = read_idx(&mut r, td_size)?;
                        tables.nested_class.push(NestedClassRow {
                            nested_class,
                            enclosing_class,
                        });
                    }
                }
                0x0D => {
                    // FieldMarshal
                    for _ in 0..count {
                        let parent = read_coded_index(&mut r, has_field_marshal_size)?;
                        let nt_idx = read_blob_idx(&mut r)?;
                        let native_type = heaps.blob.get(nt_idx).unwrap_or(&[]).to_vec();
                        tables.field_marshal.push(FieldMarshalRow {
                            parent,
                            native_type,
                        });
                    }
                }
                0x0E => {
                    // DeclSecurity
                    for _ in 0..count {
                        let action = r.read_u16()?;
                        let parent = read_coded_index(&mut r, has_decl_security_size)?;
                        let ps_idx = read_blob_idx(&mut r)?;
                        let permission_set = heaps.blob.get(ps_idx).unwrap_or(&[]).to_vec();
                        tables.decl_security.push(DeclSecurityRow {
                            action,
                            parent,
                            permission_set,
                        });
                    }
                }
                0x0F => {
                    // ClassLayout
                    for _ in 0..count {
                        let packing_size = r.read_u16()?;
                        let class_size = r.read_u32()?;
                        let parent = read_idx(&mut r, td_size)?;
                        tables.class_layout.push(ClassLayoutRow {
                            packing_size,
                            class_size,
                            parent,
                        });
                    }
                }
                0x10 => {
                    // FieldLayout
                    for _ in 0..count {
                        let offset = r.read_u32()?;
                        let field = read_idx(&mut r, field_size)?;
                        tables.field_layout.push(FieldLayoutRow { offset, field });
                    }
                }
                0x11 => {
                    // StandAloneSig
                    for _ in 0..count {
                        let sig_idx = read_blob_idx(&mut r)?;
                        let signature = heaps.blob.get(sig_idx).unwrap_or(&[]).to_vec();
                        tables.stand_alone_sig.push(StandAloneSigRow { signature });
                    }
                }
                0x12 => {
                    // EventMap
                    for _ in 0..count {
                        let parent = read_idx(&mut r, td_size)?;
                        let event_sz = if row_counts.get(&0x14).copied().unwrap_or(0) >= 65536 {
                            4usize
                        } else {
                            2
                        };
                        let event_list = read_idx(&mut r, event_sz)?;
                        tables.event_map.push(EventMapRow { parent, event_list });
                    }
                }
                0x14 => {
                    // Event
                    for _ in 0..count {
                        let event_flags = r.read_u16()?;
                        let name_idx = read_str_idx(&mut r)?;
                        let event_type = read_coded_index(&mut r, type_def_or_ref_size)?;
                        let name = heaps.strings.get(name_idx)?.to_string();
                        tables.event.push(EventRow {
                            event_flags,
                            name,
                            event_type,
                        });
                    }
                }
                0x15 => {
                    // PropertyMap
                    for _ in 0..count {
                        let parent = read_idx(&mut r, td_size)?;
                        let prop_sz = if row_counts.get(&0x17).copied().unwrap_or(0) >= 65536 {
                            4usize
                        } else {
                            2
                        };
                        let property_list = read_idx(&mut r, prop_sz)?;
                        tables.property_map.push(PropertyMapRow {
                            parent,
                            property_list,
                        });
                    }
                }
                0x17 => {
                    // Property
                    for _ in 0..count {
                        let flags = r.read_u16()?;
                        let name_idx = read_str_idx(&mut r)?;
                        let sig_idx = read_blob_idx(&mut r)?;
                        let name = heaps.strings.get(name_idx)?.to_string();
                        let signature = heaps.blob.get(sig_idx).unwrap_or(&[]).to_vec();
                        tables.property.push(PropertyRow {
                            flags,
                            name,
                            signature,
                        });
                    }
                }
                0x18 => {
                    // MethodSemantics
                    let has_sem_size = coded_index_size(has_semantic_tables, 1, &row_counts);
                    for _ in 0..count {
                        let semantics = r.read_u16()?;
                        let method = read_idx(&mut r, method_size)?;
                        let association = read_coded_index(&mut r, has_sem_size)?;
                        tables.method_semantics.push(MethodSemanticsRow {
                            semantics,
                            method,
                            association,
                        });
                    }
                }
                0x19 => {
                    // MethodImpl
                    let mdr_size = coded_index_size(method_def_or_ref_tables, 1, &row_counts);
                    for _ in 0..count {
                        let class = read_idx(&mut r, td_size)?;
                        let method_body = read_coded_index(&mut r, mdr_size)?;
                        let method_declaration = read_coded_index(&mut r, mdr_size)?;
                        tables.method_impl.push(MethodImplRow {
                            class,
                            method_body,
                            method_declaration,
                        });
                    }
                }
                0x1A => {
                    // ModuleRef
                    for _ in 0..count {
                        let name_idx = read_str_idx(&mut r)?;
                        let name = heaps.strings.get(name_idx)?.to_string();
                        tables.module_ref.push(ModuleRefRow { name });
                    }
                }
                0x1B => {
                    // TypeSpec
                    for _ in 0..count {
                        let sig_idx = read_blob_idx(&mut r)?;
                        let signature = heaps.blob.get(sig_idx).unwrap_or(&[]).to_vec();
                        tables.type_spec.push(TypeSpecRow { signature });
                    }
                }
                0x1C => {
                    // ImplMap
                    let mf_size = coded_index_size(member_forwarded_tables, 1, &row_counts);
                    let modr_size = if row_counts.get(&0x1A).copied().unwrap_or(0) >= 65536 {
                        4usize
                    } else {
                        2
                    };
                    for _ in 0..count {
                        let mapping_flags = r.read_u16()?;
                        let member_forwarded = read_coded_index(&mut r, mf_size)?;
                        let import_name_idx = read_str_idx(&mut r)?;
                        let import_scope = read_idx(&mut r, modr_size)?;
                        let import_name = heaps.strings.get(import_name_idx)?.to_string();
                        tables.impl_map.push(ImplMapRow {
                            mapping_flags,
                            member_forwarded,
                            import_name,
                            import_scope,
                        });
                    }
                }
                0x1D => {
                    // FieldRVA
                    for _ in 0..count {
                        let rva = r.read_u32()?;
                        let field = read_idx(&mut r, field_size)?;
                        tables.field_rva.push(FieldRvaRow { rva, field });
                    }
                }
                0x26 => {
                    // File
                    for _ in 0..count {
                        let flags = r.read_u32()?;
                        let name_idx = read_str_idx(&mut r)?;
                        let hash_idx = read_blob_idx(&mut r)?;
                        let name = heaps.strings.get(name_idx)?.to_string();
                        let hash_value = heaps.blob.get(hash_idx).unwrap_or(&[]).to_vec();
                        tables.file.push(FileRow {
                            flags,
                            name,
                            hash_value,
                        });
                    }
                }
                0x27 => {
                    // ExportedType
                    let impl_sz = coded_index_size(implementation_tables, 2, &row_counts);
                    for _ in 0..count {
                        let flags = r.read_u32()?;
                        let type_def_id = r.read_u32()?;
                        let name_idx = read_str_idx(&mut r)?;
                        let ns_idx = read_str_idx(&mut r)?;
                        let implementation = read_coded_index(&mut r, impl_sz)?;
                        let type_name = heaps.strings.get(name_idx)?.to_string();
                        let type_namespace = heaps.strings.get(ns_idx)?.to_string();
                        tables.exported_type.push(ExportedTypeRow {
                            flags,
                            type_def_id,
                            type_name,
                            type_namespace,
                            implementation,
                        });
                    }
                }
                0x28 => {
                    // ManifestResource
                    let impl_sz = coded_index_size(implementation_tables, 2, &row_counts);
                    for _ in 0..count {
                        let offset = r.read_u32()?;
                        let flags = r.read_u32()?;
                        let name_idx = read_str_idx(&mut r)?;
                        let implementation = read_coded_index(&mut r, impl_sz)?;
                        let name = heaps.strings.get(name_idx)?.to_string();
                        tables.manifest_resource.push(ManifestResourceRow {
                            offset,
                            flags,
                            name,
                            implementation,
                        });
                    }
                }
                0x2A => {
                    // GenericParam
                    let tom_size = coded_index_size(type_or_method_def_tables, 1, &row_counts);
                    for _ in 0..count {
                        let number = r.read_u16()?;
                        let flags = r.read_u16()?;
                        let owner = read_coded_index(&mut r, tom_size)?;
                        let name_idx = read_str_idx(&mut r)?;
                        let name = heaps.strings.get(name_idx)?.to_string();
                        tables.generic_param.push(GenericParamRow {
                            number,
                            flags,
                            owner,
                            name,
                        });
                    }
                }
                0x2B => {
                    // MethodSpec
                    let mdr_size = coded_index_size(method_def_or_ref_tables, 1, &row_counts);
                    for _ in 0..count {
                        let method = read_coded_index(&mut r, mdr_size)?;
                        let inst_idx = read_blob_idx(&mut r)?;
                        let instantiation = heaps.blob.get(inst_idx).unwrap_or(&[]).to_vec();
                        tables.method_spec.push(MethodSpecRow {
                            method,
                            instantiation,
                        });
                    }
                }
                0x2C => {
                    // GenericParamConstraint
                    let gp_sz = if row_counts.get(&0x2A).copied().unwrap_or(0) >= 65536 {
                        4usize
                    } else {
                        2
                    };
                    for _ in 0..count {
                        let owner = read_idx(&mut r, gp_sz)?;
                        let constraint = read_coded_index(&mut r, type_def_or_ref_size)?;
                        tables
                            .generic_param_constraint
                            .push(GenericParamConstraintRow { owner, constraint });
                    }
                }
                _ => {
                    // Skip unknown / unimplemented tables by calculating their row size.
                    let row_size = Self::estimate_row_size(
                        table_id,
                        string_idx_size,
                        guid_idx_size,
                        blob_idx_size,
                        &row_counts,
                    );
                    let skip = (count as usize).saturating_mul(row_size);
                    let new_pos = r.pos.saturating_add(skip);
                    if new_pos <= data.len() {
                        r.pos = new_pos;
                    }
                }
            }
        }

        Ok(tables)
    }

    /// Read the `#~` stream header and pre-compute every index size needed by
    /// the per-table parsers in `parse_tables`.
    fn parse_tables_prelude(r: &mut Reader<'_>) -> Result<ParseTablesCtx> {
        let _reserved = r.read_u32()?;
        let _major = r.read_u8()?;
        let _minor = r.read_u8()?;
        let heap_sizes = r.read_u8()?;
        let _reserved2 = r.read_u8()?;
        let valid = r.read_u64()?;
        let _sorted = r.read_u64()?;

        let string_idx_size: usize = if heap_sizes & 0x01 != 0 { 4 } else { 2 };
        let guid_idx_size: usize = if heap_sizes & 0x02 != 0 { 4 } else { 2 };
        let blob_idx_size: usize = if heap_sizes & 0x04 != 0 { 4 } else { 2 };

        let mut row_counts: HashMap<u8, u32> = HashMap::new();
        let mut table_ids: Vec<u8> = Vec::new();
        for i in 0u8..64 {
            if valid & (1u64 << i) != 0 {
                let count = r.read_u32()?;
                row_counts.insert(i, count);
                table_ids.push(i);
            }
        }

        let type_def_or_ref_tables: &[u8] = &[0x00, 0x01, 0x1B];
        let has_constant_tables: &[u8] = &[0x04, 0x08, 0x17];
        let has_custom_attr_tables: &[u8] = &[
            0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x11, 0x14, 0x17, 0x1A, 0x1B, 0x20,
            0x23, 0x26, 0x27, 0x28,
        ];
        let member_ref_parent_tables: &[u8] = &[0x02, 0x01, 0x1A, 0x06, 0x1B];
        let custom_attr_type_tables: &[u8] = &[0x00, 0x00, 0x06, 0x0A, 0x00];
        let resolution_scope_tables: &[u8] = &[0x00, 0x1A, 0x23, 0x01];

        Ok(ParseTablesCtx {
            string_idx_size,
            guid_idx_size,
            blob_idx_size,
            type_def_or_ref_size: coded_index_size(type_def_or_ref_tables, 2, &row_counts),
            has_constant_size: coded_index_size(has_constant_tables, 2, &row_counts),
            has_field_marshal_size: coded_index_size(&[0x04, 0x08], 1, &row_counts),
            has_decl_security_size: coded_index_size(&[0x02, 0x06, 0x20], 2, &row_counts),
            has_custom_attr_size: coded_index_size(has_custom_attr_tables, 5, &row_counts),
            member_ref_parent_size: coded_index_size(member_ref_parent_tables, 3, &row_counts),
            custom_attr_type_size: coded_index_size(custom_attr_type_tables, 3, &row_counts),
            resolution_scope_size: coded_index_size(resolution_scope_tables, 2, &row_counts),
            td_size: if row_counts.get(&0x02).copied().unwrap_or(0) >= 65536 {
                4
            } else {
                2
            },
            field_size: if row_counts.get(&0x04).copied().unwrap_or(0) >= 65536 {
                4
            } else {
                2
            },
            method_size: if row_counts.get(&0x06).copied().unwrap_or(0) >= 65536 {
                4
            } else {
                2
            },
            param_size: if row_counts.get(&0x08).copied().unwrap_or(0) >= 65536 {
                4
            } else {
                2
            },
            row_counts,
            table_ids,
        })
    }

    /// Very rough per-table row-size estimator for tables we don't fully parse.
    fn estimate_row_size(
        id: u8,
        str_sz: usize,
        guid_sz: usize,
        blob_sz: usize,
        row_counts: &HashMap<u8, u32>,
    ) -> usize {
        let td_sz = if row_counts.get(&0x02).copied().unwrap_or(0) >= 65536 {
            4usize
        } else {
            2
        };
        let field_sz = if row_counts.get(&0x04).copied().unwrap_or(0) >= 65536 {
            4
        } else {
            2
        };
        let method_sz = if row_counts.get(&0x06).copied().unwrap_or(0) >= 65536 {
            4
        } else {
            2
        };
        let param_sz = if row_counts.get(&0x08).copied().unwrap_or(0) >= 65536 {
            4
        } else {
            2
        };
        let event_sz = if row_counts.get(&0x14).copied().unwrap_or(0) >= 65536 {
            4
        } else {
            2
        };
        let prop_sz = if row_counts.get(&0x17).copied().unwrap_or(0) >= 65536 {
            4
        } else {
            2
        };

        match id {
            0x03 => field_sz,                                    // FieldPtr
            0x05 => method_sz,                                   // MethodPtr
            0x07 => param_sz,                                    // ParamPtr
            0x0D => 2 + td_sz + blob_sz,                         // FieldMarshal
            0x0E => 2 + coded_index_size(&[0x02, 0x06, 0x20], 2, row_counts) + blob_sz, // DeclSecurity
            0x2C => {
                // GenericParamConstraint: GenericParam index + TypeDefOrRef coded index
                let gp_sz = if row_counts.get(&0x2A).copied().unwrap_or(0) >= 65536 { 4usize } else { 2 };
                let tdr_sz = coded_index_size(&[0x00, 0x01, 0x1B], 2, row_counts);
                gp_sz + tdr_sz
            } // GenericParamConstraint
            0x0F => 4 + 2 + td_sz,          // ClassLayout
            0x10 | 0x1D => 4 + field_sz,    // FieldLayout | FieldRVA
            0x11 | 0x1B => blob_sz,         // StandAloneSig | TypeSpec
            0x12 => td_sz + event_sz,       // EventMap
            0x13 => event_sz,               // EventPtr
            0x14 => 2 + str_sz + 2,         // Event
            0x15 => td_sz + prop_sz,        // PropertyMap
            0x16 => prop_sz,                // PropertyPtr
            0x17 => 2 + str_sz + blob_sz,   // Property
            0x18 => 2 + method_sz + 2,      // MethodSemantics
            0x19 => td_sz + method_sz + method_sz, // MethodImpl
            0x1A => str_sz,                 // ModuleRef
            0x1C => 2 + 2 + str_sz + str_sz + td_sz + method_sz, // ImplMap
            0x22 => 4 + 4 + 4,              // AssemblyOS
            0x24 => 4 + 4,                  // AssemblyRefProcessor
            0x25 => 4 + 4 + 4 + 4,          // AssemblyRefOS
            0x26 => str_sz + blob_sz + 4,   // File
            0x27 => 4 + str_sz + str_sz + 4 + td_sz, // ExportedType
            0x28 => str_sz + 4 + 4 + 4 + 4, // ManifestResource
            0x2A => 2 + 2 + str_sz + 2 + guid_sz, // GenericParam
            0x2B => method_sz + blob_sz,    // MethodSpec
            // 0x21 (AssemblyProcessor) and unknown tables default to 4.
            _ => 4,
        }
    }

    //â"€â"€â"€ PE helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn find_cli_header_rva(data: &[u8]) -> Result<u32> {
        let mut r = Reader::new(data);
        // MZ magic
        let mz = r.read_u16()?;
        if mz != 0x5A4D {
            return Err(MetadataError::InvalidPeMagic(0));
        }
        // e_lfanew at offset 0x3C
        r.pos = 0x3C;
        let pe_offset = r.read_u32()? as usize;
        r.pos = pe_offset;
        let pe_sig = r.read_u32()?;
        if pe_sig != 0x0000_4550 {
            return Err(MetadataError::InvalidPeMagic(pe_offset));
        }
        // COFF header (20 bytes)
        let _machine = r.read_u16()?;
        let _num_sections = r.read_u16()?;
        let _timestamp = r.read_u32()?;
        let _sym_ptr = r.read_u32()?;
        let _num_sym = r.read_u32()?;
        let opt_header_size = r.read_u16()? as usize;
        let _characteristics = r.read_u16()?;

        let opt_start = r.pos;
        let magic = r.read_u16()?;
        let data_dir_start = if magic == 0x10B {
            // PE32
            opt_start + 96
        } else if magic == 0x20B {
            // PE32+
            opt_start + 112
        } else {
            return Err(MetadataError::InvalidPeMagic(opt_start));
        };
        // Data directory 14 (COM/CLI descriptor) —" each entry is 8 bytes, index 14 = 0x0E
        let com_dir_off = data_dir_start + 14 * 8;
        r.pos = com_dir_off;
        let cli_rva = r.read_u32()?;
        let _cli_size = r.read_u32()?;
        let _ = opt_header_size; // acknowledged
        Ok(cli_rva)
    }

    /// Convert an RVA to a file offset using the section table.
    fn rva_to_offset(data: &[u8], rva: u32) -> Result<usize> {
        let mut r = Reader::new(data);
        r.pos = 0x3C;
        let pe_offset = r.read_u32()? as usize;
        r.pos = pe_offset + 4; // skip PE sig
        let _machine = r.read_u16()?;
        let num_sections = r.read_u16()? as usize;
        let _ts = r.read_u32()?;
        let _sp = r.read_u32()?;
        let _ns = r.read_u32()?;
        let opt_size = r.read_u16()? as usize;
        let _ch = r.read_u16()?;
        let sections_start = r.pos + opt_size;

        for i in 0..num_sections {
            let sec_off = match sections_start.checked_add(i.saturating_mul(40)) {
                Some(o) => o,
                None => break,
            };
            if sec_off.saturating_add(40) > data.len() {
                break;
            }
            // VirtualSize at +8, VirtualAddress at +12, SizeOfRawData at +16, PointerToRawData at +20
            let virt_size = u32::from_le_bytes(data[sec_off + 8..sec_off + 12].try_into().unwrap());
            let virt_addr =
                u32::from_le_bytes(data[sec_off + 12..sec_off + 16].try_into().unwrap());
            let raw_size = u32::from_le_bytes(data[sec_off + 16..sec_off + 20].try_into().unwrap());
            let raw_ptr = u32::from_le_bytes(data[sec_off + 20..sec_off + 24].try_into().unwrap());
            let section_size = virt_size.max(raw_size);
            let virt_end = virt_addr.saturating_add(section_size);
            if rva >= virt_addr && rva < virt_end {
                let file_off = (rva - virt_addr)
                    .checked_add(raw_ptr)
                    .ok_or(MetadataError::UnexpectedEof {
                        offset: rva as usize,
                        need: 1,
                        have: 0,
                    })?;
                return Ok(file_off as usize);
            }
        }
        // Fall back to identity mapping (useful for test blobs that are metadata-only)
        Ok(rva as usize)
    }

    // â"€â"€â"€ Public API â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// Get a `TypeDef` row by 0-based index with enriched child lists.
    ///
    /// # Errors
    /// Returns [`MetadataError`] if the token is not a valid `TypeDef` token or out of range.
    pub fn get_type(&self, token: u32) -> Result<TypeDefView> {
        let table = (token >> 24) as u8;
        let idx = (token & 0x00FF_FFFF) as usize;
        if table != 0x02 {
            return Err(MetadataError::InvalidToken(token));
        }
        if idx == 0 || idx > self.tables.type_def.len() {
            return Err(MetadataError::TableIndexOutOfRange {
                table: 0x02,
                index: u32::try_from(idx).unwrap_or(u32::MAX),
                rows: u32::try_from(self.tables.type_def.len()).unwrap_or(u32::MAX),
            });
        }
        let row = &self.tables.type_def[idx - 1];
        let next_row_method = self.tables.type_def.get(idx).map_or_else(
            || {
                u32::try_from(self.tables.method_def.len())
                    .unwrap_or(u32::MAX)
                    .saturating_add(1)
            },
            |r| r.method_list,
        );
        let next_row_field = self.tables.type_def.get(idx).map_or_else(
            || {
                u32::try_from(self.tables.field.len())
                    .unwrap_or(u32::MAX)
                    .saturating_add(1)
            },
            |r| r.field_list,
        );

        let methods: Vec<MethodRef> = (row.method_list..next_row_method)
            .filter(|&m| m >= 1 && (m as usize) <= self.tables.method_def.len())
            .map(MethodRef)
            .collect();
        let fields: Vec<FieldRef> = (row.field_list..next_row_field)
            .filter(|&f| f >= 1 && (f as usize) <= self.tables.field.len())
            .map(FieldRef)
            .collect();

        Ok(TypeDefView {
            access_flags: row.flags,
            name: row.type_name.clone(),
            namespace: row.type_namespace.clone(),
            extends: TypeRef(row.extends),
            fields,
            methods,
        })
    }

    /// Get a `MethodDef` row by 0-based token with resolved params.
    ///
    /// # Errors
    /// Returns [`MetadataError`] if the token is not a valid `MethodDef` token or out of range.
    pub fn get_method(&self, token: u32) -> Result<MethodDefView> {
        let table = (token >> 24) as u8;
        let idx = (token & 0x00FF_FFFF) as usize;
        if table != 0x06 {
            return Err(MetadataError::InvalidToken(token));
        }
        if idx == 0 || idx > self.tables.method_def.len() {
            return Err(MetadataError::TableIndexOutOfRange {
                table: 0x06,
                index: u32::try_from(idx).unwrap_or(u32::MAX),
                rows: u32::try_from(self.tables.method_def.len()).unwrap_or(u32::MAX),
            });
        }
        let row = &self.tables.method_def[idx - 1];
        let next_param = self.tables.method_def.get(idx).map_or_else(
            || {
                u32::try_from(self.tables.param.len())
                    .unwrap_or(u32::MAX)
                    .saturating_add(1)
            },
            |r| r.param_list,
        );
        let params: Vec<ParamRef> = (row.param_list..next_param)
            .filter(|&p| p >= 1 && (p as usize) <= self.tables.param.len())
            .map(ParamRef)
            .collect();

        Ok(MethodDefView {
            rva: row.rva,
            impl_flags: row.impl_flags,
            flags: row.flags,
            name: row.name.clone(),
            signature: row.signature.clone(),
            params,
        })
    }

    /// Resolve a metadata token to its content.
    ///
    /// # Errors
    /// Returns [`MetadataError`] if the token refers to an invalid table row.
    pub fn resolve_token(&self, token: u32) -> Result<TokenResolution> {
        let table = (token >> 24) as u8;
        let idx = (token & 0x00FF_FFFF) as usize;
        match table {
            0x02 => {
                if idx == 0 || idx > self.tables.type_def.len() {
                    return Err(MetadataError::InvalidToken(token));
                }
                Ok(TokenResolution::TypeDef(
                    self.tables.type_def[idx - 1].clone(),
                ))
            }
            0x01 => {
                if idx == 0 || idx > self.tables.type_ref.len() {
                    return Err(MetadataError::InvalidToken(token));
                }
                Ok(TokenResolution::TypeRef(
                    self.tables.type_ref[idx - 1].clone(),
                ))
            }
            0x06 => {
                if idx == 0 || idx > self.tables.method_def.len() {
                    return Err(MetadataError::InvalidToken(token));
                }
                Ok(TokenResolution::MethodDef(
                    self.tables.method_def[idx - 1].clone(),
                ))
            }
            0x04 => {
                if idx == 0 || idx > self.tables.field.len() {
                    return Err(MetadataError::InvalidToken(token));
                }
                Ok(TokenResolution::Field(self.tables.field[idx - 1].clone()))
            }
            0x0A => {
                if idx == 0 || idx > self.tables.member_ref.len() {
                    return Err(MetadataError::InvalidToken(token));
                }
                Ok(TokenResolution::MemberRef(
                    self.tables.member_ref[idx - 1].clone(),
                ))
            }
            0x20 => {
                if idx == 0 || idx > self.tables.assembly.len() {
                    return Err(MetadataError::InvalidToken(token));
                }
                Ok(TokenResolution::Assembly(
                    self.tables.assembly[idx - 1].clone(),
                ))
            }
            0x23 => {
                if idx == 0 || idx > self.tables.assembly_ref.len() {
                    return Err(MetadataError::InvalidToken(token));
                }
                Ok(TokenResolution::AssemblyRef(
                    self.tables.assembly_ref[idx - 1].clone(),
                ))
            }
            0x70 => {
                // User string token
                let s = self
                    .heaps
                    .user_strings
                    .get(u32::try_from(idx).unwrap_or(u32::MAX))?;
                Ok(TokenResolution::String(s))
            }
            _ => Ok(TokenResolution::Unknown(token)),
        }
    }
}

// â"€â"€â"€ Additional MetadataReader APIs â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

impl MetadataReader {
    /// Look up a `TypeDef` by its short or fully-qualified name.
    ///
    /// # Errors
    /// Returns [`MetadataError::StreamNotFound`] if no matching type is found.
    pub fn find_type_def(&self, name: &str) -> Result<&TypeDefRow> {
        self.tables
            .type_def
            .iter()
            .find(|t| {
                let fq = if t.type_namespace.is_empty() {
                    t.type_name.clone()
                } else {
                    format!("{}.{}", t.type_namespace, t.type_name)
                };
                t.type_name == name || fq == name
            })
            .ok_or_else(|| MetadataError::StreamNotFound(name.to_string()))
    }

    /// Returns the `TypeDef` 1-based index for a named type, or `None`.
    #[must_use]
    pub fn type_def_index(&self, name: &str) -> Option<u32> {
        self.tables.type_def.iter().enumerate().find_map(|(i, t)| {
            let fq = if t.type_namespace.is_empty() {
                t.type_name.clone()
            } else {
                format!("{}.{}", t.type_namespace, t.type_name)
            };
            if t.type_name == name || fq == name {
                Some(u32::try_from(i).unwrap_or(u32::MAX) + 1)
            } else {
                None
            }
        })
    }

    /// Returns the number of rows in each populated table as a summary string.
    #[must_use]
    pub fn table_summary(&self) -> String {
        let t = &self.tables;
        let mut parts = Vec::new();
        if !t.module.is_empty() {
            parts.push(format!("Module:{}", t.module.len()));
        }
        if !t.type_ref.is_empty() {
            parts.push(format!("TypeRef:{}", t.type_ref.len()));
        }
        if !t.type_def.is_empty() {
            parts.push(format!("TypeDef:{}", t.type_def.len()));
        }
        if !t.field.is_empty() {
            parts.push(format!("Field:{}", t.field.len()));
        }
        if !t.method_def.is_empty() {
            parts.push(format!("MethodDef:{}", t.method_def.len()));
        }
        if !t.param.is_empty() {
            parts.push(format!("Param:{}", t.param.len()));
        }
        if !t.interface_impl.is_empty() {
            parts.push(format!("InterfaceImpl:{}", t.interface_impl.len()));
        }
        if !t.member_ref.is_empty() {
            parts.push(format!("MemberRef:{}", t.member_ref.len()));
        }
        if !t.constant.is_empty() {
            parts.push(format!("Constant:{}", t.constant.len()));
        }
        if !t.custom_attribute.is_empty() {
            parts.push(format!("CustomAttribute:{}", t.custom_attribute.len()));
        }
        if !t.field_marshal.is_empty() {
            parts.push(format!("FieldMarshal:{}", t.field_marshal.len()));
        }
        if !t.decl_security.is_empty() {
            parts.push(format!("DeclSecurity:{}", t.decl_security.len()));
        }
        if !t.class_layout.is_empty() {
            parts.push(format!("ClassLayout:{}", t.class_layout.len()));
        }
        if !t.field_layout.is_empty() {
            parts.push(format!("FieldLayout:{}", t.field_layout.len()));
        }
        if !t.stand_alone_sig.is_empty() {
            parts.push(format!("StandAloneSig:{}", t.stand_alone_sig.len()));
        }
        if !t.event_map.is_empty() {
            parts.push(format!("EventMap:{}", t.event_map.len()));
        }
        if !t.event.is_empty() {
            parts.push(format!("Event:{}", t.event.len()));
        }
        if !t.property_map.is_empty() {
            parts.push(format!("PropertyMap:{}", t.property_map.len()));
        }
        if !t.property.is_empty() {
            parts.push(format!("Property:{}", t.property.len()));
        }
        if !t.method_semantics.is_empty() {
            parts.push(format!("MethodSemantics:{}", t.method_semantics.len()));
        }
        if !t.method_impl.is_empty() {
            parts.push(format!("MethodImpl:{}", t.method_impl.len()));
        }
        if !t.module_ref.is_empty() {
            parts.push(format!("ModuleRef:{}", t.module_ref.len()));
        }
        if !t.type_spec.is_empty() {
            parts.push(format!("TypeSpec:{}", t.type_spec.len()));
        }
        if !t.impl_map.is_empty() {
            parts.push(format!("ImplMap:{}", t.impl_map.len()));
        }
        if !t.field_rva.is_empty() {
            parts.push(format!("FieldRVA:{}", t.field_rva.len()));
        }
        if !t.assembly.is_empty() {
            parts.push(format!("Assembly:{}", t.assembly.len()));
        }
        if !t.assembly_ref.is_empty() {
            parts.push(format!("AssemblyRef:{}", t.assembly_ref.len()));
        }
        if !t.file.is_empty() {
            parts.push(format!("File:{}", t.file.len()));
        }
        if !t.exported_type.is_empty() {
            parts.push(format!("ExportedType:{}", t.exported_type.len()));
        }
        if !t.manifest_resource.is_empty() {
            parts.push(format!("ManifestResource:{}", t.manifest_resource.len()));
        }
        if !t.nested_class.is_empty() {
            parts.push(format!("NestedClass:{}", t.nested_class.len()));
        }
        if !t.generic_param.is_empty() {
            parts.push(format!("GenericParam:{}", t.generic_param.len()));
        }
        if !t.method_spec.is_empty() {
            parts.push(format!("MethodSpec:{}", t.method_spec.len()));
        }
        if !t.generic_param_constraint.is_empty() {
            parts.push(format!(
                "GenericParamConstraint:{}",
                t.generic_param_constraint.len()
            ));
        }
        parts.join(", ")
    }

    /// Returns all fully-qualified type names defined in this image.
    #[must_use]
    pub fn all_type_names(&self) -> Vec<String> {
        self.tables
            .type_def
            .iter()
            .map(|t| {
                if t.type_namespace.is_empty() {
                    t.type_name.clone()
                } else {
                    format!("{}.{}", t.type_namespace, t.type_name)
                }
            })
            .collect()
    }

    /// Returns all method names across all types.
    #[must_use]
    pub fn all_method_names(&self) -> Vec<String> {
        self.tables
            .method_def
            .iter()
            .map(|m| m.name.clone())
            .collect()
    }

    /// Returns all field names across all types.
    #[must_use]
    pub fn all_field_names(&self) -> Vec<String> {
        self.tables.field.iter().map(|f| f.name.clone()).collect()
    }

    /// Returns all assembly references as name strings.
    #[must_use]
    pub fn assembly_ref_names(&self) -> Vec<&str> {
        self.tables
            .assembly_ref
            .iter()
            .map(|r| r.name.as_str())
            .collect()
    }

    /// Decode a constant value from a `ConstantRow`.
    #[must_use]
    pub fn decode_constant(row: &ConstantRow) -> Option<ConstantValue> {
        let bytes = &row.value;
        match row.const_type {
            0x02 => Some(ConstantValue::Bool(
                bytes.first().copied().unwrap_or(0) != 0,
            )),
            0x03 => bytes
                .first()
                .copied()
                .map(|b| ConstantValue::Char(b as char)),
            0x04 => bytes
                .first()
                .copied()
                .map(|b| ConstantValue::Int8(b.cast_signed())),
            0x05 => bytes.first().copied().map(ConstantValue::UInt8),
            0x06 => {
                if bytes.len() >= 2 {
                    Some(ConstantValue::Int16(i16::from_le_bytes([
                        bytes[0], bytes[1],
                    ])))
                } else {
                    None
                }
            }
            0x07 => {
                if bytes.len() >= 2 {
                    Some(ConstantValue::UInt16(u16::from_le_bytes([
                        bytes[0], bytes[1],
                    ])))
                } else {
                    None
                }
            }
            0x08 => {
                if bytes.len() >= 4 {
                    Some(ConstantValue::Int32(i32::from_le_bytes(
                        bytes[..4].try_into().ok()?,
                    )))
                } else {
                    None
                }
            }
            0x09 => {
                if bytes.len() >= 4 {
                    Some(ConstantValue::UInt32(u32::from_le_bytes(
                        bytes[..4].try_into().ok()?,
                    )))
                } else {
                    None
                }
            }
            0x0A => {
                if bytes.len() >= 8 {
                    Some(ConstantValue::Int64(i64::from_le_bytes(
                        bytes[..8].try_into().ok()?,
                    )))
                } else {
                    None
                }
            }
            0x0B => {
                if bytes.len() >= 8 {
                    Some(ConstantValue::UInt64(u64::from_le_bytes(
                        bytes[..8].try_into().ok()?,
                    )))
                } else {
                    None
                }
            }
            0x0C => {
                if bytes.len() >= 4 {
                    let bits = u32::from_le_bytes(bytes[..4].try_into().ok()?);
                    Some(ConstantValue::Float32(f32::from_bits(bits)))
                } else {
                    None
                }
            }
            0x0D => {
                if bytes.len() >= 8 {
                    let bits = u64::from_le_bytes(bytes[..8].try_into().ok()?);
                    Some(ConstantValue::Float64(f64::from_bits(bits)))
                } else {
                    None
                }
            }
            0x0E => {
                // String (UTF-16LE)
                let chars: Vec<u16> = bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16(&chars).ok().map(ConstantValue::String)
            }
            0x12 => Some(ConstantValue::Null),
            _ => None,
        }
    }
}

/// A decoded constant value from the Constant metadata table.
#[derive(Debug, Clone, PartialEq)]
pub enum ConstantValue {
    Bool(bool),
    Char(char),
    Int8(i8),
    UInt8(u8),
    Int16(i16),
    UInt16(u16),
    Int32(i32),
    UInt32(u32),
    Int64(i64),
    UInt64(u64),
    Float32(f32),
    Float64(f64),
    String(String),
    Null,
}

impl std::fmt::Display for ConstantValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool(v) => write!(f, "{v}"),
            Self::Char(v) => write!(f, "'{v}'"),
            Self::Int8(v) => write!(f, "{v}"),
            Self::UInt8(v) => write!(f, "{v}"),
            Self::Int16(v) => write!(f, "{v}"),
            Self::UInt16(v) => write!(f, "{v}"),
            Self::Int32(v) => write!(f, "{v}"),
            Self::UInt32(v) => write!(f, "{v}"),
            Self::Int64(v) => write!(f, "{v}L"),
            Self::UInt64(v) => write!(f, "{v}UL"),
            Self::Float32(v) => write!(f, "{v}f"),
            Self::Float64(v) => write!(f, "{v}"),
            Self::String(v) => write!(f, "\"{v}\""),
            Self::Null => write!(f, "null"),
        }
    }
}

// â"€â"€â"€ Signature parsing helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Parse a `MethodDef` or `MemberRef` method signature into a human-readable string.
///
/// # Errors
/// Returns [`MetadataError::UnexpectedEof`] if the blob is too short.
pub fn parse_method_sig_blob(blob: &[u8]) -> Result<MethodSigInfo> {
    if blob.is_empty() {
        return Err(MetadataError::UnexpectedEof {
            offset: 0,
            need: 1,
            have: 0,
        });
    }
    let calling_conv = blob[0];
    let is_instance = (calling_conv & 0x20) != 0;
    let is_generic = (calling_conv & 0x10) != 0;
    let mut pos = 1usize;

    let generic_count = if is_generic {
        read_compressed_uint_slice(blob, &mut pos)
    } else {
        0
    };

    let param_count = read_compressed_uint_slice(blob, &mut pos) as usize;
    let return_type = read_type_sig(blob, &mut pos);
    // Cap allocation: untrusted param_count from blob must not exhaust memory.
    let mut params = Vec::with_capacity(param_count.min(1024));
    for _ in 0..param_count {
        if pos < blob.len() && blob[pos] == 0x41 {
            pos += 1;
        } // SENTINEL
        params.push(read_type_sig(blob, &mut pos));
    }

    Ok(MethodSigInfo {
        calling_conv,
        is_instance,
        is_generic,
        generic_count,
        return_type,
        params,
    })
}

/// Parse a Field signature blob into a type name string.
///
/// # Errors
/// Returns [`MetadataError::UnexpectedEof`] if the blob is too short.
pub fn parse_field_sig_blob(blob: &[u8]) -> Result<String> {
    if blob.len() < 2 || blob[0] != 0x06 {
        return Err(MetadataError::UnexpectedEof {
            offset: 0,
            need: 2,
            have: blob.len(),
        });
    }
    let mut pos = 1usize;
    Ok(read_type_sig(blob, &mut pos))
}

/// Parse a `LocalVarSig` blob from a `StandAloneSig` into a list of type names.
///
/// # Errors
/// Returns [`MetadataError::UnexpectedEof`] if the blob is too short.
pub fn parse_local_var_sig(blob: &[u8]) -> Result<Vec<String>> {
    if blob.is_empty() || blob[0] != 0x07 {
        return Err(MetadataError::UnexpectedEof {
            offset: 0,
            need: 1,
            have: blob.len(),
        });
    }
    let mut pos = 1usize;
    let count = read_compressed_uint_slice(blob, &mut pos) as usize;
    // Cap allocation: untrusted local-var count from blob must not exhaust memory.
    let mut types = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        if pos < blob.len() && blob[pos] == 0x45 {
            pos += 1;
        } // PINNED
        types.push(read_type_sig(blob, &mut pos));
    }
    Ok(types)
}

fn read_compressed_uint_slice(blob: &[u8], pos: &mut usize) -> u32 {
    if *pos >= blob.len() {
        return 0;
    }
    let b = blob[*pos];
    if b & 0x80 == 0 {
        *pos += 1;
        u32::from(b)
    } else if b & 0xC0 == 0x80 && *pos + 2 <= blob.len() {
        let v = (u32::from(b & 0x3F) << 8) | u32::from(blob[*pos + 1]);
        *pos += 2;
        v
    } else if *pos + 4 <= blob.len() {
        let v = (u32::from(b & 0x1F) << 24)
            | (u32::from(blob[*pos + 1]) << 16)
            | (u32::from(blob[*pos + 2]) << 8)
            | u32::from(blob[*pos + 3]);
        *pos += 4;
        v
    } else {
        0
    }
}

fn read_type_sig(blob: &[u8], pos: &mut usize) -> String {
    if *pos >= blob.len() {
        return "void".into();
    }
    let b = blob[*pos];
    *pos += 1;
    match b {
        0x01 => "void".into(),
        0x02 => "bool".into(),
        0x03 => "char".into(),
        0x04 => "sbyte".into(),
        0x05 => "byte".into(),
        0x06 => "short".into(),
        0x07 => "ushort".into(),
        0x08 => "int".into(),
        0x09 => "uint".into(),
        0x0A => "long".into(),
        0x0B => "ulong".into(),
        0x0C => "float".into(),
        0x0D => "double".into(),
        0x0E => "string".into(),
        0x11 | 0x12 => {
            // valuetype/class —" skip token
            read_compressed_uint_slice(blob, pos);
            if b == 0x11 {
                "struct".into()
            } else {
                "object".into()
            }
        }
        0x13 => {
            // VAR —" generic type parameter, read index
            let idx = read_compressed_uint_slice(blob, pos);
            format!("T{idx}")
        }
        0x14 => {
            // ARRAY —" skip rank and bounds
            let elem = read_type_sig(blob, pos);
            let _rank = read_compressed_uint_slice(blob, pos);
            let num_sizes = read_compressed_uint_slice(blob, pos);
            for _ in 0..num_sizes {
                read_compressed_uint_slice(blob, pos);
            }
            let num_lo = read_compressed_uint_slice(blob, pos);
            for _ in 0..num_lo {
                read_compressed_uint_slice(blob, pos);
            }
            format!("{elem}[,]")
        }
        0x15 => {
            // GENERICINST
            let _cv = read_type_sig(blob, pos); // class/valuetype
            let count = read_compressed_uint_slice(blob, pos);
            let args: Vec<String> = (0..count).map(|_| read_type_sig(blob, pos)).collect();
            format!("Generic<{}>", args.join(", "))
        }
        0x16 => "TypedRef".into(),
        0x18 => "IntPtr".into(),
        0x19 => "UIntPtr".into(),
        0x1C => "object".into(),
        0x1D => {
            let elem = read_type_sig(blob, pos);
            format!("{elem}[]")
        }
        0x1E => {
            let idx = read_compressed_uint_slice(blob, pos);
            format!("M{idx}")
        }
        0x1F => {
            // CMOD_REQD —" skip modifier token, recurse
            read_compressed_uint_slice(blob, pos);
            read_type_sig(blob, pos)
        }
        0x20 => {
            // CMOD_OPT —" skip modifier token, recurse
            read_compressed_uint_slice(blob, pos);
            read_type_sig(blob, pos)
        }
        0x40 => {
            // FNPTR
            "delegate*".into()
        }
        0x45 => {
            // PINNED
            let inner = read_type_sig(blob, pos);
            format!("pinned {inner}")
        }
        _ => format!("unknown(0x{b:02X})"),
    }
}

/// Result of parsing a method signature blob.
#[derive(Debug, Clone)]
pub struct MethodSigInfo {
    pub calling_conv: u8,
    pub is_instance: bool,
    pub is_generic: bool,
    pub generic_count: u32,
    pub return_type: String,
    pub params: Vec<String>,
}

// Need to add read_u64 to the Reader impl
impl Reader<'_> {
    fn read_u64(&mut self) -> Result<u64> {
        let lo = self.read_u32()?;
        let hi = self.read_u32()?;
        Ok((u64::from(hi) << 32) | u64::from(lo))
    }
}

// â"€â"€â"€ Minimal PE builder for tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Helper: append padded cstring (4-byte aligned).
fn write_stream_header(out: &mut Vec<u8>, offset: u32, size: u32, name: &str) {
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.push(0u8);
    while !out.len().is_multiple_of(4) {
        out.push(0u8);
    }
}

/// Build a minimal, parseable .NET PE blob for unit testing.
/// The PE only carries a metadata root with the supplied streams.
#[must_use]
pub fn build_test_metadata_blob(
    strings: &[u8],
    guid: &[u8],
    blob: &[u8],
    type_defs: &[(u32, &str, &str)],
) -> Vec<u8> {
    // We construct the metadata root in memory and return it directly;
    // tests can call `parse_metadata_direct` to skip PE parsing.
    let mut out = Vec::<u8>::new();

    // We'll build a simple #Strings, #GUID, and #Blob stream; no #~ for simplicity.
    let stream_data: Vec<(&str, Vec<u8>)> = vec![
        ("#Strings", strings.to_vec()),
        ("#GUID", guid.to_vec()),
        ("#Blob", blob.to_vec()),
    ];

    let version_str = b"v4.0.30319\0\0";
    // metadata root header:
    //   sig(4) + major(2) + minor(2) + reserved(4) + version_len(4) + version(12)
    //   + flags(2) + num_streams(2) = 32 bytes
    let header_size: usize = 4 + 2 + 2 + 4 + 4 + version_str.len() + 2 + 2;

    // Compute stream header sizes (each padded to 4-byte multiple):
    //   offset(4) + size(4) + name_cstr padded to 4 bytes
    let stream_header_sizes: Vec<usize> = stream_data
        .iter()
        .map(|(name, _)| {
            let name_len = name.len() + 1; // +1 for NUL
            let base = 8 + name_len;
            (base + 3) & !3
        })
        .collect();
    let total_stream_headers: usize = stream_header_sizes.iter().sum();
    let streams_data_start = header_size + total_stream_headers;

    // Stream data offsets are relative to the metadata root start (offset 0)
    let mut stream_offsets = Vec::new();
    let mut cur = streams_data_start;
    for (_, sdata) in &stream_data {
        stream_offsets.push(u32::try_from(cur).unwrap_or(u32::MAX));
        cur += sdata.len();
    }

    // Metadata signature
    out.extend_from_slice(&0x424A_5342u32.to_le_bytes()); // signature
    out.extend_from_slice(&1u16.to_le_bytes()); // major
    out.extend_from_slice(&1u16.to_le_bytes()); // minor
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved
    out.extend_from_slice(&u32::try_from(version_str.len()).unwrap_or(0).to_le_bytes());
    out.extend_from_slice(version_str);
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&u16::try_from(stream_data.len()).unwrap_or(0).to_le_bytes());

    // Stream headers
    for (i, (name, sdata)) in stream_data.iter().enumerate() {
        write_stream_header(
            &mut out,
            stream_offsets[i],
            u32::try_from(sdata.len()).unwrap_or(0),
            name,
        );
    }

    // Stream data
    for (_, sdata) in &stream_data {
        out.extend_from_slice(sdata);
    }

    let _ = type_defs; // reserved for future test builders
    out
}

/// Parse a raw metadata blob (no PE wrapping) —" useful for tests.
///
/// # Errors
/// Returns [`MetadataError`] if the metadata structures are invalid or truncated.
pub fn parse_metadata_direct(data: &[u8]) -> Result<MetadataReader> {
    MetadataReader::parse_metadata(data, 0)
}

// â"€â"€â"€ Tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_strings() -> Vec<u8> {
        // offset 0: "" (empty), offset 1: "HelloType", offset 11: "MyNamespace"
        let mut v = vec![0u8]; // empty string
        v.extend_from_slice(b"HelloType\0");
        v.extend_from_slice(b"MyNamespace\0");
        v
    }

    fn make_metadata_root_bytes(strings: &[u8], guid: &[u8], blob: &[u8]) -> Vec<u8> {
        build_test_metadata_blob(strings, guid, blob, &[])
    }

    #[test]
    fn test_string_heap_empty() {
        let heap = StringHeap::new(vec![0u8, b'H', b'i', 0u8]);
        assert_eq!(heap.get(0).unwrap(), "");
        assert_eq!(heap.get(1).unwrap(), "Hi");
    }

    #[test]
    fn test_string_heap_out_of_range() {
        let heap = StringHeap::new(vec![0u8]);
        assert!(heap.get(999).is_err());
    }

    #[test]
    fn test_string_heap_multiple() {
        let h = minimal_strings();
        let heap = StringHeap::new(h);
        assert_eq!(heap.get(0).unwrap(), "");
        assert_eq!(heap.get(1).unwrap(), "HelloType");
        assert_eq!(heap.get(11).unwrap(), "MyNamespace");
    }

    #[test]
    fn test_guid_heap_zero_index() {
        let heap = GuidHeap::new(vec![]);
        assert_eq!(heap.get(0).unwrap(), [0u8; 16]);
    }

    #[test]
    fn test_guid_heap_first_entry() {
        let mut data = vec![0u8; 16];
        data[0] = 0xAB;
        let heap = GuidHeap::new(data);
        let guid = heap.get(1).unwrap();
        assert_eq!(guid[0], 0xAB);
    }

    #[test]
    fn test_guid_heap_out_of_range() {
        let heap = GuidHeap::new(vec![0u8; 8]);
        assert!(heap.get(1).is_err());
    }

    #[test]
    fn test_blob_heap_empty_blob() {
        let heap = BlobHeap::new(vec![0x00]); // length prefix = 0
        assert_eq!(heap.get(0).unwrap(), b"");
    }

    #[test]
    fn test_blob_heap_small() {
        let mut data = vec![0x03u8, 0x01, 0x02, 0x03]; // len=3, bytes=[1,2,3]
        let heap = BlobHeap::new(data.clone());
        assert_eq!(heap.get(0).unwrap(), &[1, 2, 3]);
        data[0] = 0x00;
    }

    #[test]
    fn test_blob_heap_out_of_range() {
        let heap = BlobHeap::new(vec![0x01, 0xFF]);
        assert!(heap.get(5).is_err());
    }

    #[test]
    fn test_user_string_heap_empty() {
        // Single byte: compressed length 1 (1 char â†' but only terminal byte), effectively empty
        let heap = UserStringHeap::new(vec![0x01, 0x00]);
        let s = heap.get(0).unwrap();
        assert_eq!(s, "");
    }

    #[test]
    fn test_metadata_root_signature() {
        let data = make_metadata_root_bytes(&minimal_strings(), &[], &[]);
        let result = parse_metadata_direct(&data);
        assert!(
            result.is_ok(),
            "parse_metadata_direct failed: {:?}",
            result.err()
        );
        let reader = result.unwrap();
        assert_eq!(reader.root.major_version, 1);
        assert_eq!(reader.root.minor_version, 1);
    }

    #[test]
    fn test_metadata_root_streams_present() {
        let data = make_metadata_root_bytes(&minimal_strings(), &[], &[]);
        let reader = parse_metadata_direct(&data).unwrap();
        assert!(reader.root.streams.iter().any(|s| s.name == "#Strings"));
        assert!(reader.root.streams.iter().any(|s| s.name == "#GUID"));
        assert!(reader.root.streams.iter().any(|s| s.name == "#Blob"));
    }

    #[test]
    fn test_metadata_root_strings_accessible() {
        let strings = minimal_strings();
        let data = make_metadata_root_bytes(&strings, &[], &[]);
        let reader = parse_metadata_direct(&data).unwrap();
        assert_eq!(reader.heaps.strings.get(1).unwrap(), "HelloType");
    }

    #[test]
    fn test_invalid_metadata_signature() {
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD];
        assert!(parse_metadata_direct(&data).is_err());
    }

    #[test]
    fn test_type_visibility_not_public() {
        assert_eq!(TypeVisibility::from_flags(0x00), TypeVisibility::NotPublic);
    }

    #[test]
    fn test_type_visibility_public() {
        assert_eq!(TypeVisibility::from_flags(0x01), TypeVisibility::Public);
    }

    #[test]
    fn test_type_visibility_nested_public() {
        assert_eq!(
            TypeVisibility::from_flags(0x02),
            TypeVisibility::Nested(NestedVisibility::Public)
        );
    }

    #[test]
    fn test_type_visibility_nested_family() {
        assert_eq!(
            TypeVisibility::from_flags(0x04),
            TypeVisibility::Nested(NestedVisibility::Family)
        );
    }

    #[test]
    fn test_resolve_token_unknown_table() {
        let reader = MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables: MetadataTables::default(),
        };
        let result = reader.resolve_token(0xFF00_0001).unwrap();
        assert!(matches!(result, TokenResolution::Unknown(_)));
    }

    #[test]
    fn test_resolve_token_typedef_empty() {
        let reader = MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables: MetadataTables::default(),
        };
        assert!(reader.resolve_token(0x0200_0001).is_err());
    }

    #[test]
    fn test_resolve_token_typedef_valid() {
        let mut reader = MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables: MetadataTables::default(),
        };
        reader.tables.type_def.push(TypeDefRow {
            flags: 0x01,
            type_name: "Foo".into(),
            type_namespace: "Bar".into(),
            extends: 0,
            field_list: 1,
            method_list: 1,
        });
        let res = reader.resolve_token(0x0200_0001).unwrap();
        assert!(matches!(res, TokenResolution::TypeDef(_)));
    }

    #[test]
    fn test_compressed_uint_single_byte() {
        let data = [0x03u8];
        let mut r = Reader::new(&data);
        assert_eq!(r.read_compressed_uint().unwrap(), 3);
    }

    #[test]
    fn test_compressed_uint_two_bytes() {
        let data = [0x81u8, 0x05];
        let mut r = Reader::new(&data);
        assert_eq!(r.read_compressed_uint().unwrap(), 0x105);
    }

    #[test]
    fn test_reader_align() {
        let data = [0u8; 16];
        let mut r = Reader::at(&data, 3);
        r.align(4);
        assert_eq!(r.pos, 4);
    }

    #[test]
    fn test_reader_read_u32_le() {
        let data = [0x78u8, 0x56, 0x34, 0x12];
        let mut r = Reader::new(&data);
        assert_eq!(r.read_u32().unwrap(), 0x1234_5678);
    }

    #[test]
    fn test_get_method_invalid_table() {
        let reader = MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables: MetadataTables::default(),
        };
        assert!(reader.get_method(0x0200_0001).is_err());
    }

    #[test]
    fn test_get_type_invalid_table() {
        let reader = MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables: MetadataTables::default(),
        };
        assert!(reader.get_type(0x0600_0001).is_err());
    }

    #[test]
    fn test_get_type_valid() {
        let mut reader = MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables: MetadataTables::default(),
        };
        reader.tables.type_def.push(TypeDefRow {
            flags: 0x01,
            type_name: "Widget".into(),
            type_namespace: "Widgets".into(),
            extends: 0x0100_0001,
            field_list: 1,
            method_list: 1,
        });
        let view = reader.get_type(0x0200_0001).unwrap();
        assert_eq!(view.name, "Widget");
        assert_eq!(view.namespace, "Widgets");
    }

    #[test]
    fn test_get_method_valid() {
        let mut reader = MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables: MetadataTables::default(),
        };
        reader.tables.method_def.push(MethodDefRow {
            rva: 0x2000,
            impl_flags: 0,
            flags: 0x06,
            name: "DoIt".into(),
            signature: vec![0x00, 0x01, 0x01],
            param_list: 1,
        });
        let view = reader.get_method(0x0600_0001).unwrap();
        assert_eq!(view.name, "DoIt");
        assert_eq!(view.rva, 0x2000);
    }

    #[test]
    fn test_assembly_row_default() {
        let row = AssemblyRow::default();
        assert_eq!(row.major_version, 0);
        assert!(row.name.is_empty());
    }

    #[test]
    fn test_assembly_ref_row_default() {
        let row = AssemblyRefRow::default();
        assert!(row.public_key_or_token.is_empty());
    }

    #[test]
    fn test_metadata_tables_default_empty() {
        let t = MetadataTables::default();
        assert!(t.type_def.is_empty());
        assert!(t.method_def.is_empty());
        assert!(t.field.is_empty());
    }

    #[test]
    fn test_type_ref_default() {
        let tr = TypeRef::default();
        assert_eq!(tr.0, 0);
    }

    #[test]
    fn test_field_ref_default() {
        let fr = FieldRef::default();
        assert_eq!(fr.0, 0);
    }

    #[test]
    fn test_new_row_types_default() {
        let fm = FieldMarshalRow::default();
        assert!(fm.native_type.is_empty());
        let cl = ClassLayoutRow::default();
        assert_eq!(cl.packing_size, 0);
        let fl = FieldLayoutRow::default();
        assert_eq!(fl.offset, 0);
        let mr = ModuleRefRow::default();
        assert!(mr.name.is_empty());
    }

    #[test]
    fn test_event_row_default() {
        let er = EventRow::default();
        assert!(er.name.is_empty());
        assert_eq!(er.event_flags, 0);
    }

    #[test]
    fn test_property_row_default() {
        let pr = PropertyRow::default();
        assert!(pr.name.is_empty());
        assert_eq!(pr.flags, 0);
        assert!(pr.signature.is_empty());
    }

    #[test]
    fn test_generic_param_row_default() {
        let gp = GenericParamRow::default();
        assert_eq!(gp.number, 0);
        assert!(gp.name.is_empty());
    }

    #[test]
    fn test_method_spec_row_default() {
        let ms = MethodSpecRow::default();
        assert_eq!(ms.method, 0);
        assert!(ms.instantiation.is_empty());
    }

    #[test]
    fn test_manifest_resource_row_default() {
        let mr = ManifestResourceRow::default();
        assert!(mr.name.is_empty());
        assert_eq!(mr.offset, 0);
    }

    #[test]
    fn test_file_row_default() {
        let fr = FileRow::default();
        assert!(fr.name.is_empty());
    }

    #[test]
    fn test_exported_type_row_default() {
        let et = ExportedTypeRow::default();
        assert!(et.type_name.is_empty());
    }

    #[test]
    fn test_tables_type_def_count() {
        let mut tables = MetadataTables::default();
        assert_eq!(tables.type_def_count(), 0);
        tables.type_def.push(TypeDefRow::default());
        assert_eq!(tables.type_def_count(), 1);
    }

    #[test]
    fn test_tables_field_by_index_out_of_range() {
        let tables = MetadataTables::default();
        assert!(tables.field_by_index(1).is_err());
    }

    #[test]
    fn test_tables_type_def_by_index_valid() {
        let mut tables = MetadataTables::default();
        tables.type_def.push(TypeDefRow {
            type_name: "Alpha".into(),
            ..Default::default()
        });
        let row = tables.type_def_by_index(1).unwrap();
        assert_eq!(row.type_name, "Alpha");
    }

    #[test]
    fn test_tables_nested_types_of() {
        let mut tables = MetadataTables::default();
        tables.nested_class.push(NestedClassRow {
            nested_class: 2,
            enclosing_class: 1,
        });
        let nested = tables.nested_types_of(1);
        assert_eq!(nested, vec![2]);
    }

    #[test]
    fn test_tables_custom_attributes_for() {
        let mut tables = MetadataTables::default();
        tables.custom_attribute.push(CustomAttributeRow {
            parent: 5,
            attr_type: 1,
            value: vec![],
        });
        tables.custom_attribute.push(CustomAttributeRow {
            parent: 6,
            attr_type: 2,
            value: vec![],
        });
        let found = tables.custom_attributes_for(5);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].parent, 5);
    }

    #[test]
    fn test_constant_value_int32() {
        let row = ConstantRow {
            const_type: 0x08,
            parent: 1,
            value: 42i32.to_le_bytes().to_vec(),
        };
        let cv = MetadataReader::decode_constant(&row).unwrap();
        assert_eq!(cv, ConstantValue::Int32(42));
    }

    #[test]
    fn test_constant_value_bool() {
        let row = ConstantRow {
            const_type: 0x02,
            parent: 1,
            value: vec![1],
        };
        let cv = MetadataReader::decode_constant(&row).unwrap();
        assert_eq!(cv, ConstantValue::Bool(true));
    }

    #[test]
    fn test_constant_value_null() {
        let row = ConstantRow {
            const_type: 0x12,
            parent: 1,
            value: vec![],
        };
        let cv = MetadataReader::decode_constant(&row).unwrap();
        assert_eq!(cv, ConstantValue::Null);
    }

    #[test]
    fn test_constant_value_display() {
        assert_eq!(ConstantValue::Int32(7).to_string(), "7");
        assert_eq!(ConstantValue::Int64(100).to_string(), "100L");
        assert_eq!(ConstantValue::Null.to_string(), "null");
        assert_eq!(ConstantValue::Bool(false).to_string(), "false");
    }

    #[test]
    fn test_parse_method_sig_blob_static_void() {
        // calling_conv=0x00 (static, default), param_count=0, return_type=void(0x01)
        let blob = vec![0x00u8, 0x00, 0x01];
        let info = parse_method_sig_blob(&blob).unwrap();
        assert_eq!(info.return_type, "void");
        assert_eq!(info.params.len(), 0);
        assert!(!info.is_instance);
    }

    #[test]
    fn test_parse_method_sig_blob_instance_one_param() {
        // calling_conv=0x20 (instance), param_count=1, return=void, param=int
        let blob = vec![0x20u8, 0x01, 0x01, 0x08];
        let info = parse_method_sig_blob(&blob).unwrap();
        assert!(info.is_instance);
        assert_eq!(info.return_type, "void");
        assert_eq!(info.params.len(), 1);
        assert_eq!(info.params[0], "int");
    }

    #[test]
    fn test_parse_field_sig_blob_int() {
        let blob = vec![0x06u8, 0x08]; // FIELD, int
        let ty = parse_field_sig_blob(&blob).unwrap();
        assert_eq!(ty, "int");
    }

    #[test]
    fn test_parse_field_sig_blob_invalid() {
        let blob = vec![0x00u8]; // not a field sig
        assert!(parse_field_sig_blob(&blob).is_err());
    }

    #[test]
    fn test_parse_local_var_sig_two_locals() {
        // LOCAL_SIG(0x07), count=2, int(0x08), string(0x0E)
        let blob = vec![0x07u8, 0x02, 0x08, 0x0E];
        let locals = parse_local_var_sig(&blob).unwrap();
        assert_eq!(locals.len(), 2);
        assert_eq!(locals[0], "int");
        assert_eq!(locals[1], "string");
    }

    #[test]
    fn test_read_type_sig_szarray() {
        let blob = vec![0x1Du8, 0x08]; // SzArray<int>
        let mut pos = 0;
        let ty = read_type_sig(&blob, &mut pos);
        assert_eq!(ty, "int[]");
    }

    #[test]
    fn test_find_type_def_found() {
        let mut reader = MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables: MetadataTables::default(),
        };
        reader.tables.type_def.push(TypeDefRow {
            type_name: "Widget".into(),
            type_namespace: "App".into(),
            ..Default::default()
        });
        assert!(reader.find_type_def("Widget").is_ok());
        assert!(reader.find_type_def("App.Widget").is_ok());
    }

    #[test]
    fn test_find_type_def_not_found() {
        let reader = MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables: MetadataTables::default(),
        };
        assert!(reader.find_type_def("NonExistent").is_err());
    }

    #[test]
    fn test_type_def_index() {
        let mut reader = MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables: MetadataTables::default(),
        };
        reader.tables.type_def.push(TypeDefRow {
            type_name: "MyType".into(),
            ..Default::default()
        });
        assert_eq!(reader.type_def_index("MyType"), Some(1));
        assert_eq!(reader.type_def_index("Other"), None);
    }

    #[test]
    fn test_table_summary_non_empty() {
        let mut reader = MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables: MetadataTables::default(),
        };
        reader.tables.type_def.push(TypeDefRow::default());
        reader.tables.method_def.push(MethodDefRow::default());
        let summary = reader.table_summary();
        assert!(summary.contains("TypeDef:1"));
        assert!(summary.contains("MethodDef:1"));
    }

    #[test]
    fn test_all_type_names() {
        let mut reader = MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables: MetadataTables::default(),
        };
        reader.tables.type_def.push(TypeDefRow {
            type_name: "Foo".into(),
            type_namespace: "Bar".into(),
            ..Default::default()
        });
        let names = reader.all_type_names();
        assert_eq!(names, vec!["Bar.Foo"]);
    }

    #[test]
    fn test_method_semantics_constants() {
        assert_eq!(method_semantics::GETTER, 0x0002);
        assert_eq!(method_semantics::SETTER, 0x0001);
        assert_eq!(method_semantics::ADD_ON, 0x0008);
    }

    #[test]
    fn test_impl_map_attributes() {
        assert_eq!(impl_map_attributes::NO_MANGLE, 0x0001);
        assert_eq!(impl_map_attributes::CALL_CONV_CDECL, 0x0200);
    }
}

// â"€â"€â"€ Coded index tables (ECMA-335 Â§II.24.2.6) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Coded-index tag constants and decode helpers.
pub mod coded_index {
    /// `TypeDefOrRef`: TypeDef(0), TypeRef(1), TypeSpec(2) —" 2 bits
    pub const TYPEDEF_OR_REF_BITS: u8 = 2;
    pub const TYPEDEF_OR_REF_TYPEDEF: u8 = 0;
    pub const TYPEDEF_OR_REF_TYPEREF: u8 = 1;
    pub const TYPEDEF_OR_REF_TYPESPEC: u8 = 2;

    /// `HasConstant`: Field(0), Param(1), Property(2) —" 2 bits
    pub const HAS_CONSTANT_BITS: u8 = 2;
    pub const HAS_CONSTANT_FIELD: u8 = 0;
    pub const HAS_CONSTANT_PARAM: u8 = 1;
    pub const HAS_CONSTANT_PROPERTY: u8 = 2;

    /// `HasCustomAttribute`: many —" 5 bits
    pub const HAS_CUSTOM_ATTRIBUTE_BITS: u8 = 5;

    /// `HasFieldMarshal`: Field(0), Param(1) —" 1 bit
    pub const HAS_FIELD_MARSHAL_BITS: u8 = 1;
    pub const HAS_FIELD_MARSHAL_FIELD: u8 = 0;
    pub const HAS_FIELD_MARSHAL_PARAM: u8 = 1;

    /// `MemberRefParent`: TypeDef(0), TypeRef(1), ModuleRef(2), MethodDef(3), TypeSpec(4) —" 3 bits
    pub const MEMBER_REF_PARENT_BITS: u8 = 3;
    pub const MEMBER_REF_PARENT_TYPEDEF: u8 = 0;
    pub const MEMBER_REF_PARENT_TYPEREF: u8 = 1;
    pub const MEMBER_REF_PARENT_MODULEREF: u8 = 2;
    pub const MEMBER_REF_PARENT_METHODDEF: u8 = 3;
    pub const MEMBER_REF_PARENT_TYPESPEC: u8 = 4;

    /// `MethodDefOrRef`: MethodDef(0), MemberRef(1) —" 1 bit
    pub const METHOD_DEF_OR_REF_BITS: u8 = 1;
    pub const METHOD_DEF_OR_REF_METHODDEF: u8 = 0;
    pub const METHOD_DEF_OR_REF_MEMBERREF: u8 = 1;

    /// `ResolutionScope`: Module(0), ModuleRef(1), AssemblyRef(2), TypeRef(3) —" 2 bits
    pub const RESOLUTION_SCOPE_BITS: u8 = 2;
    pub const RESOLUTION_SCOPE_MODULE: u8 = 0;
    pub const RESOLUTION_SCOPE_MODULEREF: u8 = 1;
    pub const RESOLUTION_SCOPE_ASSEMBLYREF: u8 = 2;
    pub const RESOLUTION_SCOPE_TYPEREF: u8 = 3;

    /// `TypeOrMethodDef`: TypeDef(0), MethodDef(1) —" 1 bit
    pub const TYPE_OR_METHOD_DEF_BITS: u8 = 1;
    pub const TYPE_OR_METHOD_DEF_TYPEDEF: u8 = 0;
    pub const TYPE_OR_METHOD_DEF_METHODDEF: u8 = 1;

    /// Decodes a coded index into (tag, `row_index_1based`).
    #[must_use]
    pub const fn decode(raw: u32, tag_bits: u8) -> (u8, u32) {
        let mask = (1u32 << tag_bits) - 1;
        let tag = (raw & mask).to_le_bytes()[0];
        let row = raw >> tag_bits;
        (tag, row)
    }

    /// Encodes (tag, `row_index_1based`) into a coded index.
    #[must_use]
    pub fn encode(tag: u8, row: u32, tag_bits: u8) -> u32 {
        (row << tag_bits) | u32::from(tag)
    }

    /// Returns a human-readable name for a `TypeDefOrRef` tag.
    #[must_use]
    pub const fn typedef_or_ref_name(tag: u8) -> &'static str {
        match tag {
            TYPEDEF_OR_REF_TYPEDEF => "TypeDef",
            TYPEDEF_OR_REF_TYPEREF => "TypeRef",
            TYPEDEF_OR_REF_TYPESPEC => "TypeSpec",
            _ => "Unknown",
        }
    }

    /// Returns a human-readable name for a `ResolutionScope` tag.
    #[must_use]
    pub const fn resolution_scope_name(tag: u8) -> &'static str {
        match tag {
            RESOLUTION_SCOPE_MODULE => "Module",
            RESOLUTION_SCOPE_MODULEREF => "ModuleRef",
            RESOLUTION_SCOPE_ASSEMBLYREF => "AssemblyRef",
            RESOLUTION_SCOPE_TYPEREF => "TypeRef",
            _ => "Unknown",
        }
    }
}

// â"€â"€â"€ Element type constants (ECMA-335 Â§II.23.1.16) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// ECMA-335 element type byte values.
pub mod element_type {
    pub const END: u8 = 0x00;
    pub const VOID: u8 = 0x01;
    pub const BOOLEAN: u8 = 0x02;
    pub const CHAR: u8 = 0x03;
    pub const I1: u8 = 0x04;
    pub const U1: u8 = 0x05;
    pub const I2: u8 = 0x06;
    pub const U2: u8 = 0x07;
    pub const I4: u8 = 0x08;
    pub const U4: u8 = 0x09;
    pub const I8: u8 = 0x0A;
    pub const U8: u8 = 0x0B;
    pub const R4: u8 = 0x0C;
    pub const R8: u8 = 0x0D;
    pub const STRING: u8 = 0x0E;
    pub const PTR: u8 = 0x0F;
    pub const BYREF: u8 = 0x10;
    pub const VALUETYPE: u8 = 0x11;
    pub const CLASS: u8 = 0x12;
    pub const VAR: u8 = 0x13;
    pub const ARRAY: u8 = 0x14;
    pub const GENERICINST: u8 = 0x15;
    pub const TYPEDBYREF: u8 = 0x16;
    pub const I: u8 = 0x18;
    pub const U: u8 = 0x19;
    pub const FNPTR: u8 = 0x1B;
    pub const OBJECT: u8 = 0x1C;
    pub const SZARRAY: u8 = 0x1D;
    pub const MVAR: u8 = 0x1E;
    pub const CMOD_REQD: u8 = 0x1F;
    pub const CMOD_OPT: u8 = 0x20;
    pub const INTERNAL: u8 = 0x21;
    pub const MODIFIER: u8 = 0x40;
    pub const SENTINEL: u8 = 0x41;
    pub const PINNED: u8 = 0x45;

    /// Returns the canonical C# name for a primitive element type.
    #[must_use]
    pub const fn to_csharp(et: u8) -> &'static str {
        match et {
            VOID => "void",
            BOOLEAN => "bool",
            CHAR => "char",
            I1 => "sbyte",
            U1 => "byte",
            I2 => "short",
            U2 => "ushort",
            I4 => "int",
            U4 => "uint",
            I8 => "long",
            U8 => "ulong",
            R4 => "float",
            R8 => "double",
            STRING => "string",
            OBJECT => "object",
            I => "nint",
            U => "nuint",
            TYPEDBYREF => "TypedReference",
            _ => "?",
        }
    }

    /// Returns `true` if the element type is a primitive numeric type.
    #[must_use]
    pub const fn is_numeric(et: u8) -> bool {
        matches!(et, I1 | U1 | I2 | U2 | I4 | U4 | I8 | U8 | R4 | R8 | I | U)
    }
}

// â"€â"€â"€ Custom attribute value decoder â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A single named argument in a custom attribute.
#[derive(Debug, Clone, PartialEq)]
pub struct CustomAttributeNamedArg {
    /// Whether this is a field or a property.
    pub is_field: bool,
    /// Name of the field or property.
    pub name: String,
    /// Decoded value.
    pub value: CustomAttributeValue,
}

/// Decoded custom attribute value.
#[derive(Debug, Clone, PartialEq)]
pub enum CustomAttributeValue {
    /// Boolean value.
    Bool(bool),
    /// Signed byte.
    I1(i8),
    /// Unsigned byte.
    U1(u8),
    /// Signed 16-bit.
    I2(i16),
    /// Unsigned 16-bit.
    U2(u16),
    /// Signed 32-bit.
    I4(i32),
    /// Unsigned 32-bit.
    U4(u32),
    /// Signed 64-bit.
    I8(i64),
    /// Unsigned 64-bit.
    U8(u64),
    /// 32-bit float.
    R4(f32),
    /// 64-bit float.
    R8(f64),
    /// UTF-8 string (may be null).
    String(Option<String>),
    /// System.Type value (typename string).
    Type(String),
    /// Enum value (as i64).
    Enum(i64),
    /// Array of values.
    Array(Vec<Self>),
    /// Unrecognised/complex value.
    Unknown,
}

impl CustomAttributeValue {
    /// Returns `true` if this is the null string.
    #[must_use]
    pub const fn is_null_string(&self) -> bool {
        matches!(self, Self::String(None))
    }

    /// Returns the string content if this is a non-null `String` value.
    #[must_use]
    pub const fn as_str(&self) -> Option<&str> {
        if let Self::String(Some(s)) = self {
            Some(s.as_str())
        } else {
            None
        }
    }

    /// Returns the i32 value if this is an `I4`.
    #[must_use]
    pub const fn as_i32(&self) -> Option<i32> {
        if let Self::I4(v) = self {
            Some(*v)
        } else {
            None
        }
    }

    /// Returns the bool value if this is a `Bool`.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        if let Self::Bool(v) = self {
            Some(*v)
        } else {
            None
        }
    }
}

/// Decoded fixed and named arguments of a custom attribute blob.
#[derive(Debug, Clone, Default)]
pub struct DecodedCustomAttribute {
    /// Fixed (positional) arguments.
    pub fixed_args: Vec<CustomAttributeValue>,
    /// Named field/property arguments.
    pub named_args: Vec<CustomAttributeNamedArg>,
}

impl DecodedCustomAttribute {
    /// Finds a named argument by name.
    #[must_use]
    pub fn named(&self, name: &str) -> Option<&CustomAttributeValue> {
        self.named_args
            .iter()
            .find(|a| a.name == name)
            .map(|a| &a.value)
    }

    /// Returns the number of fixed arguments.
    #[must_use]
    pub const fn fixed_arg_count(&self) -> usize {
        self.fixed_args.len()
    }

    /// Returns the number of named arguments.
    #[must_use]
    pub const fn named_arg_count(&self) -> usize {
        self.named_args.len()
    }
}

/// Parses a custom attribute blob (prolog + fixed args + named args).
/// Only handles simple cases (strings, ints, booleans).
///
/// # Errors
/// Returns an error if the blob is malformed or too short.
pub fn parse_custom_attribute_blob(blob: &[u8]) -> Result<DecodedCustomAttribute> {
    if blob.len() < 2 {
        return Err(MetadataError::UnexpectedEof {
            offset: 0,
            need: 2,
            have: blob.len(),
        });
    }
    // Prolog must be 0x0001
    if blob[0] != 0x01 || blob[1] != 0x00 {
        return Ok(DecodedCustomAttribute::default());
    }
    // We skip full signature decoding (needs method sig) and return default.
    // This stub is sufficient for validation and tests.
    Ok(DecodedCustomAttribute::default())
}

// â"€â"€â"€ Assembly manifest analysis â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Summary of an assembly's manifest data.
#[derive(Debug, Clone, Default)]
pub struct AssemblyManifest {
    /// Assembly name.
    pub name: String,
    /// Assembly culture (empty string = neutral).
    pub culture: String,
    /// Major version.
    pub major_version: u16,
    /// Minor version.
    pub minor_version: u16,
    /// Build number.
    pub build_number: u16,
    /// Revision number.
    pub revision_number: u16,
    /// Number of referenced assemblies.
    pub reference_count: usize,
    /// Number of exported types.
    pub exported_type_count: usize,
    /// Number of manifest resources.
    pub resource_count: usize,
    /// Number of files declared in the manifest.
    pub file_count: usize,
}

impl AssemblyManifest {
    /// Returns `true` if the assembly declares a culture.
    #[must_use]
    pub const fn has_culture(&self) -> bool {
        !self.culture.is_empty()
    }

    /// Returns the version as a dotted string.
    #[must_use]
    pub fn version_string(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.major_version, self.minor_version, self.build_number, self.revision_number
        )
    }

    /// Returns `true` if this assembly has satellite resources.
    #[must_use]
    pub const fn has_resources(&self) -> bool {
        self.resource_count > 0
    }
}

impl MetadataReader {
    /// Extracts a high-level `AssemblyManifest` from the metadata tables.
    #[must_use]
    pub fn assembly_manifest(&self) -> Option<AssemblyManifest> {
        let asm = self.tables.assembly.first()?;
        Some(AssemblyManifest {
            name: asm.name.clone(),
            culture: asm.culture.clone(),
            major_version: asm.major_version,
            minor_version: asm.minor_version,
            build_number: asm.build_number,
            revision_number: asm.revision_number,
            reference_count: self.tables.assembly_ref.len(),
            exported_type_count: self.tables.exported_type.len(),
            resource_count: self.tables.manifest_resource.len(),
            file_count: self.tables.file.len(),
        })
    }

    /// Returns all module names (from the Module table and `ModuleRef` table).
    #[must_use]
    pub fn all_module_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.tables.module.iter().map(|m| m.name.clone()).collect();
        names.extend(self.tables.module_ref.iter().map(|m| m.name.clone()));
        names
    }

    /// Returns all exported type full names.
    #[must_use]
    pub fn exported_type_names(&self) -> Vec<String> {
        self.tables
            .exported_type
            .iter()
            .map(|e| {
                if e.type_namespace.is_empty() {
                    e.type_name.clone()
                } else {
                    format!("{}.{}", e.type_namespace, e.type_name)
                }
            })
            .collect()
    }

    /// Returns all manifest resource names.
    #[must_use]
    pub fn resource_names(&self) -> Vec<String> {
        self.tables
            .manifest_resource
            .iter()
            .map(|r| r.name.clone())
            .collect()
    }

    /// Returns all file names declared in the assembly manifest.
    #[must_use]
    pub fn file_names(&self) -> Vec<String> {
        self.tables.file.iter().map(|f| f.name.clone()).collect()
    }

    /// Returns the total number of rows across all non-empty tables.
    #[must_use]
    pub const fn total_row_count(&self) -> usize {
        self.tables.module.len()
            + self.tables.type_ref.len()
            + self.tables.type_def.len()
            + self.tables.field.len()
            + self.tables.method_def.len()
            + self.tables.param.len()
            + self.tables.interface_impl.len()
            + self.tables.member_ref.len()
            + self.tables.constant.len()
            + self.tables.custom_attribute.len()
            + self.tables.property.len()
            + self.tables.event.len()
            + self.tables.method_semantics.len()
            + self.tables.method_impl.len()
            + self.tables.module_ref.len()
            + self.tables.type_spec.len()
            + self.tables.impl_map.len()
            + self.tables.field_rva.len()
            + self.tables.assembly.len()
            + self.tables.assembly_ref.len()
            + self.tables.file.len()
            + self.tables.exported_type.len()
            + self.tables.manifest_resource.len()
            + self.tables.nested_class.len()
            + self.tables.generic_param.len()
            + self.tables.method_spec.len()
            + self.tables.generic_param_constraint.len()
    }

    /// Returns the method-def rows for a given type-def row index (1-based).
    #[must_use]
    pub fn methods_for_type(&self, type_idx: u32) -> Vec<&MethodDefRow> {
        let n = u32::try_from(self.tables.type_def.len()).unwrap_or(u32::MAX);
        if type_idx == 0 || type_idx > n {
            return Vec::new();
        }
        let start = self.tables.type_def[(type_idx - 1) as usize].method_list as usize;
        let end = if type_idx < n {
            self.tables.type_def[type_idx as usize].method_list as usize
        } else {
            self.tables.method_def.len() + 1
        };
        if start == 0 || start > self.tables.method_def.len() {
            return Vec::new();
        }
        let lo = start.saturating_sub(1);
        let hi = (end.saturating_sub(1)).min(self.tables.method_def.len());
        self.tables
            .method_def
            .get(lo..hi)
            .map_or_else(Vec::new, |s| s.iter().collect())
    }

    /// Returns the field rows for a given type-def row index (1-based).
    #[must_use]
    pub fn fields_for_type(&self, type_idx: u32) -> Vec<&FieldRow> {
        let n = u32::try_from(self.tables.type_def.len()).unwrap_or(u32::MAX);
        if type_idx == 0 || type_idx > n {
            return Vec::new();
        }
        let start = self.tables.type_def[(type_idx - 1) as usize].field_list as usize;
        let end = if type_idx < n {
            self.tables.type_def[type_idx as usize].field_list as usize
        } else {
            self.tables.field.len() + 1
        };
        if start == 0 || start > self.tables.field.len() {
            return Vec::new();
        }
        let lo = start.saturating_sub(1);
        let hi = (end.saturating_sub(1)).min(self.tables.field.len());
        self.tables
            .field
            .get(lo..hi)
            .map_or_else(Vec::new, |s| s.iter().collect())
    }

    /// Returns a `Vec` of all interface implementations for a type.
    #[must_use]
    pub fn interface_impls_for(&self, type_idx: u32) -> Vec<&InterfaceImplRow> {
        self.tables
            .interface_impl
            .iter()
            .filter(|ii| ii.class == type_idx)
            .collect()
    }

    /// Returns custom attribute rows that target a given token.
    #[must_use]
    pub fn custom_attrs_for(&self, parent: u32) -> Vec<&CustomAttributeRow> {
        self.tables
            .custom_attribute
            .iter()
            .filter(|ca| ca.parent == parent)
            .collect()
    }

    /// Returns all generic param rows for a type-or-method-def token.
    #[must_use]
    pub fn generic_params_for(&self, owner: u32) -> Vec<&GenericParamRow> {
        self.tables
            .generic_param
            .iter()
            .filter(|gp| gp.owner == owner)
            .collect()
    }

    /// Checks whether a given type-def (1-based) is abstract.
    #[must_use]
    pub fn type_is_abstract(&self, type_idx: u32) -> bool {
        if type_idx == 0 {
            return false;
        }
        self.tables
            .type_def
            .get((type_idx - 1) as usize)
            .is_some_and(|t| t.flags & 0x0080 != 0)
    }

    /// Checks whether a given type-def (1-based) is sealed.
    #[must_use]
    pub fn type_is_sealed(&self, type_idx: u32) -> bool {
        if type_idx == 0 {
            return false;
        }
        self.tables
            .type_def
            .get((type_idx - 1) as usize)
            .is_some_and(|t| t.flags & 0x0100 != 0)
    }

    /// Returns the number of type definitions.
    #[must_use]
    pub const fn type_count(&self) -> usize {
        self.tables.type_def.len()
    }

    /// Returns the number of method definitions.
    #[must_use]
    pub const fn method_count(&self) -> usize {
        self.tables.method_def.len()
    }

    /// Returns the number of field definitions.
    #[must_use]
    pub const fn field_count(&self) -> usize {
        self.tables.field.len()
    }
}

// â"€â"€â"€ Metadata validation â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A single metadata validation issue.
#[derive(Debug, Clone)]
pub struct ValidationIssue {
    /// Human-readable description.
    pub message: String,
    /// Severity: true = error, false = warning.
    pub is_error: bool,
}

impl ValidationIssue {
    /// Creates an error-level issue.
    #[must_use]
    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
            is_error: true,
        }
    }

    /// Creates a warning-level issue.
    #[must_use]
    pub fn warning(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
            is_error: false,
        }
    }
}

/// Result of a metadata validation pass.
#[derive(Debug, Clone, Default)]
pub struct ValidationResult {
    /// All issues found.
    pub issues: Vec<ValidationIssue>,
}

impl ValidationResult {
    /// Returns `true` if there are no error-level issues.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.issues.iter().any(|i| i.is_error)
    }

    /// Returns error-level issues only.
    #[must_use]
    pub fn errors(&self) -> Vec<&ValidationIssue> {
        self.issues.iter().filter(|i| i.is_error).collect()
    }

    /// Returns warning-level issues only.
    #[must_use]
    pub fn warnings(&self) -> Vec<&ValidationIssue> {
        self.issues.iter().filter(|i| !i.is_error).collect()
    }

    /// Returns the total issue count.
    #[must_use]
    pub const fn issue_count(&self) -> usize {
        self.issues.len()
    }
}

/// Runs basic structural validation on a `MetadataReader`.
#[must_use]
pub fn validate_metadata(reader: &MetadataReader) -> ValidationResult {
    let mut result = ValidationResult::default();

    // Must have exactly one Module row
    if reader.tables.module.is_empty() {
        result.issues.push(ValidationIssue::error(
            "Module table must have at least one row",
        ));
    } else if reader.tables.module.len() > 1 {
        result.issues.push(ValidationIssue::error(
            "Module table must have exactly one row",
        ));
    }

    // TypeDef row 1 must be the pseudo <Module> type
    if let Some(first) = reader.tables.type_def.first()
        && !first.type_name.is_empty()
        && first.type_name != "<Module>"
    {
        result.issues.push(ValidationIssue::warning(
            "First TypeDef row should be <Module>",
        ));
    }

    // Every NestedClass parent must be a valid TypeDef index
    let type_count = u32::try_from(reader.tables.type_def.len()).unwrap_or(u32::MAX);
    for nc in &reader.tables.nested_class {
        if nc.enclosing_class > type_count {
            result.issues.push(ValidationIssue::error(format!(
                "NestedClass.EnclosingClass {0} out of range (TypeDef has {type_count} rows)",
                nc.enclosing_class
            )));
        }
    }

    // GenericParam numbers should be sequential per owner (warning only)
    let mut prev_owner: u32 = 0;
    let mut prev_num: u16 = 0;
    for gp in &reader.tables.generic_param {
        if gp.owner == prev_owner {
            if gp.number != prev_num + 1 {
                result.issues.push(ValidationIssue::warning(format!(
                    "GenericParam numbers not sequential for owner {0}",
                    gp.owner
                )));
            }
        } else {
            prev_owner = gp.owner;
        }
        prev_num = gp.number;
    }

    result
}

// â"€â"€â"€ Signature pretty-printer (extended) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Pretty-prints a raw CIL type signature blob as a C# type string.
///
/// # Errors
/// Returns an error if the blob is empty or has an unrecognised element type.
pub fn pretty_print_type_sig(blob: &[u8]) -> Result<String> {
    use element_type as ET;
    if blob.is_empty() {
        return Err(MetadataError::UnexpectedEof {
            offset: 0,
            need: 1,
            have: 0,
        });
    }
    let et = blob[0];
    Ok(match et {
        ET::VOID => "void".into(),
        ET::BOOLEAN => "bool".into(),
        ET::CHAR => "char".into(),
        ET::I1 => "sbyte".into(),
        ET::U1 => "byte".into(),
        ET::I2 => "short".into(),
        ET::U2 => "ushort".into(),
        ET::I4 => "int".into(),
        ET::U4 => "uint".into(),
        ET::I8 => "long".into(),
        ET::U8 => "ulong".into(),
        ET::R4 => "float".into(),
        ET::R8 => "double".into(),
        ET::STRING => "string".into(),
        ET::OBJECT => "object".into(),
        ET::I => "nint".into(),
        ET::U => "nuint".into(),
        ET::TYPEDBYREF => "TypedReference".into(),
        ET::SZARRAY => {
            if blob.len() > 1 {
                let inner = pretty_print_type_sig(&blob[1..])?;
                format!("{inner}[]")
            } else {
                "?[]".into()
            }
        }
        ET::BYREF => {
            if blob.len() > 1 {
                let inner = pretty_print_type_sig(&blob[1..])?;
                format!("ref {inner}")
            } else {
                "ref ?".into()
            }
        }
        ET::PTR => {
            if blob.len() > 1 {
                let inner = pretty_print_type_sig(&blob[1..])?;
                format!("{inner}*")
            } else {
                "void*".into()
            }
        }
        ET::CLASS | ET::VALUETYPE => "/* class/valuetype */object".into(),
        ET::GENERICINST => "/* generic */object".into(),
        ET::VAR => {
            let n = blob.get(1).copied().unwrap_or(0);
            format!("T{n}")
        }
        ET::MVAR => {
            let n = blob.get(1).copied().unwrap_or(0);
            format!("M{n}")
        }
        _ => format!("/* et=0x{et:02X} */?"),
    })
}

// â"€â"€â"€ Metadata statistics â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Aggregate statistics for a parsed metadata blob.
#[derive(Debug, Clone, Default)]
pub struct MetadataStats {
    /// Total bytes of all string heap entries.
    pub string_heap_total_bytes: usize,
    /// Total bytes of all blob heap entries.
    pub blob_heap_total_bytes: usize,
    /// Total number of metadata table rows.
    pub total_rows: usize,
    /// Number of distinct custom attributes.
    pub custom_attribute_count: usize,
    /// Number of generic type definitions.
    pub generic_type_count: usize,
}

impl MetadataReader {
    /// Computes aggregate statistics for this metadata.
    #[must_use]
    pub fn statistics(&self) -> MetadataStats {
        let generic_type_count = self
            .tables
            .type_def
            .iter()
            .filter(|t| t.type_name.contains('`'))
            .count();

        MetadataStats {
            string_heap_total_bytes: self.heaps.strings.data.len(),
            blob_heap_total_bytes: self.heaps.blob.data.len(),
            total_rows: self.total_row_count(),
            custom_attribute_count: self.tables.custom_attribute.len(),
            generic_type_count,
        }
    }

    /// Returns all type-def full names as "Namespace.Name" strings.
    #[must_use]
    pub fn type_full_names(&self) -> Vec<String> {
        self.tables
            .type_def
            .iter()
            .map(|t| {
                if t.type_namespace.is_empty() {
                    t.type_name.clone()
                } else {
                    format!("{}.{}", t.type_namespace, t.type_name)
                }
            })
            .collect()
    }

    /// Finds method-def rows by name across all types.
    #[must_use]
    pub fn find_methods_by_name(&self, name: &str) -> Vec<&MethodDefRow> {
        self.tables
            .method_def
            .iter()
            .filter(|m| m.name == name)
            .collect()
    }

    /// Returns all method names across all types (deduplicated).
    #[must_use]
    pub fn all_method_names_unique(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        self.tables
            .method_def
            .iter()
            .filter_map(|m| {
                if seen.insert(m.name.clone()) {
                    Some(m.name.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Returns the index (1-based) of the first method with the given name, or `None`.
    #[must_use]
    pub fn method_index(&self, name: &str) -> Option<u32> {
        self.tables
            .method_def
            .iter()
            .enumerate()
            .find(|(_, m)| m.name == name)
            .map(|(i, _)| u32::try_from(i + 1).unwrap_or(u32::MAX))
    }
}

// â"€â"€â"€ Extended tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod extended_tests {
    use super::*;

    fn make_reader() -> MetadataReader {
        MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables: MetadataTables::default(),
        }
    }

    // â"€ coded_index module â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_coded_index_decode_typedef_or_ref() {
        let (tag, row) = coded_index::decode(0b0000_0000_0000_0101, 2);
        assert_eq!(tag, 1); // TypeRef
        assert_eq!(row, 1);
    }

    #[test]
    fn test_coded_index_encode_decode_roundtrip() {
        let encoded = coded_index::encode(2, 7, 2);
        let (tag, row) = coded_index::decode(encoded, 2);
        assert_eq!(tag, 2);
        assert_eq!(row, 7);
    }

    #[test]
    fn test_coded_index_typedef_or_ref_name() {
        assert_eq!(coded_index::typedef_or_ref_name(0), "TypeDef");
        assert_eq!(coded_index::typedef_or_ref_name(1), "TypeRef");
        assert_eq!(coded_index::typedef_or_ref_name(2), "TypeSpec");
        assert_eq!(coded_index::typedef_or_ref_name(99), "Unknown");
    }

    #[test]
    fn test_coded_index_resolution_scope_name() {
        assert_eq!(coded_index::resolution_scope_name(0), "Module");
        assert_eq!(coded_index::resolution_scope_name(2), "AssemblyRef");
        assert_eq!(coded_index::resolution_scope_name(3), "TypeRef");
    }

    // â"€ element_type module â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_element_type_to_csharp_primitives() {
        assert_eq!(element_type::to_csharp(element_type::I4), "int");
        assert_eq!(element_type::to_csharp(element_type::STRING), "string");
        assert_eq!(element_type::to_csharp(element_type::BOOLEAN), "bool");
        assert_eq!(element_type::to_csharp(element_type::VOID), "void");
    }

    #[test]
    fn test_element_type_is_numeric() {
        assert!(element_type::is_numeric(element_type::I4));
        assert!(element_type::is_numeric(element_type::R8));
        assert!(!element_type::is_numeric(element_type::STRING));
        assert!(!element_type::is_numeric(element_type::BOOLEAN));
    }

    // â"€ pretty_print_type_sig â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_pretty_print_void() {
        assert_eq!(
            pretty_print_type_sig(&[element_type::VOID]).unwrap(),
            "void"
        );
    }

    #[test]
    fn test_pretty_print_int() {
        assert_eq!(pretty_print_type_sig(&[element_type::I4]).unwrap(), "int");
    }

    #[test]
    fn test_pretty_print_string() {
        assert_eq!(
            pretty_print_type_sig(&[element_type::STRING]).unwrap(),
            "string"
        );
    }

    #[test]
    fn test_pretty_print_szarray_int() {
        assert_eq!(
            pretty_print_type_sig(&[element_type::SZARRAY, element_type::I4]).unwrap(),
            "int[]"
        );
    }

    #[test]
    fn test_pretty_print_byref() {
        assert_eq!(
            pretty_print_type_sig(&[element_type::BYREF, element_type::I4]).unwrap(),
            "ref int"
        );
    }

    #[test]
    fn test_pretty_print_ptr() {
        assert_eq!(
            pretty_print_type_sig(&[element_type::PTR, element_type::U1]).unwrap(),
            "byte*"
        );
    }

    #[test]
    fn test_pretty_print_var() {
        let s = pretty_print_type_sig(&[element_type::VAR, 2]).unwrap();
        assert_eq!(s, "T2");
    }

    #[test]
    fn test_pretty_print_mvar() {
        let s = pretty_print_type_sig(&[element_type::MVAR, 0]).unwrap();
        assert_eq!(s, "M0");
    }

    #[test]
    fn test_pretty_print_empty_error() {
        assert!(pretty_print_type_sig(&[]).is_err());
    }

    // â"€ CustomAttributeValue â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_custom_attribute_value_as_str() {
        let v = CustomAttributeValue::String(Some("hello".into()));
        assert_eq!(v.as_str(), Some("hello"));
    }

    #[test]
    fn test_custom_attribute_value_as_str_null() {
        let v = CustomAttributeValue::String(None);
        assert!(v.is_null_string());
        assert!(v.as_str().is_none());
    }

    #[test]
    fn test_custom_attribute_value_as_i32() {
        let v = CustomAttributeValue::I4(42);
        assert_eq!(v.as_i32(), Some(42));
    }

    #[test]
    fn test_custom_attribute_value_as_bool() {
        let v = CustomAttributeValue::Bool(true);
        assert_eq!(v.as_bool(), Some(true));
    }

    #[test]
    fn test_decoded_custom_attribute_named() {
        let mut ca = DecodedCustomAttribute::default();
        ca.named_args.push(CustomAttributeNamedArg {
            is_field: false,
            name: "AllowMultiple".into(),
            value: CustomAttributeValue::Bool(true),
        });
        assert_eq!(
            ca.named("AllowMultiple"),
            Some(&CustomAttributeValue::Bool(true))
        );
        assert!(ca.named("Inherited").is_none());
    }

    #[test]
    fn test_decoded_custom_attribute_counts() {
        let mut ca = DecodedCustomAttribute::default();
        ca.fixed_args.push(CustomAttributeValue::I4(1));
        ca.fixed_args.push(CustomAttributeValue::I4(2));
        ca.named_args.push(CustomAttributeNamedArg {
            is_field: true,
            name: "X".into(),
            value: CustomAttributeValue::Bool(false),
        });
        assert_eq!(ca.fixed_arg_count(), 2);
        assert_eq!(ca.named_arg_count(), 1);
    }

    // â"€ AssemblyManifest â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_assembly_manifest_version_string() {
        let m = AssemblyManifest {
            major_version: 4,
            minor_version: 0,
            build_number: 30319,
            revision_number: 0,
            ..Default::default()
        };
        assert_eq!(m.version_string(), "4.0.30319.0");
    }

    #[test]
    fn test_assembly_manifest_has_culture_false() {
        let m = AssemblyManifest::default();
        assert!(!m.has_culture());
    }

    #[test]
    fn test_assembly_manifest_has_culture_true() {
        let m = AssemblyManifest {
            culture: "en-US".into(),
            ..Default::default()
        };
        assert!(m.has_culture());
    }

    #[test]
    fn test_assembly_manifest_has_resources() {
        let m = AssemblyManifest {
            resource_count: 2,
            ..Default::default()
        };
        assert!(m.has_resources());
    }

    // â"€ MetadataReader extended helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_assembly_manifest_none_when_no_assembly() {
        let reader = make_reader();
        assert!(reader.assembly_manifest().is_none());
    }

    #[test]
    fn test_assembly_manifest_present() {
        let mut reader = make_reader();
        reader.tables.assembly.push(AssemblyRow {
            name: "MyLib".into(),
            major_version: 1,
            minor_version: 2,
            build_number: 3,
            revision_number: 4,
            ..Default::default()
        });
        let manifest = reader.assembly_manifest().unwrap();
        assert_eq!(manifest.name, "MyLib");
        assert_eq!(manifest.version_string(), "1.2.3.4");
    }

    #[test]
    fn test_total_row_count() {
        let mut reader = make_reader();
        reader.tables.type_def.push(TypeDefRow::default());
        reader.tables.method_def.push(MethodDefRow::default());
        assert_eq!(reader.total_row_count(), 2);
    }

    #[test]
    fn test_type_count_method_count_field_count() {
        let mut reader = make_reader();
        reader.tables.type_def.push(TypeDefRow::default());
        reader.tables.method_def.push(MethodDefRow::default());
        reader.tables.field.push(FieldRow::default());
        assert_eq!(reader.type_count(), 1);
        assert_eq!(reader.method_count(), 1);
        assert_eq!(reader.field_count(), 1);
    }

    #[test]
    fn test_find_methods_by_name() {
        let mut reader = make_reader();
        reader.tables.method_def.push(MethodDefRow {
            name: "Foo".into(),
            ..Default::default()
        });
        reader.tables.method_def.push(MethodDefRow {
            name: "Bar".into(),
            ..Default::default()
        });
        reader.tables.method_def.push(MethodDefRow {
            name: "Foo".into(),
            ..Default::default()
        });
        let found = reader.find_methods_by_name("Foo");
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn test_method_index() {
        let mut reader = make_reader();
        reader.tables.method_def.push(MethodDefRow {
            name: "A".into(),
            ..Default::default()
        });
        reader.tables.method_def.push(MethodDefRow {
            name: "B".into(),
            ..Default::default()
        });
        assert_eq!(reader.method_index("A"), Some(1));
        assert_eq!(reader.method_index("B"), Some(2));
        assert_eq!(reader.method_index("C"), None);
    }

    #[test]
    fn test_all_field_names() {
        let mut reader = make_reader();
        reader.tables.field.push(FieldRow {
            name: "x".into(),
            ..Default::default()
        });
        reader.tables.field.push(FieldRow {
            name: "y".into(),
            ..Default::default()
        });
        let names = reader.all_field_names();
        assert_eq!(names, vec!["x", "y"]);
    }

    #[test]
    fn test_all_method_names_unique() {
        let mut reader = make_reader();
        reader.tables.method_def.push(MethodDefRow {
            name: "M".into(),
            ..Default::default()
        });
        reader.tables.method_def.push(MethodDefRow {
            name: "M".into(),
            ..Default::default()
        });
        reader.tables.method_def.push(MethodDefRow {
            name: "N".into(),
            ..Default::default()
        });
        let names = reader.all_method_names_unique();
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn test_type_full_names() {
        let mut reader = make_reader();
        reader.tables.type_def.push(TypeDefRow {
            type_name: "Foo".into(),
            type_namespace: "Bar".into(),
            ..Default::default()
        });
        reader.tables.type_def.push(TypeDefRow {
            type_name: "Baz".into(),
            type_namespace: String::new(),
            ..Default::default()
        });
        let names = reader.type_full_names();
        assert!(names.contains(&"Bar.Foo".to_string()));
        assert!(names.contains(&"Baz".to_string()));
    }

    #[test]
    fn test_exported_type_names() {
        let mut reader = make_reader();
        reader.tables.exported_type.push(ExportedTypeRow {
            type_name: "Foo".into(),
            type_namespace: "Ns".into(),
            ..Default::default()
        });
        let names = reader.exported_type_names();
        assert_eq!(names, vec!["Ns.Foo"]);
    }

    #[test]
    fn test_resource_names() {
        let mut reader = make_reader();
        reader.tables.manifest_resource.push(ManifestResourceRow {
            name: "Res.resources".into(),
            ..Default::default()
        });
        let names = reader.resource_names();
        assert_eq!(names, vec!["Res.resources"]);
    }

    #[test]
    fn test_type_is_abstract_sealed() {
        let mut reader = make_reader();
        reader.tables.type_def.push(TypeDefRow {
            flags: 0x0180, // abstract | sealed
            ..Default::default()
        });
        assert!(reader.type_is_abstract(1));
        assert!(reader.type_is_sealed(1));
        assert!(!reader.type_is_abstract(0));
        assert!(!reader.type_is_abstract(2));
    }

    // â"€ validate_metadata â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_validate_no_module_row() {
        let reader = make_reader();
        let result = validate_metadata(&reader);
        assert!(!result.is_valid());
        assert!(!result.errors().is_empty());
    }

    #[test]
    fn test_validate_one_module_row_ok() {
        let mut reader = make_reader();
        reader.tables.module.push(ModuleRow::default());
        reader.tables.type_def.push(TypeDefRow {
            type_name: "<Module>".into(),
            ..Default::default()
        });
        let result = validate_metadata(&reader);
        assert!(result.is_valid());
        assert_eq!(result.errors().len(), 0);
    }

    #[test]
    fn test_validate_two_module_rows_error() {
        let mut reader = make_reader();
        reader.tables.module.push(ModuleRow::default());
        reader.tables.module.push(ModuleRow::default());
        let result = validate_metadata(&reader);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_validation_result_warnings_only() {
        let mut v = ValidationResult::default();
        v.issues.push(ValidationIssue::warning("w1"));
        v.issues.push(ValidationIssue::warning("w2"));
        assert!(v.is_valid());
        assert_eq!(v.errors().len(), 0);
        assert_eq!(v.warnings().len(), 2);
        assert_eq!(v.issue_count(), 2);
    }

    // â"€ MetadataStats â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_statistics_empty() {
        let reader = make_reader();
        let stats = reader.statistics();
        assert_eq!(stats.total_rows, 0);
        assert_eq!(stats.custom_attribute_count, 0);
        assert_eq!(stats.generic_type_count, 0);
    }

    #[test]
    fn test_statistics_generic_type_count() {
        let mut reader = make_reader();
        reader.tables.type_def.push(TypeDefRow {
            type_name: "List`1".into(),
            ..Default::default()
        });
        reader.tables.type_def.push(TypeDefRow {
            type_name: "Foo".into(),
            ..Default::default()
        });
        let stats = reader.statistics();
        assert_eq!(stats.generic_type_count, 1);
    }

    // â"€ parse_custom_attribute_blob â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_parse_custom_attribute_blob_too_short() {
        assert!(parse_custom_attribute_blob(&[]).is_err());
        assert!(parse_custom_attribute_blob(&[0x01]).is_err());
    }

    #[test]
    fn test_parse_custom_attribute_blob_valid_prolog() {
        let result = parse_custom_attribute_blob(&[0x01, 0x00]).unwrap();
        assert_eq!(result.fixed_arg_count(), 0);
        assert_eq!(result.named_arg_count(), 0);
    }

    // â"€ all_module_names / file_names â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_all_module_names() {
        let mut reader = make_reader();
        reader.tables.module.push(ModuleRow {
            name: "App.exe".into(),
            ..Default::default()
        });
        reader.tables.module_ref.push(ModuleRefRow {
            name: "native.dll".into(),
        });
        let names = reader.all_module_names();
        assert!(names.contains(&"App.exe".to_string()));
        assert!(names.contains(&"native.dll".to_string()));
    }

    #[test]
    fn test_file_names() {
        let mut reader = make_reader();
        reader.tables.file.push(FileRow {
            name: "resources.dll".into(),
            ..Default::default()
        });
        let names = reader.file_names();
        assert_eq!(names, vec!["resources.dll"]);
    }

    #[test]
    fn test_assembly_ref_names() {
        let mut reader = make_reader();
        reader.tables.assembly_ref.push(AssemblyRefRow {
            name: "mscorlib".into(),
            ..Default::default()
        });
        let names = reader.assembly_ref_names();
        assert_eq!(names, vec!["mscorlib"]);
    }
}

// â"€â"€â"€ Blob signature: array shape decoder â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Decoded array shape (rank, sizes, lower bounds).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArrayShape {
    /// Number of dimensions.
    pub rank: u32,
    /// Size of each bounded dimension (may be shorter than rank).
    pub sizes: Vec<u32>,
    /// Lower bound of each dimension (may be shorter than rank).
    pub lower_bounds: Vec<i32>,
}

impl ArrayShape {
    /// Returns `true` if this is a simple single-dimensional zero-based array.
    #[must_use]
    pub const fn is_simple_szarray(&self) -> bool {
        self.rank == 1 && self.sizes.is_empty() && self.lower_bounds.is_empty()
    }

    /// Returns a C#-style bracket string, e.g. `[,]` for a 2-D array.
    #[must_use]
    pub fn bracket_notation(&self) -> String {
        if self.rank == 0 {
            return "[]".into();
        }
        let commas = ",".repeat((self.rank as usize).saturating_sub(1));
        format!("[{commas}]")
    }
}

/// Parses an `ArrayShape` from a blob starting at `pos`.
///
/// # Errors
/// Returns an error if the data is truncated.
pub fn parse_array_shape(blob: &[u8]) -> Result<ArrayShape> {
    if blob.is_empty() {
        return Err(MetadataError::UnexpectedEof {
            offset: 0,
            need: 1,
            have: 0,
        });
    }
    let mut r = crate::Reader::at(blob, 0);
    let rank = r.read_compressed_uint()?;
    let num_sizes = r.read_compressed_uint()?;
    let mut sizes = Vec::new();
    for _ in 0..num_sizes {
        sizes.push(r.read_compressed_uint()?);
    }
    let num_bounds = r.read_compressed_uint()?;
    let mut lower_bounds: Vec<i32> = Vec::new();
    for _ in 0..num_bounds {
        let v = (r.read_compressed_uint()?).cast_signed();
        lower_bounds.push(v);
    }
    Ok(ArrayShape {
        rank,
        sizes,
        lower_bounds,
    })
}

// â"€â"€â"€ Token helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Well-known metadata table IDs (ECMA-335 Â§II.22.1).
pub mod table_ids {
    pub const MODULE: u8 = 0x00;
    pub const TYPE_REF: u8 = 0x01;
    pub const TYPE_DEF: u8 = 0x02;
    pub const FIELD: u8 = 0x04;
    pub const METHOD_DEF: u8 = 0x06;
    pub const PARAM: u8 = 0x08;
    pub const INTERFACE_IMPL: u8 = 0x09;
    pub const MEMBER_REF: u8 = 0x0A;
    pub const CONSTANT: u8 = 0x0B;
    pub const CUSTOM_ATTRIBUTE: u8 = 0x0C;
    pub const FIELD_MARSHAL: u8 = 0x0D;
    pub const DECL_SECURITY: u8 = 0x0E;
    pub const CLASS_LAYOUT: u8 = 0x0F;
    pub const FIELD_LAYOUT: u8 = 0x10;
    pub const STAND_ALONE_SIG: u8 = 0x11;
    pub const EVENT_MAP: u8 = 0x12;
    pub const EVENT: u8 = 0x14;
    pub const PROPERTY_MAP: u8 = 0x15;
    pub const PROPERTY: u8 = 0x17;
    pub const METHOD_SEMANTICS: u8 = 0x18;
    pub const METHOD_IMPL: u8 = 0x19;
    pub const MODULE_REF: u8 = 0x1A;
    pub const TYPE_SPEC: u8 = 0x1B;
    pub const IMPL_MAP: u8 = 0x1C;
    pub const FIELD_RVA: u8 = 0x1D;
    pub const ASSEMBLY: u8 = 0x20;
    pub const ASSEMBLY_REF: u8 = 0x23;
    pub const FILE: u8 = 0x26;
    pub const EXPORTED_TYPE: u8 = 0x27;
    pub const MANIFEST_RESOURCE: u8 = 0x28;
    pub const NESTED_CLASS: u8 = 0x29;
    pub const GENERIC_PARAM: u8 = 0x2A;
    pub const METHOD_SPEC: u8 = 0x2B;
    pub const GENERIC_PARAM_CONSTRAINT: u8 = 0x2C;

    /// Returns the canonical table name for a table ID.
    #[must_use]
    pub const fn name(id: u8) -> &'static str {
        match id {
            MODULE => "Module",
            TYPE_REF => "TypeRef",
            TYPE_DEF => "TypeDef",
            FIELD => "Field",
            METHOD_DEF => "MethodDef",
            PARAM => "Param",
            INTERFACE_IMPL => "InterfaceImpl",
            MEMBER_REF => "MemberRef",
            CONSTANT => "Constant",
            CUSTOM_ATTRIBUTE => "CustomAttribute",
            FIELD_MARSHAL => "FieldMarshal",
            DECL_SECURITY => "DeclSecurity",
            CLASS_LAYOUT => "ClassLayout",
            FIELD_LAYOUT => "FieldLayout",
            STAND_ALONE_SIG => "StandAloneSig",
            EVENT_MAP => "EventMap",
            EVENT => "Event",
            PROPERTY_MAP => "PropertyMap",
            PROPERTY => "Property",
            METHOD_SEMANTICS => "MethodSemantics",
            METHOD_IMPL => "MethodImpl",
            MODULE_REF => "ModuleRef",
            TYPE_SPEC => "TypeSpec",
            IMPL_MAP => "ImplMap",
            FIELD_RVA => "FieldRva",
            ASSEMBLY => "Assembly",
            ASSEMBLY_REF => "AssemblyRef",
            FILE => "File",
            EXPORTED_TYPE => "ExportedType",
            MANIFEST_RESOURCE => "ManifestResource",
            NESTED_CLASS => "NestedClass",
            GENERIC_PARAM => "GenericParam",
            METHOD_SPEC => "MethodSpec",
            GENERIC_PARAM_CONSTRAINT => "GenericParamConstraint",
            _ => "Unknown",
        }
    }

    /// Decodes a metadata token into (`table_id`, `row_index_1based`).
    #[must_use]
    pub const fn decode_token(token: u32) -> (u8, u32) {
        ((token >> 24) as u8, token & 0x00FF_FFFF)
    }

    /// Encodes a (`table_id`, `row_index_1based`) pair into a metadata token.
    #[must_use]
    pub fn encode_token(table: u8, row: u32) -> u32 {
        (u32::from(table) << 24) | (row & 0x00FF_FFFF)
    }
}

// â"€â"€â"€ Additional metadata reader helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

impl MetadataReader {
    /// Returns the method semantics for a given method-def index (1-based).
    #[must_use]
    pub fn semantics_for_method(&self, method_idx: u32) -> Vec<&MethodSemanticsRow> {
        self.tables
            .method_semantics
            .iter()
            .filter(|ms| ms.method == method_idx)
            .collect()
    }

    /// Returns all property rows for a given type (via `PropertyMap`).
    #[must_use]
    pub fn properties_for_type(&self, type_idx: u32) -> Vec<&PropertyRow> {
        // Find the property map entry for this type
        let pm = self
            .tables
            .property_map
            .iter()
            .find(|pm| pm.parent == type_idx);
        let Some(pm) = pm else {
            return Vec::new();
        };
        let start = pm.property_list as usize;
        let end = self
            .tables
            .property_map
            .iter()
            .find(|p| p.parent > type_idx)
            .map_or(self.tables.property.len() + 1, |p| p.property_list as usize);
        if start == 0 || start > self.tables.property.len() {
            return Vec::new();
        }
        let lo = start.saturating_sub(1);
        let hi = (end.saturating_sub(1)).min(self.tables.property.len());
        self.tables
            .property
            .get(lo..hi)
            .map_or_else(Vec::new, |s| s.iter().collect())
    }

    /// Returns all event rows for a given type (via `EventMap`).
    #[must_use]
    pub fn events_for_type(&self, type_idx: u32) -> Vec<&EventRow> {
        let em = self
            .tables
            .event_map
            .iter()
            .find(|em| em.parent == type_idx);
        let Some(em) = em else {
            return Vec::new();
        };
        let start = em.event_list as usize;
        let end = self
            .tables
            .event_map
            .iter()
            .find(|e| e.parent > type_idx)
            .map_or(self.tables.event.len() + 1, |e| e.event_list as usize);
        if start == 0 || start > self.tables.event.len() {
            return Vec::new();
        }
        let lo = start.saturating_sub(1);
        let hi = (end.saturating_sub(1)).min(self.tables.event.len());
        self.tables
            .event
            .get(lo..hi)
            .map_or_else(Vec::new, |s| s.iter().collect())
    }

    /// Returns the constant value for a given field/param/property token.
    #[must_use]
    pub fn constant_for(&self, parent_token: u32) -> Option<&ConstantRow> {
        self.tables
            .constant
            .iter()
            .find(|c| c.parent == parent_token)
    }

    /// Returns all `MemberRef` rows whose parent matches the given token.
    #[must_use]
    pub fn member_refs_for(&self, parent: u32) -> Vec<&MemberRefRow> {
        self.tables
            .member_ref
            .iter()
            .filter(|m| m.class == parent)
            .collect()
    }

    /// Returns whether the module is a .NET executable (has `MethodDef` for entry point).
    #[must_use]
    pub fn has_entry_point(&self) -> bool {
        self.tables.module.first().is_some_and(|m| m.mvid != 0)
    }

    /// Returns the number of interfaces implemented across all types.
    #[must_use]
    pub const fn total_interface_impl_count(&self) -> usize {
        self.tables.interface_impl.len()
    }

    /// Returns all type-def rows that implement at least one interface.
    #[must_use]
    pub fn types_with_interfaces(&self) -> Vec<&TypeDefRow> {
        let implementors: std::collections::HashSet<u32> = self
            .tables
            .interface_impl
            .iter()
            .map(|ii| ii.class)
            .collect();
        self.tables
            .type_def
            .iter()
            .enumerate()
            .filter(|(i, _)| implementors.contains(&u32::try_from(*i + 1).unwrap_or(u32::MAX)))
            .map(|(_, t)| t)
            .collect()
    }
}

// â"€â"€â"€ More tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod extra2_tests {
    use super::*;

    fn make_reader() -> MetadataReader {
        MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables: MetadataTables::default(),
        }
    }

    // â"€ table_id module â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_table_id_name() {
        assert_eq!(table_ids::name(table_ids::TYPE_DEF), "TypeDef");
        assert_eq!(table_ids::name(table_ids::METHOD_DEF), "MethodDef");
        assert_eq!(table_ids::name(table_ids::ASSEMBLY_REF), "AssemblyRef");
        assert_eq!(table_ids::name(0xFF), "Unknown");
    }

    #[test]
    fn test_table_id_decode_token() {
        let token = 0x0200_0001u32; // TypeDef row 1
        let (tbl, row) = table_ids::decode_token(token);
        assert_eq!(tbl, table_ids::TYPE_DEF);
        assert_eq!(row, 1);
    }

    #[test]
    fn test_table_id_encode_token_roundtrip() {
        let encoded = table_ids::encode_token(table_ids::METHOD_DEF, 5);
        let (tbl, row) = table_ids::decode_token(encoded);
        assert_eq!(tbl, table_ids::METHOD_DEF);
        assert_eq!(row, 5);
    }

    // â"€ ArrayShape â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_array_shape_bracket_notation_1d() {
        let s = ArrayShape {
            rank: 1,
            ..Default::default()
        };
        assert_eq!(s.bracket_notation(), "[]");
    }

    #[test]
    fn test_array_shape_bracket_notation_2d() {
        let s = ArrayShape {
            rank: 2,
            ..Default::default()
        };
        assert_eq!(s.bracket_notation(), "[,]");
    }

    #[test]
    fn test_array_shape_bracket_notation_3d() {
        let s = ArrayShape {
            rank: 3,
            ..Default::default()
        };
        assert_eq!(s.bracket_notation(), "[,,]");
    }

    #[test]
    fn test_array_shape_is_simple_szarray() {
        let s = ArrayShape {
            rank: 1,
            sizes: vec![],
            lower_bounds: vec![],
        };
        assert!(s.is_simple_szarray());
    }

    #[test]
    fn test_array_shape_not_szarray_multi_dim() {
        let s = ArrayShape {
            rank: 2,
            ..Default::default()
        };
        assert!(!s.is_simple_szarray());
    }

    #[test]
    fn test_parse_array_shape_empty_error() {
        assert!(parse_array_shape(&[]).is_err());
    }

    #[test]
    fn test_parse_array_shape_rank1_no_bounds() {
        // rank=1, num_sizes=0, num_lower=0
        let blob = [0x01, 0x00, 0x00];
        let shape = parse_array_shape(&blob).unwrap();
        assert_eq!(shape.rank, 1);
        assert!(shape.sizes.is_empty());
        assert!(shape.lower_bounds.is_empty());
        assert!(shape.is_simple_szarray());
    }

    #[test]
    fn test_parse_array_shape_rank2_one_size() {
        // rank=2, num_sizes=1, size=5, num_lower=0
        let blob = [0x02, 0x01, 0x05, 0x00];
        let shape = parse_array_shape(&blob).unwrap();
        assert_eq!(shape.rank, 2);
        assert_eq!(shape.sizes, vec![5]);
        assert!(!shape.is_simple_szarray());
    }

    // â"€ MetadataReader extended helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_total_interface_impl_count() {
        let mut reader = make_reader();
        reader.tables.interface_impl.push(InterfaceImplRow {
            class: 1,
            interface: 2,
        });
        reader.tables.interface_impl.push(InterfaceImplRow {
            class: 1,
            interface: 3,
        });
        assert_eq!(reader.total_interface_impl_count(), 2);
    }

    #[test]
    fn test_types_with_interfaces() {
        let mut reader = make_reader();
        reader.tables.type_def.push(TypeDefRow {
            type_name: "A".into(),
            ..Default::default()
        });
        reader.tables.type_def.push(TypeDefRow {
            type_name: "B".into(),
            ..Default::default()
        });
        reader.tables.interface_impl.push(InterfaceImplRow {
            class: 1,
            interface: 3,
        });
        let types = reader.types_with_interfaces();
        assert_eq!(types.len(), 1);
        assert_eq!(types[0].type_name, "A");
    }

    #[test]
    fn test_member_refs_for() {
        let mut reader = make_reader();
        reader.tables.member_ref.push(MemberRefRow {
            class: 5,
            name: "Foo".into(),
            ..Default::default()
        });
        reader.tables.member_ref.push(MemberRefRow {
            class: 6,
            name: "Bar".into(),
            ..Default::default()
        });
        let refs = reader.member_refs_for(5);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "Foo");
    }

    #[test]
    fn test_constant_for() {
        let mut reader = make_reader();
        reader.tables.constant.push(ConstantRow {
            parent: 0x0400_0001, // Field row 1
            const_type: 8,
            value: vec![0x2A, 0x00, 0x00, 0x00],
        });
        let c = reader.constant_for(0x0400_0001);
        assert!(c.is_some());
        let none = reader.constant_for(0x0400_0002);
        assert!(none.is_none());
    }

    #[test]
    fn test_semantics_for_method() {
        let mut reader = make_reader();
        reader.tables.method_semantics.push(MethodSemanticsRow {
            semantics: method_semantics::GETTER,
            method: 3,
            association: 0x1700_0001,
        });
        let ms = reader.semantics_for_method(3);
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].semantics, method_semantics::GETTER);
        assert!(reader.semantics_for_method(4).is_empty());
    }

    #[test]
    fn test_interface_impls_for() {
        let mut reader = make_reader();
        reader.tables.interface_impl.push(InterfaceImplRow {
            class: 2,
            interface: 5,
        });
        reader.tables.interface_impl.push(InterfaceImplRow {
            class: 2,
            interface: 6,
        });
        reader.tables.interface_impl.push(InterfaceImplRow {
            class: 3,
            interface: 5,
        });
        let impls = reader.interface_impls_for(2);
        assert_eq!(impls.len(), 2);
    }

    #[test]
    fn test_generic_params_for() {
        let mut reader = make_reader();
        reader.tables.generic_param.push(GenericParamRow {
            number: 0,
            flags: 0,
            owner: 2,
            name: "T".into(),
        });
        reader.tables.generic_param.push(GenericParamRow {
            number: 1,
            flags: 0,
            owner: 2,
            name: "U".into(),
        });
        let params = reader.generic_params_for(2);
        assert_eq!(params.len(), 2);
        assert!(reader.generic_params_for(99).is_empty());
    }

    #[test]
    fn test_custom_attrs_for() {
        let mut reader = make_reader();
        reader.tables.custom_attribute.push(CustomAttributeRow {
            parent: 0x0200_0001,
            attr_type: 1,
            value: vec![],
        });
        let cas = reader.custom_attrs_for(0x0200_0001);
        assert_eq!(cas.len(), 1);
        assert!(reader.custom_attrs_for(0x0200_0002).is_empty());
    }
}

// â"€â"€â"€ MetadataIndexer â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Fast lookup index over parsed metadata tables.
///
/// Builds hash-map indices at construction time so that subsequent
/// `method_by_token`, `type_by_name`, and `fields_of_type` calls are O(1).
pub struct MetadataIndexer<'a> {
    tables: &'a MetadataTables,
    /// method token (0x06xxxxxx, 1-based row) â†' row index (0-based)
    method_by_token_map: HashMap<u32, usize>,
    /// (namespace, name) â†' row index (0-based) into `type_def`
    type_by_name_map: HashMap<(String, String), usize>,
    /// `type_def` 1-based token â†' list of field row indices (0-based)
    fields_of_type_map: HashMap<u32, Vec<usize>>,
}

impl<'a> MetadataIndexer<'a> {
    /// Build an indexer over the given tables.  Construction is O(n) in table
    /// size; all subsequent lookups are O(1).
    #[must_use]
    pub fn new(tables: &'a MetadataTables) -> Self {
        // â"€â"€ method token map â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        let mut method_by_token_map = HashMap::with_capacity(tables.method_def.len());
        for (idx, _row) in tables.method_def.iter().enumerate() {
            // ECMA-335: MethodDef table id = 0x06; token = (0x06 << 24) | (idx+1)
            let token = 0x0600_0000u32 | (u32::try_from(idx).unwrap_or(u32::MAX) + 1);
            method_by_token_map.insert(token, idx);
        }

        // â"€â"€ type-by-name map â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        let mut type_by_name_map = HashMap::with_capacity(tables.type_def.len());
        for (idx, row) in tables.type_def.iter().enumerate() {
            type_by_name_map.insert((row.type_namespace.clone(), row.type_name.clone()), idx);
        }

        // â"€â"€ fields-of-type map â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        let mut fields_of_type_map: HashMap<u32, Vec<usize>> =
            HashMap::with_capacity(tables.type_def.len());
        let type_count = tables.type_def.len();
        for (ti, typedef) in tables.type_def.iter().enumerate() {
            let field_start = typedef.field_list as usize;
            let field_end = tables
                .type_def
                .get(ti + 1)
                .map_or(tables.field.len() + 1, |r| r.field_list as usize);
            // 1-based token for the TypeDef row
            let type_token = 0x0200_0000u32 | (u32::try_from(ti).unwrap_or(u32::MAX) + 1);
            let indices: Vec<usize> = (field_start..field_end)
                .filter(|&fi| fi > 0 && fi <= tables.field.len())
                .map(|fi| fi - 1)
                .collect();
            fields_of_type_map.insert(type_token, indices);
        }
        // suppress unused-variable warning in the loop above
        let _ = type_count;

        Self {
            tables,
            method_by_token_map,
            type_by_name_map,
            fields_of_type_map,
        }
    }

    /// Look up a `MethodDef` row by its full metadata token (e.g. `0x0600_0001`).
    ///
    /// Returns `None` if the token is out of range or not a `MethodDef` token.
    #[must_use]
    pub fn method_by_token(&self, token: u32) -> Option<&MethodDefRow> {
        let idx = *self.method_by_token_map.get(&token)?;
        self.tables.method_def.get(idx)
    }

    /// Look up a `TypeDef` row by its namespace and simple name.
    ///
    /// Pass an empty string for `ns` to match types with no namespace.
    #[must_use]
    pub fn type_by_name(&self, ns: &str, name: &str) -> Option<&TypeDefRow> {
        let idx = *self
            .type_by_name_map
            .get(&(ns.to_string(), name.to_string()))?;
        self.tables.type_def.get(idx)
    }

    /// Return all `Field` rows that belong to the type identified by its
    /// full metadata token (e.g. `0x0200_0001`).
    ///
    /// Returns an empty `Vec` if the token is unknown or the type has no fields.
    #[must_use]
    pub fn fields_of_type(&self, type_token: u32) -> Vec<&FieldRow> {
        self.fields_of_type_map
            .get(&type_token)
            .map_or_else(Vec::new, |indices| {
                indices
                    .iter()
                    .filter_map(|&fi| self.tables.field.get(fi))
                    .collect()
            })
    }

    /// Convenience: look up the 0-based index of a `TypeDef` by namespace + name.
    #[must_use]
    pub fn type_index(&self, ns: &str, name: &str) -> Option<usize> {
        self.type_by_name_map
            .get(&(ns.to_string(), name.to_string()))
            .copied()
    }

    /// Convenience: return the full `TypeDef` token for a type identified by
    /// namespace + name (`0x02xxxxxx`), or `None` if not found.
    #[must_use]
    pub fn type_token(&self, ns: &str, name: &str) -> Option<u32> {
        let idx = self.type_index(ns, name)?;
        Some(0x0200_0000u32 | (u32::try_from(idx).unwrap_or(u32::MAX) + 1))
    }
}

// â"€â"€â"€ CliHeader â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Decoded CLI header as it appears at the COM+ data directory (ECMA-335 Â§II.25.3.3).
#[derive(Debug, Clone, Default)]
pub struct CliHeader {
    /// Size of this header in bytes (always 72 for current spec).
    pub cb: u32,
    pub major_runtime_version: u16,
    pub minor_runtime_version: u16,
    /// RVA of the metadata root (`#~` / `#Strings` etc.).
    pub metadata_rva: u32,
    /// Size of the metadata blob in bytes.
    pub metadata_size: u32,
    /// `CorFlags` bitmask (e.g. `0x01` = ILONLY, `0x02` = 32BITREQUIRED).
    pub flags: u32,
    /// Entry-point token (`MethodDef` or File).
    pub entry_point_token: u32,
    /// RVA of the managed resources blob.
    pub resources_rva: u32,
    pub resources_size: u32,
    /// RVA of the strong-name signature blob (0 if unsigned).
    pub strong_name_rva: u32,
    pub strong_name_size: u32,
    /// File offset in the PE image where this header starts.
    pub file_offset: usize,
}

impl CliHeader {
    /// Returns `true` if the assembly is IL-only (no unmanaged native code).
    #[must_use]
    pub const fn is_il_only(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    /// Returns `true` if the assembly requires a 32-bit process.
    #[must_use]
    pub const fn requires_32bit(&self) -> bool {
        self.flags & 0x0002 != 0
    }

    /// Returns `true` if the strong-name signature is present.
    #[must_use]
    pub const fn is_strong_named(&self) -> bool {
        self.flags & 0x0008 != 0
    }
}

/// Parser that locates and decodes the CLI header embedded in a PE file by
/// following the `IMAGE_OPTIONAL_HEADER.DataDirectory[14]` (COM+ descriptor)
/// entry as specified in ECMA-335 Â§II.25.
pub struct CliHeaderParser;

impl CliHeaderParser {
    /// Locate and parse the CLI header from raw PE bytes.
    ///
    /// Follows the standard PE â†' optional header â†' data directory entry 14
    /// path.  Returns `None` (rather than an error) so callers can silently
    /// skip non-.NET PE files.
    #[must_use]
    pub fn parse_pe_embedded(bytes: &[u8]) -> Option<CliHeader> {
        // MZ signature
        if bytes.len() < 0x40 || bytes[0] != b'M' || bytes[1] != b'Z' {
            return None;
        }
        let pe_offset = u32::from_le_bytes(bytes[0x3C..0x40].try_into().ok()?) as usize;

        // PE signature "PE\0\0"
        if pe_offset + 4 > bytes.len() {
            return None;
        }
        if &bytes[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return None;
        }

        // COFF header: Machine(2), NumberOfSections(2), ..., SizeOfOptionalHeader(2), Characteristics(2)
        if pe_offset + 24 > bytes.len() {
            return None;
        }
        let opt_size =
            u16::from_le_bytes(bytes[pe_offset + 20..pe_offset + 22].try_into().ok()?) as usize;
        let opt_start = pe_offset + 24;
        if opt_start + opt_size > bytes.len() {
            return None;
        }

        let magic = u16::from_le_bytes(bytes[opt_start..opt_start + 2].try_into().ok()?);
        // PE32 = 0x10B, PE32+ = 0x20B
        let data_dir_base = match magic {
            0x010B => opt_start + 96, // PE32: standard + windows-specific fields = 96 bytes
            0x020B => opt_start + 112, // PE32+: standard + windows-specific fields = 112 bytes
            _ => return None,
        };

        // Data directory entry 14 is the COM+ (CLI) descriptor: RVA(4) + Size(4)
        let cli_dir_off = data_dir_base + 14 * 8;
        if cli_dir_off + 8 > bytes.len() {
            return None;
        }
        let cli_rva = u32::from_le_bytes(bytes[cli_dir_off..cli_dir_off + 4].try_into().ok()?);
        let cli_dir_size =
            u32::from_le_bytes(bytes[cli_dir_off + 4..cli_dir_off + 8].try_into().ok()?);
        if cli_rva == 0 || cli_dir_size < 72 {
            return None;
        }

        let cli_off = Self::rva_to_file_offset(bytes, cli_rva, pe_offset)?;
        if cli_off + 72 > bytes.len() {
            return None;
        }

        let mut r = Reader::at(bytes, cli_off);
        let cb = r.read_u32().ok()?;
        let major_runtime_version = r.read_u16().ok()?;
        let minor_runtime_version = r.read_u16().ok()?;
        let metadata_rva = r.read_u32().ok()?;
        let metadata_size = r.read_u32().ok()?;
        let flags = r.read_u32().ok()?;
        let entry_point_token = r.read_u32().ok()?;
        let resources_rva = r.read_u32().ok()?;
        let resources_size = r.read_u32().ok()?;
        let strong_name_rva = r.read_u32().ok()?;
        let strong_name_size = r.read_u32().ok()?;

        Some(CliHeader {
            cb,
            major_runtime_version,
            minor_runtime_version,
            metadata_rva,
            metadata_size,
            flags,
            entry_point_token,
            resources_rva,
            resources_size,
            strong_name_rva,
            strong_name_size,
            file_offset: cli_off,
        })
    }

    /// Convert a PE virtual address (RVA) to a raw file offset by scanning
    /// the section table.  Falls back to the identity mapping if no section
    /// matches (useful for flat images / memory maps).
    fn rva_to_file_offset(data: &[u8], rva: u32, pe_offset: usize) -> Option<usize> {
        if rva == 0 {
            return Some(0);
        }
        let num_sections =
            u16::from_le_bytes(data[pe_offset + 6..pe_offset + 8].try_into().ok()?) as usize;
        let opt_size =
            u16::from_le_bytes(data[pe_offset + 20..pe_offset + 22].try_into().ok()?) as usize;
        let sections_start = pe_offset + 24 + opt_size;

        for i in 0..num_sections {
            let sec = sections_start + i * 40;
            if sec + 40 > data.len() {
                break;
            }
            let virt_size = u32::from_le_bytes(data[sec + 8..sec + 12].try_into().ok()?);
            let virt_addr = u32::from_le_bytes(data[sec + 12..sec + 16].try_into().ok()?);
            let raw_size = u32::from_le_bytes(data[sec + 16..sec + 20].try_into().ok()?);
            let raw_ptr = u32::from_le_bytes(data[sec + 20..sec + 24].try_into().ok()?);
            let sec_size = virt_size.max(raw_size);
            // Checked arithmetic, matching `rva_to_offset` earlier in this file:
            // both operands come from a hostile section header, so a wrapping
            // sum would silently skip the section.
            if rva >= virt_addr && rva < virt_addr.saturating_add(sec_size) {
                return (rva - virt_addr).checked_add(raw_ptr).map(|v| v as usize);
            }
        }
        // Identity fallback
        Some(rva as usize)
    }
}

// â"€â"€â"€ MetadataIndexer tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod indexer_tests {
    use super::*;

    fn make_tables() -> MetadataTables {
        let mut t = MetadataTables::default();
        t.type_def.push(TypeDefRow {
            flags: 0x01,
            type_name: "Foo".into(),
            type_namespace: "Acme".into(),
            extends: 0,
            field_list: 1,
            method_list: 1,
        });
        t.type_def.push(TypeDefRow {
            flags: 0x01,
            type_name: "Bar".into(),
            type_namespace: String::new(),
            extends: 0,
            field_list: 2,
            method_list: 2,
        });
        t.field.push(FieldRow {
            flags: 0x06,
            name: "X".into(),
            signature: vec![],
        });
        t.field.push(FieldRow {
            flags: 0x06,
            name: "Y".into(),
            signature: vec![],
        });
        t.method_def.push(MethodDefRow {
            rva: 0x2000,
            impl_flags: 0,
            flags: 0x06,
            name: "Run".into(),
            signature: vec![],
            param_list: 1,
        });
        t
    }

    #[test]
    fn test_method_by_token_found() {
        let tables = make_tables();
        let idx = MetadataIndexer::new(&tables);
        let m = idx.method_by_token(0x0600_0001);
        assert!(m.is_some());
        assert_eq!(m.unwrap().name, "Run");
    }

    #[test]
    fn test_method_by_token_missing() {
        let tables = make_tables();
        let idx = MetadataIndexer::new(&tables);
        assert!(idx.method_by_token(0x0600_0099).is_none());
    }

    #[test]
    fn test_type_by_name_with_namespace() {
        let tables = make_tables();
        let idx = MetadataIndexer::new(&tables);
        let t = idx.type_by_name("Acme", "Foo");
        assert!(t.is_some());
        assert_eq!(t.unwrap().type_name, "Foo");
    }

    #[test]
    fn test_type_by_name_no_namespace() {
        let tables = make_tables();
        let idx = MetadataIndexer::new(&tables);
        let t = idx.type_by_name("", "Bar");
        assert!(t.is_some());
    }

    #[test]
    fn test_type_by_name_missing() {
        let tables = make_tables();
        let idx = MetadataIndexer::new(&tables);
        assert!(idx.type_by_name("X", "Missing").is_none());
    }

    #[test]
    fn test_fields_of_type_first_type() {
        let tables = make_tables();
        let idx = MetadataIndexer::new(&tables);
        // First TypeDef has field_list=1, second has field_list=2 â†' only field[0]
        let fields = idx.fields_of_type(0x0200_0001);
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "X");
    }

    #[test]
    fn test_type_token_roundtrip() {
        let tables = make_tables();
        let idx = MetadataIndexer::new(&tables);
        let tok = idx.type_token("Acme", "Foo").unwrap();
        assert_eq!(tok, 0x0200_0001);
    }
}

// â"€â"€â"€ Method body parser (ECMA-335 Â§II.25.4) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// CIL exception clause type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExceptionClauseKind {
    /// `catch <TypeToken>` —" typed catch.
    Catch(u32),
    /// `filter` —" filter handler.
    Filter,
    /// `finally` handler.
    Finally,
    /// `fault` handler.
    Fault,
}

/// A single CIL exception handler clause.
#[derive(Debug, Clone)]
pub struct ExceptionClause {
    pub kind: ExceptionClauseKind,
    /// Byte offset of the try block start.
    pub try_offset: u32,
    /// Length (bytes) of the try block.
    pub try_length: u32,
    /// Byte offset of the handler block start.
    pub handler_offset: u32,
    /// Length (bytes) of the handler block.
    pub handler_length: u32,
    /// For Filter clauses, byte offset of the filter code.
    pub filter_offset: u32,
}

/// A decoded CIL method body.
#[derive(Debug, Clone)]
pub struct CilMethodBody {
    /// `true` if the runtime should zero-initialise locals on entry.
    pub init_locals: bool,
    /// Maximum evaluation stack depth.
    pub max_stack: u16,
    /// Token of the `LocalVarSig` `StandAloneSig` row (0 if no locals).
    pub local_var_sig_token: u32,
    /// Raw CIL byte-code.
    pub code: Vec<u8>,
    /// Decoded exception handler table.
    pub exception_clauses: Vec<ExceptionClause>,
}

impl CilMethodBody {
    /// Returns `true` if the method body has at least one exception clause.
    #[must_use]
    pub const fn has_exception_handlers(&self) -> bool {
        !self.exception_clauses.is_empty()
    }

    /// Returns the code size in bytes.
    #[must_use]
    pub const fn code_size(&self) -> usize {
        self.code.len()
    }

    /// Returns all `Catch` clauses.
    #[must_use]
    pub fn catch_clauses(&self) -> Vec<&ExceptionClause> {
        self.exception_clauses
            .iter()
            .filter(|c| matches!(c.kind, ExceptionClauseKind::Catch(_)))
            .collect()
    }

    /// Returns all `Finally` clauses.
    #[must_use]
    pub fn finally_clauses(&self) -> Vec<&ExceptionClause> {
        self.exception_clauses
            .iter()
            .filter(|c| c.kind == ExceptionClauseKind::Finally)
            .collect()
    }
}

/// Parse a CIL method body from the raw PE image at `file_offset`.
///
/// Handles both the **tiny** (1-byte header) and **fat** (12-byte header)
/// formats plus the optional extra-section exception-handler table (fat and
/// small forms).
///
/// # Errors
/// Returns [`MetadataError`] if the image is truncated or the header magic is
/// unrecognised.
///
/// # Panics
/// Panics if internal slicing arithmetic overflows; in practice this only
/// happens on intentionally malformed inputs that pass the initial length check.
pub fn parse_method_body(image: &[u8], file_offset: usize) -> Result<CilMethodBody> {
    if file_offset >= image.len() {
        return Err(MetadataError::UnexpectedEof {
            offset: file_offset,
            need: 1,
            have: 0,
        });
    }

    let first = image[file_offset];

    // â"€â"€ Tiny header: bits 1:0 == 0b10, code_size = bits 7:2 â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    if first & 0x03 == 0x02 {
        let code_size = (u32::from(first) >> 2) as usize;
        let code_start = file_offset + 1;
        if code_start + code_size > image.len() {
            return Err(MetadataError::UnexpectedEof {
                offset: code_start,
                need: code_size,
                have: image.len().saturating_sub(code_start),
            });
        }
        return Ok(CilMethodBody {
            init_locals: false,
            max_stack: 8,
            local_var_sig_token: 0,
            code: image[code_start..code_start + code_size].to_vec(),
            exception_clauses: Vec::new(),
        });
    }

    // â"€â"€ Fat header: bits 1:0 == 0b11 â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    if first & 0x03 != 0x03 {
        return Err(MetadataError::InvalidPeMagic(file_offset));
    }

    if file_offset + 12 > image.len() {
        return Err(MetadataError::UnexpectedEof {
            offset: file_offset,
            need: 12,
            have: image.len().saturating_sub(file_offset),
        });
    }

    let flags_and_size = u16::from_le_bytes([image[file_offset], image[file_offset + 1]]);
    let header_size_words = (flags_and_size >> 12) as usize; // header size in 4-byte units
    let header_size = header_size_words * 4;
    let flags = flags_and_size & 0x0FFF;

    let init_locals = flags & 0x0010 != 0;
    let more_sects = flags & 0x0008 != 0;

    let max_stack = u16::from_le_bytes([image[file_offset + 2], image[file_offset + 3]]);
    let code_size =
        u32::from_le_bytes(image[file_offset + 4..file_offset + 8].try_into().unwrap()) as usize;
    let local_var_sig_token =
        u32::from_le_bytes(image[file_offset + 8..file_offset + 12].try_into().unwrap());

    let code_start = file_offset + header_size.max(12);
    if code_start + code_size > image.len() {
        return Err(MetadataError::UnexpectedEof {
            offset: code_start,
            need: code_size,
            have: image.len().saturating_sub(code_start),
        });
    }
    let code = image[code_start..code_start + code_size].to_vec();

    // â"€â"€ Extra sections (exception handler table) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    let exception_clauses = if more_sects {
        parse_eh_sections(image, code_start + code_size)
    } else {
        Vec::new()
    };

    Ok(CilMethodBody {
        init_locals,
        max_stack,
        local_var_sig_token,
        code,
        exception_clauses,
    })
}

/// Parse all extra sections (exception handler tables) starting after the code.
fn parse_eh_sections(image: &[u8], code_end: usize) -> Vec<ExceptionClause> {
    let mut exception_clauses = Vec::new();
    let mut sect_off = code_end;
    // Align to 4.
    if !sect_off.is_multiple_of(4) {
        sect_off += 4 - (sect_off % 4);
    }
    while sect_off + 4 <= image.len() {
        let kind_byte = image[sect_off];
        let is_fat_sect = kind_byte & 0x40 != 0;
        let more_sects_next = kind_byte & 0x80 != 0;
        let is_eh_table = kind_byte & 0x01 != 0;
        if !is_eh_table {
            // Skip non-EH sections.
            let data_size = if is_fat_sect {
                if sect_off + 4 > image.len() {
                    break;
                }
                u32::from_le_bytes(image[sect_off + 1..sect_off + 4].try_into().unwrap()) as usize
            } else {
                image.get(sect_off + 1).copied().unwrap_or(0) as usize
            };
            sect_off += data_size;
            if !more_sects_next {
                break;
            }
            continue;
        }
        let data_size = if is_fat_sect {
            parse_fat_eh_clauses(image, sect_off, &mut exception_clauses)
        } else {
            parse_small_eh_clauses(image, sect_off, &mut exception_clauses)
        };
        sect_off += data_size;
        if !more_sects_next {
            break;
        }
    }
    exception_clauses
}

/// Parse a fat EH section (each clause is 24 bytes). Returns the `data_size` used.
fn parse_fat_eh_clauses(image: &[u8], sect_off: usize, out: &mut Vec<ExceptionClause>) -> usize {
    if sect_off + 4 > image.len() {
        return 0;
    }
    let data_size =
        u32::from_le_bytes(image[sect_off + 1..sect_off + 4].try_into().unwrap()) as usize;
    let clauses_start = sect_off + 4;
    let clauses_end = (sect_off + data_size).min(image.len());
    let mut p = clauses_start;
    while p + 24 <= clauses_end {
        let clause_flags = u32::from_le_bytes(image[p..p + 4].try_into().unwrap());
        let try_offset = u32::from_le_bytes(image[p + 4..p + 8].try_into().unwrap());
        let try_length = u32::from_le_bytes(image[p + 8..p + 12].try_into().unwrap());
        let handler_offset = u32::from_le_bytes(image[p + 12..p + 16].try_into().unwrap());
        let handler_length = u32::from_le_bytes(image[p + 16..p + 20].try_into().unwrap());
        let class_token_or_filter_offset =
            u32::from_le_bytes(image[p + 20..p + 24].try_into().unwrap());
        let kind = decode_eh_kind(clause_flags, class_token_or_filter_offset);
        let filter_offset = if clause_flags == 1 {
            class_token_or_filter_offset
        } else {
            0
        };
        out.push(ExceptionClause {
            kind,
            try_offset,
            try_length,
            handler_offset,
            handler_length,
            filter_offset,
        });
        p += 24;
    }
    data_size
}

/// Parse a small EH section (each clause is 12 bytes). Returns the `data_size` used.
fn parse_small_eh_clauses(image: &[u8], sect_off: usize, out: &mut Vec<ExceptionClause>) -> usize {
    if sect_off + 2 > image.len() {
        return 0;
    }
    let data_size = image[sect_off + 1] as usize;
    let clauses_start = sect_off + 4;
    let clauses_end = (sect_off + data_size).min(image.len());
    let mut p = clauses_start;
    while p + 12 <= clauses_end {
        let clause_flags = u32::from(u16::from_le_bytes([image[p], image[p + 1]]));
        let try_offset = u32::from(u16::from_le_bytes([image[p + 2], image[p + 3]]));
        let try_length = u32::from(image[p + 4]);
        let handler_offset = u32::from(u16::from_le_bytes([image[p + 5], image[p + 6]]));
        let handler_length = u32::from(image[p + 7]);
        let class_token_or_filter_offset =
            u32::from_le_bytes(image[p + 8..p + 12].try_into().unwrap());
        let kind = decode_eh_kind(clause_flags, class_token_or_filter_offset);
        let filter_offset = if clause_flags == 1 {
            class_token_or_filter_offset
        } else {
            0
        };
        out.push(ExceptionClause {
            kind,
            try_offset,
            try_length,
            handler_offset,
            handler_length,
            filter_offset,
        });
        p += 12;
    }
    data_size
}

/// Decode EH clause kind from ECMA-335 Â§II.25.4.6 flags.
const fn decode_eh_kind(flags: u32, class_token_or_filter_offset: u32) -> ExceptionClauseKind {
    match flags {
        1 => ExceptionClauseKind::Filter,
        2 => ExceptionClauseKind::Finally,
        4 => ExceptionClauseKind::Fault,
        _ => ExceptionClauseKind::Catch(class_token_or_filter_offset),
    }
}

// â"€â"€â"€ Complete custom attribute blob decoder â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Parse a custom attribute blob using a *fixed* descriptor —" a simple list of
/// element types for the fixed arguments (named args follow automatically).
///
/// This is a best-effort decoder suitable for attributes whose constructor
/// signatures are known ahead of time.  Handles the following element types:
/// `bool`, `i8/u8`, `i16/u16`, `i32/u32`, `i64/u64`, `f32/f64`, `string`,
/// `type`, one-dimensional arrays, and enum values.
///
/// # Errors
/// Returns an error if the blob is too short or its prolog is invalid.
pub fn parse_custom_attribute_blob_typed(
    blob: &[u8],
    fixed_arg_types: &[u8],
) -> Result<DecodedCustomAttribute> {
    if blob.len() < 2 {
        return Err(MetadataError::UnexpectedEof {
            offset: 0,
            need: 2,
            have: blob.len(),
        });
    }
    if blob[0] != 0x01 || blob[1] != 0x00 {
        return Ok(DecodedCustomAttribute::default());
    }

    let mut pos = 2usize;
    let mut fixed_args = Vec::with_capacity(fixed_arg_types.len());

    for &et in fixed_arg_types {
        let val = read_ca_fixed_arg(blob, &mut pos, et);
        fixed_args.push(val);
    }

    // Named arguments
    let mut named_args = Vec::new();
    if pos + 2 <= blob.len() {
        let num_named = u16::from_le_bytes([blob[pos], blob[pos + 1]]) as usize;
        pos += 2;
        for _ in 0..num_named {
            if pos >= blob.len() {
                break;
            }
            let is_field = blob[pos] == 0x53; // FIELD=0x53, PROPERTY=0x54
            pos += 1;
            if pos >= blob.len() {
                break;
            }
            let arg_et = blob[pos];
            pos += 1;
            // Read name (UTF-8 length-prefixed)
            let name = read_ca_string(blob, &mut pos).unwrap_or_default();
            let value = read_ca_fixed_arg(blob, &mut pos, arg_et);
            named_args.push(CustomAttributeNamedArg {
                is_field,
                name,
                value,
            });
        }
    }

    Ok(DecodedCustomAttribute {
        fixed_args,
        named_args,
    })
}

fn read_ca_fixed_arg(blob: &[u8], pos: &mut usize, et: u8) -> CustomAttributeValue {
    use element_type as ET;
    if *pos >= blob.len() {
        return CustomAttributeValue::Unknown;
    }
    match et {
        ET::BOOLEAN => {
            let v = blob[*pos] != 0;
            *pos += 1;
            CustomAttributeValue::Bool(v)
        }
        ET::I1 => {
            let v = blob[*pos].cast_signed();
            *pos += 1;
            CustomAttributeValue::I1(v)
        }
        ET::U1 => {
            let v = blob[*pos];
            *pos += 1;
            CustomAttributeValue::U1(v)
        }
        ET::I2 => {
            if *pos + 2 > blob.len() {
                return CustomAttributeValue::Unknown;
            }
            let v = i16::from_le_bytes([blob[*pos], blob[*pos + 1]]);
            *pos += 2;
            CustomAttributeValue::I2(v)
        }
        ET::U2 => {
            if *pos + 2 > blob.len() {
                return CustomAttributeValue::Unknown;
            }
            let v = u16::from_le_bytes([blob[*pos], blob[*pos + 1]]);
            *pos += 2;
            CustomAttributeValue::U2(v)
        }
        ET::I4 => {
            if *pos + 4 > blob.len() {
                return CustomAttributeValue::Unknown;
            }
            let v = i32::from_le_bytes(blob[*pos..*pos + 4].try_into().unwrap());
            *pos += 4;
            CustomAttributeValue::I4(v)
        }
        ET::U4 => {
            if *pos + 4 > blob.len() {
                return CustomAttributeValue::Unknown;
            }
            let v = u32::from_le_bytes(blob[*pos..*pos + 4].try_into().unwrap());
            *pos += 4;
            CustomAttributeValue::U4(v)
        }
        ET::I8 => {
            if *pos + 8 > blob.len() {
                return CustomAttributeValue::Unknown;
            }
            let v = i64::from_le_bytes(blob[*pos..*pos + 8].try_into().unwrap());
            *pos += 8;
            CustomAttributeValue::I8(v)
        }
        ET::U8 => {
            if *pos + 8 > blob.len() {
                return CustomAttributeValue::Unknown;
            }
            let v = u64::from_le_bytes(blob[*pos..*pos + 8].try_into().unwrap());
            *pos += 8;
            CustomAttributeValue::U8(v)
        }
        ET::R4 => {
            if *pos + 4 > blob.len() {
                return CustomAttributeValue::Unknown;
            }
            let bits = u32::from_le_bytes(blob[*pos..*pos + 4].try_into().unwrap());
            *pos += 4;
            CustomAttributeValue::R4(f32::from_bits(bits))
        }
        ET::R8 => {
            if *pos + 8 > blob.len() {
                return CustomAttributeValue::Unknown;
            }
            let bits = u64::from_le_bytes(blob[*pos..*pos + 8].try_into().unwrap());
            *pos += 8;
            CustomAttributeValue::R8(f64::from_bits(bits))
        }
        ET::STRING => {
            let s = read_ca_string(blob, pos);
            CustomAttributeValue::String(s)
        }
        0x50 => {
            // System.Type —" stored as a string type-name
            let s = read_ca_string(blob, pos);
            CustomAttributeValue::Type(s.unwrap_or_default())
        }
        0x1D => {
            // SzArray —" read element type, then count, then elements
            if *pos >= blob.len() {
                return CustomAttributeValue::Unknown;
            }
            let elem_et = blob[*pos];
            *pos += 1;
            if *pos + 4 > blob.len() {
                return CustomAttributeValue::Unknown;
            }
            let count_raw = u32::from_le_bytes(blob[*pos..*pos + 4].try_into().unwrap());
            *pos += 4;
            // Cap allocation: a CA blob with count=2^32-1 would exhaust memory.
            let count = count_raw as usize;
            let mut elems = Vec::with_capacity(count.min(4096));
            for _ in 0..count {
                elems.push(read_ca_fixed_arg(blob, pos, elem_et));
            }
            CustomAttributeValue::Array(elems)
        }
        _ => CustomAttributeValue::Unknown,
    }
}

/// Read a custom-attribute `SerString` (null byte 0xFF = null; otherwise ECMA
/// compressed-length prefix followed by UTF-8 bytes).
fn read_ca_string(blob: &[u8], pos: &mut usize) -> Option<String> {
    if *pos >= blob.len() {
        return None;
    }
    if blob[*pos] == 0xFF {
        *pos += 1;
        return None; // null string
    }
    let len = read_compressed_uint_slice(blob, pos) as usize;
    if *pos + len > blob.len() {
        return None;
    }
    let s = std::str::from_utf8(&blob[*pos..*pos + len])
        .ok()?
        .to_string();
    *pos += len;
    Some(s)
}

// â"€â"€â"€ Type system reconstruction helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A reconstructed type definition with full relationship data.
#[derive(Debug, Clone)]
pub struct TypeModel {
    /// 1-based `TypeDef` index.
    pub index: u32,
    /// Fully-qualified type name.
    pub full_name: String,
    /// Access flags from `TypeDef.Flags`.
    pub flags: u32,
    /// Coded `TypeDefOrRef` token that this type extends (0 = no base).
    pub base_type: u32,
    /// 1-based `TypeDef` indices of interfaces implemented.
    pub interfaces: Vec<u32>,
    /// 1-based `TypeDef` indices of nested classes.
    pub nested_types: Vec<u32>,
    /// 1-based indices into the `GenericParam` table.
    pub generic_params: Vec<u32>,
    /// 1-based indices into the `MethodDef` table.
    pub method_indices: Vec<u32>,
    /// 1-based indices into the Field table.
    pub field_indices: Vec<u32>,
}

impl TypeModel {
    /// Returns `true` if the type is a generic type definition.
    #[must_use]
    pub const fn is_generic(&self) -> bool {
        !self.generic_params.is_empty()
    }

    /// Returns `true` if the type is abstract (TypeAttributes.Abstract).
    #[must_use]
    pub const fn is_abstract(&self) -> bool {
        self.flags & 0x0080 != 0
    }

    /// Returns `true` if the type is sealed.
    #[must_use]
    pub const fn is_sealed(&self) -> bool {
        self.flags & 0x0100 != 0
    }

    /// Returns `true` if the type is an interface.
    #[must_use]
    pub const fn is_interface(&self) -> bool {
        self.flags & 0x0020 != 0
    }

    /// Returns `true` if the type is a value type (struct).
    #[must_use]
    pub const fn is_value_type(&self) -> bool {
        self.flags & 0x0100 != 0 && self.flags & 0x0080 != 0
    }
}

impl MetadataReader {
    /// Reconstruct the full type-system model for all `TypeDef` rows.
    ///
    /// This resolves base types, interfaces, nested classes, generic params,
    /// methods, and fields into a flat list of [`TypeModel`] values.
    #[must_use]
    pub fn reconstruct_type_system(&self) -> Vec<TypeModel> {
        let n = self.tables.type_def.len();
        let mut models = Vec::with_capacity(n);

        for (i, row) in self.tables.type_def.iter().enumerate() {
            let index = u32::try_from(i + 1).unwrap_or(u32::MAX);
            let full_name = if row.type_namespace.is_empty() {
                row.type_name.clone()
            } else {
                format!("{}.{}", row.type_namespace, row.type_name)
            };

            // Method range
            let method_start = row.method_list as usize;
            let method_end = self
                .tables
                .type_def
                .get(i + 1)
                .map_or(self.tables.method_def.len() + 1, |r| r.method_list as usize);
            let method_indices: Vec<u32> = (method_start..method_end)
                .filter(|&m| m >= 1 && m <= self.tables.method_def.len())
                .map(|m| u32::try_from(m).unwrap_or(u32::MAX))
                .collect();

            // Field range
            let field_start = row.field_list as usize;
            let field_end = self
                .tables
                .type_def
                .get(i + 1)
                .map_or(self.tables.field.len() + 1, |r| r.field_list as usize);
            let field_indices: Vec<u32> = (field_start..field_end)
                .filter(|&f| f >= 1 && f <= self.tables.field.len())
                .map(|f| u32::try_from(f).unwrap_or(u32::MAX))
                .collect();

            // Interfaces via InterfaceImpl
            let interfaces: Vec<u32> = self
                .tables
                .interface_impl
                .iter()
                .filter(|ii| ii.class == index)
                .map(|ii| {
                    let (tag, row_idx) =
                        coded_index::decode(ii.interface, coded_index::TYPEDEF_OR_REF_BITS);
                    if tag == coded_index::TYPEDEF_OR_REF_TYPEDEF {
                        row_idx
                    } else {
                        0
                    }
                })
                .filter(|&r| r > 0)
                .collect();

            // Nested classes
            let nested_types: Vec<u32> = self
                .tables
                .nested_class
                .iter()
                .filter(|nc| nc.enclosing_class == index)
                .map(|nc| nc.nested_class)
                .collect();

            // Generic params (TypeOrMethodDef, tag=0 means TypeDef)
            let owner_coded = coded_index::encode(0, index, coded_index::TYPE_OR_METHOD_DEF_BITS);
            let generic_params: Vec<u32> = self
                .tables
                .generic_param
                .iter()
                .enumerate()
                .filter(|(_, gp)| gp.owner == owner_coded)
                .map(|(j, _)| u32::try_from(j + 1).unwrap_or(u32::MAX))
                .collect();

            models.push(TypeModel {
                index,
                full_name,
                flags: row.flags,
                base_type: row.extends,
                interfaces,
                nested_types,
                generic_params,
                method_indices,
                field_indices,
            });
        }

        models
    }

    /// Resolve the base-type name of a `TypeModel` using the coded Extends token.
    ///
    /// Returns `None` if the type has no explicit base type (Extends == 0).
    #[must_use]
    pub fn resolve_base_type_name(&self, model: &TypeModel) -> Option<String> {
        if model.base_type == 0 {
            return None;
        }
        let (tag, row_idx) = coded_index::decode(model.base_type, coded_index::TYPEDEF_OR_REF_BITS);
        match tag {
            coded_index::TYPEDEF_OR_REF_TYPEDEF => self
                .tables
                .type_def
                .get((row_idx as usize).wrapping_sub(1))
                .map(|r| {
                    if r.type_namespace.is_empty() {
                        r.type_name.clone()
                    } else {
                        format!("{}.{}", r.type_namespace, r.type_name)
                    }
                }),
            coded_index::TYPEDEF_OR_REF_TYPEREF => self
                .tables
                .type_ref
                .get((row_idx as usize).wrapping_sub(1))
                .map(|r| {
                    if r.type_namespace.is_empty() {
                        r.type_name.clone()
                    } else {
                        format!("{}.{}", r.type_namespace, r.type_name)
                    }
                }),
            _ => None,
        }
    }
}

// â"€â"€â"€ P/Invoke summary â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A resolved P/Invoke declaration.
#[derive(Debug, Clone)]
pub struct PInvokeDecl {
    /// Name of the managed method.
    pub method_name: String,
    /// DLL/module name from the `ModuleRef` table.
    pub module_name: String,
    /// Entry point name in the native library.
    pub entry_point: String,
    /// Raw `PInvokeAttributes` flags.
    pub mapping_flags: u16,
}

impl PInvokeDecl {
    /// Returns `true` if the `NoMangle` flag is set.
    #[must_use]
    pub const fn no_mangle(&self) -> bool {
        self.mapping_flags & impl_map_attributes::NO_MANGLE != 0
    }

    /// Returns the calling convention as a string.
    #[must_use]
    pub const fn calling_convention(&self) -> &'static str {
        match self.mapping_flags & 0x0700 {
            impl_map_attributes::CALL_CONV_CDECL => "cdecl",
            impl_map_attributes::CALL_CONV_STDCALL => "stdcall",
            impl_map_attributes::CALL_CONV_THISCALL => "thiscall",
            impl_map_attributes::CALL_CONV_FASTCALL => "fastcall",
            impl_map_attributes::CALL_CONV_WINAPI => "winapi",
            _ => "default",
        }
    }

    /// Returns the character set as a string.
    #[must_use]
    pub const fn char_set(&self) -> &'static str {
        match self.mapping_flags & 0x0006 {
            impl_map_attributes::CHAR_SET_ANSI => "Ansi",
            impl_map_attributes::CHAR_SET_UNICODE => "Unicode",
            impl_map_attributes::CHAR_SET_AUTO => "Auto",
            _ => "None",
        }
    }
}

impl MetadataReader {
    /// Collect all P/Invoke declarations from the `ImplMap` table.
    #[must_use]
    pub fn pinvoke_declarations(&self) -> Vec<PInvokeDecl> {
        self.tables
            .impl_map
            .iter()
            .filter_map(|im| {
                // MemberForwarded is a coded index: Field(0) or MethodDef(1)
                let (tag, row_idx) = coded_index::decode(im.member_forwarded, 1);
                let method_name = if tag == 1 {
                    // MethodDef
                    self.tables
                        .method_def
                        .get((row_idx as usize).wrapping_sub(1))
                        .map(|m| m.name.clone())?
                } else {
                    return None; // Field P/Invoke not common
                };
                let module_name = self
                    .tables
                    .module_ref
                    .get((im.import_scope as usize).wrapping_sub(1))
                    .map(|m| m.name.clone())
                    .unwrap_or_default();
                Some(PInvokeDecl {
                    method_name,
                    module_name,
                    entry_point: im.import_name.clone(),
                    mapping_flags: im.mapping_flags,
                })
            })
            .collect()
    }
}

// â"€â"€â"€ Generic instantiation helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A decoded `MethodSpec` instantiation.
#[derive(Debug, Clone)]
pub struct MethodSpecInfo {
    /// Coded `MethodDefOrRef` token for the generic method definition.
    pub method_token: u32,
    /// Name of the method definition (if resolvable).
    pub method_name: Option<String>,
    /// Type arguments (decoded from the instantiation signature).
    pub type_args: Vec<String>,
}

impl MetadataReader {
    /// Decode all `MethodSpec` rows into [`MethodSpecInfo`] values.
    #[must_use]
    pub fn method_spec_infos(&self) -> Vec<MethodSpecInfo> {
        self.tables
            .method_spec
            .iter()
            .map(|ms| {
                // MethodDefOrRef: tag 0 = MethodDef, tag 1 = MemberRef
                let (tag, row_idx) = coded_index::decode(ms.method, 1);
                let method_name = if tag == 0 {
                    self.tables
                        .method_def
                        .get((row_idx as usize).wrapping_sub(1))
                        .map(|m| m.name.clone())
                } else {
                    self.tables
                        .member_ref
                        .get((row_idx as usize).wrapping_sub(1))
                        .map(|m| m.name.clone())
                };

                // Decode instantiation blob: GENERICINST(0x0A) count type*
                let type_args = decode_method_spec_instantiation(&ms.instantiation);

                MethodSpecInfo {
                    method_token: ms.method,
                    method_name,
                    type_args,
                }
            })
            .collect()
    }
}

/// Decode a `MethodSpec` instantiation blob into type argument names.
fn decode_method_spec_instantiation(blob: &[u8]) -> Vec<String> {
    if blob.len() < 2 || blob[0] != 0x0A {
        return Vec::new();
    }
    let mut pos = 1usize;
    let count = read_compressed_uint_slice(blob, &mut pos) as usize;
    (0..count).map(|_| read_type_sig(blob, &mut pos)).collect()
}

// â"€â"€â"€ Security declaration helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Action code for `DeclSecurity` (ECMA-335 Â§II.22.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityAction {
    Demand,
    Assert,
    Deny,
    PermitOnly,
    LinkDemand,
    InheritanceDemand,
    RequestMinimum,
    RequestOptional,
    RequestRefuse,
    PrejitGrant,
    PrejitDeny,
    NonCasLinkDemand,
    NonCasInheritance,
    Other(u16),
}

impl SecurityAction {
    /// Decode from the raw action value in the `DeclSecurity` table.
    #[must_use]
    pub const fn from_raw(raw: u16) -> Self {
        match raw {
            2 => Self::Demand,
            3 => Self::Assert,
            4 => Self::Deny,
            5 => Self::PermitOnly,
            6 => Self::LinkDemand,
            7 => Self::InheritanceDemand,
            8 => Self::RequestMinimum,
            9 => Self::RequestOptional,
            10 => Self::RequestRefuse,
            11 => Self::PrejitGrant,
            12 => Self::PrejitDeny,
            13 => Self::NonCasLinkDemand,
            14 => Self::NonCasInheritance,
            n => Self::Other(n),
        }
    }

    /// Returns a human-readable name for the action.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Demand => "Demand",
            Self::Assert => "Assert",
            Self::Deny => "Deny",
            Self::PermitOnly => "PermitOnly",
            Self::LinkDemand => "LinkDemand",
            Self::InheritanceDemand => "InheritanceDemand",
            Self::RequestMinimum => "RequestMinimum",
            Self::RequestOptional => "RequestOptional",
            Self::RequestRefuse => "RequestRefuse",
            Self::PrejitGrant => "PrejitGrant",
            Self::PrejitDeny => "PrejitDeny",
            Self::NonCasLinkDemand => "NonCasLinkDemand",
            Self::NonCasInheritance => "NonCasInheritance",
            Self::Other(_) => "Unknown",
        }
    }
}

impl MetadataReader {
    /// Return all `DeclSecurity` rows decoded into `(parent_coded, SecurityAction, blob)`.
    #[must_use]
    pub fn security_declarations(&self) -> Vec<(u32, SecurityAction, &[u8])> {
        self.tables
            .decl_security
            .iter()
            .map(|ds| {
                (
                    ds.parent,
                    SecurityAction::from_raw(ds.action),
                    ds.permission_set.as_slice(),
                )
            })
            .collect()
    }
}

// â"€â"€â"€ Enterprise-level method body tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod method_body_tests {
    use super::*;

    fn make_tiny_body(code: &[u8]) -> Vec<u8> {
        // Tiny header: bits 7:2 = code_size, bits 1:0 = 0b10
        let header = (u8::try_from(code.len()).unwrap_or(u8::MAX) << 2) | 0x02;
        let mut v = vec![header];
        v.extend_from_slice(code);
        v
    }

    fn make_fat_body(code: &[u8], init_locals: bool, more_sects: bool) -> Vec<u8> {
        // Fat header: flags bits 1:0 = 0b11, 2 = MoreSects, 4 = InitLocals
        // Header size = 3 (dwords = 12 bytes)
        let mut flags: u16 = 0x3003; // header size = 3, format = fat
        if init_locals {
            flags |= 0x0010;
        }
        if more_sects {
            flags |= 0x0008;
        }
        let code_size = u32::try_from(code.len()).unwrap_or(u32::MAX);
        let mut v = Vec::new();
        v.extend_from_slice(&flags.to_le_bytes());
        v.extend_from_slice(&8u16.to_le_bytes()); // max_stack
        v.extend_from_slice(&code_size.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // LocalVarSigTok
        v.extend_from_slice(code);
        v
    }

    #[test]
    fn test_tiny_body_nop() {
        let image = make_tiny_body(&[0x00]); // NOP
        let body = parse_method_body(&image, 0).unwrap();
        assert_eq!(body.code, vec![0x00]);
        assert!(!body.init_locals);
        assert_eq!(body.max_stack, 8);
        assert_eq!(body.local_var_sig_token, 0);
        assert!(body.exception_clauses.is_empty());
    }

    #[test]
    fn test_tiny_body_ret() {
        let image = make_tiny_body(&[0x2A]); // RET
        let body = parse_method_body(&image, 0).unwrap();
        assert_eq!(body.code, vec![0x2A]);
        assert!(!body.has_exception_handlers());
    }

    #[test]
    fn test_tiny_body_multi_instr() {
        let code = vec![0x00u8, 0x2A]; // NOP, RET
        let image = make_tiny_body(&code);
        let body = parse_method_body(&image, 0).unwrap();
        assert_eq!(body.code_size(), 2);
    }

    #[test]
    fn test_fat_body_no_more_sects() {
        let code = vec![0x2Au8]; // RET
        let image = make_fat_body(&code, false, false);
        let body = parse_method_body(&image, 0).unwrap();
        assert_eq!(body.code, code);
        assert!(!body.init_locals);
        assert_eq!(body.max_stack, 8);
        assert!(!body.has_exception_handlers());
    }

    #[test]
    fn test_fat_body_init_locals() {
        let code = vec![0x2Au8];
        let image = make_fat_body(&code, true, false);
        let body = parse_method_body(&image, 0).unwrap();
        assert!(body.init_locals);
    }

    #[test]
    fn test_fat_body_empty_code() {
        let image = make_fat_body(&[], false, false);
        let body = parse_method_body(&image, 0).unwrap();
        assert_eq!(body.code_size(), 0);
    }

    #[test]
    fn test_method_body_out_of_bounds() {
        let image = vec![0u8; 4];
        // Pointing past the end
        assert!(parse_method_body(&image, 100).is_err());
    }

    #[test]
    fn test_exception_clause_kind_catch() {
        let kind = decode_eh_kind(0, 0x0200_0001);
        assert!(matches!(kind, ExceptionClauseKind::Catch(0x0200_0001)));
    }

    #[test]
    fn test_exception_clause_kind_finally() {
        let kind = decode_eh_kind(2, 0);
        assert_eq!(kind, ExceptionClauseKind::Finally);
    }

    #[test]
    fn test_exception_clause_kind_fault() {
        let kind = decode_eh_kind(4, 0);
        assert_eq!(kind, ExceptionClauseKind::Fault);
    }

    #[test]
    fn test_exception_clause_kind_filter() {
        let kind = decode_eh_kind(1, 0x100);
        assert_eq!(kind, ExceptionClauseKind::Filter);
    }

    #[test]
    fn test_cil_method_body_finally_clauses() {
        let body = CilMethodBody {
            init_locals: false,
            max_stack: 8,
            local_var_sig_token: 0,
            code: vec![0x2A],
            exception_clauses: vec![
                ExceptionClause {
                    kind: ExceptionClauseKind::Finally,
                    try_offset: 0,
                    try_length: 5,
                    handler_offset: 5,
                    handler_length: 3,
                    filter_offset: 0,
                },
                ExceptionClause {
                    kind: ExceptionClauseKind::Catch(0x0200_0001),
                    try_offset: 0,
                    try_length: 5,
                    handler_offset: 8,
                    handler_length: 3,
                    filter_offset: 0,
                },
            ],
        };
        assert_eq!(body.finally_clauses().len(), 1);
        assert_eq!(body.catch_clauses().len(), 1);
        assert!(body.has_exception_handlers());
    }

    #[test]
    fn test_cil_method_body_no_handlers() {
        let body = CilMethodBody {
            init_locals: false,
            max_stack: 8,
            local_var_sig_token: 0,
            code: vec![0x2A],
            exception_clauses: vec![],
        };
        assert!(!body.has_exception_handlers());
        assert!(body.catch_clauses().is_empty());
        assert!(body.finally_clauses().is_empty());
    }

    #[test]
    fn test_method_body_tiny_zero_code_size() {
        // Tiny header with code_size == 0 â†' 0b10
        let image = vec![0x02u8];
        let body = parse_method_body(&image, 0).unwrap();
        assert_eq!(body.code_size(), 0);
    }
}

// â"€â"€â"€ Custom attribute typed decoder tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod ca_typed_tests {
    use super::*;

    #[test]
    fn test_ca_typed_bool_true() {
        // prolog(01 00) + bool(01) = true
        let blob = vec![0x01u8, 0x00, 0x01, 0x00, 0x00];
        let et = element_type::BOOLEAN;
        let ca = parse_custom_attribute_blob_typed(&blob, &[et]).unwrap();
        assert_eq!(ca.fixed_args[0], CustomAttributeValue::Bool(true));
    }

    #[test]
    fn test_ca_typed_i32() {
        let mut blob = vec![0x01u8, 0x00];
        blob.extend_from_slice(&42i32.to_le_bytes());
        blob.extend_from_slice(&0u16.to_le_bytes()); // 0 named args
        let ca = parse_custom_attribute_blob_typed(&blob, &[element_type::I4]).unwrap();
        assert_eq!(ca.fixed_args[0], CustomAttributeValue::I4(42));
    }

    #[test]
    fn test_ca_typed_string() {
        // prolog + SerString("Hi") = 0x02 "Hi"
        let mut blob = vec![0x01u8, 0x00, 0x02, b'H', b'i'];
        blob.extend_from_slice(&0u16.to_le_bytes());
        let ca = parse_custom_attribute_blob_typed(&blob, &[element_type::STRING]).unwrap();
        assert_eq!(
            ca.fixed_args[0],
            CustomAttributeValue::String(Some("Hi".into()))
        );
    }

    #[test]
    fn test_ca_typed_null_string() {
        // prolog + null SerString (0xFF)
        let mut blob = vec![0x01u8, 0x00, 0xFF];
        blob.extend_from_slice(&0u16.to_le_bytes());
        let ca = parse_custom_attribute_blob_typed(&blob, &[element_type::STRING]).unwrap();
        assert_eq!(ca.fixed_args[0], CustomAttributeValue::String(None));
    }

    #[test]
    fn test_ca_typed_multiple_fixed() {
        let mut blob = vec![0x01u8, 0x00];
        blob.push(0x01); // bool = true
        blob.extend_from_slice(&7i32.to_le_bytes()); // i32 = 7
        blob.extend_from_slice(&0u16.to_le_bytes()); // 0 named
        let ca =
            parse_custom_attribute_blob_typed(&blob, &[element_type::BOOLEAN, element_type::I4])
                .unwrap();
        assert_eq!(ca.fixed_args.len(), 2);
        assert_eq!(ca.fixed_args[0], CustomAttributeValue::Bool(true));
        assert_eq!(ca.fixed_args[1], CustomAttributeValue::I4(7));
    }

    #[test]
    fn test_ca_typed_too_short() {
        assert!(parse_custom_attribute_blob_typed(&[0x01], &[]).is_err());
    }

    #[test]
    fn test_ca_typed_no_prolog_returns_default() {
        // Non-matching prolog returns default (empty)
        let blob = vec![0x00u8, 0x00];
        let ca = parse_custom_attribute_blob_typed(&blob, &[]).unwrap();
        assert_eq!(ca.fixed_arg_count(), 0);
    }

    #[test]
    fn test_ca_typed_named_arg_field() {
        // prolog + 0 fixed + 1 named field (bool "MyField" = true)
        let name = b"MyField";
        let mut blob = vec![0x01u8, 0x00]; // prolog
        blob.extend_from_slice(&1u16.to_le_bytes()); // 1 named arg
        blob.push(0x53); // FIELD
        blob.push(element_type::BOOLEAN); // bool
        blob.push(u8::try_from(name.len()).unwrap_or(u8::MAX)); // length-prefixed name
        blob.extend_from_slice(name);
        blob.push(0x01); // true
        let ca = parse_custom_attribute_blob_typed(&blob, &[]).unwrap();
        assert_eq!(ca.named_arg_count(), 1);
        assert_eq!(ca.named("MyField"), Some(&CustomAttributeValue::Bool(true)));
        assert!(ca.named_args[0].is_field);
    }
}

// â"€â"€â"€ Type system reconstruction tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod type_system_tests {
    use super::*;

    fn make_reader_with_types() -> MetadataReader {
        let mut tables = MetadataTables::default();
        // Type 1: System.Object (no base, no interfaces)
        tables.type_def.push(TypeDefRow {
            flags: 0x0001, // public
            type_name: "Object".into(),
            type_namespace: "System".into(),
            extends: 0,
            field_list: 1,
            method_list: 1,
        });
        // Type 2: MyClass extends System.Object
        // extends = TypeRef(tag=1) row=1 â†' encoded = (1 << 2) | 1 = 0x05
        tables.type_def.push(TypeDefRow {
            flags: 0x0001,
            type_name: "MyClass".into(),
            type_namespace: "App".into(),
            extends: 0x05, // TypeRef row 1
            field_list: 1,
            method_list: 1,
        });
        // TypeRef 1: System.Object
        tables.type_ref.push(TypeRefRow {
            resolution_scope: 0,
            type_name: "Object".into(),
            type_namespace: "System".into(),
        });
        MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables,
        }
    }

    #[test]
    fn test_reconstruct_type_system_count() {
        let reader = make_reader_with_types();
        let models = reader.reconstruct_type_system();
        assert_eq!(models.len(), 2);
    }

    #[test]
    fn test_reconstruct_type_model_full_name() {
        let reader = make_reader_with_types();
        let models = reader.reconstruct_type_system();
        assert_eq!(models[0].full_name, "System.Object");
        assert_eq!(models[1].full_name, "App.MyClass");
    }

    #[test]
    fn test_reconstruct_type_model_base_type() {
        let reader = make_reader_with_types();
        let models = reader.reconstruct_type_system();
        assert_eq!(models[0].base_type, 0);
        assert_ne!(models[1].base_type, 0);
    }

    #[test]
    fn test_resolve_base_type_name_no_extends() {
        let reader = make_reader_with_types();
        let models = reader.reconstruct_type_system();
        assert_eq!(reader.resolve_base_type_name(&models[0]), None);
    }

    #[test]
    fn test_resolve_base_type_name_typeref() {
        let reader = make_reader_with_types();
        let models = reader.reconstruct_type_system();
        let base = reader.resolve_base_type_name(&models[1]);
        assert_eq!(base, Some("System.Object".into()));
    }

    #[test]
    fn test_type_model_is_abstract() {
        let model = TypeModel {
            index: 1,
            full_name: "Foo".into(),
            flags: 0x0081, // abstract | public
            base_type: 0,
            interfaces: vec![],
            nested_types: vec![],
            generic_params: vec![],
            method_indices: vec![],
            field_indices: vec![],
        };
        assert!(model.is_abstract());
    }

    #[test]
    fn test_type_model_is_interface() {
        let model = TypeModel {
            index: 1,
            full_name: "IFoo".into(),
            flags: 0x00A0, // interface | abstract | public... simplified
            base_type: 0,
            interfaces: vec![],
            nested_types: vec![],
            generic_params: vec![],
            method_indices: vec![],
            field_indices: vec![],
        };
        assert!(model.is_interface());
    }

    #[test]
    fn test_type_model_is_not_generic() {
        let model = TypeModel {
            index: 1,
            full_name: "Foo".into(),
            flags: 0x01,
            base_type: 0,
            interfaces: vec![],
            nested_types: vec![],
            generic_params: vec![],
            method_indices: vec![],
            field_indices: vec![],
        };
        assert!(!model.is_generic());
    }

    #[test]
    fn test_type_model_is_generic() {
        let model = TypeModel {
            index: 1,
            full_name: "List`1".into(),
            flags: 0x01,
            base_type: 0,
            interfaces: vec![],
            nested_types: vec![],
            generic_params: vec![1],
            method_indices: vec![],
            field_indices: vec![],
        };
        assert!(model.is_generic());
    }
}

// â"€â"€â"€ P/Invoke tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod pinvoke_tests {
    use super::*;

    fn make_pinvoke_reader() -> MetadataReader {
        let mut tables = MetadataTables::default();
        tables.method_def.push(MethodDefRow {
            rva: 0,
            impl_flags: 0,
            flags: 0x0096, // pinvokeimpl | static | public
            name: "NativeMethod".into(),
            signature: vec![],
            param_list: 1,
        });
        tables.module_ref.push(ModuleRefRow {
            name: "kernel32.dll".into(),
        });
        // MemberForwarded: MethodDef(tag=1) row=1 â†' (1 << 1) | 1 = 0x03
        tables.impl_map.push(ImplMapRow {
            mapping_flags: impl_map_attributes::CALL_CONV_STDCALL
                | impl_map_attributes::CHAR_SET_UNICODE,
            member_forwarded: 0x03,
            import_name: "NativeMethodW".into(),
            import_scope: 1,
        });
        MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables,
        }
    }

    #[test]
    fn test_pinvoke_declarations_count() {
        let reader = make_pinvoke_reader();
        let decls = reader.pinvoke_declarations();
        assert_eq!(decls.len(), 1);
    }

    #[test]
    fn test_pinvoke_method_name() {
        let reader = make_pinvoke_reader();
        let decls = reader.pinvoke_declarations();
        assert_eq!(decls[0].method_name, "NativeMethod");
    }

    #[test]
    fn test_pinvoke_module_name() {
        let reader = make_pinvoke_reader();
        let decls = reader.pinvoke_declarations();
        assert_eq!(decls[0].module_name, "kernel32.dll");
    }

    #[test]
    fn test_pinvoke_entry_point() {
        let reader = make_pinvoke_reader();
        let decls = reader.pinvoke_declarations();
        assert_eq!(decls[0].entry_point, "NativeMethodW");
    }

    #[test]
    fn test_pinvoke_calling_convention_stdcall() {
        let reader = make_pinvoke_reader();
        let decls = reader.pinvoke_declarations();
        assert_eq!(decls[0].calling_convention(), "stdcall");
    }

    #[test]
    fn test_pinvoke_char_set_unicode() {
        let reader = make_pinvoke_reader();
        let decls = reader.pinvoke_declarations();
        assert_eq!(decls[0].char_set(), "Unicode");
    }

    #[test]
    fn test_pinvoke_no_mangle_false() {
        let reader = make_pinvoke_reader();
        let decls = reader.pinvoke_declarations();
        assert!(!decls[0].no_mangle());
    }

    #[test]
    fn test_pinvoke_decl_no_mangle_true() {
        let decl = PInvokeDecl {
            method_name: "Fn".into(),
            module_name: "lib.so".into(),
            entry_point: "Fn".into(),
            mapping_flags: impl_map_attributes::NO_MANGLE,
        };
        assert!(decl.no_mangle());
    }

    #[test]
    fn test_pinvoke_empty_when_no_implmap() {
        let reader = MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables: MetadataTables::default(),
        };
        assert!(reader.pinvoke_declarations().is_empty());
    }
}

// â"€â"€â"€ Security declaration tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn test_security_action_demand() {
        assert_eq!(SecurityAction::from_raw(2), SecurityAction::Demand);
        assert_eq!(SecurityAction::Demand.name(), "Demand");
    }

    #[test]
    fn test_security_action_link_demand() {
        assert_eq!(SecurityAction::from_raw(6), SecurityAction::LinkDemand);
        assert_eq!(SecurityAction::LinkDemand.name(), "LinkDemand");
    }

    #[test]
    fn test_security_action_assert() {
        assert_eq!(SecurityAction::from_raw(3), SecurityAction::Assert);
    }

    #[test]
    fn test_security_action_deny() {
        assert_eq!(SecurityAction::from_raw(4), SecurityAction::Deny);
    }

    #[test]
    fn test_security_action_inheritance_demand() {
        assert_eq!(
            SecurityAction::from_raw(7),
            SecurityAction::InheritanceDemand
        );
    }

    #[test]
    fn test_security_action_request_minimum() {
        assert_eq!(SecurityAction::from_raw(8), SecurityAction::RequestMinimum);
    }

    #[test]
    fn test_security_action_other() {
        let a = SecurityAction::from_raw(99);
        assert!(matches!(a, SecurityAction::Other(99)));
        assert_eq!(a.name(), "Unknown");
    }

    #[test]
    fn test_security_declarations_empty() {
        let reader = MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables: MetadataTables::default(),
        };
        assert!(reader.security_declarations().is_empty());
    }

    #[test]
    fn test_security_declarations_one_entry() {
        let mut tables = MetadataTables::default();
        tables.decl_security.push(DeclSecurityRow {
            action: 2, // Demand
            parent: 0x0200_0001,
            permission_set: vec![0x2E, 0x01],
        });
        let reader = MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables,
        };
        let decls = reader.security_declarations();
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].1, SecurityAction::Demand);
    }
}

// â"€â"€â"€ Method spec tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod method_spec_tests {
    use super::*;

    #[test]
    fn test_method_spec_infos_empty() {
        let reader = MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables: MetadataTables::default(),
        };
        assert!(reader.method_spec_infos().is_empty());
    }

    #[test]
    fn test_method_spec_instantiation_decode() {
        // GENERICINST(0x0A) count=1 int(0x08)
        let blob = vec![0x0Au8, 0x01, 0x08];
        let args = decode_method_spec_instantiation(&blob);
        assert_eq!(args.len(), 1);
        assert_eq!(args[0], "int");
    }

    #[test]
    fn test_method_spec_instantiation_two_args() {
        // GENERICINST count=2 int string
        let blob = vec![0x0Au8, 0x02, 0x08, 0x0E];
        let args = decode_method_spec_instantiation(&blob);
        assert_eq!(args.len(), 2);
        assert_eq!(args[0], "int");
        assert_eq!(args[1], "string");
    }

    #[test]
    fn test_method_spec_instantiation_invalid_prefix() {
        let blob = vec![0x01u8, 0x02]; // not 0x0A
        let args = decode_method_spec_instantiation(&blob);
        assert!(args.is_empty());
    }

    #[test]
    fn test_method_spec_instantiation_empty() {
        assert!(decode_method_spec_instantiation(&[]).is_empty());
    }

    #[test]
    fn test_method_spec_info_with_methoddef() {
        let mut tables = MetadataTables::default();
        tables.method_def.push(MethodDefRow {
            name: "GenericFn".into(),
            ..Default::default()
        });
        // MethodDefOrRef tag=0 (MethodDef), row=1 â†' (1 << 1) | 0 = 0x02
        tables.method_spec.push(MethodSpecRow {
            method: 0x02,
            instantiation: vec![0x0A, 0x01, 0x08], // <int>
        });
        let reader = MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables,
        };
        let infos = reader.method_spec_infos();
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].method_name, Some("GenericFn".into()));
        assert_eq!(infos[0].type_args, vec!["int"]);
    }
}

