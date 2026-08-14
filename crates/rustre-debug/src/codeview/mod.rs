//! `rustre-symbols-codeview` — `CodeView` debug format parser.
//!
//! Full support for `CodeView` 4.0/7.0 symbol records (`S_PUB32`, `S_LPROC32`, `S_GPROC32`,
//! `S_GDATA32`, `S_LDATA32`, `S_LOCAL`, `S_REGREL32`, `S_COMPILE3`, `S_LABEL32`, `S_THUNK32`),
//! type records (`LF_CLASS`, `LF_STRUCTURE`, `LF_ENUM`, `LF_PROCEDURE`, `LF_POINTER`,
//! `LF_ARRAY`, `LF_MODIFIER`, `LF_BITFIELD`, `LF_UNION`, `LF_ARGLIST`, `LF_FIELDLIST`,
//! `LF_MEMBER`, `LF_ENUMERATE`), PDB 7.0 stream layout parsing, CV8 line-number
//! tables, source-file name tables, and a full [`SymbolProvider`] implementation.
#![warn(missing_docs)]

pub mod casts;
pub mod codeview_parser;
pub mod cv_function_info;
pub mod cv_lineinfo;
pub mod cv_stream_parser;
pub mod cv_symbol_records;
pub mod cv_symbols;
pub mod cv_type_records;
pub mod cv_types;
pub mod codeview_type_parser;
pub mod codeview_symbol_parser;
pub mod msf_reader;
pub mod pdb_tpi_reader;
pub mod codeview_types;

use rustre_symbols::{SourceLocation, StructField, TypeInfo};
// `pub use` so downstream crates (e.g. the MCP `debug.resolve_symbol` /
// `debug.load_symbols` tools) can name these via `rustre_debug::codeview::…`
// without a direct `rustre_symbols` dependency. They stay in scope here under
// their original names, so existing uses are unaffected.
pub use rustre_symbols::{SymKind, Symbol, SymbolProvider};

// Re-exported so callers can name the architecture without reaching into the
// record module: `pe_arch` returns it.
pub use cv_symbol_records::CvArch;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors produced by the `CodeView` parser.
#[derive(Debug, Error)]
pub enum CodeViewError {
    /// The four-byte file signature was not recognised.
    #[error("invalid signature: {0:#x}")]
    InvalidSignature(u32),
    /// The `CodeView` version is not supported.
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u32),
    /// A record header extends beyond the end of the buffer.
    #[error("record too short")]
    RecordTooShort,
    /// The stream was truncated or does not contain enough bytes.
    #[error("truncated stream")]
    TruncatedStream,
    /// The record is invalid or malformed.
    #[error("invalid record")]
    InvalidRecord,
    /// A type index is out of range.
    #[error("type index out of range: {0}")]
    TypeIndexOob(u32),
    /// A string offset is out of range.
    #[error("string offset out of range: {0}")]
    StringOffsetOob(u32),
    /// A generic parse error with a human-readable description.
    #[error("parse: {0}")]
    Parse(String),
}

// ---------------------------------------------------------------------------
// CvSignature
// ---------------------------------------------------------------------------

/// Known `CodeView` signature tags found at the start of the debug stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CvSignature {
    /// NB09 — `CodeView` 4.1
    Cv41,
    /// NB10 — `CodeView` 5.0
    Cv50,
    /// NB11 — `CodeView` 7.0
    Cv70,
    /// RSDS / PDB 7.0
    Pdb70,
    /// CV8 — used in PE .debug$S sections
    Cv8,
}

impl CvSignature {
    /// Parse a signature from the first four bytes of a buffer, returning `None` if unknown.
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 4 {
            return None;
        }
        match &b[0..4] {
            b"NB09" => Some(Self::Cv41),
            b"NB10" => Some(Self::Cv50),
            b"NB11" => Some(Self::Cv70),
            b"Micr" => Some(Self::Pdb70),
            _ if b[0..4] == [4, 0, 0, 0] => Some(Self::Cv8),
            _ => None,
        }
    }

    /// Returns a human-readable name for the signature.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Cv41 => "NB09 (CV 4.1)",
            Self::Cv50 => "NB10 (CV 5.0)",
            Self::Cv70 => "NB11 (CV 7.0)",
            Self::Pdb70 => "RSDS (PDB 7.0)",
            Self::Cv8 => "CV8",
        }
    }
}

impl fmt::Display for CvSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ---------------------------------------------------------------------------
// CvSymKind
// ---------------------------------------------------------------------------

/// `CodeView` symbol record type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum CvSymKind {
    /// Public symbol (32-bit) — `S_PUB32`.
    Pub32 = 0x1009,
    /// Global procedure start (32-bit) — `S_GPROC32`.
    GProc32 = 0x1110,
    /// Local procedure start (32-bit) — `S_LPROC32`.
    LProc32 = 0x110F,
    /// Register-relative symbol (32-bit) — `S_REGREL32`.
    RegRel32 = 0x1111,
    /// Global data symbol (32-bit) — `S_GDATA32`.
    GData32 = 0x110D,
    /// Local data symbol (32-bit) — `S_LDATA32`.
    LData32 = 0x110C,
    /// Code label (32-bit) — `S_LABEL32`.
    Label32 = 0x1105,
    /// Thunk start (32-bit) — `S_THUNK32`.
    Thunk32 = 0x1102,
    /// Block start (32-bit) — `S_BLOCK32`.
    Block32 = 0x1103,
    /// End of block / scope — `S_END`.
    End = 0x0006,
    /// Local variable — `S_LOCAL`.
    Local = 0x113E,
    /// Compilation unit info (version 3) — `S_COMPILE3`.
    Compile3 = 0x113C,
    /// Inline site start — `S_INLINESITE`.
    InlineSite = 0x114D,
    /// Inline site end — `S_INLINESITE_END`.
    InlineSiteEnd = 0x114E,
    /// Anything else.
    Unknown = 0xFFFF,
}

impl CvSymKind {
    /// Convert a raw `u16` record-type tag to a `CvSymKind`.
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            0x1009 => Self::Pub32,
            0x1110 => Self::GProc32,
            0x110F => Self::LProc32,
            0x1111 => Self::RegRel32,
            0x110D => Self::GData32,
            0x110C => Self::LData32,
            0x1105 => Self::Label32,
            0x1102 => Self::Thunk32,
            0x1103 => Self::Block32,
            0x0006 => Self::End,
            0x113E => Self::Local,
            0x113C => Self::Compile3,
            0x114D => Self::InlineSite,
            0x114E => Self::InlineSiteEnd,
            _ => Self::Unknown,
        }
    }

    /// Returns `true` if this record contains a name and an address.
    #[must_use]
    pub const fn is_named_address(&self) -> bool {
        matches!(
            self,
            Self::GProc32
                | Self::LProc32
                | Self::Pub32
                | Self::GData32
                | Self::LData32
                | Self::Label32
                | Self::Thunk32
        )
    }

    /// Returns `true` if this is a function-like record.
    #[must_use]
    pub const fn is_function(&self) -> bool {
        matches!(self, Self::GProc32 | Self::LProc32 | Self::Thunk32)
    }

    /// Returns `true` if this is a data-like record.
    #[must_use]
    pub const fn is_data(&self) -> bool {
        matches!(
            self,
            Self::GData32 | Self::LData32 | Self::Pub32 | Self::Label32
        )
    }
}

impl fmt::Display for CvSymKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ---------------------------------------------------------------------------
// CvTypeKind
// ---------------------------------------------------------------------------

/// `CodeView` type record leaf type codes (TPI stream).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum CvTypeKind {
    /// `LF_MODIFIER` — type modifier (const/volatile).
    Modifier = 0x1001,
    /// `LF_POINTER` — pointer type.
    Pointer = 0x1002,
    /// `LF_ARRAY` — array type.
    Array = 0x1003,
    /// `LF_CLASS` — class type.
    Class = 0x1004,
    /// `LF_STRUCTURE` — struct type.
    Structure = 0x1005,
    /// `LF_UNION` — union type.
    Union = 0x1006,
    /// `LF_ENUM` — enum type.
    Enum = 0x1007,
    /// `LF_PROCEDURE` — procedure (function) type.
    Procedure = 0x1008,
    /// `LF_MFUNCTION` — member function.
    MFunction = 0x1009,
    /// `LF_ARGLIST` — argument list.
    Arglist = 0x1201,
    /// `LF_FIELDLIST` — field descriptor list.
    FieldList = 0x1203,
    /// `LF_BITFIELD` — bit-field member.
    Bitfield = 0x1205,
    /// `LF_MEMBER` — struct/class/union member (leaf).
    Member = 0x150D,
    /// `LF_ENUMERATE` — enum member (leaf).
    Enumerate = 0x1502,
    /// Anything else.
    Unknown = 0xFFFF,
}

impl CvTypeKind {
    /// Convert a raw `u16` to a `CvTypeKind`.
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            0x1001 => Self::Modifier,
            0x1002 => Self::Pointer,
            0x1003 => Self::Array,
            0x1004 => Self::Class,
            0x1005 => Self::Structure,
            0x1006 => Self::Union,
            0x1007 => Self::Enum,
            0x1008 => Self::Procedure,
            0x1009 => Self::MFunction,
            0x1201 => Self::Arglist,
            0x1203 => Self::FieldList,
            0x1205 => Self::Bitfield,
            0x150D => Self::Member,
            0x1502 => Self::Enumerate,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for CvTypeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ---------------------------------------------------------------------------
// CvSymbol
// ---------------------------------------------------------------------------

/// A single parsed `CodeView` symbol record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvSymbol {
    /// Record type.
    pub kind: CvSymKind,
    /// Section-relative offset.
    pub offset: u32,
    /// Section index.
    pub segment: u16,
    /// Symbol name.
    pub name: String,
    /// Type-info index (into the TPI stream).
    pub type_index: u32,
    /// Raw flags (meaning depends on record kind).
    pub flags: u32,
}

impl CvSymbol {
    /// Returns `true` if the record represents a function.
    #[must_use]
    pub const fn is_function(&self) -> bool {
        self.kind.is_function()
    }

    /// Returns `true` if the record represents a data item.
    #[must_use]
    pub const fn is_data(&self) -> bool {
        self.kind.is_data()
    }
}

impl fmt::Display for CvSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} seg:{} off:{:#x} ti:{:#x} '{}'",
            self.kind, self.segment, self.offset, self.type_index, self.name
        )
    }
}

// ---------------------------------------------------------------------------
// CvTypeRecord
// ---------------------------------------------------------------------------

/// A parsed `CodeView` type record (from the TPI stream).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvTypeRecord {
    /// Record type.
    pub kind: CvTypeKind,
    /// 1-based type index assigned during parsing.
    pub index: u32,
    /// Reconstructed name (for class, struct, union, enum).
    pub name: String,
    /// Size in bytes (for class, struct, union; 0 if unknown).
    pub size: u32,
    /// Element count (enum variants count or array length).
    pub count: u32,
    /// Underlying type index (for pointer target, enum base type, etc.).
    pub underlying_type: u32,
    /// For procedure types: return type index.
    pub return_type: u32,
    /// For procedure types: argument type indices.
    pub arg_types: Vec<u32>,
}

impl CvTypeRecord {
    /// Returns `true` if this is an aggregate (class, struct, union).
    #[must_use]
    pub const fn is_aggregate(&self) -> bool {
        matches!(
            self.kind,
            CvTypeKind::Class | CvTypeKind::Structure | CvTypeKind::Union
        )
    }

    /// Returns `true` if this is callable (procedure/member function).
    #[must_use]
    pub const fn is_callable(&self) -> bool {
        matches!(self.kind, CvTypeKind::Procedure | CvTypeKind::MFunction)
    }
}

impl fmt::Display for CvTypeRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}] '{}' size={}",
            self.kind, self.index, self.name, self.size
        )
    }
}

// ---------------------------------------------------------------------------
// CvLineEntry / CvSourceFile
// ---------------------------------------------------------------------------

/// A line-number entry from a `CodeView` CV8 line-number subsection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvLineEntry {
    /// Offset from the start of the function/section.
    pub offset: u32,
    /// One-based line number.
    pub line_start: u32,
    /// Whether this is a statement boundary.
    pub is_statement: bool,
}

impl fmt::Display for CvLineEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "off:{:#x} line:{}", self.offset, self.line_start)
    }
}

/// A source-file record from the file-checksum subsection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvSourceFile {
    /// Offset into the string table.
    pub name_offset: u32,
    /// File name resolved from the string table.
    pub name: String,
    /// MD5 checksum (16 bytes), if present.
    pub checksum: Vec<u8>,
}

impl fmt::Display for CvSourceFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "'{}'", self.name)
    }
}

// ---------------------------------------------------------------------------
// CV8 subsection types
// ---------------------------------------------------------------------------

/// CV8 subsection type codes (used in PE `.debug$S` sections).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Cv8SubsectionKind {
    /// Symbol data (F1).
    Symbols = 0xF1,
    /// Line-number data (F2).
    Lines = 0xF2,
    /// String table (F3).
    StringTable = 0xF3,
    /// File checksum table (F4).
    FileChecksums = 0xF4,
    /// Frame data (F5).
    FrameData = 0xF5,
    /// Inlined-function data (F6).
    InlineeLines = 0xF6,
    /// Cross-scope imports (F7).
    CrossScopeImports = 0xF7,
    /// Cross-scope exports (F8).
    CrossScopeExports = 0xF8,
    /// Unknown.
    Unknown(u32),
}

impl Cv8SubsectionKind {
    /// Decode from a raw `u32` tag.
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0xF1 => Self::Symbols,
            0xF2 => Self::Lines,
            0xF3 => Self::StringTable,
            0xF4 => Self::FileChecksums,
            0xF5 => Self::FrameData,
            0xF6 => Self::InlineeLines,
            0xF7 => Self::CrossScopeImports,
            0xF8 => Self::CrossScopeExports,
            other => Self::Unknown(other),
        }
    }
}

// ---------------------------------------------------------------------------
// parse_cv_symbols
// ---------------------------------------------------------------------------

/// Parse all `CodeView` symbol records from a raw byte slice.
///
/// The buffer is expected to be the raw content of the `CodeView` symbol stream
/// (i.e. the bytes immediately after the stream header have been stripped).
///
/// # Errors
///
/// Returns [`CodeViewError::RecordTooShort`] when a record claims a length that
/// extends beyond the end of the buffer.
pub fn parse_cv_symbols(data: &[u8]) -> Result<Vec<CvSymbol>, CodeViewError> {
    let mut symbols = vec![];
    let mut offset = 0usize;

    while offset + 4 <= data.len() {
        let len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        let kind_raw = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);
        let kind = CvSymKind::from_u16(kind_raw);

        if len < 2 {
            break;
        }

        let record_end = offset + 2 + len;
        if record_end > data.len() {
            return Err(CodeViewError::RecordTooShort);
        }

        let record_data = &data[offset + 4..record_end];
        parse_one_symbol(kind, record_data, &mut symbols);
        offset = record_end;
    }

    Ok(symbols)
}

fn read_null_str(data: &[u8], from: usize) -> String {
    if from >= data.len() {
        return String::new();
    }
    String::from_utf8_lossy(data[from..].split(|&b| b == 0).next().unwrap_or(&[])).to_string()
}

pub(crate) fn read_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
}

pub(crate) fn read_u16(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[off], data[off + 1]])
}

fn parse_one_symbol(kind: CvSymKind, data: &[u8], out: &mut Vec<CvSymbol>) {
    match kind {
        // S_GPROC32 / S_LPROC32:
        // [type_index:u32][parent:u32][end:u32][next:u32][proc_len:u32]
        // [debug_start:u32][debug_end:u32][offset:u32][seg:u16][flags:u8][name\0]
        CvSymKind::GProc32 | CvSymKind::LProc32 => {
            if data.len() < 35 {
                return;
            }
            let type_index = read_u32(data, 0);
            let offset = read_u32(data, 28);
            let seg = read_u16(data, 32);
            let _flags = data.get(34).copied().unwrap_or(0);
            let name = read_null_str(data, 35);
            out.push(CvSymbol {
                kind,
                offset,
                segment: seg,
                name,
                type_index,
                flags: 0,
            });
        }
        // S_PUB32:
        // [flags:u32][offset:u32][seg:u16][name\0]
        CvSymKind::Pub32 => {
            if data.len() < 8 {
                return;
            }
            let flags = read_u32(data, 0);
            let offset = read_u32(data, 4);
            let seg = read_u16(data, 8);
            let name = read_null_str(data, 10);
            out.push(CvSymbol {
                kind,
                offset,
                segment: seg,
                name,
                type_index: 0,
                flags,
            });
        }
        // S_GDATA32 / S_LDATA32:
        // [type_index:u32][offset:u32][seg:u16][name\0]
        CvSymKind::GData32 | CvSymKind::LData32 => {
            if data.len() < 8 {
                return;
            }
            let type_index = read_u32(data, 0);
            let offset = read_u32(data, 4);
            let seg = read_u16(data, 8);
            let name = read_null_str(data, 10);
            out.push(CvSymbol {
                kind,
                offset,
                segment: seg,
                name,
                type_index,
                flags: 0,
            });
        }
        // S_LABEL32:
        // [offset:u32][seg:u16][flags:u8][name\0]
        CvSymKind::Label32 => {
            if data.len() < 6 {
                return;
            }
            let offset = read_u32(data, 0);
            let seg = read_u16(data, 4);
            let name = read_null_str(data, 7);
            out.push(CvSymbol {
                kind,
                offset,
                segment: seg,
                name,
                type_index: 0,
                flags: 0,
            });
        }
        // S_THUNK32:
        // [parent:u32][end:u32][next:u32][offset:u32][seg:u16][thunk_len:u16][ord:u8][name\0]
        CvSymKind::Thunk32 => {
            if data.len() < 21 {
                return;
            }
            let offset = read_u32(data, 12);
            let seg = read_u16(data, 16);
            let name = read_null_str(data, 21);
            out.push(CvSymbol {
                kind,
                offset,
                segment: seg,
                name,
                type_index: 0,
                flags: 0,
            });
        }
        _ => {} // S_END, S_BLOCK32, S_COMPILE3, etc. are silently skipped
    }
}

// ---------------------------------------------------------------------------
// parse_cv_type_records
// ---------------------------------------------------------------------------

/// Parse `CodeView` type records from a TPI (Type Info) stream.
///
/// The TPI stream begins with an 8-byte header (skipped here); this function
/// expects the raw record bytes starting immediately after the header.
///
/// # Errors
///
/// Returns [`CodeViewError::RecordTooShort`] if a record extends beyond the buffer.
pub fn parse_cv_type_records(data: &[u8]) -> Result<Vec<CvTypeRecord>, CodeViewError> {
    let mut records = vec![];
    let mut offset = 0usize;
    let mut index: u32 = 0x1000; // TPI types start at 0x1000

    while offset + 4 <= data.len() {
        let len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        if len < 2 {
            break;
        }
        let record_end = offset + 2 + len;
        if record_end > data.len() {
            return Err(CodeViewError::RecordTooShort);
        }

        let leaf = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);
        let kind = CvTypeKind::from_u16(leaf);
        let body = &data[offset + 4..record_end];

        let rec = parse_one_type(kind, body, index);
        records.push(rec);
        index += 1;
        offset = record_end;
    }

    Ok(records)
}

fn parse_one_type(kind: CvTypeKind, data: &[u8], index: u32) -> CvTypeRecord {
    match kind {
        // LF_STRUCTURE / LF_CLASS / LF_UNION:
        // [count:u16][property:u16][field_list:u32][derived:u32][vshape:u32][size:u16/u32][name\0]
        CvTypeKind::Structure | CvTypeKind::Class | CvTypeKind::Union => {
            // Layout: count:u16 @0, property:u16 @2, field_list:u32 @4,
            // derived:u32 @8, vshape:u32 @12, size:u16 @16, name\0 @18.
            let count = u32::from(read_u16(data, 0));
            let size = if data.len() >= 18 {
                u32::from(read_u16(data, 16))
            } else {
                0
            };
            let name = read_null_str(data, 18);
            CvTypeRecord {
                kind,
                index,
                name,
                size,
                count,
                underlying_type: 0,
                return_type: 0,
                arg_types: vec![],
            }
        }
        // LF_ENUM:
        // [count:u16][prop:u16][utype:u32][field_list:u32][name\0]
        CvTypeKind::Enum => {
            let count = u32::from(read_u16(data, 0));
            let underlying = read_u32(data, 4);
            let name = read_null_str(data, 12);
            CvTypeRecord {
                kind,
                index,
                name,
                size: 0,
                count,
                underlying_type: underlying,
                return_type: 0,
                arg_types: vec![],
            }
        }
        // LF_PROCEDURE:
        // [return_type:u32][call_type:u8][func_attr:u8][param_count:u16][arg_list:u32]
        CvTypeKind::Procedure => {
            let ret = read_u32(data, 0);
            let count = u32::from(read_u16(data, 6));
            let arglist = read_u32(data, 8);
            CvTypeRecord {
                kind,
                index,
                name: String::new(),
                size: 0,
                count,
                underlying_type: arglist,
                return_type: ret,
                arg_types: vec![],
            }
        }
        // LF_POINTER:
        // [type_index:u32][attributes:u32]
        CvTypeKind::Pointer => {
            let target = read_u32(data, 0);
            CvTypeRecord {
                kind,
                index,
                name: String::new(),
                size: if data.len() >= 8 {
                    let attr = read_u32(data, 4);
                    // pointer size: bits 13..16 of attributes (0=near32=4, 4=64bit=8)
                    let ptr_mode = (attr >> 5) & 0x7;
                    if ptr_mode == 4 { 8 } else { 4 }
                } else {
                    4
                },
                count: 0,
                underlying_type: target,
                return_type: 0,
                arg_types: vec![],
            }
        }
        // LF_ARRAY:
        // [element_type:u32][index_type:u32][size: numeric leaf][name\0]
        CvTypeKind::Array => {
            let elem_type = read_u32(data, 0);
            let size = parse_numeric_leaf(data, 8)
                .map_or(0, |(v, _)| u32::try_from(v).unwrap_or(u32::MAX));
            CvTypeRecord {
                kind,
                index,
                name: String::new(),
                size,
                count: 0,
                underlying_type: elem_type,
                return_type: 0,
                arg_types: vec![],
            }
        }
        _ => CvTypeRecord {
            kind,
            index,
            name: String::new(),
            size: 0,
            count: 0,
            underlying_type: 0,
            return_type: 0,
            arg_types: vec![],
        },
    }
}

// ---------------------------------------------------------------------------
// CvTypeTable
// ---------------------------------------------------------------------------

/// A table of parsed `CodeView` type records indexed by their TPI index.
#[derive(Debug, Default)]
pub struct CvTypeTable {
    records: Vec<CvTypeRecord>,
    index_map: HashMap<u32, usize>,
}

impl CvTypeTable {
    /// Create an empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from a slice of parsed records.
    #[must_use]
    pub fn from_records(records: Vec<CvTypeRecord>) -> Self {
        let mut index_map = HashMap::new();
        for (pos, rec) in records.iter().enumerate() {
            index_map.insert(rec.index, pos);
        }
        Self { records, index_map }
    }

    /// Parse and build from a TPI stream byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`CodeViewError`] if parsing fails.
    pub fn from_bytes(data: &[u8]) -> Result<Self, CodeViewError> {
        let records = parse_cv_type_records(data)?;
        Ok(Self::from_records(records))
    }

    /// Look up a record by TPI index.
    #[must_use]
    pub fn lookup(&self, index: u32) -> Option<&CvTypeRecord> {
        self.index_map
            .get(&index)
            .and_then(|&pos| self.records.get(pos))
    }

    /// All records.
    #[must_use]
    pub fn records(&self) -> &[CvTypeRecord] {
        &self.records
    }

    /// Number of records.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Reconstruct a [`TypeInfo`] from a TPI type index.
    ///
    /// Unknown or unresolvable types become [`TypeInfo::Unknown`].
    #[must_use]
    pub fn to_type_info(&self, index: u32) -> TypeInfo {
        // Primitive types (index < 0x1000) are encoded directly.
        if index < 0x1000 {
            return primitive_type(index);
        }
        let Some(rec) = self.lookup(index) else {
            return TypeInfo::Unknown;
        };
        match rec.kind {
                CvTypeKind::Pointer => TypeInfo::Pointer {
                    target: Box::new(self.to_type_info(rec.underlying_type)),
                    size: u8::try_from(rec.size).unwrap_or(u8::MAX),
                },
                CvTypeKind::Structure | CvTypeKind::Class | CvTypeKind::Union => {
                    // Reconstruct one StructField per member reported by the TPI
                    // record. The TPI summary record only carries the member count
                    // and aggregate size; LF_FIELDLIST data is required for
                    // accurate per-member offsets and types.
                    //
                    // WARNING: lossy approximation. This fallback is only valid
                    // when LF_FIELDLIST data is not available. The stride is
                    // computed via integer division (`size / member_count`),
                    // which truncates: for a 10-byte struct with 3 members the
                    // stride is 3 and offsets become 0, 3, 6 — the trailing
                    // byte(s) are not covered and every offset past the first
                    // is wrong whenever size is not an exact multiple of
                    // member_count. The generated field types are always
                    // `TypeInfo::Unknown`. Callers consuming these offsets for
                    // display or analysis MUST treat them as best-effort
                    // placeholders and prefer the LF_FIELDLIST parser, which
                    // supersedes this reconstruction once field-list data is
                    // resolved.
                    let member_count = rec.count;
                    let stride = rec.size.checked_div(member_count).unwrap_or(0);
                    let fields: Vec<StructField> = (0..member_count)
                        .map(|i| StructField {
                            name: format!("field_{i}"),
                            offset: i * stride,
                            type_info: TypeInfo::Unknown,
                        })
                        .collect();
                    TypeInfo::Struct {
                        name: rec.name.clone(),
                        fields,
                    }
                }
                CvTypeKind::Enum => TypeInfo::Enum {
                    name: rec.name.clone(),
                    variants: vec![],
                    base_type: Box::new(self.to_type_info(rec.underlying_type)),
                },
                CvTypeKind::Array => TypeInfo::Array {
                    element: Box::new(self.to_type_info(rec.underlying_type)),
                    count: u64::from(rec.count),
                },
                _ => TypeInfo::Unknown,
        }
    }
}

/// Map a `CodeView` primitive type index to a [`TypeInfo`].
#[must_use]
pub fn primitive_type(index: u32) -> TypeInfo {
    // Mode bits: [7:4] pointer mode. [3:0] basic type.
    let mode = (index >> 8) & 0x7;
    let base_type = index & 0xFF;
    if mode != 0 {
        // Pointer to something
        let inner = primitive_type(base_type);
        return TypeInfo::Pointer {
            target: Box::new(inner),
            size: if mode == 4 { 8 } else { 4 },
        };
    }
    match base_type {
        0x00 => TypeInfo::Void,
        0x10 | 0x68 => TypeInfo::Int {
            width: 8,
            signed: true,
        },
        0x20 | 0x69 => TypeInfo::Int {
            width: 8,
            signed: false,
        },
        0x11 | 0x70 | 0x72 => TypeInfo::Int {
            width: 16,
            signed: true,
        },
        0x21 | 0x71 | 0x73 => TypeInfo::Int {
            width: 16,
            signed: false,
        },
        0x12 | 0x74 => TypeInfo::Int {
            width: 32,
            signed: true,
        },
        0x22 | 0x75 => TypeInfo::Int {
            width: 32,
            signed: false,
        },
        0x13 | 0x76 => TypeInfo::Int {
            width: 64,
            signed: true,
        },
        0x23 | 0x77 => TypeInfo::Int {
            width: 64,
            signed: false,
        },
        0x14 => TypeInfo::Int {
            width: 128,
            signed: true,
        },
        0x24 => TypeInfo::Int {
            width: 128,
            signed: false,
        },
        0x40 => TypeInfo::Float { width: 32 },
        0x41 => TypeInfo::Float { width: 64 },
        0x42 => TypeInfo::Float { width: 80 },
        0x43 => TypeInfo::Float { width: 128 },
        0x30 => TypeInfo::Bool,
        _ => TypeInfo::Unknown,
    }
}

// ---------------------------------------------------------------------------
// CV8 Line-number subsection parser
// ---------------------------------------------------------------------------

/// A single CV8 line-number block (covers one source file in one function).
#[derive(Debug, Clone)]
pub struct Cv8LineBlock {
    /// Section offset at which this function starts.
    pub code_offset: u32,
    /// Section index.
    pub segment: u16,
    /// Code byte length of the function.
    pub code_len: u32,
    /// Index into the file checksum table.
    pub file_index: u32,
    /// Line entries.
    pub lines: Vec<CvLineEntry>,
}

/// Parse a CV8 `DEBUG_S_LINES` (0xF2) subsection.
///
/// # Errors
///
/// Returns [`CodeViewError::RecordTooShort`] if the buffer is truncated.
pub fn parse_cv8_lines(data: &[u8]) -> Result<Vec<Cv8LineBlock>, CodeViewError> {
    if data.len() < 12 {
        return Ok(vec![]);
    }
    let code_offset = read_u32(data, 0);
    let segment = read_u16(data, 4);
    let _flags = read_u16(data, 6);
    let code_len = read_u32(data, 8);

    let mut blocks = vec![];
    let mut pos = 12usize;

    while pos + 12 <= data.len() {
        let file_index = read_u32(data, pos);
        let num_lines = read_u32(data, pos + 4) as usize;
        let block_size = read_u32(data, pos + 8) as usize;
        pos += 12;

        // Guard against num_lines overflow and out-of-bounds access.
        let line_bytes = num_lines.checked_mul(8).ok_or(CodeViewError::RecordTooShort)?;
        if pos.checked_add(line_bytes).is_none_or(|end| end > data.len()) {
            return Err(CodeViewError::RecordTooShort);
        }

        let mut lines = Vec::with_capacity(num_lines.min(65536));
        for i in 0..num_lines {
            let off = pos + i * 8; // safe: bounds already checked above
            let line_off = read_u32(data, off);
            let line_num_raw = read_u32(data, off + 4);
            let line_start = line_num_raw & 0x7FFF_FFFF;
            let is_statement = (line_num_raw & 0x8000_0000) == 0;
            lines.push(CvLineEntry {
                offset: line_off,
                line_start,
                is_statement,
            });
        }

        blocks.push(Cv8LineBlock {
            code_offset,
            segment,
            code_len,
            file_index,
            lines,
        });
        // Advance pos past line entries already consumed, then skip any
        // trailing column data as indicated by block_size.  If a malformed
        // record reports a block_size smaller than the data we already read,
        // clamp so pos never goes backwards.
        pos += line_bytes;
        let already_read = 12usize.saturating_add(line_bytes);
        if block_size > already_read {
            pos = pos.saturating_add(block_size - already_read);
        }
    }

    Ok(blocks)
}

// ---------------------------------------------------------------------------
// CvStringTable
// ---------------------------------------------------------------------------

/// A `CodeView` string table (used in CV8 `DEBUG_S_STRINGTABLE` subsections).
#[derive(Debug, Default, Clone)]
pub struct CvStringTable {
    data: Vec<u8>,
}

impl CvStringTable {
    /// Build from raw bytes (the subsection payload).
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }

    /// Look up a null-terminated string at `offset`.
    #[must_use]
    pub fn get(&self, offset: u32) -> &str {
        let off = offset as usize;
        if off >= self.data.len() {
            return "";
        }
        let end = self.data[off..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.data.len() - off);
        std::str::from_utf8(&self.data[off..off + end]).unwrap_or("")
    }

    /// Total byte length.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// ---------------------------------------------------------------------------
// CvDebugSection — full `.debug$S` / `.debug$T` parser
// ---------------------------------------------------------------------------

/// Result of parsing a full PE `.debug$S` debug section (CV8 format).
#[derive(Debug, Default)]
pub struct CvDebugSection {
    /// All symbol records parsed.
    pub symbols: Vec<CvSymbol>,
    /// All line-number blocks.
    pub line_blocks: Vec<Cv8LineBlock>,
    /// The string table (for resolving file names).
    pub string_table: CvStringTable,
    /// Source file checksums.
    pub source_files: Vec<CvSourceFile>,
}

impl CvDebugSection {
    /// Parse a raw `.debug$S` section.
    ///
    /// The first 4 bytes are the CV8 version tag (0x000000004).
    ///
    /// # Errors
    ///
    /// Returns [`CodeViewError`] if parsing fails.
    pub fn parse(data: &[u8]) -> Result<Self, CodeViewError> {
        if data.len() < 4 {
            return Ok(Self::default());
        }
        let version = read_u32(data, 0);
        if version != 4 {
            return Err(CodeViewError::UnsupportedVersion(version));
        }

        let mut result = Self::default();
        let mut pos = 4usize;

        while pos + 8 <= data.len() {
            let subsection_type = read_u32(data, pos);
            let subsection_len = read_u32(data, pos + 4) as usize;
            pos += 8;

            let end = pos + subsection_len;
            if end > data.len() {
                return Err(CodeViewError::RecordTooShort);
            }

            let payload = &data[pos..end];
            match Cv8SubsectionKind::from_u32(subsection_type) {
                Cv8SubsectionKind::Symbols => {
                    let syms = parse_cv_symbols(payload)?;
                    result.symbols.extend(syms);
                }
                Cv8SubsectionKind::Lines => {
                    let blocks = parse_cv8_lines(payload)?;
                    result.line_blocks.extend(blocks);
                }
                Cv8SubsectionKind::StringTable => {
                    result.string_table = CvStringTable::from_bytes(payload);
                }
                Cv8SubsectionKind::FileChecksums => {
                    let files = parse_file_checksums(payload, &result.string_table);
                    result.source_files.extend(files);
                }
                _ => {}
            }

            // Subsections are 4-byte aligned.
            pos = end;
            let rem = pos % 4;
            if rem != 0 {
                pos += 4 - rem;
            }
        }

        Ok(result)
    }
}

fn parse_file_checksums(data: &[u8], strtab: &CvStringTable) -> Vec<CvSourceFile> {
    let mut files = vec![];
    let mut pos = 0usize;
    while pos + 8 <= data.len() {
        let name_offset = read_u32(data, pos);
        let checksum_len = data[pos + 4] as usize;
        let _ = data[pos + 5];
        let checksum = data[pos + 6..pos + 6 + checksum_len.min(data.len() - pos - 6)].to_vec();
        let name = strtab.get(name_offset).to_string();
        files.push(CvSourceFile {
            name_offset,
            name,
            checksum,
        });
        pos += 6 + checksum_len;
        let rem = pos % 4;
        if rem != 0 {
            pos += 4 - rem;
        }
    }
    files
}

// ---------------------------------------------------------------------------
// CodeViewProvider
// ---------------------------------------------------------------------------

/// A [`SymbolProvider`] that reads `CodeView` debug information.
#[derive(Debug)]
pub struct CodeViewProvider {
    symbols: Vec<Symbol>,
    raw_syms: Vec<CvSymbol>,
    type_table: CvTypeTable,
    source_map: Vec<(u64, SourceLocation)>,
}

impl CodeViewProvider {
    /// Build a provider by parsing `data` as a `CodeView` symbol stream.
    ///
    /// `image_base` is added to every section-relative offset to produce virtual addresses.
    ///
    /// # Errors
    ///
    /// Returns [`CodeViewError`] if `data` cannot be parsed.
    pub fn from_bytes(data: &[u8], image_base: u64) -> Result<Self, CodeViewError> {
        let raw_syms = parse_cv_symbols(data)?;
        let symbols = raw_syms
            .iter()
            .map(|cv| {
                let kind = if cv.kind.is_function() {
                    SymKind::Function
                } else {
                    SymKind::Data
                };
                Symbol::new(cv.name.clone(), image_base + u64::from(cv.offset), kind)
            })
            .collect();
        Ok(Self {
            symbols,
            raw_syms,
            type_table: CvTypeTable::new(),
            source_map: vec![],
        })
    }

    /// Build a provider from a complete CV8 `.debug$S` section.
    ///
    /// # Errors
    ///
    /// Returns [`CodeViewError`] if parsing fails.
    pub fn from_debug_section(data: &[u8], image_base: u64) -> Result<Self, CodeViewError> {
        let section = CvDebugSection::parse(data)?;
        let symbols = section
            .symbols
            .iter()
            .map(|cv| {
                let kind = if cv.kind.is_function() {
                    SymKind::Function
                } else {
                    SymKind::Data
                };
                Symbol::new(cv.name.clone(), image_base + u64::from(cv.offset), kind)
            })
            .collect();

        // Build source map from line blocks.
        let mut source_map = vec![];
        for block in &section.line_blocks {
            let file_name = section
                .source_files
                .get(block.file_index as usize)
                .map(|f| f.name.clone())
                .unwrap_or_default();
            for entry in &block.lines {
                let addr = image_base + u64::from(block.code_offset) + u64::from(entry.offset);
                source_map.push((
                    addr,
                    SourceLocation {
                        file: file_name.clone(),
                        line: entry.line_start,
                        column: 0,
                    },
                ));
            }
        }

        Ok(Self {
            symbols,
            raw_syms: section.symbols,
            type_table: CvTypeTable::new(),
            source_map,
        })
    }

    /// Attach a pre-parsed type table to this provider.
    #[must_use]
    pub fn with_type_table(mut self, table: CvTypeTable) -> Self {
        self.type_table = table;
        self
    }

    /// The parsed raw `CodeView` symbol records, before conversion to [`Symbol`].
    #[must_use]
    pub fn raw_symbols(&self) -> &[CvSymbol] {
        &self.raw_syms
    }

    /// The type table.
    #[must_use]
    pub const fn type_table(&self) -> &CvTypeTable {
        &self.type_table
    }

    /// Number of symbols.
    #[must_use]
    pub const fn symbol_count(&self) -> usize {
        self.symbols.len()
    }

    /// All function symbols.
    #[must_use]
    pub fn functions(&self) -> Vec<&Symbol> {
        self.symbols
            .iter()
            .filter(|s| s.kind == SymKind::Function)
            .collect()
    }

    /// All data symbols.
    #[must_use]
    pub fn data_symbols(&self) -> Vec<&Symbol> {
        self.symbols
            .iter()
            .filter(|s| s.kind == SymKind::Data)
            .collect()
    }

    /// Highest symbol address in the table, or `None` when it is empty.
    ///
    /// Cheap on purpose: frame symbolication needs to know whether a symbol has
    /// any successor (which bounds it from above) and must not clone the whole
    /// table once per stack frame to find out. See
    /// [`crate::symbol_resolver::FrameSymbolResolver`] for `CodeViewProvider`.
    #[must_use]
    pub fn highest_symbol_address(&self) -> Option<u64> {
        self.symbols.iter().map(|s| s.address).max()
    }

    /// Symbols sorted by address.
    #[must_use]
    pub fn symbols_sorted(&self) -> Vec<Symbol> {
        let mut v = self.symbols.clone();
        v.sort_by_key(|s| s.address);
        v
    }

    /// Find all symbols whose names start with `prefix`.
    #[must_use]
    pub fn symbols_with_prefix(&self, prefix: &str) -> Vec<Symbol> {
        self.symbols
            .iter()
            .filter(|s| s.name.starts_with(prefix))
            .cloned()
            .collect()
    }

    /// Resolve a type index to a [`TypeInfo`] using the attached type table.
    #[must_use]
    pub fn resolve_type(&self, index: u32) -> TypeInfo {
        self.type_table.to_type_info(index)
    }
}

impl SymbolProvider for CodeViewProvider {
    fn name(&self) -> &'static str {
        "codeview"
    }

    fn lookup_name(&self, name: &str) -> Option<Symbol> {
        self.symbols.iter().find(|s| s.name == name).cloned()
    }

    fn lookup_address(&self, addr: u64) -> Option<Symbol> {
        self.symbols.iter().find(|s| s.address == addr).cloned()
    }

    fn lookup_nearest(&self, addr: u64) -> Option<Symbol> {
        self.symbols
            .iter()
            .filter(|s| s.address <= addr)
            .min_by_key(|s| addr - s.address)
            .cloned()
    }

    fn all_symbols(&self) -> Vec<Symbol> {
        self.symbols.clone()
    }

    fn all_functions(&self) -> Vec<Symbol> {
        self.symbols
            .iter()
            .filter(|s| s.kind == SymKind::Function)
            .cloned()
            .collect()
    }

    fn source_line_for_address(&self, addr: u64) -> Option<SourceLocation> {
        self.source_map
            .iter()
            .filter(|(a, _)| *a <= addr)
            .min_by_key(|(a, _)| addr - a)
            .map(|(_, loc)| loc.clone())
    }
}

// ---------------------------------------------------------------------------
// CvSymbolFilter — utility for filtering/querying symbol sets
// ---------------------------------------------------------------------------

/// Helper for filtering sets of [`CvSymbol`] records.
#[derive(Debug, Default)]
pub struct CvSymbolFilter {
    symbols: Vec<CvSymbol>,
}

impl CvSymbolFilter {
    /// Create from a slice of symbols.
    #[must_use]
    pub const fn new(symbols: Vec<CvSymbol>) -> Self {
        Self { symbols }
    }

    /// Retain only symbols of the given kind.
    #[must_use]
    pub fn by_kind(mut self, kind: CvSymKind) -> Self {
        self.symbols.retain(|s| s.kind == kind);
        self
    }

    /// Retain only symbols whose names contain `substr`.
    #[must_use]
    pub fn name_contains(mut self, substr: &str) -> Self {
        self.symbols.retain(|s| s.name.contains(substr));
        self
    }

    /// Retain only symbols in the given section (segment index).
    #[must_use]
    pub fn in_segment(mut self, seg: u16) -> Self {
        self.symbols.retain(|s| s.segment == seg);
        self
    }

    /// Return the filtered symbols.
    #[must_use]
    pub fn into_symbols(self) -> Vec<CvSymbol> {
        self.symbols
    }

    /// Count of matching symbols.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.symbols.len()
    }
}

// ---------------------------------------------------------------------------
// Utility: build a minimal symbol stream for testing
// ---------------------------------------------------------------------------

/// Build a minimal `CodeView` symbol record byte stream containing one `S_GPROC32`.
///
/// Useful for unit testing without real PDB files.
#[must_use]
pub fn build_test_gproc32(name: &str, offset: u32, seg: u16, type_index: u32) -> Vec<u8> {
    // S_GPROC32 layout (record_data part):
    // [type_index:u32][parent:u32][end:u32][next:u32][proc_len:u32]
    // [debug_start:u32][debug_end:u32][offset:u32][seg:u16][flags:u8][name\0]
    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(&type_index.to_le_bytes()); // type_index @ 0
    payload.extend_from_slice(&0u32.to_le_bytes()); // parent @ 4
    payload.extend_from_slice(&0u32.to_le_bytes()); // end @ 8
    payload.extend_from_slice(&0u32.to_le_bytes()); // next @ 12
    payload.extend_from_slice(&0u32.to_le_bytes()); // proc_len @ 16
    payload.extend_from_slice(&0u32.to_le_bytes()); // debug_start @ 20
    payload.extend_from_slice(&0u32.to_le_bytes()); // debug_end @ 24
    payload.extend_from_slice(&offset.to_le_bytes()); // offset @ 28
    payload.extend_from_slice(&seg.to_le_bytes()); // seg @ 32
    payload.push(0u8); // flags @ 34
    payload.extend_from_slice(name.as_bytes()); // name @ 35
    payload.push(0);

    let kind: u16 = 0x1110;
    let len = u16::try_from(2 + payload.len()).unwrap_or(u16::MAX);
    let mut record = Vec::new();
    record.extend_from_slice(&len.to_le_bytes());
    record.extend_from_slice(&kind.to_le_bytes());
    record.extend_from_slice(&payload);
    record
}

/// Build a minimal `S_LPROC32` record.
#[must_use]
pub fn build_test_lproc32(name: &str, offset: u32) -> Vec<u8> {
    let mut payload: Vec<u8> = vec![0u8; 35]; // type+parent+end+next+len+dstart+dend+offset+seg+flags
    payload[28..32].copy_from_slice(&offset.to_le_bytes());
    payload.extend_from_slice(name.as_bytes());
    payload.push(0);
    let kind: u16 = 0x110F;
    let len = u16::try_from(2 + payload.len()).unwrap_or(u16::MAX);
    let mut record = Vec::new();
    record.extend_from_slice(&len.to_le_bytes());
    record.extend_from_slice(&kind.to_le_bytes());
    record.extend_from_slice(&payload);
    record
}

/// Build a minimal `S_PUB32` record.
#[must_use]
pub fn build_test_pub32(name: &str, offset: u32) -> Vec<u8> {
    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(&0u32.to_le_bytes()); // flags
    payload.extend_from_slice(&offset.to_le_bytes()); // offset
    payload.extend_from_slice(&1u16.to_le_bytes()); // seg
    payload.extend_from_slice(name.as_bytes());
    payload.push(0);
    let kind: u16 = 0x1009;
    let len = u16::try_from(2 + payload.len()).unwrap_or(u16::MAX);
    let mut record = Vec::new();
    record.extend_from_slice(&len.to_le_bytes());
    record.extend_from_slice(&kind.to_le_bytes());
    record.extend_from_slice(&payload);
    record
}

/// Build a minimal `S_GDATA32` record.
#[must_use]
pub fn build_test_gdata32(name: &str, offset: u32, type_index: u32) -> Vec<u8> {
    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(&type_index.to_le_bytes());
    payload.extend_from_slice(&offset.to_le_bytes());
    payload.extend_from_slice(&1u16.to_le_bytes()); // seg
    payload.extend_from_slice(name.as_bytes());
    payload.push(0);
    let kind: u16 = 0x110D;
    let len = u16::try_from(2 + payload.len()).unwrap_or(u16::MAX);
    let mut record = Vec::new();
    record.extend_from_slice(&len.to_le_bytes());
    record.extend_from_slice(&kind.to_le_bytes());
    record.extend_from_slice(&payload);
    record
}

// ---------------------------------------------------------------------------
// CodeViewMagic — alternative magic enum matching the spec constants
// ---------------------------------------------------------------------------

/// Alternative `CodeView` magic signatures as raw `u32` constants.
///
/// Each variant corresponds to the 4-byte tag found at offset 0 of the
/// respective debug stream / directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodeViewMagic {
    /// "NB09" — `CodeView` 4.1 (little-endian u32 = 0x3930424E)
    Cv41,
    /// "NB11" — `CodeView` 5.0 / 7.0 (little-endian u32 = 0x3131424E)
    Cv50,
    /// "RSDS" — PDB 7.0 (little-endian u32 = 0x53445352)
    Cv70,
}

impl CodeViewMagic {
    /// The raw `u32` tag value for `CodeView` 4.1 ("NB09").
    pub const CV41_TAG: u32 = 0x3930_424E; // "NB09"
    /// The raw `u32` tag value for `CodeView` 5.0/7.0 ("NB11").
    pub const CV50_TAG: u32 = 0x3131_424E; // "NB11"
    /// The raw `u32` tag value for PDB 7.0 ("RSDS").
    pub const CV70_TAG: u32 = 0x5344_5352; // "RSDS"

    /// Detect the magic from the first 4 bytes of `data`.
    ///
    /// Returns `None` if the bytes do not match any known signature.
    #[must_use]
    pub fn detect(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let tag = u32::from_le_bytes(data[..4].try_into().ok()?);
        match tag {
            Self::CV41_TAG => Some(Self::Cv41),
            Self::CV50_TAG => Some(Self::Cv50),
            Self::CV70_TAG => Some(Self::Cv70),
            _ => None,
        }
    }

    /// Human-readable label for the magic.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Cv41 => "NB09 (CodeView 4.1)",
            Self::Cv50 => "NB11 (CodeView 5.0)",
            Self::Cv70 => "RSDS (PDB 7.0)",
        }
    }
}

impl fmt::Display for CodeViewMagic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// CvSymbolKind — complete set of common S_* record type codes
// ---------------------------------------------------------------------------

/// Full set of common `CodeView` symbol record kind tags (`S_*`).
///
/// This enum complements the existing [`CvSymKind`] with additional record
/// kinds that appear in real PDB/CV streams (older low-numbered records,
/// `S_COMPILE3`, `S_FRAMEPROC`, `S_LOCAL`, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum CvSymbolKind {
    /// `S_COMPILE` — compilation unit info (legacy).
    SCompile = 0x0001,
    /// `S_END` — end of block / scope.
    SEnd = 0x0006,
    /// `S_ENDARG` — end of argument list.
    SEndarg = 0x000A,
    /// `S_OBJNAME` — object-file name.
    SObjname = 0x1101,
    /// `S_THUNK32` — thunk start (32-bit).
    SThunk32 = 0x1102,
    /// `S_BLOCK32` — block start (32-bit).
    SBlock32 = 0x1103,
    /// `S_LABEL32` — code label (32-bit).
    SLabel32 = 0x1105,
    /// `S_REGISTER` — register variable.
    SRegister = 0x1001,
    /// `S_CONSTANT` — constant symbol.
    SConstant = 0x1002,
    /// `S_UDT` — user-defined type alias.
    SUdt = 0x1008,
    /// `S_FRAMEPROC` — frame-procedure info.
    SFrameproc = 0x1012,
    /// `S_BPREL32` — BP-relative variable (32-bit).
    SBprel32 = 0x110B,
    /// `S_LDATA32` — local data (32-bit).
    SLdata32 = 0x110C,
    /// `S_GDATA32` — global data (32-bit).
    SGdata32 = 0x110D,
    /// `S_PUB32` — public symbol (32-bit).
    SPub32 = 0x110E,
    /// `S_LPROC32` — local procedure start (32-bit).
    SLproc32 = 0x110F,
    /// `S_GPROC32` — global procedure start (32-bit).
    SGproc32 = 0x1110,
    /// `S_REGREL32` — register-relative variable (32-bit).
    SRegrel32 = 0x1111,
    /// `S_COMPILE3` — compilation unit info (version 3).
    SCompile3 = 0x113C,
    /// `S_LOCAL` — local variable.
    SLocal = 0x113E,
    /// Unknown / unrecognised record kind.
    Unknown = 0xFFFF,
}

impl CvSymbolKind {
    /// Decode a raw `u16` record-type tag.
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            0x0001 => Self::SCompile,
            0x0006 => Self::SEnd,
            0x000A => Self::SEndarg,
            0x1001 => Self::SRegister,
            0x1002 => Self::SConstant,
            0x1008 => Self::SUdt,
            0x1012 => Self::SFrameproc,
            0x1101 => Self::SObjname,
            0x1102 => Self::SThunk32,
            0x1103 => Self::SBlock32,
            0x1105 => Self::SLabel32,
            0x110B => Self::SBprel32,
            0x110C => Self::SLdata32,
            0x110D => Self::SGdata32,
            0x110E => Self::SPub32,
            0x110F => Self::SLproc32,
            0x1110 => Self::SGproc32,
            0x1111 => Self::SRegrel32,
            0x113C => Self::SCompile3,
            0x113E => Self::SLocal,
            _ => Self::Unknown,
        }
    }

    /// Returns `true` for function-like records.
    #[must_use]
    pub const fn is_function(&self) -> bool {
        matches!(self, Self::SGproc32 | Self::SLproc32 | Self::SThunk32)
    }

    /// Returns `true` for data-like records.
    #[must_use]
    pub const fn is_data(&self) -> bool {
        matches!(
            self,
            Self::SGdata32 | Self::SLdata32 | Self::SPub32 | Self::SLabel32
        )
    }
}

impl fmt::Display for CvSymbolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ---------------------------------------------------------------------------
// Structured symbol payloads
// ---------------------------------------------------------------------------

/// Parsed payload for `S_GPROC32` / `S_LPROC32`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvProc32 {
    /// Offset of the parent symbol record (0 if none).
    pub parent: u32,
    /// Offset of the end record.
    pub end: u32,
    /// Offset of the next sibling.
    pub next: u32,
    /// Length of the procedure code in bytes.
    pub len: u32,
    /// Offset of the first statement from the start of the procedure.
    pub dbg_start: u32,
    /// Offset past the last statement in the procedure.
    pub dbg_end: u32,
    /// Type index of the procedure type (TPI).
    pub type_index: u32,
    /// Section-relative offset.
    pub offset: u32,
    /// Section (segment) index.
    pub segment: u16,
    /// Procedure flags.
    pub flags: u8,
    /// Mangled / decorated name.
    pub name: String,
}

impl CvProc32 {
    /// Try to parse from the record payload (bytes after the 2-byte kind field).
    ///
    /// Layout: parent(4) + end(4) + next(4) + len(4) + `dbg_start(4)` +
    ///         `dbg_end(4)` + `type_index(4)` + offset(4) + segment(2) + flags(1) + name\0
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 35 {
            return None;
        }
        Some(Self {
            parent: read_u32(data, 0),
            end: read_u32(data, 4),
            next: read_u32(data, 8),
            len: read_u32(data, 12),
            dbg_start: read_u32(data, 16),
            dbg_end: read_u32(data, 20),
            type_index: read_u32(data, 24),
            offset: read_u32(data, 28),
            segment: read_u16(data, 32),
            flags: *data.get(34)?,
            name: read_null_str(data, 35),
        })
    }
}

impl fmt::Display for CvProc32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "proc '{}' seg:{} off:{:#x} len:{}",
            self.name, self.segment, self.offset, self.len
        )
    }
}

/// Parsed payload for `S_GDATA32` / `S_LDATA32`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvData32 {
    /// Type index (TPI).
    pub type_index: u32,
    /// Section-relative offset.
    pub offset: u32,
    /// Section (segment) index.
    pub segment: u16,
    /// Symbol name.
    pub name: String,
}

impl CvData32 {
    /// Parse from the record payload bytes.
    ///
    /// Layout: `type_index(4)` + offset(4) + segment(2) + name\0
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }
        Some(Self {
            type_index: read_u32(data, 0),
            offset: read_u32(data, 4),
            segment: read_u16(data, 8),
            name: read_null_str(data, 10),
        })
    }
}

impl fmt::Display for CvData32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "data '{}' seg:{} off:{:#x} ti:{:#x}",
            self.name, self.segment, self.offset, self.type_index
        )
    }
}

/// Parsed payload for `S_PUB32`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvPublic32 {
    /// Public symbol flags (`CV_PUBSYMFLAGS`).
    pub flags: u32,
    /// Section-relative offset.
    pub offset: u32,
    /// Section (segment) index.
    pub segment: u16,
    /// Decorated symbol name.
    pub name: String,
}

impl CvPublic32 {
    /// Parse from the record payload bytes.
    ///
    /// Layout: flags(4) + offset(4) + segment(2) + name\0
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }
        Some(Self {
            flags: read_u32(data, 0),
            offset: read_u32(data, 4),
            segment: read_u16(data, 8),
            name: read_null_str(data, 10),
        })
    }

    /// Returns `true` if the `CVPSFLAG_FUNCTION` bit is set.
    #[must_use]
    pub const fn is_function(&self) -> bool {
        self.flags & 0x02 != 0
    }
}

impl fmt::Display for CvPublic32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "pub '{}' seg:{} off:{:#x} flags:{:#x}",
            self.name, self.segment, self.offset, self.flags
        )
    }
}

// ---------------------------------------------------------------------------
// parse_cv_symbol — single-record parser returning (CvSymbol, bytes_consumed)
// ---------------------------------------------------------------------------

/// Parse a single `CodeView` symbol record starting at `data[offset]`.
///
/// Returns `(symbol, bytes_consumed)` where `bytes_consumed` includes the
/// 2-byte length prefix.
///
/// # Errors
///
/// Returns [`anyhow::Error`] if the record is truncated or malformed.
pub fn parse_cv_symbol(data: &[u8], offset: usize) -> anyhow::Result<(CvSymbol, usize)> {
    use anyhow::bail;

    if offset + 4 > data.len() {
        bail!("parse_cv_symbol: buffer too short at offset {offset}");
    }
    let len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
    let kind_raw = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);

    if len < 2 {
        bail!("parse_cv_symbol: record length {len} too small");
    }
    let record_end = offset + 2 + len;
    if record_end > data.len() {
        bail!(
            "parse_cv_symbol: record extends past buffer (len={len}, buf={})",
            data.len()
        );
    }

    let payload = &data[offset + 4..record_end];
    let kind = CvSymKind::from_u16(kind_raw);
    let sym = parse_cv_symbol_payload(kind, payload);
    Ok((sym, record_end - offset))
}

fn parse_cv_symbol_payload(kind: CvSymKind, payload: &[u8]) -> CvSymbol {
    match kind {
        CvSymKind::GProc32 | CvSymKind::LProc32 => {
            if let Some(proc) = CvProc32::parse(payload) {
                return CvSymbol {
                    kind,
                    offset: proc.offset,
                    segment: proc.segment,
                    name: proc.name,
                    type_index: proc.type_index,
                    flags: u32::from(proc.flags),
                };
            }
        }
        CvSymKind::Pub32 => {
            if let Some(pub32) = CvPublic32::parse(payload) {
                return CvSymbol {
                    kind,
                    offset: pub32.offset,
                    segment: pub32.segment,
                    name: pub32.name,
                    type_index: 0,
                    flags: pub32.flags,
                };
            }
        }
        CvSymKind::GData32 | CvSymKind::LData32 => {
            if let Some(data32) = CvData32::parse(payload) {
                return CvSymbol {
                    kind,
                    offset: data32.offset,
                    segment: data32.segment,
                    name: data32.name,
                    type_index: data32.type_index,
                    flags: 0,
                };
            }
        }
        CvSymKind::Label32 => {
            if payload.len() >= 7 {
                return CvSymbol {
                    kind,
                    offset: read_u32(payload, 0),
                    segment: read_u16(payload, 4),
                    name: read_null_str(payload, 7),
                    type_index: 0,
                    flags: 0,
                };
            }
        }
        CvSymKind::Thunk32 if payload.len() >= 21 => {
            return CvSymbol {
                kind,
                offset: read_u32(payload, 12),
                segment: read_u16(payload, 16),
                name: read_null_str(payload, 21),
                type_index: 0,
                flags: 0,
            };
        }
        _ => {}
    }
    // Fallback — empty symbol for kinds we don't decode.
    CvSymbol {
        kind,
        offset: 0,
        segment: 0,
        name: String::new(),
        type_index: 0,
        flags: 0,
    }
}

// ---------------------------------------------------------------------------
// parse_debug_s — full .debug$S / CV8 subsection dispatcher
// ---------------------------------------------------------------------------

/// Parse a complete CV8 `.debug$S` section and return only the symbol records.
///
/// Subsection types handled:
/// * `0xF1` — Symbols: decoded into [`CvSymbol`] via [`parse_cv_symbols`].
/// * `0xF3` — `StringTable`: stored for file-name resolution.
/// * `0xF4` — `FileChecksums`: decoded into [`CvSourceFile`].
///
/// # Errors
///
/// Returns [`anyhow::Error`] if the section header is invalid or a subsection
/// is truncated.
pub fn parse_debug_s(section_data: &[u8]) -> anyhow::Result<Vec<CvSymbol>> {
    if section_data.len() < 4 {
        return Ok(vec![]);
    }
    let version = read_u32(section_data, 0);
    if version != 4 {
        anyhow::bail!("parse_debug_s: unsupported CV8 version {version:#x}");
    }

    let mut symbols = Vec::new();
    let mut pos = 4usize;

    while pos + 8 <= section_data.len() {
        let sub_type = read_u32(section_data, pos);
        let sub_len = read_u32(section_data, pos + 4) as usize;
        pos += 8;

        let end = pos + sub_len;
        if end > section_data.len() {
            anyhow::bail!("parse_debug_s: subsection {sub_type:#x} extends past buffer");
        }

        let payload = &section_data[pos..end];

        if Cv8SubsectionKind::from_u32(sub_type) == Cv8SubsectionKind::Symbols {
            let syms =
                parse_cv_symbols(payload).map_err(|e| anyhow::anyhow!("symbol parse: {e}"))?;
            symbols.extend(syms);
        }

        pos = end;
        let rem = pos % 4;
        if rem != 0 {
            pos += 4 - rem;
        }
    }

    Ok(symbols)
}

// ---------------------------------------------------------------------------
// PDB path extraction from PE IMAGE_DEBUG_DIRECTORY
// ---------------------------------------------------------------------------

/// The PDB location embedded in a PE binary's debug directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdbLocation {
    /// GUID formatted as `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
    pub guid: String,
    /// PDB age (incremented on each link of the same PDB).
    pub age: u32,
    /// Absolute or relative path to the PDB file.
    pub path: String,
}

impl fmt::Display for PdbLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PDB '{}' guid={} age={}", self.path, self.guid, self.age)
    }
}

/// Helpers for extracting the PDB path from a PE binary.
pub struct PdbPathFromPe;

impl PdbPathFromPe {
    /// Extract the PDB location from raw PE bytes.
    ///
    /// Locates `IMAGE_DEBUG_TYPE_CODEVIEW` (type = 2) in the debug directory
    /// and parses the embedded RSDS record.
    ///
    /// Returns `None` if the PE cannot be parsed or no `CodeView` entry is found.
    #[must_use]
    pub fn extract(pe_data: &[u8]) -> Option<PdbLocation> {
        // Minimal PE header walking without pulling in external crates.
        if pe_data.len() < 0x40 {
            return None;
        }
        // DOS header magic check ("MZ")
        if &pe_data[..2] != b"MZ" {
            return None;
        }
        // e_lfanew at offset 0x3C
        let e_lfanew = read_u32(pe_data, 0x3C) as usize;
        if e_lfanew + 4 > pe_data.len() {
            return None;
        }
        // "PE\0\0"
        if &pe_data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return None;
        }
        // COFF header starts at e_lfanew + 4
        let coff = e_lfanew + 4;
        if coff + 20 > pe_data.len() {
            return None;
        }
        let machine = read_u16(pe_data, coff);
        let opt_hdr_size = read_u16(pe_data, coff + 16) as usize;
        if opt_hdr_size == 0 {
            return None;
        }
        let opt_hdr = coff + 20;
        if opt_hdr + opt_hdr_size > pe_data.len() {
            return None;
        }

        // Determine PE32 vs PE32+
        let magic = read_u16(pe_data, opt_hdr);
        let is_pe32_plus = magic == 0x20B;
        let is_pe32 = magic == 0x10B;
        if !is_pe32 && !is_pe32_plus {
            return None;
        }

        // Data directory index 6 = Debug directory
        // In PE32:  directories start at opt_hdr + 96
        // In PE32+: directories start at opt_hdr + 112
        let dir_base = opt_hdr + if is_pe32_plus { 112 } else { 96 };
        let dbg_dir_rva_off = dir_base + 6 * 8;
        if dbg_dir_rva_off + 8 > pe_data.len() {
            return None;
        }
        let dbg_dir_rva = read_u32(pe_data, dbg_dir_rva_off) as usize;
        let dbg_dir_size = read_u32(pe_data, dbg_dir_rva_off + 4) as usize;

        if dbg_dir_rva == 0 || dbg_dir_size < 28 {
            return None;
        }

        // Resolve RVA → file offset via section headers.
        let num_sections = read_u16(pe_data, coff + 2) as usize;
        let sections_off = opt_hdr + opt_hdr_size;
        let dbg_foff = rva_to_foff(pe_data, dbg_dir_rva, num_sections, sections_off, machine)?;

        // Walk IMAGE_DEBUG_DIRECTORY entries (each 28 bytes).
        let num_entries = dbg_dir_size / 28;
        for i in 0..num_entries {
            let entry = dbg_foff + i * 28;
            if entry + 28 > pe_data.len() {
                break;
            }
            // Characteristics(4) + TimeDateStamp(4) + MajorVer(2) + MinorVer(2) +
            // Type(4) + SizeOfData(4) + AddressOfRawData(4) + PointerToRawData(4)
            let dbg_type = read_u32(pe_data, entry + 12);
            let data_size = read_u32(pe_data, entry + 16) as usize;
            let raw_data_off = read_u32(pe_data, entry + 24) as usize; // file offset

            // IMAGE_DEBUG_TYPE_CODEVIEW = 2
            if dbg_type != 2 {
                continue;
            }
            if raw_data_off == 0 || data_size < 24 {
                continue;
            }
            if raw_data_off + data_size > pe_data.len() {
                continue;
            }

            let cv = &pe_data[raw_data_off..raw_data_off + data_size];
            // RSDS record: signature(4) + GUID(16) + age(4) + path\0
            if cv.len() < 24 {
                continue;
            }
            if &cv[..4] != b"RSDS" {
                continue;
            }
            let guid_bytes: [u8; 16] = cv[4..20].try_into().ok()?;
            let age = read_u32(cv, 20);
            let path = read_null_str(cv, 24);
            return Some(PdbLocation {
                guid: guid_to_string(&guid_bytes),
                age,
                path,
            });
        }
        None
    }
}

/// Target architecture of a PE image, from its COFF `Machine` field.
///
/// A separate entry point from [`PdbPathFromPe::extract`] on purpose: that
/// function's signature is public API (`symbol_resolver` calls it) and this
/// crate has enough per-architecture decisions to make — register numbering
/// above all — that the machine value must stop being read and discarded.
///
/// Returns `None` only when the bytes are not a PE at all; a PE with an
/// unrecognised machine yields `Some(CvArch::Unknown(v))`, which is a different
/// fact and must not be collapsed into "not a PE".
#[must_use]
pub fn pe_arch(pe_data: &[u8]) -> Option<CvArch> {
    if pe_data.len() < 0x40 || &pe_data[..2] != b"MZ" {
        return None;
    }
    let e_lfanew = read_u32(pe_data, 0x3C) as usize;
    if e_lfanew + 4 > pe_data.len() || &pe_data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let coff = e_lfanew + 4;
    if coff + 20 > pe_data.len() {
        return None;
    }
    Some(CvArch::from_image_file_machine(read_u16(pe_data, coff)))
}

/// Convert a PE RVA to a file offset by scanning the section table.
fn rva_to_foff(
    pe_data: &[u8],
    rva: usize,
    num_sections: usize,
    sections_off: usize,
    _machine: u16,
) -> Option<usize> {
    for i in 0..num_sections {
        let sec = sections_off + i * 40;
        if sec + 40 > pe_data.len() {
            break;
        }
        let virt_addr = read_u32(pe_data, sec + 12) as usize;
        let virt_size = read_u32(pe_data, sec + 16) as usize;
        let raw_off = read_u32(pe_data, sec + 20) as usize;
        if rva >= virt_addr && rva < virt_addr + virt_size.max(1) {
            return Some(raw_off + (rva - virt_addr));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// GUID formatting
// ---------------------------------------------------------------------------

/// Format 16 raw GUID bytes as `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
///
/// The first three components are little-endian integers; the last two are
/// big-endian byte sequences, matching the mixed-endian GUID encoding used
/// by Windows and PDB files.
#[must_use]
pub fn guid_to_string(guid_bytes: &[u8; 16]) -> String {
    // Data1: 4 bytes LE u32
    let d1 = u32::from_le_bytes([guid_bytes[0], guid_bytes[1], guid_bytes[2], guid_bytes[3]]);
    // Data2: 2 bytes LE u16
    let d2 = u16::from_le_bytes([guid_bytes[4], guid_bytes[5]]);
    // Data3: 2 bytes LE u16
    let d3 = u16::from_le_bytes([guid_bytes[6], guid_bytes[7]]);
    // Data4: 8 bytes big-endian (two groups: [8..10] and [10..16])
    let d4a = u16::from_be_bytes([guid_bytes[8], guid_bytes[9]]);
    let d4b = &guid_bytes[10..16];
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:04X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        d1, d2, d3, d4a, d4b[0], d4b[1], d4b[2], d4b[3], d4b[4], d4b[5]
    )
}

// ---------------------------------------------------------------------------
// CvTypeRecord — basic type info with a simpler parse_type_record API
// ---------------------------------------------------------------------------

// NOTE: CvTypeRecord is already defined above (full TPI version).
// parse_type_record provides a lightweight entry-point returning Option<CvTypeRecord>.

/// Parse a single `CodeView` type record from `data` (the raw TPI record bytes
/// including the 2-byte length prefix).
///
/// Returns `None` if `data` is too short, the length is invalid, or the leaf
/// kind is not supported.
#[must_use]
pub fn parse_type_record(data: &[u8]) -> Option<CvTypeRecord> {
    if data.len() < 4 {
        return None;
    }
    let len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let leaf = u16::from_le_bytes([data[2], data[3]]);
    if len < 2 || 2 + len > data.len() {
        return None;
    }
    let body = &data[4..2 + len];
    let kind = CvTypeKind::from_u16(leaf);
    if kind == CvTypeKind::Unknown {
        return None;
    }
    Some(parse_one_type(kind, body, 0x1000))
}

// ---------------------------------------------------------------------------
// Extended: CvRegrel32 — register-relative variable
// ---------------------------------------------------------------------------

/// Parsed payload for `S_REGREL32`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvRegrel32 {
    /// Offset from the register value.
    pub offset: u32,
    /// Type index (TPI).
    pub type_index: u32,
    /// Register number (`CV_HREG_e`).
    pub register: u16,
    /// Variable name.
    pub name: String,
}

impl CvRegrel32 {
    /// Parse from the record payload bytes.
    ///
    /// Layout: offset(4) + `type_index(4)` + register(2) + name\0
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }
        Some(Self {
            offset: read_u32(data, 0),
            type_index: read_u32(data, 4),
            register: read_u16(data, 8),
            name: read_null_str(data, 10),
        })
    }
}

impl fmt::Display for CvRegrel32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "regrel '{}' reg:{} off:{:#x} ti:{:#x}",
            self.name, self.register, self.offset, self.type_index
        )
    }
}

// ---------------------------------------------------------------------------
// Extended: CvObjname — object file name record
// ---------------------------------------------------------------------------

/// Parsed payload for `S_OBJNAME`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvObjname {
    /// Signature (usually 0).
    pub signature: u32,
    /// Object file path.
    pub name: String,
}

impl CvObjname {
    /// Parse from the record payload bytes.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        Some(Self {
            signature: read_u32(data, 0),
            name: read_null_str(data, 4),
        })
    }
}

impl fmt::Display for CvObjname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "objname '{}'", self.name)
    }
}

// ---------------------------------------------------------------------------
// Extended: CvFrameproc — frame-procedure information
// ---------------------------------------------------------------------------

/// Parsed payload for `S_FRAMEPROC`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvFrameproc {
    /// Total size of the locals on the stack.
    pub frame_size: u32,
    /// Size of the padding between the locals and saved registers.
    pub pad_size: u32,
    /// Offset of the padding.
    pub pad_offset: u32,
    /// Bytes for callee-save registers.
    pub save_regs_size: u32,
    /// Exception handler section index.
    pub eh_section: u32,
    /// Exception handler section offset.
    pub eh_offset: u32,
    /// Frame-procedure flags.
    pub flags: u32,
}

impl CvFrameproc {
    /// Parse from the record payload (28 bytes minimum).
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 28 {
            return None;
        }
        Some(Self {
            frame_size: read_u32(data, 0),
            pad_size: read_u32(data, 4),
            pad_offset: read_u32(data, 8),
            save_regs_size: read_u32(data, 12),
            eh_section: read_u32(data, 16),
            eh_offset: read_u32(data, 20),
            flags: read_u32(data, 24),
        })
    }

    /// Returns `true` if the asymmetric save/restore flag is set.
    #[must_use]
    pub const fn has_async_eh(&self) -> bool {
        self.flags & 0x0000_0200 != 0
    }

    /// Returns `true` if the function uses __alloca.
    #[must_use]
    pub const fn has_alloca(&self) -> bool {
        self.flags & 0x0000_0100 != 0
    }
}

impl fmt::Display for CvFrameproc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "frameproc frame={} pad={} flags={:#x}",
            self.frame_size, self.pad_size, self.flags
        )
    }
}

// ---------------------------------------------------------------------------
// Extended: CvConstant — S_CONSTANT record
// ---------------------------------------------------------------------------

/// Parsed payload for `S_CONSTANT`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvConstant {
    /// Type index (TPI).
    pub type_index: u32,
    /// Numeric value (stored as a u64; sign extension depends on type).
    pub value: u64,
    /// Constant name.
    pub name: String,
}

impl CvConstant {
    /// Parse from the record payload bytes.
    ///
    /// Layout: `type_index(4)` + `value_leaf` + name\0
    /// The value leaf is a `CodeView` numeric leaf: if < 0x8000 it is a literal u16;
    /// otherwise it encodes a longer integer (`LF_CHAR`, `LF_SHORT`, `LF_LONG`, `LF_ULONG`, etc.)
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 6 {
            return None;
        }
        let type_index = read_u32(data, 0);
        // Numeric leaf starts at offset 4.
        let (value, name_start) = parse_numeric_leaf(data, 4)?;
        let name = read_null_str(data, name_start);
        Some(Self {
            type_index,
            value,
            name,
        })
    }
}

impl fmt::Display for CvConstant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "const '{}' = {} ti:{:#x}",
            self.name, self.value, self.type_index
        )
    }
}

// ---------------------------------------------------------------------------
// Extended: CvUdt — S_UDT record
// ---------------------------------------------------------------------------

/// Parsed payload for `S_UDT`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvUdt {
    /// Type index of the UDT (TPI).
    pub type_index: u32,
    /// Typedef or tag name.
    pub name: String,
}

impl CvUdt {
    /// Parse from the record payload bytes.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        Some(Self {
            type_index: read_u32(data, 0),
            name: read_null_str(data, 4),
        })
    }
}

impl fmt::Display for CvUdt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "udt '{}' ti:{:#x}", self.name, self.type_index)
    }
}

// ---------------------------------------------------------------------------
// Numeric leaf helper
// ---------------------------------------------------------------------------

/// Parse a `CodeView` numeric leaf value starting at `data[off]`.
///
/// Returns `(value_as_u64, bytes_consumed_including_tag)`.
fn parse_numeric_leaf(data: &[u8], off: usize) -> Option<(u64, usize)> {
    if off >= data.len() {
        return None;
    }
    let tag = read_u16(data, off);
    if tag < 0x8000 {
        // Immediate u16 value.
        return Some((u64::from(tag), off + 2));
    }
    match tag {
        0x8000 => {
            // LF_CHAR
            if off + 3 > data.len() {
                return None;
            }
            Some((u64::from(data[off + 2]), off + 3))
        }
        0x8001 => {
            // LF_SHORT
            if off + 4 > data.len() {
                return None;
            }
            let v = i16::from_le_bytes([data[off + 2], data[off + 3]]);
            Some((self::casts::i16_sext_u64(v), off + 4))
        }
        0x8002 => {
            // LF_USHORT
            if off + 4 > data.len() {
                return None;
            }
            Some((u64::from(read_u16(data, off + 2)), off + 4))
        }
        0x8003 => {
            // LF_LONG
            if off + 6 > data.len() {
                return None;
            }
            let v = i32::from_le_bytes(data[off + 2..off + 6].try_into().ok()?);
            Some((self::casts::i32_sext_u64(v), off + 6))
        }
        0x8004 => {
            // LF_ULONG
            if off + 6 > data.len() {
                return None;
            }
            Some((u64::from(read_u32(data, off + 2)), off + 6))
        }
        0x8009 => {
            // LF_QUADWORD
            if off + 10 > data.len() {
                return None;
            }
            let bytes: [u8; 8] = data[off + 2..off + 10].try_into().ok()?;
            Some((u64::from_le_bytes(bytes), off + 10))
        }
        0x800A => {
            // LF_UQUADWORD
            if off + 10 > data.len() {
                return None;
            }
            let bytes: [u8; 8] = data[off + 2..off + 10].try_into().ok()?;
            Some((u64::from_le_bytes(bytes), off + 10))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// CvSymbolStream — high-level iterator over a raw symbol stream
// ---------------------------------------------------------------------------

/// Iterator that yields `(CvSymbolKind, payload: &[u8])` tuples from a raw
/// symbol byte stream, using the extended [`CvSymbolKind`] enum.
pub struct CvSymbolStream<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> CvSymbolStream<'a> {
    /// Create a new stream iterator over `data`.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }
}

impl<'a> Iterator for CvSymbolStream<'a> {
    /// `(kind, payload_bytes, bytes_consumed)`
    type Item = (CvSymbolKind, &'a [u8], usize);

    fn next(&mut self) -> Option<Self::Item> {
        let data = self.data;
        let off = self.offset;

        if off + 4 > data.len() {
            return None;
        }
        let len = u16::from_le_bytes([data[off], data[off + 1]]) as usize;
        let kind_raw = u16::from_le_bytes([data[off + 2], data[off + 3]]);

        if len < 2 {
            return None;
        }
        let record_end = off + 2 + len;
        if record_end > data.len() {
            return None;
        }

        let payload = &data[off + 4..record_end];
        let kind = CvSymbolKind::from_u16(kind_raw);
        let consumed = record_end - off;
        self.offset = record_end;
        Some((kind, payload, consumed))
    }
}

// ---------------------------------------------------------------------------
// PdbStreamHeader — minimal PDB 7.0 multi-stream file header helpers
// ---------------------------------------------------------------------------

/// Minimal representation of a PDB 7.0 MSF (multi-stream file) super-block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdbSuperBlock {
    /// Magic: "Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\0\0\0"
    pub magic_ok: bool,
    /// Page size in bytes (typically 4096 for modern PDBs).
    pub page_size: u32,
    /// Free page map page index.
    pub free_page_map: u32,
    /// Number of pages in the file.
    pub num_pages: u32,
    /// Number of bytes in the root directory stream.
    pub num_dir_bytes: u32,
    /// Block index of the block-map page (offset 52 in the super-block;
    /// offset 48 is a reserved/unknown field).
    pub block_map_addr: u32,
}

/// Expected MSF 7.00 magic (29 bytes + 3 padding = 32 bytes total).
pub const MSF_MAGIC: &[u8] = b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\0\0\0";

impl PdbSuperBlock {
    /// Parse from the first 56 bytes of a PDB file.
    ///
    /// Returns `None` if `data` is shorter than 56 bytes.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 56 {
            return None;
        }
        let magic_ok = data[..MSF_MAGIC.len()] == *MSF_MAGIC;
        // The super-block fields start after the 32-byte magic:
        // BlockSize(32) FreeBlockMap(36) NumBlocks(40) NumDirectoryBytes(44)
        // Unknown/reserved(48) BlockMapAddr(52).
        let page_size = read_u32(data, 32);
        let free_page_map = read_u32(data, 36);
        let num_pages = read_u32(data, 40);
        let num_dir_bytes = read_u32(data, 44);
        let block_map_addr = read_u32(data, 52);
        Some(Self {
            magic_ok,
            page_size,
            free_page_map,
            num_pages,
            num_dir_bytes,
            block_map_addr,
        })
    }

    /// Returns `true` if this looks like a valid PDB 7.0 super-block.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.magic_ok && self.page_size.is_power_of_two() && self.page_size >= 512
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the smallest PE header that carries a `Machine` value.
    fn pe_with_machine(machine: u16) -> Vec<u8> {
        let mut v = vec![0u8; 0x100];
        v[0] = b'M';
        v[1] = b'Z';
        v[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        v[0x80..0x84].copy_from_slice(b"PE\0\0");
        v[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
        v
    }

    /// The COFF `Machine` field must reach callers instead of being discarded.
    ///
    /// `PdbPathFromPe::extract` read it and passed it to `rva_to_foff`, which
    /// ignored it (`_machine`). Meanwhile the record decoders have no way to
    /// know whether a register number is x86 or arm64 — the one place that
    /// knows was throwing the answer away.
    #[test]
    fn pe_arch_reports_the_image_architecture() {
        assert_eq!(pe_arch(&pe_with_machine(0x8664)), Some(CvArch::X64));
        assert_eq!(
            pe_arch(&pe_with_machine(0xAA64)),
            Some(CvArch::Arm64),
            "Windows on ARM is a shipping platform; its PDBs use arm64 register numbers"
        );
        assert_eq!(pe_arch(&pe_with_machine(0x014C)), Some(CvArch::X86));
        // Unrecognised machine is NOT the same fact as "not a PE".
        assert_eq!(
            pe_arch(&pe_with_machine(0x5032)),
            Some(CvArch::Unknown(0x5032))
        );
        assert_eq!(pe_arch(b"not a pe at all"), None);
        assert_eq!(pe_arch(&[]), None);
    }

    // ---- CvSignature ----

    #[test]
    fn test_sig_cv41() {
        assert_eq!(
            CvSignature::from_bytes(b"NB09xxxx"),
            Some(CvSignature::Cv41)
        );
    }

    #[test]
    fn test_sig_cv50() {
        assert_eq!(
            CvSignature::from_bytes(b"NB10xxxx"),
            Some(CvSignature::Cv50)
        );
    }

    #[test]
    fn test_sig_cv70() {
        assert_eq!(
            CvSignature::from_bytes(b"NB11xxxx"),
            Some(CvSignature::Cv70)
        );
    }

    #[test]
    fn test_sig_pdb70() {
        assert_eq!(
            CvSignature::from_bytes(b"Micrxxxx"),
            Some(CvSignature::Pdb70)
        );
    }

    #[test]
    fn test_sig_unknown() {
        assert!(CvSignature::from_bytes(b"XXXX").is_none());
    }

    #[test]
    fn test_sig_too_short() {
        assert!(CvSignature::from_bytes(b"NB").is_none());
    }

    #[test]
    fn test_sig_display() {
        assert_eq!(CvSignature::Cv41.to_string(), "Cv41");
        assert_eq!(CvSignature::Pdb70.to_string(), "Pdb70");
    }

    #[test]
    fn test_sig_as_str() {
        assert!(CvSignature::Cv41.as_str().contains("4.1"));
        assert!(CvSignature::Pdb70.as_str().contains("PDB"));
    }

    // ---- CvSymKind ----

    #[test]
    fn test_cv_sym_kind_roundtrip() {
        assert_eq!(CvSymKind::from_u16(0x1009), CvSymKind::Pub32);
        assert_eq!(CvSymKind::from_u16(0x1110), CvSymKind::GProc32);
        assert_eq!(CvSymKind::from_u16(0x110F), CvSymKind::LProc32);
        assert_eq!(CvSymKind::from_u16(0x1111), CvSymKind::RegRel32);
        assert_eq!(CvSymKind::from_u16(0x110D), CvSymKind::GData32);
        assert_eq!(CvSymKind::from_u16(0x110C), CvSymKind::LData32);
        assert_eq!(CvSymKind::from_u16(0x1105), CvSymKind::Label32);
        assert_eq!(CvSymKind::from_u16(0x1102), CvSymKind::Thunk32);
        assert_eq!(CvSymKind::from_u16(0x1103), CvSymKind::Block32);
        assert_eq!(CvSymKind::from_u16(0x0006), CvSymKind::End);
        assert_eq!(CvSymKind::from_u16(0x113C), CvSymKind::Compile3);
        assert_eq!(CvSymKind::from_u16(0xABCD), CvSymKind::Unknown);
    }

    #[test]
    fn test_cv_sym_kind_display() {
        assert_eq!(CvSymKind::GProc32.to_string(), "GProc32");
        assert_eq!(CvSymKind::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn test_cv_sym_kind_is_function() {
        assert!(CvSymKind::GProc32.is_function());
        assert!(CvSymKind::LProc32.is_function());
        assert!(!CvSymKind::Pub32.is_function());
    }

    #[test]
    fn test_cv_sym_kind_is_data() {
        assert!(CvSymKind::GData32.is_data());
        assert!(CvSymKind::LData32.is_data());
        assert!(!CvSymKind::GProc32.is_data());
    }

    #[test]
    fn test_cv_sym_kind_is_named_address() {
        assert!(CvSymKind::GProc32.is_named_address());
        assert!(CvSymKind::Pub32.is_named_address());
        assert!(!CvSymKind::End.is_named_address());
    }

    // ---- CvTypeKind ----

    #[test]
    fn test_cv_type_kind_roundtrip() {
        assert_eq!(CvTypeKind::from_u16(0x1001), CvTypeKind::Modifier);
        assert_eq!(CvTypeKind::from_u16(0x1002), CvTypeKind::Pointer);
        assert_eq!(CvTypeKind::from_u16(0x1005), CvTypeKind::Structure);
        assert_eq!(CvTypeKind::from_u16(0x1007), CvTypeKind::Enum);
        assert_eq!(CvTypeKind::from_u16(0xDEAD), CvTypeKind::Unknown);
    }

    // ---- CvSymbol ----

    #[test]
    fn test_cv_symbol_display() {
        let s = CvSymbol {
            kind: CvSymKind::GProc32,
            offset: 0x100,
            segment: 1,
            name: "foo".to_string(),
            type_index: 0,
            flags: 0,
        };
        let text = s.to_string();
        assert!(text.contains("GProc32"));
        assert!(text.contains("foo"));
        assert!(text.contains("0x100"));
    }

    #[test]
    fn test_cv_symbol_is_function() {
        let mut s = CvSymbol {
            kind: CvSymKind::GProc32,
            offset: 0,
            segment: 1,
            name: "fn".to_string(),
            type_index: 0,
            flags: 0,
        };
        assert!(s.is_function());
        s.kind = CvSymKind::GData32;
        assert!(!s.is_function());
    }

    // ---- parse_cv_symbols ----

    #[test]
    fn test_parse_empty() {
        let syms = parse_cv_symbols(&[]).unwrap();
        assert!(syms.is_empty());
    }

    #[test]
    fn test_parse_gproc32() {
        let data = build_test_gproc32("main", 0x1000, 1, 0x1234);
        let syms = parse_cv_symbols(&data).unwrap();
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].name, "main");
        assert_eq!(syms[0].offset, 0x1000);
        assert_eq!(syms[0].kind, CvSymKind::GProc32);
        assert_eq!(syms[0].type_index, 0x1234);
    }

    #[test]
    fn test_parse_lproc32() {
        let data = build_test_lproc32("helper", 0x2000);
        let syms = parse_cv_symbols(&data).unwrap();
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].kind, CvSymKind::LProc32);
        assert_eq!(syms[0].name, "helper");
        assert_eq!(syms[0].offset, 0x2000);
    }

    #[test]
    fn test_parse_pub32() {
        let data = build_test_pub32("exported_fn", 0x500);
        let syms = parse_cv_symbols(&data).unwrap();
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].kind, CvSymKind::Pub32);
        assert_eq!(syms[0].name, "exported_fn");
    }

    #[test]
    fn test_parse_gdata32() {
        let data = build_test_gdata32("g_counter", 0x4000, 0x74);
        let syms = parse_cv_symbols(&data).unwrap();
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].kind, CvSymKind::GData32);
        assert_eq!(syms[0].name, "g_counter");
        assert_eq!(syms[0].type_index, 0x74);
    }

    #[test]
    fn test_parse_multiple_records() {
        let mut data = build_test_gproc32("f1", 0x100, 1, 0);
        data.extend(build_test_lproc32("f2", 0x200));
        let syms = parse_cv_symbols(&data).unwrap();
        assert_eq!(syms.len(), 2);
    }

    #[test]
    fn test_parse_record_too_short() {
        let data: Vec<u8> = vec![100, 0, 0x10, 0x11]; // len=100 but no payload
        let result = parse_cv_symbols(&data);
        assert!(matches!(result, Err(CodeViewError::RecordTooShort)));
    }

    #[test]
    fn test_parse_skips_end_record() {
        let kind: u16 = 0x0006;
        let len: u16 = 2;
        let mut data = Vec::new();
        data.extend_from_slice(&len.to_le_bytes());
        data.extend_from_slice(&kind.to_le_bytes());
        let syms = parse_cv_symbols(&data).unwrap();
        assert!(syms.is_empty());
    }

    // ---- parse_cv_type_records ----

    #[test]
    fn test_parse_type_records_empty() {
        let recs = parse_cv_type_records(&[]).unwrap();
        assert!(recs.is_empty());
    }

    fn build_struct_type_record(name: &str, count: u16, size: u16) -> Vec<u8> {
        // LF_STRUCTURE body: [count:u16][prop:u16][field_list:u32][derived:u32][vshape:u32][size:u16][name\0]
        let mut body = Vec::new();
        body.extend_from_slice(&count.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes()); // property
        body.extend_from_slice(&0u32.to_le_bytes()); // field_list
        body.extend_from_slice(&0u32.to_le_bytes()); // derived
        body.extend_from_slice(&0u32.to_le_bytes()); // vshape
        body.extend_from_slice(&size.to_le_bytes()); // size
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        let leaf: u16 = 0x1005; // LF_STRUCTURE
        let len = self::casts::usize_to_u16(2 + body.len());
        let mut record = Vec::new();
        record.extend_from_slice(&len.to_le_bytes());
        record.extend_from_slice(&leaf.to_le_bytes());
        record.extend_from_slice(&body);
        record
    }

    #[test]
    fn test_parse_structure_type() {
        let data = build_struct_type_record("MyStruct", 3, 24);
        let recs = parse_cv_type_records(&data).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].kind, CvTypeKind::Structure);
        assert_eq!(recs[0].name, "MyStruct");
        assert_eq!(recs[0].size, 24);
        assert_eq!(recs[0].count, 3);
        assert_eq!(recs[0].index, 0x1000);
    }

    #[test]
    fn test_parse_type_record_too_short() {
        let data: Vec<u8> = vec![50, 0, 0x05, 0x10]; // len=50 but buffer is tiny
        let result = parse_cv_type_records(&data);
        assert!(matches!(result, Err(CodeViewError::RecordTooShort)));
    }

    // ---- CvTypeTable ----

    #[test]
    fn test_type_table_empty() {
        let t = CvTypeTable::new();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
        assert!(t.lookup(0x1000).is_none());
    }

    #[test]
    fn test_type_table_lookup() {
        let data = build_struct_type_record("Foo", 2, 8);
        let t = CvTypeTable::from_bytes(&data).unwrap();
        assert_eq!(t.len(), 1);
        let rec = t.lookup(0x1000).unwrap();
        assert_eq!(rec.name, "Foo");
    }

    #[test]
    fn test_type_table_to_type_info_struct() {
        let data = build_struct_type_record("Bar", 1, 4);
        let t = CvTypeTable::from_bytes(&data).unwrap();
        let ti = t.to_type_info(0x1000);
        assert!(matches!(ti, TypeInfo::Struct { .. }));
    }

    #[test]
    fn test_type_table_struct_fields_populated() {
        // Three members across 24 bytes => 8-byte stride.
        let data = build_struct_type_record("MyStruct", 3, 24);
        let t = CvTypeTable::from_bytes(&data).unwrap();
        match t.to_type_info(0x1000) {
            TypeInfo::Struct { name, fields } => {
                assert_eq!(name, "MyStruct");
                assert_eq!(fields.len(), 3);
                assert_eq!(fields[0].offset, 0);
                assert_eq!(fields[1].offset, 8);
                assert_eq!(fields[2].offset, 16);
                assert_eq!(fields[0].name, "field_0");
            }
            other => panic!("expected struct, got {other}"),
        }
    }

    #[test]
    fn test_type_table_primitive_int32() {
        let t = CvTypeTable::new();
        let ti = t.to_type_info(0x74); // T_INT4 (signed 32-bit)
        assert!(matches!(
            ti,
            TypeInfo::Int {
                width: 32,
                signed: true
            }
        ));
    }

    #[test]
    fn test_type_table_primitive_void() {
        let t = CvTypeTable::new();
        let ti = t.to_type_info(0x00);
        assert!(matches!(ti, TypeInfo::Void));
    }

    #[test]
    fn test_type_record_is_aggregate() {
        let rec = CvTypeRecord {
            kind: CvTypeKind::Structure,
            index: 0x1000,
            name: "S".to_string(),
            size: 8,
            count: 1,
            underlying_type: 0,
            return_type: 0,
            arg_types: vec![],
        };
        assert!(rec.is_aggregate());
    }

    #[test]
    fn test_type_record_is_callable() {
        let rec = CvTypeRecord {
            kind: CvTypeKind::Procedure,
            index: 0x1001,
            name: String::new(),
            size: 0,
            count: 0,
            underlying_type: 0,
            return_type: 0x74,
            arg_types: vec![],
        };
        assert!(rec.is_callable());
    }

    // ---- primitive_type ----

    #[test]
    fn test_primitive_type_bool() {
        assert!(matches!(primitive_type(0x30), TypeInfo::Bool));
    }

    #[test]
    fn test_primitive_type_float32() {
        assert!(matches!(
            primitive_type(0x40),
            TypeInfo::Float { width: 32 }
        ));
    }

    #[test]
    fn test_primitive_type_pointer_mode() {
        // mode=1 (near pointer) to int32
        let ti = primitive_type(0x0174);
        assert!(matches!(ti, TypeInfo::Pointer { .. }));
    }

    // ---- CvStringTable ----

    #[test]
    fn test_string_table_empty() {
        let t = CvStringTable::default();
        assert!(t.is_empty());
        assert_eq!(t.get(0), "");
    }

    #[test]
    fn test_string_table_lookup() {
        let data = b"hello\0world\0";
        let t = CvStringTable::from_bytes(data);
        assert_eq!(t.get(0), "hello");
        assert_eq!(t.get(6), "world");
    }

    #[test]
    fn test_string_table_oob() {
        let t = CvStringTable::from_bytes(b"x\0");
        assert_eq!(t.get(9999), "");
    }

    // ---- CvLineEntry / Cv8LineBlock ----

    #[test]
    fn test_cv_line_entry_display() {
        let e = CvLineEntry {
            offset: 0x10,
            line_start: 42,
            is_statement: true,
        };
        let s = e.to_string();
        assert!(s.contains("42"));
        assert!(s.contains("0x10"));
    }

    #[test]
    fn test_parse_cv8_lines_too_short() {
        let result = parse_cv8_lines(&[0u8; 4]);
        assert!(result.unwrap().is_empty());
    }

    // ---- CodeViewProvider ----

    #[test]
    fn test_provider_from_empty_bytes() {
        let provider = CodeViewProvider::from_bytes(&[], 0x0040_0000).unwrap();
        assert!(provider.all_symbols().is_empty());
        assert!(provider.raw_symbols().is_empty());
    }

    #[test]
    fn test_provider_from_gproc32() {
        let data = build_test_gproc32("WinMain", 0x1000, 1, 0);
        let p = CodeViewProvider::from_bytes(&data, 0x0040_0000).unwrap();
        assert_eq!(p.all_symbols().len(), 1);
        let sym = &p.all_symbols()[0];
        assert_eq!(sym.name, "WinMain");
        assert_eq!(sym.address, 0x0040_0000 + 0x1000);
        assert_eq!(sym.kind, SymKind::Function);
    }

    #[test]
    fn test_provider_lookup_name() {
        let data = build_test_gproc32("foo", 0x500, 1, 0);
        let p = CodeViewProvider::from_bytes(&data, 0).unwrap();
        assert!(p.lookup_name("foo").is_some());
        assert!(p.lookup_name("bar").is_none());
    }

    #[test]
    fn test_provider_lookup_address() {
        let data = build_test_gproc32("fn1", 0x1234, 1, 0);
        let p = CodeViewProvider::from_bytes(&data, 0x0040_0000).unwrap();
        assert!(p.lookup_address(0x0040_0000 + 0x1234).is_some());
        assert!(p.lookup_address(0).is_none());
    }

    #[test]
    fn test_provider_lookup_nearest() {
        let mut data = build_test_gproc32("a", 0x100, 1, 0);
        data.extend(build_test_gproc32("b", 0x300, 1, 0));
        let p = CodeViewProvider::from_bytes(&data, 0).unwrap();
        let nearest = p.lookup_nearest(0x200).unwrap();
        assert_eq!(nearest.name, "a");
    }

    #[test]
    fn test_provider_all_functions() {
        let data = build_test_gproc32("myfn", 0x100, 1, 0);
        let p = CodeViewProvider::from_bytes(&data, 0).unwrap();
        let fns = p.all_functions();
        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].kind, SymKind::Function);
    }

    #[test]
    fn test_provider_source_line_none() {
        let p = CodeViewProvider::from_bytes(&[], 0).unwrap();
        assert!(p.source_line_for_address(0x1000).is_none());
    }

    #[test]
    fn test_provider_name() {
        let p = CodeViewProvider::from_bytes(&[], 0).unwrap();
        assert_eq!(p.name(), "codeview");
    }

    #[test]
    fn test_provider_raw_symbols() {
        let data = build_test_lproc32("local_fn", 0xABCD);
        let p = CodeViewProvider::from_bytes(&data, 0).unwrap();
        assert_eq!(p.raw_symbols().len(), 1);
        assert_eq!(p.raw_symbols()[0].name, "local_fn");
    }

    #[test]
    fn test_provider_symbol_count() {
        let mut data = build_test_gproc32("a", 0, 1, 0);
        data.extend(build_test_gproc32("b", 0x100, 1, 0));
        let p = CodeViewProvider::from_bytes(&data, 0).unwrap();
        assert_eq!(p.symbol_count(), 2);
    }

    #[test]
    fn test_provider_symbols_sorted() {
        let mut data = build_test_gproc32("z", 0x300, 1, 0);
        data.extend(build_test_gproc32("a", 0x100, 1, 0));
        let p = CodeViewProvider::from_bytes(&data, 0).unwrap();
        let sorted = p.symbols_sorted();
        assert!(sorted[0].address <= sorted[1].address);
    }

    #[test]
    fn test_provider_symbols_with_prefix() {
        let mut data = build_test_gproc32("my_func", 0x100, 1, 0);
        data.extend(build_test_gproc32("other_fn", 0x200, 1, 0));
        let p = CodeViewProvider::from_bytes(&data, 0).unwrap();
        let prefixed = p.symbols_with_prefix("my_");
        assert_eq!(prefixed.len(), 1);
        assert_eq!(prefixed[0].name, "my_func");
    }

    #[test]
    fn test_provider_functions_filter() {
        let mut data = build_test_gproc32("fn1", 0x100, 1, 0);
        data.extend(build_test_gdata32("g_var", 0x200, 0x74));
        let p = CodeViewProvider::from_bytes(&data, 0).unwrap();
        assert_eq!(p.functions().len(), 1);
        assert_eq!(p.data_symbols().len(), 1);
    }

    #[test]
    fn test_provider_resolve_type_primitive() {
        let p = CodeViewProvider::from_bytes(&[], 0).unwrap();
        let ti = p.resolve_type(0x74);
        assert!(matches!(ti, TypeInfo::Int { .. }));
    }

    // ---- CvSymbolFilter ----

    #[test]
    fn test_filter_by_kind() {
        let syms = vec![
            CvSymbol {
                kind: CvSymKind::GProc32,
                offset: 0,
                segment: 1,
                name: "f".to_string(),
                type_index: 0,
                flags: 0,
            },
            CvSymbol {
                kind: CvSymKind::GData32,
                offset: 0,
                segment: 1,
                name: "d".to_string(),
                type_index: 0,
                flags: 0,
            },
        ];
        let filter = CvSymbolFilter::new(syms).by_kind(CvSymKind::GProc32);
        assert_eq!(filter.count(), 1);
        assert_eq!(filter.into_symbols()[0].name, "f");
    }

    #[test]
    fn test_filter_name_contains() {
        let syms = vec![
            CvSymbol {
                kind: CvSymKind::GProc32,
                offset: 0,
                segment: 1,
                name: "foo_bar".to_string(),
                type_index: 0,
                flags: 0,
            },
            CvSymbol {
                kind: CvSymKind::GProc32,
                offset: 0,
                segment: 1,
                name: "baz".to_string(),
                type_index: 0,
                flags: 0,
            },
        ];
        let filter = CvSymbolFilter::new(syms).name_contains("foo");
        assert_eq!(filter.count(), 1);
    }

    #[test]
    fn test_filter_in_segment() {
        let syms = vec![
            CvSymbol {
                kind: CvSymKind::GProc32,
                offset: 0,
                segment: 1,
                name: "a".to_string(),
                type_index: 0,
                flags: 0,
            },
            CvSymbol {
                kind: CvSymKind::GProc32,
                offset: 0,
                segment: 2,
                name: "b".to_string(),
                type_index: 0,
                flags: 0,
            },
        ];
        let filter = CvSymbolFilter::new(syms).in_segment(2);
        assert_eq!(filter.count(), 1);
        assert_eq!(filter.into_symbols()[0].name, "b");
    }

    // ---- Error display ----

    #[test]
    fn test_codeview_error_display() {
        assert!(
            CodeViewError::InvalidSignature(0xDEAD)
                .to_string()
                .contains("0xdead")
        );
        assert!(
            CodeViewError::UnsupportedVersion(42)
                .to_string()
                .contains("42")
        );
        assert!(CodeViewError::RecordTooShort.to_string().contains("short"));
        assert!(
            CodeViewError::Parse("bad".to_string())
                .to_string()
                .contains("bad")
        );
        assert!(CodeViewError::TypeIndexOob(5).to_string().contains('5'));
        assert!(
            CodeViewError::StringOffsetOob(99)
                .to_string()
                .contains("99")
        );
    }

    // ---- CvTypeRecord display ----

    #[test]
    fn test_type_record_display() {
        let rec = CvTypeRecord {
            kind: CvTypeKind::Structure,
            index: 0x1005,
            name: "MyType".to_string(),
            size: 16,
            count: 4,
            underlying_type: 0,
            return_type: 0,
            arg_types: vec![],
        };
        let s = rec.to_string();
        assert!(s.contains("MyType"));
        assert!(s.contains("16"));
    }
}
